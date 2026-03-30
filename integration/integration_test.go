package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests must run inside the Docker container with eBPF capabilities.
// They start the collector binary, generate HTTP traffic, and verify captured events.
//
// Prerequisites:
//   - The collector binary must be built at /workspace/bin/collector
//   - The container must have CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON (or privileged)
//   - Run via: make test-smoke (handles Docker orchestration)

func TestCaptureHTTPGet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start HTTP server on a known port
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})
	server := &http.Server{Addr: ":18080", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	// Start collector
	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond) // wait for eBPF attach

	// Send HTTP request
	resp, err := http.Get("http://127.0.0.1:18080/health")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	resp.Body.Close()

	// Read events from collector stdout
	event := readEvent(t, stdout, 5*time.Second)

	if event["request"] == nil {
		t.Fatal("missing request in event")
	}
	req := event["request"].(map[string]any)
	if req["method"] != "GET" {
		t.Errorf("method = %v, want GET", req["method"])
	}
	if req["path"] != "/health" {
		t.Errorf("path = %v, want /health", req["path"])
	}
}

func TestCaptureHTTPPost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"created"}`))
	})
	server := &http.Server{Addr: ":18081", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	resp, err := http.Post("http://127.0.0.1:18081/data", "application/json",
		strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("HTTP POST: %v", err)
	}
	resp.Body.Close()

	event := readEvent(t, stdout, 5*time.Second)

	req := event["request"].(map[string]any)
	if req["method"] != "POST" {
		t.Errorf("method = %v, want POST", req["method"])
	}
	if req["path"] != "/data" {
		t.Errorf("path = %v, want /data", req["path"])
	}
}

func TestCapturePayloadTruncation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Server that returns a large body
	largeBody := strings.Repeat("X", 1024)
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(largeBody))
	})
	server := &http.Server{Addr: ":18082", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18082/big")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// The event should exist — the response body will be truncated
	// at 512 bytes, but the response headers + partial body should be captured
	event := readEvent(t, stdout, 5*time.Second)
	if event == nil {
		t.Fatal("expected event for large response")
	}
}

// readEvent reads a single JSON event from the collector's stdout.
func readEvent(t *testing.T, r io.Reader, timeout time.Duration) map[string]any {
	t.Helper()
	ch := make(chan map[string]any, 1)

	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			var event map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				continue
			}
			ch <- event
			return
		}
	}()

	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		t.Fatal("timeout waiting for event")
		return nil
	}
}
