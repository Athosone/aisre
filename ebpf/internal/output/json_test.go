package output_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/athosone/aisre/ebpf/internal/output"
	"github.com/athosone/aisre/ebpf/internal/parser"
)

func TestJSONEmitter(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method:  "GET",
			Path:    "/api/health",
			Version: "HTTP/1.1",
			Headers: []parser.Header{
				{Key: "Host", Value: "localhost"},
			},
		},
		Response: &parser.HTTPResponseParsed{
			StatusCode: 200,
			StatusText: "OK",
			Version:    "HTTP/1.1",
			Headers: []parser.Header{
				{Key: "Content-Type", Value: "text/plain"},
			},
			PartialBody: []byte("OK"),
		},
		LatencyNs:   1_500_000,
		TimestampNs: 9_000_000,
		Process: parser.ProcessInfo{
			Pid: 1234,
			Tid: 1234,
			Uid: 0,
		},
		Connection: parser.ConnectionInfo{
			SrcIP:   0x0100007F,
			SrcPort: 54321,
			DstIP:   0x0100007F,
			DstPort: 8080,
		},
	}

	err := emitter.Emit(context.Background(), pair)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	// Should be valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	// Check key fields
	req, ok := result["request"].(map[string]interface{})
	if !ok {
		t.Fatal("missing request field")
	}
	if req["method"] != "GET" {
		t.Errorf("method = %v, want GET", req["method"])
	}
	if req["path"] != "/api/health" {
		t.Errorf("path = %v, want /api/health", req["path"])
	}

	resp, ok := result["response"].(map[string]interface{})
	if !ok {
		t.Fatal("missing response field")
	}
	if resp["status_code"].(float64) != 200 {
		t.Errorf("status_code = %v, want 200", resp["status_code"])
	}

	if result["latency_ns"].(float64) != 1_500_000 {
		t.Errorf("latency_ns = %v, want 1500000", result["latency_ns"])
	}

	if result["timestamp_ns"].(float64) != 9_000_000 {
		t.Errorf("timestamp_ns = %v, want 9000000", result["timestamp_ns"])
	}
}

func TestJSONEmitterIPFormatting(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method: "GET", Path: "/", Version: "HTTP/1.1",
		},
		Connection: parser.ConnectionInfo{
			SrcIP:   0x0100007F, // 127.0.0.1
			SrcPort: 12345,
			DstIP:   0x0100007F,
			DstPort: 80,
		},
		Process: parser.ProcessInfo{Pid: 1},
	}

	err := emitter.Emit(context.Background(), pair)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(buf.Bytes(), &result)

	conn := result["connection"].(map[string]interface{})
	if conn["src_ip"] != "127.0.0.1" {
		t.Errorf("src_ip = %v, want 127.0.0.1", conn["src_ip"])
	}
}

func TestJSONEmitterNilResponse(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method: "GET", Path: "/timeout", Version: "HTTP/1.1",
		},
		// Response is nil (timed out)
		Process:    parser.ProcessInfo{Pid: 42},
		Connection: parser.ConnectionInfo{DstPort: 8080},
	}

	err := emitter.Emit(context.Background(), pair)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["response"] != nil {
		t.Error("expected nil response for timed-out request")
	}

	req := result["request"].(map[string]interface{})
	if req["path"] != "/timeout" {
		t.Errorf("path = %v, want /timeout", req["path"])
	}
}

func TestJSONEmitterNewlineTerminated(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method: "GET", Path: "/", Version: "HTTP/1.1",
		},
		Process:    parser.ProcessInfo{Pid: 1},
		Connection: parser.ConnectionInfo{},
	}

	emitter.Emit(context.Background(), pair)

	output := buf.Bytes()
	if len(output) == 0 || output[len(output)-1] != '\n' {
		t.Error("output should be newline-terminated for JSON lines format")
	}
}
