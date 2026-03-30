package parser_test

import (
	"testing"
	"time"

	"github.com/athosone/aisre/ebpf/internal/events"
	"github.com/athosone/aisre/ebpf/internal/parser"
)

func makeEvent(pid, tid uint32, dstPort uint16, direction uint8, tsNs uint64, payload string) *events.HTTPEvent {
	e := &events.HTTPEvent{
		TimestampNs: tsNs,
		Pid:         pid,
		Tid:         tid,
		SrcIP:       0x0100007F,
		DstIP:       0x0100007F,
		SrcPort:     54321,
		DstPort:     dstPort,
		Direction:   direction,
		PayloadLen:  uint32(len(payload)),
		CapturedLen: uint32(len(payload)),
	}
	copy(e.Payload[:], payload)
	return e
}

func TestCorrelateRequestResponse(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	req := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")

	// Feed request — should not produce a pair yet
	pair := c.Feed(req)
	if pair != nil {
		t.Fatal("expected nil pair for request-only")
	}

	resp := makeEvent(100, 100, 8080, events.DirectionResponse, 2_000_000,
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	// Feed response — should correlate
	pair = c.Feed(resp)
	if pair == nil {
		t.Fatal("expected correlated pair")
	}

	if pair.Request.Method != "GET" {
		t.Errorf("Method = %q, want GET", pair.Request.Method)
	}
	if pair.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", pair.Response.StatusCode)
	}
	if pair.LatencyNs != 1_000_000 {
		t.Errorf("LatencyNs = %d, want 1000000", pair.LatencyNs)
	}
}

func TestCorrelateTimeout(t *testing.T) {
	c := parser.NewCorrelator(100 * time.Millisecond)

	req := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
	c.Feed(req)

	// Wait for timeout
	time.Sleep(200 * time.Millisecond)

	// Evict expired entries
	expired := c.EvictExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}
	if expired[0].Request.Method != "GET" {
		t.Errorf("expired request Method = %q, want GET", expired[0].Request.Method)
	}
	if expired[0].Response != nil {
		t.Error("expired entry should have nil response")
	}
}

func TestCorrelateResponseBeforeRequest(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	// Response arrives first — should be dropped
	resp := makeEvent(100, 100, 8080, events.DirectionResponse, 1_000_000,
		"HTTP/1.1 200 OK\r\n\r\n")
	pair := c.Feed(resp)
	if pair != nil {
		t.Fatal("expected nil for response-before-request")
	}
}

func TestCorrelateDifferentConnections(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	// Two requests on different ports
	req1 := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /a HTTP/1.1\r\nHost: localhost\r\n\r\n")
	req2 := makeEvent(100, 100, 9090, events.DirectionRequest, 1_000_000,
		"GET /b HTTP/1.1\r\nHost: localhost\r\n\r\n")

	c.Feed(req1)
	c.Feed(req2)

	// Response for port 9090
	resp2 := makeEvent(100, 100, 9090, events.DirectionResponse, 2_000_000,
		"HTTP/1.1 404 Not Found\r\n\r\n")
	pair := c.Feed(resp2)
	if pair == nil {
		t.Fatal("expected pair")
	}
	if pair.Request.Path != "/b" {
		t.Errorf("Path = %q, want /b", pair.Request.Path)
	}
	if pair.Response.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", pair.Response.StatusCode)
	}
}

func TestCorrelateTimestampPreserved(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	req := makeEvent(100, 100, 8080, events.DirectionRequest, 5_000_000,
		"POST /data HTTP/1.1\r\nHost: localhost\r\n\r\n")
	c.Feed(req)

	resp := makeEvent(100, 100, 8080, events.DirectionResponse, 8_000_000,
		"HTTP/1.1 201 Created\r\n\r\n")
	pair := c.Feed(resp)

	if pair == nil {
		t.Fatal("expected pair")
	}
	if pair.TimestampNs != 5_000_000 {
		t.Errorf("TimestampNs = %d, want 5000000", pair.TimestampNs)
	}
	if pair.LatencyNs != 3_000_000 {
		t.Errorf("LatencyNs = %d, want 3000000", pair.LatencyNs)
	}
}
