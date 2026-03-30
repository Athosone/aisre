package events_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/athosone/aisre/ebpf/internal/events"
)

func TestDecodeHTTPEvent(t *testing.T) {
	payload := []byte("GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
	raw := buildRawEvent(t, rawEventFields{
		TimestampNs: 1000000,
		Pid:         1234,
		Tid:         1234,
		Uid:         0,
		SrcIP:       0x0100007F, // 127.0.0.1
		DstIP:       0x0100007F,
		SrcPort:     54321,
		DstPort:     8080,
		Direction:   0,
		PayloadLen:  uint32(len(payload)),
		CapturedLen: uint32(len(payload)),
		Payload:     payload,
	})

	event, err := events.DecodeHTTPEvent(raw)
	if err != nil {
		t.Fatalf("DecodeHTTPEvent() error = %v", err)
	}

	if event.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", event.Pid)
	}
	if event.DstPort != 8080 {
		t.Errorf("DstPort = %d, want 8080", event.DstPort)
	}
	if event.Direction != events.DirectionRequest {
		t.Errorf("Direction = %d, want DirectionRequest", event.Direction)
	}
	if event.CapturedLen != uint32(len(payload)) {
		t.Errorf("CapturedLen = %d, want %d", event.CapturedLen, len(payload))
	}
	if !bytes.Equal(event.Payload[:event.CapturedLen], payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestDecodeHTTPEventTruncated(t *testing.T) {
	raw := make([]byte, 10) // Too short to be valid
	_, err := events.DecodeHTTPEvent(raw)
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

func TestCapturedPayload(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\n\r\n")
	raw := buildRawEvent(t, rawEventFields{
		TimestampNs: 500,
		Pid:         42,
		Tid:         42,
		Direction:   1,
		PayloadLen:  uint32(len(payload)),
		CapturedLen: uint32(len(payload)),
		Payload:     payload,
	})

	event, err := events.DecodeHTTPEvent(raw)
	if err != nil {
		t.Fatalf("DecodeHTTPEvent() error = %v", err)
	}

	captured := event.CapturedPayload()
	if !bytes.Equal(captured, payload) {
		t.Errorf("CapturedPayload() = %q, want %q", captured, payload)
	}
}

func TestCapturedPayloadClamped(t *testing.T) {
	// CapturedLen larger than MaxPayloadCapture should be clamped
	raw := buildRawEvent(t, rawEventFields{
		CapturedLen: events.MaxPayloadCapture + 100,
		PayloadLen:  events.MaxPayloadCapture + 100,
	})

	event, err := events.DecodeHTTPEvent(raw)
	if err != nil {
		t.Fatalf("DecodeHTTPEvent() error = %v", err)
	}

	captured := event.CapturedPayload()
	if uint32(len(captured)) != events.MaxPayloadCapture {
		t.Errorf("CapturedPayload() len = %d, want %d", len(captured), events.MaxPayloadCapture)
	}
}

type rawEventFields struct {
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Uid         uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Direction   uint8
	PayloadLen  uint32
	CapturedLen uint32
	Payload     []byte
}

func buildRawEvent(t *testing.T, f rawEventFields) []byte {
	t.Helper()
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, f.TimestampNs)
	binary.Write(&buf, binary.LittleEndian, f.Pid)
	binary.Write(&buf, binary.LittleEndian, f.Tid)
	binary.Write(&buf, binary.LittleEndian, f.Uid)
	binary.Write(&buf, binary.LittleEndian, f.SrcIP)
	binary.Write(&buf, binary.LittleEndian, f.DstIP)
	binary.Write(&buf, binary.LittleEndian, f.SrcPort)
	binary.Write(&buf, binary.LittleEndian, f.DstPort)
	binary.Write(&buf, binary.LittleEndian, f.Direction)
	buf.Write([]byte{0, 0, 0}) // _pad[3]
	binary.Write(&buf, binary.LittleEndian, f.PayloadLen)
	binary.Write(&buf, binary.LittleEndian, f.CapturedLen)
	// Payload: pad to MAX_PAYLOAD_CAPTURE
	padded := make([]byte, events.MaxPayloadCapture)
	copy(padded, f.Payload)
	buf.Write(padded)
	return buf.Bytes()
}
