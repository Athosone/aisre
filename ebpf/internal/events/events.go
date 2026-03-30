package events

import (
	"encoding/binary"
	"fmt"
)

const MaxPayloadCapture = 512

const (
	DirectionRequest  uint8 = 0
	DirectionResponse uint8 = 1
)

// HTTPEvent mirrors the packed C struct http_event from common.h.
// Field order and sizes must match exactly.
type HTTPEvent struct {
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Uid         uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Direction   uint8
	Pad         [3]uint8
	PayloadLen  uint32
	CapturedLen uint32
	Payload     [MaxPayloadCapture]uint8
}

// HTTPEventSize is the size of the packed struct in bytes.
const HTTPEventSize = 8 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 1 + 3 + 4 + 4 + MaxPayloadCapture // = 544

// DecodeHTTPEvent deserializes a raw byte slice from the BPF ring buffer
// into an HTTPEvent. The input must be at least HTTPEventSize bytes.
func DecodeHTTPEvent(raw []byte) (*HTTPEvent, error) {
	if len(raw) < HTTPEventSize {
		return nil, fmt.Errorf("buffer too short: got %d, need %d", len(raw), HTTPEventSize)
	}

	event := &HTTPEvent{}
	event.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	event.Pid = binary.LittleEndian.Uint32(raw[8:12])
	event.Tid = binary.LittleEndian.Uint32(raw[12:16])
	event.Uid = binary.LittleEndian.Uint32(raw[16:20])
	event.SrcIP = binary.LittleEndian.Uint32(raw[20:24])
	event.DstIP = binary.LittleEndian.Uint32(raw[24:28])
	event.SrcPort = binary.LittleEndian.Uint16(raw[28:30])
	event.DstPort = binary.LittleEndian.Uint16(raw[30:32])
	event.Direction = raw[32]
	copy(event.Pad[:], raw[33:36])
	event.PayloadLen = binary.LittleEndian.Uint32(raw[36:40])
	event.CapturedLen = binary.LittleEndian.Uint32(raw[40:44])
	copy(event.Payload[:], raw[44:44+MaxPayloadCapture])

	return event, nil
}

// CapturedPayload returns the meaningful portion of the payload.
func (e *HTTPEvent) CapturedPayload() []byte {
	n := e.CapturedLen
	if n > MaxPayloadCapture {
		n = MaxPayloadCapture
	}
	return e.Payload[:n]
}
