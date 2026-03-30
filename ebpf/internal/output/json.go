package output

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/athosone/aisre/ebpf/internal/parser"
)

// JSONEmitter writes correlated HTTP events as JSON lines to a writer.
type JSONEmitter struct {
	w io.Writer
}

// NewJSONEmitter creates a new JSONEmitter writing to w.
func NewJSONEmitter(w io.Writer) *JSONEmitter {
	return &JSONEmitter{w: w}
}

func (e *JSONEmitter) Emit(_ context.Context, pair *parser.CorrelatedPair) error {
	out := jsonEvent{
		TimestampNs: pair.TimestampNs,
		LatencyNs:   pair.LatencyNs,
		Process: jsonProcess{
			Pid:  pair.Process.Pid,
			Tid:  pair.Process.Tid,
			Uid:  pair.Process.Uid,
			Comm: pair.Process.Comm,
		},
		Connection: jsonConnection{
			SrcIP:   ipToString(pair.Connection.SrcIP),
			SrcPort: pair.Connection.SrcPort,
			DstIP:   ipToString(pair.Connection.DstIP),
			DstPort: pair.Connection.DstPort,
		},
	}

	if pair.Request != nil {
		out.Request = &jsonHTTPRequest{
			Method:  pair.Request.Method,
			Path:    pair.Request.Path,
			Version: pair.Request.Version,
			Headers: convertHeaders(pair.Request.Headers),
		}
		if len(pair.Request.PartialBody) > 0 {
			out.Request.PartialBody = base64.StdEncoding.EncodeToString(pair.Request.PartialBody)
		}
	}

	if pair.Response != nil {
		out.Response = &jsonHTTPResponse{
			StatusCode: pair.Response.StatusCode,
			StatusText: pair.Response.StatusText,
			Version:    pair.Response.Version,
			Headers:    convertHeaders(pair.Response.Headers),
		}
		if len(pair.Response.PartialBody) > 0 {
			out.Response.PartialBody = base64.StdEncoding.EncodeToString(pair.Response.PartialBody)
		}
	}

	data, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	data = append(data, '\n')

	_, err = e.w.Write(data)
	return err
}

func (e *JSONEmitter) Close() error {
	return nil
}

// ipToString converts a uint32 IPv4 address to dotted-decimal string.
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
}

func convertHeaders(headers []parser.Header) []jsonHeader {
	out := make([]jsonHeader, len(headers))
	for i, h := range headers {
		out[i] = jsonHeader{Key: h.Key, Value: h.Value}
	}
	return out
}

type jsonEvent struct {
	TimestampNs uint64            `json:"timestamp_ns,omitempty"`
	LatencyNs   uint64            `json:"latency_ns,omitempty"`
	Process     jsonProcess       `json:"process"`
	Connection  jsonConnection    `json:"connection"`
	Request     *jsonHTTPRequest  `json:"request,omitempty"`
	Response    *jsonHTTPResponse `json:"response,omitempty"`
}

type jsonProcess struct {
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Comm string `json:"comm,omitempty"`
}

type jsonConnection struct {
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
}

type jsonHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type jsonHTTPRequest struct {
	Method      string       `json:"method"`
	Path        string       `json:"path"`
	Version     string       `json:"version"`
	Headers     []jsonHeader `json:"headers,omitempty"`
	PartialBody string       `json:"partial_body,omitempty"`
}

type jsonHTTPResponse struct {
	StatusCode  uint32       `json:"status_code"`
	StatusText  string       `json:"status_text"`
	Version     string       `json:"version"`
	Headers     []jsonHeader `json:"headers,omitempty"`
	PartialBody string       `json:"partial_body,omitempty"`
}
