package parser

import (
	"sync"
	"time"

	"github.com/athosone/aisre/ebpf/internal/events"
)

// CorrelatedPair is a matched HTTP request/response with latency.
type CorrelatedPair struct {
	Request     *HTTPRequestParsed
	Response    *HTTPResponseParsed
	LatencyNs   uint64
	TimestampNs uint64 // from the request event
	Process     ProcessInfo
	Connection  ConnectionInfo
}

// ProcessInfo holds process metadata from the event.
type ProcessInfo struct {
	Pid  uint32
	Tid  uint32
	Uid  uint32
	Comm string // enriched in userspace via /proc/{pid}/comm
}

// ConnectionInfo holds connection metadata from the event.
type ConnectionInfo struct {
	SrcIP   uint32
	SrcPort uint16
	DstIP   uint32
	DstPort uint16
}

// connKey identifies a connection for correlation.
type connKey struct {
	Pid     uint32
	Tid     uint32
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

type pendingRequest struct {
	parsed      *HTTPRequestParsed
	timestampNs uint64
	process     ProcessInfo
	connection  ConnectionInfo
	createdAt   time.Time
}

// Correlator matches HTTP request events with their corresponding responses.
type Correlator struct {
	timeout time.Duration
	mu      sync.Mutex
	pending map[connKey]*pendingRequest
}

// NewCorrelator creates a correlator with the given timeout for unmatched requests.
func NewCorrelator(timeout time.Duration) *Correlator {
	return &Correlator{
		timeout: timeout,
		pending: make(map[connKey]*pendingRequest),
	}
}

// Feed processes an HTTP event. Returns a CorrelatedPair if a request/response
// match is found, nil otherwise.
func (c *Correlator) Feed(event *events.HTTPEvent) *CorrelatedPair {
	key := connKey{
		Pid:     event.Pid,
		Tid:     event.Tid,
		SrcIP:   event.SrcIP,
		DstIP:   event.DstIP,
		SrcPort: event.SrcPort,
		DstPort: event.DstPort,
	}

	payload := event.CapturedPayload()

	proc := ProcessInfo{
		Pid: event.Pid,
		Tid: event.Tid,
		Uid: event.Uid,
	}

	conn := ConnectionInfo{
		SrcIP:   event.SrcIP,
		SrcPort: event.SrcPort,
		DstIP:   event.DstIP,
		DstPort: event.DstPort,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if event.Direction == events.DirectionRequest {
		parsed, err := ParseHTTPRequest(payload)
		if err != nil {
			return nil
		}
		c.pending[key] = &pendingRequest{
			parsed:      parsed,
			timestampNs: event.TimestampNs,
			process:     proc,
			connection:  conn,
			createdAt:   time.Now(),
		}
		return nil
	}

	// Direction == Response
	pending, ok := c.pending[key]
	if !ok {
		return nil // No matching request — drop
	}
	delete(c.pending, key)

	parsed, err := ParseHTTPResponse(payload)
	if err != nil {
		return nil
	}

	latency := event.TimestampNs - pending.timestampNs

	return &CorrelatedPair{
		Request:     pending.parsed,
		Response:    parsed,
		LatencyNs:   latency,
		TimestampNs: pending.timestampNs,
		Process:     pending.process,
		Connection:  pending.connection,
	}
}

// EvictExpired removes and returns pending requests that have exceeded the timeout.
// Returned pairs have a nil Response.
func (c *Correlator) EvictExpired() []*CorrelatedPair {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expired []*CorrelatedPair
	now := time.Now()

	for key, req := range c.pending {
		if now.Sub(req.createdAt) > c.timeout {
			expired = append(expired, &CorrelatedPair{
				Request:     req.parsed,
				TimestampNs: req.timestampNs,
				Process:     req.process,
				Connection:  req.connection,
			})
			delete(c.pending, key)
		}
	}

	return expired
}
