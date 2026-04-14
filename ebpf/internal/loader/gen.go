package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC tcpTracker ../../c/tcp_tracker.c -- -I../../c/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC httpCapture ../../c/http_capture.c -- -I../../c/headers -D__TARGET_ARCH_x86

var ErrTCPTrackerTraceLink = errors.New("linking tcp tracker to tracepoint")
var ErrHTTPTrackerTraceLink = errors.New("linking http tracker to tracepoint")

type Collector struct {
	tcpObjs    *tcpTrackerObjects
	httpObjs   *httpCaptureObjects
	links      []link.Link
	ringReader *ringbuf.Reader
}

type Config struct {
}

var defaultConfig = &Config{}

func New(cfg *Config) (*Collector, error) {
	if cfg == nil {
		cfg = defaultConfig
	}

	err := rlimit.RemoveMemlock()
	if err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}
	c := &Collector{}

	t, err := loadCollectorHttpTCPTracker()
	if err != nil {
		return nil, fmt.Errorf("loading tcp tracker: %w", err)
	}
	c.tcpObjs = t

	h, err := loadCollectorHttpCapture(c.tcpObjs)
	if err != nil {
		return nil, fmt.Errorf("loading http capture: %w", err)
	}
	c.httpObjs = h

	l, err := link.Tracepoint("syscalls", "sys_enter_connect", c.tcpObjs.TraceConnect, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_connect", c.tcpObjs.TraceConnectExit, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_accept4", c.tcpObjs.TraceAccept4Enter, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_accept4", c.tcpObjs.TraceAccept4Exit, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_read", c.httpObjs.TracepointSysEnterRead, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_read", c.httpObjs.TracepointSysExitRead, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_write", c.httpObjs.TracepointSysEnterWrite, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_write", c.httpObjs.TracepointSysExitWrite, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_recvfrom", c.httpObjs.TracepointSysEnterRecvfrom, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_recvfrom", c.httpObjs.TracepointSysExitRecvfrom, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_sendto", c.httpObjs.TracepointSysEnterSendto, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_sendto", c.httpObjs.TracepointSysExitSendto, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPTrackerTraceLink, err)
	}
	c.links = append(c.links, l)

	return c, nil
}

func loadCollectorHttpTCPTracker() (*tcpTrackerObjects, error) {
	objs := &tcpTrackerObjects{}
	if err := loadTcpTrackerObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading tcp tracker objects: %w", err)
	}
	return objs, nil
}

func loadCollectorHttpCapture(tcpObjs *tcpTrackerObjects) (*httpCaptureObjects, error) {
	objs := &httpCaptureObjects{}
	if err := loadHttpCaptureObjects(objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"conn_info_map":       tcpObjs.ConnInfoMap,
			"pending_connect_map": tcpObjs.PendingConnectMap,
			"config_map":          tcpObjs.ConfigMap,
			"active_syscall_map":  tcpObjs.ActiveSyscallMap,
		}}); err != nil {
		return nil, fmt.Errorf("loading http capture objects: %w", err)
	}
	return objs, nil
}

func (c *Collector) RingReader() *ringbuf.Reader {
	return c.ringReader
}

func (c *Collector) Close() error {
	for _, l := range c.links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing link: %w", err)
		}
	}
	if err := c.tcpObjs.Close(); err != nil {
		return fmt.Errorf("closing tcp tracker objects: %w", err)
	}
	if err := c.httpObjs.Close(); err != nil {
		return fmt.Errorf("closing http capture objects: %w", err)
	}
	return nil
}
