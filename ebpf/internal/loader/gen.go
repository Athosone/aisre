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

	cleanup := func(c *Collector) {
		if c.ringReader != nil {
			c.ringReader.Close()
		}
		if c.tcpObjs != nil {
			c.tcpObjs.Close()
		}
		if c.httpObjs != nil {
			c.httpObjs.Close()
		}
		for _, l := range c.links {
			l.Close()
		}
	}
	t, err := loadCollectorHttpTCPTracker()
	if err != nil {
		cleanup(c)
		return nil, fmt.Errorf("loading tcp tracker: %w", err)
	}
	c.tcpObjs = t

	h, err := loadCollectorHttpCapture(c.tcpObjs)
	if err != nil {
		cleanup(c)
		return nil, fmt.Errorf("loading http capture: %w", err)
	}
	c.httpObjs = h

	links, err := createLinks(c)
	if err != nil {
		cleanup(c)
		return nil, fmt.Errorf("creating links: %w", err)
	}
	c.links = links

	c.ringReader, err = ringbuf.NewReader(c.tcpObjs.Events)
	if err != nil {
		cleanup(c)
		return nil, fmt.Errorf("creating ring reader: %w", err)
	}

	return c, nil
}

func createLinks(c *Collector) ([]link.Link, error) {
	var links []link.Link
	cleanup := func(links []link.Link) {
		for _, l := range links {
			l.Close()
		}
	}
	attach := func(tpCategory, tpName string, prog *ebpf.Program) error {
		l, err := link.Tracepoint(tpCategory, tpName, prog, nil)
		if err != nil {
			return fmt.Errorf("linking to tracepoint %s:%s: %w", tpCategory, tpName, err)
		}
		links = append(links, l)
		return nil
	}

	if err := attach("syscalls", "sys_enter_connect", c.tcpObjs.TraceConnect); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_exit_connect", c.tcpObjs.TraceConnectExit); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_enter_accept4", c.tcpObjs.TraceAccept4Enter); err != nil {
		cleanup(links)
		return nil, err
	}
	if err := attach("syscalls", "sys_exit_accept4", c.tcpObjs.TraceAccept4Exit); err != nil {
		cleanup(links)
		return nil, err
	}
	if err := attach("sock", "inet_sock_set_state", c.tcpObjs.TraceInetSockSetState); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_enter_read", c.httpObjs.TracepointSysEnterRead); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_exit_read", c.httpObjs.TracepointSysExitRead); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_enter_write", c.httpObjs.TracepointSysEnterWrite); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_exit_write", c.httpObjs.TracepointSysExitWrite); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_enter_recvfrom", c.httpObjs.TracepointSysEnterRecvfrom); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_exit_recvfrom", c.httpObjs.TracepointSysExitRecvfrom); err != nil {
		cleanup(links)
		return nil, err
	}

	if err := attach("syscalls", "sys_enter_sendto", c.httpObjs.TracepointSysEnterSendto); err != nil {
		cleanup(links)
		return nil, err
	}
	if err := attach("syscalls", "sys_exit_sendto", c.httpObjs.TracepointSysExitSendto); err != nil {
		cleanup(links)
		return nil, err
	}

	return links, nil
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
			"events":              tcpObjs.Events,
			"payload_scratch":     tcpObjs.PayloadScratch,
		}}); err != nil {
		return nil, fmt.Errorf("loading http capture objects: %w", err)
	}
	return objs, nil
}

func (c *Collector) RingReader() *ringbuf.Reader {
	return c.ringReader
}

func (c *Collector) Close() error {
	var errs []error
	if c.ringReader != nil {
		if err := c.ringReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing ring reader: %w", err))
		}
	}
	for _, l := range c.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing link: %w", err))
		}
	}
	if c.httpObjs != nil {
		if err := c.httpObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing http capture objects: %w", err))
		}
	}
	if c.tcpObjs != nil {
		if err := c.tcpObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing tcp tracker objects: %w", err))
		}
	}
	return errors.Join(errs...)
}
