package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC tcpTracker ../../c/tcp_tracker.c -- -I../../c/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC httpCapture ../../c/http_capture.c -- -I../../c/headers -D__TARGET_ARCH_x86

type Collector struct {
	tcpObjs  *tcpTrackerObjects
	httpObjs *httpCaptureObjects
	links    []link.Link
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
		return nil, fmt.Errorf("linking tcp tracker to tracepoint: %w", err)
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
