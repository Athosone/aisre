package loader

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestLoadTcpTrackerSpec(t *testing.T) {
	spec, err := loadTcpTracker()
	if err != nil {
		t.Fatalf("loadTcpTracker() failed: %v", err)
	}

	expectedPrograms := []string{
		"trace_connect",
		"trace_connect_exit",
		"trace_accept4_enter",
		"trace_accept4_exit",
		"trace_inet_sock_set_state",
	}
	for _, name := range expectedPrograms {
		if spec.Programs[name] == nil {
			t.Errorf("missing program %q in tcp_tracker spec", name)
		}
	}

	expectedMaps := []string{
		"conn_info_map",
		"pending_connect_map",
		"config_map",
		"events",
		"active_syscall_map",
	}
	for _, name := range expectedMaps {
		if spec.Maps[name] == nil {
			t.Errorf("missing map %q in tcp_tracker spec", name)
		}
	}
}

func TestLoadHttpCaptureSpec(t *testing.T) {
	spec, err := loadHttpCapture()
	if err != nil {
		t.Fatalf("loadHttpCapture() failed: %v", err)
	}

	expectedPrograms := []string{
		"tracepoint_sys_enter_write",
		"tracepoint_sys_exit_write",
		"tracepoint_sys_enter_read",
		"tracepoint_sys_exit_read",
		"tracepoint_sys_enter_sendto",
		"tracepoint_sys_exit_sendto",
		"tracepoint_sys_enter_recvfrom",
		"tracepoint_sys_exit_recvfrom",
	}
	for _, name := range expectedPrograms {
		if spec.Programs[name] == nil {
			t.Errorf("missing program %q in http_capture spec", name)
		}
	}

	expectedMaps := []string{
		"conn_info_map",
		"config_map",
		"events",
		"active_syscall_map",
		"pending_connect_map",
	}
	for _, name := range expectedMaps {
		if spec.Maps[name] == nil {
			t.Errorf("missing map %q in http_capture spec", name)
		}
	}
}

func TestTcpTrackerProgramTypes(t *testing.T) {
	spec, err := loadTcpTracker()
	if err != nil {
		t.Fatalf("loadTcpTracker() failed: %v", err)
	}

	tracepointPrograms := []string{
		"trace_connect",
		"trace_connect_exit",
		"trace_accept4_enter",
		"trace_accept4_exit",
	}
	for _, name := range tracepointPrograms {
		prog := spec.Programs[name]
		if prog.Type != ebpf.TracePoint {
			t.Errorf("program %q: got type %v, want TracePoint", name, prog.Type)
		}
	}
}

func TestHttpCaptureProgramTypes(t *testing.T) {
	spec, err := loadHttpCapture()
	if err != nil {
		t.Fatalf("loadHttpCapture() failed: %v", err)
	}

	for name, prog := range spec.Programs {
		if prog.Type != ebpf.TracePoint {
			t.Errorf("program %q: got type %v, want TracePoint", name, prog.Type)
		}
	}
}

func TestSharedMapsBetweenSpecs(t *testing.T) {
	tcpSpec, err := loadTcpTracker()
	if err != nil {
		t.Fatalf("loadTcpTracker() failed: %v", err)
	}

	httpSpec, err := loadHttpCapture()
	if err != nil {
		t.Fatalf("loadHttpCapture() failed: %v", err)
	}

	// Maps that must be shared between tcp_tracker and http_capture
	sharedMaps := []string{
		"conn_info_map",
		"pending_connect_map",
		"config_map",
		"events",
		"active_syscall_map",
	}

	for _, name := range sharedMaps {
		tcpMap := tcpSpec.Maps[name]
		httpMap := httpSpec.Maps[name]

		if tcpMap == nil {
			t.Errorf("tcp_tracker missing shared map %q", name)
			continue
		}
		if httpMap == nil {
			t.Errorf("http_capture missing shared map %q", name)
			continue
		}

		if tcpMap.Type != httpMap.Type {
			t.Errorf("map %q type mismatch: tcp=%v, http=%v", name, tcpMap.Type, httpMap.Type)
		}
		if tcpMap.KeySize != httpMap.KeySize {
			t.Errorf("map %q key size mismatch: tcp=%d, http=%d", name, tcpMap.KeySize, httpMap.KeySize)
		}
		if tcpMap.ValueSize != httpMap.ValueSize {
			t.Errorf("map %q value size mismatch: tcp=%d, http=%d", name, tcpMap.ValueSize, httpMap.ValueSize)
		}
	}
}
