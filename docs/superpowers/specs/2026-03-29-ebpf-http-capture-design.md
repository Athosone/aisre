# eBPF HTTP Traffic Capture — Design Spec

## Overview

First milestone of the AI SRE agent: an eBPF-based HTTP traffic capture system that hooks syscall tracepoints to observe plaintext HTTP traffic, filters in-kernel, and emits structured events to userspace via perf ring buffers. A Go collector (using cilium/ebpf) deserializes, parses, correlates request/response pairs, and outputs JSON events conforming to a shared protobuf schema.

## Goals

- Capture HTTP request/response traffic with headers and partial body (configurable, default 512 bytes)
- Filter non-HTTP traffic in-kernel to minimize userspace overhead
- Correlate request/response pairs with latency calculation
- Emit structured JSON events to stdout, defined by a protobuf interface
- Run and test entirely locally using Docker on WSL2 (kernel 6.6)
- Structure as a monorepo supporting future Clojure/Go services and Temporal workflows

## Non-Goals (for this milestone)

- TLS/encrypted traffic interception (future: uprobes)
- Protocols beyond HTTP (DNS, PostgreSQL, Redis, etc.)
- Kubernetes pod enrichment
- Real transport layer (gRPC, message queues, OTLP)
- AI agent logic or Temporal workflows

## Monorepo Structure

```
aisre/
├── proto/                     # Protobuf event definitions (shared interface)
│   └── events/
│       └── v1/
│           └── http.proto
├── ebpf/                      # eBPF C programs + Go loader/collector
│   ├── c/                     # eBPF C source
│   │   ├── http_capture.c
│   │   ├── tcp_tracker.c
│   │   └── headers/           # Shared BPF headers/structs
│   ├── cmd/
│   │   └── collector/         # Go binary entry point
│   │       └── main.go
│   ├── internal/
│   │   ├── loader/            # eBPF program loading and lifecycle
│   │   ├── events/            # Perf buffer reading, event deserialization
│   │   ├── parser/            # HTTP parsing and request/response correlation
│   │   └── output/            # Event emission (Emitter interface + JSON impl)
│   ├── testdata/              # Fixtures for unit tests
│   └── go.mod
├── services/                  # Future: Clojure/Go consumer services
├── temporal/                  # Future: Temporal workflows
├── deploy/
│   └── docker/
│       ├── Dockerfile.ebpf-dev
│       └── docker-compose.yml
├── docs/
└── Makefile
```

Each top-level directory is an independent module (`go.mod` or `deps.edn`). The `proto/` directory is shared; generated code goes into each consumer's module.

## eBPF Kernel Programs

### tcp_tracker.c

Uses two attachment points:

1. **Kprobe on `tcp_v4_connect` / tracepoint `tcp_connect`**: captures the fd-to-socket association at connect time, when both `pid_tgid` and the socket's fd are available. Stores `{pid_tgid, fd}` -> socket pointer.
2. **Tracepoint `inet_sock_set_state`**: fires on TCP state transitions and provides the socket pointer with the full 4-tuple (src/dst IP and port). On ESTABLISHED, enriches the map entry with the 4-tuple. On CLOSE, cleans up the entry.

For accept (server side), attaches a kretprobe on `inet_csk_accept` to capture the new socket and its fd.

- Maintains a BPF hash map: `{pid_tgid, fd}` -> `{src_ip, src_port, dst_ip, dst_port, state}`
- Entries created on connect/accept, enriched on ESTABLISHED, cleaned up on CLOSE

### http_capture.c

Attaches to syscall tracepoints:
- `sys_enter_read`, `sys_exit_read`
- `sys_enter_write`, `sys_exit_write`
- `sys_enter_sendto`, `sys_exit_sendto`
- `sys_enter_recvfrom`, `sys_exit_recvfrom`

Behavior:
- On `sys_enter_*`: saves buffer pointer and fd into a per-CPU map keyed by `{pid_tgid}`
- On `sys_exit_*`: reads saved buffer pointer, copies first N bytes (configurable, default 512)
- Checks for HTTP signature (`GET `, `POST `, `PUT `, `DELETE `, `HEAD `, `OPTIONS `, `PATCH `, `CONNECT `, `HTTP/1.`)
- If HTTP detected: looks up connection 4-tuple from `tcp_tracker`'s map, builds event struct, pushes to perf ring buffer
- Non-HTTP traffic is dropped in-kernel

### Shared BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `conn_info_map` | Hash | `{pid_tgid, fd}` | Connection 4-tuple + timestamps | TCP connection tracking |
| `active_syscall_map` | Per-CPU Hash | `{pid_tgid}` | `{fd, buf_ptr, entry_ts}` | Correlate syscall enter/exit |
| `events` | Perf Event Array | CPU index | `http_event` struct | Kernel -> userspace channel |
| `config_map` | Array | index 0 | `{max_capture_bytes}` | Runtime configuration |

### Kernel Event Struct

```c
#define MAX_PAYLOAD_CAPTURE 512

struct http_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  direction;      // 0 = request (write/send), 1 = response (read/recv)
    __u32 payload_len;    // actual bytes transferred by syscall
    __u32 captured_len;   // bytes captured (min of payload_len, max_capture)
    __u8  payload[MAX_PAYLOAD_CAPTURE];
};
```

## Go Userspace Collector

### Loader (internal/loader/)

- Uses `cilium/ebpf` with `bpf2go` to generate Go bindings from C source at build time
- Loads both eBPF programs into the kernel
- Attaches to tracepoints
- Manages lifecycle: graceful shutdown (SIGINT/SIGTERM) detaches programs and closes maps

### Event Reader (internal/events/)

- Opens perf ring buffer via `cilium/ebpf/perf.Reader`
- Reads raw `http_event` structs, deserializes into Go structs
- Tracks and logs lost events (perf buffer overflow)

### Parser (internal/parser/)

- Extracts structured HTTP fields from raw payload bytes:
  - Request: method, path, HTTP version, headers, partial body
  - Response: status code, status text, HTTP version, headers, partial body
- Correlates request/response pairs by `{pid, fd, connection 4-tuple}` using a time-windowed buffer (5s default timeout for unmatched requests)
- Calculates latency: response read timestamp - request write timestamp
- Enriches with process name (`comm`) via `/proc/{pid}/comm`

### Output (internal/output/)

Defines an `Emitter` interface:

```go
type Emitter interface {
    Emit(context.Context, *events.HTTPEvent) error
    Close() error
}
```

Initial implementation: `JSONStdoutEmitter` — writes one JSON line per correlated event to stdout, serialized via `protojson` from the shared protobuf schema.

Future implementations (gRPC, NATS, OTLP) plug into this interface.

### Configuration

| Parameter | Default | Source |
|-----------|---------|--------|
| Max payload capture size | 512 bytes | Env `AISRE_MAX_CAPTURE` / CLI flag |
| Perf buffer size | 256 pages | Env `AISRE_PERF_PAGES` / CLI flag |
| Correlation timeout | 5 seconds | Env `AISRE_CORR_TIMEOUT` / CLI flag |
| Output format | json | Env `AISRE_OUTPUT` / CLI flag |

## Protobuf Event Interface

Located at `proto/events/v1/http.proto`. Defines the shared contract between the collector and any downstream consumer.

```protobuf
syntax = "proto3";
package events.v1;

option go_package = "github.com/athosone/aisre/proto/events/v1;eventsv1";

message HTTPEvent {
  uint64 timestamp_ns = 1;
  ProcessInfo process = 2;
  ConnectionInfo connection = 3;
  HTTPRequest request = 4;
  HTTPResponse response = 5;
  uint64 latency_ns = 6;
}

message ProcessInfo {
  uint32 pid = 1;
  uint32 tid = 2;
  uint32 uid = 3;
  string comm = 4;
}

message ConnectionInfo {
  string src_ip = 1;
  uint32 src_port = 2;
  string dst_ip = 3;
  uint32 dst_port = 4;
}

message HTTPRequest {
  string method = 1;
  string path = 2;
  string version = 3;
  map<string, string> headers = 4;
  bytes partial_body = 5;
  uint32 total_body_length = 6;
}

message HTTPResponse {
  uint32 status_code = 1;
  string status_text = 2;
  string version = 3;
  map<string, string> headers = 4;
  bytes partial_body = 5;
  uint32 total_body_length = 6;
}
```

## Testing Strategy

### Unit Tests (no kernel, no privileges)

- **Parser tests**: table-driven, feed raw HTTP byte slices, assert extraction of method/path/status/headers/body. Fixtures in `testdata/`.
- **Correlation tests**: feed sequences of request/response events, verify pairing and latency. Edge cases: unmatched requests (timeout), out-of-order, duplicates.
- **Output tests**: verify JSON serialization matches protobuf schema via `protojson`.
- Run with `go test ./...`.

### Integration Tests (eBPF + kernel, Docker)

Docker container with `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`:

1. Start the collector
2. Run a simple HTTP server (`net/http` on known port)
3. Send known HTTP requests (Go HTTP client)
4. Read collector JSON output from stdout
5. Assert events match: correct method, path, status, src/dst ports, payload content

Test matrix:
- HTTP methods: GET, POST, PUT, DELETE
- Payload sizes: 0, 100B, 1KB (verify truncation at 512B)
- Concurrent requests
- Keep-alive connections

`docker-compose.yml` orchestrates: collector service + test runner entrypoint.

### Smoke Tests

`make test-smoke`:
1. Build eBPF programs + collector
2. Spin up docker-compose
3. Run integration test suite
4. Tear down

### Dockerfile.ebpf-dev

Based on Ubuntu with:
- clang/LLVM (for BPF compilation)
- Go toolchain
- libbpf-dev, linux-headers
- protobuf compiler + Go protobuf plugin

Supports both building and running tests (with targeted capabilities).

## Build System

Top-level `Makefile` targets:

| Target | Description |
|--------|-------------|
| `make generate` | Compile protobuf, run bpf2go |
| `make build` | Build the collector binary |
| `make test` | Run unit tests (no kernel needed) |
| `make test-integration` | Run integration tests in Docker |
| `make test-smoke` | Full end-to-end: build + docker + integration tests + teardown |
| `make docker-build` | Build the dev Docker image |
| `make clean` | Remove build artifacts |
