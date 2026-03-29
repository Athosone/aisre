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
- IPv6 support (IPv4 only for this milestone; IPv6 can be added by widening address fields)

## Known Limitations

- **IPv4 only**: Address fields are 4 bytes. IPv6 (`::1`) connections will not be captured. This is acceptable for initial Docker/WSL2 development where traffic is predominantly IPv4.
- **First-segment capture only**: HTTP headers/body spanning multiple `read()`/`write()` calls are not reassembled. Only the first segment of a request or response is captured. Continuation reads without an HTTP signature are dropped. This means large headers or chunked transfer encoding may be partially missed.
- **`/proc` enrichment is best-effort**: Short-lived processes may exit before userspace reads `/proc/{pid}/comm`. The `comm` field will be empty for exited processes.
- **Syscall noise**: `read`/`write` tracepoints fire for all file descriptors (files, pipes, terminals), not just sockets. Non-socket fds are filtered by checking `conn_info_map` on `sys_enter` (early discard), but there is inherent overhead. `sendto`/`recvfrom` are socket-specific and lower noise.

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

Uses BPF CO-RE (Compile Once, Run Everywhere) with BTF type information via `vmlinux.h` for portable struct access across kernel versions.

Tracks connections using a two-phase approach that correlates fds (available at the syscall layer) with socket 4-tuples (available at the TCP layer):

**Client-side (outgoing connections):**
1. **Tracepoint `sys_enter_connect`**: captures `{pid_tgid, fd}` and the `sockaddr` argument. Stores a temporary entry in `pending_connect_map`: `{pid_tgid, fd}` -> `{sock_addr}`.
2. **Tracepoint `sys_exit_connect`**: on success (or EINPROGRESS for non-blocking), promotes the pending entry into `conn_info_map` by reading the socket's local address (src ip/port) via the sock pointer obtained from the fd. Removes the pending entry.

**Server-side (incoming connections):**
1. **Tracepoint `sys_enter_accept4`** (covers both `accept` and `accept4`): saves `pid_tgid` in a scratch map.
2. **Tracepoint `sys_exit_accept4`**: the return value is the new fd. Reads the new socket's 4-tuple from the kernel `struct sock` (via the fd -> file -> socket -> sock chain, or via `inet_sock_set_state` enrichment). Stores in `conn_info_map`.

**Connection lifecycle:**
3. **Tracepoint `inet_sock_set_state`**: enriches entries on ESTABLISHED (fills in 4-tuple if not yet complete for non-blocking connects). Cleans up entries on TCP_CLOSE.

- Maintains `conn_info_map` (BPF hash): `{pid_tgid, fd}` -> `{src_ip, src_port, dst_ip, dst_port, state}`
- Maintains `pending_connect_map` (BPF hash): `{pid_tgid, fd}` -> `{sockaddr, timestamp}` — temporary, cleaned on exit or timeout
- Entries created on connect/accept syscalls, enriched on ESTABLISHED, cleaned up on CLOSE

### http_capture.c

Attaches to syscall tracepoints:
- `sys_enter_read`, `sys_exit_read`
- `sys_enter_write`, `sys_exit_write`
- `sys_enter_sendto`, `sys_exit_sendto`
- `sys_enter_recvfrom`, `sys_exit_recvfrom`

Also uses BPF CO-RE with `vmlinux.h`.

Behavior:
- On `sys_enter_*`: first checks if `{pid_tgid, fd}` exists in `conn_info_map` (early discard for non-socket fds). If found, saves buffer pointer and fd into a per-CPU map keyed by `{pid_tgid}` (unique per-thread since `pid_tgid` encodes both tgid in upper 32 bits and tid in lower 32 bits — a single thread cannot be in two syscalls simultaneously, so this is safe).
- On `sys_exit_*`: reads saved buffer pointer, copies first `MAX_PAYLOAD_CAPTURE` bytes (compile-time constant, default 512). The BPF verifier requires a static bound for `bpf_probe_read_user`, so the buffer size is fixed at compile time. A logical capture limit can be read from `config_map` to emit fewer bytes, but the read itself is always bounded by the constant.
- Checks for HTTP signature (`GET `, `POST `, `PUT `, `DELETE `, `HEAD `, `OPTIONS `, `PATCH `, `CONNECT `, `HTTP/1.`)
- If HTTP detected: looks up connection 4-tuple from `tcp_tracker`'s `conn_info_map`, builds event struct, pushes to BPF ring buffer
- Non-HTTP traffic is dropped in-kernel

### Shared BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `conn_info_map` | Hash | `{pid_tgid, fd}` | Connection 4-tuple + timestamps | TCP connection tracking |
| `pending_connect_map` | Hash | `{pid_tgid, fd}` | `{sockaddr, timestamp}` | Temporary: in-flight connect() calls |
| `active_syscall_map` | Per-CPU Hash | `{pid_tgid}` | `{fd, buf_ptr, entry_ts}` | Correlate syscall enter/exit (per-thread safe) |
| `events` | Ring Buffer | N/A (shared) | `http_event` struct | Kernel -> userspace channel |
| `config_map` | Array | index 0 | `{logical_capture_bytes}` | Runtime config (logical limit, not verifier bound) |

**Why BPF Ring Buffer over Perf Event Array:** Kernel 6.6 supports `BPF_MAP_TYPE_RINGBUF` (available since 5.8). Ring buffers are shared across CPUs (no per-CPU waste), preserve event ordering, support variable-length records, and avoid the wakeup-per-CPU overhead of perf event arrays. The Go collector reads via `cilium/ebpf/ringbuf.Reader` instead of `perf.Reader`.

### Kernel Event Struct

```c
#define MAX_PAYLOAD_CAPTURE 512  // compile-time constant, required by BPF verifier

struct http_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 src_ip;          // IPv4 only for this milestone
    __u32 dst_ip;           // IPv4 only for this milestone
    __u16 src_port;
    __u16 dst_port;
    __u8  direction;        // 0 = request (write/send), 1 = response (read/recv)
    __u8  _pad[3];          // explicit padding for alignment before u32 fields
    __u32 payload_len;      // actual bytes transferred by syscall
    __u32 captured_len;     // min(payload_len, logical_capture_limit)
    __u8  payload[MAX_PAYLOAD_CAPTURE];
} __attribute__((packed));
```

**Note on packing:** The struct uses `__attribute__((packed))` to ensure the wire format between kernel and userspace is deterministic with no compiler-inserted padding. The Go deserialization must use `binary.Read` with the matching layout (or `encoding/binary.LittleEndian` field-by-field). The explicit `_pad` field before `payload_len` is for documentation — with packed, it's not strictly needed but clarifies intent.

## Go Userspace Collector

### Loader (internal/loader/)

- Uses `cilium/ebpf` with `bpf2go` to generate Go bindings from C source at build time
- Loads both eBPF programs into the kernel
- Attaches to tracepoints
- Manages lifecycle: graceful shutdown (SIGINT/SIGTERM) detaches programs and closes maps

### Event Reader (internal/events/)

- Opens BPF ring buffer via `cilium/ebpf/ringbuf.Reader`
- Reads raw `http_event` structs, deserializes into Go structs using `binary.Read` matching the packed C struct layout
- Tracks and logs lost events (ring buffer overflow)

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

| Parameter | Default | Source | Notes |
|-----------|---------|--------|-------|
| Max payload buffer | 512 bytes | Compile-time (`MAX_PAYLOAD_CAPTURE`) | BPF verifier requires static bound; changing requires rebuild |
| Logical capture limit | 512 bytes | Env `AISRE_MAX_CAPTURE` / CLI flag | Written to `config_map`; must be <= `MAX_PAYLOAD_CAPTURE` |
| Ring buffer size | 256 pages (1MB) | Env `AISRE_RINGBUF_SIZE` / CLI flag | Allocated at program load time |
| Correlation timeout | 5 seconds | Env `AISRE_CORR_TIMEOUT` / CLI flag | Unmatched requests evicted after this |
| Output format | json | Env `AISRE_OUTPUT` / CLI flag | Only `json` supported initially |

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

message Header {
  string key = 1;
  string value = 2;
}

message HTTPRequest {
  string method = 1;
  string path = 2;
  string version = 3;
  repeated Header headers = 4;  // repeated, not map — HTTP allows duplicate header keys (e.g. Set-Cookie)
  bytes partial_body = 5;
  uint32 total_body_length = 6;
}

message HTTPResponse {
  uint32 status_code = 1;
  string status_text = 2;
  string version = 3;
  repeated Header headers = 4;  // repeated, not map — preserves duplicates and ordering
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
