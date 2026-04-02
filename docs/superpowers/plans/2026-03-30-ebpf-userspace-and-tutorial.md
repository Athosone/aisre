# eBPF HTTP Capture — Userspace Implementation + Tutorial Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Go userspace layer (parser, correlator, emitter, event decoder) with full unit tests, the monorepo scaffold, shared BPF headers, and a tutorial guiding the user through implementing the eBPF kernel programs, loader, and main.go.

**Architecture:** Userspace components are pure Go with no kernel dependency — fully testable locally. The BPF headers define the shared contract (structs, maps) that both the C eBPF programs and Go decoder depend on. The tutorial teaches the user to implement the kernel-side programs and wire everything together.

**Tech Stack:** Go (userspace), C (BPF headers), Protocol Buffers, Docker

**Spec:** `docs/superpowers/specs/2026-03-29-ebpf-http-capture-design.md`
**Full plan reference:** `docs/superpowers/plans/2026-03-29-ebpf-http-capture.md`

---

## File Map

```
aisre/
├── .gitignore
├── Makefile
├── proto/events/v1/http.proto
├── ebpf/
│   ├── go.mod
│   ├── c/headers/
│   │   ├── common.h
│   │   └── http_detect.h
│   ├── internal/
│   │   ├── events/
│   │   │   ├── events.go          # Go struct matching packed C layout + decoder
│   │   │   └── events_test.go     # Deserialization tests
│   │   ├── parser/
│   │   │   ├── http.go            # HTTP request/response byte parsing
│   │   │   ├── http_test.go       # Parser table-driven tests
│   │   │   ├── correlator.go      # Request/response pairing + latency
│   │   │   └── correlator_test.go # Correlation + timeout tests
│   │   └── output/
│   │       ├── emitter.go         # Emitter interface
│   │       ├── json.go            # JSON stdout implementation
│   │       └── json_test.go       # JSON output tests
│   └── testdata/                  # (empty, for future fixtures)
├── integration/
│   ├── go.mod
│   └── integration_test.go        # Integration test skeleton (runs in Docker)
├── deploy/docker/
│   ├── Dockerfile.ebpf-dev
│   └── docker-compose.yml
└── tutorial/
    ├── README.md                  # Overview + learning path
    ├── 01-ebpf-concepts.md        # eBPF primer: maps, programs, verifier
    ├── 02-tcp-tracker.md          # Guide: implement tcp_tracker.c
    ├── 03-http-capture.md         # Guide: implement http_capture.c
    ├── 04-loader-and-bpf2go.md    # Guide: Go loader + bpf2go generation
    └── 05-collector-main.md       # Guide: wire main.go + run integration tests
```

---

## Task 1: Monorepo Scaffold

**Files:**
- Create: `.gitignore`
- Create: `Makefile`
- Create: `ebpf/go.mod`
- Create: `proto/events/v1/http.proto`
- Create: `deploy/docker/Dockerfile.ebpf-dev`
- Create: `deploy/docker/docker-compose.yml`

- [ ] **Step 1: Create .gitignore**

```gitignore
# Go
*.exe
*.test
*.out
/vendor/

# eBPF generated
ebpf/c/headers/vmlinux.h
*_bpfel.go
*_bpfeb.go
*_bpfel.o
*_bpfeb.o

# Proto generated
*.pb.go

# Build artifacts
/bin/
```

- [ ] **Step 2: Create proto/events/v1/http.proto**

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
  repeated Header headers = 4;
  bytes partial_body = 5;
  uint32 total_body_length = 6;
}

message HTTPResponse {
  uint32 status_code = 1;
  string status_text = 2;
  string version = 3;
  repeated Header headers = 4;
  bytes partial_body = 5;
  uint32 total_body_length = 6;
}
```

- [ ] **Step 3: Initialize Go module**

Run:
```bash
mkdir -p ebpf && cd ebpf && go mod init github.com/athosone/aisre/ebpf
```

- [ ] **Step 4: Create Dockerfile.ebpf-dev**

```dockerfile
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    bpftool \
    gcc-multilib \
    make \
    git \
    curl \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.23
RUN curl -fsSL https://go.dev/dl/go1.23.8.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install protoc-gen-go
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

WORKDIR /workspace
```

- [ ] **Step 5: Create docker-compose.yml**

```yaml
services:
  ebpf-dev:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.ebpf-dev
    privileged: true
    pid: host
    volumes:
      - ../..:/workspace
      - /sys/kernel/btf:/sys/kernel/btf:ro
      - /sys/kernel/debug:/sys/kernel/debug:ro
    working_dir: /workspace
    command: ["sleep", "infinity"]

  test-runner:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile.ebpf-dev
    privileged: true
    pid: host
    volumes:
      - ../..:/workspace
      - /sys/kernel/btf:/sys/kernel/btf:ro
      - /sys/kernel/debug:/sys/kernel/debug:ro
    working_dir: /workspace
    command: ["sh", "-c", "make generate-vmlinux && make generate-ebpf && make build && make test-integration"]
    depends_on:
      - ebpf-dev
```

- [ ] **Step 6: Create Makefile**

```makefile
.PHONY: generate build test test-integration test-smoke docker-build clean

DOCKER_COMPOSE := docker compose -f deploy/docker/docker-compose.yml

# Generate vmlinux.h from running kernel BTF (requires bpftool + /sys/kernel/btf)
generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/c/headers/vmlinux.h

# Generate protobuf Go code
generate-proto:
	protoc --go_out=. --go_opt=module=github.com/athosone/aisre proto/events/v1/http.proto

# Run bpf2go to compile eBPF C and generate Go bindings
generate-ebpf:
	cd ebpf && go generate ./...

generate: generate-proto generate-ebpf

# Build the collector binary
build: generate
	cd ebpf && go build -o ../bin/collector ./cmd/collector/

# Run unit tests (no kernel needed)
test:
	cd ebpf && go test ./internal/... -v

# Run integration tests inside Docker (requires privileged)
test-integration:
	cd integration && go test -v -count=1 -timeout 120s ./...

# Full smoke test: docker build + integration
test-smoke: docker-build
	$(DOCKER_COMPOSE) run --rm test-runner

# Build the dev Docker image
docker-build:
	$(DOCKER_COMPOSE) build

clean:
	rm -rf bin/
	find . -name '*_bpfel.go' -o -name '*_bpfeb.go' -o -name '*_bpfel.o' -o -name '*_bpfeb.o' | xargs rm -f
```

- [ ] **Step 7: Commit scaffold**

```bash
git add .gitignore Makefile proto/ ebpf/go.mod deploy/
git commit -m "feat: add monorepo scaffold with proto, Makefile, Docker dev environment"
```

---

## Task 2: Shared BPF Headers

**Files:**
- Create: `ebpf/c/headers/common.h`
- Create: `ebpf/c/headers/http_detect.h`

- [ ] **Step 1: Create common.h**

Contains all shared structs, map definitions, and constants that both `tcp_tracker.c` and `http_capture.c` will include. This is the contract between kernel and userspace.

```c
#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD_CAPTURE 512
#define AF_INET 2

// Key for connection and pending maps
struct conn_key {
    __u64 pid_tgid;
    __u32 fd;
};

// Connection info stored in conn_info_map
struct conn_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 established_ns;
};

// Scratch space for correlating syscall enter/exit
struct active_syscall {
    __u32 fd;
    const char *buf_ptr;
    __u64 entry_ts;
};

// Pending connect info
struct pending_conn {
    __u32 dst_ip;
    __u16 dst_port;
    __u64 timestamp;
};

// Runtime config
struct config {
    __u32 logical_capture_bytes;
};

// Event emitted to ring buffer — layout must match Go events.HTTPEvent exactly
struct http_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  direction;  // 0 = request (write/send), 1 = response (read/recv)
    __u8  _pad[3];
    __u32 payload_len;
    __u32 captured_len;
    __u8  payload[MAX_PAYLOAD_CAPTURE];
} __attribute__((packed));

// --- Shared maps ---

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} conn_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct conn_key);
    __type(value, struct pending_conn);
} pending_connect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct active_syscall);
} active_syscall_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096); // 1MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

#endif /* __COMMON_H__ */
```

- [ ] **Step 2: Create http_detect.h**

```c
#ifndef __HTTP_DETECT_H__
#define __HTTP_DETECT_H__

// Check if buffer starts with an HTTP method or response signature.
// Returns 1 if HTTP detected, 0 otherwise.
static __always_inline int is_http(const __u8 *buf, __u32 len) {
    if (len < 4)
        return 0;

    // HTTP response: "HTTP/"
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P')
        return 1;

    // GET
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return 1;

    // PUT
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return 1;

    if (len < 5)
        return 0;

    // POST
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
        return 1;

    // HEAD
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ')
        return 1;

    if (len < 6)
        return 0;

    // PATCH
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ')
        return 1;

    if (len < 7)
        return 0;

    // DELETE
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ')
        return 1;

    if (len < 8)
        return 0;

    // OPTIONS
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' &&
        buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ')
        return 1;

    // CONNECT
    if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' &&
        buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T' && buf[7] == ' ')
        return 1;

    return 0;
}

#endif /* __HTTP_DETECT_H__ */
```

- [ ] **Step 3: Commit headers**

```bash
git add ebpf/c/headers/
git commit -m "feat: add shared BPF headers with structs, maps, and HTTP detection"
```

---

## Task 3: Go Event Struct and Decoder

**Files:**
- Create: `ebpf/internal/events/events.go`
- Create: `ebpf/internal/events/events_test.go`

- [ ] **Step 1: Write failing deserialization tests**

Create `ebpf/internal/events/events_test.go` with tests for:
- Decoding a valid raw event with known fields (pid, ports, direction, payload)
- Rejecting truncated input (too short)
- `CapturedPayload()` returning only the meaningful bytes

See full plan Task 5 for exact test code.

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ebpf && go test ./internal/events/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement events.go**

The Go struct mirrors the packed C `http_event` exactly:
- Field order and sizes match the C struct byte-for-byte
- `DecodeHTTPEvent()` reads fields at fixed offsets using `binary.LittleEndian`
- `CapturedPayload()` returns `Payload[:CapturedLen]`
- Constants: `MaxPayloadCapture = 512`, `HTTPEventSize = 544`, `DirectionRequest = 0`, `DirectionResponse = 1`

See full plan Task 5 for exact implementation.

- [ ] **Step 4: Run tests**

Run: `cd ebpf && go test ./internal/events/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/events/
git commit -m "feat: add Go event struct and decoder matching packed C layout"
```

---

## Task 4: HTTP Parser

**Files:**
- Create: `ebpf/internal/parser/http.go`
- Create: `ebpf/internal/parser/http_test.go`

- [ ] **Step 1: Write failing parser tests**

Table-driven tests covering:
- Simple GET, POST, DELETE request parsing (method, path, version)
- Empty input, non-HTTP input, truncated request line → errors
- Duplicate headers preserved (e.g., two `Accept` headers)
- Body extraction from POST with Content-Length
- Response parsing: 200 OK, 404 Not Found
- Non-HTTP-response input → error

See full plan Task 6 for exact test code.

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement http.go**

Types: `Header{Key, Value}`, `HTTPRequestParsed`, `HTTPResponseParsed`

`ParseHTTPRequest(data []byte)`:
- Find CRLF, split request line into method/path/version
- Validate method against known HTTP methods
- Parse headers (preserving duplicates via `[]Header`)
- Extract body after `\r\n\r\n`

`ParseHTTPResponse(data []byte)`:
- Verify starts with `HTTP/`
- Parse status line into version/code/text
- Parse headers and body same as request

See full plan Task 6 for exact implementation.

- [ ] **Step 4: Run tests**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/parser/http.go ebpf/internal/parser/http_test.go
git commit -m "feat: add HTTP request/response parser with header preservation"
```

---

## Task 5: Request/Response Correlator

**Files:**
- Create: `ebpf/internal/parser/correlator.go`
- Create: `ebpf/internal/parser/correlator_test.go`

- [ ] **Step 1: Write failing correlator tests**

Tests covering:
- Request then response → produces `CorrelatedPair` with correct latency
- Request only → nil (no pair yet)
- Timeout → `EvictExpired()` returns unmatched request with nil response
- Response before request → dropped (nil)
- Two requests on different ports → correct pairing by connection key

See full plan Task 7 for exact test code.

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ebpf && go test ./internal/parser/ -v -run TestCorrelate`
Expected: FAIL — `NewCorrelator` does not exist.

- [ ] **Step 3: Implement correlator.go**

Types: `CorrelatedPair`, `ProcessInfo`, `ConnectionInfo`, `connKey`

`Correlator` uses a `map[connKey]*pendingRequest` protected by `sync.Mutex`.
- `Feed(event)`: on request → store in pending; on response → match by connKey, compute latency, return pair
- `EvictExpired()`: remove entries older than timeout, return as pairs with nil Response
- `connKey` includes `{Pid, Tid, SrcIP, DstIP, SrcPort, DstPort}`

The `CorrelatedPair` includes `TimestampNs` from the original request event.

See full plan Task 7 for exact implementation.

- [ ] **Step 4: Run tests**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/parser/correlator.go ebpf/internal/parser/correlator_test.go
git commit -m "feat: add request/response correlator with time-windowed matching"
```

---

## Task 6: JSON Output Emitter

**Files:**
- Create: `ebpf/internal/output/emitter.go`
- Create: `ebpf/internal/output/json.go`
- Create: `ebpf/internal/output/json_test.go`

- [ ] **Step 1: Write failing JSON emitter tests**

Tests covering:
- Emit a full pair → valid JSON with request.method, response.status_code, latency_ns
- IP formatting: uint32 `0x0100007F` → `"127.0.0.1"`
- Body encoded as base64 in output

See full plan Task 8 for exact test code.

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ebpf && go test ./internal/output/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Create emitter.go (interface)**

```go
type Emitter interface {
    Emit(ctx context.Context, pair *parser.CorrelatedPair) error
    Close() error
}
```

- [ ] **Step 4: Create json.go (implementation)**

`JSONEmitter` writes one JSON line per event to an `io.Writer`:
- Converts `CorrelatedPair` to a flat JSON structure with nested `process`, `connection`, `request`, `response`
- IPs converted from uint32 to dotted-decimal via `ipToString()`
- Body bytes base64-encoded
- Uses `pair.TimestampNs` (not from the parsed request)

See full plan Task 8 for exact implementation.

- [ ] **Step 5: Run tests**

Run: `cd ebpf && go test ./internal/output/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add ebpf/internal/output/
git commit -m "feat: add Emitter interface and JSON stdout implementation"
```

---

## Task 7: Integration Test Skeleton

**Files:**
- Create: `integration/go.mod`
- Create: `integration/integration_test.go`

- [ ] **Step 1: Initialize integration module**

Run:
```bash
mkdir -p integration && cd integration && go mod init github.com/athosone/aisre/integration
```

- [ ] **Step 2: Create integration_test.go skeleton**

This runs inside Docker with eBPF capabilities. Tests:
- `TestCaptureHTTPGet`: start HTTP server, start collector, send GET, read JSON from stdout, assert method/path
- `TestCaptureHTTPPost`: same pattern with POST + body
- `TestCapturePayloadTruncation`: 1KB response body, verify capture still works
- Helper: `readEvent(t, reader, timeout)` reads one JSON line from collector stdout

See full plan Task 11 for exact test code.

- [ ] **Step 3: Create testdata directory**

```bash
mkdir -p ebpf/testdata
```

- [ ] **Step 4: Commit**

```bash
git add integration/ ebpf/testdata/
git commit -m "feat: add integration test skeleton and testdata directory"
```

---

## Task 8: Tutorial — eBPF Learning Guide

**Files:**
- Create: `tutorial/README.md`
- Create: `tutorial/01-ebpf-concepts.md`
- Create: `tutorial/02-tcp-tracker.md`
- Create: `tutorial/03-http-capture.md`
- Create: `tutorial/04-loader-and-bpf2go.md`
- Create: `tutorial/05-collector-main.md`

- [ ] **Step 1: Create tutorial/README.md** — overview and learning path
- [ ] **Step 2: Create tutorial/01-ebpf-concepts.md** — eBPF primer focused on what you need for this project
- [ ] **Step 3: Create tutorial/02-tcp-tracker.md** — step-by-step guide to implement tcp_tracker.c
- [ ] **Step 4: Create tutorial/03-http-capture.md** — step-by-step guide to implement http_capture.c
- [ ] **Step 5: Create tutorial/04-loader-and-bpf2go.md** — guide to implement Go loader + bpf2go
- [ ] **Step 6: Create tutorial/05-collector-main.md** — guide to wire main.go and run integration tests
- [ ] **Step 7: Commit tutorial**

```bash
git add tutorial/
git commit -m "docs: add eBPF implementation tutorial for kernel programs and loader"
```

---

## Task 9: Verify Unit Tests Pass

- [ ] **Step 1: Run all unit tests**

Run: `cd ebpf && go test ./internal/... -v`
Expected: All tests pass (events, parser, output).

- [ ] **Step 2: Run go vet**

Run: `cd ebpf && go vet ./...`
Expected: No issues.
