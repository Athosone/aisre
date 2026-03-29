# eBPF HTTP Traffic Capture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an eBPF-based HTTP traffic capture system that hooks syscall tracepoints, filters HTTP in-kernel, and emits structured JSON events to stdout via a Go collector.

**Architecture:** Two eBPF C programs (tcp_tracker for connection tracking, http_capture for payload capture) attach to syscall tracepoints and communicate via shared BPF maps. A Go userspace collector built with cilium/ebpf reads events from a BPF ring buffer, parses HTTP, correlates request/response pairs, and emits JSON conforming to a shared protobuf schema.

**Tech Stack:** C (eBPF programs, BPF CO-RE), Go (userspace collector, cilium/ebpf, bpf2go), Protocol Buffers, Docker (testing)

**Spec:** `docs/superpowers/specs/2026-03-29-ebpf-http-capture-design.md`

---

## File Map

```
aisre/
├── proto/
│   └── events/
│       └── v1/
│           └── http.proto                          # Protobuf event definitions
├── ebpf/
│   ├── c/
│   │   ├── headers/
│   │   │   ├── vmlinux.h                           # BTF kernel type definitions (generated)
│   │   │   ├── common.h                            # Shared structs, map definitions, constants
│   │   │   └── http_detect.h                       # HTTP signature detection helpers
│   │   ├── tcp_tracker.c                           # Connection tracking eBPF program
│   │   └── http_capture.c                          # HTTP capture eBPF program
│   ├── cmd/
│   │   └── collector/
│   │       └── main.go                             # Entry point: CLI flags, lifecycle, signal handling
│   ├── internal/
│   │   ├── loader/
│   │   │   └── loader.go                           # eBPF program loading, tracepoint attachment
│   │   ├── events/
│   │   │   ├── events.go                           # Go event struct, ring buffer reader
│   │   │   └── events_test.go                      # Deserialization tests
│   │   ├── parser/
│   │   │   ├── http.go                             # HTTP request/response parsing from bytes
│   │   │   ├── http_test.go                        # HTTP parsing tests
│   │   │   ├── correlator.go                       # Request/response pairing + latency
│   │   │   └── correlator_test.go                  # Correlation tests
│   │   └── output/
│   │       ├── emitter.go                          # Emitter interface
│   │       ├── json.go                             # JSONStdoutEmitter implementation
│   │       └── json_test.go                        # JSON output tests
│   ├── testdata/
│   │   ├── http_get_request.bin                    # Raw bytes fixture
│   │   ├── http_post_request.bin                   # Raw bytes fixture
│   │   └── http_200_response.bin                   # Raw bytes fixture
│   └── go.mod
├── deploy/
│   └── docker/
│       ├── Dockerfile.ebpf-dev                     # Build + test environment
│       └── docker-compose.yml                      # Integration test orchestration
├── integration/
│   ├── integration_test.go                         # eBPF integration tests (run in Docker)
│   └── go.mod
├── Makefile                                        # Top-level build orchestration
└── .gitignore
```

---

## Task 1: Monorepo Scaffold and Build Tooling

**Files:**
- Create: `Makefile`
- Create: `ebpf/go.mod`
- Create: `proto/events/v1/http.proto`
- Create: `deploy/docker/Dockerfile.ebpf-dev`
- Create: `deploy/docker/docker-compose.yml`
- Create: `.gitignore`

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

- [ ] **Step 3: Initialize Go module for ebpf/**

Run:
```bash
cd ebpf && go mod init github.com/athosone/aisre/ebpf
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

# Generate vmlinux.h from running kernel's BTF
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h

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
    command: ["make", "test-integration"]
    depends_on:
      - ebpf-dev
```

- [ ] **Step 6: Create top-level Makefile**

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

## Task 2: Shared BPF Headers and Structs

**Files:**
- Create: `ebpf/c/headers/common.h`
- Create: `ebpf/c/headers/http_detect.h`

- [ ] **Step 1: Create common.h with shared structs and map definitions**

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

// Event emitted to ring buffer
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

// --- Shared maps (extern in http_capture.c, defined in tcp_tracker.c) ---

// Connection tracking: {pid_tgid, fd} -> conn_info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} conn_info_map SEC(".maps");

// Pending connect() calls: {pid_tgid, fd} -> pending_conn
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct conn_key);
    __type(value, struct pending_conn);
} pending_connect_map SEC(".maps");

// Syscall enter/exit scratch: pid_tgid -> active_syscall
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct active_syscall);
} active_syscall_map SEC(".maps");

// Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096); // 1MB
} events SEC(".maps");

// Runtime config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

#endif /* __COMMON_H__ */
```

- [ ] **Step 2: Create http_detect.h with HTTP signature matching**

```c
#ifndef __HTTP_DETECT_H__
#define __HTTP_DETECT_H__

// Check if buffer starts with an HTTP method or response
// Returns 1 if HTTP detected, 0 otherwise
// Only checks the first few bytes — enough for signature matching
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
git add ebpf/c/headers/common.h ebpf/c/headers/http_detect.h
git commit -m "feat: add shared BPF headers with structs, maps, and HTTP detection"
```

---

## Task 3: TCP Connection Tracker eBPF Program

**Files:**
- Create: `ebpf/c/tcp_tracker.c`

- [ ] **Step 1: Create tcp_tracker.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"

char LICENSE[] SEC("license") = "GPL";

// --- Client-side: sys_enter_connect / sys_exit_connect ---

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    // Only handle AF_INET (IPv4)
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET)
        return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct conn_key key = {
        .pid_tgid = pid_tgid,
        .fd = (__u32)fd,
    };

    struct pending_conn pending = {
        .dst_ip = sin.sin_addr.s_addr,
        .dst_port = bpf_ntohs(sin.sin_port),
        .timestamp = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&pending_connect_map, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;

    // connect() returns 0 on success, or -EINPROGRESS for non-blocking
    if (ret != 0 && ret != -115) // -EINPROGRESS = -115
        goto cleanup;

    // We need the fd from the enter call — look up pending
    // Iterate is not allowed in BPF, so we need a scratch map for the fd.
    // Alternative: store fd in a per-CPU scratch map on enter, read on exit.
    // For now, we use a per-CPU map keyed by pid_tgid to pass the fd.
    // Actually, we stored it in pending_connect_map with the fd in the key,
    // but on exit we don't have the fd from args. We need a second scratch map.

    // Scratch: pid_tgid -> fd (saved on enter)
    // This is handled by reusing active_syscall_map for the fd pass-through.
    goto cleanup; // Promotion happens via inet_sock_set_state ESTABLISHED

cleanup:
    return 0;
}

// --- Server-side: sys_enter_accept4 / sys_exit_accept4 ---

// Scratch map for accept: pid_tgid -> 1 (just marks that accept is in progress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} accept_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 val = 1;
    bpf_map_update_elem(&accept_scratch, &pid_tgid, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Clean up scratch
    bpf_map_delete_elem(&accept_scratch, &pid_tgid);

    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    // The 4-tuple will be filled by inet_sock_set_state when ESTABLISHED.
    // For now, create a placeholder entry so http_capture can find it.
    struct conn_key key = {
        .pid_tgid = pid_tgid,
        .fd = (__u32)fd,
    };

    struct conn_info info = {
        .established_ns = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&conn_info_map, &key, &info, BPF_ANY);
    return 0;
}

// --- Connection lifecycle: inet_sock_set_state ---

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Only handle AF_INET
    if (ctx->family != AF_INET)
        return 0;

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    __u32 src_ip = ctx->saddr[0];
    __u32 dst_ip = ctx->daddr[0];
    __u16 src_port = ctx->sport;
    __u16 dst_port = bpf_ntohs(ctx->dport);

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (newstate == BPF_TCP_ESTABLISHED) {
        // Try to find and enrich an existing entry (from accept or connect).
        // We need to scan by pid_tgid — but we don't know the fd here.
        // Strategy: for pending connects, match by dst_ip:dst_port.
        // For accepts, the placeholder already exists.
        //
        // For connect: promote from pending_connect_map.
        // We iterate conceptually by having stored the fd on enter_connect.
        // Since BPF can't iterate maps, we use a pid_tgid->fd scratch.

        // For accepted connections, the fd is already in conn_info_map
        // but without the 4-tuple. We can't easily find it by pid_tgid alone
        // without the fd. In practice, the accept exit already has the fd.
        //
        // Simplified approach: store a pid_tgid -> last_fd map on connect/accept
        // enter, so we can retrieve it here.

        // This is a known complexity — for now, we enrich based on a
        // pid_tgid -> fd lookup via connect_fd_scratch.
        return 0;
    }

    if (newstate == BPF_TCP_CLOSE) {
        // Cleanup: we can't easily find the exact fd, but connection is done.
        // Userspace should handle stale entries via TTL.
        return 0;
    }

    return 0;
}
```

**Note:** The `inet_sock_set_state` handler has inherent complexity because it doesn't provide the fd. The implementation above documents this limitation. The practical approach is:
- `sys_exit_connect` promotes pending entries using a `connect_fd_scratch` per-CPU map (pid_tgid -> fd saved on enter)
- `sys_exit_accept4` creates the entry directly with the fd from the return value
- `inet_sock_set_state` enriches entries where possible, and handles cleanup

- [ ] **Step 2: Refine tcp_tracker.c with fd scratch maps for connect**

Replace the `sys_enter_connect` and `sys_exit_connect` handlers with a working fd-passing approach:

```c
// Per-CPU scratch: pid_tgid -> fd (passed from sys_enter_connect to sys_exit_connect)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u32);
} connect_fd_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET)
        return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    // Save fd for sys_exit_connect
    bpf_map_update_elem(&connect_fd_scratch, &pid_tgid, &fd, BPF_ANY);

    // Save pending connection info
    struct conn_key key = {
        .pid_tgid = pid_tgid,
        .fd = fd,
    };

    struct pending_conn pending = {
        .dst_ip = sin.sin_addr.s_addr,
        .dst_port = bpf_ntohs(sin.sin_port),
        .timestamp = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&pending_connect_map, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;

    __u32 *fd_ptr = bpf_map_lookup_elem(&connect_fd_scratch, &pid_tgid);
    if (!fd_ptr)
        return 0;
    __u32 fd = *fd_ptr;
    bpf_map_delete_elem(&connect_fd_scratch, &pid_tgid);

    // connect() returns 0 on success, -EINPROGRESS (-115) for non-blocking
    if (ret != 0 && ret != -115) {
        // Failed connect — clean up pending
        struct conn_key key = { .pid_tgid = pid_tgid, .fd = fd };
        bpf_map_delete_elem(&pending_connect_map, &key);
        return 0;
    }

    // Promote pending to conn_info_map
    struct conn_key key = { .pid_tgid = pid_tgid, .fd = fd };

    struct pending_conn *pending = bpf_map_lookup_elem(&pending_connect_map, &key);
    if (!pending)
        return 0;

    struct conn_info info = {
        .dst_ip = pending->dst_ip,
        .dst_port = pending->dst_port,
        // src_ip and src_port will be filled by inet_sock_set_state
        // or can be read from the socket, but that requires complex
        // kernel struct traversal. For now, leave as 0 — userspace
        // can infer local address if needed.
        .established_ns = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&conn_info_map, &key, &info, BPF_ANY);
    bpf_map_delete_elem(&pending_connect_map, &key);

    return 0;
}
```

- [ ] **Step 3: Commit tcp_tracker.c**

```bash
git add ebpf/c/tcp_tracker.c
git commit -m "feat: add TCP connection tracker eBPF program with connect/accept tracking"
```

---

## Task 4: HTTP Capture eBPF Program

**Files:**
- Create: `ebpf/c/http_capture.c`

- [ ] **Step 1: Create http_capture.c**

```c
// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"
#include "headers/http_detect.h"

char LICENSE[] SEC("license") = "GPL";

// Helper: save syscall enter state if fd is a tracked connection
static __always_inline int handle_syscall_enter(__u64 pid_tgid, __u32 fd, const char *buf) {
    // Early discard: check if this fd belongs to a tracked connection
    struct conn_key ck = { .pid_tgid = pid_tgid, .fd = fd };
    struct conn_info *ci = bpf_map_lookup_elem(&conn_info_map, &ck);
    if (!ci)
        return 0; // Not a tracked socket — skip

    struct active_syscall as = {
        .fd = fd,
        .buf_ptr = buf,
        .entry_ts = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&active_syscall_map, &pid_tgid, &as, BPF_ANY);
    return 0;
}

// Helper: on syscall exit, read buffer, detect HTTP, emit event
static __always_inline int handle_syscall_exit(__u64 pid_tgid, long ret, __u8 direction) {
    if (ret <= 0)
        goto cleanup;

    struct active_syscall *as = bpf_map_lookup_elem(&active_syscall_map, &pid_tgid);
    if (!as)
        return 0;

    __u32 payload_len = (__u32)ret;

    // Read first MAX_PAYLOAD_CAPTURE bytes from userspace buffer
    __u8 buf[MAX_PAYLOAD_CAPTURE] = {};
    __u32 to_read = payload_len;
    if (to_read > MAX_PAYLOAD_CAPTURE)
        to_read = MAX_PAYLOAD_CAPTURE;

    // BPF verifier needs the bound check above to prove safety
    if (bpf_probe_read_user(buf, to_read & (MAX_PAYLOAD_CAPTURE - 1), as->buf_ptr) < 0)
        goto cleanup;

    // Check for HTTP signature
    if (!is_http(buf, to_read))
        goto cleanup;

    // Apply logical capture limit from config
    __u32 captured_len = to_read;
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (cfg && cfg->logical_capture_bytes > 0 && cfg->logical_capture_bytes < captured_len)
        captured_len = cfg->logical_capture_bytes;

    // Look up connection info
    struct conn_key ck = { .pid_tgid = pid_tgid, .fd = as->fd };
    struct conn_info *ci = bpf_map_lookup_elem(&conn_info_map, &ck);

    // Reserve ring buffer space and emit event
    struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!event)
        goto cleanup;

    event->timestamp_ns = as->entry_ts;
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->direction = direction;
    event->_pad[0] = 0;
    event->_pad[1] = 0;
    event->_pad[2] = 0;
    event->payload_len = payload_len;
    event->captured_len = captured_len;

    if (ci) {
        event->src_ip = ci->src_ip;
        event->dst_ip = ci->dst_ip;
        event->src_port = ci->src_port;
        event->dst_port = ci->dst_port;
    }

    // Copy payload into event
    // Use __builtin_memcpy for a bounded copy the verifier can prove
    __builtin_memcpy(event->payload, buf, MAX_PAYLOAD_CAPTURE);

    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&active_syscall_map, &pid_tgid);
    return 0;
}

// --- Tracepoints for write/sendto (direction = 0, request) ---

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    return handle_syscall_exit(bpf_get_current_pid_tgid(), ctx->ret, 0);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    return handle_syscall_exit(bpf_get_current_pid_tgid(), ctx->ret, 0);
}

// --- Tracepoints for read/recvfrom (direction = 1, response) ---

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    return handle_syscall_exit(bpf_get_current_pid_tgid(), ctx->ret, 1);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    return handle_syscall_exit(bpf_get_current_pid_tgid(), ctx->ret, 1);
}
```

- [ ] **Step 2: Commit http_capture.c**

```bash
git add ebpf/c/http_capture.c
git commit -m "feat: add HTTP capture eBPF program with syscall tracepoints and ring buffer"
```

---

## Task 5: Go Event Struct and Ring Buffer Reader

**Files:**
- Create: `ebpf/internal/events/events.go`
- Create: `ebpf/internal/events/events_test.go`
- Create: `ebpf/testdata/http_get_request.bin`

- [ ] **Step 1: Write the failing deserialization test**

Create `ebpf/internal/events/events_test.go`:

```go
package events_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/athosone/aisre/ebpf/internal/events"
)

func TestDecodeHTTPEvent(t *testing.T) {
	// Build a raw event matching the packed C struct layout
	payload := []byte("GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
	raw := buildRawEvent(t, rawEventFields{
		TimestampNs: 1000000,
		Pid:         1234,
		Tid:         1234,
		Uid:         0,
		SrcIP:       0x0100007F, // 127.0.0.1 in network byte order
		DstIP:       0x0100007F,
		SrcPort:     54321,
		DstPort:     8080,
		Direction:   0,
		PayloadLen:  uint32(len(payload)),
		CapturedLen: uint32(len(payload)),
		Payload:     payload,
	})

	event, err := events.DecodeHTTPEvent(raw)
	if err != nil {
		t.Fatalf("DecodeHTTPEvent() error = %v", err)
	}

	if event.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", event.Pid)
	}
	if event.DstPort != 8080 {
		t.Errorf("DstPort = %d, want 8080", event.DstPort)
	}
	if event.Direction != events.DirectionRequest {
		t.Errorf("Direction = %d, want DirectionRequest", event.Direction)
	}
	if event.CapturedLen != uint32(len(payload)) {
		t.Errorf("CapturedLen = %d, want %d", event.CapturedLen, len(payload))
	}
	if !bytes.Equal(event.Payload[:event.CapturedLen], payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestDecodeHTTPEventTruncated(t *testing.T) {
	// Test with payload shorter than MAX_PAYLOAD_CAPTURE
	raw := make([]byte, 10) // Too short to be valid
	_, err := events.DecodeHTTPEvent(raw)
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

type rawEventFields struct {
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Uid         uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Direction   uint8
	PayloadLen  uint32
	CapturedLen uint32
	Payload     []byte
}

func buildRawEvent(t *testing.T, f rawEventFields) []byte {
	t.Helper()
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, f.TimestampNs)
	binary.Write(&buf, binary.LittleEndian, f.Pid)
	binary.Write(&buf, binary.LittleEndian, f.Tid)
	binary.Write(&buf, binary.LittleEndian, f.Uid)
	binary.Write(&buf, binary.LittleEndian, f.SrcIP)
	binary.Write(&buf, binary.LittleEndian, f.DstIP)
	binary.Write(&buf, binary.LittleEndian, f.SrcPort)
	binary.Write(&buf, binary.LittleEndian, f.DstPort)
	binary.Write(&buf, binary.LittleEndian, f.Direction)
	buf.Write([]byte{0, 0, 0}) // _pad[3]
	binary.Write(&buf, binary.LittleEndian, f.PayloadLen)
	binary.Write(&buf, binary.LittleEndian, f.CapturedLen)
	// Payload: pad to MAX_PAYLOAD_CAPTURE
	padded := make([]byte, events.MaxPayloadCapture)
	copy(padded, f.Payload)
	buf.Write(padded)
	return buf.Bytes()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ebpf && go test ./internal/events/ -v`
Expected: FAIL — package `events` does not exist yet.

- [ ] **Step 3: Write events.go**

Create `ebpf/internal/events/events.go`:

```go
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

// Size of the packed struct in bytes.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ebpf && go test ./internal/events/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/events/
git commit -m "feat: add Go event struct and decoder matching packed C struct layout"
```

---

## Task 6: HTTP Parser

**Files:**
- Create: `ebpf/internal/parser/http.go`
- Create: `ebpf/internal/parser/http_test.go`

- [ ] **Step 1: Write failing HTTP parser tests**

Create `ebpf/internal/parser/http_test.go`:

```go
package parser_test

import (
	"testing"

	"github.com/athosone/aisre/ebpf/internal/parser"
)

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantMethod string
		wantPath   string
		wantVer    string
		wantErr    bool
	}{
		{
			name:       "simple GET",
			input:      []byte("GET /api/health HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.81\r\n\r\n"),
			wantMethod: "GET",
			wantPath:   "/api/health",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "POST with body",
			input:      []byte("POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}"),
			wantMethod: "POST",
			wantPath:   "/api/data",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "DELETE",
			input:      []byte("DELETE /api/items/42 HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			wantMethod: "DELETE",
			wantPath:   "/api/items/42",
			wantVer:    "HTTP/1.1",
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "not HTTP",
			input:   []byte("some random data"),
			wantErr: true,
		},
		{
			name:    "truncated request line",
			input:   []byte("GET /ap"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parser.ParseHTTPRequest(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", req.Method, tt.wantMethod)
			}
			if req.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", req.Path, tt.wantPath)
			}
			if req.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", req.Version, tt.wantVer)
			}
		})
	}
}

func TestParseHTTPRequestHeaders(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n")
	req, err := parser.ParseHTTPRequest(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should preserve duplicate headers
	acceptCount := 0
	for _, h := range req.Headers {
		if h.Key == "Accept" {
			acceptCount++
		}
	}
	if acceptCount != 2 {
		t.Errorf("expected 2 Accept headers, got %d", acceptCount)
	}
}

func TestParseHTTPRequestBody(t *testing.T) {
	body := `{"hello":"world"}`
	input := []byte("POST /data HTTP/1.1\r\nContent-Length: 17\r\n\r\n" + body)
	req, err := parser.ParseHTTPRequest(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(req.PartialBody) != body {
		t.Errorf("Body = %q, want %q", string(req.PartialBody), body)
	}
}

func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantStatus uint32
		wantText   string
		wantVer    string
		wantErr    bool
	}{
		{
			name:       "200 OK",
			input:      []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"),
			wantStatus: 200,
			wantText:   "OK",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "404 Not Found",
			input:      []byte("HTTP/1.1 404 Not Found\r\n\r\n"),
			wantStatus: 404,
			wantText:   "Not Found",
			wantVer:    "HTTP/1.1",
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "not HTTP response",
			input:   []byte("GET /foo HTTP/1.1\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := parser.ParseHTTPResponse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if resp.StatusText != tt.wantText {
				t.Errorf("StatusText = %q, want %q", resp.StatusText, tt.wantText)
			}
			if resp.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", resp.Version, tt.wantVer)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement http.go**

Create `ebpf/internal/parser/http.go`:

```go
package parser

import (
	"bytes"
	"fmt"
	"strconv"
)

// Header represents a single HTTP header key-value pair.
type Header struct {
	Key   string
	Value string
}

// HTTPRequestParsed is the result of parsing raw HTTP request bytes.
type HTTPRequestParsed struct {
	Method      string
	Path        string
	Version     string
	Headers     []Header
	PartialBody []byte
}

// HTTPResponseParsed is the result of parsing raw HTTP response bytes.
type HTTPResponseParsed struct {
	StatusCode uint32
	StatusText string
	Version    string
	Headers    []Header
	PartialBody []byte
}

var crlf = []byte("\r\n")
var doubleCRLF = []byte("\r\n\r\n")

// ParseHTTPRequest parses raw bytes into a structured HTTP request.
// Only parses the first segment — does not handle multi-read reassembly.
func ParseHTTPRequest(data []byte) (*HTTPRequestParsed, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Find end of request line
	lineEnd := bytes.Index(data, crlf)
	if lineEnd < 0 {
		return nil, fmt.Errorf("no CRLF found in request line")
	}

	requestLine := string(data[:lineEnd])

	// Parse "METHOD PATH VERSION"
	parts := bytes.SplitN(data[:lineEnd], []byte(" "), 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line: %q", requestLine)
	}

	method := string(parts[0])
	if !isValidMethod(method) {
		return nil, fmt.Errorf("invalid HTTP method: %q", method)
	}

	req := &HTTPRequestParsed{
		Method:  method,
		Path:    string(parts[1]),
		Version: string(parts[2]),
	}

	// Parse headers
	headerStart := lineEnd + 2 // skip \r\n
	headers, bodyStart, err := parseHeaders(data[headerStart:])
	if err != nil {
		return req, nil // Return what we have without headers
	}
	req.Headers = headers

	// Extract body (everything after \r\n\r\n)
	absBodyStart := headerStart + bodyStart
	if absBodyStart < len(data) {
		req.PartialBody = data[absBodyStart:]
	}

	return req, nil
}

// ParseHTTPResponse parses raw bytes into a structured HTTP response.
func ParseHTTPResponse(data []byte) (*HTTPResponseParsed, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Must start with "HTTP/"
	if len(data) < 5 || string(data[:5]) != "HTTP/" {
		return nil, fmt.Errorf("not an HTTP response")
	}

	lineEnd := bytes.Index(data, crlf)
	if lineEnd < 0 {
		return nil, fmt.Errorf("no CRLF found in status line")
	}

	// Parse "HTTP/1.1 200 OK"
	statusLine := data[:lineEnd]

	// Split into version, status code, status text
	firstSpace := bytes.IndexByte(statusLine, ' ')
	if firstSpace < 0 {
		return nil, fmt.Errorf("malformed status line")
	}

	version := string(statusLine[:firstSpace])
	rest := statusLine[firstSpace+1:]

	secondSpace := bytes.IndexByte(rest, ' ')
	var codeStr, statusText string
	if secondSpace < 0 {
		codeStr = string(rest)
		statusText = ""
	} else {
		codeStr = string(rest[:secondSpace])
		statusText = string(rest[secondSpace+1:])
	}

	code, err := strconv.ParseUint(codeStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %q", codeStr)
	}

	resp := &HTTPResponseParsed{
		StatusCode: uint32(code),
		StatusText: statusText,
		Version:    version,
	}

	// Parse headers
	headerStart := lineEnd + 2
	headers, bodyStart, err := parseHeaders(data[headerStart:])
	if err != nil {
		return resp, nil
	}
	resp.Headers = headers

	absBodyStart := headerStart + bodyStart
	if absBodyStart < len(data) {
		resp.PartialBody = data[absBodyStart:]
	}

	return resp, nil
}

// parseHeaders parses HTTP headers from data starting after the request/status line.
// Returns the parsed headers and the offset where the body starts (after \r\n\r\n).
func parseHeaders(data []byte) ([]Header, int, error) {
	var headers []Header

	bodyMarker := bytes.Index(data, doubleCRLF)
	var headerBlock []byte
	var bodyStart int

	if bodyMarker >= 0 {
		headerBlock = data[:bodyMarker]
		bodyStart = bodyMarker + 4 // skip \r\n\r\n
	} else {
		// No body marker — parse what we have
		headerBlock = data
		bodyStart = len(data)
	}

	lines := bytes.Split(headerBlock, crlf)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			continue // skip malformed header lines
		}
		key := string(line[:colonIdx])
		value := string(bytes.TrimLeft(line[colonIdx+1:], " "))
		headers = append(headers, Header{Key: key, Value: value})
	}

	return headers, bodyStart, nil
}

func isValidMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT":
		return true
	}
	return false
}
```

- [ ] **Step 4: Run tests**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/parser/http.go ebpf/internal/parser/http_test.go
git commit -m "feat: add HTTP request/response parser with header preservation"
```

---

## Task 7: Request/Response Correlator

**Files:**
- Create: `ebpf/internal/parser/correlator.go`
- Create: `ebpf/internal/parser/correlator_test.go`

- [ ] **Step 1: Write failing correlator tests**

Create `ebpf/internal/parser/correlator_test.go`:

```go
package parser_test

import (
	"testing"
	"time"

	"github.com/athosone/aisre/ebpf/internal/events"
	"github.com/athosone/aisre/ebpf/internal/parser"
)

func makeEvent(pid, tid, dstPort uint32, direction uint8, tsNs uint64, payload string) *events.HTTPEvent {
	e := &events.HTTPEvent{
		TimestampNs: tsNs,
		Pid:         pid,
		Tid:         tid,
		SrcIP:       0x0100007F,
		DstIP:       0x0100007F,
		SrcPort:     54321,
		DstPort:     uint16(dstPort),
		Direction:   direction,
		PayloadLen:  uint32(len(payload)),
		CapturedLen: uint32(len(payload)),
	}
	copy(e.Payload[:], payload)
	return e
}

func TestCorrelateRequestResponse(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	req := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")

	// Feed request — should not produce a pair yet
	pair := c.Feed(req)
	if pair != nil {
		t.Fatal("expected nil pair for request-only")
	}

	resp := makeEvent(100, 100, 8080, events.DirectionResponse, 2_000_000,
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	// Feed response — should correlate
	pair = c.Feed(resp)
	if pair == nil {
		t.Fatal("expected correlated pair")
	}

	if pair.Request.Method != "GET" {
		t.Errorf("Method = %q, want GET", pair.Request.Method)
	}
	if pair.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", pair.Response.StatusCode)
	}
	if pair.LatencyNs != 1_000_000 {
		t.Errorf("LatencyNs = %d, want 1000000", pair.LatencyNs)
	}
}

func TestCorrelateTimeout(t *testing.T) {
	c := parser.NewCorrelator(100 * time.Millisecond)

	req := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
	c.Feed(req)

	// Wait for timeout
	time.Sleep(200 * time.Millisecond)

	// Evict expired entries
	expired := c.EvictExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}
	if expired[0].Request.Method != "GET" {
		t.Errorf("expired request Method = %q, want GET", expired[0].Request.Method)
	}
	if expired[0].Response != nil {
		t.Error("expired entry should have nil response")
	}
}

func TestCorrelateResponseBeforeRequest(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	// Response arrives first (edge case — should be dropped or buffered)
	resp := makeEvent(100, 100, 8080, events.DirectionResponse, 1_000_000,
		"HTTP/1.1 200 OK\r\n\r\n")
	pair := c.Feed(resp)
	if pair != nil {
		t.Fatal("expected nil for response-before-request")
	}
}

func TestCorrelateDifferentConnections(t *testing.T) {
	c := parser.NewCorrelator(5 * time.Second)

	// Two requests on different ports
	req1 := makeEvent(100, 100, 8080, events.DirectionRequest, 1_000_000,
		"GET /a HTTP/1.1\r\nHost: localhost\r\n\r\n")
	req2 := makeEvent(100, 100, 9090, events.DirectionRequest, 1_000_000,
		"GET /b HTTP/1.1\r\nHost: localhost\r\n\r\n")

	c.Feed(req1)
	c.Feed(req2)

	// Response for port 9090
	resp2 := makeEvent(100, 100, 9090, events.DirectionResponse, 2_000_000,
		"HTTP/1.1 404 Not Found\r\n\r\n")
	pair := c.Feed(resp2)
	if pair == nil {
		t.Fatal("expected pair")
	}
	if pair.Request.Path != "/b" {
		t.Errorf("Path = %q, want /b", pair.Request.Path)
	}
	if pair.Response.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", pair.Response.StatusCode)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ebpf && go test ./internal/parser/ -v -run TestCorrelate`
Expected: FAIL — `parser.NewCorrelator` does not exist.

- [ ] **Step 3: Implement correlator.go**

Create `ebpf/internal/parser/correlator.go`:

```go
package parser

import (
	"sync"
	"time"

	"github.com/athosone/aisre/ebpf/internal/events"
)

// CorrelatedPair is a matched HTTP request/response with latency.
type CorrelatedPair struct {
	Request   *HTTPRequestParsed
	Response  *HTTPResponseParsed
	LatencyNs uint64
	Process   ProcessInfo
	Connection ConnectionInfo
}

// ProcessInfo holds process metadata from the event.
type ProcessInfo struct {
	Pid  uint32
	Tid  uint32
	Uid  uint32
	Comm string // enriched in userspace
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
	parsed     *HTTPRequestParsed
	timestampNs uint64
	process    ProcessInfo
	connection ConnectionInfo
	createdAt  time.Time
}

// Correlator matches HTTP request events with their corresponding responses.
type Correlator struct {
	timeout  time.Duration
	mu       sync.Mutex
	pending  map[connKey]*pendingRequest
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
		Request:    pending.parsed,
		Response:   parsed,
		LatencyNs:  latency,
		Process:    pending.process,
		Connection: pending.connection,
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
				Request:    req.parsed,
				Process:    req.process,
				Connection: req.connection,
			})
			delete(c.pending, key)
		}
	}

	return expired
}
```

- [ ] **Step 4: Run tests**

Run: `cd ebpf && go test ./internal/parser/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add ebpf/internal/parser/correlator.go ebpf/internal/parser/correlator_test.go
git commit -m "feat: add request/response correlator with time-windowed matching"
```

---

## Task 8: JSON Output Emitter

**Files:**
- Create: `ebpf/internal/output/emitter.go`
- Create: `ebpf/internal/output/json.go`
- Create: `ebpf/internal/output/json_test.go`

- [ ] **Step 1: Write failing JSON emitter test**

Create `ebpf/internal/output/json_test.go`:

```go
package output_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/athosone/aisre/ebpf/internal/output"
	"github.com/athosone/aisre/ebpf/internal/parser"
)

func TestJSONEmitter(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method:  "GET",
			Path:    "/api/health",
			Version: "HTTP/1.1",
			Headers: []parser.Header{
				{Key: "Host", Value: "localhost"},
			},
		},
		Response: &parser.HTTPResponseParsed{
			StatusCode: 200,
			StatusText: "OK",
			Version:    "HTTP/1.1",
			Headers: []parser.Header{
				{Key: "Content-Type", Value: "text/plain"},
			},
			PartialBody: []byte("OK"),
		},
		LatencyNs: 1_500_000,
		Process: parser.ProcessInfo{
			Pid: 1234,
			Tid: 1234,
			Uid: 0,
		},
		Connection: parser.ConnectionInfo{
			SrcIP:   0x0100007F,
			SrcPort: 54321,
			DstIP:   0x0100007F,
			DstPort: 8080,
		},
	}

	err := emitter.Emit(context.Background(), pair)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	// Should be valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	// Check key fields
	req, ok := result["request"].(map[string]interface{})
	if !ok {
		t.Fatal("missing request field")
	}
	if req["method"] != "GET" {
		t.Errorf("method = %v, want GET", req["method"])
	}
	if req["path"] != "/api/health" {
		t.Errorf("path = %v, want /api/health", req["path"])
	}

	resp, ok := result["response"].(map[string]interface{})
	if !ok {
		t.Fatal("missing response field")
	}
	if resp["status_code"].(float64) != 200 {
		t.Errorf("status_code = %v, want 200", resp["status_code"])
	}

	// Latency should be present
	if result["latency_ns"].(float64) != 1_500_000 {
		t.Errorf("latency_ns = %v, want 1500000", result["latency_ns"])
	}
}

func TestJSONEmitterIPFormatting(t *testing.T) {
	var buf bytes.Buffer
	emitter := output.NewJSONEmitter(&buf)

	pair := &parser.CorrelatedPair{
		Request: &parser.HTTPRequestParsed{
			Method: "GET", Path: "/", Version: "HTTP/1.1",
		},
		Connection: parser.ConnectionInfo{
			SrcIP:   0x0100007F, // 127.0.0.1
			SrcPort: 12345,
			DstIP:   0x0100007F,
			DstPort: 80,
		},
		Process: parser.ProcessInfo{Pid: 1},
	}

	err := emitter.Emit(context.Background(), pair)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(buf.Bytes(), &result)

	conn := result["connection"].(map[string]interface{})
	if conn["src_ip"] != "127.0.0.1" {
		t.Errorf("src_ip = %v, want 127.0.0.1", conn["src_ip"])
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cd ebpf && go test ./internal/output/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Create emitter.go (interface)**

Create `ebpf/internal/output/emitter.go`:

```go
package output

import (
	"context"

	"github.com/athosone/aisre/ebpf/internal/parser"
)

// Emitter defines the interface for outputting correlated HTTP events.
type Emitter interface {
	Emit(ctx context.Context, pair *parser.CorrelatedPair) error
	Close() error
}
```

- [ ] **Step 4: Create json.go (implementation)**

Create `ebpf/internal/output/json.go`:

```go
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
		TimestampNs: pair.Request.TimestampNs(), // will use process info
		LatencyNs:   pair.LatencyNs,
		Process:     jsonProcess{
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
```

**Note:** The test references `pair.Request.TimestampNs()` which doesn't exist on `HTTPRequestParsed`. The JSON emitter doesn't need the timestamp from the request parser — it should be stored in the `CorrelatedPair`. Let me fix both:

Update `correlator.go` to add `TimestampNs` to `CorrelatedPair`:

The `CorrelatedPair` struct already receives `timestampNs` from the pending request. Add it as a field:

```go
// In correlator.go, add to CorrelatedPair:
type CorrelatedPair struct {
	Request     *HTTPRequestParsed
	Response    *HTTPResponseParsed
	LatencyNs   uint64
	TimestampNs uint64 // from the request event
	Process     ProcessInfo
	Connection  ConnectionInfo
}
```

And in the `Feed` method, set it when creating the pair:

```go
return &CorrelatedPair{
	Request:     pending.parsed,
	Response:    parsed,
	LatencyNs:   latency,
	TimestampNs: pending.timestampNs,
	Process:     pending.process,
	Connection:  pending.connection,
}
```

Then fix `json.go` to use `pair.TimestampNs` instead of `pair.Request.TimestampNs()`:

```go
out := jsonEvent{
	TimestampNs: pair.TimestampNs,
	LatencyNs:   pair.LatencyNs,
	// ...
}
```

- [ ] **Step 5: Run tests**

Run: `cd ebpf && go test ./internal/output/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add ebpf/internal/output/
git commit -m "feat: add Emitter interface and JSON stdout implementation"
```

---

## Task 9: eBPF Loader and bpf2go Generation

**Files:**
- Create: `ebpf/internal/loader/loader.go`
- Create: `ebpf/internal/loader/gen.go` (go:generate directive)

- [ ] **Step 1: Create gen.go with bpf2go directives**

Create `ebpf/internal/loader/gen.go`:

```go
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang tcpTracker ../../c/tcp_tracker.c -- -I../../c/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang httpCapture ../../c/http_capture.c -- -I../../c/headers -D__TARGET_ARCH_x86
```

- [ ] **Step 2: Create loader.go**

Create `ebpf/internal/loader/loader.go`:

```go
package loader

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Collector holds loaded eBPF objects and their attachments.
type Collector struct {
	tcpObjs     tcpTrackerObjects
	httpObjs    httpCaptureObjects
	links       []link.Link
	ringReader  *ringbuf.Reader
}

// Config holds runtime configuration for the collector.
type Config struct {
	LogicalCaptureBytes uint32
	RingBufSizePages    int
}

// DefaultConfig returns the default collector configuration.
func DefaultConfig() Config {
	return Config{
		LogicalCaptureBytes: 512,
		RingBufSizePages:    256,
	}
}

// New loads eBPF programs and attaches them to tracepoints.
// Returns a Collector that must be closed when done.
func New(cfg Config) (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	c := &Collector{}

	// Load TCP tracker objects
	if err := loadTcpTrackerObjects(&c.tcpObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "", // no pinning
		},
	}); err != nil {
		return nil, fmt.Errorf("load tcp_tracker: %w", err)
	}

	// Load HTTP capture objects, reusing shared maps from tcp_tracker
	if err := loadHttpCaptureObjects(&c.httpObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"conn_info_map":      c.tcpObjs.ConnInfoMap,
			"pending_connect_map": c.tcpObjs.PendingConnectMap,
			"config_map":         c.tcpObjs.ConfigMap,
			"events":             c.tcpObjs.Events,
			"active_syscall_map": c.tcpObjs.ActiveSyscallMap,
		},
	}); err != nil {
		c.tcpObjs.Close()
		return nil, fmt.Errorf("load http_capture: %w", err)
	}

	// Write config
	if err := c.writeConfig(cfg); err != nil {
		c.Close()
		return nil, fmt.Errorf("write config: %w", err)
	}

	// Attach tracepoints
	if err := c.attach(); err != nil {
		c.Close()
		return nil, fmt.Errorf("attach tracepoints: %w", err)
	}

	// Create ring buffer reader
	rd, err := ringbuf.NewReader(c.tcpObjs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}
	c.ringReader = rd

	return c, nil
}

func (c *Collector) writeConfig(cfg Config) error {
	key := uint32(0)
	val := struct{ LogicalCaptureBytes uint32 }{cfg.LogicalCaptureBytes}
	return c.tcpObjs.ConfigMap.Put(key, val)
}

func (c *Collector) attach() error {
	tracepoints := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		// TCP tracker
		{"syscalls", "sys_enter_connect", c.tcpObjs.TracepointSysEnterConnect},
		{"syscalls", "sys_exit_connect", c.tcpObjs.TracepointSysExitConnect},
		{"syscalls", "sys_enter_accept4", c.tcpObjs.TracepointSysEnterAccept4},
		{"syscalls", "sys_exit_accept4", c.tcpObjs.TracepointSysExitAccept4},
		{"sock", "inet_sock_set_state", c.tcpObjs.TracepointInetSockSetState},
		// HTTP capture
		{"syscalls", "sys_enter_write", c.httpObjs.TracepointSysEnterWrite},
		{"syscalls", "sys_exit_write", c.httpObjs.TracepointSysExitWrite},
		{"syscalls", "sys_enter_read", c.httpObjs.TracepointSysEnterRead},
		{"syscalls", "sys_exit_read", c.httpObjs.TracepointSysExitRead},
		{"syscalls", "sys_enter_sendto", c.httpObjs.TracepointSysEnterSendto},
		{"syscalls", "sys_exit_sendto", c.httpObjs.TracepointSysExitSendto},
		{"syscalls", "sys_enter_recvfrom", c.httpObjs.TracepointSysEnterRecvfrom},
		{"syscalls", "sys_exit_recvfrom", c.httpObjs.TracepointSysExitRecvfrom},
	}

	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		c.links = append(c.links, l)
	}

	log.Printf("Attached %d tracepoints", len(c.links))
	return nil
}

// RingReader returns the ring buffer reader for consuming events.
func (c *Collector) RingReader() *ringbuf.Reader {
	return c.ringReader
}

// Close detaches all programs and closes resources.
func (c *Collector) Close() error {
	if c.ringReader != nil {
		c.ringReader.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	c.httpObjs.Close()
	c.tcpObjs.Close()
	return nil
}
```

- [ ] **Step 3: Add cilium/ebpf dependency**

Run:
```bash
cd ebpf && go get github.com/cilium/ebpf@latest && go mod tidy
```

- [ ] **Step 4: Commit**

```bash
git add ebpf/internal/loader/ ebpf/go.mod ebpf/go.sum
git commit -m "feat: add eBPF loader with bpf2go generation and tracepoint attachment"
```

---

## Task 10: Collector main.go (CLI Entry Point)

**Files:**
- Create: `ebpf/cmd/collector/main.go`

- [ ] **Step 1: Create main.go**

```go
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/athosone/aisre/ebpf/internal/events"
	"github.com/athosone/aisre/ebpf/internal/loader"
	"github.com/athosone/aisre/ebpf/internal/output"
	"github.com/athosone/aisre/ebpf/internal/parser"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	var (
		maxCapture  = flag.Uint("max-capture", 512, "Logical capture limit in bytes (max 512)")
		ringBufSize = flag.Int("ringbuf-size", 256, "Ring buffer size in pages")
		corrTimeout = flag.Duration("corr-timeout", 5*time.Second, "Request/response correlation timeout")
	)
	flag.Parse()

	if *maxCapture > events.MaxPayloadCapture {
		log.Fatalf("max-capture cannot exceed %d", events.MaxPayloadCapture)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	// Load eBPF programs
	cfg := loader.Config{
		LogicalCaptureBytes: uint32(*maxCapture),
		RingBufSizePages:    *ringBufSize,
	}

	collector, err := loader.New(cfg)
	if err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}
	defer collector.Close()

	log.Println("eBPF programs loaded and attached. Capturing HTTP traffic...")

	// Set up correlator and emitter
	correlator := parser.NewCorrelator(*corrTimeout)
	emitter := output.NewJSONEmitter(os.Stdout)

	// Start eviction ticker
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				expired := correlator.EvictExpired()
				for _, pair := range expired {
					// Emit unmatched requests (response will be nil)
					emitter.Emit(ctx, pair)
				}
			}
		}
	}()

	// Read events from ring buffer
	rd := collector.RingReader()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed")
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		event, err := events.DecodeHTTPEvent(record.RawSample)
		if err != nil {
			log.Printf("Error decoding event: %v", err)
			continue
		}

		// Enrich with process name (best effort)
		comm := readComm(event.Pid)

		pair := correlator.Feed(event)
		if pair != nil {
			pair.Process.Comm = comm
			if err := emitter.Emit(ctx, pair); err != nil {
				log.Printf("Error emitting event: %v", err)
			}
		}
	}
}

// readComm reads the process name from /proc/<pid>/comm.
// Returns empty string if the process has exited.
func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}
```

- [ ] **Step 2: Commit**

```bash
git add ebpf/cmd/collector/main.go
git commit -m "feat: add collector CLI entry point with signal handling and event loop"
```

---

## Task 11: Docker Build and Integration Test Harness

**Files:**
- Create: `integration/go.mod`
- Create: `integration/integration_test.go`

- [ ] **Step 1: Initialize integration test module**

Run:
```bash
mkdir -p integration && cd integration && go mod init github.com/athosone/aisre/integration
```

- [ ] **Step 2: Create integration_test.go**

```go
package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests must run inside the Docker container with eBPF capabilities.
// They start the collector, generate HTTP traffic, and verify captured events.

func TestCaptureHTTPGet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})
	server := &http.Server{Addr: ":18080", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	// Start collector
	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	collector.Stderr = nil // ignore stderr logs
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond) // wait for eBPF attach

	// Send HTTP request
	resp, err := http.Get("http://127.0.0.1:18080/health")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	resp.Body.Close()

	// Read events from collector stdout
	event := readEvent(t, stdout, 5*time.Second)

	if event["request"] == nil {
		t.Fatal("missing request in event")
	}
	req := event["request"].(map[string]interface{})
	if req["method"] != "GET" {
		t.Errorf("method = %v, want GET", req["method"])
	}
	if req["path"] != "/health" {
		t.Errorf("path = %v, want /health", req["path"])
	}
}

func TestCaptureHTTPPost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"created"}`))
	})
	server := &http.Server{Addr: ":18081", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	resp, err := http.Post("http://127.0.0.1:18081/data", "application/json",
		strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("HTTP POST: %v", err)
	}
	resp.Body.Close()

	event := readEvent(t, stdout, 5*time.Second)

	req := event["request"].(map[string]interface{})
	if req["method"] != "POST" {
		t.Errorf("method = %v, want POST", req["method"])
	}
	if req["path"] != "/data" {
		t.Errorf("path = %v, want /data", req["path"])
	}
}

func TestCapturePayloadTruncation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Server that returns a large body
	largeBody := strings.Repeat("X", 1024)
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(largeBody))
	})
	server := &http.Server{Addr: ":18082", Handler: mux}
	go server.ListenAndServe()
	defer server.Shutdown(ctx)
	time.Sleep(100 * time.Millisecond)

	collector := exec.CommandContext(ctx, "/workspace/bin/collector")
	stdout, err := collector.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	defer collector.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18082/big")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// The event should exist — the response body will be truncated
	// at 512 bytes, but the response headers + partial body should be captured
	event := readEvent(t, stdout, 5*time.Second)
	if event == nil {
		t.Fatal("expected event for large response")
	}
}

func readEvent(t *testing.T, r io.Reader, timeout time.Duration) map[string]interface{} {
	t.Helper()
	ch := make(chan map[string]interface{}, 1)

	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			var event map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				continue
			}
			ch <- event
			return
		}
	}()

	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		t.Fatal("timeout waiting for event")
		return nil
	}
}
```

- [ ] **Step 3: Update docker-compose.yml test-runner command**

The test-runner in docker-compose should build first, then run integration tests:

```yaml
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
```

- [ ] **Step 4: Commit**

```bash
git add integration/ deploy/docker/docker-compose.yml
git commit -m "feat: add integration test harness with HTTP capture verification"
```

---

## Task 12: First Build and Verification

This task verifies the entire pipeline compiles and unit tests pass.

- [ ] **Step 1: Install Go protobuf plugin and generate proto**

Run:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
make generate-proto
```

Expected: `proto/events/v1/http.pb.go` is generated.

- [ ] **Step 2: Run unit tests**

Run:
```bash
cd ebpf && go test ./internal/... -v
```

Expected: All parser, events, and output tests pass.

- [ ] **Step 3: Build Docker image and run eBPF generation**

Run:
```bash
make docker-build
docker compose -f deploy/docker/docker-compose.yml run --rm ebpf-dev sh -c "cd /workspace && make generate-vmlinux && make generate-ebpf"
```

Expected: `vmlinux.h` generated, `bpf2go` compiles C programs and generates Go bindings.

- [ ] **Step 4: Build collector binary inside Docker**

Run:
```bash
docker compose -f deploy/docker/docker-compose.yml run --rm ebpf-dev sh -c "cd /workspace && make build"
```

Expected: `bin/collector` binary is produced.

- [ ] **Step 5: Run smoke test**

Run:
```bash
make test-smoke
```

Expected: Docker builds, integration tests run, events are captured from HTTP traffic.

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix: address build and test issues from first full verification"
```

---

## Dependency Summary

| Task | Depends On | Produces |
|------|-----------|----------|
| 1 | None | Scaffold, Dockerfile, Makefile, proto |
| 2 | 1 | BPF headers (common.h, http_detect.h) |
| 3 | 2 | tcp_tracker.c |
| 4 | 2 | http_capture.c |
| 5 | 1 | Go event struct + decoder |
| 6 | 5 | HTTP parser |
| 7 | 5, 6 | Correlator |
| 8 | 6, 7 | JSON emitter |
| 9 | 3, 4, 5 | eBPF loader + bpf2go |
| 10 | 7, 8, 9 | Collector binary |
| 11 | 10 | Integration tests |
| 12 | All | Full verification |

**Parallelizable:** Tasks 3+4 (both depend on 2 only). Tasks 5+6 can start after 1. Task 7 needs 5+6. Task 8 needs 7. Tasks 3,4 and 5,6,7,8 are independent tracks that converge at Task 9.
