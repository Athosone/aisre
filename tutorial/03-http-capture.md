# Chapter 3: HTTP Capture eBPF Program

In this chapter you'll implement `ebpf/c/http_capture.c` — the program that intercepts `read()`/`write()`/`sendto()`/`recvfrom()` syscalls, detects HTTP traffic, and emits events to the ring buffer.

## The Pattern: Enter/Exit Correlation

Every syscall hook follows the same pattern:

1. **On enter**: save the buffer pointer and fd into a scratch map
2. **On exit**: read the buffer, check for HTTP, emit event if found

Why two phases? On `sys_enter_write`, you have the buffer pointer and fd, but you don't know how many bytes were actually written. On `sys_exit_write`, you have the byte count (`ctx->ret`), but you no longer have access to the original arguments.

The scratch map `active_syscall_map` (per-CPU hash, keyed by `pid_tgid`) bridges the two.

## What You'll Build

Eight tracepoint handlers (4 syscalls × enter/exit):

| Syscall | Direction | When |
|---------|-----------|------|
| `write` / `sendto` | Request (direction=0) | Process sends HTTP request |
| `read` / `recvfrom` | Response (direction=1) | Process receives HTTP response |

## Step-by-Step

### Step 1: File skeleton

Create `ebpf/c/http_capture.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"
#include "headers/http_detect.h"

char LICENSE[] SEC("license") = "GPL";
```

### Step 2: Implement the enter helper

Create a static inline helper that all `sys_enter_*` handlers will call:

```c
static __always_inline int handle_syscall_enter(__u64 pid_tgid, __u32 fd, const char *buf) {
    // 1. Early discard: check if fd is in conn_info_map
    //    If not, this fd isn't a tracked socket — skip it
    //
    // 2. Save {fd, buf_ptr, timestamp} into active_syscall_map
    //    Key: pid_tgid (safe because one thread = one syscall at a time)
}
```

**Why early discard matters:** `write()` fires for stdout, log files, pipes — everything. Without the `conn_info_map` check, you'd be copying buffers from every write in the system.

### Step 3: Implement the exit helper

This is the core logic. Create:

```c
static __always_inline int handle_syscall_exit(__u64 pid_tgid, long ret, __u8 direction) {
    // 1. If ret <= 0, clean up and return (no data transferred)
    //
    // 2. Look up active_syscall_map for this pid_tgid
    //    If not found, return (we didn't track the enter)
    //
    // 3. Read first MAX_PAYLOAD_CAPTURE bytes from the userspace buffer
    //    using bpf_probe_read_user()
    //
    // 4. Check for HTTP signature using is_http() from http_detect.h
    //    If not HTTP, clean up and return
    //
    // 5. Apply logical capture limit from config_map
    //
    // 6. Look up connection info from conn_info_map
    //
    // 7. Reserve ring buffer space: bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0)
    //
    // 8. Fill in the event struct fields
    //
    // 9. Copy payload into event using __builtin_memcpy()
    //
    // 10. Submit: bpf_ringbuf_submit(event, 0)
    //
    // 11. Clean up active_syscall_map entry
}
```

### Step 4: The verifier-safe buffer read

This is the trickiest part. The BPF verifier must prove that `bpf_probe_read_user()` reads a bounded number of bytes.

```c
__u8 buf[MAX_PAYLOAD_CAPTURE] = {};
__u32 to_read = (__u32)ret;
if (to_read > MAX_PAYLOAD_CAPTURE)
    to_read = MAX_PAYLOAD_CAPTURE;

// The & mask gives the verifier a provable bound
if (bpf_probe_read_user(buf, to_read & (MAX_PAYLOAD_CAPTURE - 1), saved->buf_ptr) < 0)
    goto cleanup;
```

**Why the `& (MAX_PAYLOAD_CAPTURE - 1)` mask?**
The verifier tracks value ranges. After the `if` check, it knows `to_read <= 512`. But between the check and the use, the verifier may lose track (especially with compiler optimizations). The bitwise AND is an unconditional bound — the verifier can prove the result is always `< MAX_PAYLOAD_CAPTURE` regardless of the input.

Note: `MAX_PAYLOAD_CAPTURE` must be a power of 2 for this mask to work correctly. It's 512 = 2^9.

### Step 5: Wire up the tracepoint handlers

Each handler is thin — it just extracts args and calls the helper:

```c
SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_syscall_exit(pid_tgid, ctx->ret, 0);  // 0 = request
}
```

**Syscall argument positions:**

| Syscall | args[0] | args[1] | args[2] |
|---------|---------|---------|---------|
| `write(fd, buf, count)` | fd | buf | count |
| `read(fd, buf, count)` | fd | buf | count |
| `sendto(fd, buf, len, flags, dest_addr, addrlen)` | fd | buf | len |
| `recvfrom(fd, buf, len, flags, src_addr, addrlen)` | fd | buf | len |

**Direction mapping:**
- `write` and `sendto` → direction `0` (request, outgoing)
- `read` and `recvfrom` → direction `1` (response, incoming)

You need 8 handlers total (4 enter + 4 exit). They're all nearly identical — just different SEC names and direction values.

### Step 6: Fill the event struct

When emitting to the ring buffer:

```c
struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
if (!event)
    goto cleanup;

event->timestamp_ns = saved->entry_ts;  // from sys_enter
event->pid = pid_tgid >> 32;
event->tid = (__u32)pid_tgid;
event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
event->direction = direction;
event->_pad[0] = 0; event->_pad[1] = 0; event->_pad[2] = 0;
event->payload_len = (__u32)ret;  // actual bytes from syscall
event->captured_len = captured_len;  // after applying config limit

// Fill connection info from conn_info_map (if available)
if (conn_info) {
    event->src_ip = conn_info->src_ip;
    event->dst_ip = conn_info->dst_ip;
    event->src_port = conn_info->src_port;
    event->dst_port = conn_info->dst_port;
}

// Copy payload — use __builtin_memcpy for fixed-size copy
__builtin_memcpy(event->payload, buf, MAX_PAYLOAD_CAPTURE);

bpf_ringbuf_submit(event, 0);
```

**Important:** Use `__builtin_memcpy` instead of `memcpy` for the payload copy. The BPF compiler optimizes this into inline instructions that the verifier understands. Using `memcpy` might not work.

## Common Pitfalls

1. **Stack overflow**: `__u8 buf[512]` uses the entire 512-byte BPF stack. If you add other large locals, you'll overflow. Keep locals minimal.

2. **Forgetting cleanup**: Always delete from `active_syscall_map` in the exit handler, even on error paths. A `goto cleanup` pattern works well.

3. **Reading user memory**: `bpf_probe_read_user()` can fail if the user pointer is invalid. Always check the return value.

4. **Shared maps with tcp_tracker**: Both programs define maps in `common.h`. When loaded, the loader must share the actual map instances between them (via `MapReplacements` in cilium/ebpf). You'll set this up in chapter 4.

## Verification

You can't test this in isolation — it needs to be compiled and loaded. After implementing the loader in chapter 4:

1. Compile via `make generate-ebpf`
2. Build via `make build`
3. Run the collector and make HTTP requests
4. Check stdout for JSON events

## Reference

- The `is_http()` function in `ebpf/c/headers/http_detect.h` — study how it matches HTTP signatures
- The complete reference implementation is in `docs/superpowers/plans/2026-03-29-ebpf-http-capture.md`, Task 4

## Next

Proceed to [Chapter 4: Loader and bpf2go](04-loader-and-bpf2go.md) to compile your C programs and wire them into Go.
