# Chapter 2: TCP Connection Tracker

In this chapter you'll implement `ebpf/c/tcp_tracker.c` — the eBPF program that tracks TCP connections so the HTTP capture program knows which file descriptors are sockets.

## Why This Is Needed

The HTTP capture program hooks `read()`/`write()` syscalls, but these fire for **all** file descriptors — files, pipes, terminals, not just sockets. Without a connection map, we'd waste time reading non-HTTP data from pipes and files.

`tcp_tracker.c` maintains a map (`conn_info_map`) of `{pid_tgid, fd}` → connection info. The HTTP capture program checks this map to quickly discard non-socket fds.

## What You'll Build

Five tracepoint handlers:

| Tracepoint | Purpose |
|-----------|---------|
| `sys_enter_connect` | Client initiates connection — save fd + destination |
| `sys_exit_connect` | Connection succeeded — promote to conn_info_map |
| `sys_enter_accept4` | Server accepting — mark pid_tgid as accepting |
| `sys_exit_accept4` | New connection accepted — save fd to conn_info_map |
| `inet_sock_set_state` | TCP state change — enrich or clean up entries |

## Step-by-Step

### Step 1: File skeleton

Create `ebpf/c/tcp_tracker.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"

char LICENSE[] SEC("license") = "GPL";
```

Every eBPF program needs:
- The GPL license (required to use most BPF helpers)
- The `#include "headers/common.h"` which brings in vmlinux.h, BPF helpers, map definitions, and struct definitions

### Step 2: Connect tracking (client-side)

When a process calls `connect(fd, addr, addrlen)`, we want to:
1. On **enter**: save the fd and destination address
2. On **exit**: if successful, promote to `conn_info_map`

The challenge: `sys_exit_connect` doesn't give you the fd (it's not in the return args). You need to save it from `sys_enter_connect` and retrieve it on exit.

**Your task:** Add a scratch map to pass the fd from enter to exit:

```c
// Per-CPU scratch: pid_tgid -> fd
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u32);
} connect_fd_scratch SEC(".maps");
```

Then implement two handlers:

**`sys_enter_connect`:**
1. Get `pid_tgid` via `bpf_get_current_pid_tgid()`
2. Read `fd` from `ctx->args[0]`
3. Read `sockaddr` from `ctx->args[1]` using `bpf_probe_read_user()`
4. Check `sa_family == AF_INET` (skip IPv6 for now)
5. Save fd to `connect_fd_scratch` keyed by `pid_tgid`
6. Save destination to `pending_connect_map` keyed by `{pid_tgid, fd}`

**`sys_exit_connect`:**
1. Get `pid_tgid`, look up fd from `connect_fd_scratch`, clean up scratch
2. Check `ctx->ret` — success is `0` or `-115` (EINPROGRESS for non-blocking)
3. On success: look up pending entry, promote to `conn_info_map`
4. On failure: clean up pending entry
5. Note: `src_ip`/`src_port` won't be available here — leave as 0

**Hints:**
- `struct sockaddr_in` is defined in `vmlinux.h` — use `bpf_probe_read_user()` to read it
- Port is in network byte order — use `bpf_ntohs()` to convert
- The `conn_key` struct is defined in `common.h`

### Step 3: Accept tracking (server-side)

When a server calls `accept4()`, the return value is the new fd.

**`sys_enter_accept4`:**
Simple — just save a marker that this pid_tgid is in an accept call. You need a small scratch map:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} accept_scratch SEC(".maps");
```

**`sys_exit_accept4`:**
1. Clean up the scratch entry
2. `ctx->ret` is the new fd (or negative on error)
3. If `fd >= 0`: create an entry in `conn_info_map` with the fd
4. The 4-tuple will be filled later by `inet_sock_set_state`

### Step 4: TCP state changes

`inet_sock_set_state` fires when a socket transitions between TCP states. The tracepoint argument is `struct trace_event_raw_inet_sock_set_state` which has:
- `family` — address family (check for `AF_INET`)
- `saddr[0]`, `daddr[0]` — source/dest IP as `__u8[4]` (actually `__u32` for IPv4)
- `sport`, `dport` — source/dest port (dport is in network byte order)
- `oldstate`, `newstate` — TCP state constants

**On `BPF_TCP_ESTABLISHED`:**
This is where you'd enrich existing entries with the 4-tuple. The tricky part: you have the 4-tuple but not the fd. You can't easily map back to the fd from here.

**Practical approach:** For the initial implementation, you can leave this as a no-op or just log. The accept handler already creates the entry, and the connect handler has the destination. Source port enrichment can be a future improvement.

**On `BPF_TCP_CLOSE`:**
Ideally clean up the `conn_info_map` entry. Same problem — no fd available. For now, rely on userspace TTL-based cleanup.

### Step 5: SEC annotations

Each function needs a `SEC()` annotation matching the tracepoint path:

```c
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) { ... }

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) { ... }

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) { ... }

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) { ... }

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) { ... }
```

## Verification

After implementing, you'll compile it in chapter 4 via `bpf2go`. For now, focus on getting the logic right. Common verifier issues you might hit:

1. **"invalid mem access"** — forgot a NULL check after `bpf_map_lookup_elem()`
2. **"R1 type=scalar expected=fp"** — passing wrong argument type to a helper
3. **"back-edge from insn X to Y"** — unbounded loop detected

## Testing Strategy

tcp_tracker doesn't produce events to userspace directly — it populates `conn_info_map` which http_capture reads. You can verify it works by:
1. Loading the program
2. Running `connect()` from a test process
3. Reading `conn_info_map` from userspace to confirm entries appear

The integration tests do this implicitly — if http_capture can find connections, tcp_tracker is working.

## Reference

- Syscall signatures: `man 2 connect`, `man 2 accept4`
- TCP states: `BPF_TCP_ESTABLISHED`, `BPF_TCP_CLOSE`, etc. (defined in vmlinux.h)
- The existing plan has a complete reference implementation at `docs/superpowers/plans/2026-03-29-ebpf-http-capture.md`, Task 3

## Next

Once tcp_tracker.c is done, proceed to [Chapter 3: HTTP Capture](03-http-capture.md).
