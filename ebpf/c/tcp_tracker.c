// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"

char LICENSE[] SEC("license") = "GPL";

// ─── Debug logging ────────────────────────────────────────────────────────────
//
// bpf_printk acquires a global spinlock on every call and writes to tracefs.
// On a busy server this serialises the whole system.  All informational traces
// are therefore compiled out unless -DDEBUG is passed at build time.
//
// Error traces (map-full, unexpected failures) remain unconditional: those
// conditions need visibility in production and should be rare.

#ifdef DEBUG
#define dbg(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg(fmt, ...)
#endif

// ─── Local scratch maps ───────────────────────────────────────────────────────

// pid_tgid -> fd: ferry the fd from sys_enter_connect to sys_exit_connect,
// because the exit tracepoint only exposes the return value, not the arguments.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);   // pid_tgid
    __type(value, __u32);   // fd
} connect_fd_scratch SEC(".maps");

// pid_tgid -> marker: set on sys_enter_accept4, cleared on sys_exit_accept4.
// Guards the exit handler so it only fires for calls we actually tracked.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);   // pid_tgid
    __type(value, __u8);    // always 1
} accept_scratch SEC(".maps");

// skaddr (struct sock * cast to u64) -> conn_key.
//
// The bridge between accept4/connect (which know the fd) and
// inet_sock_set_state (which knows the 4-tuple but not the fd).
// Written by accept4_exit / connect_exit; read and deleted by
// inet_sock_set_state.
//
// Sized to match conn_info_map: if the bridge fills first, connections past
// the limit silently lose their entry and conn_info_map leaks those rows
// permanently (CLOSE can't clean what it can't find).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);         // must match conn_info_map
    __type(key,   __u64);               // skaddr
    __type(value, struct conn_key);
} sock_to_conn_map SEC(".maps");

// ─── Helper: fd → struct sock * ──────────────────────────────────────────────
//
// Walk the kernel file-descriptor table to reach the underlying socket:
//
//   task_struct
//     └── files  (struct files_struct *)
//           └── fdt  (struct fdtable *)
//                 └── fd[]  (struct file **)  ← array indexed by fd number
//                       └── private_data      ← struct socket *
//                             └── sk          ← struct sock *  (what we want)
//
// BPF_CORE_READ handles struct-field traversal with CO-RE relocations.
// bpf_probe_read_kernel handles the variable-index array dereference because
// BPF_CORE_READ cannot express a runtime array index.
//
// Returns the struct sock * cast to __u64, or 0 on any failure.
static __always_inline __u64 fd_to_skaddr(__u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    // fdt->fd is struct file **, the base of the fd array.
    struct file **fds = BPF_CORE_READ(fdt, fd);
    if (!fds)
        return 0;

    // Variable-index read: fds[fd].  bpf_probe_read_kernel is safe for this;
    // BPF_CORE_READ cannot express a runtime index.
    struct file *f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), fds + fd) < 0 || !f)
        return 0;

    // private_data for a socket file is struct socket *.
    struct socket *sock = (struct socket *)BPF_CORE_READ(f, private_data);
    if (!sock)
        return 0;

    // struct socket.sk is the protocol-layer struct sock *.
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return (__u64)sk;
}

// ─── Helper: register socket in the bridge map ───────────────────────────────
//
// Shared by connect_exit and accept4_exit.  Logs unconditionally on map-full
// because a missed bridge entry means the connection is never enriched or
// cleaned up — that is an operational problem worth surfacing in production.
static __always_inline void register_skaddr(__u64 skaddr, struct conn_key *key) {
    if (!skaddr)
        return;

    if (bpf_map_update_elem(&sock_to_conn_map, &skaddr, key, BPF_ANY) < 0)
        bpf_printk("ERROR sock_to_conn_map full: fd=%u will not be enriched or cleaned up\n",
                   key->fd);
}

// ─── Connect tracking (client-side) ──────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    if (ctx == NULL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd       = (__u32)ctx->args[0];

    const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    struct sockaddr_in sin = {};

    // FIX: the original check was `addrlen > sizeof(sin)`, which is backwards.
    // A too-large addrlen is harmless (we only read sizeof(sin) bytes anyway).
    // A too-small addrlen is the real risk: bpf_probe_read_user would read past
    // the end of the user-supplied buffer.  Reject anything smaller than a full
    // struct sockaddr_in.
    if (!uaddr || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0)
        return 0;

    // Only track IPv4 for now.
    if (sin.sin_family != AF_INET)
        return 0;

    dbg("connect enter: pid=%u fd=%u dst_ip=%u\n",
        (__u32)(pid_tgid >> 32), fd, sin.sin_addr.s_addr);

    // Ferry the fd to the exit handler (not present in sys_exit_connect args).
    bpf_map_update_elem(&connect_fd_scratch, &pid_tgid, &fd, BPF_ANY);

    // Stash the destination so we can promote it on a successful exit.
    struct conn_key     key     = { .pid_tgid = pid_tgid, .fd = fd };
    struct pending_conn pending = {
        .dst_ip    = sin.sin_addr.s_addr,
        .dst_port  = sin.sin_port,      // kept in network byte order
        .timestamp = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&pending_connect_map, &key, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx == NULL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 *fd_ptr = bpf_map_lookup_elem(&connect_fd_scratch, &pid_tgid);
    if (!fd_ptr)
        return 0;

    __u32 fd = *fd_ptr;
    bpf_map_delete_elem(&connect_fd_scratch, &pid_tgid);

    struct conn_key key = { .pid_tgid = pid_tgid, .fd = fd };

    // ret == 0    → immediate success (rare for TCP)
    // ret == -115 → EINPROGRESS: non-blocking socket, handshake in flight
    // anything else → error; clean up and bail
    long ret = ctx->ret;
    if (ret != 0 && ret != -115) {
        bpf_map_delete_elem(&pending_connect_map, &key);
        return 0;
    }

    struct pending_conn *pending = bpf_map_lookup_elem(&pending_connect_map, &key);
    if (!pending)
        return 0;

    // Promote to the active connection map.
    // src_ip / src_port are unknown here — the kernel picks the ephemeral port
    // during the handshake.  Leave established_ns as 0 too: the ESTABLISHED
    // handler fires after the handshake completes and will write the correct
    // values for all three fields.
    struct conn_info conn_info = {
        .src_ip         = 0,
        .src_port       = 0,
        .dst_ip         = pending->dst_ip,
        .dst_port       = pending->dst_port,
        .established_ns = 0,    // corrected by inet_sock_set_state ESTABLISHED
    };
    bpf_map_delete_elem(&pending_connect_map, &key);
    bpf_map_update_elem(&conn_info_map, &key, &conn_info, BPF_ANY);

    // Register the socket in the bridge map so inet_sock_set_state can locate
    // this conn_key when ESTABLISHED fires and fill in src_ip / src_port /
    // established_ns.
    __u64 skaddr = fd_to_skaddr(fd);
    register_skaddr(skaddr, &key);

    dbg("connect exit: fd=%u dst_ip=%u dst_port=%u skaddr=0x%llx\n",
        fd, conn_info.dst_ip, (__u32)conn_info.dst_port, skaddr);
    return 0;
}

// ─── Accept tracking (server-side) ───────────────────────────────────────────
//
// Ordering note: for accepted connections, BPF_TCP_ESTABLISHED fires in the
// kernel's network receive path — before the accepting process ever calls
// accept4().  This means the ESTABLISHED handler cannot enrich accepted entries
// (the bridge map entry doesn't exist yet).  The 4-tuple is therefore filled
// in here instead, while the bridge entry written below is used only by the
// CLOSE handler for cleanup.

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx) {
    if (ctx == NULL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Mark this thread as being inside accept4 so the exit handler can
    // distinguish calls it tracked from stray exits.
    __u8 marker = 1;
    bpf_map_update_elem(&accept_scratch, &pid_tgid, &marker, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_accept4_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx == NULL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Only proceed for calls we observed entering.
    __u8 *marker = bpf_map_lookup_elem(&accept_scratch, &pid_tgid);
    if (!marker)
        return 0;

    bpf_map_delete_elem(&accept_scratch, &pid_tgid);

    // ctx->ret is the newly accepted fd, or negative on error.
    long ret = ctx->ret;
    if (ret < 0)
        return 0;

    __u32 fd = (__u32)ret;
    struct conn_key key = { .pid_tgid = pid_tgid, .fd = fd };

    // Walk the fd table to reach the underlying sock so we can read the
    // 4-tuple directly.  By the time accept4 returns, the 3-way handshake is
    // complete and all four fields are stable on the sock.
    __u64 skaddr = fd_to_skaddr(fd);
    struct sock *sk = (struct sock *)skaddr;

    __u32 src_ip   = sk ? BPF_CORE_READ(sk, sk_rcv_saddr) : 0;
    __u32 dst_ip   = sk ? BPF_CORE_READ(sk, sk_daddr)     : 0;
    __u16 src_port = sk ? BPF_CORE_READ(sk, sk_num)        : 0;
    __u16 dst_port = sk ? BPF_CORE_READ(sk, sk_dport)      : 0;

    // sk_num is in host byte order; convert to network byte order to match
    // how all other ports are stored in conn_info.
    src_port = bpf_htons(src_port);

    struct conn_info conn_info = {
        .src_ip         = src_ip,
        .src_port       = src_port,
        .dst_ip         = dst_ip,
        .dst_port       = dst_port,
        // Handshake is already complete at this point, so this timestamp is
        // accurate for accepted connections (unlike the connect/EINPROGRESS path
        // where we must wait for the ESTABLISHED event).
        .established_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&conn_info_map, &key, &conn_info, BPF_ANY);

    // Register the socket in the bridge map so the CLOSE handler can find and
    // delete this conn_info_map entry when the connection ends.
    register_skaddr(skaddr, &key);

    dbg("accept4 exit: pid_tgid=%llu fd=%u src=%u:%u dst=%u:%u skaddr=0x%llx\n",
        pid_tgid, fd, src_ip, (__u32)src_port, dst_ip, (__u32)dst_port, skaddr);
    return 0;
}

// ─── TCP state change: enrichment and cleanup ─────────────────────────────────

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx == NULL)
        return 0;

    // Only handle IPv4 for now.
    if (ctx->family != AF_INET)
        return 0;

    __u64 skaddr = (__u64)ctx->skaddr;
    int newstate = ctx->newstate;

    if (newstate == BPF_TCP_ESTABLISHED) {
        // Applies to the connect (client) path only.  For accepted connections,
        // ESTABLISHED fires before accept4_exit registers the bridge entry, so
        // the lookup below correctly returns NULL and we skip — the 4-tuple was
        // already written in accept4_exit via the sock struct walk.
        struct conn_key *key = bpf_map_lookup_elem(&sock_to_conn_map, &skaddr);
        if (!key)
            return 0;

        struct conn_info *conn = bpf_map_lookup_elem(&conn_info_map, key);
        if (!conn)
            return 0;

        // FIX: saddr / daddr are __u8[4].  Casting to __u32 * and dereferencing
        // is a strict-aliasing violation — C may not alias __u8 storage as __u32.
        // __builtin_memcpy expresses the same 4-byte load without aliasing
        // assumptions; the compiler lowers it to an identical instruction.
        __builtin_memcpy(&conn->src_ip, ctx->saddr, sizeof(conn->src_ip));
        __builtin_memcpy(&conn->dst_ip, ctx->daddr, sizeof(conn->dst_ip));

        // sport / dport are __u16 in network byte order — assign directly.
        conn->src_port = ctx->sport;
        conn->dst_port = ctx->dport;

        // FIX: stamp established_ns here, not at connect_exit.  connect_exit
        // fires at EINPROGRESS — before the handshake.  This handler fires when
        // the kernel confirms the connection is up, which is the correct moment.
        conn->established_ns = bpf_ktime_get_ns();

        dbg("TCP ESTABLISHED: fd=%u src=%u:%u dst=%u:%u\n",
            key->fd,
            conn->src_ip, (__u32)conn->src_port,
            conn->dst_ip, (__u32)conn->dst_port);

    } else if (newstate == BPF_TCP_CLOSE) {
        // Copy the key out before touching the maps: once we delete from
        // sock_to_conn_map the pointer into that map's value storage may be
        // reused, so we must not dereference it after the deletion.
        struct conn_key *key_ptr = bpf_map_lookup_elem(&sock_to_conn_map, &skaddr);
        if (!key_ptr)
            return 0;

        struct conn_key key_copy = *key_ptr;

        dbg("TCP CLOSE: fd=%u pid_tgid=%llu\n", key_copy.fd, key_copy.pid_tgid);

        bpf_map_delete_elem(&conn_info_map,    &key_copy);
        bpf_map_delete_elem(&sock_to_conn_map, &skaddr);
    }

    return 0;
}