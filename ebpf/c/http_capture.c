// SPDX-License-Identifier: GPL-2.0
#include "headers/common.h"
#include "headers/http_detect.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int handle_syscall_enter(__u64 pid_tgid, __u32 fd, const char *buf_ptr)
{
    struct conn_info *ci = bpf_map_lookup_elem(&conn_info_map, &(struct conn_key){.pid_tgid = pid_tgid, .fd = fd});
    if (!ci)
        return 0;

    struct active_syscall as = {
        .fd = fd,
        .buf_ptr = (__u64)buf_ptr,
        .entry_ts = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&active_syscall_map, &pid_tgid, &as, BPF_ANY);
    return 0;
}

// Helper: on syscall exit, read buffer, detect HTTP, emit event
static __always_inline int handle_syscall_exit(__u64 pid_tgid, long ret, __u8 direction)
{
    if (ret <= 0)
        goto cleanup;

    struct active_syscall *as = bpf_map_lookup_elem(&active_syscall_map, &pid_tgid);
    if (!as)
        return 0;

    __u32 payload_len = (__u32)ret;

    // Use per-CPU scratch map instead of stack — __u8[512] would overflow the
    // 512-byte BPF stack when combined with other locals.
    __u32 scratch_key = 0;
    struct payload_scratch_val *scratch = bpf_map_lookup_elem(&payload_scratch, &scratch_key);
    if (!scratch)
        goto cleanup;
    __u8 *buf = scratch->data;

    __u32 to_read = payload_len;
    if (to_read > MAX_PAYLOAD_CAPTURE)
        to_read = MAX_PAYLOAD_CAPTURE;

    // The & mask gives the verifier a provable bound
    if (bpf_probe_read_user(buf, to_read & (MAX_PAYLOAD_CAPTURE - 1), (const void *)as->buf_ptr) < 0)
        goto cleanup;

    if (!is_http(buf, to_read))
        goto cleanup;

    // Apply logical capture limit from config
    __u32 captured_len = to_read;
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (cfg && cfg->logical_capture_bytes > 0 && cfg->logical_capture_bytes < captured_len)
        captured_len = cfg->logical_capture_bytes;

    // Look up connection info
    struct conn_key ck = {.pid_tgid = pid_tgid, .fd = as->fd};
    struct conn_info *ci = bpf_map_lookup_elem(&conn_info_map, &ck);

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

    if (ci)
    {
        event->src_ip = ci->src_ip;
        event->dst_ip = ci->dst_ip;
        event->src_port = ci->src_port;
        event->dst_port = ci->dst_port;
    }

    __builtin_memcpy(event->payload, buf, MAX_PAYLOAD_CAPTURE);
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&active_syscall_map, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_syscall_exit(pid_tgid, ctx->ret, 0); // 0 = request
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_syscall_exit(pid_tgid, ctx->ret, 0); // 0 = request
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_syscall_exit(pid_tgid, ctx->ret, 1); // 1 = response
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 fd = (__u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    return handle_syscall_enter(pid_tgid, fd, buf);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_syscall_exit(pid_tgid, ctx->ret, 1); // 1 = response
}