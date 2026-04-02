#include "headers/common.h"
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
// Per-CPU scratch: pid_tgid -> fd
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);
  __type(value, __u32);
} connect_fd_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    if (ctx == NULL) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xffffffff;

    int fd = ctx->args[0];
    const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[1];
    int addrlen = ctx->args[2];

    struct sockaddr_in sin = {};

    if (!uaddr || addrlen <= 0 || addrlen > sizeof(sin)) {
        return 0;
    }
    if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0) {
        return 0;
    }
    if (sin.sin_family == AF_INET) {
        bpf_printk("connect: pid=%d, tgid=%d, fd=%d, addrlen=%d, ip=%u.%u.%u.%u\n", pid, tgid, fd, addrlen, sin.sin_addr.s_addr & 0xff, (sin.sin_addr.s_addr >> 8) & 0xff, (sin.sin_addr.s_addr >> 16) & 0xff, (sin.sin_addr.s_addr >> 24) & 0xff);
    }

    bpf_map_update_elem(&connect_fd_scratch, &pid_tgid, &fd, BPF_ANY);
    struct conn_key key = { .fd = fd, .pid_tgid = pid_tgid };
    struct pending_conn pending = {.dst_ip = sin.sin_addr.s_addr, .dst_port = sin.sin_port,};
    bpf_map_update_elem(&pending_connect_map, &key, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx == NULL) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xffffffff;

    __u32 *current_fd = bpf_map_lookup_elem(&connect_fd_scratch, &pid_tgid);
    if (!current_fd) {
        return 0;
    }
    struct conn_key key = { .fd = *current_fd, .pid_tgid = pid_tgid };

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&connect_fd_scratch, &pid_tgid);
        bpf_map_delete_elem(&pending_connect_map, &key);
        return 0;
    }

    bpf_map_delete_elem(&connect_fd_scratch, &pid_tgid);
    bpf_printk("deleted fd=%d", current_fd);

    struct pending_conn *pending = bpf_map_lookup_elem(&pending_connect_map, &key);

    if (!pending) {
        return 0;
    }
    struct conn_info conn_info = { .dst_ip = pending->dst_ip, .dst_port = pending->dst_port};
    bpf_map_delete_elem(&pending_connect_map, &key);
    bpf_map_update_elem(&conn_info_map, &key, &conn_info, BPF_ANY);
    bpf_printk("set conn info for destIP=%d", conn_info.dst_ip);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4_enter(struct trace_event_raw_sys_enter *ctx) {
    if (ctx == NULL) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xffffffff;
    __u32 *current_fd = bpf_map_lookup_elem(&, &pid_tgid);
    if (!current_fd) {
        return 0;
    }
    struct conn_key key = { .fd = *current_fd, .pid_tgid = pid_tgid };
    bpf_printk("accept4 enter fd=%d", current_fd);
    return 0;
}
