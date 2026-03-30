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
