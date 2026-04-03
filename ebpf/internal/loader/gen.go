package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC tcpTracker ../../c/tcp_tracker.c -- -I../../c/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc $CC httpCapture ../../c/http_capture.c -- -I../../c/headers -D__TARGET_ARCH_x86
