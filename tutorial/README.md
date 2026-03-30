# eBPF HTTP Capture — Implementation Tutorial

This tutorial guides you through implementing the kernel-side eBPF programs and the Go glue code that ties everything together. The userspace Go components (parser, correlator, emitter, event decoder) are already built and fully tested — your job is to implement the parts that talk to the kernel.

## What's Already Done

| Component | Location | Status |
|-----------|----------|--------|
| Event decoder | `ebpf/internal/events/` | Done, tested |
| HTTP parser | `ebpf/internal/parser/http.go` | Done, tested |
| Request/response correlator | `ebpf/internal/parser/correlator.go` | Done, tested |
| JSON output emitter | `ebpf/internal/output/` | Done, tested |
| BPF headers (structs, maps) | `ebpf/c/headers/` | Done |
| Protobuf schema | `proto/events/v1/http.proto` | Done |
| Integration test skeleton | `integration/` | Done (needs collector to run) |
| Docker + Makefile | `deploy/docker/`, `Makefile` | Done |

## What You'll Implement

| Chapter | What You Build | File(s) |
|---------|---------------|---------|
| [01 - eBPF Concepts](01-ebpf-concepts.md) | Nothing — read this first | — |
| [02 - TCP Tracker](02-tcp-tracker.md) | Connection tracking eBPF program | `ebpf/c/tcp_tracker.c` |
| [03 - HTTP Capture](03-http-capture.md) | HTTP payload capture eBPF program | `ebpf/c/http_capture.c` |
| [04 - Loader + bpf2go](04-loader-and-bpf2go.md) | Go eBPF loader | `ebpf/internal/loader/` |
| [05 - Collector main](05-collector-main.md) | CLI entry point wiring everything | `ebpf/cmd/collector/main.go` |

## Prerequisites

- WSL2 with kernel 6.6+ (you already have this)
- Nix dev shell (`nix develop`) or the Docker dev container
- Understanding of Go (assumed)
- Curiosity about how the kernel works

## How to Use This Tutorial

1. Read chapter 01 to build mental models for eBPF
2. Implement each chapter in order — later chapters depend on earlier ones
3. Each chapter has verification steps so you know when you're done
4. The integration tests in `integration/integration_test.go` are your final validation
5. Use `make test` to run unit tests and `make test-smoke` for the full end-to-end

## Quick Reference

```bash
# Run unit tests (no kernel needed)
make test

# Enter the Docker dev container
docker compose -f deploy/docker/docker-compose.yml run --rm ebpf-dev bash

# Inside Docker: generate vmlinux.h from your kernel's BTF
make generate-vmlinux

# Inside Docker: compile eBPF C and generate Go bindings
make generate-ebpf

# Inside Docker: build the collector binary
make build

# Full end-to-end smoke test
make test-smoke
```
