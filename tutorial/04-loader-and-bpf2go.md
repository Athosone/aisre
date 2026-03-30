# Chapter 4: Go Loader and bpf2go

In this chapter you'll set up `bpf2go` to compile your eBPF C programs into Go-embeddable bytecode, then write the Go loader that loads them into the kernel and attaches them to tracepoints.

## How bpf2go Works

`bpf2go` is a code generator from the `cilium/ebpf` library. It:

1. Compiles your `.c` file with clang targeting BPF
2. Generates Go source files containing the compiled bytecode as embedded data
3. Generates Go types for your maps and programs

You invoke it via `//go:generate` directives, and `go generate` does the rest.

## Step-by-Step

### Step 1: Create the go:generate file

Create `ebpf/internal/loader/gen.go`:

```go
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang tcpTracker ../../c/tcp_tracker.c -- -I../../c/headers -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang httpCapture ../../c/http_capture.c -- -I../../c/headers -D__TARGET_ARCH_x86
```

What happens when you run `go generate ./...`:
- `bpf2go` invokes clang to compile each `.c` file to BPF bytecode
- It generates files like `tcptracker_bpfel.go`, `tcptracker_bpfel.o` (little-endian, amd64)
- The generated Go files contain:
  - `tcpTrackerObjects` struct with fields for each program and map
  - `loadTcpTrackerObjects()` function to load them
  - Similar for `httpCapture`

### Step 2: Add the cilium/ebpf dependency

```bash
cd ebpf
go get github.com/cilium/ebpf@latest
go mod tidy
```

### Step 3: Generate the code (inside Docker)

This must run inside the Docker container because it needs clang and libbpf headers, plus `vmlinux.h` generated from your kernel:

```bash
# Enter the dev container
docker compose -f deploy/docker/docker-compose.yml run --rm ebpf-dev bash

# Generate vmlinux.h
make generate-vmlinux

# Generate Go bindings
make generate-ebpf
```

If compilation fails, the errors come from clang — they're standard C compiler errors, not Go errors. Common issues:
- Missing `vmlinux.h` → run `make generate-vmlinux` first
- Undefined types → check your `#include` paths
- Verifier errors appear later, at load time, not at compile time

### Step 4: Implement the loader

Create `ebpf/internal/loader/loader.go`. The loader's job:

1. Remove the memlock rlimit (required for BPF map allocation)
2. Load tcp_tracker objects (programs + maps)
3. Load http_capture objects, **sharing maps** with tcp_tracker
4. Write runtime config to `config_map`
5. Attach all programs to their tracepoints
6. Create a ring buffer reader for userspace event consumption
7. Provide a `Close()` method for cleanup

**Key concept — Map sharing:**

Both tcp_tracker and http_capture define the same maps (via `common.h`). But when loaded separately, they'd get different map instances. We need them to share the same maps.

cilium/ebpf handles this via `MapReplacements`:

```go
// Load tcp_tracker first — it creates the maps
loadTcpTrackerObjects(&c.tcpObjs, nil)

// Load http_capture, replacing its maps with tcp_tracker's
loadHttpCaptureObjects(&c.httpObjs, &ebpf.CollectionOptions{
    MapReplacements: map[string]*ebpf.Map{
        "conn_info_map":       c.tcpObjs.ConnInfoMap,
        "pending_connect_map": c.tcpObjs.PendingConnectMap,
        "config_map":          c.tcpObjs.ConfigMap,
        "events":              c.tcpObjs.Events,
        "active_syscall_map":  c.tcpObjs.ActiveSyscallMap,
    },
})
```

This tells the loader: "When http_capture references `conn_info_map`, use the one tcp_tracker already created."

**Attaching to tracepoints:**

```go
l, err := link.Tracepoint("syscalls", "sys_enter_connect", c.tcpObjs.TracepointSysEnterConnect, nil)
```

The `link.Tracepoint()` function returns a `link.Link` that you must keep alive — if it's garbage collected, the program detaches. Store all links and close them in `Close()`.

**The complete tracepoint list:**

TCP tracker (5):
- `syscalls/sys_enter_connect`
- `syscalls/sys_exit_connect`
- `syscalls/sys_enter_accept4`
- `syscalls/sys_exit_accept4`
- `sock/inet_sock_set_state`

HTTP capture (8):
- `syscalls/sys_enter_write`, `sys_exit_write`
- `syscalls/sys_enter_read`, `sys_exit_read`
- `syscalls/sys_enter_sendto`, `sys_exit_sendto`
- `syscalls/sys_enter_recvfrom`, `sys_exit_recvfrom`

### Step 5: Expose the ring buffer reader

The loader should expose the ring buffer reader so `main.go` can consume events:

```go
func (c *Collector) RingReader() *ringbuf.Reader {
    return c.ringReader
}
```

### Step 6: Config struct

```go
type Config struct {
    LogicalCaptureBytes uint32
    RingBufSizePages    int
}

func DefaultConfig() Config {
    return Config{
        LogicalCaptureBytes: 512,
        RingBufSizePages:    256, // 256 * 4096 = 1MB
    }
}
```

Write the config to the BPF array map at index 0 after loading.

## Verification

After implementing:

```bash
# Inside Docker
make generate-vmlinux
make generate-ebpf  # Should generate *_bpfel.go files
make build           # Should produce bin/collector
```

If `go generate` fails with verifier errors, the error message tells you which instruction and what the verifier expected. These are your eBPF C bugs — go back to chapters 2-3 and fix them.

## Reference

- cilium/ebpf docs: https://pkg.go.dev/github.com/cilium/ebpf
- bpf2go docs: https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
- The complete reference implementation is in `docs/superpowers/plans/2026-03-29-ebpf-http-capture.md`, Task 9

## Next

Proceed to [Chapter 5: Collector main.go](05-collector-main.md) to wire everything together.
