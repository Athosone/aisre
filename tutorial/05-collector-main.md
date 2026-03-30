# Chapter 5: Collector main.go

In this chapter you'll wire everything together into a CLI binary that loads the eBPF programs, reads events, correlates them, and outputs JSON.

## What main.go Does

```
Parse CLI flags
  → Load eBPF programs (loader.New)
    → Read events from ring buffer (loop)
      → Decode raw bytes (events.DecodeHTTPEvent)
        → Feed to correlator (correlator.Feed)
          → If paired: emit JSON (emitter.Emit)
  → Background: evict expired requests (ticker)
  → On SIGINT/SIGTERM: graceful shutdown
```

## Step-by-Step

### Step 1: Create the file

Create `ebpf/cmd/collector/main.go`.

### Step 2: CLI flags

Use the standard `flag` package:

```go
var (
    maxCapture  = flag.Uint("max-capture", 512, "Logical capture limit in bytes (max 512)")
    ringBufSize = flag.Int("ringbuf-size", 256, "Ring buffer size in pages")
    corrTimeout = flag.Duration("corr-timeout", 5*time.Second, "Correlation timeout")
)
flag.Parse()
```

Validate that `maxCapture <= events.MaxPayloadCapture`.

### Step 3: Signal handling

Set up graceful shutdown:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
go func() {
    <-sigCh
    log.Println("Shutting down...")
    cancel()
}()
```

### Step 4: Load eBPF programs

```go
collector, err := loader.New(loader.Config{
    LogicalCaptureBytes: uint32(*maxCapture),
    RingBufSizePages:    *ringBufSize,
})
if err != nil {
    log.Fatalf("Failed to load eBPF programs: %v", err)
}
defer collector.Close()
```

### Step 5: Event loop

The core loop reads from the ring buffer, decodes, correlates, and emits:

```go
correlator := parser.NewCorrelator(*corrTimeout)
emitter := output.NewJSONEmitter(os.Stdout)
rd := collector.RingReader()

for {
    record, err := rd.Read()
    if err != nil {
        if errors.Is(err, ringbuf.ErrClosed) {
            return  // Normal shutdown
        }
        log.Printf("ringbuf read error: %v", err)
        continue
    }

    event, err := events.DecodeHTTPEvent(record.RawSample)
    if err != nil {
        log.Printf("decode error: %v", err)
        continue
    }

    pair := correlator.Feed(event)
    if pair != nil {
        // Enrich with process name (best-effort)
        pair.Process.Comm = readComm(event.Pid)
        emitter.Emit(ctx, pair)
    }
}
```

### Step 6: Process name enrichment

Read the process name from `/proc/{pid}/comm`. This is best-effort — short-lived processes may exit before we read it:

```go
func readComm(pid uint32) string {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
    if err != nil {
        return ""
    }
    return string(bytes.TrimSpace(data))
}
```

### Step 7: Eviction ticker

Unmatched requests (where the response never arrives) need to be evicted. Run a background goroutine:

```go
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
                emitter.Emit(ctx, pair)
            }
        }
    }
}()
```

## Verification

### Unit test (no kernel)

The event loop itself is hard to unit test since it depends on the eBPF loader. But the components it uses are all tested:
- `events.DecodeHTTPEvent` — tested in `events_test.go`
- `correlator.Feed` — tested in `correlator_test.go`
- `emitter.Emit` — tested in `json_test.go`

### Build test

```bash
# Inside Docker
make build
ls -la bin/collector  # Should exist
```

### Manual smoke test

```bash
# Inside Docker (privileged)
./bin/collector &

# In another terminal (or same container)
curl http://localhost:8080/something

# You should see JSON on collector stdout
```

### Integration tests

```bash
make test-smoke
```

This runs the integration tests in `integration/integration_test.go` which:
1. Start the collector
2. Start an HTTP server
3. Send requests
4. Verify JSON output contains correct method, path, status

If these pass, your entire pipeline works end-to-end.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Failed to load eBPF programs" | Missing CAP_BPF or not running privileged | Run inside Docker with `privileged: true` |
| "remove memlock: operation not permitted" | Old kernel or missing capabilities | Use `--privileged` flag |
| No events appearing | tcp_tracker not tracking connections | Check that `conn_info_map` has entries (use `bpftool map dump`) |
| Events but no correlation | Direction mismatch or connection key mismatch | Add debug logging to the correlator |
| "ringbuf read error" | Ring buffer overflow (too many events) | Increase `--ringbuf-size` |

## Reference

The complete reference implementation is in `docs/superpowers/plans/2026-03-29-ebpf-http-capture.md`, Task 10.

## You're Done!

Once the integration tests pass, you have a working eBPF HTTP traffic capture system. The JSON output conforms to the protobuf schema in `proto/events/v1/http.proto` and can be consumed by future services.

Potential next steps:
- Add IPv6 support (widen address fields in `common.h` and `events.go`)
- Add `sendto`/`recvfrom` support if not already done
- Enrich with Kubernetes pod info
- Add TLS interception via uprobes on OpenSSL
- Build a Temporal workflow to process events
