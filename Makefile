.PHONY: generate build test test-integration test-smoke docker-build compile-bpf clean

# Unwrapped clang (Nix-wrapped clang injects flags incompatible with -target bpf)
CLANG ?= $(shell find /nix/store -maxdepth 3 -name 'clang' -path '*/bin/clang' ! -path '*wrapper*' 2>/dev/null | head -1)
BPF_CFLAGS := -target bpf -O2 -g -Wall -I ebpf/c $(shell pkg-config --cflags libbpf)

DOCKER_COMPOSE := docker compose -f deploy/docker/docker-compose.yml

# Generate vmlinux.h from running kernel BTF (requires bpftool + /sys/kernel/btf)
generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/c/headers/vmlinux.h

# Generate protobuf Go code
generate-proto:
	protoc --go_out=. --go_opt=module=github.com/athosone/aisre proto/events/v1/http.proto

# Compile eBPF C programs directly (useful for quick error checking without bpf2go)
# Requires: nix develop (for unwrapped clang + libbpf headers)
compile-bpf:
	@test -n "$(CLANG)" || (echo "ERROR: unwrapped clang not found in /nix/store. Run: nix develop" && exit 1)
	@echo "Using clang: $(CLANG)"
	$(CLANG) $(BPF_CFLAGS) -c ebpf/c/tcp_tracker.c -o /tmp/tcp_tracker.o
	@echo "tcp_tracker.c compiled OK -> /tmp/tcp_tracker.o"

# Run bpf2go to compile eBPF C and generate Go bindings
generate-ebpf:
	@test -n "$(CLANG)" || (echo "ERROR: unwrapped clang not found in /nix/store. Run: nix develop" && exit 1)
	cd ebpf && CC=$(CLANG) go generate ./...

generate: generate-proto generate-ebpf

# Build the collector binary
build: generate
	cd ebpf && go build -o ../bin/collector ./cmd/collector/

# Run unit tests (no kernel needed)
test:
	cd ebpf && go test ./internal/... -v

# Run integration tests inside Docker (requires privileged)
test-integration:
	cd integration && go test -v -count=1 -timeout 120s ./...

# Full smoke test: docker build + integration
test-smoke: docker-build
	$(DOCKER_COMPOSE) run --rm test-runner

# Build the dev Docker image
docker-build:
	$(DOCKER_COMPOSE) build

clean:
	rm -rf bin/
	find . -name '*_bpfel.go' -o -name '*_bpfeb.go' -o -name '*_bpfel.o' -o -name '*_bpfeb.o' | xargs rm -f
