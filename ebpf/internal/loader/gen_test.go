package loader_test

import (
	"os"
	"testing"

	"github.com/athosone/aisre/ebpf/internal/loader"
)

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires root privileges (CAP_BPF)")
	}
}

func TestNewWithNilConfig(t *testing.T) {
	skipIfNotRoot(t)

	c, err := loader.New(nil)
	if err != nil {
		t.Fatalf("New(nil) failed: %v", err)
	}
	defer c.Close()

	if c == nil {
		t.Fatal("New(nil) returned nil collector without error")
	}
}

func TestNewWithEmptyConfig(t *testing.T) {
	skipIfNotRoot(t)

	c, err := loader.New(&loader.Config{})
	if err != nil {
		t.Fatalf("New(&Config{}) failed: %v", err)
	}
	defer c.Close()
}

func TestCollectorClose(t *testing.T) {
	skipIfNotRoot(t)

	c, err := loader.New(nil)
	if err != nil {
		t.Fatalf("New(nil) failed: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}
