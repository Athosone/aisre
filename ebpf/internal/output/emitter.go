package output

import (
	"context"

	"github.com/athosone/aisre/ebpf/internal/parser"
)

// Emitter defines the interface for outputting correlated HTTP events.
type Emitter interface {
	Emit(ctx context.Context, pair *parser.CorrelatedPair) error
	Close() error
}
