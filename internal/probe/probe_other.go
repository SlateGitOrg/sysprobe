//go:build !linux

package probe

import (
	"context"

	"github.com/archit2501/sysprobe/internal/events"
)

// Probe is unavailable on this OS.
type Probe struct{}

// Open always fails with ErrUnsupported outside Linux.
func Open(Config) (*Probe, error) { return nil, ErrUnsupported }

// Statuses returns nothing on this OS.
func (*Probe) Statuses() []Status { return nil }

// Run is never reachable because Open fails.
func (*Probe) Run(context.Context, func(*events.Snapshot) error) error { return ErrUnsupported }

// Close is a no-op.
func (*Probe) Close() error { return nil }
