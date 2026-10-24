// Package probe loads the sysprobe BPF collectors into the running kernel,
// attaches them, and turns their maps and ring buffer into a stream of
// events.Snapshot values. It is the only package that talks to the kernel;
// on non-Linux systems Open returns ErrUnsupported.
package probe

import (
	"errors"
	"log/slog"
	"time"
)

// ErrUnsupported is returned by Open on systems without eBPF.
var ErrUnsupported = errors.New("eBPF collectors require Linux")

// Collector names, used in logs, drop metrics and `sysprobe doctor`.
const (
	CollectorSyscalls = "syscalls"
	CollectorRunq     = "runq"
	CollectorTCP      = "tcp"
)

// Config selects and parameterizes the collectors.
type Config struct {
	Syscalls, Runq, TCP bool
	// TargetPID restricts every collector to one process (0: all).
	TargetPID uint32
	// IncludeSelf disables filtering of sysprobe's own syscalls and
	// scheduling, which are otherwise excluded to limit observer effect.
	IncludeSelf bool
	// Interval between snapshots (default 1s).
	Interval time.Duration
	Logger   *slog.Logger

	// OnRawTCP, when set, receives every raw ring-buffer record before it is
	// decoded (used to capture byte-level fixtures). It must not retain b.
	OnRawTCP func(b []byte)
	// OnRawHist, when set, receives every raw per-CPU histogram value read
	// from a kernel map. It must not retain the slices.
	OnRawHist func(collector string, key []byte, perCPU [][]byte)
}

// Status reports whether a collector was loaded and attached.
type Status struct {
	Name    string
	Enabled bool  // requested in Config
	Err     error // nil when running
}
