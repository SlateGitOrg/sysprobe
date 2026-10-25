// Package source abstracts where snapshots come from: the live BPF probe or
// a recorded fixture. Both satisfy Source, so the aggregation pipeline, the
// exporter and the top view are identical in live use, replay and tests.
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/fixture"
)

// Emit receives one snapshot. Returning an error stops the source.
type Emit func(*events.Snapshot) error

// Source produces snapshots until its input ends or ctx is cancelled.
type Source interface {
	Run(ctx context.Context, emit func(*events.Snapshot) error) error
}

// Replay plays a fixture back.
type Replay struct {
	r *fixture.Reader
	// Speed scales the recorded pacing: 1 replays in real time, 10 ten
	// times faster, 0 (the default) as fast as possible.
	Speed float64
	// sleep is replaceable in tests.
	sleep func(ctx context.Context, d time.Duration) error
}

// NewReplay reads the fixture header from r.
func NewReplay(r io.Reader) (*Replay, error) {
	fr, err := fixture.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &Replay{r: fr, sleep: sleepCtx}, nil
}

// Header returns the fixture header.
func (rp *Replay) Header() fixture.Header { return rp.r.Header() }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run emits every snapshot in order. It returns nil at the end of the
// fixture and ctx.Err() when cancelled.
func (rp *Replay) Run(ctx context.Context, emit func(*events.Snapshot) error) error {
	var prev time.Duration
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, err := rp.r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if rp.Speed > 0 {
			if d := time.Duration(float64(s.Elapsed-prev) / rp.Speed); d > 0 {
				if err := rp.sleep(ctx, d); err != nil {
					return err
				}
			}
		}
		prev = s.Elapsed
		if err := emit(&s); err != nil {
			return err
		}
	}
}

// Tee returns an Emit that writes each snapshot to w before calling next.
func Tee(w *fixture.Writer, next Emit) Emit {
	return func(s *events.Snapshot) error {
		if err := w.Write(s); err != nil {
			return fmt.Errorf("record: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("record: %w", err)
		}
		return next(s)
	}
}
