package app

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/exporter"
	"github.com/archit2501/sysprobe/internal/source"
	"github.com/archit2501/sysprobe/internal/top"
)

// ReplayOptions configures Replay.
type ReplayOptions struct {
	Agg  aggregate.Config // Arch is taken from the fixture header
	Top  top.Options
	Prom exporter.Options
	// Speed paces the replay (0: as fast as possible).
	Speed float64
	// Frames renders a top frame after every snapshot instead of only the
	// last one.
	Frames bool
	// PID, when non-zero, appends the per-syscall detail of that process.
	PID uint32
	// Metrics appends the Prometheus exposition after the replay.
	Metrics bool
	// MetricsFilter keeps only exposition lines containing this substring
	// (comments for kept families are kept too). Empty keeps everything.
	MetricsFilter string
}

// Replay feeds a fixture through the full pipeline and writes the rendered
// output to out. It is what `sysprobe replay` and `make demo` run.
func Replay(ctx context.Context, in io.Reader, out io.Writer, o ReplayOptions) error {
	rp, err := source.NewReplay(in)
	if err != nil {
		return err
	}
	rp.Speed = o.Speed
	h := rp.Header()
	o.Agg.Arch = h.Arch
	agg, err := aggregate.New(o.Agg)
	if err != nil {
		return err
	}
	kind := "recorded"
	if h.Synthetic {
		kind = "SYNTHETIC"
	}
	fmt.Fprintf(out, "replaying %s fixture: kernel %s, arch %s, interval %dms, recorded by %q\n",
		kind, h.Kernel, h.Arch, h.IntervalMs, h.RecordedBy)
	if h.Note != "" {
		fmt.Fprintf(out, "note: %s\n", h.Note)
	}
	fmt.Fprintln(out)
	err = rp.Run(ctx, func(s *events.Snapshot) error {
		if err := agg.Ingest(s); err != nil {
			return err
		}
		if o.Frames {
			v := agg.View()
			fmt.Fprintln(out, top.Render(&v, o.Top))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	v := agg.View()
	if !o.Frames {
		fmt.Fprint(out, top.Render(&v, o.Top))
	}
	if o.PID != 0 {
		d, err := top.RenderProcess(&v, o.PID, 2)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\n%s", d)
	}
	if o.Metrics {
		reg, err := Registry(agg, o.Prom, false)
		if err != nil {
			return err
		}
		text, err := MetricsText(reg)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\n# ---- Prometheus exposition (filter %q) ----\n%s", o.MetricsFilter, filterMetrics(text, o.MetricsFilter))
	}
	return nil
}

func filterMetrics(text, sub string) string {
	if sub == "" {
		return text
	}
	var b strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		if strings.Contains(line, sub) {
			b.WriteString(line)
		}
	}
	return b.String()
}
