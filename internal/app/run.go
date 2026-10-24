package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/exporter"
	"github.com/archit2501/sysprobe/internal/fixture"
	"github.com/archit2501/sysprobe/internal/source"
	"github.com/archit2501/sysprobe/internal/top"
)

// RunOptions configures Run.
type RunOptions struct {
	// Arch and Kernel describe the host the source observes; they select
	// the syscall table and are written into recordings.
	Arch, Kernel string
	Interval     time.Duration
	Agg          aggregate.Config
	Prom         exporter.Options
	// Listen is the metrics address (e.g. ":9464"); empty disables HTTP.
	Listen string
	// Top redraws the top view on Out after every snapshot.
	Top     bool
	TopOpts top.Options
	// Keys, when set with Top, is read for interactive keystrokes.
	Keys io.Reader
	// Record, when set, receives the snapshot stream as a fixture.
	Record     io.Writer
	RecordedBy string
	// Summary prints a final top frame to Out when the run ends (used by
	// non-interactive runs such as `sysprobe record`).
	Summary bool
	Out     io.Writer
	Logger  *slog.Logger
	// OnListen is called with the bound metrics address (tests use it with
	// Listen ":0").
	OnListen func(addr string)
}

// Run drives src until it ends or ctx is cancelled, feeding the aggregator
// and serving metrics / the top view as configured.
func Run(ctx context.Context, src source.Source, o RunOptions) error {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	o.Agg.Arch = o.Arch
	agg, err := aggregate.New(o.Agg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()
	if o.Listen != "" {
		reg, err := Registry(agg, o.Prom, true)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", o.Listen)
		if err != nil {
			return fmt.Errorf("metrics listener: %w", err)
		}
		srv := NewServer(o.Listen, reg)
		o.Logger.Info("serving metrics", "addr", ln.Addr().String())
		if o.OnListen != nil {
			o.OnListen(ln.Addr().String())
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				o.Logger.Error("metrics server", "err", err)
			}
		}()
		go func() {
			defer wg.Done()
			<-ctx.Done()
			sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer scancel()
			_ = srv.Shutdown(sctx)
		}()
	}

	var screen *Screen
	if o.Top {
		screen = NewScreen(o.Out, o.TopOpts)
		if o.Keys != nil {
			go screen.ReadKeys(o.Keys, cancel)
		}
	}
	emit := func(s *events.Snapshot) error {
		if err := agg.Ingest(s); err != nil {
			return err
		}
		if screen != nil {
			v := agg.View()
			screen.Draw(&v)
		}
		return nil
	}
	var rec *fixture.Writer
	if o.Record != nil {
		rec, err = fixture.NewWriter(o.Record, fixture.Header{
			Arch: o.Arch, Kernel: o.Kernel, IntervalMs: o.Interval.Milliseconds(), RecordedBy: o.RecordedBy,
		})
		if err != nil {
			return err
		}
		emit = source.Tee(rec, emit)
	}
	err = src.Run(ctx, emit)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}
	if rec != nil {
		if ferr := rec.Flush(); ferr != nil && err == nil {
			err = ferr
		}
	}
	if o.Summary {
		v := agg.View()
		fmt.Fprint(o.Out, top.Render(&v, o.TopOpts))
	}
	cancel()
	return err
}

// Screen is the interactive top display.
type Screen struct {
	mu   sync.Mutex
	out  io.Writer
	opts top.Options
	last *aggregate.View
}

// NewScreen returns a screen drawing to out.
func NewScreen(out io.Writer, o top.Options) *Screen {
	return &Screen{out: out, opts: o}
}

const clearScreen = "\x1b[H\x1b[2J"

// Draw renders a view unless the display is paused.
func (s *Screen) Draw(v *aggregate.View) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = v
	if s.opts.Paused {
		return
	}
	s.redraw()
}

func (s *Screen) redraw() {
	if s.last == nil {
		return
	}
	body := top.Render(s.last, s.opts) + "\nkeys: s sort  e exited  p pause  q quit\n"
	// Raw terminal mode disables output post-processing, so emit CRLF.
	fmt.Fprint(s.out, clearScreen+crlf(body))
}

func crlf(s string) string {
	out := make([]byte, 0, len(s)+len(s)/40)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, '\r')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// HandleKey applies one keystroke and reports whether it asks to quit.
func (s *Screen) HandleKey(k byte) (quit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch k {
	case 'q', 'Q', 3: // 3: Ctrl-C in raw mode
		return true
	case 's':
		s.opts.Sort = s.opts.Sort.Next()
	case 'e':
		s.opts.ShowExited = !s.opts.ShowExited
	case 'p':
		s.opts.Paused = !s.opts.Paused
	default:
		return false
	}
	s.redraw()
	return false
}

// ReadKeys consumes keystrokes until EOF or a quit key, then calls quit.
func (s *Screen) ReadKeys(r io.Reader, quit func()) {
	buf := make([]byte, 16)
	for {
		n, err := r.Read(buf)
		for _, k := range buf[:n] {
			if s.HandleKey(k) {
				quit()
				return
			}
		}
		if err != nil {
			return
		}
	}
}
