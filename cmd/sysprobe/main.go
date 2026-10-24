// Command sysprobe is an eBPF profiler: per-process syscall latency
// histograms, run-queue latency, and TCP connect/retransmit events, exported
// to Prometheus and shown in a top-style view.
//
//	sysprobe run     live collection, metrics on :9464
//	sysprobe top     live interactive top view
//	sysprobe record  live collection into a fixture file
//	sysprobe replay  offline: feed a fixture through the same pipeline
//	sysprobe doctor  check kernel requirements per collector
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/app"
	"github.com/archit2501/sysprobe/internal/exporter"
	"github.com/archit2501/sysprobe/internal/kernel"
	"github.com/archit2501/sysprobe/internal/probe"
	"github.com/archit2501/sysprobe/internal/top"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: sysprobe <command> [flags]

commands:
  run      collect live and serve Prometheus metrics (default :9464)
  top      collect live and show the interactive top view
  record   collect live into a fixture file:  sysprobe record -o FILE -duration 10s
  replay   replay a fixture offline:          sysprobe replay [flags] FILE
  doctor   report which collectors this kernel supports
  version  print the version

run "sysprobe <command> -h" for the flags of a command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "run", "top", "record":
		err = cmdLive(ctx, args[0], args[1:], stdout, stderr)
	case "replay":
		err = cmdReplay(ctx, args[1:], stdout, stderr)
	case "doctor":
		f := kernel.Gather()
		cs := kernel.Evaluate(&f)
		fmt.Fprint(stdout, kernel.Report(&f, cs))
		for _, c := range cs {
			if !c.Ready() {
				return 1
			}
		}
		return 0
	case "version":
		fmt.Fprintf(stdout, "sysprobe %s\n", version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "sysprobe: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "sysprobe: %v\n", err)
		return 1
	}
	return 0
}

type commonFlags struct {
	window, retention, rows int
	maxComms, maxDests      int
	sort, promLabels        string
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&c.window, "window", 10, "snapshots in the sliding window used by the top view")
	fs.IntVar(&c.retention, "retention", 30, "snapshots an exited process stays visible")
	fs.IntVar(&c.rows, "rows", 20, "process rows in the top view")
	fs.IntVar(&c.maxComms, "max-comms", 256, "distinct comm label values before folding into \"other\"")
	fs.IntVar(&c.maxDests, "max-dests", 64, "distinct TCP destinations before folding into \"other\"")
	fs.StringVar(&c.sort, "sort", "busy", "top view sort key: busy, rate, p99, runq, pid")
	fs.StringVar(&c.promLabels, "prom-labels", "comm", "process labels on metrics: comm or pid")
}

func (c *commonFlags) build() (aggregate.Config, top.Options, exporter.Options, error) {
	sk, err := top.ParseSortKey(c.sort)
	if err != nil {
		return aggregate.Config{}, top.Options{}, exporter.Options{}, err
	}
	lm, err := exporter.ParseLabelMode(c.promLabels)
	if err != nil {
		return aggregate.Config{}, top.Options{}, exporter.Options{}, err
	}
	return aggregate.Config{
			Window: c.window, Retention: c.retention, MaxCommLabels: c.maxComms, MaxDestLabels: c.maxDests,
		}, top.Options{Sort: sk, Rows: c.rows},
		exporter.Options{Labels: lm}, nil
}

func parseCollectors(s string) (sys, runq, tcp bool, err error) {
	for _, c := range strings.Split(s, ",") {
		switch strings.TrimSpace(c) {
		case probe.CollectorSyscalls:
			sys = true
		case probe.CollectorRunq:
			runq = true
		case probe.CollectorTCP:
			tcp = true
		case "":
		default:
			return false, false, false, fmt.Errorf("unknown collector %q (want syscalls, runq, tcp)", c)
		}
	}
	if !sys && !runq && !tcp {
		return false, false, false, errors.New("no collectors selected")
	}
	return sys, runq, tcp, nil
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})), nil
}

func cmdLive(ctx context.Context, mode string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sysprobe "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	interval := fs.Duration("interval", time.Second, "snapshot interval")
	duration := fs.Duration("duration", 0, "stop after this long (0: until interrupted)")
	collectors := fs.String("collectors", "syscalls,runq,tcp", "comma-separated collectors to load")
	pid := fs.Uint("pid", 0, "trace only this process (host PID namespace)")
	includeSelf := fs.Bool("include-self", false, "do not filter out sysprobe's own activity")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	listenDefault, out := ":9464", ""
	if mode != "run" {
		listenDefault = ""
	}
	listen := fs.String("listen", listenDefault, "metrics listen address (empty disables)")
	fs.StringVar(&out, "o", "", "write the snapshot stream to this fixture file (record: required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if mode == "record" && out == "" {
		return errors.New("record: -o FILE is required")
	}
	aggCfg, topOpts, promOpts, err := cf.build()
	if err != nil {
		return err
	}
	sys, runq, tcp, err := parseCollectors(*collectors)
	if err != nil {
		return err
	}
	logger, err := newLogger(stderr, *logLevel)
	if err != nil {
		return err
	}
	facts := kernel.Gather()
	p, err := probe.Open(probe.Config{
		Syscalls: sys, Runq: runq, TCP: tcp, TargetPID: uint32(*pid), IncludeSelf: *includeSelf,
		Interval: *interval, Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("%w (see `sysprobe doctor`)", err)
	}
	defer func() { _ = p.Close() }()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	o := app.RunOptions{
		Arch: facts.Arch, Kernel: facts.Release, Interval: *interval,
		Agg: aggCfg, Prom: promOpts, Listen: *listen, TopOpts: topOpts,
		RecordedBy: "sysprobe " + version + " " + mode, Out: stdout, Logger: logger,
		Summary: mode != "top",
	}
	if mode == "top" {
		o.Top = true
		if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
			state, err := term.MakeRaw(fd)
			if err == nil {
				defer func() { _ = term.Restore(fd, state) }()
				o.Keys = os.Stdin
			}
		}
	}
	if out != "" {
		fh, err := os.Create(out)
		if err != nil {
			return err
		}
		defer func() { _ = fh.Close() }()
		o.Record = fh
	}
	return app.Run(ctx, p, o)
}

func cmdReplay(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sysprobe replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	speed := fs.Float64("speed", 0, "pacing multiplier (1 = real time, 0 = as fast as possible)")
	frames := fs.Bool("frames", false, "render a frame after every snapshot")
	pid := fs.Uint("pid", 0, "append the per-syscall detail of this process")
	metrics := fs.Bool("metrics", false, "append the Prometheus exposition")
	filter := fs.String("metrics-filter", "", "only print exposition lines containing this text")
	exited := fs.Bool("exited", false, "include exited processes in the table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("replay: exactly one fixture file expected")
	}
	aggCfg, topOpts, promOpts, err := cf.build()
	if err != nil {
		return err
	}
	topOpts.ShowExited = *exited
	fh, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	return app.Replay(ctx, fh, stdout, app.ReplayOptions{
		Agg: aggCfg, Top: topOpts, Prom: promOpts, Speed: *speed, Frames: *frames,
		PID: uint32(*pid), Metrics: *metrics, MetricsFilter: *filter,
	})
}
