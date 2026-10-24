package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/fixture"
	"github.com/archit2501/sysprobe/internal/hist"
	"github.com/archit2501/sysprobe/internal/source"
	"github.com/archit2501/sysprobe/internal/top"
)

var update = flag.Bool("update", false, "rewrite golden files and the synthetic fixture")

const syntheticPath = "../../testdata/synthetic/churn.jsonl"

func cum(n int, ns uint64) hist.Log2 {
	var h hist.Log2
	for range n {
		h.Record(ns)
	}
	return h
}

// churn is a hand-built scenario covering what live recordings rarely show
// in a few seconds: an exit, PID reuse, an exec rename, a counter reset and
// all three TCP event kinds. x86_64 syscall numbers: 0 read, 1 write,
// 230 clock_nanosleep, 202 futex.
func churn() []events.Snapshot {
	addr := netip.MustParseAddr
	var out []events.Snapshot
	for seq := uint64(1); seq <= 8; seq++ {
		n := int(seq)
		s := events.Snapshot{Seq: seq, Elapsed: time.Duration(seq) * time.Second}
		s.Syscalls = append(s.Syscalls,
			events.SyscallSample{TGID: 100, NR: 0, Comm: "api", Hist: cum(400*n, 3_000)},
			events.SyscallSample{TGID: 100, NR: 202, Comm: "api", Hist: cum(20*n, 900_000)},
		)
		s.Runq = append(s.Runq, events.RunqSample{TGID: 100, Comm: "api", Hist: cum(300*n, 20_000)})
		if seq <= 3 { // batch job exits after snapshot 3
			s.Syscalls = append(s.Syscalls, events.SyscallSample{TGID: 200, NR: 1, Comm: "batch", Hist: cum(1000*n, 15_000)})
		}
		if seq >= 6 { // its pid is reused by a new process
			s.Syscalls = append(s.Syscalls, events.SyscallSample{TGID: 200, NR: 230, Comm: "sleeper", Hist: cum(n-5, 3_100_000)})
		}
		comm := "sh"
		if seq >= 4 {
			comm = "worker" // exec'd
		}
		w := cum(50*n, 120_000)
		if seq >= 7 {
			w = cum(10*(n-6), 120_000) // kernel key re-created: counter reset
		}
		s.Syscalls = append(s.Syscalls, events.SyscallSample{TGID: 300, NR: 0, Comm: comm, Hist: w})
		switch seq {
		case 2:
			s.TCP = []events.TCPEvent{
				{KtimeNs: 2_000_000_000, Latency: 150 * time.Microsecond, TGID: 100, Comm: "api", Kind: events.TCPConnect,
					SAddr: addr("10.1.0.5"), DAddr: addr("10.1.0.9"), SPort: 41000, DPort: 5432, State: 1},
				{KtimeNs: 2_100_000_000, Latency: 90 * time.Microsecond, TGID: 100, Comm: "api", Kind: events.TCPConnect,
					SAddr: addr("10.1.0.5"), DAddr: addr("10.1.0.9"), SPort: 41002, DPort: 5432, State: 1},
			}
		case 5:
			s.TCP = []events.TCPEvent{
				{KtimeNs: 5_000_000_000, Latency: 0, Kind: events.TCPRetransmit,
					SAddr: addr("10.1.0.5"), DAddr: addr("10.1.0.9"), SPort: 41002, DPort: 5432, State: 1},
				{KtimeNs: 5_200_000_000, Latency: 30 * time.Microsecond, TGID: 100, Comm: "api", Kind: events.TCPConnectFail,
					SAddr: addr("10.1.0.5"), DAddr: addr("10.1.0.7"), SPort: 41004, DPort: 6379, State: 7},
			}
		}
		s.Drops = []events.Drop{{Collector: "syscalls", Reason: "missed_start", Count: 3}}
		out = append(out, s)
	}
	return out
}

func encodeChurn(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := fixture.NewWriter(&buf, fixture.Header{
		Arch: "x86_64", Kernel: "synthetic", IntervalMs: 1000, RecordedBy: "internal/app churn()",
		Synthetic: true, Note: "hand-built: exit, pid reuse, exec rename, counter reset, tcp events",
	})
	if err != nil {
		t.Fatal(err)
	}
	snaps := churn()
	for i := range snaps {
		if err := w.Write(&snaps[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSyntheticFixtureUpToDate(t *testing.T) {
	got := encodeChurn(t)
	if *update {
		if err := os.WriteFile(syntheticPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(syntheticPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/synthetic/churn.jsonl is stale: run go test ./internal/app -update")
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestReplaySyntheticGolden(t *testing.T) {
	var out bytes.Buffer
	err := Replay(context.Background(), bytes.NewReader(encodeChurn(t)), &out, ReplayOptions{
		Agg: aggregate.Config{Window: 3, Retention: 3}, Top: top.Options{ShowExited: true},
		PID: 100, Metrics: true, MetricsFilter: `comm="worker"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "replay-churn.txt", out.String())
	s := out.String()
	for _, want := range []string{"replaying SYNTHETIC fixture", "series resets 1", "sleeper", "10.1.0.9:5432", "connect_fail"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(s, " batch ") {
		t.Error("exited batch job should be evicted after retention")
	}
}

func TestReplayRecordedFixture(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/recorded/itest-*.jsonl")
	if len(files) == 0 {
		t.Fatal("no recorded fixture")
	}
	fh, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var out bytes.Buffer
	if err := Replay(context.Background(), fh, &out, ReplayOptions{Metrics: true, MetricsFilter: "sysprobe-loadge"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"replaying recorded fixture", "arch aarch64", "RECENT TCP EVENTS",
		`sysprobe_syscall_latency_seconds_count{comm="sysprobe-loadge",syscall="clock_nanosleep"}`} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestReplayFramesAndErrors(t *testing.T) {
	var out bytes.Buffer
	if err := Replay(context.Background(), bytes.NewReader(encodeChurn(t)), &out, ReplayOptions{Frames: true}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "sysprobe top  snapshot"); n != 8 {
		t.Errorf("%d frames, want 8", n)
	}
	if err := Replay(context.Background(), strings.NewReader("x"), io.Discard, ReplayOptions{}); err == nil {
		t.Error("bad fixture accepted")
	}
	if err := Replay(context.Background(), bytes.NewReader(encodeChurn(t)), io.Discard, ReplayOptions{PID: 4242}); err == nil {
		t.Error("unknown pid accepted")
	}
	bad := strings.Replace(string(encodeChurn(t)), `"seq":2,`, `"seq":1,`, 1)
	if err := Replay(context.Background(), strings.NewReader(bad), io.Discard, ReplayOptions{}); err == nil {
		t.Error("out-of-order fixture accepted")
	}
}

// gated emits its snapshots, then blocks until released, so the HTTP side
// can be exercised while the pipeline is live.
type gated struct {
	snaps   []events.Snapshot
	emitted chan struct{}
	release chan struct{}
}

func (g *gated) Run(ctx context.Context, emit func(*events.Snapshot) error) error {
	for i := range g.snaps {
		if err := emit(&g.snaps[i]); err != nil {
			return err
		}
	}
	close(g.emitted)
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d", url, resp.StatusCode)
	}
	return string(b)
}

func TestRunServesMetricsAndRecords(t *testing.T) {
	g := &gated{snaps: churn(), emitted: make(chan struct{}), release: make(chan struct{})}
	addrc := make(chan string, 1)
	var rec, out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), g, RunOptions{
			Arch: "x86_64", Kernel: "test", Interval: time.Second, Listen: "127.0.0.1:0",
			OnListen: func(a string) { addrc <- a }, Record: &rec, RecordedBy: "test", Summary: true, Out: &out,
		})
	}()
	addr := <-addrc
	<-g.emitted
	metrics := get(t, "http://"+addr+"/metrics")
	for _, want := range []string{`sysprobe_syscall_latency_seconds_count{comm="api",syscall="read"} 3200`,
		"sysprobe_tcp_retransmits_total", "go_goroutines", "sysprobe_snapshots_total 8"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if get(t, "http://"+addr+"/healthz") != "ok\n" {
		t.Error("healthz")
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	h, snaps, err := fixture.ReadAll(&rec)
	if err != nil || len(snaps) != 8 || h.Kernel != "test" || h.Synthetic {
		t.Fatalf("recording: %v %d %+v", err, len(snaps), h)
	}
	if !strings.Contains(out.String(), "snapshot 8") {
		t.Errorf("summary missing:\n%s", out.String())
	}
}

func TestRunErrors(t *testing.T) {
	g := &gated{snaps: churn(), emitted: make(chan struct{}), release: make(chan struct{})}
	if err := Run(context.Background(), g, RunOptions{Arch: "vax"}); err == nil {
		t.Error("bad arch accepted")
	}
	if err := Run(context.Background(), g, RunOptions{Arch: "x86_64", Listen: "256.0.0.1:1"}); err == nil {
		t.Error("bad listen address accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	g2 := &gated{snaps: churn(), emitted: make(chan struct{}), release: make(chan struct{})}
	if err := Run(ctx, g2, RunOptions{Arch: "x86_64"}); err != nil {
		t.Errorf("deadline should end the run cleanly: %v", err)
	}
	bad := churn()
	bad[1].Seq = 1
	g3 := &gated{snaps: bad, emitted: make(chan struct{}), release: make(chan struct{})}
	if err := Run(context.Background(), g3, RunOptions{Arch: "x86_64"}); !errors.Is(err, aggregate.ErrOutOfOrder) {
		t.Errorf("ingest error not returned: %v", err)
	}
}

func TestInteractiveTop(t *testing.T) {
	rp, err := source.NewReplay(bytes.NewReader(encodeChurn(t)))
	if err != nil {
		t.Fatal(err)
	}
	g := &gated{emitted: make(chan struct{}), release: make(chan struct{})}
	// Replay first, then block on the gate so keystrokes arrive while live.
	src := sourceFunc(func(ctx context.Context, emit func(*events.Snapshot) error) error {
		if err := rp.Run(ctx, emit); err != nil {
			return err
		}
		return g.Run(ctx, emit)
	})
	pr, pw := io.Pipe()
	var out lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), src, RunOptions{Arch: "x86_64", Top: true, Keys: pr, Out: &out})
	}()
	<-g.emitted
	if _, err := pw.Write([]byte("sxq")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, clearScreen) || !strings.Contains(s, "sort rate") || !strings.Contains(s, "\r\n") {
		t.Errorf("interactive output missing redraw/sort change:\n%q", s[:min(len(s), 400)])
	}
}

type sourceFunc func(ctx context.Context, emit func(*events.Snapshot) error) error

func (f sourceFunc) Run(ctx context.Context, emit func(*events.Snapshot) error) error {
	return f(ctx, emit)
}

type lockedBuffer struct {
	mu  chan struct{}
	buf bytes.Buffer
}

func (b *lockedBuffer) lock() {
	if b.mu == nil {
		b.mu = make(chan struct{}, 1)
	}
	b.mu <- struct{}{}
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.lock()
	defer func() { <-b.mu }()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.lock()
	defer func() { <-b.mu }()
	return b.buf.String()
}

func TestScreenKeys(t *testing.T) {
	var out bytes.Buffer
	s := NewScreen(&out, top.Options{})
	s.Draw(&aggregate.View{Arch: "x86_64"})
	if !strings.Contains(out.String(), "sort busy") {
		t.Fatal("first draw missing")
	}
	out.Reset()
	if s.HandleKey('p') || !strings.Contains(out.String(), "[paused]") {
		t.Fatal("pause not shown")
	}
	out.Reset()
	s.Draw(&aggregate.View{Arch: "x86_64", Seq: 2})
	if out.Len() != 0 {
		t.Fatal("paused screen redrew on new data")
	}
	if s.HandleKey('z') {
		t.Fatal("unknown key quit")
	}
	if s.HandleKey('e') || !s.opts.ShowExited {
		t.Fatal("e did not toggle exited")
	}
	for _, k := range []byte{'q', 'Q', 3} {
		if !s.HandleKey(k) {
			t.Fatalf("key %q did not quit", k)
		}
	}
	quit := false
	s.ReadKeys(strings.NewReader("s"), func() { quit = true })
	if quit || s.opts.Sort != top.SortRate {
		t.Fatal("EOF must not quit; s must cycle sort")
	}
	if crlf("a\nb\n") != "a\r\nb\r\n" {
		t.Fatal("crlf")
	}
	empty := NewScreen(io.Discard, top.Options{})
	empty.redraw() // no view yet: must not panic
}

func TestFilterMetrics(t *testing.T) {
	in := "a 1\nb 2\nab 3\n"
	if filterMetrics(in, "") != in || filterMetrics(in, "a") != "a 1\nab 3\n" || filterMetrics(in, "a,b") != "ab 3\n" {
		t.Fatal("filter")
	}
}
