package aggregate

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/hist"
	"github.com/archit2501/sysprobe/internal/labels"
)

// h builds a cumulative histogram holding n samples of ns each.
func h(n int, ns uint64) hist.Log2 {
	var x hist.Log2
	for range n {
		x.Record(ns)
	}
	return x
}

func snap(seq uint64, sys ...events.SyscallSample) *events.Snapshot {
	return &events.Snapshot{Seq: seq, Elapsed: time.Duration(seq) * time.Second, Syscalls: sys}
}

func sc(tgid, nr uint32, comm string, x hist.Log2) events.SyscallSample {
	return events.SyscallSample{TGID: tgid, NR: nr, Comm: comm, Hist: x}
}

func newAgg(t *testing.T, cfg Config) *Aggregator {
	t.Helper()
	if cfg.Arch == "" {
		cfg.Arch = "x86_64"
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func proc(v View, tgid uint32) *ProcessView {
	for i := range v.Processes {
		if v.Processes[i].TGID == tgid {
			return &v.Processes[i]
		}
	}
	return nil
}

func TestNewRejectsUnknownArch(t *testing.T) {
	if _, err := New(Config{Arch: "sparc"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDeltasRatesAndWindow(t *testing.T) {
	a := newAgg(t, Config{Window: 3})
	// read (nr 0) grows by 100 calls of 1us per second.
	for seq := uint64(1); seq <= 5; seq++ {
		if err := a.Ingest(snap(seq, sc(7, 0, "app", h(int(seq)*100, 1000)))); err != nil {
			t.Fatal(err)
		}
	}
	v := a.View()
	p := proc(v, 7)
	if p == nil {
		t.Fatal("process missing")
	}
	if v.Window != 3*time.Second {
		t.Fatalf("window %v", v.Window)
	}
	if p.SyscallRate != 100 || p.Syscalls[0].Name != "read" || p.Syscalls[0].Count != 300 || p.Syscalls[0].Total != 500 {
		t.Fatalf("rate %v syscalls %+v", p.SyscallRate, p.Syscalls)
	}
	// 100 calls/s * 1us = 100us busy per second = 0.0001.
	if d := p.SyscallBusy - 1e-4; d > 1e-12 || d < -1e-12 {
		t.Fatalf("busy %v", p.SyscallBusy)
	}
	if p.SyscallP50 < 512 || p.SyscallP50 > 1024 {
		t.Fatalf("p50 %v not in the 1us bucket", p.SyscallP50)
	}
	tot := a.Totals(true)
	if tot.CommSys[0].Hist.Count != 500 || tot.PIDSys[0].Hist.Count != 500 || tot.Snapshots != 5 {
		t.Fatalf("totals %+v", tot)
	}
}

func TestWindowAgesOutIdleSeries(t *testing.T) {
	a := newAgg(t, Config{Window: 2})
	mustIngest(t, a, snap(1, sc(1, 0, "x", h(10, 100))))
	// Same cumulative value: no new calls.
	for seq := uint64(2); seq <= 4; seq++ {
		mustIngest(t, a, snap(seq, sc(1, 0, "x", h(10, 100))))
	}
	p := proc(a.View(), 1)
	if p.SyscallRate != 0 || p.Syscalls[0].Count != 0 || p.Syscalls[0].Total != 10 {
		t.Fatalf("idle series still in window: %+v", p.Syscalls[0])
	}
}

func mustIngest(t *testing.T, a *Aggregator, s *events.Snapshot) {
	t.Helper()
	if err := a.Ingest(s); err != nil {
		t.Fatal(err)
	}
}

func TestOutOfOrder(t *testing.T) {
	a := newAgg(t, Config{})
	mustIngest(t, a, snap(2))
	if err := a.Ingest(snap(2)); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("repeat seq: %v", err)
	}
	s := snap(3)
	s.Elapsed = time.Second
	if err := a.Ingest(s); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("elapsed backwards: %v", err)
	}
}

func TestResetIsCountedAndTreatedAsFresh(t *testing.T) {
	a := newAgg(t, Config{})
	mustIngest(t, a, snap(1, sc(1, 0, "x", h(50, 100))))
	// Key re-created in the kernel: cumulative drops to 5.
	mustIngest(t, a, snap(2, sc(1, 0, "x", h(5, 100))))
	tot := a.Totals(true)
	if tot.Resets != 1 || tot.PIDSys[0].Hist.Count != 55 || tot.CommSys[0].Hist.Count != 55 {
		t.Fatalf("resets %d pid %d comm %d", tot.Resets, tot.PIDSys[0].Hist.Count, tot.CommSys[0].Hist.Count)
	}
}

func TestExitRetentionAndEviction(t *testing.T) {
	a := newAgg(t, Config{Retention: 2})
	mustIngest(t, a, snap(1, sc(1, 0, "keep", h(1, 10)), sc(2, 0, "gone", h(1, 10))))
	mustIngest(t, a, snap(2, sc(1, 0, "keep", h(2, 10))))
	v := a.View()
	if p := proc(v, 2); p == nil || !p.Exited {
		t.Fatalf("pid 2 should be marked exited: %+v", p)
	}
	mustIngest(t, a, snap(3, sc(1, 0, "keep", h(3, 10))))
	mustIngest(t, a, snap(4, sc(1, 0, "keep", h(4, 10))))
	v = a.View()
	if proc(v, 2) != nil || v.Evicted != 1 {
		t.Fatalf("pid 2 not evicted after retention (evicted=%d)", v.Evicted)
	}
	// Its contribution survives in the per-comm totals.
	found := false
	for _, c := range a.Totals(false).CommSys {
		if c.Comm == "gone" && c.Hist.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("exited process lost from comm totals")
	}
}

func TestPIDReuseStartsFreshProcess(t *testing.T) {
	a := newAgg(t, Config{})
	mustIngest(t, a, snap(1, sc(9, 0, "old", h(100, 10))))
	mustIngest(t, a, snap(2))
	mustIngest(t, a, snap(3, sc(9, 0, "new", h(3, 10))))
	p := proc(a.View(), 9)
	if p.Exited || p.Comm != "new" || p.Syscalls[0].Total != 3 {
		t.Fatalf("reused pid kept old state: %+v", p)
	}
	if a.Totals(false).Resets != 0 {
		t.Fatal("pid reuse must not count as a reset")
	}
}

func TestExecRelabelsProcess(t *testing.T) {
	a := newAgg(t, Config{})
	mustIngest(t, a, snap(1, sc(5, 0, "bash", h(2, 10))))
	mustIngest(t, a, snap(2, sc(5, 0, "ls", h(4, 10)), sc(5, 1, "ls", h(1, 10))))
	if p := proc(a.View(), 5); p.Comm != "ls" {
		t.Fatalf("comm %q", p.Comm)
	}
	counts := map[string]uint64{}
	for _, c := range a.Totals(false).CommSys {
		counts[c.Comm+"/"+c.Syscall] = c.Hist.Count
	}
	if counts["bash/read"] != 2 || counts["ls/read"] != 2 || counts["ls/write"] != 1 {
		t.Fatalf("activity not split at exec: %v", counts)
	}
}

func TestMaxProcessesEvictsLeastRecent(t *testing.T) {
	a := newAgg(t, Config{MaxProcesses: 2})
	mustIngest(t, a, snap(1, sc(1, 0, "a", h(1, 1)), sc(2, 0, "b", h(1, 1))))
	mustIngest(t, a, snap(2, sc(2, 0, "b", h(2, 1)), sc(3, 0, "c", h(1, 1))))
	v := a.View()
	// pid 1 exited at seq 2 and is evicted first.
	if proc(v, 1) != nil || proc(v, 2) == nil || proc(v, 3) == nil {
		t.Fatalf("wrong victim: %+v", v.Processes)
	}
	mustIngest(t, a, snap(3, sc(2, 0, "b", h(2, 1)), sc(3, 0, "c", h(1, 1)), sc(4, 0, "d", h(1, 1))))
	v = a.View()
	if len(v.Processes) != 2 || v.Evicted != 2 {
		t.Fatalf("cap not enforced: %d processes, %d evicted", len(v.Processes), v.Evicted)
	}
}

func TestCommLabelOverflowIsSticky(t *testing.T) {
	a := newAgg(t, Config{MaxCommLabels: 1})
	mustIngest(t, a, snap(1, sc(1, 0, "first", h(1, 1)), sc(2, 0, "second", h(1, 1))))
	mustIngest(t, a, snap(2, sc(1, 0, "first", h(1, 1)), sc(2, 0, "second", h(3, 1))))
	got := map[string]uint64{}
	for _, c := range a.Totals(false).CommSys {
		got[c.Comm] = c.Hist.Count
	}
	if got["first"] != 1 || got[labels.Overflow] != 3 || len(got) != 2 {
		t.Fatalf("totals %v", got)
	}
}

func TestRunqSeries(t *testing.T) {
	a := newAgg(t, Config{})
	mustIngest(t, a, &events.Snapshot{Seq: 1, Elapsed: time.Second, Runq: []events.RunqSample{{TGID: 3, Comm: "w", Hist: h(10, 50_000)}}})
	mustIngest(t, a, &events.Snapshot{Seq: 2, Elapsed: 2 * time.Second, Runq: []events.RunqSample{{TGID: 3, Comm: "w", Hist: h(30, 50_000)}}})
	p := proc(a.View(), 3)
	if p.RunqRate != 15 || p.RunqP99 < 32768 || p.RunqP99 > 65536 {
		t.Fatalf("runq rate %v p99 %v", p.RunqRate, p.RunqP99)
	}
	tot := a.Totals(true)
	if tot.CommRunq[0].Hist.Count != 30 || tot.PIDRunq[0].Hist.Count != 30 {
		t.Fatalf("runq totals %+v %+v", tot.CommRunq, tot.PIDRunq)
	}
}

func tcpEv(kind events.TCPKind, tgid uint32, port uint16, lat time.Duration, kt uint64) events.TCPEvent {
	return events.TCPEvent{
		KtimeNs: kt, Latency: lat, TGID: tgid, Comm: "cli", Kind: kind,
		SAddr: netip.MustParseAddr("10.0.0.1"), DAddr: netip.MustParseAddr("10.0.0.2"), SPort: 4000, DPort: port,
	}
}

func TestTCPAggregation(t *testing.T) {
	a := newAgg(t, Config{RecentEvents: 3, MaxDestLabels: 1})
	s := &events.Snapshot{Seq: 1, Elapsed: time.Second, TCP: []events.TCPEvent{
		tcpEv(events.TCPConnect, 42, 80, 100*time.Microsecond, 1),
		tcpEv(events.TCPConnect, 42, 80, 300*time.Microsecond, 2),
		tcpEv(events.TCPConnectFail, 42, 80, time.Millisecond, 3),
		tcpEv(events.TCPRetransmit, 0, 80, 0, 4),
		tcpEv(events.TCPConnect, 42, 443, 0, 5), // past the dest cap: "other"
	}, Drops: []events.Drop{{Collector: "tcp", Reason: "ringbuf_full", Count: 2}}}
	mustIngest(t, a, s)
	v := a.View()
	if v.Connects != 3 || v.ConnectFails != 1 || v.Retransmits != 1 {
		t.Fatalf("totals %d %d %d", v.Connects, v.ConnectFails, v.Retransmits)
	}
	if len(v.Recent) != 3 || v.Recent[0].KtimeNs != 5 || v.Recent[2].KtimeNs != 3 {
		t.Fatalf("recent ring %+v", v.Recent)
	}
	if v.Dests[0].Dest != "10.0.0.2:80" || v.Dests[0].Connects != 2 || v.Dests[0].Retransmits != 1 || v.Dests[1].Dest != labels.Overflow {
		t.Fatalf("dests %+v", v.Dests)
	}
	p := proc(v, 42)
	if p == nil || p.Connects != 3 || p.ConnectFails != 1 || p.ConnectP50 == 0 {
		t.Fatalf("process tcp view %+v", p)
	}
	if len(v.Drops) != 1 || v.Drops[0].Count != 2 {
		t.Fatalf("drops %+v", v.Drops)
	}
	// Event-only processes age out after Retention silent snapshots.
	for seq := uint64(2); seq <= 32; seq++ {
		mustIngest(t, a, snap(seq))
	}
	if proc(a.View(), 42) != nil {
		t.Fatal("silent event-only process not evicted")
	}
	tot := a.Totals(false)
	if len(tot.Dests) != 2 || tot.Connects != 3 {
		t.Fatalf("dest totals lost: %+v", tot.Dests)
	}
}

// Property: over random churn (exits, PID reuse, resets, comm overflow),
// every exported comm total is non-decreasing, i.e. Prometheus counters
// built from Totals never reset.
func TestCommTotalsMonotonicProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	a := newAgg(t, Config{Retention: 2, MaxProcesses: 6, MaxCommLabels: 3, Window: 4})
	cum := map[[2]uint32]hist.Log2{}
	prev := map[string]uint64{}
	comms := []string{"a", "b", "c", "d", "e"}
	for seq := uint64(1); seq <= 400; seq++ {
		var samples []events.SyscallSample
		for tgid := uint32(1); tgid <= 8; tgid++ {
			if r.IntN(4) == 0 {
				continue // process absent this snapshot (exited / gc'd)
			}
			for nr := uint32(0); nr < 3; nr++ {
				k := [2]uint32{tgid, nr}
				c := cum[k]
				if r.IntN(25) == 0 {
					c = hist.Log2{} // kernel key re-created
				}
				for range r.IntN(5) {
					c.Record(uint64(1 + r.IntN(1<<20)))
				}
				cum[k] = c
				samples = append(samples, sc(tgid, nr, comms[r.IntN(len(comms))], c))
			}
		}
		mustIngest(t, a, snap(seq, samples...))
		for _, ct := range a.Totals(false).CommSys {
			key := ct.Comm + "/" + ct.Syscall
			if ct.Hist.Count < prev[key] {
				t.Fatalf("seq %d: %s went from %d to %d", seq, key, prev[key], ct.Hist.Count)
			}
			prev[key] = ct.Hist.Count
		}
		if n := len(a.View().Processes); n > 6 {
			t.Fatalf("seq %d: %d processes over cap", seq, n)
		}
	}
}

func BenchmarkIngest(b *testing.B) {
	a, _ := New(Config{Arch: "x86_64"})
	samples := make([]events.SyscallSample, 0, 2000)
	for tgid := uint32(1); tgid <= 100; tgid++ {
		for nr := uint32(0); nr < 20; nr++ {
			samples = append(samples, sc(tgid, nr, "bench", h(int(nr)+1, 1000)))
		}
	}
	b.ReportAllocs()
	seq := uint64(0)
	for b.Loop() {
		seq++
		for i := range samples {
			samples[i].Hist.Record(2000)
		}
		if err := a.Ingest(&events.Snapshot{Seq: seq, Elapsed: time.Duration(seq) * time.Second, Syscalls: samples}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(samples)), "samples/op")
}

func BenchmarkView(b *testing.B) {
	a, _ := New(Config{Arch: "x86_64"})
	for seq := uint64(1); seq <= 10; seq++ {
		var samples []events.SyscallSample
		for tgid := uint32(1); tgid <= 100; tgid++ {
			for nr := uint32(0); nr < 20; nr++ {
				samples = append(samples, sc(tgid, nr, "bench", h(int(seq), 1000)))
			}
		}
		_ = a.Ingest(&events.Snapshot{Seq: seq, Elapsed: time.Duration(seq) * time.Second, Syscalls: samples})
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = a.View()
	}
}
