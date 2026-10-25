package top

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/aggregate"
	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

var update = flag.Bool("update", false, "rewrite golden files")

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
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func lat(n int, ns uint64) hist.Log2 {
	var h hist.Log2
	for range n {
		h.Record(ns)
	}
	return h
}

func view() aggregate.View {
	ev := func(kind events.TCPKind, tgid uint32, kt uint64, lat time.Duration) events.TCPEvent {
		return events.TCPEvent{KtimeNs: kt, Latency: lat, TGID: tgid, Comm: "curl", Kind: kind,
			SAddr: netip.MustParseAddr("10.0.0.1"), DAddr: netip.MustParseAddr("10.0.0.9"), SPort: 40000, DPort: 443}
	}
	return aggregate.View{
		Arch: "x86_64", Seq: 12, Elapsed: 12 * time.Second, Window: 10 * time.Second,
		Processes: []aggregate.ProcessView{
			{TGID: 100, Comm: "postgres", SyscallRate: 2500, SyscallBusy: 0.42, SyscallP50: 3 * time.Microsecond,
				SyscallP99: 2 * time.Millisecond, RunqRate: 300, RunqBusy: 0.01, RunqP99: 80 * time.Microsecond,
				Syscalls: []aggregate.SyscallView{
					{NR: 17, Name: "pread64", Count: 20000, Rate: 2000, Busy: 0.4, P50: 4 * time.Microsecond, P99: 2 * time.Millisecond, Total: 24000, Hist: lat(20000, 4000)},
					{NR: 0, Name: "read", Count: 5000, Rate: 500, Busy: 0.02, P50: time.Microsecond, P99: 9 * time.Microsecond, Total: 6000, Hist: lat(5000, 1000)},
					{NR: 3, Name: "close", Total: 2},
				}},
			{TGID: 7, Comm: "a-very-long-command-name", SyscallRate: 15000, SyscallBusy: 0.05, SyscallP50: 500, SyscallP99: 10 * time.Microsecond,
				RunqRate: 50, RunqBusy: 0.2, RunqP99: 4 * time.Millisecond,
				Syscalls: []aggregate.SyscallView{{NR: 39, Name: "getpid", Count: 150000, Rate: 15000, Busy: 0.05}}},
			{TGID: 55, Comm: "curl", Exited: true, Connects: 3, ConnectFails: 1, SyscallP99: 50 * time.Millisecond},
			{TGID: 2, Comm: "kthreadd"},
		},
		Dests: []aggregate.DestView{{Dest: "10.0.0.9:443", Connects: 3, ConnectFails: 1, Retransmits: 2,
			ConnectP50: 300 * time.Microsecond, ConnectP99: 900 * time.Microsecond}},
		Recent: []events.TCPEvent{
			ev(events.TCPRetransmit, 0, 3_500_000_000, 0),
			ev(events.TCPConnectFail, 55, 1_200_000_000, 2*time.Second),
			ev(events.TCPConnect, 55, 1_000_000_000, 300*time.Microsecond),
		},
		Drops:    []events.Drop{{Collector: "syscalls", Reason: "missed_start", Count: 12}, {Collector: "tcp", Reason: "ringbuf_full"}},
		Connects: 3, ConnectFails: 1, Retransmits: 2, Resets: 1, Evicted: 4,
	}
}

func TestRenderGolden(t *testing.T) {
	v := view()
	golden(t, "render-default.txt", Render(&v, Options{}))
	golden(t, "render-runq-exited.txt", Render(&v, Options{Sort: SortRunq, ShowExited: true, Rows: 2, Paused: true, Events: -1, Dests: -1}))
}

func TestSortKeys(t *testing.T) {
	v := view()
	order := func(k SortKey) []uint32 {
		ps := append([]aggregate.ProcessView(nil), v.Processes...)
		sortProcs(ps, k)
		var out []uint32
		for _, p := range ps {
			out = append(out, p.TGID)
		}
		return out
	}
	cases := map[SortKey][]uint32{
		SortBusy: {100, 7, 2, 55},
		SortRate: {7, 100, 2, 55},
		SortP99:  {55, 100, 7, 2},
		SortRunq: {7, 100, 2, 55},
		SortPID:  {2, 7, 55, 100},
	}
	for k, want := range cases {
		got := order(k)
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("sort %s: %v, want %v", k, got, want)
				break
			}
		}
	}
	for i, k := range SortKeys {
		if k.Next() != SortKeys[(i+1)%len(SortKeys)] {
			t.Errorf("%s.Next() = %s", k, k.Next())
		}
		if p, err := ParseSortKey(string(k)); err != nil || p != k {
			t.Errorf("parse %s: %v", k, err)
		}
	}
	if SortKey("x").Next() != SortBusy {
		t.Error("unknown key should cycle to busy")
	}
	if _, err := ParseSortKey("cpu"); err == nil {
		t.Error("unknown key accepted")
	}
}

func TestFormatting(t *testing.T) {
	durs := map[time.Duration]string{
		0: "-", -5: "-", 999: "999ns", 1500: "1.5us", 2500 * time.Microsecond: "2.5ms", 3 * time.Second: "3.00s",
	}
	for d, want := range durs {
		if got := Dur(d); got != want {
			t.Errorf("Dur(%v) = %q, want %q", d, got, want)
		}
	}
	if pct(0) != "-" || pct(0.123) != "12.3%" {
		t.Error("pct")
	}
	if rate(0) != "-" || rate(12.34) != "12.3" || rate(25000) != "25k" {
		t.Error("rate")
	}
	if trunc("abcdef", 4) != "abc~" || trunc("ab", 4) != "ab" {
		t.Error("trunc")
	}
	for ns, want := range map[uint64]string{512: "512ns", 2048: "2us", 4 << 20: "4ms", 1 << 31: "2s"} {
		if got := bound(ns); got != want {
			t.Errorf("bound(%d) = %q, want %q", ns, got, want)
		}
	}
}

func TestRenderProcess(t *testing.T) {
	v := view()
	out, err := RenderProcess(&v, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "process-100.txt", out)
	if _, err := RenderProcess(&v, 999, 1); err == nil {
		t.Error("unknown pid accepted")
	}
	out, _ = RenderProcess(&v, 55, 2)
	if !strings.Contains(out, "(exited)") {
		t.Errorf("exited marker missing:\n%s", out)
	}
}

func TestBars(t *testing.T) {
	var empty hist.Log2
	if Bars(&empty, 10) != "    (empty)\n" {
		t.Error("empty bars")
	}
	var h hist.Log2
	h.Buckets[10] = 1000
	h.Buckets[12] = 1
	h.Buckets[hist.Slots-1] = 2
	out := Bars(&h, 10)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != hist.Slots-10 {
		t.Fatalf("%d rows:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "##########") || !strings.Contains(lines[2], "|#") || !strings.Contains(lines[len(lines)-1], "+Inf") {
		t.Errorf("bars:\n%s", out)
	}
}
