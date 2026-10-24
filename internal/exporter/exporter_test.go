package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/hist"
)

type fakeSource struct {
	t      aggregate.Totals
	perPID []bool
}

func (f *fakeSource) Totals(perPID bool) aggregate.Totals {
	f.perPID = append(f.perPID, perPID)
	return f.t
}

func lat(ns ...uint64) hist.Log2 {
	var h hist.Log2
	for _, n := range ns {
		h.Record(n)
	}
	return h
}

func totals() aggregate.Totals {
	return aggregate.Totals{
		Snapshots: 7, Processes: 2, Resets: 1, Evicted: 3,
		CommSys:  []aggregate.CommSyscall{{Comm: "nginx", Syscall: "read", Hist: lat(500, 3000, 2_000_000)}},
		CommRunq: []aggregate.CommRunq{{Comm: "nginx", Hist: lat(40_000)}},
		PIDSys:   []aggregate.PIDSyscall{{TGID: 12, Comm: "nginx", Syscall: "read", Hist: lat(500)}},
		PIDRunq:  []aggregate.PIDRunq{{TGID: 12, Comm: "nginx", Hist: lat(40_000)}},
		Dests: []aggregate.DestTotal{{
			Dest: "10.0.0.2:443", ConnectOK: lat(80_000), ConnectFail: lat(), Retransmits: 4,
		}},
		Drops: []events.Drop{{Collector: "tcp", Reason: "ringbuf_full", Count: 9}},
	}
}

func TestParseLabelMode(t *testing.T) {
	for _, s := range []string{"comm", "pid"} {
		if m, err := ParseLabelMode(s); err != nil || string(m) != s {
			t.Errorf("%s: %v %v", s, m, err)
		}
	}
	if _, err := ParseLabelMode("tid"); err == nil {
		t.Error("tid accepted")
	}
}

func TestOptionDefaults(t *testing.T) {
	o := Options{MinPow: 40, MaxPow: 99}.withDefaults()
	if o.Labels != ByComm || o.Step != 2 || o.MaxPow != 34 || o.MinPow != 34 {
		t.Fatalf("defaults %+v", o)
	}
	c := New(&fakeSource{}, Options{})
	if len(c.pows) != 13 || c.pows[0] != 10 || c.pows[12] != 34 {
		t.Fatalf("bucket powers %v", c.pows)
	}
}

// Golden exposition: bucket edges are exact powers of two in seconds and
// cumulative counts match the log2 buckets with no re-bucketing error.
func TestCollectByComm(t *testing.T) {
	src := &fakeSource{t: totals()}
	c := New(src, Options{MinPow: 10, MaxPow: 22, Step: 6})
	want := `
# HELP sysprobe_syscall_latency_seconds Syscall latency (sys_enter to sys_exit) per process and syscall.
# TYPE sysprobe_syscall_latency_seconds histogram
sysprobe_syscall_latency_seconds_bucket{comm="nginx",syscall="read",le="1.024e-06"} 1
sysprobe_syscall_latency_seconds_bucket{comm="nginx",syscall="read",le="6.5536e-05"} 2
sysprobe_syscall_latency_seconds_bucket{comm="nginx",syscall="read",le="0.004194304"} 3
sysprobe_syscall_latency_seconds_bucket{comm="nginx",syscall="read",le="+Inf"} 3
sysprobe_syscall_latency_seconds_sum{comm="nginx",syscall="read"} 0.0020035
sysprobe_syscall_latency_seconds_count{comm="nginx",syscall="read"} 3
# HELP sysprobe_tcp_retransmits_total TCP segments retransmitted, per destination.
# TYPE sysprobe_tcp_retransmits_total counter
sysprobe_tcp_retransmits_total{dest="10.0.0.2:443"} 4
# HELP sysprobe_bpf_drops_total Samples the kernel side could not record, per collector and reason.
# TYPE sysprobe_bpf_drops_total counter
sysprobe_bpf_drops_total{collector="tcp",reason="ringbuf_full"} 9
# HELP sysprobe_snapshots_total Kernel map snapshots ingested.
# TYPE sysprobe_snapshots_total counter
sysprobe_snapshots_total 7
`
	names := []string{"sysprobe_syscall_latency_seconds", "sysprobe_tcp_retransmits_total", "sysprobe_bpf_drops_total", "sysprobe_snapshots_total"}
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), names...); err != nil {
		t.Fatal(err)
	}
	if src.perPID[0] {
		t.Error("comm mode asked for per-pid totals")
	}
	if n := testutil.CollectAndCount(c); n != 10 {
		t.Errorf("collected %d metrics, want 10", n)
	}
	problems, err := testutil.CollectAndLint(c)
	if err != nil || len(problems) != 0 {
		t.Errorf("lint: %v %v", err, problems)
	}
}

func TestCollectByPID(t *testing.T) {
	src := &fakeSource{t: totals()}
	c := New(src, Options{Labels: ByPID, MinPow: 16, MaxPow: 16})
	want := `
# HELP sysprobe_runq_latency_seconds Run-queue latency (runnable to running) per process.
# TYPE sysprobe_runq_latency_seconds histogram
sysprobe_runq_latency_seconds_bucket{comm="nginx",pid="12",le="6.5536e-05"} 1
sysprobe_runq_latency_seconds_bucket{comm="nginx",pid="12",le="+Inf"} 1
sysprobe_runq_latency_seconds_sum{comm="nginx",pid="12"} 4e-05
sysprobe_runq_latency_seconds_count{comm="nginx",pid="12"} 1
# HELP sysprobe_tcp_connect_latency_seconds TCP active-open latency (SYN_SENT to ESTABLISHED or failure) per destination.
# TYPE sysprobe_tcp_connect_latency_seconds histogram
sysprobe_tcp_connect_latency_seconds_bucket{dest="10.0.0.2:443",result="fail",le="6.5536e-05"} 0
sysprobe_tcp_connect_latency_seconds_bucket{dest="10.0.0.2:443",result="fail",le="+Inf"} 0
sysprobe_tcp_connect_latency_seconds_sum{dest="10.0.0.2:443",result="fail"} 0
sysprobe_tcp_connect_latency_seconds_count{dest="10.0.0.2:443",result="fail"} 0
sysprobe_tcp_connect_latency_seconds_bucket{dest="10.0.0.2:443",result="ok",le="6.5536e-05"} 0
sysprobe_tcp_connect_latency_seconds_bucket{dest="10.0.0.2:443",result="ok",le="+Inf"} 1
sysprobe_tcp_connect_latency_seconds_sum{dest="10.0.0.2:443",result="ok"} 8e-05
sysprobe_tcp_connect_latency_seconds_count{dest="10.0.0.2:443",result="ok"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "sysprobe_runq_latency_seconds", "sysprobe_tcp_connect_latency_seconds"); err != nil {
		t.Fatal(err)
	}
	if !src.perPID[0] {
		t.Error("pid mode did not ask for per-pid totals")
	}
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("pedantic gather: %v", err)
	}
}
