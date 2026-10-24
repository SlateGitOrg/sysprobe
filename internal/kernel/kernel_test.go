package kernel

import (
	"strings"
	"testing"
)

func TestParseRelease(t *testing.T) {
	cases := map[string]Version{
		"6.8.0-1017-azure": {6, 8, 0}, "7.0.14-linuxkit": {7, 0, 14}, "5.15.0": {5, 15, 0},
		"4.19": {4, 19, 0}, "6": {6, 0, 0}, "5.10.0+": {5, 10, 0}, "6.1.0.": {6, 1, 0},
	}
	for in, want := range cases {
		got, err := ParseRelease(in)
		if err != nil || got != want {
			t.Errorf("ParseRelease(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "linux", "x.y"} {
		if _, err := ParseRelease(bad); err == nil {
			t.Errorf("ParseRelease(%q) accepted", bad)
		}
	}
	if (Version{5, 8, 0}).String() != "5.8.0" {
		t.Error("String")
	}
}

func TestAtLeast(t *testing.T) {
	v := Version{5, 8, 3}
	for o, want := range map[Version]bool{
		{5, 8, 3}: true, {5, 8, 4}: false, {5, 7, 9}: true, {5, 9, 0}: false, {4, 20, 0}: true, {6, 0, 0}: false,
	} {
		if v.AtLeast(o) != want {
			t.Errorf("%v >= %v should be %v", v, o, want)
		}
	}
}

func TestParseCapEff(t *testing.T) {
	status := "Name:\tsysprobe\nCapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\n"
	m, err := ParseCapEff(status)
	if err != nil || m != 0x1ffffffffff {
		t.Fatalf("%x %v", m, err)
	}
	if _, err := ParseCapEff("CapEff:\tzz\n"); err == nil {
		t.Error("bad hex accepted")
	}
	if _, err := ParseCapEff("Name:\tx\n"); err == nil {
		t.Error("missing line accepted")
	}
}

func full() Facts {
	f := Facts{
		Release: "6.8.0-1017-azure", Version: Version{6, 8, 0}, Arch: "x86_64", BTF: true,
		CapEff: 1 << CapSysAdmin, RingBuf: true, Tracing: true, PerCPUMap: true,
		Tracepoints: map[string]bool{},
	}
	for _, tp := range Tracepoints {
		f.Tracepoints[tp] = true
	}
	return f
}

func ready(cs []Collector) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.Name] = c.Ready()
	}
	return out
}

func TestEvaluate(t *testing.T) {
	f := full()
	if r := ready(Evaluate(&f)); !r["syscalls"] || !r["runq"] || !r["tcp"] {
		t.Fatalf("modern kernel not ready: %v", r)
	}
	// No BTF: only the syscalls collector (plain raw tracepoints) works, and
	// tracepoint presence cannot be verified.
	nobtf := full()
	nobtf.BTF, nobtf.Tracepoints = false, nil
	cs := Evaluate(&nobtf)
	if r := ready(cs); !r["syscalls"] || r["runq"] || r["tcp"] {
		t.Fatalf("no-BTF readiness %v", r)
	}
	if !strings.Contains(Report(&nobtf, cs), "unverified") {
		t.Error("report should say tracepoints are unverified")
	}
	// 5.4: no ring buffer, no tp_btf on 5.4 for tcp; runq needs 5.5.
	old := full()
	old.Version, old.Release = Version{5, 4, 0}, "5.4.0"
	if r := ready(Evaluate(&old)); !r["syscalls"] || r["runq"] || r["tcp"] {
		t.Fatalf("5.4 readiness %v", r)
	}
	// CAP_BPF + CAP_PERFMON is enough; CAP_BPF alone is not.
	caps := full()
	caps.CapEff = 1<<CapBPF | 1<<CapPerfmon
	if !caps.Privileged() {
		t.Error("CAP_BPF+CAP_PERFMON should be privileged")
	}
	caps.CapEff = 1 << CapBPF
	if r := ready(Evaluate(&caps)); r["syscalls"] {
		t.Error("CAP_BPF alone accepted")
	}
	missing := full()
	delete(missing.Tracepoints, "tcp_retransmit_skb")
	cs = Evaluate(&missing)
	if r := ready(cs); r["tcp"] || !r["runq"] {
		t.Fatalf("missing tracepoint readiness %v", r)
	}
	rep := Report(&missing, cs)
	if !strings.Contains(rep, "collector tcp      UNAVAILABLE") || !strings.Contains(rep, "[MISSING] tracepoint tcp_retransmit_skb") {
		t.Errorf("report:\n%s", rep)
	}
}

func TestGatherDoesNotPanic(t *testing.T) {
	f := Gather()
	if f.Release == "" || f.Arch == "" {
		t.Fatalf("empty facts %+v", f)
	}
	_ = Report(&f, Evaluate(&f))
}
