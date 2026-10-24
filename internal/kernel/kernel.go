// Package kernel decides whether the running kernel can host each sysprobe
// collector. The decision logic is pure (Evaluate over Facts) so it is unit
// tested on any OS; facts are gathered by Gather, which is Linux-only.
package kernel

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a kernel release triple.
type Version struct{ Major, Minor, Patch int }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// AtLeast reports v >= o.
func (v Version) AtLeast(o Version) bool {
	if v.Major != o.Major {
		return v.Major > o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor > o.Minor
	}
	return v.Patch >= o.Patch
}

// ParseRelease parses `uname -r` output such as "6.8.0-1017-azure",
// "7.0.14-linuxkit" or "5.15.0". Missing components are zero.
func ParseRelease(r string) (Version, error) {
	core := r
	if i := strings.IndexFunc(r, func(c rune) bool { return c != '.' && (c < '0' || c > '9') }); i >= 0 {
		core = r[:i]
	}
	parts := strings.Split(strings.TrimRight(core, "."), ".")
	var nums [3]int
	if parts[0] == "" {
		return Version{}, fmt.Errorf("unparseable kernel release %q", r)
	}
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return Version{}, fmt.Errorf("unparseable kernel release %q: %w", r, err)
		}
		nums[i] = n
	}
	return Version{nums[0], nums[1], nums[2]}, nil
}

// Capability bits from linux/capability.h.
const (
	CapSysAdmin = 21
	CapPerfmon  = 38
	CapBPF      = 39
)

// ParseCapEff parses the CapEff hex mask from /proc/self/status.
func ParseCapEff(status string) (uint64, error) {
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return 0, fmt.Errorf("parse CapEff: %w", err)
			}
			return m, nil
		}
	}
	return 0, fmt.Errorf("no CapEff line in status")
}

// Facts describes the host as far as sysprobe cares.
type Facts struct {
	Release   string
	Version   Version
	Arch      string
	BTF       bool // /sys/kernel/btf/vmlinux readable
	CapEff    uint64
	RingBuf   bool // BPF_MAP_TYPE_RINGBUF supported
	Tracing   bool // BPF_PROG_TYPE_TRACING (tp_btf) supported
	PerCPUMap bool // BPF_MAP_TYPE_PERCPU_HASH supported
	// Tracepoints holds the tracepoints found in kernel BTF (a
	// "btf_trace_<name>" typedef exists for every tracepoint). Without BTF
	// it is nil and tracepoint presence is unverified.
	Tracepoints map[string]bool
}

func (f *Facts) has(c int) bool { return f.CapEff&(1<<uint(c)) != 0 }

// Privileged reports whether the capability set can load and attach
// tracing programs: CAP_SYS_ADMIN, or CAP_BPF together with CAP_PERFMON
// (kernel >= 5.8).
func (f *Facts) Privileged() bool {
	return f.has(CapSysAdmin) || (f.has(CapBPF) && f.has(CapPerfmon))
}

// Check is one requirement and whether the host meets it.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Collector requirements.
type Collector struct {
	Name   string
	Checks []Check
}

// Ready reports whether every check passed.
func (c *Collector) Ready() bool {
	for _, ch := range c.Checks {
		if !ch.OK {
			return false
		}
	}
	return true
}

func tp(f *Facts, name string) Check {
	if f.Tracepoints == nil {
		return Check{Name: "tracepoint " + name, OK: true, Detail: "unverified (no kernel BTF to inspect)"}
	}
	return Check{Name: "tracepoint " + name, OK: f.Tracepoints[name], Detail: "btf_trace_" + name + " in kernel BTF"}
}

func minVersion(f *Facts, v Version, why string) Check {
	return Check{Name: "kernel >= " + v.String(), OK: f.Version.AtLeast(v), Detail: why + " (running " + f.Release + ")"}
}

// Evaluate returns the per-collector requirement checks for a host.
// sysprobe attaches only raw and BTF-typed tracepoints, so tracefs is never
// required.
func Evaluate(f *Facts) []Collector {
	priv := Check{Name: "privileges", OK: f.Privileged(), Detail: "CAP_SYS_ADMIN, or CAP_BPF+CAP_PERFMON"}
	btf := Check{Name: "kernel BTF", OK: f.BTF, Detail: "CONFIG_DEBUG_INFO_BTF=y (/sys/kernel/btf/vmlinux)"}
	percpu := Check{Name: "per-CPU hash maps", OK: f.PerCPUMap, Detail: "BPF_MAP_TYPE_PERCPU_HASH"}
	tracing := Check{Name: "tracing programs", OK: f.Tracing, Detail: "BPF_PROG_TYPE_TRACING (tp_btf)"}
	return []Collector{
		{Name: "syscalls", Checks: []Check{
			minVersion(f, Version{4, 17, 0}, "raw tracepoints"), priv, percpu,
			tp(f, "sys_enter"), tp(f, "sys_exit"), tp(f, "sched_process_exit"), tp(f, "sched_process_exec"),
		}},
		{Name: "runq", Checks: []Check{
			minVersion(f, Version{5, 5, 0}, "BTF-typed tracepoints"), priv, btf, percpu, tracing,
			tp(f, "sched_wakeup"), tp(f, "sched_wakeup_new"), tp(f, "sched_switch"),
			tp(f, "sched_process_exit"), tp(f, "sched_process_exec"),
		}},
		{Name: "tcp", Checks: []Check{
			minVersion(f, Version{5, 8, 0}, "BPF ring buffer"), priv, btf, tracing,
			{Name: "ring buffer", OK: f.RingBuf, Detail: "BPF_MAP_TYPE_RINGBUF"},
			tp(f, "inet_sock_set_state"), tp(f, "tcp_retransmit_skb"),
		}},
	}
}

// Report renders Evaluate output as text.
func Report(f *Facts, cs []Collector) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kernel %s (%s), arch %s\n", f.Release, f.Version, f.Arch)
	for _, c := range cs {
		status := "READY"
		if !c.Ready() {
			status = "UNAVAILABLE"
		}
		fmt.Fprintf(&b, "\ncollector %-8s %s\n", c.Name, status)
		for _, ch := range c.Checks {
			mark := "ok "
			if !ch.OK {
				mark = "MISSING"
			}
			fmt.Fprintf(&b, "  [%-7s] %-36s %s\n", mark, ch.Name, ch.Detail)
		}
	}
	return b.String()
}

// Tracepoints is the full list sysprobe attaches to.
var Tracepoints = []string{
	"sys_enter", "sys_exit", "sched_process_exit", "sched_process_exec",
	"sched_wakeup", "sched_wakeup_new", "sched_switch",
	"inet_sock_set_state", "tcp_retransmit_skb",
}
