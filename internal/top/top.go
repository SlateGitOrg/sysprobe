// Package top renders an aggregate.View as a fixed-width text screen, the
// body of `sysprobe top` and of `sysprobe replay --once`. Rendering is a pure
// function of the view and options so it is golden-tested.
package top

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/aggregate"
	"github.com/SlateGitOrg/sysprobe/internal/events"
)

// SortKey orders the process table.
type SortKey string

// Sort keys accepted by --sort and cycled by the "s" key.
const (
	SortBusy SortKey = "busy" // time inside syscalls per second (IN-SYS)
	SortRate SortKey = "rate" // syscalls per second
	SortP99  SortKey = "p99"  // syscall p99
	SortRunq SortKey = "runq" // summed run-queue delay per second
	SortPID  SortKey = "pid"
)

// SortKeys lists the keys in cycling order.
var SortKeys = []SortKey{SortBusy, SortRate, SortP99, SortRunq, SortPID}

// ParseSortKey validates a sort key.
func ParseSortKey(s string) (SortKey, error) {
	for _, k := range SortKeys {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown sort key %q (want one of %v)", s, SortKeys)
}

// Next returns the key after k in SortKeys.
func (k SortKey) Next() SortKey {
	for i, x := range SortKeys {
		if x == k {
			return SortKeys[(i+1)%len(SortKeys)]
		}
	}
	return SortBusy
}

// Options controls rendering.
type Options struct {
	Sort SortKey
	// Rows caps the process table (default 20; negative hides the table).
	Rows int
	// Dests caps the destination table (default 5); Events caps the recent
	// event list (default 8). Zero means default; negative hides the section.
	Dests, Events int
	// ShowExited includes processes whose kernel series have vanished.
	ShowExited bool
	// Paused adds a marker to the header (interactive mode).
	Paused bool
}

func (o Options) withDefaults() Options {
	if o.Sort == "" {
		o.Sort = SortBusy
	}
	if o.Rows == 0 {
		o.Rows = 20
	}
	if o.Dests == 0 {
		o.Dests = 5
	}
	if o.Events == 0 {
		o.Events = 8
	}
	return o
}

// Dur formats a latency compactly with ASCII units ("-" for zero).
func Dur(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fus", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func pct(f float64) string {
	if f == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", f*100)
}

func rate(r float64) string {
	if r == 0 {
		return "-"
	}
	if r >= 10000 {
		return fmt.Sprintf("%.0fk", r/1000)
	}
	return fmt.Sprintf("%.1f", r)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func sortProcs(ps []aggregate.ProcessView, k SortKey) {
	less := func(a, b *aggregate.ProcessView) (bool, bool) {
		switch k {
		case SortRate:
			return a.SyscallRate > b.SyscallRate, a.SyscallRate != b.SyscallRate
		case SortP99:
			return a.SyscallP99 > b.SyscallP99, a.SyscallP99 != b.SyscallP99
		case SortRunq:
			return a.RunqBusy > b.RunqBusy, a.RunqBusy != b.RunqBusy
		case SortPID:
			return a.TGID < b.TGID, a.TGID != b.TGID
		default:
			return a.SyscallBusy > b.SyscallBusy, a.SyscallBusy != b.SyscallBusy
		}
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if l, decided := less(&ps[i], &ps[j]); decided {
			return l
		}
		return ps[i].TGID < ps[j].TGID
	})
}

// Render draws one screen.
func Render(v *aggregate.View, o Options) string {
	o = o.withDefaults()
	var b strings.Builder
	paused := ""
	if o.Paused {
		paused = "  [paused]"
	}
	fmt.Fprintf(&b, "sysprobe top  snapshot %d  elapsed %s  window %s  arch %s  sort %s%s\n",
		v.Seq, v.Elapsed.Round(time.Millisecond), v.Window.Round(time.Millisecond), v.Arch, o.Sort, paused)

	procs := make([]aggregate.ProcessView, 0, len(v.Processes))
	for _, p := range v.Processes {
		if p.Exited && !o.ShowExited {
			continue
		}
		procs = append(procs, p)
	}
	sortProcs(procs, o.Sort)
	fmt.Fprintf(&b, "processes %d  tcp connects %d  failed %d  retransmits %d  series resets %d  evicted %d\n",
		len(procs), v.Connects, v.ConnectFails, v.Retransmits, v.Resets, v.Evicted)
	if d := dropSummary(v.Drops); d != "" {
		fmt.Fprintf(&b, "kernel drops  %s\n", d)
	}
	b.WriteString("\n")
	rows := procs
	if o.Rows > 0 && len(rows) > o.Rows {
		rows = rows[:o.Rows]
	}
	if o.Rows < 0 {
		rows = nil
	} else {
		fmt.Fprintf(&b, "%7s %-15s %8s %7s %8s %8s  %-26s %8s %8s %5s\n",
			"PID", "COMM", "SYSC/s", "IN-SYS", "P50", "P99", "TOP SYSCALL (IN-SYS)", "RUNQ/s", "RQ-P99", "CONN")
	}
	for i := range rows {
		p := &rows[i]
		topSys := "-"
		if len(p.Syscalls) > 0 && p.Syscalls[0].Count > 0 {
			s := p.Syscalls[0]
			topSys = fmt.Sprintf("%s (%s)", trunc(s.Name, 16), pct(s.Busy))
		}
		comm := trunc(p.Comm, 15)
		if p.Exited {
			comm = trunc(p.Comm, 12) + " x"
		}
		conn := "-"
		if p.Connects+p.ConnectFails > 0 {
			conn = fmt.Sprintf("%d", p.Connects+p.ConnectFails)
		}
		fmt.Fprintf(&b, "%7d %-15s %8s %7s %8s %8s  %-26s %8s %8s %5s\n",
			p.TGID, comm, rate(p.SyscallRate), pct(p.SyscallBusy), Dur(p.SyscallP50), Dur(p.SyscallP99),
			topSys, rate(p.RunqRate), Dur(p.RunqP99), conn)
	}
	if hidden := len(procs) - len(rows); hidden > 0 && o.Rows >= 0 {
		fmt.Fprintf(&b, "        ... %d more\n", hidden)
	}
	if o.Dests > 0 && len(v.Dests) > 0 {
		b.WriteString("\n")
		fmt.Fprintf(&b, "%-40s %6s %6s %6s %8s %8s\n", "TCP DESTINATION", "CONN", "FAIL", "RETX", "P50", "P99")
		for i, d := range v.Dests {
			if i >= o.Dests {
				break
			}
			fmt.Fprintf(&b, "%-40s %6d %6d %6d %8s %8s\n", trunc(d.Dest, 40), d.Connects, d.ConnectFails,
				d.Retransmits, Dur(d.ConnectP50), Dur(d.ConnectP99))
		}
	}
	if o.Events > 0 && len(v.Recent) > 0 {
		b.WriteString("\nRECENT TCP EVENTS (newest first)\n")
		n := min(o.Events, len(v.Recent))
		base := v.Recent[n-1].KtimeNs
		for _, e := range v.Recent[:n] {
			b.WriteString(eventLine(&e, base))
		}
	}
	return b.String()
}

func eventLine(e *events.TCPEvent, base uint64) string {
	who := "softirq"
	if e.TGID != 0 {
		who = fmt.Sprintf("%s(%d)", e.Comm, e.TGID)
	}
	src := fmt.Sprintf("%s:%d", e.SAddr, e.SPort)
	if e.SPort == 0 {
		src = e.SAddr.String() + ":*" // failed connects can lose their port before the event
	}
	lat := ""
	if e.Kind != events.TCPRetransmit {
		lat = Dur(e.Latency)
	}
	off := time.Duration(e.KtimeNs - base)
	line := fmt.Sprintf("  +%-9s %-12s %-22s %s -> %s %s",
		off.Round(time.Millisecond), e.Kind, trunc(who, 22), src, e.Dest(), lat)
	return strings.TrimRight(line, " ") + "\n"
}

func dropSummary(ds []events.Drop) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		if d.Count > 0 {
			parts = append(parts, fmt.Sprintf("%s/%s=%d", d.Collector, d.Reason, d.Count))
		}
	}
	return strings.Join(parts, " ")
}
