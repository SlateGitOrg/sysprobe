package top

import (
	"fmt"
	"strings"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/hist"
)

// RenderProcess draws the per-syscall breakdown of one process and the
// latency distribution of its busiest syscalls (at most maxHists).
func RenderProcess(v *aggregate.View, tgid uint32, maxHists int) (string, error) {
	var p *aggregate.ProcessView
	for i := range v.Processes {
		if v.Processes[i].TGID == tgid {
			p = &v.Processes[i]
			break
		}
	}
	if p == nil {
		return "", fmt.Errorf("pid %d not tracked in this view", tgid)
	}
	var b strings.Builder
	state := ""
	if p.Exited {
		state = " (exited)"
	}
	fmt.Fprintf(&b, "process %d %s%s  window %s\n", p.TGID, p.Comm, state, v.Window)
	fmt.Fprintf(&b, "  syscalls %s/s  in-sys %s  p50 %s  p99 %s  runq p50 %s p99 %s  connects %d failed %d\n\n",
		rate(p.SyscallRate), pct(p.SyscallBusy), Dur(p.SyscallP50), Dur(p.SyscallP99),
		Dur(p.RunqP50), Dur(p.RunqP99), p.Connects, p.ConnectFails)
	fmt.Fprintf(&b, "  %-22s %10s %9s %8s %9s %9s %12s\n", "SYSCALL", "WINDOW", "RATE/s", "IN-SYS", "P50", "P99", "TOTAL")
	shown := 0
	for _, s := range p.Syscalls {
		if s.Count == 0 && s.Total == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-22s %10d %9s %8s %9s %9s %12d\n", trunc(s.Name, 22), s.Count, rate(s.Rate),
			pct(s.Busy), Dur(s.P50), Dur(s.P99), s.Total)
	}
	for _, s := range p.Syscalls {
		if shown >= maxHists || s.Count == 0 {
			break
		}
		shown++
		fmt.Fprintf(&b, "\n  %s latency (window, %d calls)\n", s.Name, s.Count)
		b.WriteString(Bars(&s.Hist, 40))
	}
	return b.String(), nil
}

// Bars draws the non-empty range of a log2 histogram as horizontal bars,
// one row per bucket, the longest bar width characters wide.
func Bars(h *hist.Log2, width int) string {
	lo, hi := -1, h.MaxSlot()
	var peak uint64
	for i, c := range h.Buckets {
		if c == 0 {
			continue
		}
		if lo < 0 {
			lo = i
		}
		peak = max(peak, c)
	}
	if lo < 0 {
		return "    (empty)\n"
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		c := h.Buckets[i]
		n := int(c * uint64(width) / peak)
		if c > 0 && n == 0 {
			n = 1
		}
		upper := "+Inf"
		if i < hist.Slots-1 {
			upper = bound(hist.Upper(i))
		}
		fmt.Fprintf(&b, "    %8s .. %-8s |%-*s| %d\n", bound(hist.Lower(i)), upper, width, strings.Repeat("#", n), c)
	}
	return b.String()
}

func bound(ns uint64) string {
	switch {
	case ns < 1000:
		return fmt.Sprintf("%dns", ns)
	case ns < 1000_000:
		return fmt.Sprintf("%.0fus", float64(ns)/1e3)
	case ns < 1000_000_000:
		return fmt.Sprintf("%.0fms", float64(ns)/1e6)
	default:
		return fmt.Sprintf("%.0fs", float64(ns)/1e9)
	}
}
