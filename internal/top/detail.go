package top

import (
	"fmt"
	"strings"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/aggregate"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

// RenderProcess draws the per-syscall breakdown of one process, over the
// sliding window and over its whole tracked lifetime, then the latency
// distribution of its busiest syscalls (at most maxHists). Lifetime
// histograms are drawn when the window is empty (e.g. the process exited).
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
	fmt.Fprintf(&b, "process %d %s%s  window %s\n", p.TGID, p.Comm, state, v.Window.Round(time.Millisecond))
	fmt.Fprintf(&b, "  window: syscalls %s/s  in-sys %s  p50 %s  p99 %s  runq p50 %s p99 %s  connects %d failed %d\n\n",
		rate(p.SyscallRate), pct(p.SyscallBusy), Dur(p.SyscallP50), Dur(p.SyscallP99),
		Dur(p.RunqP50), Dur(p.RunqP99), p.Connects, p.ConnectFails)
	fmt.Fprintf(&b, "  %-20s %9s %8s %9s %9s | %10s %9s %9s %9s\n",
		"SYSCALL", "WIN-CALLS", "IN-SYS", "WIN-P50", "WIN-P99", "CALLS", "MEAN", "P50", "P99")
	for _, s := range p.Syscalls {
		if s.Total == 0 {
			continue
		}
		th := s.TotalHist
		fmt.Fprintf(&b, "  %-20s %9d %8s %9s %9s | %10d %9s %9s %9s\n", trunc(s.Name, 20), s.Count,
			pct(s.Busy), Dur(s.P50), Dur(s.P99), s.Total, Dur(time.Duration(th.Mean())),
			Dur(time.Duration(th.Quantile(0.5))), Dur(time.Duration(th.Quantile(0.99))))
	}
	shown := 0
	for i := range p.Syscalls {
		s := &p.Syscalls[i]
		if shown >= maxHists || s.Total == 0 {
			break
		}
		shown++
		h, scope := &s.Hist, fmt.Sprintf("window, %d calls", s.Count)
		if s.Count == 0 {
			h, scope = &s.TotalHist, fmt.Sprintf("lifetime, %d calls", s.Total)
		}
		fmt.Fprintf(&b, "\n  %s latency (%s)\n", s.Name, scope)
		b.WriteString(Bars(h, 40))
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
