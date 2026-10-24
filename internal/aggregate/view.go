package aggregate

import (
	"sort"
	"time"

	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/hist"
)

// SyscallView is one syscall of one process over the sliding window.
type SyscallView struct {
	NR    uint32
	Name  string
	Count uint64        // calls completed in the window
	Rate  float64       // calls per second
	Busy  float64       // summed latency / window length (1.0 = one thread always inside)
	P50   time.Duration // window quantiles (log2 bucket interpolation)
	P99   time.Duration
	Total uint64 // calls since first seen
	// Hist is the window histogram the fields above were derived from.
	Hist hist.Log2
}

// ProcessView is one process over the sliding window.
type ProcessView struct {
	TGID   uint32
	Comm   string
	Exited bool

	SyscallRate float64
	SyscallBusy float64
	SyscallP50  time.Duration
	SyscallP99  time.Duration
	// Syscalls is sorted by Busy, descending (ties by NR).
	Syscalls []SyscallView

	RunqRate float64 // run-queue waits per second
	RunqBusy float64 // summed run-queue delay / window length
	RunqP50  time.Duration
	RunqP99  time.Duration

	Connects     uint64 // completed connects in the window
	ConnectFails uint64
	ConnectP50   time.Duration
}

// DestView is cumulative TCP activity towards one destination label.
type DestView struct {
	Dest         string
	Connects     uint64
	ConnectFails uint64
	Retransmits  uint64
	ConnectP50   time.Duration
	ConnectP99   time.Duration
}

// View is an immutable picture of the aggregate for rendering.
type View struct {
	Arch      string
	Seq       uint64
	Elapsed   time.Duration
	Window    time.Duration // time covered by the sliding window
	Processes []ProcessView // sorted by SyscallBusy, descending
	Dests     []DestView    // sorted by connects+retransmits, descending
	Recent    []events.TCPEvent
	Drops     []events.Drop
	Resets    uint64
	Evicted   uint64

	Connects, ConnectFails, Retransmits uint64
}

func perSec(n uint64, w time.Duration) float64 {
	if w <= 0 {
		return 0
	}
	return float64(n) / w.Seconds()
}

func busy(h *hist.Log2, w time.Duration) float64 {
	if w <= 0 {
		return 0
	}
	return float64(h.SumNs) / float64(w)
}

func q(h *hist.Log2, p float64) time.Duration {
	return time.Duration(h.Quantile(p))
}

// View renders the current aggregate.
func (a *Aggregator) View() View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w := a.steps.sum(a.seq)
	v := View{
		Arch: a.table.Arch(), Seq: a.seq, Elapsed: a.elapsed, Window: w,
		Resets: a.resets, Evicted: a.evicted,
		Connects: a.tcp.connects, ConnectFails: a.tcp.fails, Retransmits: a.tcp.retransmits,
	}
	v.Processes = make([]ProcessView, 0, len(a.procs))
	for _, p := range a.procs {
		v.Processes = append(v.Processes, a.processView(p, w))
	}
	sort.Slice(v.Processes, func(i, j int) bool {
		pi, pj := &v.Processes[i], &v.Processes[j]
		if pi.SyscallBusy != pj.SyscallBusy {
			return pi.SyscallBusy > pj.SyscallBusy
		}
		return pi.TGID < pj.TGID
	})
	for label, ds := range a.destStats {
		v.Dests = append(v.Dests, DestView{
			Dest: label, Connects: ds.ok.Count, ConnectFails: ds.fail.Count, Retransmits: ds.retransmits,
			ConnectP50: q(&ds.ok, 0.5), ConnectP99: q(&ds.ok, 0.99),
		})
	}
	sort.Slice(v.Dests, func(i, j int) bool {
		di, dj := &v.Dests[i], &v.Dests[j]
		ai := di.Connects + di.ConnectFails + di.Retransmits
		aj := dj.Connects + dj.ConnectFails + dj.Retransmits
		if ai != aj {
			return ai > aj
		}
		return di.Dest < dj.Dest
	})
	for i := 0; i < a.recentLen; i++ {
		idx := (a.recentNext - 1 - i + len(a.recent)) % len(a.recent)
		v.Recent = append(v.Recent, a.recent[idx])
	}
	for k, c := range a.drops {
		v.Drops = append(v.Drops, events.Drop{Collector: k.collector, Reason: k.reason, Count: c})
	}
	sort.Slice(v.Drops, func(i, j int) bool {
		if v.Drops[i].Collector != v.Drops[j].Collector {
			return v.Drops[i].Collector < v.Drops[j].Collector
		}
		return v.Drops[i].Reason < v.Drops[j].Reason
	})
	return v
}

func (a *Aggregator) processView(p *process, w time.Duration) ProcessView {
	pv := ProcessView{TGID: p.tgid, Comm: p.comm, Exited: p.exitSeq != 0}
	var all hist.Log2
	pv.Syscalls = make([]SyscallView, 0, len(p.sys))
	for nr, sr := range p.sys {
		h := sr.win.sum(a.seq)
		all.Add(&h)
		pv.Syscalls = append(pv.Syscalls, SyscallView{
			NR: nr, Name: a.table.Name(nr), Count: h.Count, Rate: perSec(h.Count, w),
			Busy: busy(&h, w), P50: q(&h, 0.5), P99: q(&h, 0.99), Total: sr.total.Count, Hist: h,
		})
	}
	sort.Slice(pv.Syscalls, func(i, j int) bool {
		si, sj := &pv.Syscalls[i], &pv.Syscalls[j]
		if si.Busy != sj.Busy {
			return si.Busy > sj.Busy
		}
		return si.NR < sj.NR
	})
	pv.SyscallRate, pv.SyscallBusy = perSec(all.Count, w), busy(&all, w)
	pv.SyscallP50, pv.SyscallP99 = q(&all, 0.5), q(&all, 0.99)
	if p.runq != nil {
		h := p.runq.win.sum(a.seq)
		pv.RunqRate, pv.RunqBusy = perSec(h.Count, w), busy(&h, w)
		pv.RunqP50, pv.RunqP99 = q(&h, 0.5), q(&h, 0.99)
	}
	if p.connOK != nil {
		h := p.connOK.win.sum(a.seq)
		pv.Connects, pv.ConnectP50 = h.Count, q(&h, 0.5)
	}
	if p.connFail != nil {
		h := p.connFail.win.sum(a.seq)
		pv.ConnectFails = h.Count
	}
	return pv
}
