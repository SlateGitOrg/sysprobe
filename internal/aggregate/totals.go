package aggregate

import (
	"sort"

	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

// CommSyscall is the cumulative histogram of one syscall across every
// process that ever ran under one comm label. It never decreases.
type CommSyscall struct {
	Comm    string
	Syscall string
	Hist    hist.Log2
}

// CommRunq is the cumulative run-queue histogram of one comm label.
type CommRunq struct {
	Comm string
	Hist hist.Log2
}

// PIDSyscall is the cumulative histogram of one syscall in one live (or
// recently exited) process. It disappears when the process is evicted.
type PIDSyscall struct {
	TGID    uint32
	Comm    string
	Syscall string
	Hist    hist.Log2
}

// PIDRunq is the cumulative run-queue histogram of one tracked process.
type PIDRunq struct {
	TGID uint32
	Comm string
	Hist hist.Log2
}

// DestTotal is cumulative TCP activity towards one destination label.
type DestTotal struct {
	Dest        string
	ConnectOK   hist.Log2
	ConnectFail hist.Log2
	Retransmits uint64
}

// Totals is a copy of every cumulative series, for exporters.
type Totals struct {
	Snapshots   uint64
	Processes   int
	Resets      uint64
	Evicted     uint64
	CommSys     []CommSyscall
	CommRunq    []CommRunq
	PIDSys      []PIDSyscall
	PIDRunq     []PIDRunq
	Dests       []DestTotal
	Drops       []events.Drop
	Connects    uint64
	Fails       uint64
	Retransmits uint64
}

// Totals copies the cumulative series, sorted for deterministic output.
// perPID controls whether per-process series are included (they are the
// expensive part on hosts with many processes).
func (a *Aggregator) Totals(perPID bool) Totals {
	a.mu.RLock()
	defer a.mu.RUnlock()
	t := Totals{
		Snapshots: a.seq, Processes: len(a.procs), Resets: a.resets, Evicted: a.evicted,
		Connects: a.tcp.connects, Fails: a.tcp.fails, Retransmits: a.tcp.retransmits,
	}
	for k, h := range a.commSys {
		t.CommSys = append(t.CommSys, CommSyscall{Comm: k.comm, Syscall: a.table.Name(k.nr), Hist: *h})
	}
	sort.Slice(t.CommSys, func(i, j int) bool {
		if t.CommSys[i].Comm != t.CommSys[j].Comm {
			return t.CommSys[i].Comm < t.CommSys[j].Comm
		}
		return t.CommSys[i].Syscall < t.CommSys[j].Syscall
	})
	for c, h := range a.commRunq {
		t.CommRunq = append(t.CommRunq, CommRunq{Comm: c, Hist: *h})
	}
	sort.Slice(t.CommRunq, func(i, j int) bool { return t.CommRunq[i].Comm < t.CommRunq[j].Comm })
	if perPID {
		for _, p := range a.procs {
			for nr, sr := range p.sys {
				t.PIDSys = append(t.PIDSys, PIDSyscall{TGID: p.tgid, Comm: p.comm, Syscall: a.table.Name(nr), Hist: sr.total})
			}
			if p.runq != nil {
				t.PIDRunq = append(t.PIDRunq, PIDRunq{TGID: p.tgid, Comm: p.comm, Hist: p.runq.total})
			}
		}
		sort.Slice(t.PIDSys, func(i, j int) bool {
			if t.PIDSys[i].TGID != t.PIDSys[j].TGID {
				return t.PIDSys[i].TGID < t.PIDSys[j].TGID
			}
			return t.PIDSys[i].Syscall < t.PIDSys[j].Syscall
		})
		sort.Slice(t.PIDRunq, func(i, j int) bool { return t.PIDRunq[i].TGID < t.PIDRunq[j].TGID })
	}
	for d, ds := range a.destStats {
		t.Dests = append(t.Dests, DestTotal{Dest: d, ConnectOK: ds.ok, ConnectFail: ds.fail, Retransmits: ds.retransmits})
	}
	sort.Slice(t.Dests, func(i, j int) bool { return t.Dests[i].Dest < t.Dests[j].Dest })
	for k, c := range a.drops {
		t.Drops = append(t.Drops, events.Drop{Collector: k.collector, Reason: k.reason, Count: c})
	}
	sort.Slice(t.Drops, func(i, j int) bool {
		if t.Drops[i].Collector != t.Drops[j].Collector {
			return t.Drops[i].Collector < t.Drops[j].Collector
		}
		return t.Drops[i].Reason < t.Drops[j].Reason
	})
	return t
}
