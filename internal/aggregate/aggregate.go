// Package aggregate turns the snapshot stream of a source into per-process
// metrics: cumulative totals for the Prometheus exporter and sliding-window
// rates and quantiles for the top view.
//
// Kernel maps hold cumulative histograms. Each snapshot is differenced
// against the previous reading of the same series (with reset detection),
// and the delta is folded into three places:
//
//   - the series' cumulative total (per process, evicted when it exits),
//   - the series' sliding window (last Window snapshots),
//   - a per-comm total that is never evicted, so exported counters stay
//     monotonic across process churn.
//
// A live process evicted over MaxProcesses still has its series in the
// kernel maps. Its last readings are kept as a tombstone until the next
// snapshot: if the tgid is in it, the new series difference against the
// tombstone instead of zero, so the comm totals are not credited with the
// whole cumulative history again; if not, the process exited and the
// tombstone is dropped.
//
// Ingest is O(samples*Slots); View is O((processes*series)*Window*Slots).
package aggregate

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/hist"
	"github.com/archit2501/sysprobe/internal/labels"
	"github.com/archit2501/sysprobe/internal/syscalls"
)

// Config tunes the aggregator. Zero fields take the defaults below.
type Config struct {
	// Arch selects the syscall name table (e.g. "aarch64", "amd64").
	Arch string
	// Window is the number of snapshots in the sliding window (default 10).
	Window int
	// Retention is how many snapshots an exited process stays visible
	// before it is evicted (default 30).
	Retention int
	// MaxProcesses caps tracked processes; exited, then the least recently
	// active are evicted first (default 4096). Evicting a live process
	// leaves a one-snapshot tombstone of its last kernel readings so the
	// comm totals stay exact when it is seen again.
	MaxProcesses int
	// MaxCommLabels caps distinct comm label values in exported totals;
	// later comms fold into "other" (default 256).
	MaxCommLabels int
	// MaxDestLabels caps distinct TCP destinations (default 64).
	MaxDestLabels int
	// RecentEvents is the size of the recent TCP event ring (default 50).
	RecentEvents int
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 10
	}
	if c.Retention <= 0 {
		c.Retention = 30
	}
	if c.MaxProcesses <= 0 {
		c.MaxProcesses = 4096
	}
	if c.MaxCommLabels <= 0 {
		c.MaxCommLabels = 256
	}
	if c.MaxDestLabels <= 0 {
		c.MaxDestLabels = 64
	}
	if c.RecentEvents <= 0 {
		c.RecentEvents = 50
	}
	return c
}

// ErrOutOfOrder is returned when a snapshot does not follow the previous one.
var ErrOutOfOrder = errors.New("snapshot out of order")

// tomb holds the last kernel readings of a live process evicted over
// MaxProcesses. It lives until the next snapshot is ingested.
type tomb struct {
	sys     map[uint32]hist.Log2
	runq    hist.Log2
	hasRunq bool
}

type series struct {
	last  hist.Log2 // previous cumulative kernel reading
	total hist.Log2 // accumulated deltas since first seen
	win   window
}

type process struct {
	tgid     uint32
	comm     string
	firstSeq uint64
	lastSeq  uint64 // last snapshot with any data for this process
	exitSeq  uint64 // snapshot at which its kernel series vanished (0: alive)
	hasHist  bool
	seed     *tomb // readings to difference new series against (this snapshot only)
	sys      map[uint32]*series
	runq     *series
	connOK   *series // connect latency histograms built from events
	connFail *series
}

type commSys struct {
	comm string
	nr   uint32
}

type destStats struct {
	ok, fail    hist.Log2
	retransmits uint64
}

type dropKey struct{ collector, reason string }

// Aggregator is safe for concurrent use: one goroutine ingests while others
// render views or serve scrapes.
type Aggregator struct {
	mu    sync.RWMutex
	cfg   Config
	table syscalls.Table

	seq     uint64
	elapsed time.Duration
	steps   steps

	procs map[uint32]*process
	tombs map[uint32]*tomb // live processes evicted by the last snapshot

	comms     *labels.Sticky
	commSys   map[commSys]*hist.Log2
	commRunq  map[string]*hist.Log2
	dests     *labels.Sticky
	destStats map[string]*destStats

	recent     []events.TCPEvent // ring, recentNext is the next write index
	recentNext int
	recentLen  int

	drops   map[dropKey]uint64
	resets  uint64
	evicted uint64
	tcp     struct{ connects, fails, retransmits uint64 }
}

// New returns an empty aggregator.
func New(cfg Config) (*Aggregator, error) {
	cfg = cfg.withDefaults()
	t, err := syscalls.ForArch(cfg.Arch)
	if err != nil {
		return nil, err
	}
	return &Aggregator{
		cfg:       cfg,
		table:     t,
		steps:     newSteps(cfg.Window),
		procs:     make(map[uint32]*process),
		tombs:     make(map[uint32]*tomb),
		comms:     labels.NewSticky(cfg.MaxCommLabels),
		commSys:   make(map[commSys]*hist.Log2),
		commRunq:  make(map[string]*hist.Log2),
		dests:     labels.NewSticky(cfg.MaxDestLabels),
		destStats: make(map[string]*destStats),
		recent:    make([]events.TCPEvent, cfg.RecentEvents),
		drops:     make(map[dropKey]uint64),
	}, nil
}

// Ingest folds one snapshot into the aggregate.
func (a *Aggregator) Ingest(s *events.Snapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Seq <= a.seq {
		return fmt.Errorf("%w: seq %d after %d", ErrOutOfOrder, s.Seq, a.seq)
	}
	if s.Elapsed < a.elapsed {
		return fmt.Errorf("%w: elapsed %v before %v", ErrOutOfOrder, s.Elapsed, a.elapsed)
	}
	a.steps.put(s.Seq, s.Elapsed-a.elapsed)
	a.seq, a.elapsed = s.Seq, s.Elapsed

	present := make(map[uint32]struct{}, len(a.procs))
	for i := range s.Syscalls {
		x := &s.Syscalls[i]
		p := a.histProcess(x.TGID, x.Comm, present)
		sr := p.sys[x.NR]
		if sr == nil {
			sr = a.newSeries()
			if p.seed != nil {
				sr.last = p.seed.sys[x.NR]
			}
			p.sys[x.NR] = sr
		}
		d := a.advance(sr, &x.Hist)
		a.commTotal(commSys{a.comms.Assign(p.comm), x.NR}).Add(&d)
	}
	for i := range s.Runq {
		x := &s.Runq[i]
		p := a.histProcess(x.TGID, x.Comm, present)
		if p.runq == nil {
			p.runq = a.newSeries()
			if p.seed != nil && p.seed.hasRunq {
				p.runq.last = p.seed.runq
			}
		}
		d := a.advance(p.runq, &x.Hist)
		label := a.comms.Assign(p.comm)
		t := a.commRunq[label]
		if t == nil {
			t = &hist.Log2{}
			a.commRunq[label] = t
		}
		t.Add(&d)
	}
	// Tombstones still here belong to tgids absent from this snapshot: the
	// process exited and its kernel series are gone, so a later process
	// with the same tgid must start from zero.
	clear(a.tombs)
	for _, p := range a.procs {
		p.seed = nil
		if _, ok := present[p.tgid]; !ok && p.hasHist && p.exitSeq == 0 {
			p.exitSeq = s.Seq
		}
	}
	for i := range s.TCP {
		a.ingestTCP(&s.TCP[i])
	}
	for _, d := range s.Drops {
		a.drops[dropKey{d.Collector, d.Reason}] = d.Count
	}
	a.evict()
	return nil
}

func (a *Aggregator) newSeries() *series {
	return &series{win: newWindow(a.cfg.Window)}
}

// histProcess returns the live process for a kernel-map sample, replacing a
// process record whose kernel series had vanished (the tgid was reused or
// its map entries were garbage-collected and re-created).
func (a *Aggregator) histProcess(tgid uint32, comm string, present map[uint32]struct{}) *process {
	p := a.procs[tgid]
	if p != nil && p.exitSeq != 0 {
		p = nil
	}
	if p == nil {
		p = &process{tgid: tgid, comm: comm, firstSeq: a.seq, sys: make(map[uint32]*series)}
		if t := a.tombs[tgid]; t != nil {
			p.seed = t // evicted while alive: its kernel series carried on
			delete(a.tombs, tgid)
		}
		a.procs[tgid] = p
	}
	if comm != "" {
		p.comm = comm // latest wins: the probe relabels a process after exec
	}
	p.hasHist = true
	p.lastSeq = a.seq
	present[tgid] = struct{}{}
	return p
}

// advance differences a cumulative reading against the series' previous one
// and records the delta.
func (a *Aggregator) advance(sr *series, cur *hist.Log2) hist.Log2 {
	d, ok := cur.Sub(&sr.last)
	if !ok {
		a.resets++
	}
	sr.last = *cur
	if d.IsZero() {
		return d
	}
	sr.total.Add(&d)
	sr.win.put(a.seq, &d)
	return d
}

func (a *Aggregator) commTotal(k commSys) *hist.Log2 {
	t := a.commSys[k]
	if t == nil {
		t = &hist.Log2{}
		a.commSys[k] = t
	}
	return t
}

func (a *Aggregator) ingestTCP(e *events.TCPEvent) {
	label := a.dests.Assign(e.Dest())
	ds := a.destStats[label]
	if ds == nil {
		ds = &destStats{}
		a.destStats[label] = ds
	}
	var one hist.Log2
	one.Record(uint64(max(e.Latency, 0)))
	switch e.Kind {
	case events.TCPRetransmit:
		ds.retransmits++
		a.tcp.retransmits++
	case events.TCPConnect:
		ds.ok.Add(&one)
		a.tcp.connects++
	case events.TCPConnectFail:
		ds.fail.Add(&one)
		a.tcp.fails++
	}
	if e.TGID != 0 && e.Kind != events.TCPRetransmit {
		p := a.procs[e.TGID]
		if p == nil {
			p = &process{tgid: e.TGID, comm: e.Comm, firstSeq: a.seq, sys: make(map[uint32]*series)}
			a.procs[e.TGID] = p
		}
		if p.comm == "" {
			p.comm = e.Comm
		}
		p.lastSeq = a.seq
		target := &p.connOK
		if e.Kind == events.TCPConnectFail {
			target = &p.connFail
		}
		if *target == nil {
			*target = a.newSeries()
		}
		(*target).total.Add(&one)
		(*target).win.put(a.seq, &one)
	}
	a.recent[a.recentNext] = *e
	a.recentNext = (a.recentNext + 1) % len(a.recent)
	a.recentLen = min(a.recentLen+1, len(a.recent))
}

// evict drops processes that exited more than Retention snapshots ago (or,
// for event-only processes, have been silent that long), then enforces
// MaxProcesses by evicting exited, then the least recently active. A live
// process evicted by the cap leaves a tombstone of its last readings.
func (a *Aggregator) evict() {
	ret := uint64(a.cfg.Retention)
	for tgid, p := range a.procs {
		gone := p.exitSeq != 0 && a.seq-p.exitSeq >= ret
		silent := !p.hasHist && a.seq-p.lastSeq >= ret
		if gone || silent {
			delete(a.procs, tgid)
			a.evicted++
		}
	}
	over := len(a.procs) - a.cfg.MaxProcesses
	if over <= 0 {
		return
	}
	victims := make([]*process, 0, len(a.procs))
	for _, p := range a.procs {
		victims = append(victims, p)
	}
	sort.Slice(victims, func(i, j int) bool {
		vi, vj := victims[i], victims[j]
		if (vi.exitSeq != 0) != (vj.exitSeq != 0) {
			return vi.exitSeq != 0
		}
		if vi.lastSeq != vj.lastSeq {
			return vi.lastSeq < vj.lastSeq
		}
		return vi.tgid < vj.tgid
	})
	for _, p := range victims[:over] {
		if p.hasHist && p.exitSeq == 0 {
			a.tombs[p.tgid] = p.tomb()
		}
		delete(a.procs, p.tgid)
		a.evicted++
	}
}

// tomb copies the process's last kernel readings.
func (p *process) tomb() *tomb {
	t := &tomb{sys: make(map[uint32]hist.Log2, len(p.sys))}
	for nr, sr := range p.sys {
		t.sys[nr] = sr.last
	}
	if p.runq != nil {
		t.runq, t.hasRunq = p.runq.last, true
	}
	return t
}
