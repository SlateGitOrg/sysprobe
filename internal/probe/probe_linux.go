//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/archit2501/sysprobe/internal/events"
)

// Stat indexes, mirroring STAT_* in bpf/sysprobe.h.
var statNames = [...]string{"missed_start", "hist_insert_failed", "ringbuf_full", "start_full"}

// Stats each collector can increment (indexes into statNames).
var (
	histStats = []int{0, 1, 3}
	tcpStats  = []int{0, 2, 3}
)

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}

// maxPendingTCP bounds the userspace queue between the ring-buffer reader
// and the snapshot loop; beyond it events are counted as dropped.
const maxPendingTCP = 100_000

// histSource is one loaded histogram collector (syscalls or runq).
type histSource struct {
	name     string
	hist     *ebpf.Map
	exited   *ebpf.Map
	execComm *ebpf.Map
	stats    *ebpf.Map
}

// Probe owns the loaded BPF objects and links.
type Probe struct {
	cfg      Config
	start    time.Time
	statuses []Status
	closers  []io.Closer

	sys, runq *histSource
	tcpStats  *ebpf.Map
	rb        *ringbuf.Reader

	mu         sync.Mutex
	pending    []events.TCPEvent
	decodeErrs uint64
	queueDrops uint64
	seq        uint64
	readerDone chan struct{}
}

// Open loads and attaches every requested collector. A collector that fails
// (old kernel, no BTF, missing tracepoint) is reported in Statuses and
// skipped; Open fails only when none could be started.
func Open(cfg Config) (*Probe, error) {
	cfg = cfg.withDefaults()
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	p := &Probe{cfg: cfg}
	self := uint32(0)
	if !cfg.IncludeSelf {
		self = uint32(os.Getpid())
	}
	type opener struct {
		name    string
		enabled bool
		open    func(self uint32) error
	}
	for _, o := range []opener{
		{CollectorSyscalls, cfg.Syscalls, p.openSyscalls},
		{CollectorRunq, cfg.Runq, p.openRunq},
		{CollectorTCP, cfg.TCP, p.openTCP},
	} {
		st := Status{Name: o.name, Enabled: o.enabled}
		if o.enabled {
			st.Err = o.open(self)
			if st.Err != nil {
				cfg.Logger.Warn("collector unavailable", "collector", o.name, "err", st.Err)
			} else {
				cfg.Logger.Info("collector attached", "collector", o.name)
			}
		}
		p.statuses = append(p.statuses, st)
	}
	if p.sys == nil && p.runq == nil && p.rb == nil {
		var errs []error
		for _, s := range p.statuses {
			if s.Err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Name, s.Err))
			}
		}
		_ = p.Close()
		if len(errs) == 0 {
			return nil, errors.New("no collectors enabled")
		}
		return nil, fmt.Errorf("no collector could be started: %w", errors.Join(errs...))
	}
	p.start = time.Now()
	return p, nil
}

// Statuses reports the outcome of each collector.
func (p *Probe) Statuses() []Status { return append([]Status(nil), p.statuses...) }

func loadErr(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("verifier rejected program: %w\nverifier log:\n%s", err, fmt.Sprintf("%+v", ve))
	}
	return err
}

func setVar(spec *ebpf.CollectionSpec, name string, v uint32) error {
	vs, ok := spec.Variables[name]
	if !ok {
		return fmt.Errorf("object has no variable %q", name)
	}
	return vs.Set(v)
}

func (p *Probe) attachTP(group, name string, prog *ebpf.Program) error {
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint %s/%s: %w", group, name, err)
	}
	p.closers = append(p.closers, l)
	return nil
}

func (p *Probe) attachBTF(prog *ebpf.Program, what string) error {
	l, err := link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceRawTp})
	if err != nil {
		return fmt.Errorf("attach tp_btf/%s: %w", what, err)
	}
	p.closers = append(p.closers, l)
	return nil
}

func (p *Probe) openSyscalls(self uint32) error {
	spec, err := loadSyscalls()
	if err != nil {
		return err
	}
	if err := setVar(spec, "targ_tgid", p.cfg.TargetPID); err != nil {
		return err
	}
	if err := setVar(spec, "self_tgid", self); err != nil {
		return err
	}
	var objs syscallsObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return loadErr(err)
	}
	p.closers = append(p.closers, &objs)
	for _, a := range []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"raw_syscalls", "sys_enter", objs.SysEnter},
		{"raw_syscalls", "sys_exit", objs.SysExit},
		{"sched", "sched_process_exit", objs.SchedProcessExit},
		{"sched", "sched_process_exec", objs.SchedProcessExec},
	} {
		if err := p.attachTP(a.group, a.name, a.prog); err != nil {
			return err
		}
	}
	p.sys = &histSource{name: CollectorSyscalls, hist: objs.SysHist, exited: objs.Exited, execComm: objs.ExecComm, stats: objs.Stats}
	return nil
}

func (p *Probe) openRunq(self uint32) error {
	spec, err := loadRunq()
	if err != nil {
		return err
	}
	if err := setVar(spec, "targ_tgid", p.cfg.TargetPID); err != nil {
		return err
	}
	if err := setVar(spec, "self_tgid", self); err != nil {
		return err
	}
	var objs runqObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return loadErr(err)
	}
	p.closers = append(p.closers, &objs)
	if err := p.attachBTF(objs.SchedWakeup, "sched_wakeup"); err != nil {
		return err
	}
	if err := p.attachBTF(objs.SchedWakeupNew, "sched_wakeup_new"); err != nil {
		return err
	}
	if err := p.attachBTF(objs.SchedSwitch, "sched_switch"); err != nil {
		return err
	}
	if err := p.attachTP("sched", "sched_process_exit", objs.SchedProcessExit); err != nil {
		return err
	}
	if err := p.attachTP("sched", "sched_process_exec", objs.SchedProcessExec); err != nil {
		return err
	}
	p.runq = &histSource{name: CollectorRunq, hist: objs.RunqHist, exited: objs.Exited, execComm: objs.ExecComm, stats: objs.Stats}
	return nil
}

func (p *Probe) openTCP(uint32) error {
	spec, err := loadTcp()
	if err != nil {
		return err
	}
	if err := setVar(spec, "targ_tgid", p.cfg.TargetPID); err != nil {
		return err
	}
	var objs tcpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return loadErr(err)
	}
	p.closers = append(p.closers, &objs)
	if err := p.attachTP("sock", "inet_sock_set_state", objs.InetSockSetState); err != nil {
		return err
	}
	if err := p.attachBTF(objs.TcpRetransmitSkb, "tcp_retransmit_skb"); err != nil {
		return err
	}
	rb, err := ringbuf.NewReader(objs.TcpEvents)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	p.closers = append(p.closers, rb)
	p.rb = rb
	p.tcpStats = objs.Stats
	return nil
}

// Run emits a snapshot every Interval until ctx is cancelled, then emits a
// final snapshot covering the partial last interval. An error from emit
// stops the loop and is returned.
func (p *Probe) Run(ctx context.Context, emit func(*events.Snapshot) error) error {
	if p.rb != nil {
		p.readerDone = make(chan struct{})
		go p.readRing()
	}
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s, err := p.collect()
			if err != nil {
				return err
			}
			return emit(s)
		case <-t.C:
			s, err := p.collect()
			if err != nil {
				return err
			}
			if err := emit(s); err != nil {
				return err
			}
		}
	}
}

func (p *Probe) readRing() {
	defer close(p.readerDone)
	for {
		rec, err := p.rb.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return
		}
		if err != nil {
			p.cfg.Logger.Warn("ring buffer read", "err", err)
			continue
		}
		if p.cfg.OnRawTCP != nil {
			p.cfg.OnRawTCP(rec.RawSample)
		}
		e, err := events.DecodeTCPEvent(rec.RawSample)
		p.mu.Lock()
		switch {
		case err != nil:
			p.decodeErrs++
		case len(p.pending) >= maxPendingTCP:
			p.queueDrops++
		default:
			p.pending = append(p.pending, e)
		}
		p.mu.Unlock()
	}
}

// collect reads every map into one snapshot and garbage-collects the
// series of processes that exited before the read started.
func (p *Probe) collect() (*events.Snapshot, error) {
	p.seq++
	s := &events.Snapshot{Seq: p.seq, Elapsed: time.Since(p.start)}
	if p.sys != nil {
		exited, err := exitedSet(p.sys.exited)
		if err != nil {
			return nil, err
		}
		var dead [][]byte
		err = p.readHist(p.sys, func(key []byte, h events.SyscallSample) {
			s.Syscalls = append(s.Syscalls, h)
			if _, ok := exited[h.TGID]; ok {
				dead = append(dead, key)
			}
		})
		if err != nil {
			return nil, err
		}
		p.gc(p.sys, dead, exited)
		s.Drops = append(s.Drops, readStats(p.sys, histStats)...)
	}
	if p.runq != nil {
		exited, err := exitedSet(p.runq.exited)
		if err != nil {
			return nil, err
		}
		var dead [][]byte
		err = p.readHist(p.runq, func(key []byte, h events.SyscallSample) {
			s.Runq = append(s.Runq, events.RunqSample{TGID: h.TGID, Comm: h.Comm, Hist: h.Hist})
			if _, ok := exited[h.TGID]; ok {
				dead = append(dead, key)
			}
		})
		if err != nil {
			return nil, err
		}
		p.gc(p.runq, dead, exited)
		s.Drops = append(s.Drops, readStats(p.runq, histStats)...)
	}
	if p.rb != nil {
		p.mu.Lock()
		s.TCP, p.pending = p.pending, nil
		decodeErrs, queueDrops := p.decodeErrs, p.queueDrops
		p.mu.Unlock()
		s.Drops = append(s.Drops, readStats(&histSource{name: CollectorTCP, stats: p.tcpStats}, tcpStats)...)
		s.Drops = append(s.Drops,
			events.Drop{Collector: CollectorTCP, Reason: "decode_error", Count: decodeErrs},
			events.Drop{Collector: CollectorTCP, Reason: "queue_full", Count: queueDrops})
	}
	return s, nil
}

// readHist iterates a per-CPU histogram map. Runq keys are a bare tgid;
// syscall keys are (tgid, nr).
func (p *Probe) readHist(src *histSource, fn func(key []byte, s events.SyscallSample)) error {
	comms, err := execComms(src.execComm)
	if err != nil {
		return err
	}
	var key []byte
	var perCPU [][]byte
	it := src.hist.Iterate()
	for it.Next(&key, &perCPU) {
		if p.cfg.OnRawHist != nil {
			p.cfg.OnRawHist(src.name, key, perCPU)
		}
		h, comm, err := events.SumPerCPU(perCPU)
		if err != nil {
			return fmt.Errorf("%s map: %w", src.name, err)
		}
		var sample events.SyscallSample
		if len(key) == 4 {
			sample.TGID = le32(key)
		} else {
			tgid, nr, err := events.DecodeSyscallKey(key)
			if err != nil {
				return fmt.Errorf("%s map: %w", src.name, err)
			}
			sample.TGID, sample.NR = tgid, nr
		}
		if c, ok := comms[sample.TGID]; ok {
			comm = c // the process exec'd: keys created before exec carry the old name
		}
		sample.Comm, sample.Hist = comm, h
		fn(append([]byte(nil), key...), sample)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate %s map: %w", src.name, err)
	}
	return nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func execComms(m *ebpf.Map) (map[uint32]string, error) {
	out := map[uint32]string{}
	var tgid uint32
	var comm []byte
	it := m.Iterate()
	for it.Next(&tgid, &comm) {
		out[tgid] = events.Comm(comm)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate exec_comm map: %w", err)
	}
	return out, nil
}

func exitedSet(m *ebpf.Map) (map[uint32]struct{}, error) {
	out := map[uint32]struct{}{}
	var tgid uint32
	var ts uint64
	it := m.Iterate()
	for it.Next(&tgid, &ts) {
		out[tgid] = struct{}{}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate exited map: %w", err)
	}
	return out, nil
}

// gc deletes the final readings of exited processes. The exited set was
// captured before the histogram read, so the values just emitted are final.
func (p *Probe) gc(src *histSource, dead [][]byte, exited map[uint32]struct{}) {
	for _, k := range dead {
		if err := src.hist.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			p.cfg.Logger.Debug("gc delete", "collector", src.name, "err", err)
		}
	}
	for tgid := range exited {
		if err := src.exited.Delete(tgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			p.cfg.Logger.Debug("gc exited delete", "collector", src.name, "err", err)
		}
		if err := src.execComm.Delete(tgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			p.cfg.Logger.Debug("gc exec_comm delete", "collector", src.name, "err", err)
		}
	}
}

func readStats(src *histSource, which []int) []events.Drop {
	out := make([]events.Drop, 0, len(which))
	for _, i := range which {
		name := statNames[i]
		var perCPU []uint64
		if err := src.stats.Lookup(uint32(i), &perCPU); err != nil {
			continue
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out = append(out, events.Drop{Collector: src.name, Reason: name, Count: sum})
	}
	return out
}

// Close detaches every program and frees the maps.
func (p *Probe) Close() error {
	var errs []error
	for i := len(p.closers) - 1; i >= 0; i-- {
		if err := p.closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	p.closers = nil
	if p.readerDone != nil {
		<-p.readerDone
	}
	return errors.Join(errs...)
}
