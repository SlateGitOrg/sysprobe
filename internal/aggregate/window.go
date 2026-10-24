package aggregate

import (
	"time"

	"github.com/archit2501/sysprobe/internal/hist"
)

// window keeps the per-snapshot deltas of one series for the last n
// snapshots in a ring indexed by seq % n. Writes are O(1) (plus the O(Slots)
// copy); a windowed histogram is the sum of the live entries, O(n*Slots),
// computed only when a view is rendered. Entries are tagged with their seq,
// so a series that stops receiving data ages out without any per-snapshot
// bookkeeping.
type window struct {
	seqs   []uint64
	deltas []hist.Log2
}

func newWindow(n int) window {
	return window{seqs: make([]uint64, n), deltas: make([]hist.Log2, n)}
}

func (w *window) put(seq uint64, d *hist.Log2) {
	i := seq % uint64(len(w.seqs))
	if w.seqs[i] == seq {
		w.deltas[i].Add(d)
		return
	}
	w.seqs[i] = seq
	w.deltas[i] = *d
}

// sum returns the merged deltas of snapshots in (cur-n, cur].
func (w *window) sum(cur uint64) hist.Log2 {
	var out hist.Log2
	n := uint64(len(w.seqs))
	for i, s := range w.seqs {
		if s != 0 && s <= cur && cur-s < n {
			out.Add(&w.deltas[i])
		}
	}
	return out
}

// steps records the length of each snapshot interval so window rates divide
// by the time the window actually covers (intervals jitter, and replays may
// have gaps).
type steps struct {
	seqs []uint64
	durs []time.Duration
}

func newSteps(n int) steps {
	return steps{seqs: make([]uint64, n), durs: make([]time.Duration, n)}
}

func (s *steps) put(seq uint64, d time.Duration) {
	i := seq % uint64(len(s.seqs))
	s.seqs[i], s.durs[i] = seq, d
}

func (s *steps) sum(cur uint64) time.Duration {
	var out time.Duration
	n := uint64(len(s.seqs))
	for i, q := range s.seqs {
		if q != 0 && q <= cur && cur-q < n {
			out += s.durs[i]
		}
	}
	return out
}
