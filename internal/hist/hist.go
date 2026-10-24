// Package hist implements the log2 latency histogram shared by the kernel
// collectors and the userspace aggregation.
//
// The bucket layout mirrors bpf/sysprobe.h exactly: slot i counts samples d
// (nanoseconds) with 2^i <= d < 2^(i+1); slot 0 also holds d == 0 and the
// last slot is open-ended. All operations are allocation-free and O(Slots).
package hist

import (
	"math"
	"math/bits"
)

// Slots is the number of log2 buckets (MAX_SLOTS in bpf/sysprobe.h).
const Slots = 36

// Log2 is a cumulative or delta log2 histogram of nanosecond latencies.
//
// Count and SumNs are maintained by the kernel next to the buckets. Because
// per-CPU values can be read while a CPU is mid-update, Count may briefly
// disagree with the bucket total; quantiles therefore use Total(), the bucket
// sum, which is always self-consistent.
type Log2 struct {
	Buckets [Slots]uint64
	Count   uint64
	SumNs   uint64
}

// SlotFor returns the bucket index for a latency, matching slot_for() in BPF.
func SlotFor(ns uint64) int {
	if ns < 2 {
		return 0
	}
	s := bits.Len64(ns) - 1
	if s >= Slots {
		return Slots - 1
	}
	return s
}

// Lower returns the inclusive lower bound of slot i in nanoseconds.
func Lower(i int) uint64 {
	if i <= 0 {
		return 0
	}
	return 1 << uint(i)
}

// Upper returns the exclusive upper bound of slot i in nanoseconds. The last
// slot is open-ended and reports math.MaxUint64.
func Upper(i int) uint64 {
	if i >= Slots-1 {
		return math.MaxUint64
	}
	return 1 << uint(i+1)
}

// Record adds one sample. It exists for tests and synthetic sources; live
// samples are recorded in the kernel.
func (h *Log2) Record(ns uint64) {
	h.Buckets[SlotFor(ns)]++
	h.Count++
	h.SumNs += ns
}

// Add merges o into h.
func (h *Log2) Add(o *Log2) {
	for i := range h.Buckets {
		h.Buckets[i] += o.Buckets[i]
	}
	h.Count += o.Count
	h.SumNs += o.SumNs
}

// Sub returns h - prev for two cumulative readings of the same series. When
// any counter went backwards the series was reset (key deleted and
// re-created, or PID reuse) and ok is false; callers then treat h itself as
// the delta, which is exact when the reset happened at the previous reading.
func (h *Log2) Sub(prev *Log2) (delta Log2, ok bool) {
	if h.Count < prev.Count || h.SumNs < prev.SumNs {
		return *h, false
	}
	for i := range h.Buckets {
		if h.Buckets[i] < prev.Buckets[i] {
			return *h, false
		}
		delta.Buckets[i] = h.Buckets[i] - prev.Buckets[i]
	}
	delta.Count = h.Count - prev.Count
	delta.SumNs = h.SumNs - prev.SumNs
	return delta, true
}

// Total returns the number of samples according to the buckets.
func (h *Log2) Total() uint64 {
	var t uint64
	for _, b := range h.Buckets {
		t += b
	}
	return t
}

// IsZero reports whether the histogram holds no samples.
func (h *Log2) IsZero() bool {
	return h.Count == 0 && h.SumNs == 0 && h.Total() == 0
}

// Mean returns the mean latency in nanoseconds, or 0 when empty.
func (h *Log2) Mean() float64 {
	if h.Count == 0 {
		return 0
	}
	return float64(h.SumNs) / float64(h.Count)
}

// Quantile estimates the q-quantile (0 <= q <= 1) in nanoseconds by locating
// the bucket holding the rank and interpolating linearly inside it. The
// estimate always lies in the same bucket as the true quantile, so the
// relative error is bounded by the bucket width (a factor of two). The
// open-ended last bucket reports its lower bound. Returns 0 when empty or
// when q is NaN.
func (h *Log2) Quantile(q float64) float64 {
	total := h.Total()
	if total == 0 || math.IsNaN(q) {
		return 0
	}
	if q < 0 {
		q = 0
	} else if q > 1 {
		q = 1
	}
	// Rank of the target sample in 1..total.
	rank := q * float64(total)
	if rank < 1 {
		rank = 1
	}
	var seen float64
	for i, b := range h.Buckets {
		if b == 0 {
			continue
		}
		next := seen + float64(b)
		if rank <= next {
			lo := float64(Lower(i))
			if i == Slots-1 {
				return lo
			}
			hi := float64(Upper(i))
			frac := (rank - seen) / float64(b)
			return lo + frac*(hi-lo)
		}
		seen = next
	}
	return float64(Lower(Slots - 1))
}

// CumulativeAt returns the number of samples strictly below 2^k ns, the
// exact count for a Prometheus bucket with upper bound le = 2^k ns. Bucket
// boundaries coincide with powers of two, so no interpolation is needed.
func (h *Log2) CumulativeAt(k int) uint64 {
	var c uint64
	for i := 0; i < k && i < Slots; i++ {
		c += h.Buckets[i]
	}
	return c
}

// MaxSlot returns the highest non-empty slot, or -1 when empty.
func (h *Log2) MaxSlot() int {
	for i := Slots - 1; i >= 0; i-- {
		if h.Buckets[i] != 0 {
			return i
		}
	}
	return -1
}
