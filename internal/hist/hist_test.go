package hist

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestSlotForBoundaries(t *testing.T) {
	cases := []struct {
		ns   uint64
		want int
	}{
		{0, 0}, {1, 0}, {2, 1}, {3, 1}, {4, 2}, {1023, 9}, {1024, 10},
		{1<<21 - 1, 20}, {1 << 21, 21}, {3_000_000, 21},
		{1 << 35, 35}, {1 << 40, Slots - 1}, {math.MaxUint64, Slots - 1},
	}
	for _, c := range cases {
		if got := SlotFor(c.ns); got != c.want {
			t.Errorf("SlotFor(%d) = %d, want %d", c.ns, got, c.want)
		}
	}
}

func TestBoundsContainTheirSlot(t *testing.T) {
	for i := 0; i < Slots; i++ {
		lo, hi := Lower(i), Upper(i)
		if SlotFor(lo) != i {
			t.Errorf("slot %d: lower bound %d maps to slot %d", i, lo, SlotFor(lo))
		}
		if i < Slots-1 && SlotFor(hi-1) != i {
			t.Errorf("slot %d: upper bound-1 %d maps to slot %d", i, hi-1, SlotFor(hi-1))
		}
		if i < Slots-1 && Lower(i+1) != hi {
			t.Errorf("slot %d: upper %d != next lower %d", i, hi, Lower(i+1))
		}
	}
	if Upper(Slots-1) != math.MaxUint64 || Lower(-1) != 0 {
		t.Fatal("edge bounds wrong")
	}
}

func TestRecordAddMean(t *testing.T) {
	var a, b Log2
	a.Record(100)
	a.Record(300)
	b.Record(1000)
	a.Add(&b)
	if a.Count != 3 || a.SumNs != 1400 || a.Total() != 3 {
		t.Fatalf("got count=%d sum=%d total=%d", a.Count, a.SumNs, a.Total())
	}
	if m := a.Mean(); math.Abs(m-1400.0/3) > 1e-9 {
		t.Fatalf("mean %v", m)
	}
	var empty Log2
	if empty.Mean() != 0 || empty.Quantile(0.5) != 0 || !empty.IsZero() || empty.MaxSlot() != -1 {
		t.Fatal("empty histogram should report zeros")
	}
	if a.IsZero() || a.MaxSlot() != SlotFor(1000) {
		t.Fatalf("MaxSlot %d", a.MaxSlot())
	}
}

func TestSubDeltaAndReset(t *testing.T) {
	var prev, cur Log2
	prev.Record(10)
	cur = prev
	cur.Record(5000)
	cur.Record(10)
	d, ok := cur.Sub(&prev)
	if !ok || d.Count != 2 || d.SumNs != 5010 || d.Buckets[SlotFor(10)] != 1 || d.Buckets[SlotFor(5000)] != 1 {
		t.Fatalf("delta %+v ok=%v", d, ok)
	}
	// A re-created key starts from zero: any counter going backwards is a reset.
	var fresh Log2
	fresh.Record(7)
	for name, c := range map[string]Log2{"fresh": fresh} {
		got, ok := c.Sub(&cur)
		if ok || got != c {
			t.Errorf("%s: reset not detected (ok=%v)", name, ok)
		}
	}
	// Bucket regression with identical count/sum is still a reset.
	var x, y Log2
	x.Buckets[3], x.Count, x.SumNs = 1, 1, 10
	y.Buckets[4], y.Count, y.SumNs = 1, 1, 10
	if _, ok := y.Sub(&x); ok {
		t.Error("bucket regression not detected")
	}
}

func TestQuantileInterpolation(t *testing.T) {
	var h Log2
	h.Buckets[10] = 100 // [1024, 2048)
	if got := h.Quantile(0.5); got != 1024+0.5*1024 {
		t.Errorf("p50 = %v", got)
	}
	if got := h.Quantile(1); got != 2048 {
		t.Errorf("p100 = %v", got)
	}
	if got := h.Quantile(-1); got < 1024 || got > 1035 {
		t.Errorf("clamped q<0 = %v", got)
	}
	if got := h.Quantile(2); got != 2048 {
		t.Errorf("clamped q>1 = %v", got)
	}
	var top Log2
	top.Buckets[Slots-1] = 5
	if got := top.Quantile(0.99); got != float64(Lower(Slots-1)) {
		t.Errorf("open-ended bucket reports %v, want its lower bound", got)
	}
}

func TestCumulativeAt(t *testing.T) {
	var h Log2
	for _, ns := range []uint64{1, 1000, 1024, 5000, 1 << 30} {
		h.Record(ns)
	}
	// le = 2^10 ns = 1024: samples strictly below are 1 and 1000.
	if got := h.CumulativeAt(10); got != 2 {
		t.Errorf("CumulativeAt(10) = %d", got)
	}
	if got := h.CumulativeAt(Slots + 5); got != 5 {
		t.Errorf("CumulativeAt(beyond) = %d", got)
	}
}

// Property: the estimated quantile always lies in the same log2 bucket as
// the exact sample quantile, so relative error is below 2x.
func TestQuantileBucketProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 300; trial++ {
		n := 1 + r.IntN(400)
		samples := make([]uint64, n)
		var h Log2
		for i := range samples {
			// Log-uniform over 1ns..~1s, the range real latencies span.
			samples[i] = uint64(math.Exp(r.Float64() * math.Log(1e9)))
			h.Record(samples[i])
		}
		slices.Sort(samples)
		for _, q := range []float64{0.01, 0.25, 0.5, 0.9, 0.99, 1} {
			rank := int(math.Ceil(q*float64(n))) - 1
			rank = max(rank, 0)
			exact := samples[rank]
			est := h.Quantile(q)
			if SlotFor(uint64(est)) != SlotFor(exact) && uint64(est) != Upper(SlotFor(exact)) {
				t.Fatalf("trial %d q=%v: estimate %v (slot %d) vs exact %d (slot %d)",
					trial, q, est, SlotFor(uint64(est)), exact, SlotFor(exact))
			}
		}
		// Monotone in q.
		prev := -1.0
		for q := 0.0; q <= 1.0; q += 0.05 {
			v := h.Quantile(q)
			if v < prev {
				t.Fatalf("quantile not monotone at q=%v: %v < %v", q, v, prev)
			}
			prev = v
		}
	}
}

// Property: Add is commutative and Sub inverts Add.
func TestAddSubProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for trial := 0; trial < 200; trial++ {
		var a, b Log2
		for i := 0; i < r.IntN(50); i++ {
			a.Record(r.Uint64N(1 << 34))
		}
		for i := 0; i < r.IntN(50); i++ {
			b.Record(r.Uint64N(1 << 34))
		}
		ab, ba := a, b
		ab.Add(&b)
		ba.Add(&a)
		if ab != ba {
			t.Fatal("Add not commutative")
		}
		d, ok := ab.Sub(&a)
		if !ok || d != b {
			t.Fatalf("(a+b)-a != b (ok=%v)", ok)
		}
	}
}

func FuzzQuantile(f *testing.F) {
	f.Add(uint64(5), uint64(7), uint64(0), 0.5)
	f.Add(uint64(0), uint64(0), uint64(1), 0.99)
	f.Fuzz(func(t *testing.T, a, b, c uint64, q float64) {
		var h Log2
		h.Buckets[a%Slots] += a % 1000
		h.Buckets[b%Slots] += b % 1000
		h.Buckets[c%Slots] += c % 1000
		v := h.Quantile(q)
		if v < 0 || math.IsInf(v, 0) {
			t.Fatalf("quantile %v for q=%v", v, q)
		}
		if h.Total() > 0 && v > float64(Upper(Slots-2)) {
			t.Fatalf("quantile %v above finite range", v)
		}
	})
}

func BenchmarkQuantile(b *testing.B) {
	var h Log2
	for i := uint64(1); i < 1<<20; i *= 3 {
		h.Record(i)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = h.Quantile(0.99)
	}
}
