// Package labels bounds metric label cardinality without breaking counter
// monotonicity.
//
// A Sticky set admits the first Cap distinct values; later values map to
// Overflow forever after. Because a value never moves between its own series
// and the overflow series, cumulative totals folded per label value only
// ever grow, which keeps Prometheus counters and histograms monotonic.
package labels

// Overflow is the label value shared by everything past the cap.
const Overflow = "other"

// Sticky is a capped, first-come label admission set. The zero value is not
// usable; construct with NewSticky. Not safe for concurrent use.
type Sticky struct {
	cap      int
	admitted map[string]struct{}
}

// NewSticky returns a set admitting up to capacity distinct values
// (capacity <= 0 means unlimited).
func NewSticky(capacity int) *Sticky {
	return &Sticky{cap: capacity, admitted: make(map[string]struct{})}
}

// Assign returns v when it is (or can be) admitted, else Overflow.
func (s *Sticky) Assign(v string) string {
	if v == Overflow {
		return Overflow
	}
	if _, ok := s.admitted[v]; ok {
		return v
	}
	if s.cap > 0 && len(s.admitted) >= s.cap {
		return Overflow
	}
	s.admitted[v] = struct{}{}
	return v
}

// Len returns the number of admitted values.
func (s *Sticky) Len() int { return len(s.admitted) }
