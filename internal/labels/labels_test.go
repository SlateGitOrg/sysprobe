package labels

import "testing"

func TestStickyCap(t *testing.T) {
	s := NewSticky(2)
	steps := []struct{ in, want string }{
		{"a", "a"}, {"b", "b"}, {"c", Overflow}, {"a", "a"}, {"c", Overflow}, {Overflow, Overflow}, {"b", "b"},
	}
	for i, st := range steps {
		if got := s.Assign(st.in); got != st.want {
			t.Fatalf("step %d: Assign(%q) = %q, want %q", i, st.in, got, st.want)
		}
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d", s.Len())
	}
}

func TestStickyUnlimited(t *testing.T) {
	s := NewSticky(0)
	for _, v := range []string{"a", "b", "c", "d"} {
		if s.Assign(v) != v {
			t.Fatalf("unlimited set folded %q", v)
		}
	}
}
