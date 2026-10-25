package source

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/fixture"
)

func stream(t *testing.T, n int) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := fixture.NewWriter(&buf, fixture.Header{Arch: "x86_64", Synthetic: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if err := w.Write(&events.Snapshot{Seq: uint64(i), Elapsed: time.Duration(i) * 500 * time.Millisecond}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestReplayEmitsAllWithPacing(t *testing.T) {
	rp, err := NewReplay(strings.NewReader(stream(t, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if !rp.Header().Synthetic {
		t.Fatal("header not exposed")
	}
	var slept []time.Duration
	rp.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	rp.Speed = 2
	var seqs []uint64
	if err := rp.Run(context.Background(), func(s *events.Snapshot) error { seqs = append(seqs, s.Seq); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 3 || len(slept) != 3 || slept[0] != 250*time.Millisecond || slept[2] != 250*time.Millisecond {
		t.Fatalf("seqs %v slept %v", seqs, slept)
	}
}

func TestReplayErrors(t *testing.T) {
	if _, err := NewReplay(strings.NewReader("junk")); err == nil {
		t.Fatal("bad header accepted")
	}
	boom := errors.New("boom")
	rp, _ := NewReplay(strings.NewReader(stream(t, 3)))
	if err := rp.Run(context.Background(), func(*events.Snapshot) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("emit error not propagated: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rp, _ = NewReplay(strings.NewReader(stream(t, 3)))
	if err := rp.Run(ctx, func(*events.Snapshot) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	rp, _ = NewReplay(strings.NewReader(stream(t, 1) + "{bad\n"))
	if err := rp.Run(context.Background(), func(*events.Snapshot) error { return nil }); !errors.Is(err, fixture.ErrFormat) {
		t.Fatalf("corrupt line: %v", err)
	}
	// Real sleeping honours cancellation.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rp, _ = NewReplay(strings.NewReader(stream(t, 2)))
	rp.Speed = 0.001
	if err := rp.Run(ctx, func(*events.Snapshot) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("paced replay ignored deadline: %v", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

type failAfter struct{ n int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("full")
	}
	f.n--
	return len(p), nil
}

func TestTee(t *testing.T) {
	var buf bytes.Buffer
	w, _ := fixture.NewWriter(&buf, fixture.Header{Arch: "x86_64"})
	calls := 0
	emit := Tee(w, func(*events.Snapshot) error { calls++; return nil })
	if err := emit(&events.Snapshot{Seq: 1}); err != nil || calls != 1 {
		t.Fatalf("%v %d", err, calls)
	}
	if !strings.Contains(buf.String(), `"seq":1`) {
		t.Fatalf("snapshot not flushed: %q", buf.String())
	}
	if err := emit(&events.Snapshot{Seq: 1}); err == nil {
		t.Fatal("duplicate seq accepted")
	}
	w2, _ := fixture.NewWriter(&failAfter{n: 0}, fixture.Header{Arch: "x86_64"})
	if err := Tee(w2, func(*events.Snapshot) error { return nil })(&events.Snapshot{Seq: 1}); err == nil {
		t.Fatal("flush error swallowed")
	}
}
