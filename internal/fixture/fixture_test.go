package fixture

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

func sample() events.Snapshot {
	var h hist.Log2
	h.Record(1500)
	h.Record(3_000_000)
	return events.Snapshot{
		Seq: 1, Elapsed: time.Second,
		Syscalls: []events.SyscallSample{{TGID: 10, NR: 63, Comm: "cat", Hist: h}},
		Runq:     []events.RunqSample{{TGID: 10, Comm: "cat", Hist: h}},
		TCP: []events.TCPEvent{{
			KtimeNs: 99, Latency: 50 * time.Microsecond, TGID: 10, Comm: "cat", Kind: events.TCPConnect,
			SAddr: netip.MustParseAddr("127.0.0.1"), DAddr: netip.MustParseAddr("::1"), SPort: 1, DPort: 2, State: 1,
		}},
		Drops: []events.Drop{{Collector: "tcp", Reason: "ringbuf_full", Count: 3}},
	}
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Arch: "arm64", Kernel: "6.8.0", IntervalMs: 1000, RecordedBy: "test", Synthetic: true, Note: "n"})
	if err != nil {
		t.Fatal(err)
	}
	s1 := sample()
	s2 := sample()
	s2.Seq, s2.Elapsed = 2, 2*time.Second
	for _, s := range []events.Snapshot{s1, s2} {
		if err := w.Write(&s); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	h, snaps, err := ReadAll(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if h.Arch != "aarch64" || h.Format != Format || h.Version != Version || !h.Synthetic || h.Note != "n" {
		t.Fatalf("header %+v", h)
	}
	if len(snaps) != 2 {
		t.Fatalf("%d snapshots", len(snaps))
	}
	got := snaps[0]
	if got.Syscalls[0] != s1.Syscalls[0] || got.Runq[0] != s1.Runq[0] || got.TCP[0] != s1.TCP[0] || got.Drops[0] != s1.Drops[0] {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, s1)
	}
}

func TestWriterRejectsBadInput(t *testing.T) {
	if _, err := NewWriter(io.Discard, Header{Arch: "s390x"}); err == nil {
		t.Error("unsupported arch accepted")
	}
	w, _ := NewWriter(io.Discard, Header{Arch: "x86_64"})
	s := sample()
	if err := w.Write(&s); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(&s); err == nil {
		t.Error("repeated seq accepted")
	}
}

const hdr = `{"kind":"header","format":"sysprobe-fixture","version":1,"arch":"x86_64"}` + "\n"

func TestReaderErrors(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"not json":     "nope\n",
		"wrong format": `{"kind":"header","format":"other","version":1,"arch":"x86_64"}`,
		"version":      `{"kind":"header","format":"sysprobe-fixture","version":9,"arch":"x86_64"}`,
		"arch":         `{"kind":"header","format":"sysprobe-fixture","version":1,"arch":"mips"}`,
	}
	for name, in := range cases {
		if _, err := NewReader(strings.NewReader(in)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v, want ErrFormat", name, err)
		}
	}
	bodies := map[string]string{
		"bad line":     "{\n",
		"kind":         `{"kind":"other","seq":1}`,
		"seq order":    `{"kind":"snapshot","seq":2}` + "\n" + `{"kind":"snapshot","seq":2}`,
		"elapsed back": `{"kind":"snapshot","seq":1,"elapsed_ns":5}` + "\n" + `{"kind":"snapshot","seq":2,"elapsed_ns":4}`,
		"bucket":       `{"kind":"snapshot","seq":1,"syscalls":[{"buckets":{"36":1}}]}`,
		"bucket name":  `{"kind":"snapshot","seq":1,"runq":[{"buckets":{"x":1}}]}`,
		"tcp kind":     `{"kind":"snapshot","seq":1,"tcp":[{"kind":"zzz","saddr":"1.1.1.1","daddr":"1.1.1.1"}]}`,
		"tcp saddr":    `{"kind":"snapshot","seq":1,"tcp":[{"kind":"connect","saddr":"x","daddr":"1.1.1.1"}]}`,
		"tcp daddr":    `{"kind":"snapshot","seq":1,"tcp":[{"kind":"connect","saddr":"1.1.1.1","daddr":"x"}]}`,
	}
	for name, body := range bodies {
		_, _, err := ReadAll(strings.NewReader(hdr + body + "\n"))
		if !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v, want ErrFormat", name, err)
		}
	}
}

func TestReaderSkipsBlankLines(t *testing.T) {
	_, snaps, err := ReadAll(strings.NewReader(hdr + "\n" + `{"kind":"snapshot","seq":1}` + "\n\n"))
	if err != nil || len(snaps) != 1 {
		t.Fatalf("%v %d", err, len(snaps))
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteErrorsSurface(t *testing.T) {
	if _, err := NewWriter(failWriter{}, Header{Arch: "x86_64"}); err != nil {
		// The header is buffered; failures surface on Flush.
		t.Fatal(err)
	}
	w, _ := NewWriter(failWriter{}, Header{Arch: "x86_64"})
	if err := w.Flush(); err == nil {
		t.Fatal("flush to failing writer succeeded")
	}
}

// Every committed recording must stay readable by this build.
func TestCommittedRecordingsParse(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/*/*.jsonl")
	if len(files) < 2 {
		t.Fatalf("expected recorded and synthetic fixtures, found %v", files)
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		h, snaps, err := ReadAll(fh)
		_ = fh.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(snaps) == 0 {
			t.Errorf("%s: no snapshots", f)
		}
		if strings.Contains(f, "/recorded/") && h.Synthetic {
			t.Errorf("%s: recorded fixture marked synthetic", f)
		}
		if strings.Contains(f, "/synthetic/") && !h.Synthetic {
			t.Errorf("%s: synthetic fixture not marked synthetic", f)
		}
	}
}
