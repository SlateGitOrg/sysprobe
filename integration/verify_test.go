package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/fixture"
)

// aggregateFixture replays a committed recording through the aggregator,
// exactly as `sysprobe replay` does.
func aggregateFixture(t *testing.T, path string) (fixture.Header, *aggregate.Aggregator) {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	h, snaps, err := fixture.ReadAll(fh)
	if err != nil {
		t.Fatal(err)
	}
	a, err := aggregate.New(aggregate.Config{Arch: h.Arch, Retention: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for i := range snaps {
		if err := a.Ingest(&snaps[i]); err != nil {
			t.Fatal(err)
		}
	}
	return h, a
}

func recordings(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob("../testdata/recorded/itest-*.jsonl")
	if len(files) == 0 {
		t.Fatal("no itest recordings in testdata/recorded (run make integration)")
	}
	return files
}

// The recordings were made on a real kernel while a known workload ran;
// the offline aggregation must reproduce the workload's ground truth.
func TestRecordedFixturesMatchWorkload(t *testing.T) {
	for _, f := range recordings(t) {
		exp, err := LoadExpect(strings.TrimSuffix(f, ".jsonl") + ".expect.json")
		if err != nil {
			t.Fatal(err)
		}
		h, a := aggregateFixture(t, f)
		if h.Synthetic || h.Kernel != exp.Kernel {
			t.Fatalf("%s: header %+v does not match expectation kernel %s", f, h, exp.Kernel)
		}
		if exp.Where == "" {
			t.Errorf("%s: expectation does not say where it was recorded", f)
		}
		for _, problem := range Verify(a.Totals(true), exp) {
			t.Errorf("%s: %s", f, problem)
		}
	}
}

// Verify must reject a recording when the ground truth disagrees; otherwise
// the test above would prove nothing.
func TestVerifyDetectsWrongExpectations(t *testing.T) {
	f := recordings(t)[0]
	exp, err := LoadExpect(strings.TrimSuffix(f, ".jsonl") + ".expect.json")
	if err != nil {
		t.Fatal(err)
	}
	_, a := aggregateFixture(t, f)
	tot := a.Totals(true)
	mutations := map[string]func(*Expect){
		"sleeps":   func(e *Expect) { e.Sleeps += 100 },
		"sleep ns": func(e *Expect) { e.SleepNs *= 4 },
		"reads":    func(e *Expect) { e.Reads *= 2 },
		"connects": func(e *Expect) { e.ConnectsOK++ },
		"refused":  func(e *Expect) { e.Refused = 5 },
		"pid":      func(e *Expect) { e.SyscallPID = 1 },
		"tcp pid":  func(e *Expect) { e.TCPPID = 1 },
		"overflow": func(e *Expect) { e.OverflowPort = 1 },
	}
	for name, mutate := range mutations {
		e := exp
		mutate(&e)
		if len(Verify(tot, e)) == 0 {
			t.Errorf("mutation %q not detected", name)
		}
	}
}

// Invariant on real data: per-comm totals absorb every delta of every
// process that ever ran (including evicted and relabelled ones), so for each
// syscall they cover at least the sum over currently tracked processes; and
// a clean recording has no counter resets.
func TestCommTotalsCoverProcessTotals(t *testing.T) {
	files, _ := filepath.Glob("../testdata/recorded/*.jsonl")
	for _, f := range files {
		_, a := aggregateFixture(t, f)
		tot := a.Totals(true)
		procSum, commSum := map[string]uint64{}, map[string]uint64{}
		for _, s := range tot.PIDSys {
			procSum[s.Syscall] += s.Hist.Count
		}
		for _, s := range tot.CommSys {
			commSum[s.Syscall] += s.Hist.Count
		}
		for sc, n := range procSum {
			if commSum[sc] < n {
				t.Errorf("%s: %s comm totals %d < process totals %d", f, sc, commSum[sc], n)
			}
		}
		if tot.Resets != 0 {
			t.Errorf("%s: %d series resets in a clean recording", f, tot.Resets)
		}
	}
}

func TestLoadExpectErrors(t *testing.T) {
	if _, err := LoadExpect("does-not-exist.json"); err == nil {
		t.Error("missing file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExpect(bad); err == nil {
		t.Error("malformed file accepted")
	}
}
