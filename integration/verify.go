package integration

import (
	"fmt"
	"strings"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/aggregate"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

// Verify checks that aggregated totals reflect the known workload. It
// returns every violated property (empty when the recording is correct).
// It is used both against the live kernel and against committed fixtures.
func Verify(t aggregate.Totals, e Expect) []string {
	var bad []string
	fail := func(format string, args ...any) { bad = append(bad, fmt.Sprintf(format, args...)) }

	sys := map[string]hist.Log2{}
	for _, s := range t.PIDSys {
		if int(s.TGID) == e.SyscallPID {
			sys[s.Syscall] = s.Hist
		}
	}
	ns, ok := sys["clock_nanosleep"]
	switch {
	case !ok:
		fail("no clock_nanosleep series for loadgen pid %d", e.SyscallPID)
	default:
		// Every completed loop iteration is exactly one clock_nanosleep; allow one
		// in-flight call per worker at the edges.
		if ns.Count < uint64(e.Sleeps) || ns.Count > uint64(e.Sleeps+e.Workers) {
			fail("clock_nanosleep count %d, loadgen reported %d (+%d in flight)", ns.Count, e.Sleeps, e.Workers)
		}
		// Sleeping never returns early, so the exact mean (sum/count) is at
		// least the requested length; the upper bound tolerates VM jitter.
		mean := time.Duration(ns.Mean())
		if mean < time.Duration(e.SleepNs) || mean > 2*time.Duration(e.SleepNs) {
			fail("clock_nanosleep mean %v outside [%v, %v]", mean, time.Duration(e.SleepNs), 2*time.Duration(e.SleepNs))
		}
		// The median must land in the log2 bucket that holds the sleep length.
		p50 := uint64(ns.Quantile(0.5))
		want := hist.SlotFor(uint64(e.SleepNs))
		if got := hist.SlotFor(p50); got != want && got != want+1 {
			fail("clock_nanosleep p50 %v in slot %d, want slot %d (or %d)", time.Duration(p50), got, want, want+1)
		}
	}
	if rd, ok := sys["read"]; !ok || rd.Count < uint64(e.Reads) {
		fail("read count %d < loadgen reads %d", rd.Count, e.Reads)
	}
	runqSeen := false
	for _, r := range t.PIDRunq {
		if int(r.TGID) == e.SyscallPID && r.Hist.Count > 0 {
			runqSeen = true
		}
	}
	if !runqSeen {
		fail("no run-queue samples for loadgen pid %d", e.SyscallPID)
	}

	dest := func(port int) (aggregate.DestTotal, bool) {
		want := fmt.Sprintf("127.0.0.1:%d", port)
		for _, d := range t.Dests {
			if d.Dest == want {
				return d, true
			}
		}
		return aggregate.DestTotal{}, false
	}
	if d, ok := dest(e.OKPort); !ok || d.ConnectOK.Count != uint64(e.ConnectsOK) {
		fail("ok-port connects %d, want %d", d.ConnectOK.Count, e.ConnectsOK)
	} else if m := time.Duration(d.ConnectOK.Mean()); m <= 0 || m > 50*time.Millisecond {
		fail("loopback connect mean latency %v outside (0, 50ms]", m)
	}
	if d, ok := dest(e.ClosedPort); !ok || d.ConnectFail.Count != uint64(e.Refused) {
		fail("closed-port failures %d, want %d", d.ConnectFail.Count, e.Refused)
	}
	if e.TimedOut > 0 {
		if d, ok := dest(e.OverflowPort); !ok || d.Retransmits == 0 {
			fail("no SYN retransmits towards the overflowing listener :%d", e.OverflowPort)
		}
	}
	tcpProc := false
	for _, s := range t.PIDSys {
		if int(s.TGID) == e.TCPPID && strings.HasPrefix(s.Comm, "sysprobe-load") {
			tcpProc = true
		}
	}
	if !tcpProc {
		fail("tcp loadgen pid %d not attributed with its comm", e.TCPPID)
	}
	return bad
}
