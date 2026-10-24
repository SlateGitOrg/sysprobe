// Package events defines the records that flow from a collector source
// (live BPF probe or recorded fixture) into the aggregator, and decodes the
// raw kernel byte layouts declared in bpf/sysprobe.h.
package events

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/archit2501/sysprobe/internal/hist"
)

// SyscallSample is the cumulative latency histogram of one syscall number in
// one process, as read from the kernel map (already summed across CPUs).
type SyscallSample struct {
	TGID uint32
	NR   uint32
	Comm string
	Hist hist.Log2
}

// RunqSample is the cumulative run-queue latency histogram of one process.
type RunqSample struct {
	TGID uint32
	Comm string
	Hist hist.Log2
}

// TCPKind classifies a TCP event.
type TCPKind uint8

// TCP event kinds; values match TCP_EV_* in bpf/sysprobe.h.
const (
	TCPRetransmit  TCPKind = 1
	TCPConnect     TCPKind = 2
	TCPConnectFail TCPKind = 3
)

// String returns the stable lowercase name used in fixtures and labels.
func (k TCPKind) String() string {
	switch k {
	case TCPRetransmit:
		return "retransmit"
	case TCPConnect:
		return "connect"
	case TCPConnectFail:
		return "connect_fail"
	default:
		return fmt.Sprintf("kind_%d", uint8(k))
	}
}

// ParseTCPKind is the inverse of TCPKind.String.
func ParseTCPKind(s string) (TCPKind, error) {
	for _, k := range []TCPKind{TCPRetransmit, TCPConnect, TCPConnectFail} {
		if k.String() == s {
			return k, nil
		}
	}
	return 0, fmt.Errorf("unknown tcp event kind %q", s)
}

// TCPEvent is one connect completion or retransmit observed in the kernel.
type TCPEvent struct {
	// KtimeNs is the kernel monotonic clock at emission (bpf_ktime_get_ns).
	KtimeNs uint64
	// Latency is SYN_SENT -> final state for connect events, else 0.
	Latency time.Duration
	// TGID is the connecting process; 0 for retransmits (softirq context).
	TGID  uint32
	Comm  string
	Kind  TCPKind
	SAddr netip.Addr
	DAddr netip.Addr
	SPort uint16
	DPort uint16
	// State is the kernel TCP state at the event (1 = ESTABLISHED, ...).
	State uint8
}

// Dest returns "addr:port" of the remote endpoint.
func (e *TCPEvent) Dest() string {
	return netip.AddrPortFrom(e.DAddr, e.DPort).String()
}

// Drop is a cumulative kernel-side loss/skip counter for one collector.
type Drop struct {
	Collector string
	Reason    string
	Count     uint64
}

// Snapshot is everything a source observed up to one interval boundary.
// Histogram samples are cumulative since the probe attached; TCP events are
// only those emitted since the previous snapshot.
type Snapshot struct {
	// Seq increases by one per snapshot, starting at 1.
	Seq uint64
	// Elapsed is the time since the source started.
	Elapsed  time.Duration
	Syscalls []SyscallSample
	Runq     []RunqSample
	TCP      []TCPEvent
	Drops    []Drop
}
