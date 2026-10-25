// Package fixture reads and writes recorded snapshot streams.
//
// A fixture is JSON Lines: one header line, then one line per snapshot.
// Histograms are stored sparsely (only non-empty buckets) so a recording of
// a busy host stays small. Recordings made by `sysprobe record` against a
// real kernel are the inputs for the offline unit tests and `make demo`.
package fixture

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/events"
	"github.com/SlateGitOrg/sysprobe/internal/hist"
	"github.com/SlateGitOrg/sysprobe/internal/syscalls"
)

// Format identifies sysprobe fixtures; Version is bumped on any
// incompatible change.
const (
	Format  = "sysprobe-fixture"
	Version = 1
)

// maxLine bounds a single snapshot line (a very busy host with thousands of
// processes produces lines of a few MB).
const maxLine = 64 << 20

// Header describes where and how a fixture was recorded.
type Header struct {
	Kind       string `json:"kind"`
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Arch       string `json:"arch"`
	Kernel     string `json:"kernel"`
	IntervalMs int64  `json:"interval_ms"`
	RecordedBy string `json:"recorded_by"`
	// Synthetic is true for hand-built fixtures; recorded ones are false.
	Synthetic bool   `json:"synthetic"`
	Note      string `json:"note,omitempty"`
}

type histJSON struct {
	Count   uint64            `json:"count"`
	SumNs   uint64            `json:"sum_ns"`
	Buckets map[string]uint64 `json:"buckets"`
}

type syscallJSON struct {
	TGID uint32 `json:"tgid"`
	NR   uint32 `json:"nr"`
	Comm string `json:"comm"`
	histJSON
}

type runqJSON struct {
	TGID uint32 `json:"tgid"`
	Comm string `json:"comm"`
	histJSON
}

type tcpJSON struct {
	KtimeNs   uint64 `json:"ktime_ns"`
	LatencyNs int64  `json:"latency_ns"`
	TGID      uint32 `json:"tgid"`
	Comm      string `json:"comm"`
	Kind      string `json:"kind"`
	SAddr     string `json:"saddr"`
	DAddr     string `json:"daddr"`
	SPort     uint16 `json:"sport"`
	DPort     uint16 `json:"dport"`
	State     uint8  `json:"state"`
}

type dropJSON struct {
	Collector string `json:"collector"`
	Reason    string `json:"reason"`
	Count     uint64 `json:"count"`
}

type snapshotJSON struct {
	Kind      string        `json:"kind"`
	Seq       uint64        `json:"seq"`
	ElapsedNs int64         `json:"elapsed_ns"`
	Syscalls  []syscallJSON `json:"syscalls"`
	Runq      []runqJSON    `json:"runq"`
	TCP       []tcpJSON     `json:"tcp"`
	Drops     []dropJSON    `json:"drops"`
}

func encodeHist(h *hist.Log2) histJSON {
	out := histJSON{Count: h.Count, SumNs: h.SumNs, Buckets: map[string]uint64{}}
	for i, b := range h.Buckets {
		if b != 0 {
			out.Buckets[strconv.Itoa(i)] = b
		}
	}
	return out
}

func decodeHist(j histJSON) (hist.Log2, error) {
	h := hist.Log2{Count: j.Count, SumNs: j.SumNs}
	for k, v := range j.Buckets {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= hist.Slots {
			return h, fmt.Errorf("bucket index %q out of range [0,%d)", k, hist.Slots)
		}
		h.Buckets[i] = v
	}
	return h, nil
}

// Writer appends snapshots to a fixture stream.
type Writer struct {
	w       *bufio.Writer
	enc     *json.Encoder
	lastSeq uint64
}

// NewWriter writes the header and returns a Writer. The header's Kind,
// Format and Version fields are filled in.
func NewWriter(w io.Writer, h Header) (*Writer, error) {
	arch, err := syscalls.NormalizeArch(h.Arch)
	if err != nil {
		return nil, fmt.Errorf("fixture header: %w", err)
	}
	h.Kind, h.Format, h.Version, h.Arch = "header", Format, Version, arch
	bw := bufio.NewWriter(w)
	fw := &Writer{w: bw, enc: json.NewEncoder(bw)}
	if err := fw.enc.Encode(h); err != nil {
		return nil, fmt.Errorf("write fixture header: %w", err)
	}
	return fw, nil
}

// Write appends one snapshot. Sequence numbers must increase.
func (fw *Writer) Write(s *events.Snapshot) error {
	if s.Seq <= fw.lastSeq {
		return fmt.Errorf("fixture: snapshot seq %d not after %d", s.Seq, fw.lastSeq)
	}
	fw.lastSeq = s.Seq
	j := snapshotJSON{
		Kind: "snapshot", Seq: s.Seq, ElapsedNs: int64(s.Elapsed),
		Syscalls: make([]syscallJSON, 0, len(s.Syscalls)),
		Runq:     make([]runqJSON, 0, len(s.Runq)),
		TCP:      make([]tcpJSON, 0, len(s.TCP)),
		Drops:    make([]dropJSON, 0, len(s.Drops)),
	}
	for i := range s.Syscalls {
		x := &s.Syscalls[i]
		j.Syscalls = append(j.Syscalls, syscallJSON{TGID: x.TGID, NR: x.NR, Comm: x.Comm, histJSON: encodeHist(&x.Hist)})
	}
	for i := range s.Runq {
		x := &s.Runq[i]
		j.Runq = append(j.Runq, runqJSON{TGID: x.TGID, Comm: x.Comm, histJSON: encodeHist(&x.Hist)})
	}
	for _, e := range s.TCP {
		j.TCP = append(j.TCP, tcpJSON{
			KtimeNs: e.KtimeNs, LatencyNs: int64(e.Latency), TGID: e.TGID, Comm: e.Comm,
			Kind: e.Kind.String(), SAddr: e.SAddr.String(), DAddr: e.DAddr.String(),
			SPort: e.SPort, DPort: e.DPort, State: e.State,
		})
	}
	for _, d := range s.Drops {
		j.Drops = append(j.Drops, dropJSON(d))
	}
	if err := fw.enc.Encode(j); err != nil {
		return fmt.Errorf("write snapshot %d: %w", s.Seq, err)
	}
	return nil
}

// Flush writes buffered data to the underlying writer.
func (fw *Writer) Flush() error { return fw.w.Flush() }

// Reader iterates over a fixture stream.
type Reader struct {
	sc      *bufio.Scanner
	header  Header
	line    int
	lastSeq uint64
	lastEl  time.Duration
}

// ErrFormat reports a malformed or incompatible fixture.
var ErrFormat = errors.New("invalid fixture")

// NewReader reads and validates the header.
func NewReader(r io.Reader) (*Reader, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	fr := &Reader{sc: sc}
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read fixture header: %w", err)
		}
		return nil, fmt.Errorf("%w: empty input", ErrFormat)
	}
	fr.line = 1
	if err := json.Unmarshal(sc.Bytes(), &fr.header); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrFormat, err)
	}
	h := fr.header
	if h.Kind != "header" || h.Format != Format {
		return nil, fmt.Errorf("%w: not a %s stream", ErrFormat, Format)
	}
	if h.Version != Version {
		return nil, fmt.Errorf("%w: version %d, this build reads version %d", ErrFormat, h.Version, Version)
	}
	if _, err := syscalls.NormalizeArch(h.Arch); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return fr, nil
}

// Header returns the fixture header.
func (fr *Reader) Header() Header { return fr.header }

// Next returns the next snapshot, or io.EOF at the end of the stream.
func (fr *Reader) Next() (events.Snapshot, error) {
	for fr.sc.Scan() {
		fr.line++
		if len(fr.sc.Bytes()) == 0 {
			continue
		}
		s, err := fr.parse(fr.sc.Bytes())
		if err != nil {
			return s, fmt.Errorf("%w: line %d: %w", ErrFormat, fr.line, err)
		}
		return s, nil
	}
	if err := fr.sc.Err(); err != nil {
		return events.Snapshot{}, fmt.Errorf("read fixture: %w", err)
	}
	return events.Snapshot{}, io.EOF
}

func (fr *Reader) parse(line []byte) (events.Snapshot, error) {
	var j snapshotJSON
	var s events.Snapshot
	if err := json.Unmarshal(line, &j); err != nil {
		return s, err
	}
	if j.Kind != "snapshot" {
		return s, fmt.Errorf("unexpected record kind %q", j.Kind)
	}
	if j.Seq <= fr.lastSeq {
		return s, fmt.Errorf("seq %d not after %d", j.Seq, fr.lastSeq)
	}
	el := time.Duration(j.ElapsedNs)
	if el < fr.lastEl {
		return s, fmt.Errorf("elapsed went backwards (%v < %v)", el, fr.lastEl)
	}
	fr.lastSeq, fr.lastEl = j.Seq, el
	s.Seq, s.Elapsed = j.Seq, el
	for _, x := range j.Syscalls {
		h, err := decodeHist(x.histJSON)
		if err != nil {
			return s, err
		}
		s.Syscalls = append(s.Syscalls, events.SyscallSample{TGID: x.TGID, NR: x.NR, Comm: x.Comm, Hist: h})
	}
	for _, x := range j.Runq {
		h, err := decodeHist(x.histJSON)
		if err != nil {
			return s, err
		}
		s.Runq = append(s.Runq, events.RunqSample{TGID: x.TGID, Comm: x.Comm, Hist: h})
	}
	for _, x := range j.TCP {
		e, err := decodeTCP(x)
		if err != nil {
			return s, err
		}
		s.TCP = append(s.TCP, e)
	}
	for _, d := range j.Drops {
		s.Drops = append(s.Drops, events.Drop(d))
	}
	return s, nil
}

func decodeTCP(x tcpJSON) (events.TCPEvent, error) {
	kind, err := events.ParseTCPKind(x.Kind)
	if err != nil {
		return events.TCPEvent{}, err
	}
	sa, err := netip.ParseAddr(x.SAddr)
	if err != nil {
		return events.TCPEvent{}, fmt.Errorf("tcp saddr: %w", err)
	}
	da, err := netip.ParseAddr(x.DAddr)
	if err != nil {
		return events.TCPEvent{}, fmt.Errorf("tcp daddr: %w", err)
	}
	return events.TCPEvent{
		KtimeNs: x.KtimeNs, Latency: time.Duration(x.LatencyNs), TGID: x.TGID, Comm: x.Comm,
		Kind: kind, SAddr: sa, DAddr: da, SPort: x.SPort, DPort: x.DPort, State: x.State,
	}, nil
}

// ReadAll reads every snapshot of a fixture.
func ReadAll(r io.Reader) (Header, []events.Snapshot, error) {
	fr, err := NewReader(r)
	if err != nil {
		return Header{}, nil, err
	}
	var out []events.Snapshot
	for {
		s, err := fr.Next()
		if errors.Is(err, io.EOF) {
			return fr.Header(), out, nil
		}
		if err != nil {
			return fr.Header(), out, err
		}
		out = append(out, s)
	}
}
