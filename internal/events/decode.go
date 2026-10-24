package events

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/archit2501/sysprobe/internal/hist"
)

// Raw layout sizes from bpf/sysprobe.h. All BPF objects are built for
// little-endian targets (bpfel), so decoding is little-endian.
const (
	CommLen        = 16
	HistValueSize  = hist.Slots*8 + 8 + 8 + CommLen // struct hist
	SyscallKeySize = 8                              // struct syscall_key
	TCPEventSize   = 80                             // struct tcp_event
)

// ErrShort is returned when a raw record is smaller than its layout.
var ErrShort = errors.New("raw record too short")

var le = binary.LittleEndian

// DecodeHistValue decodes one CPU's struct hist value.
func DecodeHistValue(b []byte) (hist.Log2, string, error) {
	var h hist.Log2
	if len(b) < HistValueSize {
		return h, "", fmt.Errorf("hist value: %w (%d < %d bytes)", ErrShort, len(b), HistValueSize)
	}
	for i := range h.Buckets {
		h.Buckets[i] = le.Uint64(b[i*8:])
	}
	off := hist.Slots * 8
	h.Count = le.Uint64(b[off:])
	h.SumNs = le.Uint64(b[off+8:])
	return h, Comm(b[off+16 : off+16+CommLen]), nil
}

// SumPerCPU decodes a per-CPU map value (one struct hist per possible CPU)
// and merges it. The comm is taken from the first CPU that recorded one.
func SumPerCPU(perCPU [][]byte) (hist.Log2, string, error) {
	var total hist.Log2
	comm := ""
	for cpu, b := range perCPU {
		h, c, err := DecodeHistValue(b)
		if err != nil {
			return total, "", fmt.Errorf("cpu %d: %w", cpu, err)
		}
		total.Add(&h)
		if comm == "" {
			comm = c
		}
	}
	return total, comm, nil
}

// DecodeSyscallKey decodes struct syscall_key.
func DecodeSyscallKey(b []byte) (tgid, nr uint32, err error) {
	if len(b) < SyscallKeySize {
		return 0, 0, fmt.Errorf("syscall key: %w", ErrShort)
	}
	return le.Uint32(b), le.Uint32(b[4:]), nil
}

const (
	afInet  = 2
	afInet6 = 10
)

// DecodeTCPEvent decodes one struct tcp_event ring-buffer record.
func DecodeTCPEvent(b []byte) (TCPEvent, error) {
	var e TCPEvent
	if len(b) < TCPEventSize {
		return e, fmt.Errorf("tcp event: %w (%d < %d bytes)", ErrShort, len(b), TCPEventSize)
	}
	e.KtimeNs = le.Uint64(b[0:])
	e.Latency = time.Duration(le.Uint64(b[8:]))
	e.TGID = le.Uint32(b[16:])
	kind := le.Uint32(b[20:])
	if kind < uint32(TCPRetransmit) || kind > uint32(TCPConnectFail) {
		return e, fmt.Errorf("tcp event: unknown kind %d", kind)
	}
	e.Kind = TCPKind(kind)
	family := le.Uint16(b[24:])
	e.SPort = le.Uint16(b[26:])
	e.DPort = le.Uint16(b[28:])
	e.State = b[30]
	var err error
	if e.SAddr, err = decodeAddr(family, b[32:48]); err != nil {
		return e, err
	}
	if e.DAddr, err = decodeAddr(family, b[48:64]); err != nil {
		return e, err
	}
	e.Comm = Comm(b[64:80])
	return e, nil
}

func decodeAddr(family uint16, b []byte) (netip.Addr, error) {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte(b[:4])), nil
	case afInet6:
		return netip.AddrFrom16([16]byte(b[:16])).Unmap(), nil
	default:
		return netip.Addr{}, fmt.Errorf("tcp event: unknown address family %d", family)
	}
}

// Comm converts a fixed-size, NUL-padded kernel comm into a printable string.
// Bytes after the first NUL are ignored; invalid UTF-8 and control
// characters are replaced so labels and terminal output stay safe.
func Comm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	s := strings.ToValidUTF8(string(b), "?")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
}
