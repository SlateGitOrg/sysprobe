package events

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/SlateGitOrg/sysprobe/internal/hist"
)

// The Go layouts must match bpf/sysprobe.h; a drift would silently corrupt
// every decoded record, so pin the C constants from the header itself.
func TestLayoutMatchesBPFHeader(t *testing.T) {
	src, err := os.ReadFile("../../bpf/sysprobe.h")
	if err != nil {
		t.Fatal(err)
	}
	define := func(name string) int {
		m := regexp.MustCompile(`#define ` + name + ` (\d+)`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no #define %s", name)
		}
		n, _ := strconv.Atoi(string(m[1]))
		return n
	}
	if got := define("MAX_SLOTS"); got != hist.Slots {
		t.Errorf("MAX_SLOTS %d != hist.Slots %d", got, hist.Slots)
	}
	if got := define("TASK_COMM_LEN"); got != CommLen {
		t.Errorf("TASK_COMM_LEN %d != CommLen %d", got, CommLen)
	}
	sizes := regexp.MustCompile(`\}; /\* (\d+) bytes \*/`).FindAllSubmatch(src, -1)
	want := []int{HistValueSize, SyscallKeySize, TCPEventSize}
	if len(sizes) != len(want) {
		t.Fatalf("found %d size annotations, want %d", len(sizes), len(want))
	}
	for i, m := range sizes {
		if n, _ := strconv.Atoi(string(m[1])); n != want[i] {
			t.Errorf("struct %d: header says %d bytes, Go decodes %d", i, n, want[i])
		}
	}
	for kind, v := range map[TCPKind]string{TCPRetransmit: "TCP_EV_RETRANSMIT", TCPConnect: "TCP_EV_CONNECT", TCPConnectFail: "TCP_EV_CONNECT_FAIL"} {
		if got := define(v); got != int(kind) {
			t.Errorf("%s = %d, Go uses %d", v, got, kind)
		}
	}
}

func encodeHist(h hist.Log2, comm string) []byte {
	b := make([]byte, HistValueSize)
	for i, v := range h.Buckets {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	off := hist.Slots * 8
	binary.LittleEndian.PutUint64(b[off:], h.Count)
	binary.LittleEndian.PutUint64(b[off+8:], h.SumNs)
	copy(b[off+16:], comm)
	return b
}

func TestSumPerCPU(t *testing.T) {
	var a, b hist.Log2
	a.Record(100)
	b.Record(100)
	b.Record(1 << 20)
	h, comm, err := SumPerCPU([][]byte{encodeHist(hist.Log2{}, ""), encodeHist(a, "nginx"), encodeHist(b, "other")})
	if err != nil {
		t.Fatal(err)
	}
	if h.Count != 3 || h.Buckets[hist.SlotFor(100)] != 2 || comm != "nginx" {
		t.Fatalf("got %+v comm %q", h, comm)
	}
	if _, _, err := SumPerCPU([][]byte{make([]byte, 10)}); !errors.Is(err, ErrShort) {
		t.Fatalf("short value: %v", err)
	}
}

func TestDecodeSyscallKey(t *testing.T) {
	tgid, nr, err := DecodeSyscallKey([]byte{0x39, 0x30, 0, 0, 63, 0, 0, 0})
	if err != nil || tgid != 12345 || nr != 63 {
		t.Fatalf("got %d %d %v", tgid, nr, err)
	}
	if _, _, err := DecodeSyscallKey([]byte{1}); !errors.Is(err, ErrShort) {
		t.Fatal("expected ErrShort")
	}
}

func tcpBytes(kind uint32, family uint16, saddr, daddr []byte) []byte {
	b := make([]byte, TCPEventSize)
	binary.LittleEndian.PutUint64(b[0:], 42)
	binary.LittleEndian.PutUint64(b[8:], 1500)
	binary.LittleEndian.PutUint32(b[16:], 77)
	binary.LittleEndian.PutUint32(b[20:], kind)
	binary.LittleEndian.PutUint16(b[24:], family)
	binary.LittleEndian.PutUint16(b[26:], 5555)
	binary.LittleEndian.PutUint16(b[28:], 443)
	b[30] = 1
	copy(b[32:], saddr)
	copy(b[48:], daddr)
	copy(b[64:], "curl")
	return b
}

func TestDecodeTCPEvent(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1").As16()
	e, err := DecodeTCPEvent(tcpBytes(2, 10, v6[:], v6[:]))
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != TCPConnect || e.TGID != 77 || e.Latency != 1500*time.Nanosecond || e.Comm != "curl" ||
		e.DAddr.String() != "2001:db8::1" || e.DPort != 443 || e.SPort != 5555 || e.State != 1 || e.KtimeNs != 42 {
		t.Fatalf("decoded %+v", e)
	}
	if e.Dest() != "[2001:db8::1]:443" {
		t.Errorf("Dest %q", e.Dest())
	}
	// IPv4-mapped IPv6 addresses are unmapped so labels stay uniform.
	mapped := netip.MustParseAddr("::ffff:10.0.0.1").As16()
	if e, _ := DecodeTCPEvent(tcpBytes(1, 10, mapped[:], mapped[:])); e.DAddr.String() != "10.0.0.1" {
		t.Errorf("mapped address decoded as %v", e.DAddr)
	}
	for name, b := range map[string][]byte{
		"short":  make([]byte, 79),
		"kind":   tcpBytes(9, 2, nil, nil),
		"kind0":  tcpBytes(0, 2, nil, nil),
		"family": tcpBytes(1, 7, nil, nil),
	} {
		if _, err := DecodeTCPEvent(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestComm(t *testing.T) {
	cases := map[string]string{
		"bash\x00garbage":     "bash",
		"exactly16bytes!!":    "exactly16bytes!!",
		"tab\there":           "tab?here",
		"\xff\xfeinvalid":     "?invalid",
		"":                    "",
		"esc\x1b[2Jtrick\x00": "esc?[2Jtrick",
	}
	for in, want := range cases {
		if got := Comm([]byte(in)); got != want {
			t.Errorf("Comm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKindNames(t *testing.T) {
	for _, k := range []TCPKind{TCPRetransmit, TCPConnect, TCPConnectFail} {
		back, err := ParseTCPKind(k.String())
		if err != nil || back != k {
			t.Errorf("round trip %v: %v %v", k, back, err)
		}
	}
	if TCPKind(9).String() != "kind_9" {
		t.Error("unknown kind name")
	}
	if _, err := ParseTCPKind("nope"); err == nil {
		t.Error("expected error")
	}
}

type rawFixture struct {
	Arch string `json:"arch"`
	TCP  []struct {
		Hex     string `json:"hex"`
		Kind    string `json:"kind"`
		TGID    uint32 `json:"tgid"`
		Comm    string `json:"comm"`
		SAddr   string `json:"saddr"`
		DAddr   string `json:"daddr"`
		SPort   uint16 `json:"sport"`
		DPort   uint16 `json:"dport"`
		State   uint8  `json:"state"`
		Latency int64  `json:"latency_ns"`
	} `json:"tcp_events"`
	Hists []struct {
		Collector string   `json:"collector"`
		KeyHex    string   `json:"key_hex"`
		PerCPUHex []string `json:"per_cpu_hex"`
		TGID      uint32   `json:"tgid"`
		NR        uint32   `json:"nr"`
		Comm      string   `json:"comm"`
		Count     uint64   `json:"count"`
		SumNs     uint64   `json:"sum_ns"`
	} `json:"hist_values"`
}

// Decode the byte-exact records captured from a real kernel by the
// integration test and compare with the decoding recorded at capture time.
func TestRecordedRawKernelBytes(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/raw/itest-*.json")
	if len(files) == 0 {
		t.Fatal("no raw fixtures in testdata/raw (run make integration)")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx rawFixture
		if err := json.Unmarshal(b, &fx); err != nil {
			t.Fatal(err)
		}
		if len(fx.TCP) == 0 || len(fx.Hists) == 0 {
			t.Fatalf("%s: empty capture", f)
		}
		kinds := map[string]int{}
		for i, r := range fx.TCP {
			raw, _ := hex.DecodeString(r.Hex)
			e, err := DecodeTCPEvent(raw)
			if err != nil {
				t.Fatalf("%s tcp[%d]: %v", f, i, err)
			}
			kinds[e.Kind.String()]++
			if e.Kind.String() != r.Kind || e.TGID != r.TGID || e.Comm != r.Comm || e.SAddr.String() != r.SAddr ||
				e.DAddr.String() != r.DAddr || e.SPort != r.SPort || e.DPort != r.DPort || e.State != r.State ||
				int64(e.Latency) != r.Latency {
				t.Errorf("%s tcp[%d]: decoded %+v, recorded %+v", f, i, e, r)
			}
			if e.Kind == TCPRetransmit && e.TGID != 0 {
				t.Errorf("retransmit with tgid %d", e.TGID)
			}
		}
		for _, k := range []string{"connect", "connect_fail", "retransmit"} {
			if kinds[k] == 0 {
				t.Errorf("%s: no %s records captured", f, k)
			}
		}
		for i, r := range fx.Hists {
			perCPU := make([][]byte, len(r.PerCPUHex))
			for c, hx := range r.PerCPUHex {
				perCPU[c], _ = hex.DecodeString(hx)
			}
			h, comm, err := SumPerCPU(perCPU)
			if err != nil {
				t.Fatalf("hist[%d]: %v", i, err)
			}
			if h.Count != r.Count || h.SumNs != r.SumNs || comm != r.Comm {
				t.Errorf("hist[%d]: got count=%d sum=%d comm=%q, recorded %d %d %q", i, h.Count, h.SumNs, comm, r.Count, r.SumNs, r.Comm)
			}
			if h.Total() != h.Count {
				t.Errorf("hist[%d]: bucket total %d != count %d (idle process, should be consistent)", i, h.Total(), h.Count)
			}
			key, _ := hex.DecodeString(r.KeyHex)
			if r.Collector == "syscalls" {
				tgid, nr, err := DecodeSyscallKey(key)
				if err != nil || tgid != r.TGID || nr != r.NR {
					t.Errorf("hist[%d]: key %x -> %d/%d", i, key, tgid, nr)
				}
			}
		}
	}
}

func FuzzDecodeTCPEvent(f *testing.F) {
	f.Add(tcpBytes(2, 2, []byte{127, 0, 0, 1}, []byte{10, 0, 0, 1}))
	f.Add(make([]byte, 3))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeTCPEvent(b)
		if err != nil {
			return
		}
		if len(b) < TCPEventSize || !e.DAddr.IsValid() || e.Kind < TCPRetransmit || e.Kind > TCPConnectFail {
			t.Fatalf("accepted invalid record: %+v", e)
		}
		_ = e.Dest()
	})
}

func BenchmarkSumPerCPU(b *testing.B) {
	var h hist.Log2
	h.Record(1234)
	cpus := make([][]byte, 8)
	for i := range cpus {
		cpus[i] = encodeHist(h, "bench")
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := SumPerCPU(cpus); err != nil {
			b.Fatal(err)
		}
	}
}
