//go:build integration && linux

package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/app"
	"github.com/archit2501/sysprobe/internal/events"
	"github.com/archit2501/sysprobe/internal/kernel"
	"github.com/archit2501/sysprobe/internal/probe"
	"github.com/archit2501/sysprobe/internal/source"
)

func loadgen(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("loadgen %v: %v", args, err)
	}
	return out
}

type rawCapture struct {
	mu     sync.Mutex
	tcp    [][]byte
	byKind map[events.TCPKind]int
	hist map[string][][]byte // collector|keyhex -> latest per-CPU values
}

// RawTCP is one captured ring-buffer record and its decoding.
type RawTCP struct {
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
}

// RawHist is one captured per-CPU histogram value and its merged decoding.
type RawHist struct {
	Collector string   `json:"collector"`
	KeyHex    string   `json:"key_hex"`
	PerCPUHex []string `json:"per_cpu_hex"`
	TGID      uint32   `json:"tgid"`
	NR        uint32   `json:"nr"`
	Comm      string   `json:"comm"`
	Count     uint64   `json:"count"`
	SumNs     uint64   `json:"sum_ns"`
}

func TestLiveKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test needs root (CAP_BPF/CAP_SYS_ADMIN)")
	}
	facts := kernel.Gather()
	cs := kernel.Evaluate(&facts)
	t.Logf("doctor:\n%s", kernel.Report(&facts, cs))
	for _, c := range cs {
		if !c.Ready() {
			t.Fatalf("collector %s unavailable on this kernel", c.Name)
		}
	}
	bin := filepath.Join(t.TempDir(), "sysprobe-loadgen")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/sysprobe-loadgen").CombinedOutput(); err != nil {
		t.Fatalf("build loadgen: %v\n%s", err, out)
	}

	raw := &rawCapture{hist: map[string][][]byte{}, byKind: map[events.TCPKind]int{}}
	p, err := probe.Open(probe.Config{
		Syscalls: true, Runq: true, TCP: true, Interval: 500 * time.Millisecond,
		OnRawTCP: func(b []byte) {
			raw.mu.Lock()
			defer raw.mu.Unlock()
			// Keep a bounded sample of every kind, so unrelated host traffic
			// cannot crowd out the retransmits and failures we provoke.
			e, err := events.DecodeTCPEvent(b)
			if err == nil && raw.byKind[e.Kind] < 16 {
				raw.byKind[e.Kind]++
				raw.tcp = append(raw.tcp, append([]byte(nil), b...))
			}
		},
		OnRawHist: func(collector string, key []byte, perCPU [][]byte) {
			cp := make([][]byte, len(perCPU))
			for i, v := range perCPU {
				cp[i] = append([]byte(nil), v...)
			}
			raw.mu.Lock()
			raw.hist[collector+"|"+hex.EncodeToString(key)] = cp
			raw.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("open probe: %v", err)
	}
	defer func() { _ = p.Close() }()
	for _, s := range p.Statuses() {
		if s.Err != nil {
			t.Fatalf("collector %s: %v", s.Name, s.Err)
		}
	}

	var rec strings.Builder
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metricsAddr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, p, app.RunOptions{
			Arch: facts.Arch, Kernel: facts.Release, Interval: 500 * time.Millisecond,
			Listen: "127.0.0.1:0", OnListen: func(a string) { metricsAddr <- a },
			Record: &rec, RecordedBy: "integration.TestLiveKernel",
			Agg: aggregate.Config{Retention: 1000},
		})
	}()
	addr := <-metricsAddr
	time.Sleep(time.Second)

	var sres struct {
		PID, Sleeps, Reads int
		SleepNs            int64 `json:"sleep_ns"`
	}
	if err := json.Unmarshal(loadgen(t, bin, "syscalls", "-duration", "3s", "-sleep", "3ms", "-workers", "2"), &sres); err != nil {
		t.Fatal(err)
	}
	var tres struct {
		PID          int `json:"pid"`
		OKPort       int `json:"ok_port"`
		ClosedPort   int `json:"closed_port"`
		OverflowPort int `json:"overflow_port"`
		ConnectsOK   int `json:"connects_ok"`
		Refused      int `json:"refused"`
		TimedOut     int `json:"timed_out"`
	}
	if err := json.Unmarshal(loadgen(t, bin, "tcp", "-connects", "20"), &tres); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}

	exp := Expect{
		Kernel: facts.Release, Arch: facts.Arch, Where: os.Getenv("SYSPROBE_WHERE"),
		SyscallPID: sres.PID, Sleeps: sres.Sleeps, SleepNs: sres.SleepNs, Reads: sres.Reads, Workers: 2,
		TCPPID: tres.PID, OKPort: tres.OKPort, ClosedPort: tres.ClosedPort, OverflowPort: tres.OverflowPort,
		ConnectsOK: tres.ConnectsOK, Refused: tres.Refused, TimedOut: tres.TimedOut,
	}
	t.Logf("workload: %+v", exp)

	// Re-aggregate the recording: the exact bytes a replay will see.
	rp, err := source.NewReplay(strings.NewReader(rec.String()))
	if err != nil {
		t.Fatal(err)
	}
	agg, err := aggregate.New(aggregate.Config{Arch: facts.Arch, Retention: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.Run(context.Background(), func(s *events.Snapshot) error { return agg.Ingest(s) }); err != nil {
		t.Fatal(err)
	}
	tot := agg.Totals(true)
	for _, problem := range Verify(tot, exp) {
		t.Error(problem)
	}
	want := `sysprobe_syscall_latency_seconds_count{comm="sysprobe-loadge",syscall="clock_nanosleep"}`
	if !strings.Contains(string(body), want) {
		var related []string
		for _, l := range strings.Split(string(body), "\n") {
			if strings.Contains(l, "loadge") && strings.Contains(l, "_count") {
				related = append(related, l)
			}
		}
		t.Errorf("scrape lacks %s; loadgen series:\n%s", want, strings.Join(related, "\n"))
	}
	for _, d := range tot.Drops {
		t.Logf("kernel counter %s/%s = %d", d.Collector, d.Reason, d.Count)
	}
	t.Logf("snapshots %d, processes %d, tcp connects %d fails %d retransmits %d",
		tot.Snapshots, tot.Processes, tot.Connects, tot.Fails, tot.Retransmits)

	if dir := os.Getenv("SYSPROBE_RECORD_DIR"); dir != "" && !t.Failed() {
		writeRecording(t, dir, facts, exp, rec.String(), raw)
	}
}

func writeRecording(t *testing.T, dir string, facts kernel.Facts, exp Expect, rec string, raw *rawCapture) {
	t.Helper()
	base := filepath.Join(dir, "recorded", "itest-"+facts.Release)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(base+".jsonl", []byte(rec), 0o644))
	eb, _ := json.MarshalIndent(exp, "", "  ")
	must(os.WriteFile(base+".expect.json", append(eb, '\n'), 0o644))

	raw.mu.Lock()
	defer raw.mu.Unlock()
	var tcp []RawTCP
	for _, b := range raw.tcp {
		e, err := events.DecodeTCPEvent(b)
		must(err)
		tcp = append(tcp, RawTCP{Hex: hex.EncodeToString(b), Kind: e.Kind.String(), TGID: e.TGID, Comm: e.Comm,
			SAddr: e.SAddr.String(), DAddr: e.DAddr.String(), SPort: e.SPort, DPort: e.DPort, State: e.State,
			Latency: int64(e.Latency)})
	}
	var hists []RawHist
	for k, perCPU := range raw.hist {
		collector, keyHex, _ := strings.Cut(k, "|")
		key, _ := hex.DecodeString(keyHex)
		h, comm, err := events.SumPerCPU(perCPU)
		must(err)
		rh := RawHist{Collector: collector, KeyHex: keyHex, Comm: comm, Count: h.Count, SumNs: h.SumNs}
		if len(key) == 4 {
			rh.TGID = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
		} else {
			rh.TGID, rh.NR, err = events.DecodeSyscallKey(key)
			must(err)
		}
		if int(rh.TGID) != exp.SyscallPID && int(rh.TGID) != exp.TCPPID {
			continue // keep the byte-level fixture small: loadgen keys only
		}
		for _, v := range perCPU {
			rh.PerCPUHex = append(rh.PerCPUHex, hex.EncodeToString(v))
		}
		hists = append(hists, rh)
	}
	sort.Slice(hists, func(i, j int) bool {
		if hists[i].Collector != hists[j].Collector {
			return hists[i].Collector < hists[j].Collector
		}
		return hists[i].KeyHex < hists[j].KeyHex
	})
	if len(hists) > 24 {
		hists = hists[:24]
	}
	rawOut := struct {
		Kernel string    `json:"kernel"`
		Arch   string    `json:"arch"`
		TCP    []RawTCP  `json:"tcp_events"`
		Hists  []RawHist `json:"hist_values"`
	}{facts.Release, facts.Arch, tcp, hists}
	rb, _ := json.MarshalIndent(rawOut, "", "  ")
	must(os.WriteFile(filepath.Join(dir, "raw", "itest-"+facts.Release+".json"), append(rb, '\n'), 0o644))
	t.Logf("recorded fixtures under %s (itest-%s.*)", dir, facts.Release)
}
