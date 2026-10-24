package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func demoFixture(t *testing.T) string {
	t.Helper()
	files, _ := filepath.Glob("../../testdata/recorded/itest-*.jsonl")
	if len(files) == 0 {
		t.Fatal("no recorded fixture")
	}
	return files[0]
}

func TestUsageAndVersion(t *testing.T) {
	if code, _, e := runCLI(); code != 2 || !strings.Contains(e, "usage: sysprobe") {
		t.Errorf("no args: %d %q", code, e)
	}
	if code, o, _ := runCLI("version"); code != 0 || o != "sysprobe dev\n" {
		t.Errorf("version: %d %q", code, o)
	}
	if code, o, _ := runCLI("help"); code != 0 || !strings.Contains(o, "replay") {
		t.Errorf("help: %d", code)
	}
	if code, _, e := runCLI("frobnicate"); code != 2 || !strings.Contains(e, "unknown command") {
		t.Errorf("unknown: %d %q", code, e)
	}
}

func TestReplayCommand(t *testing.T) {
	code, o, e := runCLI("replay", "-rows", "5", "-sort", "rate", "-metrics", "-metrics-filter", "clock_nanosleep", demoFixture(t))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, e)
	}
	for _, want := range []string{"replaying recorded fixture", "sort rate", "... ", `syscall="clock_nanosleep"`} {
		if !strings.Contains(o, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if code, _, _ := runCLI("replay", "-h"); code != 0 {
		t.Errorf("-h exit %d", code)
	}
	bad := [][]string{
		{"replay"},
		{"replay", "missing.jsonl"},
		{"replay", "-sort", "cpu", demoFixture(t)},
		{"replay", "-prom-labels", "tid", demoFixture(t)},
		{"replay", "-pid", "1", demoFixture(t)},
		{"replay", "-nope", demoFixture(t)},
	}
	for _, args := range bad {
		if code, _, _ := runCLI(args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}

func TestLiveCommandsFailCleanlyWithoutEBPF(t *testing.T) {
	// Unit tests never run privileged: opening the probe must fail with a
	// pointer to `sysprobe doctor` instead of crashing.
	code, _, e := runCLI("run", "-listen", "", "-duration", "1ms")
	if code != 1 || !strings.Contains(e, "sysprobe doctor") {
		t.Errorf("run: %d %q", code, e)
	}
	cases := map[string][]string{
		"record without -o": {"record"},
		"bad collector":     {"top", "-collectors", "disk"},
		"no collector":      {"run", "-collectors", ","},
		"bad log level":     {"run", "-log-level", "loud"},
		"bad sort":          {"top", "-sort", "x"},
		"extra args":        {"run", "extra"},
		"bad flag":          {"record", "-zzz"},
	}
	for name, args := range cases {
		if code, _, _ := runCLI(args...); code == 0 {
			t.Errorf("%s: succeeded", name)
		}
	}
}

func TestDoctor(t *testing.T) {
	code, o, _ := runCLI("doctor")
	if (code != 0 && code != 1) || !strings.Contains(o, "collector syscalls") || !strings.Contains(o, "collector tcp") {
		t.Errorf("doctor: %d\n%s", code, o)
	}
}

func TestParseCollectors(t *testing.T) {
	sys, runq, tcp, err := parseCollectors("syscalls, tcp")
	if err != nil || !sys || runq || !tcp {
		t.Errorf("%v %v %v %v", sys, runq, tcp, err)
	}
}
