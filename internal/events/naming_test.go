package events

import "testing"

func TestNameProcesses(t *testing.T) {
	samples := []SyscallSample{
		{TGID: 1, NR: 0, Comm: "ghc_ticker"},
		{TGID: 1, NR: 1, Comm: "ghc_worker"},
		{TGID: 1, NR: 2, Comm: "ghc_worker"},
		{TGID: 2, NR: 0, Comm: "bash"}, // forked, then exec'd as ls
		{TGID: 2, NR: 1, Comm: "ls"},
		{TGID: 3, NR: 0, Comm: "zz"},
		{TGID: 3, NR: 1, Comm: "aa"},
		{TGID: 4, NR: 0, Comm: ""},
	}
	NameProcesses(samples, map[uint32]string{2: "ls"})
	want := map[uint32]string{1: "ghc_worker", 2: "ls", 3: "aa", 4: ""}
	for _, s := range samples {
		if s.Comm != want[s.TGID] {
			t.Errorf("tgid %d nr %d named %q, want %q", s.TGID, s.NR, s.Comm, want[s.TGID])
		}
	}
}
