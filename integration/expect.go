// Package integration holds the privileged end-to-end test (build tag
// "integration", Linux, root) and the shared description of what a
// recording made by it must contain. The same Expect file is checked
// offline by the unit tests in internal/aggregate, so a fixture recorded on
// a real kernel keeps being verified on machines without eBPF.
package integration

import (
	"encoding/json"
	"fmt"
	"os"
)

// Expect records the known workload that ran while a fixture was captured.
type Expect struct {
	Kernel string `json:"kernel"`
	Arch   string `json:"arch"`
	// Where describes the machine the recording ran on.
	Where string `json:"where"`

	SyscallPID int   `json:"syscall_pid"`
	Sleeps     int   `json:"sleeps"`
	SleepNs    int64 `json:"sleep_ns"`
	Reads      int   `json:"reads"`
	Workers    int   `json:"workers"`

	TCPPID       int `json:"tcp_pid"`
	OKPort       int `json:"ok_port"`
	ClosedPort   int `json:"closed_port"`
	OverflowPort int `json:"overflow_port"`
	ConnectsOK   int `json:"connects_ok"`
	Refused      int `json:"refused"`
	TimedOut     int `json:"timed_out"`
}

// LoadExpect reads an Expect sidecar file.
func LoadExpect(path string) (Expect, error) {
	var e Expect
	b, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}
