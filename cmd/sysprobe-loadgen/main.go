// Command sysprobe-loadgen generates known, benign kernel activity for the
// integration test, the demo recording and the overhead benchmark. It only
// talks to 127.0.0.1 and never to other hosts.
//
//	sysprobe-loadgen syscalls -duration 3s -sleep 3ms   clock_nanosleep + read loops
//	sysprobe-loadgen tcp -connects 20                    ok / refused / SYN-retransmit connects
//	sysprobe-loadgen bench -n 2000000                    ns per getppid() syscall
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: sysprobe-loadgen syscalls|tcp|bench [flags]")
		return 2
	}
	fs := flag.NewFlagSet("sysprobe-loadgen "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		res any
		err error
	)
	switch args[0] {
	case "syscalls":
		d := fs.Duration("duration", 3*time.Second, "how long to run")
		sleep := fs.Duration("sleep", 3*time.Millisecond, "clock_nanosleep length per iteration")
		workers := fs.Int("workers", 2, "sleeping threads")
		if err = fs.Parse(args[1:]); err == nil {
			res, err = syscallLoad(*d, *sleep, *workers)
		}
	case "tcp":
		n := fs.Int("connects", 20, "successful loopback connects")
		hold := fs.Duration("syn-wait", 3500*time.Millisecond, "how long to wait on the SYN-dropping listener")
		if err = fs.Parse(args[1:]); err == nil {
			res, err = tcpLoad(*n, *hold)
		}
	case "bench":
		n := fs.Int("n", 2_000_000, "getppid() calls")
		if err = fs.Parse(args[1:]); err == nil {
			res, err = bench(*n)
		}
	default:
		fmt.Fprintf(stderr, "unknown mode %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "sysprobe-loadgen: %v\n", err)
		return 1
	}
	out, _ := json.Marshal(res)
	fmt.Fprintln(stdout, string(out))
	return 0
}

// SyscallResult summarizes a syscalls run.
type SyscallResult struct {
	PID        int     `json:"pid"`
	Sleeps     int     `json:"sleeps"`
	Reads      int     `json:"reads"`
	SleepNs    int64   `json:"sleep_ns"`
	ElapsedSec float64 `json:"elapsed_sec"`
}

// TCPResult summarizes a tcp run; ports identify the three scenarios.
type TCPResult struct {
	PID          int `json:"pid"`
	OKPort       int `json:"ok_port"`
	ClosedPort   int `json:"closed_port"`
	OverflowPort int `json:"overflow_port"`
	ConnectsOK   int `json:"connects_ok"`
	Refused      int `json:"refused"`
	TimedOut     int `json:"timed_out"`
}

// BenchResult is the measured cost of one getppid() round trip.
type BenchResult struct {
	PID     int     `json:"pid"`
	N       int     `json:"n"`
	NsPerOp float64 `json:"ns_per_op"`
}
