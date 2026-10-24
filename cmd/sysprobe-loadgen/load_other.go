//go:build !linux

package main

import (
	"errors"
	"time"
)

var errLinuxOnly = errors.New("load generation targets Linux kernel paths; run it on Linux")

func syscallLoad(time.Duration, time.Duration, int) (SyscallResult, error) {
	return SyscallResult{}, errLinuxOnly
}

func tcpLoad(int, time.Duration) (TCPResult, error) { return TCPResult{}, errLinuxOnly }

func bench(int) (BenchResult, error) { return BenchResult{}, errLinuxOnly }
