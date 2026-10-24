//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// syscallLoad runs workers that each call clock_nanosleep(CLOCK_MONOTONIC,
// sleep) directly, plus one thread issuing 1-byte reads from /dev/zero.
// clock_nanosleep is used because the Go runtime itself never calls it
// (time.Sleep uses runtime timers and runtime.usleep uses plain nanosleep),
// so every clock_nanosleep the probe attributes to this process is ours.
func syscallLoad(d, sleep time.Duration, workers int) (SyscallResult, error) {
	res := SyscallResult{PID: os.Getpid(), SleepNs: sleep.Nanoseconds()}
	zero, err := unix.Open("/dev/zero", unix.O_RDONLY, 0)
	if err != nil {
		return res, fmt.Errorf("open /dev/zero: %w", err)
	}
	defer func() { _ = unix.Close(zero) }()
	start := time.Now()
	deadline := start.Add(d)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			ts := unix.NsecToTimespec(sleep.Nanoseconds())
			n := 0
			for time.Now().Before(deadline) {
				if err := unix.ClockNanosleep(unix.CLOCK_MONOTONIC, 0, &ts, nil); err != nil && !errors.Is(err, unix.EINTR) {
					return
				}
				n++
			}
			mu.Lock()
			res.Sleeps += n
			mu.Unlock()
		}()
	}
	buf := make([]byte, 1)
	for time.Now().Before(deadline) {
		if _, err := unix.Read(zero, buf); err != nil {
			return res, fmt.Errorf("read /dev/zero: %w", err)
		}
		res.Reads++
		if res.Reads%1000 == 0 {
			runtime.Gosched()
		}
	}
	wg.Wait()
	res.ElapsedSec = time.Since(start).Seconds()
	return res, nil
}

// tcpLoad exercises the three TCP paths sysprobe reports:
//   - n successful connects to an accepting loopback listener,
//   - one connect to a port with no listener (RST: SYN_SENT -> CLOSE),
//   - connects to a listener with backlog 0 that never accepts: once its
//     accept queue is full the kernel drops further SYNs, so the client
//     retransmits its SYN (tcp_retransmit_skb) until it gives up.
func tcpLoad(n int, synWait time.Duration) (TCPResult, error) {
	res := TCPResult{PID: os.Getpid()}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return res, err
	}
	defer func() { _ = ln.Close() }()
	res.OKPort = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	for range n {
		c, err := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
		if err != nil {
			return res, fmt.Errorf("loopback connect: %w", err)
		}
		_ = c.Close()
		res.ConnectsOK++
	}

	closed, err := freePort()
	if err != nil {
		return res, err
	}
	res.ClosedPort = closed
	if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", closed), time.Second); err == nil {
		_ = c.Close()
	} else {
		res.Refused++
	}

	fd, port, err := stuckListener()
	if err != nil {
		return res, err
	}
	defer func() { _ = unix.Close(fd) }()
	res.OverflowPort = port
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp4", addr, synWait)
			if err == nil {
				// Completed the handshake before the queue filled; hold it
				// open so later SYNs are dropped.
				time.Sleep(synWait)
				_ = c.Close()
				return
			}
			mu.Lock()
			res.TimedOut++
			mu.Unlock()
		}()
		time.Sleep(50 * time.Millisecond)
	}
	wg.Wait()
	return res, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	p := l.Addr().(*net.TCPAddr).Port
	return p, l.Close()
}

// stuckListener listens with backlog 0 and never calls accept.
func stuckListener() (fd, port int, err error) {
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, 0, err
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = unix.Close(fd)
		return 0, 0, err
	}
	if err = unix.Listen(fd, 0); err != nil {
		_ = unix.Close(fd)
		return 0, 0, err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return 0, 0, err
	}
	return fd, sa.(*unix.SockaddrInet4).Port, nil
}

func bench(n int) (BenchResult, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	start := time.Now()
	for range n {
		unix.Getppid()
	}
	el := time.Since(start)
	return BenchResult{PID: os.Getpid(), N: n, NsPerOp: float64(el.Nanoseconds()) / float64(n)}, nil
}
