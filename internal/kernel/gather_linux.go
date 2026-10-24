//go:build linux

package kernel

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// TraceFSRoots are the locations probed for tracefs, in order.
var TraceFSRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// Gather inspects the running Linux host.
func Gather() Facts {
	var f Facts
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		f.Release = string(bytes.TrimRight(u.Release[:], "\x00"))
		f.Arch = string(bytes.TrimRight(u.Machine[:], "\x00"))
	}
	f.Version, _ = ParseRelease(f.Release)
	if fh, err := os.Open("/sys/kernel/btf/vmlinux"); err == nil {
		f.BTF = true
		_ = fh.Close()
	}
	f.Tracepoints = map[string]bool{}
	for _, root := range TraceFSRoots {
		if _, err := os.Stat(filepath.Join(root, "events")); err != nil {
			continue
		}
		f.TraceFS = true
		for _, tp := range Tracepoints {
			if _, err := os.Stat(filepath.Join(root, "events", tp)); err == nil {
				f.Tracepoints[tp] = true
			}
		}
		break
	}
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		f.CapEff, _ = ParseCapEff(string(status))
	}
	f.RingBuf = features.HaveMapType(ebpf.RingBuf) == nil
	f.PerCPUMap = features.HaveMapType(ebpf.PerCPUHash) == nil
	f.Tracing = features.HaveProgramType(ebpf.Tracing) == nil
	return f
}
