//go:build linux

package kernel

import (
	"bytes"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Gather inspects the running Linux host.
func Gather() Facts {
	var f Facts
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		f.Release = string(bytes.TrimRight(u.Release[:], "\x00"))
		f.Arch = string(bytes.TrimRight(u.Machine[:], "\x00"))
	}
	f.Version, _ = ParseRelease(f.Release)
	if spec, err := btf.LoadKernelSpec(); err == nil {
		f.BTF = true
		f.Tracepoints = map[string]bool{}
		for _, tp := range Tracepoints {
			var td *btf.Typedef
			if err := spec.TypeByName("btf_trace_"+tp, &td); err == nil {
				f.Tracepoints[tp] = true
			}
		}
	}
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		f.CapEff, _ = ParseCapEff(string(status))
	}
	f.RingBuf = features.HaveMapType(ebpf.RingBuf) == nil
	f.PerCPUMap = features.HaveMapType(ebpf.PerCPUHash) == nil
	f.Tracing = features.HaveProgramType(ebpf.Tracing) == nil
	return f
}
