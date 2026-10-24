//go:build !linux

package kernel

import "runtime"

// Gather reports an empty host on non-Linux systems: every collector is
// unavailable, which `sysprobe doctor` prints as such.
func Gather() Facts {
	return Facts{Release: runtime.GOOS, Arch: runtime.GOARCH, Tracepoints: map[string]bool{}}
}
