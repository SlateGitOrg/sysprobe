// Package syscalls maps syscall numbers to names for the architectures
// sysprobe supports. Numbers are architecture specific (read is 0 on x86_64
// and 63 on arm64), so every lookup names the architecture the numbers were
// recorded on; fixtures carry it in their header.
package syscalls

import (
	"fmt"
	"runtime"
)

// Architecture names as reported by uname -m.
const (
	ArchX86_64  = "x86_64"
	ArchAarch64 = "aarch64"
)

// NormalizeArch maps GOARCH and uname spellings onto ArchX86_64 or
// ArchAarch64. It returns an error for unsupported architectures.
func NormalizeArch(arch string) (string, error) {
	switch arch {
	case "amd64", "x86_64", "x86-64":
		return ArchX86_64, nil
	case "arm64", "aarch64":
		return ArchAarch64, nil
	default:
		return "", fmt.Errorf("unsupported architecture %q (supported: x86_64, aarch64)", arch)
	}
}

// HostArch returns the normalized architecture of the running binary, or ""
// when it is unsupported.
func HostArch() string {
	a, err := NormalizeArch(runtime.GOARCH)
	if err != nil {
		return ""
	}
	return a
}

// Table resolves syscall numbers for one architecture.
type Table struct {
	arch  string
	names map[uint32]string
}

// ForArch returns the table for an architecture (any spelling accepted by
// NormalizeArch).
func ForArch(arch string) (Table, error) {
	a, err := NormalizeArch(arch)
	if err != nil {
		return Table{}, err
	}
	if a == ArchX86_64 {
		return Table{arch: a, names: namesX86_64}, nil
	}
	return Table{arch: a, names: namesAarch64}, nil
}

// Arch returns the normalized architecture name.
func (t Table) Arch() string { return t.arch }

// Name returns the syscall name, or "syscall_<nr>" when the number is not in
// the table (new syscalls, or a zero Table).
func (t Table) Name(nr uint32) string {
	if n, ok := t.names[nr]; ok {
		return n
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// Len returns the number of known syscalls.
func (t Table) Len() int { return len(t.names) }
