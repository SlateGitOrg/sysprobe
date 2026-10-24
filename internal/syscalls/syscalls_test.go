package syscalls

import (
	"runtime"
	"testing"
)

func TestNormalizeArch(t *testing.T) {
	for in, want := range map[string]string{"amd64": ArchX86_64, "x86_64": ArchX86_64, "x86-64": ArchX86_64, "arm64": ArchAarch64, "aarch64": ArchAarch64} {
		if got, err := NormalizeArch(in); err != nil || got != want {
			t.Errorf("%s -> %s, %v", in, got, err)
		}
	}
	if _, err := NormalizeArch("riscv64"); err == nil {
		t.Error("riscv64 accepted")
	}
}

func TestNames(t *testing.T) {
	x86, _ := ForArch("amd64")
	arm, _ := ForArch("aarch64")
	cases := []struct {
		t    Table
		nr   uint32
		want string
	}{
		{x86, 0, "read"}, {x86, 1, "write"}, {x86, 230, "clock_nanosleep"}, {x86, 59, "execve"},
		{arm, 63, "read"}, {arm, 64, "write"}, {arm, 115, "clock_nanosleep"}, {arm, 221, "execve"},
		{x86, 99999, "syscall_99999"}, {Table{}, 0, "syscall_0"},
	}
	for _, c := range cases {
		if got := c.t.Name(c.nr); got != c.want {
			t.Errorf("%s %d = %q, want %q", c.t.Arch(), c.nr, got, c.want)
		}
	}
	if x86.Len() < 300 || arm.Len() < 250 {
		t.Errorf("tables look truncated: %d %d", x86.Len(), arm.Len())
	}
	if _, err := ForArch("ppc64le"); err == nil {
		t.Error("ppc64le accepted")
	}
}

func TestHostArch(t *testing.T) {
	want := map[string]string{"amd64": ArchX86_64, "arm64": ArchAarch64}[runtime.GOARCH]
	if got := HostArch(); got != want {
		t.Errorf("HostArch = %q, want %q", got, want)
	}
}
