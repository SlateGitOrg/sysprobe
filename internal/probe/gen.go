package probe

// The BPF objects are compiled inside the Linux builder image (`make bpf`),
// because macOS clang has no BPF backend. The generated *_bpfel.go/.o files
// are committed so the Go module builds anywhere without clang.

//go:generate go tool bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -type hist -type syscall_key syscalls ../../bpf/syscalls.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
//go:generate go tool bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel runq ../../bpf/runq.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
//go:generate go tool bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -type tcp_event tcp ../../bpf/tcp.bpf.c -- -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu
