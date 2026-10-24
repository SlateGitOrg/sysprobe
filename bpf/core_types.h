/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Minimal kernel type definitions for CO-RE.
 *
 * Instead of committing a 3 MB generated vmlinux.h, sysprobe declares only
 * the fields it reads. preserve_access_index makes clang emit BTF
 * relocations, so libbpf/cilium-ebpf patch the real offsets from the running
 * kernel's /sys/kernel/btf/vmlinux at load time. Field order and padding here
 * are irrelevant; field names and types must match the kernel.
 */
#ifndef SYSPROBE_CORE_TYPES_H
#define SYSPROBE_CORE_TYPES_H

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct task_struct {
	unsigned int __state; /* >= 5.14 */
	int pid;
	int tgid;
	char comm[16];
};

/* Pre-5.14 kernels name the field "state" (and it is a long). */
struct task_struct___pre514 {
	long state;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* tracepoint sock/inet_sock_set_state (format stable since 4.16). */
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

#pragma clang attribute pop

/*
 * raw_syscalls tracepoint contexts. Their layout has not changed since the
 * tracepoints were introduced (2.6.32), so they are plain structs and the
 * syscall collector needs no kernel BTF at all.
 */
struct sys_enter_ctx {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
};

struct sys_exit_ctx {
	struct trace_entry ent;
	long id;
	long ret;
};

#define TASK_RUNNING 0
#define IPPROTO_TCP 6
#define AF_INET 2
#define AF_INET6 10

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_CLOSE = 7,
};

#endif /* SYSPROBE_CORE_TYPES_H */
