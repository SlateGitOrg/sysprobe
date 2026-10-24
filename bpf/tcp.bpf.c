// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * TCP connect latency and retransmit events.
 *
 * Connect latency: sock:inet_sock_set_state marks the SYN_SENT transition
 * (process context, so the pid is the connecting process) and the next
 * transition out of SYN_SENT (ESTABLISHED = success, anything else =
 * failure). The pair is joined on the socket address.
 *
 * Retransmits: tp_btf/tcp_retransmit_skb. The classic tracepoint's record
 * layout changed in 6.x (an "err" field was added and the event class was
 * split), so the BTF-typed variant reads struct sock via CO-RE instead.
 *
 * Both are rare compared to syscalls, so they are streamed as individual
 * events through a ring buffer and aggregated in userspace.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "core_types.h"
#include "sysprobe.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u32 targ_tgid = 0;

struct conn_start {
	__u64 ts;
	__u32 tgid;
	__u32 _pad;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); /* struct sock address */
	__type(value, struct conn_start);
} conn_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} tcp_events SEC(".maps");

DEFINE_STATS_MAP()

/* Forces BTF emission of the event struct for bpf2go type generation. */
const struct tcp_event *unused_tcp_event __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	__u64 sk = (__u64)BPF_CORE_READ(ctx, skaddr);
	int oldstate = BPF_CORE_READ(ctx, oldstate);
	int newstate = BPF_CORE_READ(ctx, newstate);
	struct conn_start *cs;
	struct tcp_event *e;
	__u16 family;

	if (BPF_CORE_READ(ctx, protocol) != IPPROTO_TCP)
		return 0;

	if (newstate == TCP_SYN_SENT) {
		struct conn_start v = {};
		__u32 tgid = bpf_get_current_pid_tgid() >> 32;

		if (targ_tgid && tgid != targ_tgid)
			return 0;
		v.ts = bpf_ktime_get_ns();
		v.tgid = tgid;
		bpf_get_current_comm(v.comm, sizeof(v.comm));
		if (bpf_map_update_elem(&conn_start, &sk, &v, BPF_ANY))
			stat_inc(STAT_START_FULL);
		return 0;
	}
	if (oldstate != TCP_SYN_SENT)
		return 0;

	cs = bpf_map_lookup_elem(&conn_start, &sk);
	if (!cs) {
		stat_inc(STAT_MISSED_START);
		return 0;
	}
	e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_FULL);
		bpf_map_delete_elem(&conn_start, &sk);
		return 0;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->latency_ns = e->ts_ns - cs->ts;
	e->tgid = cs->tgid;
	e->kind = newstate == TCP_ESTABLISHED ? TCP_EV_CONNECT : TCP_EV_CONNECT_FAIL;
	family = BPF_CORE_READ(ctx, family);
	e->family = family;
	e->sport = BPF_CORE_READ(ctx, sport);
	e->dport = BPF_CORE_READ(ctx, dport);
	e->state = newstate;
	e->_pad = 0;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e->saddr, ctx, saddr_v6);
		BPF_CORE_READ_INTO(&e->daddr, ctx, daddr_v6);
	} else {
		BPF_CORE_READ_INTO((__u8(*)[4])e->saddr, ctx, saddr);
		BPF_CORE_READ_INTO((__u8(*)[4])e->daddr, ctx, daddr);
	}
	__builtin_memcpy(e->comm, cs->comm, sizeof(e->comm));
	bpf_map_delete_elem(&conn_start, &sk);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, const struct sock *sk)
{
	struct tcp_event *e;
	__u16 family;

	e = bpf_ringbuf_reserve(&tcp_events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_FULL);
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = TCP_EV_RETRANSMIT;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->family = family;
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		BPF_CORE_READ_INTO((__be32 *)e->saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO((__be32 *)e->daddr, sk, __sk_common.skc_daddr);
	}
	/* Retransmits usually fire from the timer softirq: pid is not meaningful. */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
