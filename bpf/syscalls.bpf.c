// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Per-process syscall latency histograms.
 *
 * raw_syscalls:sys_enter stamps the thread; raw_syscalls:sys_exit computes
 * the latency and adds it to a per-CPU log2 histogram keyed by
 * (tgid, syscall nr). Aggregation stays in the kernel: userspace only reads
 * the map once per interval, so cost does not scale with syscall rate on
 * the userspace side.
 *
 * The programs attach as raw tracepoints (kernel >= 4.17): they receive the
 * tracepoint arguments directly instead of the record a classic tracepoint
 * builds, and need neither tracefs nor kernel BTF.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "core_types.h"
#include "sysprobe.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u32 targ_tgid = 0; /* 0: trace every process */
const volatile __u32 self_tgid = 0; /* sysprobe's own pid, skipped */

struct start {
	__u64 ts;
	__s64 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); /* tid */
	__type(value, struct start);
} sys_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct syscall_key);
	__type(value, struct hist);
} sys_hist SEC(".maps");

DEFINE_STATS_MAP()
DEFINE_PROCESS_TRACKING()

/* Zero value used to create histogram entries without a 320-byte stack copy. */
static const struct hist zero_hist;

static __always_inline int skip(__u32 tgid)
{
	if (tgid == 0 || tgid == self_tgid)
		return 1;
	return targ_tgid && tgid != targ_tgid;
}

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	struct start *sp, s;

	if (skip(id >> 32))
		return 0;
	/*
	 * Hot path: the thread already has a slot, so write it in place. A map
	 * update on an LRU hash allocates and swaps an element, which costs
	 * several times a lookup; slots are therefore never deleted, only
	 * invalidated (ts = 0) at exit and recycled by LRU eviction.
	 */
	sp = bpf_map_lookup_elem(&sys_start, &tid);
	if (sp) {
		sp->ts = bpf_ktime_get_ns();
		sp->nr = (__s64)ctx->args[1]; /* sys_enter(struct pt_regs *regs, long id) */
		return 0;
	}
	s.ts = bpf_ktime_get_ns();
	s.nr = (__s64)ctx->args[1];
	if (bpf_map_update_elem(&sys_start, &tid, &s, BPF_NOEXIST))
		stat_inc(STAT_START_FULL);
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	struct syscall_key key = {};
	struct start *s;
	struct hist *h;
	__u64 delta;

	if (skip(id >> 32))
		return 0;
	s = bpf_map_lookup_elem(&sys_start, &tid);
	if (!s || !s->ts) {
		stat_inc(STAT_MISSED_START);
		return 0;
	}
	delta = bpf_ktime_get_ns() - s->ts;
	key.tgid = id >> 32;
	key.nr = (__u32)s->nr;
	s->ts = 0;
	if (key.nr == (__u32)-1)
		return 0;

	h = bpf_map_lookup_elem(&sys_hist, &key);
	if (!h) {
		bpf_map_update_elem(&sys_hist, &key, &zero_hist, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&sys_hist, &key);
		if (!h) {
			stat_inc(STAT_HIST_FULL);
			return 0;
		}
	}
	if (!h->comm[0]) {
		bpf_get_current_comm(h->comm, sizeof(h->comm));
		if (tid == key.tgid)
			note_leader_comm(key.tgid, h->comm);
	}
	hist_record(h, delta);
	return 0;
}
