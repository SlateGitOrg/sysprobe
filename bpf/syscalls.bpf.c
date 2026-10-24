// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Per-process syscall latency histograms.
 *
 * raw_syscalls:sys_enter stamps the thread; raw_syscalls:sys_exit computes
 * the latency and adds it to a per-CPU log2 histogram keyed by
 * (tgid, syscall nr). Aggregation stays in the kernel: userspace only reads
 * the map once per interval, so cost does not scale with syscall rate on
 * the userspace side.
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

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct sys_enter_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	struct start s;

	if (skip(id >> 32))
		return 0;
	s.ts = bpf_ktime_get_ns();
	s.nr = ctx->id;
	if (bpf_map_update_elem(&sys_start, &tid, &s, BPF_ANY))
		stat_inc(STAT_START_FULL);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct sys_exit_ctx *ctx)
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
	if (!s) {
		stat_inc(STAT_MISSED_START);
		return 0;
	}
	delta = bpf_ktime_get_ns() - s->ts;
	key.tgid = id >> 32;
	key.nr = (__u32)s->nr;
	bpf_map_delete_elem(&sys_start, &tid);
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
	if (!h->comm[0])
		bpf_get_current_comm(h->comm, sizeof(h->comm));
	hist_record(h, delta);
	return 0;
}
