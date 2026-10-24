// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Per-process run-queue latency: time from a task becoming runnable
 * (wakeup, wakeup_new, or preemption while still TASK_RUNNING) until it is
 * switched onto a CPU. Uses BTF-typed tracepoints (tp_btf, kernel >= 5.5)
 * so the task_struct fields are relocated with CO-RE.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "core_types.h"
#include "sysprobe.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u32 targ_tgid = 0;
const volatile __u32 self_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); /* tid */
	__type(value, __u64);
} runq_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32); /* tgid */
	__type(value, struct hist);
} runq_hist SEC(".maps");

DEFINE_STATS_MAP()
DEFINE_EXIT_TRACKING()

static const struct hist zero_hist;

static __always_inline int skip(__u32 tgid, __u32 tid)
{
	if (tid == 0 || tgid == self_tgid) /* tid 0: the idle task */
		return 1;
	return targ_tgid && tgid != targ_tgid;
}

static __always_inline long task_state(struct task_struct *t)
{
	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___pre514 *)t, state);
}

static __always_inline void enqueue(struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u32 tid = BPF_CORE_READ(p, pid);
	__u64 ts;

	if (skip(tgid, tid))
		return;
	ts = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&runq_start, &tid, &ts, BPF_ANY))
		stat_inc(STAT_START_FULL);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	enqueue(p);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	enqueue(p);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, _Bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u32 tgid, tid;
	struct hist *h;
	__u64 *tsp, delta;

	/* A task preempted while runnable goes straight back on the queue. */
	if (task_state(prev) == TASK_RUNNING)
		enqueue(prev);

	tgid = BPF_CORE_READ(next, tgid);
	tid = BPF_CORE_READ(next, pid);
	if (skip(tgid, tid))
		return 0;
	tsp = bpf_map_lookup_elem(&runq_start, &tid);
	if (!tsp) {
		stat_inc(STAT_MISSED_START);
		return 0;
	}
	delta = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&runq_start, &tid);

	h = bpf_map_lookup_elem(&runq_hist, &tgid);
	if (!h) {
		bpf_map_update_elem(&runq_hist, &tgid, &zero_hist, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&runq_hist, &tgid);
		if (!h) {
			stat_inc(STAT_HIST_FULL);
			return 0;
		}
	}
	if (!h->comm[0])
		BPF_CORE_READ_STR_INTO(&h->comm, next, comm);
	hist_record(h, delta);
	return 0;
}
