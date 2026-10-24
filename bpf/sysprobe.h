/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Shared definitions for the sysprobe BPF programs.
 *
 * Every struct here has a byte-for-byte twin in internal/events (Go). The
 * layouts are padding-free on purpose: the Go decoders use fixed offsets and
 * a unit test pins the sizes. Change both sides together.
 */
#ifndef SYSPROBE_H
#define SYSPROBE_H

#define TASK_COMM_LEN 16

/*
 * Log2 latency histogram. Slot i counts samples whose latency in ns, d,
 * satisfies 2^i <= d < 2^(i+1); slot 0 also holds d == 0, and the last
 * slot is open-ended (d >= 2^(MAX_SLOTS-1) ns, about 34 s).
 */
#define MAX_SLOTS 36

struct hist {
	__u64 slots[MAX_SLOTS];
	__u64 count;
	__u64 sum_ns;
	char comm[TASK_COMM_LEN];
}; /* 320 bytes */

struct syscall_key {
	__u32 tgid;
	__u32 nr;
}; /* 8 bytes */

/* tcp_event.kind */
#define TCP_EV_RETRANSMIT 1
#define TCP_EV_CONNECT 2
#define TCP_EV_CONNECT_FAIL 3

struct tcp_event {
	__u64 ts_ns;      /* bpf_ktime_get_ns() at emission */
	__u64 latency_ns; /* connect events: SYN_SENT -> final state */
	__u32 tgid;       /* connecting process; 0 when unknown (softirq) */
	__u32 kind;
	__u16 family;     /* AF_INET (2) or AF_INET6 (10) */
	__u16 sport;      /* host byte order */
	__u16 dport;      /* host byte order */
	__u8 state;       /* TCP state at the event */
	__u8 _pad;
	__u8 saddr[16];   /* network byte order; IPv4 uses the first 4 bytes */
	__u8 daddr[16];
	char comm[TASK_COMM_LEN];
}; /* 80 bytes */

/* Index into each object's per-CPU "stats" array. */
#define STAT_MISSED_START 0 /* exit/switch seen without a matching start */
#define STAT_HIST_FULL 1    /* new histogram key not inserted (map full or allocator empty) */
#define STAT_RINGBUF_FULL 2 /* ring buffer reservation failed */
#define STAT_START_FULL 3   /* start-timestamp map update failed */
#define STAT_MAX 4

static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 r = 0, shift;

	shift = (v > 0xFFFFFFFFULL) << 5; v >>= shift; r |= shift;
	shift = (v > 0xFFFF) << 4; v >>= shift; r |= shift;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static __always_inline __u32 slot_for(__u64 delta_ns)
{
	__u32 s = log2_u64(delta_ns);

	return s >= MAX_SLOTS ? MAX_SLOTS - 1 : s;
}

#define DEFINE_STATS_MAP()                                   \
	struct {                                             \
		__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);     \
		__uint(max_entries, STAT_MAX);               \
		__type(key, __u32);                          \
		__type(value, __u64);                        \
	} stats SEC(".maps");                                \
	static __always_inline void stat_inc(__u32 idx)      \
	{                                                    \
		__u64 *v = bpf_map_lookup_elem(&stats, &idx); \
		if (v)                                       \
			(*v)++;                              \
	}

/* Record one latency sample into a per-CPU histogram value. */
static __always_inline void hist_record(struct hist *h, __u64 delta_ns)
{
	__u32 s = slot_for(delta_ns);

	if (s < MAX_SLOTS) /* always true; bounds the index for the verifier */
		h->slots[s]++;
	h->count++;
	h->sum_ns += delta_ns;
}

/*
 * Process lifecycle tracking, shared by the histogram collectors.
 *
 * exit: when a thread-group leader exits, its tgid goes into "exited";
 * userspace takes a final reading of that process's histograms and then
 * deletes them. Doing this from the exit tracepoint (rather than scanning
 * /proc) is independent of the PID namespace sysprobe itself runs in.
 *
 * exec: a histogram key records the comm of the thread that created it, so
 * keys created between fork and exec carry the parent's name. On exec the
 * new comm is stored in "exec_comm" and userspace relabels the process.
 */
struct comm_val {
	char comm[TASK_COMM_LEN];
};

#define DEFINE_PROCESS_TRACKING()                                        \
	struct {                                                         \
		__uint(type, BPF_MAP_TYPE_HASH);                         \
		__uint(max_entries, 16384);                              \
		__type(key, __u32);   /* tgid */                         \
		__type(value, __u64); /* exit time, ns */                \
	} exited SEC(".maps");                                           \
	struct {                                                         \
		__uint(type, BPF_MAP_TYPE_HASH);                         \
		__uint(max_entries, 16384);                              \
		__type(key, __u32); /* tgid */                           \
		__type(value, struct comm_val);                          \
	} exec_comm SEC(".maps");                                        \
	SEC("raw_tracepoint/sched_process_exit")                         \
	int sched_process_exit(void *ctx)                                \
	{                                                                \
		__u64 id = bpf_get_current_pid_tgid();                   \
		__u32 tgid = id >> 32;                                   \
		__u64 ts;                                                \
		if ((__u32)id != tgid)                                   \
			return 0; /* not the group leader */             \
		ts = bpf_ktime_get_ns();                                 \
		bpf_map_update_elem(&exited, &tgid, &ts, BPF_ANY);       \
		return 0;                                                \
	}                                                                \
	SEC("raw_tracepoint/sched_process_exec")                         \
	int sched_process_exec(void *ctx)                                \
	{                                                                \
		__u32 tgid = bpf_get_current_pid_tgid() >> 32;           \
		struct comm_val v = {};                                  \
		bpf_get_current_comm(v.comm, sizeof(v.comm));            \
		bpf_map_update_elem(&exec_comm, &tgid, &v, BPF_ANY);     \
		return 0;                                                \
	}

#endif /* SYSPROBE_H */
