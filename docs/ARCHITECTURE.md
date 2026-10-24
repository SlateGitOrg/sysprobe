# sysprobe architecture

This document covers how data moves from a tracepoint to a Prometheus series
or a terminal row, the algorithms on the way, and their cost.

## 1. Layers

| Layer | Package | Runs where | Tested by |
|---|---|---|---|
| BPF programs | `bpf/*.c` → `internal/probe/*_bpfel.o` | kernel | `make integration` (privileged) |
| Loader / snapshotter | `internal/probe` | Linux, root | `make integration` |
| Records and decoders | `internal/events` | anywhere | unit tests over raw bytes captured from the kernel |
| Recordings | `internal/fixture`, `internal/source` | anywhere | round-trip and corruption tests |
| Aggregation | `internal/aggregate`, `internal/hist`, `internal/labels` | anywhere | unit, property and recorded-fixture tests |
| Presentation | `internal/exporter`, `internal/top`, `internal/app` | anywhere | golden tests |

The boundary that makes this testable is `events.Snapshot`: everything above
it is the same code whether the snapshot came from the kernel a millisecond
ago or from a JSONL file recorded last week.

## 2. Kernel side

### 2.1 Syscall latency (`bpf/syscalls.bpf.c`)

```
raw_tp/sys_enter:  slot = sys_start[tid]           (LRU hash, 65,536 threads)
                   slot.ts = now; slot.nr = id     (in place when the slot exists)
raw_tp/sys_exit:   s = sys_start[tid]; if !s || !s.ts: missed_start++
                   delta = now - s.ts; s.ts = 0
                   h = sys_hist[(tgid, nr)]        (per-CPU hash, 16,384 keys, no prealloc)
                   h.slots[log2(delta)]++; h.count++; h.sum_ns += delta
```

- **Why raw tracepoints:** they receive `(regs, id)` directly and need
  neither tracefs nor BTF, so this collector works on 4.17+ kernels without
  `CONFIG_DEBUG_INFO_BTF`.
- **Why in-place start slots:** `bpf_map_update_elem` on an LRU hash
  allocates a new element and swaps it in; a lookup followed by a store into
  the returned value does not. Slots are invalidated (`ts = 0`) rather than
  deleted and are recycled by LRU eviction. During development, replacing
  update+delete with this pattern roughly halved the added cost measured by
  the integration script's getppid() benchmark (from about +400 ns to about
  +190 ns in the linuxkit VM; the old variant is not kept in the tree, so
  only the current number is reproducible).
- **Why per-CPU values:** two threads of one process making the same
  syscall on different CPUs would otherwise bounce one cache line on every
  exit. Per-CPU values need no atomics; userspace sums the CPUs. The cost is
  memory, which is why the map is `BPF_F_NO_PREALLOC`: a preallocated per-CPU
  map would reserve `16,384 × ncpu × 320 B` (42 MB on 8 CPUs) up front.
  The price of no-prealloc is that insertion can fail when the allocator's
  per-CPU cache is empty during a burst of new keys; that is counted as
  `hist_insert_failed` and only loses the samples that arrive during the
  failed insert.
- **Comm:** the first thread to create a key stores its `comm`. If that
  thread is the group leader, it also writes `proc_comm[tgid]`.

### 2.2 Run-queue latency (`bpf/runq.bpf.c`)

The runqlat algorithm: `tp_btf/sched_wakeup` and `sched_wakeup_new` stamp
`runq_start[tid]`; `tp_btf/sched_switch` stamps `prev` again when it was
preempted while still `TASK_RUNNING`, and for `next` computes
`now - runq_start[tid]` into `runq_hist[tgid]`. `task_struct.__state` is read
with CO-RE, falling back to the pre-5.14 field name `state`
(`bpf_core_field_exists`).

### 2.3 TCP (`bpf/tcp.bpf.c`)

- `tp_btf/inet_sock_set_state`: on `* -> SYN_SENT` (process context: the
  connecting task is current) store `{ts, tgid, comm}` under the socket
  pointer. On `SYN_SENT -> X` emit a connect event (`X == ESTABLISHED`) or a
  connect-failure event (anything else) with the latency, and delete the
  entry.
- `tp_btf/tcp_retransmit_skb`: emit the flow and state. No pid: it usually
  runs from the retransmit timer in softirq context.
- Both reserve a fixed 80-byte `struct tcp_event` in a 256 KiB ring buffer;
  a failed reservation is counted as `ringbuf_full`.

### 2.4 Lifecycle (`DEFINE_PROCESS_TRACKING` in `bpf/sysprobe.h`)

`raw_tp/sched_process_exit` puts the tgid of an exiting group leader in
`exited`; `raw_tp/sched_process_exec` writes the new comm to `proc_comm`.
Both histogram objects carry their own copy so either collector works alone.

### 2.5 Shared layouts and CO-RE

`bpf/sysprobe.h` defines `struct hist` (36 × u64 slots + count + sum + comm =
320 B), `struct syscall_key` (8 B) and `struct tcp_event` (80 B), all without
implicit padding. `internal/events` decodes them with fixed little-endian
offsets, and `TestLayoutMatchesBPFHeader` parses the header to pin
`MAX_SLOTS`, `TASK_COMM_LEN`, the three struct sizes and the event-kind
constants, so a C-side change without a Go-side change fails `make check`.

`bpf/core_types.h` declares the kernel types with
`preserve_access_index`: only the fields read, in any order. The loader
relocates every access against `/sys/kernel/btf/vmlinux` at load time.

## 3. Userspace pipeline

### 3.1 Snapshotting (`internal/probe`)

Every interval (default 1 s):

1. Read the `exited` set **first**.
2. Iterate each histogram map; sum per-CPU values (`events.SumPerCPU`).
3. Name every sample: `proc_comm[tgid]` if present, else the most common
   per-key comm of that tgid in this snapshot, ties broken lexicographically
   (`events.NameProcesses`). Without this step, threads (`ghc_ticker` vs
   `ghc_worker`) and fork-then-exec children (`integration.test` before
   exec) produced several labels for one process; the recorded-fixture
   invariant test exposed it.
4. Delete the histogram keys of the tgids from step 1, then those tgids from
   `exited` and `proc_comm`. Because step 1 happened before step 2, the values
   just emitted are the process's final values, so nothing is lost.
5. Drain the TCP events queued by the ring-buffer reader goroutine (bounded at
   100,000; overflow counted as `queue_full`) and read the drop counters.

### 3.2 Aggregation (`internal/aggregate`)

Per series (one `(tgid, nr)` pair, or one tgid for run-queue):

```
delta, ok := cur.Sub(last)     // ok=false if any counter went backwards
if !ok { resets++ ; delta = cur }
last = cur
total += delta                  // lifetime of this process record
window.put(seq, delta)          // ring of the last W snapshots
commTotal[(sticky(comm), nr)] += delta   // never evicted
```

- **Reset detection:** a cumulative reading that decreases in any bucket,
  the count or the sum means the kernel key was deleted and re-created, so the
  new reading itself is the delta. This is exact when the reset happened
  right after the previous reading and undercounts by at most one interval
  otherwise.
- **Exit and PID reuse:** a process whose kernel series are absent from a
  snapshot is marked exited at that snapshot and evicted `Retention`
  snapshots later (default 30). If the tgid reappears after being marked, it
  is a new process (PID reuse or re-created keys) and starts from zero
  without counting a reset.
- **Cap:** above `MaxProcesses` (default 4096), exited processes are evicted
  first, then the least recently active (`O(n log n)`, only when over the cap).
- **Sliding window:** a ring of `W` slots indexed by `seq mod W`, each tagged
  with its seq. `put` is O(Slots); a windowed histogram is the sum of slots
  whose tag lies in `(cur-W, cur]`, O(W × Slots), computed only when a view
  is rendered. A series that stops receiving data ages out of the window with
  no per-snapshot work. Interval lengths are kept in a parallel ring, so rates
  divide by the time the window actually covers.
- **Sticky labels (`internal/labels`):** the first `MaxCommLabels` comms (256)
  and `MaxDestLabels` destinations (64) get their own label, the rest map to
  `other` forever. Since a value never moves between its own series and
  `other`, every exported counter is monotonic.
  `TestCommTotalsMonotonicProperty` checks this over 400 snapshots of random
  exits, resets, renames and overflow.

### 3.3 Histogram maths (`internal/hist`)

Slot `i` holds latencies `2^i <= d < 2^(i+1)` ns (slot 0 also holds 0; slot
35 is open-ended at about 34 s).

- **Quantile:** find the bucket containing rank `q × total` and interpolate
  linearly inside it. The estimate always lies in the same bucket as the
  true sample quantile (property-tested against sorted samples), so the error
  is bounded by the bucket width, a factor of 2. The open-ended bucket
  reports its lower bound. O(Slots).
- **Totals:** quantiles use the bucket sum rather than the kernel's `count`
  field, because a per-CPU value read while that CPU is mid-update can have
  `count` ahead of the buckets by one.
- **Prometheus buckets:** `CumulativeAt(k)` is the exact number of samples
  `< 2^k` ns. The exporter emits `le = 2^k ns` for `k = 10, 12, ... 34`
  (1.024 µs to 17.2 s), so exported buckets are exact sums of kernel buckets.

### 3.4 Presentation

- `internal/exporter` is a const-metric `prometheus.Collector`: each scrape
  copies `Totals()` under a read lock and emits histograms. It passes
  `testutil.CollectAndLint` and a pedantic registry.
- `internal/top` renders a `View` to a string (golden-tested). The
  interactive loop (`internal/app.Screen`) redraws on each snapshot in raw
  terminal mode and handles `s`/`e`/`p`/`q`.

## 4. Complexity summary

| Operation | Time | Space |
|---|---|---|
| Kernel, per syscall | O(1): one LRU lookup, one per-CPU hash lookup, two `ktime` reads | 1 start slot per thread, 1 histogram per (process, syscall) per CPU |
| Kernel, per context switch | O(1): up to two hash updates and one lookup | 1 slot per runnable thread, 1 histogram per process per CPU |
| Snapshot read | O(keys × CPUs × Slots) | one copy of each value |
| `Ingest` | O(samples × Slots) (+ O(n log n) when over the process cap) | O(series × (W + 2) × Slots) |
| `View` | O(series × W × Slots + n log n) | O(series) |
| `Totals` / scrape | O(series × Slots + labels log labels) | O(series) |
| Quantile | O(Slots) | O(1) |

With the defaults (W = 10, Slots = 36) one series holds 12 histograms of
304 bytes: about 3.6 KB per (process, syscall) pair in userspace.

## 5. Failure handling

- A collector that cannot load (old kernel, no BTF, verifier rejection) is
  reported in `Statuses()` and skipped; `Open` fails only if none started.
  Verifier rejections include the verifier log.
- Every place the kernel side can lose data has a counter
  (`missed_start`, `hist_insert_failed`, `start_full`, `ringbuf_full`) and
  so does userspace (`decode_error`, `queue_full`); all are exported as
  `sysprobe_bpf_drops_total` and shown in the top header.
- Fixtures are validated on read (format, version, architecture, increasing
  seq, non-decreasing elapsed, bucket range, address syntax) and rejected
  with `fixture.ErrFormat` and a line number.

## 6. Security notes

sysprobe must run with `CAP_SYS_ADMIN` or `CAP_BPF + CAP_PERFMON`; it
observes every process on the host. It is read-only towards the kernel (no
`bpf_override_return`, no `bpf_probe_write_user`, no LSM or XDP programs),
the BPF verifier bounds every program, and nothing leaves the host except
`/metrics`, which exposes process names, syscall names and TCP destination
addresses. Treat that endpoint as internal; bind it to localhost
(`-listen 127.0.0.1:9464`) unless a scraper needs it. Kernel-supplied comm
strings are sanitised (`events.Comm`) before reaching a terminal or a label,
so a process cannot inject escape sequences into `sysprobe top`.
