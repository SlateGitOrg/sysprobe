# Kernel requirements and overhead

## Requirements per collector

`sysprobe doctor` evaluates these on the running host (logic in
`internal/kernel`, unit-tested on any OS) and exits non-zero if any collector
is unavailable. Collectors are independent: `sysprobe run` starts the ones
that load and reports the others.

| Collector | Minimum kernel | Kernel BTF | Other |
|---|---|---|---|
| `syscalls` | 4.17 (raw tracepoints) | not needed | per-CPU hash maps |
| `runq` | 5.5 (`tp_btf`) | required | `BPF_PROG_TYPE_TRACING` |
| `tcp` | 5.8 (BPF ring buffer) | required | `BPF_PROG_TYPE_TRACING`, `sk_protocol` as a plain field (5.6+) |

All collectors need:

- **Privileges:** `CAP_SYS_ADMIN`, or `CAP_BPF` + `CAP_PERFMON` (5.8+).
  sysprobe lifts `RLIMIT_MEMLOCK` itself (needed before 5.11's memcg
  accounting).
- **No tracefs.** Every program attaches as a raw tracepoint or a BTF
  tracepoint, so `/sys/kernel/tracing` does not have to be mounted.
- **Kernel BTF** (`CONFIG_DEBUG_INFO_BTF=y`, exposed as
  `/sys/kernel/btf/vmlinux`) for `runq` and `tcp`. Most distribution kernels
  since about 2020 ship it (the libbpf project lists, among others, Ubuntu
  20.10+, Debian 11+, Fedora 31+ and RHEL 8.2+; not verified here).
  When BTF is present, `doctor` also confirms each tracepoint exists by
  looking up its `btf_trace_<name>` typedef; without BTF, tracepoint presence
  is reported as unverified.

Architectures: the BPF objects are built for little-endian BPF (`bpfel`) and
contain no architecture-specific register access, so the same objects serve
x86_64 and arm64. Syscall names come from per-architecture tables
(`internal/syscalls`, generated from `ausyscall`). **Only arm64 has been run**
(see the README's status section).

### In containers

Run privileged (or with the capabilities above) and with the host PID
namespace (`--pid=host`); BPF reports host PIDs, and sysprobe filters out its
own activity by PID, which only matches when the namespaces agree. This is how
`make integration` runs:

```sh
docker run --rm --privileged --pid=host ... sysprobe-builder:local sh scripts/integration.sh
```

Process garbage collection does not depend on the namespace: it is driven
by the `sched_process_exit` tracepoint, not by scanning `/proc`.

### Kernel layout changes handled

| Change | Kernel | How sysprobe copes |
|---|---|---|
| `task_struct.state` renamed `__state` | 5.14 | CO-RE `bpf_core_field_exists` picks the right one |
| classic `tcp:tcp_retransmit_skb` record gained `err` and its own event class | 6.x | uses `tp_btf/tcp_retransmit_skb` and reads `struct sock` |
| `sk_protocol` bitfield became a `u16` | 5.6 | `tcp` already requires 5.8 |
| `sched_switch` gained a `prev_state` argument | 5.18 | the program reads only `prev` and `next` |

## Overhead

### What was measured

`scripts/integration.sh` (run by `make integration`) times 2,000,000
`getppid()` calls, the cheapest syscall there is, seven times each in three
configurations and takes the median:

| Configuration | ns per `getppid()` | Added |
|---|---|---|
| no probe | 158.99 | |
| `sysprobe run -collectors syscalls` | 350.38 | +191.4 ns |
| `sysprobe run` (all collectors) | 352.07 | +193.1 ns |

Source: last lines of `integration/results/7.0.14-linuxkit.txt`. Environment:
Linux 7.0.14-linuxkit aarch64, 8 vCPUs, Docker Desktop VM on an arm64 Mac.

### How to read it

- The added cost per syscall is fixed: two program invocations, an LRU-hash
  lookup and a per-CPU-hash lookup, two `bpf_ktime_get_ns()` calls. It does
  not grow with the number of processes.
- Relative overhead depends on what the syscall does. Against a 159 ns
  syscall it more than doubles the cost; against a syscall that takes 5 µs it
  is about 4%; against blocking calls it is noise. A process issuing 1 million
  syscalls per second per core would spend about 19% more CPU on that core.
- `runq` and `tcp` add almost nothing to this benchmark because the
  benchmark rarely context-switches and makes no TCP calls; their cost scales
  with context switches and TCP state changes instead. It was not measured
  separately.
- Userspace work is once per interval: reading the maps plus `Ingest`, whose
  cost is benchmarked offline (`make bench`: about 186 ns per series per
  snapshot on the dev machine).

### Reducing it

- `-collectors syscalls,tcp` drops the scheduler hooks.
- `-pid N` filters in the kernel at the top of each program, before the
  histogram and start-timestamp maps are touched.
- Task-local storage for start timestamps (roadmap) would replace the LRU
  lookup on BTF kernels.
