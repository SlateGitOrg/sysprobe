# Data

All data in this repository was produced by this project; nothing was
downloaded. Licence: MIT, like the code.

| File | Kind | How it was produced | Size |
|---|---|---|---|
| `testdata/recorded/itest-7.0.14-linuxkit.jsonl` | **recorded** snapshot stream, 500 ms interval, 19 snapshots | `integration.TestLiveKernel` during `make integration` | ~750 KB |
| `testdata/recorded/itest-7.0.14-linuxkit.expect.json` | workload ground truth for the recording above (loadgen pids, sleep count, ports, connect counts) | same run, from the loadgen's own JSON output | <1 KB |
| `testdata/recorded/demo-7.0.14-linuxkit.jsonl` | **recorded** snapshot stream, 1 s interval, 8 s | `sysprobe record` in `scripts/integration.sh`, with the loadgen running | ~375 KB |
| `testdata/raw/itest-7.0.14-linuxkit.json` | **raw kernel bytes**: up to 16 ring-buffer records per TCP event kind and 24 per-CPU histogram values (loadgen keys only), each with the decoding made at capture time | same integration run | ~140 KB |
| `testdata/synthetic/churn.jsonl` | **synthetic**, hand-built (header says `"synthetic": true`): exit, PID reuse, exec rename, counter reset, all TCP event kinds | `churn()` in `internal/app/app_test.go`; regenerate with `go test ./internal/app -update` | ~5 KB |
| `integration/results/7.0.14-linuxkit.txt` | transcript of the integration run (doctor, test log, demo recording summary, overhead benchmark) | `make integration` | ~10 KB |
| `internal/syscalls/table_*.go` | syscall number → name for x86_64 and aarch64 | `make syscalls` (auditd 4.0.2 `ausyscall --dump` in the builder image) | |

## Where the recordings were made

All recorded files above come from one machine: a privileged container
(`sysprobe-builder:local`, `--privileged --pid=host`) on Docker
Desktop (Docker Engine 29.8.1) on an arm64 Mac, whose Linux VM runs kernel
`7.0.14-linuxkit` on aarch64 with 8 vCPUs. The `where` field of the
`.expect.json` file and the header of the transcript record this.

## What they contain

The probe observes the entire VM, so besides the load generator the
recordings contain whatever else ran there at the time: Docker's own daemons
(`dockerd`, `containerd`, `containerd-shim`, `runc`), the VM's init, and a few
unrelated local containers (process names such as `nginx`, `auth`,
`.postgres-wrapp`, `ghc_worker`, and their health checks `wget` /
`pg_isready` connecting to loopback ports). Recorded fields are limited to:
process ids, 15-character command names, syscall numbers, latency
histograms, and loopback TCP endpoints. No arguments, payloads, file names,
environment or user data are captured by sysprobe.

The load generator (`cmd/sysprobe-loadgen`) only talks to 127.0.0.1.
