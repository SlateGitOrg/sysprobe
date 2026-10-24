#!/bin/sh
# Privileged end-to-end run. Executed INSIDE the builder container by
# `make integration` (docker run --privileged --pid=host), or directly as
# root on a Linux host (CI). Writes:
#   integration/results/<kernel>.txt         full transcript of this run
#   testdata/recorded/itest-<kernel>.*       snapshot stream + workload facts
#   testdata/raw/itest-<kernel>.json         raw kernel bytes + decodings
#   testdata/recorded/demo-<kernel>.jsonl    CLI recording used by make demo
set -eu

rel=$(uname -r)
mkdir -p integration/results testdata/recorded testdata/raw bin
out="integration/results/$rel.txt"
where=${SYSPROBE_WHERE:-"$(uname -sm) host, kernel $rel"}
export SYSPROBE_WHERE="$where"

median() { sort -n | awk '{ v[NR] = $1 } END { if (NR % 2) print v[(NR + 1) / 2]; else print (v[NR / 2] + v[NR / 2 + 1]) / 2 }'; }
ns_per_op() { sed -n 's/.*"ns_per_op":\([0-9.]*\).*/\1/p'; }

bench_set() {
	for _ in 1 2 3 4 5 6 7; do ./bin/sysprobe-loadgen bench -n 2000000 | ns_per_op; done | median
}

{
	echo "# sysprobe integration transcript"
	echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "where:  $where"
	echo "uname:  $(uname -a)"
	echo "cpus:   $(nproc)"
	echo "clang:  $(clang --version | head -1)"
	echo "go:     $(go version)"
	echo

	go build -o bin/sysprobe ./cmd/sysprobe
	go build -o bin/sysprobe-loadgen ./cmd/sysprobe-loadgen

	echo '$ sysprobe doctor'
	./bin/sysprobe doctor
	echo

	echo '$ SYSPROBE_RECORD_DIR=testdata go test -tags integration -count=1 -v ./integration/'
	SYSPROBE_RECORD_DIR="$PWD/testdata" go test -tags integration -count=1 -v ./integration/
	echo

	echo '$ sysprobe record -o testdata/recorded/demo-'"$rel"'.jsonl -duration 8s   (with loadgen running)'
	( sleep 1; ./bin/sysprobe-loadgen syscalls -duration 3s -sleep 3ms >/dev/null; ./bin/sysprobe-loadgen tcp -connects 10 >/dev/null ) &
	./bin/sysprobe record -o "testdata/recorded/demo-$rel.jsonl" -duration 8s -rows 12
	wait
	echo

	echo '# overhead: median of 7 runs of 2,000,000 getppid() calls, ns per call'
	base=$(bench_set)
	echo "baseline (no probe)                  : $base ns"
	./bin/sysprobe run -collectors syscalls -listen '' -duration 120s >/dev/null 2>&1 &
	sp=$!
	sleep 2
	sys=$(bench_set)
	kill -INT $sp; wait $sp || true
	echo "syscalls collector attached          : $sys ns"
	./bin/sysprobe run -listen '' -duration 120s >/dev/null 2>&1 &
	sp=$!
	sleep 2
	all=$(bench_set)
	kill -INT $sp; wait $sp || true
	echo "all collectors attached              : $all ns"
	awk -v b="$base" -v s="$sys" -v a="$all" 'BEGIN { printf "added per syscall: syscalls=%.1f ns, all=%.1f ns\n", s - b, a - b }'
	echo
	echo "integration status: PASS"
} 2>&1 | tee "$out"
echo "transcript written to $out"
grep -q '^integration status: PASS' "$out"
