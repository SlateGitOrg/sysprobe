# sysprobe — every gate runs through this file.
#   make check        format + lint (host and GOOS=linux) + tests + coverage gate
#   make demo         offline replay of a recorded fixture
#   make integration  privileged Linux run in Docker (skips without Docker)
#   make bpf          recompile BPF objects in the builder image

GO          ?= go
GOLANGCI    ?= golangci-lint
BUILDER     ?= sysprobe-builder:local
COVER_MIN   ?= 80
# Packages whose logic must stay >= COVER_MIN covered. probe (kernel I/O,
# exercised by `make integration`) and the cmd/ mains are excluded.
CORE_PKGS   := ./internal/hist ./internal/events ./internal/fixture ./internal/syscalls \
               ./internal/labels ./internal/aggregate ./internal/exporter ./internal/top \
               ./internal/kernel ./internal/source ./internal/app ./integration
CORE_LIST   := $(shell echo $(CORE_PKGS) | sed 's| ./| github.com/archit2501/sysprobe/|g; s|^./|github.com/archit2501/sysprobe/|' | tr ' ' ',')
DEMO_FIXTURE ?= $(firstword $(wildcard testdata/recorded/demo-*.jsonl))
DOCKER_RUN  := docker run --rm -v $(CURDIR):/src -v sysprobe-gomod:/go/pkg/mod -v sysprobe-gocache:/root/.cache/go-build

.PHONY: all check fmt fmt-check vet lint test cover build demo bench builder bpf syscalls bpf-verify integration clean

all: check

check: fmt-check vet lint test cover

fmt:
	gofmt -w $$(git ls-files '*.go')

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi; echo "gofmt: ok"

vet:
	$(GO) vet ./...
	GOOS=linux $(GO) vet ./...
	GOOS=linux $(GO) vet -tags integration ./integration/

lint:
	$(GOLANGCI) run ./...
	GOOS=linux $(GOLANGCI) run ./...

test:
	$(GO) test -race -count=1 ./...

cover:
	$(GO) test -count=1 -coverpkg=$(CORE_LIST) -coverprofile=coverage.out $(CORE_PKGS) >/dev/null
	@$(GO) tool cover -func=coverage.out | tail -1
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ { sub("%","",$$3); print $$3 }'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t + 0 < m + 0) { printf "coverage %.1f%% < %d%%\n", t, m; exit 1 } printf "coverage gate (>= %d%%): ok\n", m }'

build:
	$(GO) build -o bin/sysprobe ./cmd/sysprobe
	GOOS=linux $(GO) build -o bin/sysprobe-linux-$$($(GO) env GOARCH) ./cmd/sysprobe

# Offline: replays fixtures recorded on a real kernel by `make integration`.
ITEST_FIXTURE := $(firstword $(wildcard testdata/recorded/itest-*.jsonl))
ITEST_PID      = $(shell sed -n 's/.*"syscall_pid": \([0-9]*\).*/\1/p' $(ITEST_FIXTURE:.jsonl=.expect.json))

demo:
	@test -n "$(DEMO_FIXTURE)" -a -n "$(ITEST_FIXTURE)" || { echo "no recorded fixtures; run make integration"; exit 1; }
	@echo "== 1. top view at the end of a live recording (sysprobe record, 8s) =="
	@$(GO) run ./cmd/sysprobe replay -rows 10 $(DEMO_FIXTURE)
	@echo
	@echo "== 2. the known workload: loadgen pid $(ITEST_PID) slept 3ms per clock_nanosleep =="
	@$(GO) run ./cmd/sysprobe replay -rows -1 -pid $(ITEST_PID) -metrics \
		-metrics-filter 'sysprobe-loadge,clock_nanosleep' $(ITEST_FIXTURE)

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/aggregate ./internal/hist ./internal/events

builder:
	docker build -q -t $(BUILDER) -f build/Dockerfile.builder build >/dev/null

bpf: builder
	$(DOCKER_RUN) $(BUILDER) go generate ./internal/probe/

syscalls: builder
	$(DOCKER_RUN) $(BUILDER) sh scripts/gen-syscalls.sh

# Rebuilds the BPF objects and fails if they differ from the committed ones.
bpf-verify: bpf
	git diff --exit-code -- internal/probe/

integration:
	@if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then \
		echo "SKIP integration: Docker is not available"; exit 0; fi; \
	$(MAKE) --no-print-directory builder && \
	$(DOCKER_RUN) --privileged --pid=host \
		-e SYSPROBE_WHERE="privileged container (sysprobe-builder, --pid=host) on Docker $$(docker info -f '{{.ServerVersion}} {{.OperatingSystem}}'), VM kernel $$(docker info -f '{{.KernelVersion}}') $$(docker info -f '{{.Architecture}}'), host $$(uname -s) $$(uname -m)" \
		$(BUILDER) sh scripts/integration.sh

clean:
	rm -rf bin coverage.out
