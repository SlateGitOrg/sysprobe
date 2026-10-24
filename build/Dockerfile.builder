# sysprobe builder image: clang (BPF target), libbpf headers, Go toolchain,
# and the runtime bits the privileged integration run needs.
# macOS clang has no BPF backend, so every BPF object is compiled here.
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev auditd iproute2 procps make \
 && rm -rf /var/lib/apt/lists/*

ENV GOFLAGS=-p=3 \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0

WORKDIR /src
