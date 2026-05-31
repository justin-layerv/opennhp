# Stages 1 (builder) and 2 (runtime) are intentionally pinned to the
# SAME ubuntu digest. If they ever need to diverge (e.g. a CGO build
# requires a different glibc), update both digests deliberately rather
# than letting them drift; otherwise build-time apt deps and runtime
# loaders may resolve against different package indices.
FROM --platform=$BUILDPLATFORM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64 AS builder

# Get target platform architecture
ARG TARGETARCH
ARG TARGETOS

# Checksums come from https://go.dev/dl/?mode=json. Keep GO_VERSION in
# lockstep with nhp/go.mod via scripts/check-go-version-drift.sh.
ARG GO_VERSION=1.26.3
ARG GO_LINUX_AMD64_SHA256=2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556
ARG GO_LINUX_ARM64_SHA256=9d89a3ea57d141c2b22d70083f2c8459ba3890f2d9e818e7e933b75614936565
ARG GO_LINUX_ARMV6L_SHA256=d44133d4c66b1451a1e247da26db7716f76a081c0169a75e6c84e1871e394320

# Install basic tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    ca-certificates \
    clang \
    iptables \
    tcpdump \
    ipset \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV GO_VERSION=${GO_VERSION}

# Download and verify Go based on target architecture.
RUN case "${TARGETARCH}" in \
    "amd64") \
        GO_ARCH="linux-amd64"; \
        GO_SHA256="${GO_LINUX_AMD64_SHA256}" \
        ;; \
    "arm64") \
        GO_ARCH="linux-arm64"; \
        GO_SHA256="${GO_LINUX_ARM64_SHA256}" \
        ;; \
    "arm") \
        GO_ARCH="linux-armv6l"; \
        GO_SHA256="${GO_LINUX_ARMV6L_SHA256}" \
        ;; \
    *) \
        echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 \
        ;; \
    esac && \
    wget "https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH=/go
ENV PATH="${GOPATH}/bin:${PATH}"
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV CGO_ENABLED=1

# Verify installations
RUN go version && \
    gcc --version && \
    make --version
# Set working directory
WORKDIR /app

# Copy the source code
COPY ./web-app .
##
# Build the application
RUN CGO_ENABLED=0 GOOS=linux go mod tidy && go build -o app

# Stage 2: Create a minimal runtime image
FROM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    ca-certificates \
    clang \
    iptables \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/app /app
COPY ./web-app/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose port 8080
EXPOSE 8080

# Command to run the application
ENTRYPOINT ["/entrypoint.sh"]
