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
ARG GO_VERSION=1.26.4
ARG GO_LINUX_AMD64_SHA256=1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f
ARG GO_LINUX_ARM64_SHA256=ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768
ARG GO_LINUX_ARMV6L_SHA256=8db458e995f18a9427a745cefe7a3323962fa2548c4715148963311f300d3b1a

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
