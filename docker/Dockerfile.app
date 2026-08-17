# Stages 1 (builder) and 2 (runtime) are intentionally pinned to the
# SAME ubuntu digest. If they ever need to diverge (e.g. a CGO build
# requires a different glibc), update both digests deliberately rather
# than letting them drift; otherwise build-time apt deps and runtime
# loaders may resolve against different package indices.
FROM --platform=$BUILDPLATFORM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb AS builder

# Get target platform architecture
ARG TARGETARCH
ARG TARGETOS

# Checksums come from https://go.dev/dl/?mode=json. Keep GO_VERSION in
# lockstep with nhp/go.mod via scripts/check-go-version-drift.sh.
ARG GO_VERSION=1.26.6
ARG GO_LINUX_AMD64_SHA256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
ARG GO_LINUX_ARM64_SHA256=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e
ARG GO_LINUX_ARMV6L_SHA256=e1379a2fe77bd30fa29833074388247e7c65416e09279f746f20de2d5cf4dfea

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
FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    ca-certificates \
    clang \
    iptables \
    tcpdump \
    # Upgrade libssl3t64 + openssl-provider-legacy to >= 3.5.5-1ubuntu3.2
    # (fixes CVE-2026-45447). See Dockerfile.relay for the rationale (patched
    # base digest is < the docker dep-age window, so we patch the package here).
    libssl3t64 \
    openssl-provider-legacy \
    # Fail the build loudly if the openssl upgrade didn't land - this image is
    # NOT Trivy-scanned in CI, so this assertion is its only CVE-2026-45447 guard.
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3t64)" ge 3.5.5-1ubuntu3.2 \
        || { echo "ERROR: libssl3t64 < 3.5.5-1ubuntu3.2 - CVE-2026-45447 not patched"; exit 1; } \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Canonical's Pebble (unused stray Go binary the ubuntu base ships in
    # /usr/bin/pebble) - it flags HIGH x/net + stdlib CVEs. See Dockerfile.relay
    # and .trivyignore. (Not Trivy-scanned in CI today, kept consistent.)
    && rm -f /usr/bin/pebble && rm -rf /var/lib/pebble

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
