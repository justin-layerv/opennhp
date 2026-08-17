# Multi-target image for the self-contained local smoke stack: one shared
# builder stage compiles BOTH nhp-serverd and nhp-acd (so the AC binary reuses
# the server build's Go compile cache instead of recompiling nhp/endpoints
# from cold), then two thin runtime stages. docker-compose.yaml selects the
# stage per service via `target: server-runtime` / `target: ac-runtime`.
#
# This is deliberately NOT docker/Dockerfile.{server,ac}: those run `make
# init`, whose `git clean -df release` step fails when the build context is a
# git worktree (`.git` is a file pointing outside the container). Here we build
# with a plain `go build` (same packages as the Makefile serverd/acd targets,
# minus the version-stamp ldflags, which are cosmetic for a local stack), so
# the build works identically from a normal checkout, a worktree, and PR CI.
#
# Base image digests are pinned to match docker/Dockerfile.server so layers are
# shared from the local/CI cache and the golang tag stays in lockstep with the
# canonical GO_VERSION in .github/workflows/build-and-push.yml. Bump together —
# scripts/check-ubuntu-base-digest-drift.sh enforces the ubuntu digest lockstep
# (#2800) and check-go-version-drift.sh the golang one, so a one-sided bump
# (e.g. a dependabot "bump ubuntu … in /docker" PR that can't reach this file)
# fails CI until this digest is bumped too.
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS builder

WORKDIR /src

# Module manifests first for layer caching. internalauth/ is pure-stdlib today
# (no go.sum) — mirror docker/Dockerfile.server's note: add internalauth/go.sum
# here when its first external dep lands.
COPY nhp/go.mod nhp/go.sum ./nhp/
COPY internalauth/go.mod ./internalauth/
COPY endpoints/go.mod endpoints/go.sum ./endpoints/
RUN cd nhp && go mod download
RUN cd endpoints && go mod download

# Only the three modules the builds need (nhp + internalauth are pulled in via
# endpoints' replace directives). Avoids copying .git, release/, node_modules,
# etc. without a repo-root .dockerignore (which would also affect
# docker/Dockerfile.server).
COPY nhp/ ./nhp/
COPY internalauth/ ./internalauth/
COPY endpoints/ ./endpoints/

ENV CGO_ENABLED=0
# Both binaries in one stage so the second `go build` reuses the first's
# /root/.cache/go-build (the shared nhp/endpoints packages compile once).
RUN cd endpoints && \
    go build -trimpath -o /out/nhp-serverd ./server/main/main.go && \
    go build -trimpath -o /out/nhp-acd ./ac/main/main.go

# --- server runtime -------------------------------------------------------
FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb AS server-runtime

RUN apt-get -o Acquire::Retries=3 update && \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Canonical's Pebble (unused stray Go binary the ubuntu base ships in
    # /usr/bin/pebble) — flags HIGH x/net + stdlib CVEs. Required by
    # scripts/check-base-image-pebble-purge.sh; see .trivyignore.
    && rm -f /usr/bin/pebble && rm -rf /var/lib/pebble

COPY --from=builder /out/nhp-serverd /nhp-server/nhp-serverd
# Plugin templates (passcode login pages, etc.), same as docker/Dockerfile.server.
COPY docker/nhp-server/templates /nhp-server/templates
RUN mkdir -p /nhp-server/logs /nhp-server/etc

WORKDIR /nhp-server

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=12 \
    CMD curl -f http://localhost:8888/health/live || exit 1

ENTRYPOINT ["/nhp-server/nhp-serverd"]
CMD ["run"]

# --- AC runtime -----------------------------------------------------------
FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb AS ac-runtime

# The AC opens firewall pinholes via iptables + ipset (needs NET_ADMIN at
# runtime — granted by the compose service).
RUN apt-get -o Acquire::Retries=3 update && \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    ca-certificates \
    curl \
    iptables \
    ipset \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Canonical's Pebble (unused stray Go binary the ubuntu base ships in
    # /usr/bin/pebble) — flags HIGH x/net + stdlib CVEs. Required by
    # scripts/check-base-image-pebble-purge.sh; see .trivyignore.
    && rm -f /usr/bin/pebble && rm -rf /var/lib/pebble

COPY --from=builder /out/nhp-acd /nhp-ac/nhp-acd
RUN mkdir -p /nhp-ac/logs /nhp-ac/etc

WORKDIR /nhp-ac

ENTRYPOINT ["/nhp-ac/nhp-acd"]
CMD ["run"]
