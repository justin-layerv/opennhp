#!/usr/bin/env bash
# Fixture tests for scripts/check-base-image-pebble-purge.sh.
#
# The script derives REPO_ROOT from its own location, so each fixture is a fake
# repo: a symlink to the real script at <tmp>/scripts/ plus a <tmp>/docker/
# tree. That exercises the real discovery + matching logic against known-good
# and known-bad Dockerfiles, so a regression in either regex is caught here
# before the real docker/ tree runs in CI.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-base-image-pebble-purge.sh"

pass=0
fail=0

report_pass() {
  pass=$((pass + 1))
  printf '  [PASS] %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  printf '  [FAIL] %s\n      %s\n' "$1" "$2"
}

# Stage a fake repo root with the script symlinked in and an empty docker/ dir.
new_fixture() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/docker"
  ln -sf "$SCRIPT" "$dir/scripts/check-base-image-pebble-purge.sh"
}

# An ubuntu-based runtime Dockerfile that DOES purge pebble.
write_ubuntu_purged() {
  cat > "$1" <<'EOF'
FROM golang:1.26.5-bookworm AS builder
RUN true
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN apt-get update \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Canonical's Pebble.
    && rm -f /usr/bin/pebble && rm -rf /var/lib/pebble
EOF
}

# An ubuntu-based Dockerfile that does NOT purge pebble.
write_ubuntu_unpurged() {
  cat > "$1" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
}

assert_pass() {
  local name="$1" dir="$2"
  if "$dir/scripts/check-base-image-pebble-purge.sh" >/dev/null 2>&1; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got non-zero"
  fi
}

assert_fail() {
  local name="$1" dir="$2" want="$3"
  local out
  if out=$("$dir/scripts/check-base-image-pebble-purge.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0"
    return
  fi
  if [ -n "$want" ] && ! printf '%s' "$out" | grep -qF "$want"; then
    report_fail "$name" "stderr missing '$want'; got: $out"
    return
  fi
  report_pass "$name"
}

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

# 1. All ubuntu Dockerfiles purge -> pass.
d="$ROOT/all-good"; new_fixture "$d"
write_ubuntu_purged "$d/docker/Dockerfile.server"
write_ubuntu_purged "$d/docker/Dockerfile.relay"
assert_pass "all ubuntu Dockerfiles purge" "$d"

# 2. One ubuntu Dockerfile missing the purge -> fail, naming the file.
d="$ROOT/one-bad"; new_fixture "$d"
write_ubuntu_purged "$d/docker/Dockerfile.server"
write_ubuntu_unpurged "$d/docker/Dockerfile.ac"
assert_fail "ubuntu Dockerfile without purge fails" "$d" "docker/Dockerfile.ac"

# 3. Non-ubuntu Dockerfile (golang-only) is not required to purge, as long as at
#    least one ubuntu Dockerfile exists and is clean.
d="$ROOT/non-ubuntu-ignored"; new_fixture "$d"
write_ubuntu_purged "$d/docker/Dockerfile.server"
cat > "$d/docker/Dockerfile.agent" <<'EOF'
FROM golang:1.26.5-bookworm AS builder
RUN true
EOF
assert_pass "golang-only Dockerfile is not required to purge" "$d"

# 4. A comment that only mentions the command does not satisfy the check.
d="$ROOT/comment-only"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
# We could rm -f /usr/bin/pebble here, but this is just prose.
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "comment-only mention does not satisfy" "$d" "docker/Dockerfile.server"

# 5. The `FROM --platform=... ubuntu:` form (Dockerfile.app/base) is detected.
d="$ROOT/platform-flag"; new_fixture "$d"
cat > "$d/docker/Dockerfile.app" <<'EOF'
FROM --platform=$BUILDPLATFORM ubuntu:26.04@sha256:deadbeef
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "--platform ubuntu FROM is detected" "$d" "docker/Dockerfile.app"

# 6. No ubuntu Dockerfile at all -> hard error (the glob/pattern must not
#    silently pass on nothing).
d="$ROOT/no-ubuntu"; new_fixture "$d"
cat > "$d/docker/Dockerfile.agent" <<'EOF'
FROM golang:1.26.5-bookworm AS builder
RUN true
EOF
assert_fail "no ubuntu Dockerfile is a hard error" "$d" "no ubuntu-based Dockerfile"

# 7. The force flag may be any valid form (`-rf`, `--force`), not just `-f` —
#    a valid removal must not be rejected over a stylistic flag choice.
d="$ROOT/flag-variants"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -rf /usr/bin/pebble
EOF
cat > "$d/docker/Dockerfile.relay" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm --force /usr/bin/pebble
EOF
assert_pass "rm -rf / rm --force are accepted force forms" "$d"

# 8. The Dockerfile parser is case-insensitive and tolerates leading whitespace,
#    so a lowercase / indented `from ubuntu:` must still be detected and required
#    to purge — otherwise it would escape the discovery net.
d="$ROOT/lowercase-from"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
  from ubuntu:26.04@sha256:deadbeef as runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "lowercase/indented FROM is detected" "$d" "docker/Dockerfile.server"

# 9. Clearing /var/lib/pebble (the dir) without removing /usr/bin/pebble (the
#    CVE-bearing binary) must FAIL — the dir carries no CVE, the binary does.
d="$ROOT/dir-not-binary"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -rf /var/lib/pebble
EOF
assert_fail "removing only /var/lib/pebble is not enough" "$d" "docker/Dockerfile.server"

# 10. A digest-only `FROM ubuntu@sha256:...` (no :tag) must still be detected and
#     required to purge — it's the same base, just pinned without a tag.
d="$ROOT/digest-only-from"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu@sha256:deadbeef AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "digest-only FROM ubuntu@sha256 is detected" "$d" "docker/Dockerfile.server"

# 11. The purge target is path-anchored: removing a different file whose name
#     starts with the binary path (e.g. /usr/bin/pebble-old) must NOT satisfy it.
d="$ROOT/pebble-prefix"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -f /usr/bin/pebble-old
EOF
assert_fail "rm of /usr/bin/pebble-old does not count" "$d" "docker/Dockerfile.server"

# 12. The lint discovers tests/smoke/local-stack/ as a second root (mirroring
#     check-go-version-drift.sh), so an ubuntu Dockerfile there is checked too —
#     even when docker/ itself is clean.
d="$ROOT/smoke-root"; new_fixture "$d"
write_ubuntu_purged "$d/docker/Dockerfile.server"
mkdir -p "$d/tests/smoke/local-stack"
cat > "$d/tests/smoke/local-stack/Dockerfile" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS server-runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "ubuntu Dockerfile under tests/smoke/local-stack is checked" "$d" "tests/smoke/local-stack/Dockerfile"

# 13. A bare `FROM ubuntu` (no tag/digest, implicit latest) must still be
#     detected and required to purge.
d="$ROOT/bare-from"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "bare FROM ubuntu (no tag) is detected" "$d" "docker/Dockerfile.server"

# 14. A registry-qualified `FROM docker.io/library/ubuntu:` (an innocuous
#     refactor) must still be detected and required to purge.
d="$ROOT/registry-qualified"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM docker.io/library/ubuntu:26.04@sha256:deadbeef AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "registry-qualified ubuntu is detected" "$d" "docker/Dockerfile.server"

# 15. The registry-prefix tolerance must NOT over-match a different image whose
#     name merely ends in "ubuntu" (e.g. my/ubuntu-fork) — it's not required to
#     purge, so a clean ubuntu image alongside it still passes.
d="$ROOT/ubuntu-fork-ignored"; new_fixture "$d"
write_ubuntu_purged "$d/docker/Dockerfile.server"
cat > "$d/docker/Dockerfile.fork" <<'EOF'
FROM registry.example.com/my/ubuntu-fork:1 AS runtime
RUN echo no purge needed here
EOF
assert_pass "registry-prefixed ubuntu-fork is not flagged" "$d"

# 16. A multi-target `rm` (`rm -f /a /usr/bin/pebble`) fails CLOSED — the guard
#     demands the canonical single-target form. This is the documented safe bias
#     (the error points at the canonical form); locking it by test keeps it
#     intentional rather than an accidental regex artifact.
d="$ROOT/multi-target-rm"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -f /tmp/scratch /usr/bin/pebble
EOF
assert_fail "multi-target rm fails closed (canonical form required)" "$d" "docker/Dockerfile.server"

# 17-19. The other documented fail-closed forms — split-flag (`rm -r -f`),
#        quoted-path (`rm -f "…"`), and `--`-terminated (`rm -f -- …`) — are all
#        rejected the same way. Pin each so a future purge_re change can't quietly
#        start accepting them (or mis-accepting a near-miss) without the header's
#        documented contract being updated in lockstep.
d="$ROOT/split-flag-rm"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -r -f /usr/bin/pebble
EOF
assert_fail "split-flag rm -r -f fails closed" "$d" "docker/Dockerfile.server"

d="$ROOT/quoted-path-rm"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -f "/usr/bin/pebble"
EOF
assert_fail "quoted-path rm fails closed" "$d" "docker/Dockerfile.server"

d="$ROOT/dashdash-rm"; new_fixture "$d"
cat > "$d/docker/Dockerfile.server" <<'EOF'
FROM ubuntu:26.04@sha256:deadbeef AS runtime
RUN rm -f -- /usr/bin/pebble
EOF
assert_fail "-- terminated rm fails closed" "$d" "docker/Dockerfile.server"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
