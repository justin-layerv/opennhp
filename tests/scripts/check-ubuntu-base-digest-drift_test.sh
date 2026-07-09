#!/usr/bin/env bash
# Fixture tests for scripts/check-ubuntu-base-digest-drift.sh.
#
# The script derives REPO_ROOT from its own location and reads
# docker/Dockerfile.server as the canonical digest, so each fixture is a fake
# repo: a symlink to the real script at <tmp>/scripts/ plus a <tmp>/docker/
# tree (and, where relevant, a <tmp>/tests/smoke/local-stack/ tree). That
# exercises the real discovery + digest-extraction + comparison logic against
# known-good and known-bad Dockerfiles, so a regression in the FROM regex, the
# digest extractor, or the source-of-truth handling is caught here before the
# real tree runs in CI.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-ubuntu-base-digest-drift.sh"

# Two distinct, well-formed 64-hex sha256 digests. CANON is what the
# source-of-truth docker/Dockerfile.server pins in every fixture; OTHER is the
# drifted value a bad Dockerfile carries.
CANON="sha256:$(printf 'a%.0s' $(seq 1 64))"
OTHER="sha256:$(printf 'b%.0s' $(seq 1 64))"

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
  ln -sf "$SCRIPT" "$dir/scripts/check-ubuntu-base-digest-drift.sh"
}

# An ubuntu runtime Dockerfile pinning $2 as its digest.
write_ubuntu() {
  cat > "$1" <<EOF
FROM golang:1.26.5-bookworm AS builder
RUN true
FROM ubuntu:26.04@$2 AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
}

# A golang-only Dockerfile (no ubuntu FROM) — nothing this lint requires.
write_golang_only() {
  cat > "$1" <<'EOF'
FROM golang:1.26.5-bookworm AS builder
RUN true
EOF
}

# The canonical source-of-truth file every drift fixture needs.
write_server_canonical() {
  write_ubuntu "$1/docker/Dockerfile.server" "$CANON"
}

assert_pass() {
  local name="$1" dir="$2"
  if "$dir/scripts/check-ubuntu-base-digest-drift.sh" >/dev/null 2>&1; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got non-zero"
  fi
}

assert_fail() {
  local name="$1" dir="$2" want="$3"
  local out
  if out=$("$dir/scripts/check-ubuntu-base-digest-drift.sh" 2>&1); then
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

# 1. All ubuntu FROMs share the canonical digest -> pass.
d="$ROOT/all-good"; new_fixture "$d"
write_server_canonical "$d"
write_ubuntu "$d/docker/Dockerfile.relay" "$CANON"
write_ubuntu "$d/docker/Dockerfile.ac" "$CANON"
assert_pass "all ubuntu FROMs on the canonical digest" "$d"

# 2. One ubuntu Dockerfile on a different digest -> fail, naming the file.
d="$ROOT/one-drifted"; new_fixture "$d"
write_server_canonical "$d"
write_ubuntu "$d/docker/Dockerfile.ac" "$OTHER"
assert_fail "a drifted ubuntu digest fails" "$d" "docker/Dockerfile.ac"

# 3. A golang-only Dockerfile is not required to carry an ubuntu digest, as long
#    as the source of truth and every real ubuntu FROM agree.
d="$ROOT/golang-only-ignored"; new_fixture "$d"
write_server_canonical "$d"
write_golang_only "$d/docker/Dockerfile.agent"
assert_pass "golang-only Dockerfile is ignored" "$d"

# 4. An un-pinned ubuntu FROM (no @sha256) -> fail. The lockstep check can only
#    compare a pinned digest; a floating tag is non-reproducible.
d="$ROOT/unpinned"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<'EOF'
FROM ubuntu:26.04 AS runtime
RUN apt-get update && rm -rf /var/lib/apt/lists/*
EOF
assert_fail "un-pinned ubuntu FROM fails" "$d" "not digest-pinned"

# 5. The `FROM --platform=... ubuntu:...@digest` form (Dockerfile.app/base) is
#    detected and its digest compared. \$BUILDPLATFORM is escaped so it stays a
#    literal in the fixture rather than expanding to empty.
d="$ROOT/platform-flag"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.app" <<EOF
FROM --platform=\$BUILDPLATFORM ubuntu:26.04@$OTHER AS builder
RUN true
EOF
assert_fail "--platform ubuntu digest is compared" "$d" "docker/Dockerfile.app"

# 6. The source-of-truth file missing -> hard error (canonical undefined).
d="$ROOT/no-server"; new_fixture "$d"
write_ubuntu "$d/docker/Dockerfile.relay" "$CANON"
assert_fail "missing source-of-truth is a hard error" "$d" "source-of-truth docker/Dockerfile.server not found"

# 7. The source-of-truth file present but with no ubuntu FROM -> hard error
#    (no canonical digest to compare against).
d="$ROOT/server-no-ubuntu"; new_fixture "$d"
write_golang_only "$d/docker/Dockerfile.server"
write_ubuntu "$d/docker/Dockerfile.relay" "$CANON"
assert_fail "source of truth with no ubuntu FROM is a hard error" "$d" "no digest-pinned ubuntu FROM"

# 8. A multi-stage file whose two ubuntu stages BOTH match the canonical (the
#    Dockerfile.app / smoke-image shape) -> pass.
d="$ROOT/multi-stage-good"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.app" <<EOF
FROM --platform=\$BUILDPLATFORM ubuntu:26.04@$CANON AS builder
RUN true
FROM ubuntu:26.04@$CANON AS runtime
RUN true
EOF
assert_pass "multi-stage file with both ubuntu stages on canonical" "$d"

# 9. A multi-stage file whose two ubuntu stages DIFFER -> fail, naming the stage
#    (Dockerfile.app's header requires both stages pin the SAME digest).
d="$ROOT/multi-stage-drift"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.app" <<EOF
FROM --platform=\$BUILDPLATFORM ubuntu:26.04@$CANON AS builder
RUN true
FROM ubuntu:26.04@$OTHER AS runtime
RUN true
EOF
assert_fail "multi-stage file with a drifted second stage names the stage" "$d" "docker/Dockerfile.app stage 2"

# 10. A registry-qualified `docker.io/library/ubuntu:...@digest` is detected and
#     its digest compared.
d="$ROOT/registry-qualified"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
FROM docker.io/library/ubuntu:26.04@$OTHER AS runtime
RUN true
EOF
assert_fail "registry-qualified ubuntu digest is compared" "$d" "docker/Dockerfile.relay"

# 11. A digest-only `FROM ubuntu@sha256:...` (no :tag) with the SAME digest as
#     canonical -> pass. The tag is advisory once a digest pins the bytes, so
#     the comparison is digest-only, not whole-ref.
d="$ROOT/digest-only-tagless"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
FROM ubuntu@$CANON AS runtime
RUN true
EOF
assert_pass "digest-only (tagless) ubuntu with matching digest passes" "$d"

# 12. A different image whose name merely ends in "ubuntu" (my/ubuntu-fork) is
#     NOT this base — its digest is not required to match, so a clean tree with
#     one alongside still passes.
d="$ROOT/ubuntu-fork-ignored"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.fork" <<EOF
FROM registry.example.com/my/ubuntu-fork:1@$OTHER AS runtime
RUN true
EOF
assert_pass "registry-prefixed ubuntu-fork is not compared" "$d"

# 13. The lint discovers tests/smoke/local-stack/ as a second root (the actual
#     #2800 bug: a drifted smoke image), so a mismatch there fails even when
#     docker/ itself is clean.
d="$ROOT/smoke-root"; new_fixture "$d"
write_server_canonical "$d"
mkdir -p "$d/tests/smoke/local-stack"
cat > "$d/tests/smoke/local-stack/Dockerfile" <<EOF
FROM ubuntu:26.04@$OTHER AS server-runtime
RUN true
EOF
assert_fail "drifted ubuntu Dockerfile under tests/smoke/local-stack is caught" "$d" "tests/smoke/local-stack/Dockerfile"

# 14. A digest that appears only in a whole-line comment does NOT count as a pin
#     — the FROM itself is un-pinned, so it fails.
d="$ROOT/comment-only-digest"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
# Historically this pinned ubuntu:26.04@$CANON before we floated it.
FROM ubuntu:26.04 AS runtime
RUN true
EOF
assert_fail "a digest in a comment is not a pin" "$d" "not digest-pinned"

# 15. A lowercase / indented `from ubuntu:...@digest` is detected (the Dockerfile
#     parser is case-insensitive and tolerates leading whitespace).
d="$ROOT/lowercase-from"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
  from ubuntu:26.04@$OTHER as runtime
RUN true
EOF
assert_fail "lowercase/indented FROM is detected and compared" "$d" "docker/Dockerfile.relay"

# 16. A trailing inline comment that itself contains a full ubuntu:<tag>@sha256
#     ref must NOT be mistaken for the pin. Extraction is anchored at ^FROM to the
#     image ref, so a reader that floated to the LAST `ubuntu@` on the line would
#     wrongly pick the comment's drifted digest and fail; the anchored reader
#     takes the ref's canonical digest and passes.
d="$ROOT/inline-comment-ubuntu-ref"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
FROM ubuntu:26.04@$CANON AS runtime  # rolled back from ubuntu:26.04@$OTHER
RUN true
EOF
assert_pass "an inline comment's ubuntu@sha256 is not read as the pin" "$d"

# 17. Conversely, an un-pinned FROM whose trailing comment names an ubuntu@sha256
#     is still un-pinned — the anchored extractor reads only the FROM ref (which
#     carries no @digest here), never the comment.
d="$ROOT/unpinned-with-comment-ubuntu-ref"; new_fixture "$d"
write_server_canonical "$d"
cat > "$d/docker/Dockerfile.relay" <<EOF
FROM ubuntu:26.04 AS runtime  # was ubuntu:26.04@$CANON
RUN true
EOF
assert_fail "an un-pinned FROM with an ubuntu@sha256 comment is still unpinned" "$d" "not digest-pinned"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
