#!/usr/bin/env bash

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
CHECK="$REPO_ROOT/scripts/check-traefik-grpc-pin.sh"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

pass=0
fail=0

expect_pass() {
  local name=$1 file=$2
  if "$CHECK" "$file" >/dev/null 2>&1; then
    pass=$((pass + 1))
    printf '  [PASS] %s\n' "$name"
  else
    fail=$((fail + 1))
    printf '  [FAIL] %s\n' "$name"
  fi
}

expect_fail() {
  local name=$1 file=$2 want=$3 out
  if out=$("$CHECK" "$file" 2>&1); then
    fail=$((fail + 1))
    printf '  [FAIL] %s (expected non-zero)\n' "$name"
  elif ! grep -qF "$want" <<<"$out"; then
    fail=$((fail + 1))
    printf '  [FAIL] %s (missing %q in %q)\n' "$name" "$want" "$out"
  else
    pass=$((pass + 1))
    printf '  [PASS] %s\n' "$name"
  fi
}

cat >"$ROOT/good" <<'EOF'
FROM golang:1.26.5 AS traefik-builder
RUN curl https://github.com/traefik/traefik/releases/download/v3.6.24/traefik-v3.6.24.src.tar.gz \
    && echo "bdd5ac1d6d8a046a518d7f4493f15d0b4a919fab51654852c9e75c54720edbcf  /tmp/traefik-src.tar.gz" | sha256sum -c - \
    && git fetch --depth=1 origin cc336581846996ffbd01b1290fd5b44787bad324 \
    && test "$(git rev-parse HEAD)" = cc336581846996ffbd01b1290fd5b44787bad324 \
    && go get google.golang.org/grpc@v1.82.1 golang.org/x/text@v0.39.0 \
    && go build -buildvcs=true \
    && awk -v want=v1.82.1 '$1 == "dep" && $3 == want { grpc = 1 }' /tmp/build-info \
    && awk -v want=v0.39.0 '$1 == "dep" && $3 == want { text = 1 }' /tmp/build-info \
    && awk '$3 == "v3.6.24+dirty" { module = 1 } \
             $2 == "vcs.revision=cc336581846996ffbd01b1290fd5b44787bad324" { revision = 1 } \
             $2 == "vcs.modified=true" { modified = 1 }' /tmp/build-info
EOF
expect_pass "fixed literal and metadata assertion pass" "$ROOT/good"

cp "$ROOT/good" "$ROOT/overridable"
printf '\nARG TRAEFIK_GRPC_VERSION=1.82.1\n' >>"$ROOT/overridable"
expect_fail "caller-overridable floor fails" "$ROOT/overridable" "must not be caller-overridable"

# The ARG ban is name-agnostic (see check-traefik-grpc-pin.sh): it rejects any
# ARG regardless of name, so a per-floor named case adds no coverage over the
# grpc-named case above plus the arbitrary-name case below, which together span
# "security-named ARG rejected" and "any ARG rejected".
cp "$ROOT/good" "$ROOT/unrelated-arg"
printf '\nARG FOO=bar\n' >>"$ROOT/unrelated-arg"
expect_fail "differently named ARG fails" "$ROOT/unrelated-arg" "must not be caller-overridable"

sed 's/grpc@v1\.82\.1/grpc@v1.81.1/' "$ROOT/good" >"$ROOT/vulnerable"
expect_fail "vulnerable literal fails" "$ROOT/vulnerable" "grpc-go v1.82.1 selection"

sed 's|x/text@v0\.39\.0|x/text@v0.37.0|' "$ROOT/good" >"$ROOT/vulnerable-x-text"
expect_fail "vulnerable x/text literal fails" "$ROOT/vulnerable-x-text" "x/text v0.39.0 selection"

sed '/awk -v want=v1\.82\.1/d' "$ROOT/good" >"$ROOT/no-assertion"
expect_fail "missing binary assertion fails" "$ROOT/no-assertion" "embedded grpc-go v1.82.1 assertion"

sed '/awk -v want=v0\.39\.0/d' "$ROOT/good" >"$ROOT/no-x-text-assertion"
expect_fail "missing x/text binary assertion fails" "$ROOT/no-x-text-assertion" "embedded x/text v0.39.0 assertion"

cat >"$ROOT/comments-only" <<'EOF'
# https://github.com/traefik/traefik/releases/download/v3.6.24/traefik-v3.6.24.src.tar.gz
# bdd5ac1d6d8a046a518d7f4493f15d0b4a919fab51654852c9e75c54720edbcf  /tmp/traefik-src.tar.gz
# go get google.golang.org/grpc@v1.82.1
# go get golang.org/x/text@v0.39.0
EOF
expect_fail "comments cannot satisfy the pin" "$ROOT/comments-only" "pinned Traefik v3.6.24 source URL"

sed '/v3\.6\.24+dirty/d' "$ROOT/good" >"$ROOT/devel-main"
expect_fail "devel main-module metadata fails" "$ROOT/devel-main" "versioned Traefik main-module assertion"

sed '/bdd5ac1d6d8a046a518d7f4493f15d0b4a919fab51654852c9e75c54720edbcf/d' "$ROOT/good" >"$ROOT/no-source-sha"
expect_fail "missing source checksum fails" "$ROOT/no-source-sha" "pinned Traefik source SHA256 check"

sed 's/ | sha256sum -c -//' "$ROOT/good" >"$ROOT/no-checksum-verifier"
expect_fail "missing checksum verifier fails" "$ROOT/no-checksum-verifier" "Traefik source checksum verifier"

sed "/test \"\$(git rev-parse HEAD)\"/d" "$ROOT/good" >"$ROOT/no-head-assertion"
expect_fail "missing commit assertion fails" "$ROOT/no-head-assertion" "pinned upstream Traefik HEAD assertion"

sed 's/-buildvcs=true/-buildvcs=false/' "$ROOT/good" >"$ROOT/no-buildvcs"
expect_fail "disabled VCS metadata fails" "$ROOT/no-buildvcs" "VCS-enabled Traefik build"

sed '/vcs\.revision=/d' "$ROOT/good" >"$ROOT/no-revision"
expect_fail "missing VCS revision assertion fails" "$ROOT/no-revision" "Traefik VCS revision assertion"

sed '/vcs\.modified=true/d' "$ROOT/good" >"$ROOT/no-modified"
expect_fail "missing patched-state assertion fails" "$ROOT/no-modified" "expected patched-source VCS state assertion"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
