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
RUN curl https://github.com/traefik/traefik/releases/download/v3.6.23/traefik-v3.6.23.src.tar.gz \
    && echo "c8a0fcd1916ad69d8c38707975bc4ab0ed3ffc0abfbaee0a8fdb41cb6289bad2  /tmp/traefik-src.tar.gz" | sha256sum -c - \
    && git fetch --depth=1 origin 84d4e8b139d1ac5e5b2d250fff95baed5ba0584f \
    && test "$(git rev-parse HEAD)" = 84d4e8b139d1ac5e5b2d250fff95baed5ba0584f \
    && go get google.golang.org/grpc@v1.82.1 \
    && go build -buildvcs=true \
    && awk -v want=v1.82.1 '$1 == "dep" && $3 == want { grpc = 1 }' /tmp/build-info \
    && awk '$3 == "v3.6.23+dirty" { module = 1 } \
             $2 == "vcs.revision=84d4e8b139d1ac5e5b2d250fff95baed5ba0584f" { revision = 1 } \
             $2 == "vcs.modified=true" { modified = 1 }' /tmp/build-info
EOF
expect_pass "fixed literal and metadata assertion pass" "$ROOT/good"

cp "$ROOT/good" "$ROOT/overridable"
printf '\nARG TRAEFIK_GRPC_VERSION=1.82.1\n' >>"$ROOT/overridable"
expect_fail "caller-overridable floor fails" "$ROOT/overridable" "must not be caller-overridable"

sed 's/grpc@v1\.82\.1/grpc@v1.81.1/' "$ROOT/good" >"$ROOT/vulnerable"
expect_fail "vulnerable literal fails" "$ROOT/vulnerable" "grpc-go v1.82.1 selection"

sed '/awk -v want=v1\.82\.1/d' "$ROOT/good" >"$ROOT/no-assertion"
expect_fail "missing binary assertion fails" "$ROOT/no-assertion" "embedded grpc-go v1.82.1 assertion"

cat >"$ROOT/comments-only" <<'EOF'
# https://github.com/traefik/traefik/releases/download/v3.6.23/traefik-v3.6.23.src.tar.gz
# c8a0fcd1916ad69d8c38707975bc4ab0ed3ffc0abfbaee0a8fdb41cb6289bad2  /tmp/traefik-src.tar.gz
# go get google.golang.org/grpc@v1.82.1
EOF
expect_fail "comments cannot satisfy the pin" "$ROOT/comments-only" "pinned Traefik v3.6.23 source URL"

sed '/v3\.6\.23+dirty/d' "$ROOT/good" >"$ROOT/devel-main"
expect_fail "devel main-module metadata fails" "$ROOT/devel-main" "versioned Traefik main-module assertion"

sed '/c8a0fcd1916ad69d8c38707975bc4ab0ed3ffc0abfbaee0a8fdb41cb6289bad2/d' "$ROOT/good" >"$ROOT/no-source-sha"
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
