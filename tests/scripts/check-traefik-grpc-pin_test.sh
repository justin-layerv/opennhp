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
RUN curl https://github.com/traefik/traefik/releases/download/v3.6.25/traefik-v3.6.25.src.tar.gz \
    && echo "bc72a87f59e9d81f62cf3a44ef34df4fe99aebdc1549e69f864087aff07983b7  /tmp/traefik-src.tar.gz" | sha256sum -c - \
    && git fetch --depth=1 origin 4b18b24b0b002dcc80e0640c6088a87d813de29a \
    && test "$(git rev-parse HEAD)" = 4b18b24b0b002dcc80e0640c6088a87d813de29a \
    && go mod verify \
    && go get golang.org/x/mod@v0.40.0 \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/crypto)" = v0.55.0 \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/mod)" = v0.40.0 \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/net)" = v0.58.0 \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/text)" = v0.41.0 \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/tools)" = v0.49.0 \
    && go mod verify \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=true \
    && go version -m /usr/local/bin/traefik > /tmp/build-info \
    && awk -v want=v1.82.1 '$1 == "dep" && $3 == want { grpc = 1 }' /tmp/build-info \
    && awk -v want=v0.55.0 '$1 == "dep" && $2 == "golang.org/x/crypto" && $3 == want { crypto = 1 }' /tmp/build-info \
    && awk -v want=v0.40.0 '$1 == "dep" && $2 == "golang.org/x/mod" && $3 == want { mod = 1 }' /tmp/build-info \
    && awk -v want=v0.58.0 '$1 == "dep" && $2 == "golang.org/x/net" && $3 == want { net = 1 }' /tmp/build-info \
    && awk -v want=v0.41.0 '$1 == "dep" && $2 == "golang.org/x/text" && $3 == want { text = 1 }' /tmp/build-info \
    && awk '$3 == "v3.6.25+dirty" { module = 1 } \
             $2 == "vcs.revision=4b18b24b0b002dcc80e0640c6088a87d813de29a" { revision = 1 } \
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

sed '/go get golang.org\/x\/mod@v0\.40\.0/d' "$ROOT/good" >"$ROOT/no-x-mod-override"
expect_fail "missing x/mod override fails" "$ROOT/no-x-mod-override" "exact x/mod v0.40.0 security override"

sed 's#go get golang.org/x/mod@v0.40.0#go get golang.org/x/mod@v0.39.0#' "$ROOT/good" >"$ROOT/vulnerable-x-mod"
expect_fail "vulnerable x/mod override fails" "$ROOT/vulnerable-x-mod" "exact x/mod v0.40.0 security override"

sed '/go list -m -f/d' "$ROOT/good" >"$ROOT/no-selected-x-mod-assertion"
expect_fail "missing selected graph assertion fails" "$ROOT/no-selected-x-mod-assertion" "selected x/crypto v0.55.0 assertion"

# Removing either checksum verifier must fail: one authenticates the pinned
# upstream graph and one authenticates the override-selected graph.
awk '!removed && /go mod verify/ { removed = 1; next } { print }' \
  "$ROOT/good" >"$ROOT/one-module-verifier"
expect_fail "single module checksum verifier fails" "$ROOT/one-module-verifier" "before-and-after Go module checksum verifiers"

# Counts alone are insufficient: every proof must run after the artifact it
# authenticates and before the next mutation or consumption boundary.
awk '
  !moved && /go mod verify/ { moved = 1; next }
  /go get golang.org\/x\/mod@v0\.40\.0/ {
    print
    print "    && go mod verify \\\\"
    next
  }
  { print }
' "$ROOT/good" >"$ROOT/override-before-first-verify"
expect_fail "override before first verifier fails" "$ROOT/override-before-first-verify" "fail-closed order"

awk '
  /go mod verify/ { seen++; if (seen == 2) next }
  /go build -buildvcs=true/ {
    print
    print "    && go mod verify \\\\"
    next
  }
  { print }
' "$ROOT/good" >"$ROOT/build-before-second-verify"
expect_fail "build before second verifier fails" "$ROOT/build-before-second-verify" "fail-closed order"

awk '
  /go build -buildvcs=true/ { build = $0; next }
  !moved && /awk -v want=v1\.82\.1/ { print; print build; moved = 1; next }
  { print }
' "$ROOT/good" >"$ROOT/metadata-before-build"
expect_fail "metadata before build fails" "$ROOT/metadata-before-build" "fail-closed order"

sed '/awk -v want=v1\.82\.1/d' "$ROOT/good" >"$ROOT/no-assertion"
expect_fail "missing binary assertion fails" "$ROOT/no-assertion" "embedded grpc-go v1.82.1 assertion"

sed '/awk -v want=v0\.55\.0/d' "$ROOT/good" >"$ROOT/no-x-crypto-assertion"
expect_fail "missing x/crypto binary assertion fails" "$ROOT/no-x-crypto-assertion" "embedded x/crypto v0.55.0 assertion"

sed '/awk -v want=v0\.40\.0/d' "$ROOT/good" >"$ROOT/no-x-mod-assertion"
expect_fail "missing x/mod binary assertion fails" "$ROOT/no-x-mod-assertion" "embedded x/mod v0.40.0 assertion"

sed '/awk -v want=v0\.58\.0/d' "$ROOT/good" >"$ROOT/no-x-net-assertion"
expect_fail "missing x/net binary assertion fails" "$ROOT/no-x-net-assertion" "embedded x/net v0.58.0 assertion"

sed '/awk -v want=v0\.41\.0/d' "$ROOT/good" >"$ROOT/no-x-text-assertion"
expect_fail "missing x/text binary assertion fails" "$ROOT/no-x-text-assertion" "embedded x/text v0.41.0 assertion"

cat >"$ROOT/comments-only" <<'EOF'
# https://github.com/traefik/traefik/releases/download/v3.6.25/traefik-v3.6.25.src.tar.gz
# bc72a87f59e9d81f62cf3a44ef34df4fe99aebdc1549e69f864087aff07983b7  /tmp/traefik-src.tar.gz
# go get google.golang.org/grpc@v1.82.1
# go get golang.org/x/mod@v0.40.0
# test "$(go list -m -f '{{.Version}}' golang.org/x/mod)" = v0.40.0
EOF
expect_fail "comments cannot satisfy the pin" "$ROOT/comments-only" "pinned Traefik v3.6.25 source URL"

sed '/v3\.6\.25+dirty/d' "$ROOT/good" >"$ROOT/devel-main"
expect_fail "devel main-module metadata fails" "$ROOT/devel-main" "versioned Traefik main-module assertion"

sed '/bc72a87f59e9d81f62cf3a44ef34df4fe99aebdc1549e69f864087aff07983b7/d' "$ROOT/good" >"$ROOT/no-source-sha"
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
