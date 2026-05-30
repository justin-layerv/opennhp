#!/usr/bin/env bash
# Fixture tests for scripts/ami-id-from-manifest.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/ami-id-from-manifest.sh"

pass=0
fail=0
failures=""

report_pass() {
  pass=$((pass + 1))
  printf '  \033[32m✓\033[0m %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  failures+="  ✗ $1: $2\n"
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

with_manifest() {
  local body="$1"
  local file="$TMPDIR/manifest.json"
  printf '%s\n' "$body" >"$file"
  printf '%s\n' "$file"
}

assert_success() {
  local name="$1" manifest="$2" region="$3" expected="$4"
  local output
  if output=$("$SCRIPT" "$manifest" "$region" 2>&1); then
    if [ "$output" = "$expected" ]; then
      report_pass "$name"
    else
      report_fail "$name" "got '$output', expected '$expected'"
    fi
  else
    report_fail "$name" "expected success, got failure: $output"
  fi
}

assert_failure() {
  local name="$1" manifest="$2" region="$3" expected_fragment="$4"
  local output
  if output=$("$SCRIPT" "$manifest" "$region" 2>&1); then
    report_fail "$name" "expected failure, got success: $output"
  elif [[ "$output" == *"$expected_fragment"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "failure output did not contain '$expected_fragment': $output"
  fi
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

single_region=$(with_manifest '{"builds":[{"artifact_id":"us-east-2:ami-0123456789abcdef0"}]}')
assert_success "single-region artifact" "$single_region" "us-east-2" "ami-0123456789abcdef0"

multi_region=$(with_manifest '{"builds":[{"artifact_id":"us-east-1:ami-11111111111111111,us-east-2:ami-22222222222222222"}]}')
assert_success "multi-region selects requested region" "$multi_region" "us-east-2" "ami-22222222222222222"

missing_region=$(with_manifest '{"builds":[{"artifact_id":"us-west-2:ami-0123456789abcdef0"}]}')
assert_failure "missing requested region" "$missing_region" "us-east-2" "has no AMI for region us-east-2"

malformed_ami=$(with_manifest '{"builds":[{"artifact_id":"us-east-2:not-an-ami"}]}')
assert_failure "malformed ami id" "$malformed_ami" "us-east-2" "not a valid ami-* identifier"

missing_artifact=$(with_manifest '{"builds":[{"name":"no artifact here"}]}')
assert_failure "missing artifact_id" "$missing_artifact" "us-east-2" "no artifact_id"

if [ "$fail" -ne 0 ]; then
  printf '\n%s' "$failures" >&2
  printf 'ami-id-from-manifest tests failed: %d failed, %d passed\n' "$fail" "$pass" >&2
  exit 1
fi

printf 'ami-id-from-manifest tests passed: %d\n' "$pass"
