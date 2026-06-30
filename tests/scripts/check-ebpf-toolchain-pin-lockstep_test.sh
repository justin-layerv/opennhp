#!/usr/bin/env bash
# Fixture tests for scripts/check-ebpf-toolchain-pin-lockstep.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-ebpf-toolchain-pin-lockstep.sh"

REAL_WF="$REPO_ROOT/.github/workflows/ebpf-datapath-test.yml"
REAL_INSTALLER="$REPO_ROOT/scripts/install-ebpf-toolchain.sh"
REAL_DRIFT="$REPO_ROOT/scripts/check-ebpf-committed-object-drift.sh"
REAL_CLAUDE="$REPO_ROOT/CLAUDE.md"

pass=0
fail=0
LAST_OUTPUT=""

TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done; }
trap cleanup EXIT
new_tmpdir() {
  local __resultvar="$1" tmpdir_path
  tmpdir_path=$(mktemp -d)
  TMPDIRS+=("$tmpdir_path")
  printf -v "$__resultvar" '%s' "$tmpdir_path"
}

report_pass() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  FAIL %s\n      %s\n' "$1" "$2"; }

make_fixture() {
  local dir="$1"
  mkdir -p "$dir/.github/workflows" "$dir/scripts"
  cp "$REAL_WF" "$dir/.github/workflows/ebpf-datapath-test.yml"
  cp "$REAL_INSTALLER" "$dir/scripts/install-ebpf-toolchain.sh"
  cp "$REAL_DRIFT" "$dir/scripts/check-ebpf-committed-object-drift.sh"
  cp "$REAL_CLAUDE" "$dir/CLAUDE.md"
}

run_guard() {
  local dir="$1"
  LAST_OUTPUT="$dir/output"
  EBPF_TOOLCHAIN_PIN_LOCKSTEP_ROOT="$dir" bash "$SCRIPT" >"$LAST_OUTPUT" 2>&1
}

mutate() {
  local file="$1" sed_expr="$2" status=0
  cp "$file" "$file.pristine"
  sed -i.bak -E "$sed_expr" "$file" && rm -f "$file.bak"
  # Report a no-op mutation so the caller fails loudly instead of asserting
  # drift behavior against an unchanged fixture.
  diff -q "$file" "$file.pristine" >/dev/null 2>&1 && status=1
  rm -f "$file.pristine"
  return "$status"
}

test_in_sync_passes() {
  local name="in-sync pins pass"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp"
  if run_guard "$tmp" && grep -q 'eBPF toolchain pins lockstep' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected success: $(cat "$LAST_OUTPUT")"
  fi
}

expect_drift() {
  local name="$1" rel="$2" sed_expr="$3" expected="$4"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp"
  if ! mutate "$tmp/$rel" "$sed_expr"; then
    report_fail "$name" "mutation was a no-op"
    return
  fi
  if run_guard "$tmp"; then
    report_fail "$name" "expected drift failure, got success"
  elif grep -q "$expected" "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing expected diagnostic '$expected': $(cat "$LAST_OUTPUT")"
  fi
}

test_workflow_pin_drift_fails() {
  expect_drift "workflow env drift is detected" \
    ".github/workflows/ebpf-datapath-test.yml" \
    's/EBPF_CLANG_PACKAGE: clang-18=1:18\.1\.3-1ubuntu1/EBPF_CLANG_PACKAGE: clang-18=1:18.1.4-test/' \
    'installer defaults: EBPF_CLANG_PACKAGE='
}

test_installer_default_drift_fails() {
  # shellcheck disable=SC2016 # literal ${...} is the fixture text being mutated.
  expect_drift "installer default drift is detected" \
    "scripts/install-ebpf-toolchain.sh" \
    's/EBPF_LLVM_PACKAGE="\$\{EBPF_LLVM_PACKAGE:-llvm-18=1:18\.1\.3-1ubuntu1\}"/EBPF_LLVM_PACKAGE="${EBPF_LLVM_PACKAGE:-llvm-18=1:18.1.4-test}"/' \
    'installer defaults: EBPF_LLVM_PACKAGE=llvm-18=1:18.1.4-test'
}

test_drift_script_default_drift_fails() {
  # shellcheck disable=SC2016 # literal ${...} is the fixture text being mutated.
  expect_drift "drift-script default drift is detected" \
    "scripts/check-ebpf-committed-object-drift.sh" \
    's/expected_libbpf_dev_package_spec="\$\{EBPF_EXPECTED_LIBBPF_DEV_PACKAGE:-\$\{EBPF_LIBBPF_DEV_PACKAGE:-libbpf-dev=1:1\.3\.0-2build2\}\}"/expected_libbpf_dev_package_spec="${EBPF_EXPECTED_LIBBPF_DEV_PACKAGE:-${EBPF_LIBBPF_DEV_PACKAGE:-libbpf-dev=1:1.3.1-test}}"/' \
    'drift-script defaults: EBPF_LIBBPF_DEV_PACKAGE=libbpf-dev=1:1.3.1-test'
}

test_drift_script_comment_drift_fails() {
  expect_drift "drift-script canonical comment drift is detected" \
    "scripts/check-ebpf-committed-object-drift.sh" \
    's/#   apt snapshot 20260628T000000Z/#   apt snapshot 20260629T000000Z/' \
    'drift-script canonical comment: EBPF_APT_SNAPSHOT=20260629T000000Z'
}

test_claude_pin_line_drift_fails() {
  expect_drift "CLAUDE.md pin line drift is detected" \
    "CLAUDE.md" \
    's/EBPF_APT_SNAPSHOT=20260628T000000Z/EBPF_APT_SNAPSHOT=20260629T000000Z/' \
    'CLAUDE.md prose: EBPF_APT_SNAPSHOT=20260629T000000Z'
}

test_workflow_llvm_strip_derivation_drift_fails() {
  expect_drift "workflow LLVM_STRIP derivation drift is detected" \
    ".github/workflows/ebpf-datapath-test.yml" \
    's/\*\) LLVM_STRIP="llvm-strip" ;;/\*) LLVM_STRIP="llvm-strip-custom" ;;/' \
    'LLVM_STRIP derivation'
}

test_drift_script_llvm_strip_derivation_drift_fails() {
  expect_drift "drift-script LLVM_STRIP derivation drift is detected" \
    "scripts/check-ebpf-committed-object-drift.sh" \
    "s/\\*\\) printf 'llvm-strip' ;;/\\*) printf 'llvm-strip-custom' ;;/" \
    'LLVM_STRIP derivation'
}

test_missing_workflow_env_fails_loud() {
  local name="missing workflow env fails loud"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp"
  if ! mutate "$tmp/.github/workflows/ebpf-datapath-test.yml" '/EBPF_LLVM_PACKAGE:/d'; then
    report_fail "$name" "mutation was a no-op"
    return
  fi
  if run_guard "$tmp"; then
    report_fail "$name" "expected missing-env failure, got success"
  elif grep -q 'missing jobs.ebpf-datapath.env.EBPF_LLVM_PACKAGE' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing workflow-env diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_missing_claude_pin_line_fails_loud() {
  local name="missing CLAUDE.md pin line fails loud"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp"
  if ! mutate "$tmp/CLAUDE.md" '/Current canonical eBPF toolchain pins/d'; then
    report_fail "$name" "mutation was a no-op"
    return
  fi
  if run_guard "$tmp"; then
    report_fail "$name" "expected missing-CLAUDE failure, got success"
  elif grep -q 'missing canonical eBPF toolchain pin line' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing CLAUDE diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

echo "check-ebpf-toolchain-pin-lockstep.sh fixture tests"
test_in_sync_passes
test_workflow_pin_drift_fails
test_installer_default_drift_fails
test_drift_script_default_drift_fails
test_drift_script_comment_drift_fails
test_claude_pin_line_drift_fails
test_workflow_llvm_strip_derivation_drift_fails
test_drift_script_llvm_strip_derivation_drift_fails
test_missing_workflow_env_fails_loud
test_missing_claude_pin_line_fails_loud

echo ""
if [ "$fail" -gt 0 ]; then
  printf 'FAILED: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf 'PASSED: %d checks\n' "$pass"
