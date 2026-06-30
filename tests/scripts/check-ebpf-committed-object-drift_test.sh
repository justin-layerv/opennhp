#!/usr/bin/env bash
# Fixture tests for scripts/check-ebpf-committed-object-drift.sh.
#
# These fixtures cover the script's control flow and failure modes. Cross-path
# and cross-toolchain reproducibility is covered by the real eBPF workflow and
# local container checks, not by this synthetic Makefile.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-ebpf-committed-object-drift.sh"

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
output_file() { local d; new_tmpdir d; LAST_OUTPUT="$d/output"; }

make_fixture() {
  local dir="$1" committed_bytes="$2"
  mkdir -p "$dir/bin" "$dir/endpoints/ac/main/etc" "$dir/nhp/ebpf/xdp" "$dir/release/nhp-ac/etc"
  printf '%s' "$committed_bytes" >"$dir/endpoints/ac/main/etc/nhp_ebpf_xdp.o"
  printf 'source' >"$dir/nhp/ebpf/xdp/nhp_ebpf_xdp.c"
  cat >"$dir/Makefile" <<'EOF'
ebpf-objects:
	mkdir -p release/nhp-ac/etc
	printf '%s' "$${EBPF_FIXTURE_FRESH_BYTES:-fresh-object}" > release/nhp-ac/etc/nhp_ebpf_xdp.o
	printf '%s' "tc-object" > release/nhp-ac/etc/tc_egress.o
EOF
  cat >"$dir/bin/llvm-strip-18" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ] || [ "$1" != "--strip-debug" ]; then
  echo "unexpected llvm-strip fixture args: $*" >&2
  exit 2
fi
tmp="$2.tmp"
python3 - "$2" "$tmp" <<'PY'
import sys

src, dst = sys.argv[1:]
with open(src, "rb") as f:
    lines = f.read().splitlines(keepends=True)
with open(dst, "wb") as f:
    f.write(b"".join(line for line in lines if not line.startswith(b"debug:")))
PY
mv "$tmp" "$2"
EOF
  cat >"$dir/bin/clang-18" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "Ubuntu clang version 18.1.3 (fixture)"
  exit 0
fi
echo "unexpected clang fixture args: $*" >&2
exit 2
EOF
  cat >"$dir/bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
pkg="${!#}"
case "$pkg" in
  llvm-18) printf '1:18.1.3-1ubuntu1' ;;
  libbpf-dev) printf '1:1.3.0-2build2' ;;
  *) printf 'unavailable' ;;
esac
EOF
  cp "$dir/bin/llvm-strip-18" "$dir/bin/llvm-strip-fixture"
  cp "$dir/bin/clang-18" "$dir/bin/clang-fixture"
  chmod +x "$dir/bin/llvm-strip-18" "$dir/bin/llvm-strip-fixture"
  chmod +x "$dir/bin/clang-18" "$dir/bin/clang-fixture"
  chmod +x "$dir/bin/dpkg-query"
}

run_script() {
  local dir="$1"; shift
  local clang_bin="${CLANG:-$dir/bin/clang-18}"
  output_file
  EBPF_COMMITTED_OBJECT_ROOT="$dir" EBPF_FIXTURE_FRESH_BYTES="${EBPF_FIXTURE_FRESH_BYTES:-fresh-object}" CLANG="$clang_bin" LLVM_STRIP="$dir/bin/llvm-strip-18" PATH="$dir/bin:$PATH" \
    "$BASH" "$SCRIPT" "$@" >"$LAST_OUTPUT" 2>&1
}

test_matching_object_passes() {
  local name="matching committed object passes"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  if run_script "$tmp" --check &&
    grep -Fq 'OK: committed XDP load-relevant object matches fresh compile' "$LAST_OUTPUT" &&
    grep -Fq 'Ubuntu clang version 18.1.3 (fixture); llvm-18=1:18.1.3-1ubuntu1; libbpf-dev=1:1.3.0-2build2' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected full-match summary with toolchain, got: $(cat "$LAST_OUTPUT")"
  fi
}

test_default_mode_checks() {
  local name="default mode checks committed object"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  if run_script "$tmp"; then
    report_pass "$name"
  else
    report_fail "$name" "expected success, got failure: $(cat "$LAST_OUTPUT")"
  fi
}

test_stale_object_fails() {
  local name="stale committed object fails"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  if run_script "$tmp" --check; then
    report_fail "$name" "expected failure, got success"
  elif grep -q 'Regenerate with the canonical Linux eBPF toolchain' "$LAST_OUTPUT" &&
    grep -q 'FilterMode=EBPFXDP' "$LAST_OUTPUT" &&
    ! grep -q 'used a noncanonical eBPF toolchain' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing diagnostic guidance or unexpected noncanonical warning: $(cat "$LAST_OUTPUT")"
  fi
}

test_noncanonical_check_repeats_warning_before_drift_error() {
  local name="noncanonical --check repeats warning before drift error"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  if EBPF_EXPECTED_CLANG_PACKAGE="clang-not-the-test-binary=1:999.999.999-1" run_script "$tmp" --check; then
    report_fail "$name" "expected failure, got success"
  else
    local warning_line error_line
    warning_line=$(grep -n 'WARNING: --check used a noncanonical eBPF toolchain; verify the pinned toolchain before treating this as source/object drift' "$LAST_OUTPUT" | head -n 1 | cut -d: -f1)
    error_line=$(grep -n 'ERROR: committed XDP load-relevant object drifted' "$LAST_OUTPUT" | head -n 1 | cut -d: -f1)
    if grep -q 'WARNING: --check expected CLANG=clang-not-the-test-binary' "$LAST_OUTPUT" &&
      [ -n "$warning_line" ] &&
      [ -n "$error_line" ] &&
      [ "$warning_line" -lt "$error_line" ]; then
      report_pass "$name"
    else
      report_fail "$name" "missing ordered noncanonical warning: $(cat "$LAST_OUTPUT")"
    fi
  fi
}

test_full_dwarf_committed_object_fails() {
  local name="full-DWARF committed object fails"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" $'load:fresh\ndebug:old\n'
  if EBPF_FIXTURE_FRESH_BYTES=$'load:fresh\ndebug:new\n' run_script "$tmp" --check; then
    report_fail "$name" "expected failure, got success"
  elif grep -q 'committed XDP load-relevant object drifted' "$LAST_OUTPUT" &&
    grep -q 'stores DWARF-stripped, BTF-retaining committed bytes' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected full-DWARF committed object rejection: $(cat "$LAST_OUTPUT")"
  fi
}

test_update_strips_debug_sections() {
  local name="--update strips debug sections"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  if ! EBPF_FIXTURE_FRESH_BYTES=$'load:new\ndebug:gone\n' run_script "$tmp" --update; then
    report_fail "$name" "update failed: $(cat "$LAST_OUTPUT")"
    return
  fi
  local got; got=$(cat "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o")
  if [ "$got" = "load:new" ] &&
    grep -q 'DWARF-stripped fresh eBPF compile' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "update did not strip debug bytes: got '$got'; output: $(cat "$LAST_OUTPUT")"
  fi
}

test_update_rewrites_object() {
  local name="--update rewrites the committed object"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  if ! EBPF_FIXTURE_FRESH_BYTES="new-object" run_script "$tmp" --update; then
    report_fail "$name" "update failed: $(cat "$LAST_OUTPUT")"
    return
  fi
  local got; got=$(cat "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o")
  if [ "$got" = "new-object" ] &&
    grep -q '^sha256:' "$LAST_OUTPUT" &&
    grep -q '^toolchain:' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "bad update result or missing summary: $(cat "$LAST_OUTPUT")"
  fi
}

test_missing_committed_object_fails() {
  local name="missing committed object fails loud"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  rm -f "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o"
  if run_script "$tmp" --check; then
    report_fail "$name" "expected failure, got success"
  else
    report_pass "$name"
  fi
}

test_missing_fresh_compile_fails() {
  local name="missing fresh compile output fails loud"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  cat >"$tmp/Makefile" <<'EOF'
ebpf-objects:
	mkdir -p release/nhp-ac/etc
	printf '%s' "tc-object" > release/nhp-ac/etc/tc_egress.o
EOF
  if run_script "$tmp" --check; then
    report_fail "$name" "expected failure, got success"
  else
    report_pass "$name"
  fi
}

test_extra_args_fail_usage() {
  local name="extra arguments fail usage"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  local status
  run_script "$tmp" --check unexpected
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$status" -eq 2 ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 2, got $status: $(cat "$LAST_OUTPUT")"
  fi
}

test_help_exits_zero() {
  local name="--help exits zero"
  output_file
  if "$BASH" "$SCRIPT" --help >"$LAST_OUTPUT" 2>&1 &&
    grep -q '^Usage:' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected help usage, got: $(cat "$LAST_OUTPUT")"
  fi
}

test_outside_git_without_root_fails_cleanly() {
  local name="outside git without root override fails cleanly"
  local tmp; new_tmpdir tmp
  output_file
  local status
  (cd "$tmp" && "$BASH" "$SCRIPT" --check >"$LAST_OUTPUT" 2>&1)
  status=$?
  if [ "$status" -eq 1 ] &&
    grep -q 'set EBPF_COMMITTED_OBJECT_ROOT' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected clean root guidance, got status $status: $(cat "$LAST_OUTPUT")"
  fi
}

test_missing_explicit_clang_fails_cleanly() {
  local name="missing explicit CLANG fails cleanly"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  local status
  CLANG="clang-definitely-missing-for-ebpf-test" run_script "$tmp" --check
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif grep -q 'CLANG=clang-definitely-missing-for-ebpf-test was not found' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing CLANG diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_missing_default_clang_fails_cleanly() {
  local name="missing default clang fails cleanly"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  mkdir -p "$tmp/empty-path"
  local status
  output_file
  EBPF_COMMITTED_OBJECT_ROOT="$tmp" EBPF_FIXTURE_FRESH_BYTES=fresh-object LLVM_STRIP="$tmp/bin/llvm-strip-fixture" \
    PATH="$tmp/empty-path" CLANG='' "$BASH" "$SCRIPT" --check >"$LAST_OUTPUT" 2>&1
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif grep -q 'no clang binary was found' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing default clang diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_missing_strip_explains_load_relevant_check() {
  local name="missing llvm-strip explains load-relevant check"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "fresh-object"
  local status
  output_file
  EBPF_COMMITTED_OBJECT_ROOT="$tmp" EBPF_FIXTURE_FRESH_BYTES=fresh-object \
    CLANG="$tmp/bin/clang-18" LLVM_STRIP="$tmp/bin/missing-llvm-strip" PATH="$tmp/bin:$PATH" \
    "$BASH" "$SCRIPT" --check >"$LAST_OUTPUT" 2>&1
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif grep -q 'LLVM_STRIP=.* was not found' "$LAST_OUTPUT" &&
    grep -q 'strip the fresh XDP object before the load-relevant comparison' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing load-relevant strip diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_update_rejects_noncanonical_toolchain() {
  local name="--update rejects noncanonical toolchain"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  local status
  EBPF_EXPECTED_CLANG_PACKAGE="clang-not-the-test-binary=1:999.999.999-1" \
    EBPF_EXPECTED_LLVM_PACKAGE="llvm-not-the-test-binary=1:888.888.888-1" \
    EBPF_EXPECTED_LIBBPF_DEV_PACKAGE="libbpf-dev=9:9.9.9-test" \
    EBPF_FIXTURE_FRESH_BYTES="new-object" run_script "$tmp" --update
  status=$?
  local got; got=$(cat "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o")
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$got" != "stale-object" ]; then
    report_fail "$name" "noncanonical update rewrote committed object"
  elif [ -e "$tmp/release/nhp-ac/etc/nhp_ebpf_xdp.o" ]; then
    report_fail "$name" "noncanonical update ran make before rejecting"
  elif grep -q 'WARNING: --update expected CLANG=clang-not-the-test-binary' "$LAST_OUTPUT" &&
    grep -q 'WARNING: --update expected clang-not-the-test-binary version 999.999.999' "$LAST_OUTPUT" &&
    grep -q 'WARNING: --update expected LLVM_STRIP=llvm-strip-not-the-test-binary' "$LAST_OUTPUT" &&
    grep -q 'WARNING: --update expected llvm-not-the-test-binary=1:888.888.888-1' "$LAST_OUTPUT" &&
    grep -q 'WARNING: --update expected libbpf-dev=9:9.9.9-test' "$LAST_OUTPUT" &&
    grep -q -- '--update detected a noncanonical eBPF toolchain' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing noncanonical rejection diagnostics: $(cat "$LAST_OUTPUT")"
  fi
}

test_update_allows_noncanonical_toolchain_with_override() {
  local name="--update allows noncanonical toolchain with override"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  local status
  EBPF_ALLOW_NONCANONICAL_UPDATE=1 \
    EBPF_EXPECTED_CLANG_PACKAGE="clang-not-the-test-binary=1:999.999.999-1" \
    EBPF_FIXTURE_FRESH_BYTES="new-object" run_script "$tmp" --update
  status=$?
  local got; got=$(cat "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o")
  if [ "$status" -ne 0 ]; then
    report_fail "$name" "update failed despite override: $(cat "$LAST_OUTPUT")"
  elif [ "$got" != "new-object" ]; then
    report_fail "$name" "override did not rewrite committed object"
  elif grep -q 'EBPF_ALLOW_NONCANONICAL_UPDATE=1' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing override warning: $(cat "$LAST_OUTPUT")"
  fi
}

test_update_rejects_snapshot_mismatch() {
  local name="--update rejects snapshot mismatch"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  local status
  EBPF_APT_SNAPSHOT="20990101T000000Z" EBPF_FIXTURE_FRESH_BYTES="new-object" run_script "$tmp" --update
  status=$?
  local got; got=$(cat "$tmp/endpoints/ac/main/etc/nhp_ebpf_xdp.o")
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$got" != "stale-object" ]; then
    report_fail "$name" "snapshot mismatch update rewrote committed object"
  elif [ -e "$tmp/release/nhp-ac/etc/nhp_ebpf_xdp.o" ]; then
    report_fail "$name" "snapshot mismatch update ran make before rejecting"
  elif grep -q 'WARNING: --update expected EBPF_APT_SNAPSHOT=20260628T000000Z; got EBPF_APT_SNAPSHOT=20990101T000000Z' "$LAST_OUTPUT" &&
    grep -q -- '--update detected a noncanonical eBPF toolchain' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "missing snapshot mismatch rejection: $(cat "$LAST_OUTPUT")"
  fi
}

test_bare_package_specs_skip_version_warnings() {
  local name="bare package specs skip version warnings"
  local tmp; new_tmpdir tmp
  make_fixture "$tmp" "stale-object"
  local status
  EBPF_ALLOW_NONCANONICAL_UPDATE=1 \
    CLANG=sh \
    EBPF_EXPECTED_CLANG_PACKAGE="sh" \
    EBPF_EXPECTED_LLVM_PACKAGE="llvm" \
    EBPF_EXPECTED_LIBBPF_DEV_PACKAGE="libbpf-dev" \
    EBPF_FIXTURE_FRESH_BYTES="new-object" run_script "$tmp" --update
  status=$?
  if [ "$status" -ne 0 ]; then
    report_fail "$name" "update failed: $(cat "$LAST_OUTPUT")"
  elif grep -q 'WARNING: --update expected .* version' "$LAST_OUTPUT" ||
    grep -q 'WARNING: --update expected libbpf-dev=' "$LAST_OUTPUT"; then
    report_fail "$name" "unexpected version warning for bare package specs: $(cat "$LAST_OUTPUT")"
  else
    report_pass "$name"
  fi
}

echo "check-ebpf-committed-object-drift.sh fixture tests"
test_matching_object_passes
test_default_mode_checks
test_stale_object_fails
test_noncanonical_check_repeats_warning_before_drift_error
test_full_dwarf_committed_object_fails
test_update_strips_debug_sections
test_update_rewrites_object
test_missing_committed_object_fails
test_missing_fresh_compile_fails
test_extra_args_fail_usage
test_help_exits_zero
test_outside_git_without_root_fails_cleanly
test_missing_explicit_clang_fails_cleanly
test_missing_default_clang_fails_cleanly
test_missing_strip_explains_load_relevant_check
test_update_rejects_noncanonical_toolchain
test_update_allows_noncanonical_toolchain_with_override
test_update_rejects_snapshot_mismatch
test_bare_package_specs_skip_version_warnings

echo ""
if [ "$fail" -gt 0 ]; then
  printf 'FAILED: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf 'PASSED: %d checks\n' "$pass"
