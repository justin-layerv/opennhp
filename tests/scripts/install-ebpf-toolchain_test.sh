#!/usr/bin/env bash
# Fixture tests for scripts/install-ebpf-toolchain.sh. The real workflow hits
# apt snapshots; these tests stub apt-get so retry classification stays covered
# without network or root.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/install-ebpf-toolchain.sh"

pass=0
fail=0
LAST_OUTPUT=""
RUN_DIR=""

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

make_apt_stub() {
  local dir="$1"
  cat >"$dir/apt-stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ -n "${EBPF_APT_ENV_LOG:-}" ]; then
  printf 'LC_ALL=%s\n' "${LC_ALL:-}" >> "$EBPF_APT_ENV_LOG"
fi

printf '%s\n' "$*" >> "$EBPF_APT_CALL_LOG"

attempts_file="${EBPF_APT_ATTEMPTS_FILE:-}"
attempt=1
if [ -n "$attempts_file" ]; then
  if [ -f "$attempts_file" ]; then
    attempt=$(($(cat "$attempts_file") + 1))
  fi
  printf '%s' "$attempt" >"$attempts_file"
fi

case "${EBPF_APT_FIXTURE_MODE:-success}" in
  success)
    echo "apt ok: $*"
    ;;
  terminal-on-install)
    case " $* " in
      *" install "*)
        echo "E: Version '1:18.1.3-1ubuntu1' for 'clang-18' was not found" >&2
        exit 100
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  terminal-unmet-deps-on-install)
    case " $* " in
      *" install "*)
        echo "The following packages have unmet dependencies:" >&2
        echo " clang-18 : Depends: libllvm18 but it is not going to be installed" >&2
        echo "E: Unable to correct problems, you have held broken packages." >&2
        exit 100
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  terminal-dpkg-error-on-install)
    case " $* " in
      *" install "*)
        echo "dpkg: error: processing package clang-18 (--configure):" >&2
        echo " installed clang-18 package post-installation script subprocess returned error exit status 1" >&2
        exit 100
        ;;
      *)
        echo "apt ok: $*"
      ;;
    esac
    ;;
  terminal-unknown-option-on-update)
    case " $* " in
      *" update "*)
        echo "E: Command line option --snapshot is not understood in combination with the other options" >&2
        exit 100
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  transient-dpkg-lock-on-install)
    case " $* " in
      *" install "*)
        lock_seen_file="${attempts_file}.lock-seen"
        if [ ! -f "$lock_seen_file" ]; then
          : >"$lock_seen_file"
          echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 123 (apt-get)" >&2
          exit 100
        fi
        echo "apt ok: $*"
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  transient-dpkg-frontend-lock-on-install)
    case " $* " in
      *" install "*)
        lock_seen_file="${attempts_file}.frontend-lock-seen"
        if [ ! -f "$lock_seen_file" ]; then
          : >"$lock_seen_file"
          echo "dpkg: error: dpkg frontend lock is locked by another process" >&2
          exit 100
        fi
        echo "apt ok: $*"
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  transient-dpkg-generic-returned-on-install)
    case " $* " in
      *" install "*)
        returned_seen_file="${attempts_file}.returned-seen"
        if [ ! -f "$returned_seen_file" ]; then
          : >"$returned_seen_file"
          echo "dpkg: error: helper returned temporary status" >&2
          exit 100
        fi
        echo "apt ok: $*"
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  transient-update-twice)
    case " $* " in
      *" update "*)
        if [ "$attempt" -lt 3 ]; then
          echo "Temporary failure resolving snapshot.ubuntu.com" >&2
          exit 100
        fi
        ;;
    esac
    echo "apt ok: $*"
    ;;
  always-transient-update)
    case " $* " in
      *" update "*)
        echo "Temporary failure resolving snapshot.ubuntu.com" >&2
        exit 100
        ;;
      *)
        echo "apt ok: $*"
        ;;
    esac
    ;;
  *)
    echo "unknown fixture mode: ${EBPF_APT_FIXTURE_MODE:-}" >&2
    exit 2
    ;;
esac
EOF
  chmod +x "$dir/apt-stub"
}

run_installer() {
  local mode="$1"; shift
  local dir; new_tmpdir dir
  make_apt_stub "$dir"
  mkdir -p "$dir/apt-tmp"
  LAST_OUTPUT="$dir/output"
  EBPF_APT_GET_STUB="$dir/apt-stub" \
    EBPF_APT_CALL_LOG="$dir/calls" \
    EBPF_APT_ENV_LOG="$dir/env" \
    EBPF_APT_ATTEMPTS_FILE="$dir/attempts" \
    EBPF_APT_FIXTURE_MODE="$mode" \
    EBPF_APT_RETRY_SLEEP_SECONDS=0 \
    TMPDIR="$dir/apt-tmp" \
    "$@" bash "$SCRIPT" >"$LAST_OUTPUT" 2>&1
  local status=$?
  RUN_DIR="$dir"
  return "$status"
}

test_success_installs_pinned_packages() {
  local name="success installs pinned packages from snapshot"
  if ! run_installer success env \
    EBPF_APT_SNAPSHOT=20260628T000000Z \
    EBPF_CLANG_PACKAGE=clang-18=1:18.1.3-1ubuntu1 \
    EBPF_LLVM_PACKAGE=llvm-18=1:18.1.3-1ubuntu1 \
    EBPF_LIBBPF_DEV_PACKAGE=libbpf-dev=1:1.3.0-2build2; then
    report_fail "$name" "expected success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if grep -q '^update -o APT::Update::Error-Mode=any --snapshot 20260628T000000Z$' "$RUN_DIR/calls" &&
    grep -q 'install -y --no-install-recommends --snapshot 20260628T000000Z clang-18=1:18.1.3-1ubuntu1 llvm-18=1:18.1.3-1ubuntu1 libbpf-dev=1:1.3.0-2build2' "$RUN_DIR/calls"; then
    report_pass "$name"
  else
    report_fail "$name" "missing expected apt calls: $(cat "$RUN_DIR/calls")"
  fi
}

test_terminal_package_errors_do_not_retry() {
  local name="terminal package errors do not retry"
  local status
  run_installer terminal-on-install env
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 1 ] &&
    grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected one install attempt and terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_dpkg_lock_errors_retry_then_succeed() {
  local name="dpkg lock errors retry then succeed"
  if ! run_installer transient-dpkg-lock-on-install env; then
    report_fail "$name" "expected retry success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 2 ] &&
    ! grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected two install attempts without terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_dpkg_frontend_lock_errors_retry_then_succeed() {
  local name="dpkg frontend lock errors retry then succeed"
  if ! run_installer transient-dpkg-frontend-lock-on-install env; then
    report_fail "$name" "expected retry success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 2 ] &&
    ! grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected two install attempts without terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_dpkg_generic_returned_errors_retry_then_succeed() {
  local name="dpkg generic returned errors retry then succeed"
  if ! run_installer transient-dpkg-generic-returned-on-install env; then
    report_fail "$name" "expected retry success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 2 ] &&
    ! grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected two install attempts without terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_dpkg_terminal_errors_do_not_retry() {
  local name="dpkg terminal errors do not retry"
  local status
  run_installer terminal-dpkg-error-on-install env
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 1 ] &&
    grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected one install attempt and terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_unmet_dependency_errors_do_not_retry() {
  local name="unmet dependency errors do not retry"
  local status
  run_installer terminal-unmet-deps-on-install env
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 1 ] &&
    grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected one install attempt and terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_terminal_update_option_errors_do_not_retry() {
  local name="terminal update option errors do not retry"
  local status
  run_installer terminal-unknown-option-on-update env
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$(grep -c '^update ' "$RUN_DIR/calls")" -eq 1 ] &&
    ! grep -q '^install ' "$RUN_DIR/calls" &&
    grep -q 'terminal package/version resolution failure' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected one update attempt, no install, and terminal diagnostic: $(cat "$LAST_OUTPUT")"
  fi
}

test_transient_update_retries_then_succeeds() {
  local name="transient update retries then succeeds"
  if ! run_installer transient-update-twice env; then
    report_fail "$name" "expected retry success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if [ "$(grep -c '^update ' "$RUN_DIR/calls")" -eq 3 ] &&
    [ "$(grep -c '^install ' "$RUN_DIR/calls")" -eq 1 ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected three update attempts then install: $(cat "$RUN_DIR/calls")"
  fi
}

test_transient_update_fails_after_attempt_budget() {
  local name="transient update fails after attempt budget"
  local status
  run_installer always-transient-update env
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ "$status" -eq 100 ] &&
    [ "$(grep -c '^update ' "$RUN_DIR/calls")" -eq 3 ] &&
    ! grep -q '^install ' "$RUN_DIR/calls" &&
    grep -q 'all attempts failed' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected update-only retry exhaustion: $(cat "$LAST_OUTPUT")"
  fi
}

test_zero_retry_budget_fails_before_apt() {
  local name="zero retry budget fails before apt"
  local status
  run_installer success env EBPF_APT_RETRY_ATTEMPTS=0
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ ! -e "$RUN_DIR/calls" ] &&
    grep -q 'EBPF_APT_RETRY_ATTEMPTS must be at least 1' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected retry-budget validation before apt: $(cat "$LAST_OUTPUT")"
  fi
}

test_noninteger_retry_budget_fails_before_apt() {
  local name="noninteger retry budget fails before apt"
  local status
  run_installer success env EBPF_APT_RETRY_ATTEMPTS=three
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ ! -e "$RUN_DIR/calls" ] &&
    grep -q 'EBPF_APT_RETRY_ATTEMPTS must be a positive integer' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected integer validation before apt: $(cat "$LAST_OUTPUT")"
  fi
}

test_noninteger_retry_sleep_fails_before_apt() {
  local name="noninteger retry sleep fails before apt"
  local status
  run_installer success env EBPF_APT_RETRY_SLEEP_SECONDS=soon
  status=$?
  if [ "$status" -eq 0 ]; then
    report_fail "$name" "expected failure, got success"
  elif [ ! -e "$RUN_DIR/calls" ] &&
    grep -q 'EBPF_APT_RETRY_SLEEP_SECONDS must be a non-negative integer' "$LAST_OUTPUT"; then
    report_pass "$name"
  else
    report_fail "$name" "expected sleep validation before apt: $(cat "$LAST_OUTPUT")"
  fi
}

test_retry_temp_files_are_cleaned() {
  local name="retry temp files are cleaned"
  if ! run_installer success env; then
    report_fail "$name" "expected success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if find "$RUN_DIR/apt-tmp" -mindepth 1 -print -quit | grep -q .; then
    report_fail "$name" "leftover temp files: $(find "$RUN_DIR/apt-tmp" -mindepth 1 -print)"
  else
    report_pass "$name"
  fi
}

test_forces_c_locale_for_apt_diagnostics() {
  local name="forces C locale for apt diagnostics"
  if ! run_installer success env; then
    report_fail "$name" "expected success, got failure: $(cat "$LAST_OUTPUT")"
    return
  fi
  if [ "$(grep -cv '^LC_ALL=C$' "$RUN_DIR/env")" -eq 0 ] &&
    [ "$(grep -c '^LC_ALL=C$' "$RUN_DIR/env")" -eq 2 ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected apt calls to inherit LC_ALL=C: $(cat "$RUN_DIR/env")"
  fi
}

echo "install-ebpf-toolchain.sh fixture tests"
test_success_installs_pinned_packages
test_terminal_package_errors_do_not_retry
test_dpkg_lock_errors_retry_then_succeed
test_dpkg_frontend_lock_errors_retry_then_succeed
test_dpkg_generic_returned_errors_retry_then_succeed
test_dpkg_terminal_errors_do_not_retry
test_unmet_dependency_errors_do_not_retry
test_terminal_update_option_errors_do_not_retry
test_transient_update_retries_then_succeeds
test_transient_update_fails_after_attempt_budget
test_zero_retry_budget_fails_before_apt
test_noninteger_retry_budget_fails_before_apt
test_noninteger_retry_sleep_fails_before_apt
test_retry_temp_files_are_cleaned
test_forces_c_locale_for_apt_diagnostics

echo ""
if [ "$fail" -gt 0 ]; then
  printf 'FAILED: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf 'PASSED: %d checks\n' "$pass"
