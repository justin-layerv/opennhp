#!/usr/bin/env bash
# Install the pinned eBPF build toolchain used by the committed-object and
# in-kernel datapath proofs. Kept as a script so retry behavior is fixture-tested
# outside workflow YAML.
#
# The defaults below must match .github/workflows/ebpf-datapath-test.yml;
# scripts/check-ebpf-toolchain-pin-lockstep.sh guards that lockstep.

set -euo pipefail

# The retry classifier below matches apt/dpkg's English diagnostics.
export LC_ALL=C

EBPF_APT_SNAPSHOT="${EBPF_APT_SNAPSHOT:-20260628T000000Z}"
EBPF_CLANG_PACKAGE="${EBPF_CLANG_PACKAGE:-clang-18=1:18.1.3-1ubuntu1}"
EBPF_LLVM_PACKAGE="${EBPF_LLVM_PACKAGE:-llvm-18=1:18.1.3-1ubuntu1}"
EBPF_LIBBPF_DEV_PACKAGE="${EBPF_LIBBPF_DEV_PACKAGE:-libbpf-dev=1:1.3.0-2build2}"
EBPF_APT_RETRY_ATTEMPTS="${EBPF_APT_RETRY_ATTEMPTS:-3}"
EBPF_APT_RETRY_SLEEP_SECONDS="${EBPF_APT_RETRY_SLEEP_SECONDS:-10}"
APT_RETRY_OUTPUTS=()

cleanup_apt_retry_outputs() {
  if [ "${#APT_RETRY_OUTPUTS[@]}" -gt 0 ]; then
    rm -f "${APT_RETRY_OUTPUTS[@]}"
  fi
}
trap cleanup_apt_retry_outputs EXIT

case "$EBPF_APT_RETRY_ATTEMPTS" in
  ''|*[!0-9]*)
    echo "ERROR: EBPF_APT_RETRY_ATTEMPTS must be a positive integer; got '$EBPF_APT_RETRY_ATTEMPTS'." >&2
    exit 2
    ;;
esac
if [ "$EBPF_APT_RETRY_ATTEMPTS" -lt 1 ]; then
  echo "ERROR: EBPF_APT_RETRY_ATTEMPTS must be at least 1; got '$EBPF_APT_RETRY_ATTEMPTS'." >&2
  exit 2
fi

case "$EBPF_APT_RETRY_SLEEP_SECONDS" in
  ''|*[!0-9]*)
    echo "ERROR: EBPF_APT_RETRY_SLEEP_SECONDS must be a non-negative integer; got '$EBPF_APT_RETRY_SLEEP_SECONDS'." >&2
    exit 2
    ;;
esac
# The digits-only check rejects negatives; zero is intentionally valid for
# fixture tests and for no-wait local retry probes.

run_apt_get() {
  if [ -n "${EBPF_APT_GET_STUB:-}" ]; then
    "$EBPF_APT_GET_STUB" "$@"
    return
  fi
  sudo apt-get "$@"
}

is_terminal_apt_resolution_failure() {
  local output_file="$1"
  # Text matching is heuristic, so keep both directions bounded: a false
  # terminal match fails one attempt early, while a missed terminal match burns
  # only EBPF_APT_RETRY_ATTEMPTS attempts. dpkg lock-acquisition failures are
  # intentionally omitted here because they are transient on CI runners.
  if grep -Eiq "(Could not get lock|Unable to acquire the dpkg frontend lock|dpkg frontend lock is locked|/var/lib/dpkg/lock)" "$output_file"; then
    return 1
  fi
  grep -Eiq "(Version '.*' for '.*' was not found|Unable to locate package|has no installation candidate|unmet dependencies|Unable to correct problems|Sub-process .* returned an error code|No space left on device|Command line option .* is not understood|option .* is not understood|Unknown option|unrecognized option|dpkg: error(:[[:space:]]+|[[:space:]]+)(processing|while|in|.*subprocess[[:space:]]+returned[[:space:]]+error[[:space:]]+exit[[:space:]]+status))" "$output_file"
}

apt_retry() {
  local attempt final_status output status
  output="$(mktemp)"
  APT_RETRY_OUTPUTS+=("$output")

  final_status=1
  for ((attempt = 1; attempt <= EBPF_APT_RETRY_ATTEMPTS; attempt++)); do
    if run_apt_get "$@" >"$output" 2>&1; then
      cat "$output"
      final_status=0
      break
    else
      status=$?
    fi
    cat "$output" >&2
    if is_terminal_apt_resolution_failure "$output"; then
      echo "apt_retry: terminal package/version resolution failure for: apt-get $*" >&2
      final_status="$status"
      break
    fi
    if [ "$attempt" -eq "$EBPF_APT_RETRY_ATTEMPTS" ]; then
      echo "apt_retry: all attempts failed for: apt-get $*" >&2
      final_status="$status"
      break
    fi
    : >"$output"
    sleep "$((attempt * EBPF_APT_RETRY_SLEEP_SECONDS))"
  done
  return "$final_status"
}

apt_retry update -o APT::Update::Error-Mode=any --snapshot "$EBPF_APT_SNAPSHOT"
apt_retry install -y --no-install-recommends \
  --snapshot "$EBPF_APT_SNAPSHOT" \
  "$EBPF_CLANG_PACKAGE" \
  "$EBPF_LLVM_PACKAGE" \
  "$EBPF_LIBBPF_DEV_PACKAGE"
