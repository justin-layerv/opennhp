#!/usr/bin/env bash
# Fixture tests for scripts/check-l3-conntrack-pool-lockstep.sh.
#
# The tests copy the real Go/Terraform source-of-truth files into a temp repo,
# point the script at the fixture via $L3_CONNTRACK_POOL_LOCKSTEP_ROOT, and then
# mutate each side to prove drift is detected for the specific expected reason.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-l3-conntrack-pool-lockstep.sh"

REAL_PATHS=(
  "endpoints/ac/expiry_scheduler.go"
  "endpoints/ac/expiry_conntrack_flusher.go"
  "terraform/modules/ac/variables.tf"
  "terraform/variables.tf"
  "terraform/environments/sandbox/variables.tf"
  "terraform/environments/prod/variables.tf"
)

pass=0
fail=0

TMPDIRS=()
cleanup() {
  local d
  for d in "${TMPDIRS[@]:-}"; do
    [ -n "$d" ] && rm -rf "$d"
  done
}
trap cleanup EXIT

_mktemp() {
  local d
  d=$(mktemp -d)
  TMPDIRS+=("$d")
  printf '%s' "$d"
}

report_pass() {
  pass=$((pass + 1))
  printf '  \033[32m✓\033[0m %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

_make_fixture() {
  local dir="$1" rel
  for rel in "${REAL_PATHS[@]}"; do
    mkdir -p "$dir/$(dirname "$rel")"
    cp "$REPO_ROOT/$rel" "$dir/$rel"
  done
}

_run_capture() {
  local root="$1"
  L3_CONNTRACK_POOL_LOCKSTEP_ROOT="$root" bash "$SCRIPT" 2>&1
}

test_in_sync_passes() {
  local name="unmutated copy passes and reports derived constants"
  local tmp out rc
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  out=$(_run_capture "$tmp")
  rc=$?
  if [ "$rc" != "0" ]; then
    report_fail "$name" "expected exit 0, got $rc: $out"
    return
  fi
  if [[ "$out" != *"default=16 max=128"* ]]; then
    report_fail "$name" "success output did not include expected derived constants: $out"
    return
  fi
  report_pass "$name"
}

_expect_failure() {
  local name="$1" file="$2" sed_expr="$3" want_err="$4"
  local tmp out rc
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  cp "$tmp/$file" "$tmp/$file.pristine"
  sed -i.bak -E "$sed_expr" "$tmp/$file" && rm -f "$tmp/$file.bak"
  if diff -q "$tmp/$file" "$tmp/$file.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op (sed matched nothing)"
    return
  fi
  rm -f "$tmp/$file.pristine"

  out=$(_run_capture "$tmp")
  rc=$?
  if [ "$rc" = "0" ]; then
    report_fail "$name" "drift NOT detected (exit 0)"
    return
  fi
  if ! printf '%s' "$out" | grep -qF "$want_err"; then
    report_fail "$name" "failed (exit $rc) but not for expected reason '$want_err'; got: $out"
    return
  fi
  report_pass "$name"
}

test_go_worker_count_drift_updates_expected_max() {
  _expect_failure \
    "Go defaultWorkerCount drift changes expected Terraform max" \
    "endpoints/ac/expiry_scheduler.go" \
    's/(defaultWorkerCount[[:space:]]*=[[:space:]]*)64/\168/' \
    "Terraform max bound drift"
}

test_tf_module_bound_drift_fails() {
  _expect_failure \
    "AC module Terraform max-bound drift is detected" \
    "terraform/modules/ac/variables.tf" \
    's/(l3_flush_conntrack_pool_size.*<=[[:space:]]*)128/\1127/' \
    "Terraform max bound drift in terraform/modules/ac/variables.tf"
}

test_tf_env_bound_drift_fails() {
  _expect_failure \
    "environment Terraform max-bound drift is detected" \
    "terraform/environments/prod/variables.tf" \
    's/(l3_flush_conntrack_pool_size.*<=[[:space:]]*)128/\1129/' \
    "Terraform max bound drift in terraform/environments/prod/variables.tf"
}

test_tf_error_message_drift_fails() {
  _expect_failure \
    "Terraform validation message drift is detected" \
    "terraform/environments/sandbox/variables.tf" \
    's/between 0 and 128/between 0 and 127/' \
    "Terraform error-message drift"
}

test_tf_default_doc_drift_fails() {
  _expect_failure \
    "Terraform default doc drift is detected" \
    "terraform/modules/ac/variables.tf" \
    's/currently 16/currently 15/' \
    "Terraform default-doc drift"
}

test_tf_env_default_doc_drift_fails() {
  _expect_failure \
    "environment Terraform default doc drift is detected" \
    "terraform/environments/sandbox/variables.tf" \
    's/currently 16/currently 15/' \
    "Terraform default-doc drift"
}

test_go_default_expression_shape_fails() {
  _expect_failure \
    "Go default pool expression shape break fails loud" \
    "endpoints/ac/expiry_conntrack_flusher.go" \
    's/defaultWorkerCount \/ conntrackNetlinkWorkersPerSocket/16/' \
    "could not extract defaultConntrackNetlinkPoolSize expression"
}

test_validate_workflow_paths_cover_sources() {
  local name="validate-workflows trigger paths and step cover lockstep sources"
  local workflow="$REPO_ROOT/.github/workflows/validate-workflows.yml"
  local missing=() rel
  local expected_paths=(
    "scripts/check-l3-conntrack-pool-lockstep.sh"
    "endpoints/ac/expiry_scheduler.go"
    "endpoints/ac/expiry_conntrack_flusher.go"
    "terraform/modules/ac/variables.tf"
    "terraform/variables.tf"
    "terraform/environments/sandbox/variables.tf"
    "terraform/environments/prod/variables.tf"
  )

  for rel in "${expected_paths[@]}"; do
    if ! grep -qF "$rel" "$workflow"; then
      missing+=("$rel")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    report_fail "$name" "missing validate-workflows.yml path(s): ${missing[*]}"
    return
  fi

  if ! grep -qE '^[[:space:]]*bash scripts/check-l3-conntrack-pool-lockstep\.sh[[:space:]]*$' "$workflow"; then
    report_fail "$name" "validate-workflows.yml has trigger paths but no step runs the guard"
    return
  fi

  report_pass "$name"
}

echo "check-l3-conntrack-pool-lockstep.sh fixture tests"
test_in_sync_passes
test_go_worker_count_drift_updates_expected_max
test_tf_module_bound_drift_fails
test_tf_env_bound_drift_fails
test_tf_error_message_drift_fails
test_tf_default_doc_drift_fails
test_tf_env_default_doc_drift_fails
test_go_default_expression_shape_fails
test_validate_workflow_paths_cover_sources

echo ""
if [ "$fail" -gt 0 ]; then
  printf '\033[31mFAILED\033[0m: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf '\033[32mPASSED\033[0m: %d checks\n' "$pass"
