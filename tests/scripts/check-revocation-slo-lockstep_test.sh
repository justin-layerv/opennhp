#!/usr/bin/env bash
# check-revocation-slo-lockstep_test.sh
# ----------------------------------------------------------------------------
# Fixture tests for scripts/check-revocation-slo-lockstep.sh (#2817).
#
# Copies the three real source-of-truth files into a tempdir that mimics the repo
# layout, points the script at it via $REVOCATION_SLO_LOCKSTEP_ROOT, and asserts:
#   - the unmutated copy passes (exit 0),
#   - a drift on EITHER side is DETECTED (exit non-zero) — this proves the lint
#     is non-vacuous: it actually fails when a site drifts, not just when nothing
#     changed:
#       * the Go scalar (seconds form) changes, the alarm threshold does not,
#       * the alarm threshold changes, the Go scalar does not,
#       * the retry age-out precondition changes, the Go scalar does not,
#       * the Go const, re-expressed in the millisecond form, drifts,
#   - the millisecond form of the Go const that NORMALIZES to the same value
#     still passes (exit 0) — so the unit conversion is exercised, not assumed,
#   - shape-breaking edits fail loud rather than silently passing:
#       * an unsupported Go time unit (time.Minute) — the extractor regex no
#         longer matches and the script exits non-zero with a clear pointer,
#       * the alarm `threshold` key renamed out from under the block scan — the
#         awk extractor returns empty and the script fails loud,
#       * a non-integer alarm threshold — the integer guard fails loud.
#       * the retry age-out precondition key renamed out from under the block
#         scan — the awk extractor returns empty and the script fails loud.
#
# Every drift / shape-break case also asserts on the script's specific stderr
# reason (not merely a non-zero exit), so a case cannot pass on an unrelated
# failure — e.g. the non-integer case must fail with "not a plain integer", not
# with a generic drift mismatch.
#
# Usage: bash tests/scripts/check-revocation-slo-lockstep_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-revocation-slo-lockstep.sh"

REAL_GO="$REPO_ROOT/endpoints/server/revocation_retry.go"
REAL_TF="$REPO_ROOT/terraform/modules/monitoring/main.tf"
REAL_TF_COMPUTE="$REPO_ROOT/terraform/modules/compute/main.tf"

pass=0
fail=0

# Track every tempdir we create and remove them all on EXIT. (A per-function
# RETURN trap leaks into the caller's return under `set -u` and trips on the
# now-out-of-scope $tmp — so we use one EXIT trap instead.)
TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done; }
trap cleanup EXIT
_mktemp() { local d; d=$(mktemp -d); TMPDIRS+=("$d"); printf '%s' "$d"; }

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# Build a fixture repo: copy the real files into the same relative paths under a
# tempdir. The script reads only these three files, so nothing else is needed.
_make_fixture() {
  local dir="$1"
  mkdir -p "$dir/endpoints/server" "$dir/terraform/modules/monitoring" "$dir/terraform/modules/compute"
  cp "$REAL_GO" "$dir/endpoints/server/revocation_retry.go"
  cp "$REAL_TF" "$dir/terraform/modules/monitoring/main.tf"
  cp "$REAL_TF_COMPUTE" "$dir/terraform/modules/compute/main.tf"
}

# Run the script against a fixture root; echo its exit code.
_run() {
  REVOCATION_SLO_LOCKSTEP_ROOT="$1" bash "$SCRIPT" >/dev/null 2>&1
  echo $?
}

# ---- test: in-sync copy passes ---------------------------------------------
test_in_sync() {
  local name="unmutated copy passes (exit 0)"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then report_pass "$name"; else report_fail "$name" "expected exit 0, got $rc"; fi
}

# Generic: apply a sed mutation to one fixture file, expect a NON-zero exit AND
# the expected-reason substring ($4) in the script's stderr. Asserting on the
# reason — not just any failure — keeps a case from passing on an unrelated
# error (e.g. the non-integer case must trip the integer guard, not a generic
# drift mismatch).
_expect_drift_detected() {
  local name="$1" file="$2" sed_expr="$3" want_err="$4"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  # Snapshot the pristine fixture file so we can detect a no-op sed (a mutation
  # that matched nothing would make the test vacuously "pass").
  cp "$tmp/$file" "$tmp/$file.pristine"
  sed -i.bak -E "$sed_expr" "$tmp/$file" && rm -f "$tmp/$file.bak"
  if diff -q "$tmp/$file" "$tmp/$file.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op (sed matched nothing) — test would be vacuous"
    return
  fi
  rm -f "$tmp/$file.pristine"
  local out rc
  out=$(REVOCATION_SLO_LOCKSTEP_ROOT="$tmp" bash "$SCRIPT" 2>&1); rc=$?
  if [ "$rc" = "0" ]; then
    report_fail "$name" "drift NOT detected (exit 0) — lint is vacuous for this site"
    return
  fi
  if ! printf '%s' "$out" | grep -qF "$want_err"; then
    report_fail "$name" "failed (exit $rc) but not for the expected reason; wanted substring: '$want_err'; got: $out"
    return
  fi
  report_pass "$name"
}

# ---- drift tests: each site, independently ---------------------------------
test_go_scalar_drift() {
  _expect_drift_detected "Go SLO scalar drift (seconds form) is detected" \
    "endpoints/server/revocation_retry.go" \
    's/(RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*)15([[:space:]]*\*[[:space:]]*time\.Second)/\120\2/' \
    "SLO drift between the Go constant and the CloudWatch alarm"
}
test_tf_threshold_drift() {
  _expect_drift_detected "CloudWatch alarm threshold drift is detected" \
    "terraform/modules/monitoring/main.tf" \
    '/revocation_delivery_latency_high/,/^}/ s/^([[:space:]]*threshold[[:space:]]*=[[:space:]]*)15000/\120000/' \
    "SLO drift between the Go constant and the CloudWatch alarm"
}
test_tf_compute_precondition_drift() {
  _expect_drift_detected "retry age-out precondition SLO drift is detected" \
    "terraform/modules/compute/main.tf" \
    '/revocation_retry_config_contract/,/^}/ s/(var\.revocation_retry_age_out_seconds[[:space:]]*>[[:space:]]*)15/\120/' \
    "SLO drift between the Go constant and the Terraform retry age-out precondition"
}
test_go_ms_form_drift() {
  _expect_drift_detected "Go SLO drift in millisecond form is detected" \
    "endpoints/server/revocation_retry.go" \
    's/(RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*)15([[:space:]]*\*[[:space:]]*)time\.Second/\114000\2time.Millisecond/' \
    "SLO drift between the Go constant and the CloudWatch alarm"
}

# ---- test: the equivalent millisecond form still passes --------------------
# Proves the seconds->ms normalization is exercised: 15000 * time.Millisecond
# must compare equal to the 15000 ms alarm threshold.
test_go_ms_form_equivalent_passes() {
  local name="Go SLO in equivalent millisecond form passes (exit 0)"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  local f="endpoints/server/revocation_retry.go"
  cp "$tmp/$f" "$tmp/$f.pristine"
  sed -i.bak -E \
    's/(RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*)15([[:space:]]*\*[[:space:]]*)time\.Second/\115000\2time.Millisecond/' \
    "$tmp/$f" && rm -f "$tmp/$f.bak"
  if diff -q "$tmp/$f" "$tmp/$f.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op (sed matched nothing) — test would be vacuous"
    return
  fi
  rm -f "$tmp/$f.pristine"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then report_pass "$name"; else report_fail "$name" "expected the equivalent ms form to pass, got exit $rc"; fi
}

# ---- shape-breaking edits fail loud (not a silent pass) --------------------
test_shape_break_go_unit_fails_loud() {
  # An unsupported time unit is exactly the "refactor to any other shape" the
  # script header promises to reject: the extractor regex (Second|Millisecond)
  # no longer matches, so the Go value goes un-extracted and the script must
  # exit non-zero rather than accept a stale alarm threshold.
  _expect_drift_detected "unsupported Go time unit (time.Minute) fails loud" \
    "endpoints/server/revocation_retry.go" \
    's/(RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*15[[:space:]]*\*[[:space:]]*time\.)Second/\1Minute/' \
    "could not extract RevocationDeliveryLatencyP99SLO"
}
test_shape_break_tf_key_fails_loud() {
  # Rename the threshold key inside the alarm block so the awk block-scan finds
  # no `threshold =` before the closing brace -> empty extract -> fail loud.
  _expect_drift_detected "renamed alarm threshold key fails loud" \
    "terraform/modules/monitoring/main.tf" \
    '/revocation_delivery_latency_high/,/^}/ s/^([[:space:]]*)threshold([[:space:]]*=)/\1threshold_RENAMED\2/' \
    "could not extract the threshold"
}
test_shape_break_tf_non_integer_fails_loud() {
  # A non-integer threshold (15000.5) is extracted but rejected by the integer
  # guard -> fail loud instead of a bogus compare.
  _expect_drift_detected "non-integer alarm threshold fails loud" \
    "terraform/modules/monitoring/main.tf" \
    '/revocation_delivery_latency_high/,/^}/ s/^([[:space:]]*threshold[[:space:]]*=[[:space:]]*[0-9]+)$/\1.5/' \
    "is not a plain integer"
}
test_shape_break_tf_compute_key_fails_loud() {
  # Rename the age-out variable inside the compute contract so the awk block-scan
  # finds no SLO comparison -> empty extract -> fail loud.
  _expect_drift_detected "renamed retry age-out precondition key fails loud" \
    "terraform/modules/compute/main.tf" \
    '/revocation_retry_config_contract/,/^}/ s/var\.revocation_retry_age_out_seconds/var.revocation_retry_age_out_seconds_RENAMED/' \
    "could not extract the revocation_retry_age_out_seconds SLO precondition"
}

echo "check-revocation-slo-lockstep.sh fixture tests"
test_in_sync
test_go_scalar_drift
test_tf_threshold_drift
test_tf_compute_precondition_drift
test_go_ms_form_drift
test_go_ms_form_equivalent_passes
test_shape_break_go_unit_fails_loud
test_shape_break_tf_key_fails_loud
test_shape_break_tf_non_integer_fails_loud
test_shape_break_tf_compute_key_fails_loud

echo ""
if [ "$fail" -gt 0 ]; then
  printf '\033[31mFAILED\033[0m: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf '\033[32mPASSED\033[0m: %d checks\n' "$pass"
