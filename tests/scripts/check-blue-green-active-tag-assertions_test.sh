#!/usr/bin/env bash
# check-blue-green-active-tag-assertions_test.sh
# ----------------------------------------------------------------------------
# Regression guard for sandbox blue/green deploy correctness:
#
# A dispatched blue-green-deploy.yml run must prove every deployed component's
# standby slot before switching traffic and its active slot before reporting
# success. These assertions belong in switch-traffic, not the optional validate
# job, because build-and-push.yml trusts the child workflow conclusion before it
# can continue to deployment tracking.
#
# Usage: bash tests/scripts/check-blue-green-active-tag-assertions_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
WF="$REPO_ROOT/.github/workflows/blue-green-deploy.yml"
HELPER="$REPO_ROOT/.github/scripts/assert-blue-green-image-tag.sh"

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

extract_job() {
  awk -v job="$1" '
    $0 ~ "^  " job ":[[:space:]]*$" { capture=1; print; next }
    capture && /^  [A-Za-z][A-Za-z0-9_-]*:[[:space:]]*$/ { exit }
    capture { print }
  ' "$WF"
}

extract_step() {
  local block="$1" step="$2"
  awk -v step="$step" '
    /^[[:space:]]*- name: / {
      name=$0
      sub(/^[[:space:]]*- name: /, "", name)
      gsub(/^"|"$/, "", name)
      if (name == step) { capture=1; print; next }
    }
    capture && /^[[:space:]]*- name: / { exit }
    capture { print }
  ' <<< "$block"
}

assert_in() {
  local block="$1" label="$2" re="$3"
  if grep -Eq -- "$re" <<< "$block"; then
    report_pass "$label"
  else
    report_fail "$label" "pattern not found: $re"
  fi
}

assert_not_in() {
  local block="$1" label="$2" re="$3"
  if grep -Eq -- "$re" <<< "$block"; then
    report_fail "$label" "unexpected pattern found: $re"
  else
    report_pass "$label"
  fi
}

assert_step_in() {
  local block="$1" step="$2" label="$3" re="$4"
  local step_block
  step_block=$(extract_step "$block" "$step")
  if [[ -z "$step_block" ]]; then
    report_fail "$label" "step not found: $step"
    return
  fi
  assert_in "$step_block" "$label" "$re"
}

assert_step_not_in() {
  local block="$1" step="$2" label="$3" re="$4"
  local step_block
  step_block=$(extract_step "$block" "$step")
  if [[ -z "$step_block" ]]; then
    report_fail "$label" "step not found: $step"
    return
  fi
  assert_not_in "$step_block" "$label" "$re"
}

assert_step_order() {
  local block="$1" before="$2" after="$3" label="$4"
  local before_line after_line
  before_line=$(awk -v step="$before" '
    /^[[:space:]]*- name: / {
      name=$0
      sub(/^[[:space:]]*- name: /, "", name)
      gsub(/^"|"$/, "", name)
      if (name == step) { print NR; exit }
    }
  ' <<< "$block")
  after_line=$(awk -v step="$after" '
    /^[[:space:]]*- name: / {
      name=$0
      sub(/^[[:space:]]*- name: /, "", name)
      gsub(/^"|"$/, "", name)
      if (name == step) { print NR; exit }
    }
  ' <<< "$block")
  if [[ -z "$before_line" || -z "$after_line" ]]; then
    report_fail "$label" "missing step(s): before='$before' after='$after'"
  elif [[ "$before_line" -lt "$after_line" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "step '$before' must appear before '$after'"
  fi
}

echo "check-blue-green-active-tag-assertions:"

if [[ ! -f "$WF" ]]; then
  report_fail "workflow present" "blue-green-deploy.yml not found at $WF"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
if [[ ! -f "$HELPER" ]]; then
  report_fail "blue/green tag helper exists" "assert-blue-green-image-tag.sh not found at $HELPER"
else
  report_pass "blue/green tag helper exists"
fi

SWITCH=$(extract_job switch-traffic)
if [[ -z "$SWITCH" ]]; then
  report_fail "switch-traffic job exists" "no '  switch-traffic:' job header found"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
report_pass "switch-traffic job exists"

VALIDATE=$(extract_job validate)
if [[ -z "$VALIDATE" ]]; then
  report_fail "validate job exists" "no '  validate:' job header found"
else
  report_pass "validate job exists"
  assert_not_in "$VALIDATE" "old both-only active-tag assertion is not left behind in optional validate job" \
    'Assert Server and AC Active Tags Match Input'
fi

SERVER_PRE_STEP="[Server] Assert Standby Image Tag Matches Target"
AC_PRE_STEP="[AC] Assert Standby Image Tag Matches Target"
SERVER_POST_STEP="[Server] Assert Active Image Tag Matches Target"
AC_POST_STEP="[AC] Assert Active Image Tag Matches Target"

assert_step_order "$SWITCH" "$SERVER_PRE_STEP" "[Server] Switch NLB Listeners" \
  "server standby assertion runs before server switch"
assert_step_order "$SWITCH" "$AC_PRE_STEP" "[AC] Switch NLB Listener" \
  "AC standby assertion runs before AC switch"
assert_step_order "$SWITCH" "$SERVER_PRE_STEP" "$AC_PRE_STEP" \
  "all standby assertions complete before any switch can fail later"
assert_step_order "$SWITCH" "$AC_PRE_STEP" "[Server] Switch NLB Listeners" \
  "AC standby assertion completes before server switch"
assert_step_order "$SWITCH" "[AC] Switch NLB Listener" "[Server] Switch NLB Listeners" \
  "AC traffic becomes authoritative before durable-session server traffic"

assert_step_order "$SWITCH" "[Server] Switch NLB Listeners" "$SERVER_POST_STEP" \
  "server active-tag assertion runs after server switch"
assert_step_order "$SWITCH" "[AC] Switch NLB Listener" "$AC_POST_STEP" \
  "AC active-tag assertion runs after AC switch"
assert_step_order "$SWITCH" "$AC_POST_STEP" "[AC] Clear DynamoDB AC Assignments (stale server IPs)" \
  "active-tag assertions run before downstream reconnect work"

assert_step_not_in "$SWITCH" "$SERVER_PRE_STEP" "server standby assertion is not limited to deploy actions" \
  "inputs\\.action == 'deploy'"
assert_step_in "$SWITCH" "$SERVER_PRE_STEP" "server standby assertion skips dry-run only" \
  "inputs\\.dry_run != true"
assert_step_not_in "$SWITCH" "$SERVER_PRE_STEP" "server standby assertion is not controlled by skip_validation" \
  'skip_validation'
assert_step_in "$SWITCH" "$SERVER_PRE_STEP" "server standby assertion compares the prepared server target tag" \
  'EXPECTED_TAG: \$\{\{ needs\.prepare\.outputs\.server_target_image_tag \}\}'
# SC2016: $ENVIRONMENT is literal workflow text.
# shellcheck disable=SC2016
assert_step_in "$SWITCH" "$SERVER_PRE_STEP" "server standby assertion calls the helper for server standby" \
  'assert-blue-green-image-tag\.sh "\$ENVIRONMENT" server standby "\$EXPECTED_TAG"'

assert_step_not_in "$SWITCH" "$SERVER_POST_STEP" "server active assertion is not limited to deploy actions" \
  "inputs\\.action == 'deploy'"
assert_step_in "$SWITCH" "$SERVER_POST_STEP" "server active assertion skips dry-run only" \
  "inputs\\.dry_run != true"
assert_step_not_in "$SWITCH" "$SERVER_POST_STEP" "server active assertion is not controlled by skip_validation" \
  'skip_validation'
assert_step_in "$SWITCH" "$SERVER_POST_STEP" "server active assertion compares the prepared server target tag" \
  'EXPECTED_TAG: \$\{\{ needs\.prepare\.outputs\.server_target_image_tag \}\}'
# SC2016: $ENVIRONMENT is literal workflow text.
# shellcheck disable=SC2016
assert_step_in "$SWITCH" "$SERVER_POST_STEP" "server active assertion calls the helper for server active" \
  'assert-blue-green-image-tag\.sh "\$ENVIRONMENT" server active "\$EXPECTED_TAG"'

assert_step_not_in "$SWITCH" "$AC_PRE_STEP" "AC standby assertion is not limited to deploy actions" \
  "inputs\\.action == 'deploy'"
assert_step_in "$SWITCH" "$AC_PRE_STEP" "AC standby assertion skips dry-run only" \
  "inputs\\.dry_run != true"
assert_step_not_in "$SWITCH" "$AC_PRE_STEP" "AC standby assertion is not controlled by skip_validation" \
  'skip_validation'
assert_step_in "$SWITCH" "$AC_PRE_STEP" "AC standby assertion compares the prepared AC target tag" \
  'EXPECTED_TAG: \$\{\{ needs\.prepare\.outputs\.ac_target_image_tag \}\}'
# SC2016: $ENVIRONMENT is literal workflow text.
# shellcheck disable=SC2016
assert_step_in "$SWITCH" "$AC_PRE_STEP" "AC standby assertion calls the helper for ac standby" \
  'assert-blue-green-image-tag\.sh "\$ENVIRONMENT" ac standby "\$EXPECTED_TAG"'

assert_step_not_in "$SWITCH" "$AC_POST_STEP" "AC active assertion is not limited to deploy actions" \
  "inputs\\.action == 'deploy'"
assert_step_in "$SWITCH" "$AC_POST_STEP" "AC active assertion skips dry-run only" \
  "inputs\\.dry_run != true"
assert_step_not_in "$SWITCH" "$AC_POST_STEP" "AC active assertion is not controlled by skip_validation" \
  'skip_validation'
assert_step_in "$SWITCH" "$AC_POST_STEP" "AC active assertion compares the prepared AC target tag" \
  'EXPECTED_TAG: \$\{\{ needs\.prepare\.outputs\.ac_target_image_tag \}\}'
# SC2016: $ENVIRONMENT is literal workflow text.
# shellcheck disable=SC2016
assert_step_in "$SWITCH" "$AC_POST_STEP" "AC active assertion calls the helper for ac active" \
  'assert-blue-green-image-tag\.sh "\$ENVIRONMENT" ac active "\$EXPECTED_TAG"'

if [[ -f "$HELPER" ]]; then
  assert_in "$(<"$HELPER")" "blue/green tag helper resolves live active slots" \
    'resolve-active-image-tag\.sh'
  # SC2016: $RESOLVER/$ENVIRONMENT/$COMPONENT/$SLOT are literal script text.
  # shellcheck disable=SC2016
  assert_in "$(<"$HELPER")" "blue/green tag helper delegates active or standby slot to resolver" \
    '"\$RESOLVER" "\$ENVIRONMENT" "\$COMPONENT" "\$SLOT"'
  assert_in "$(<"$HELPER")" "blue/green tag helper fails stale app bytes" \
    'Refusing to report blue/green success against stale app bytes'
  assert_in "$(<"$HELPER")" "blue/green tag helper preserves half-switched remediation guidance" \
    'Traffic may already be switched'
  assert_in "$(<"$HELPER")" "blue/green tag helper preserves pre-switch remediation guidance" \
    'Traffic has not been switched by this assertion'
  assert_in "$(<"$HELPER")" "blue/green tag helper names the rerun component" \
    'component=\$\{COMPONENT\}'
fi

# SC2016: $ENVIRONMENT is literal workflow text.
# shellcheck disable=SC2016
assert_not_in "$SWITCH" "active-tag assertions do not duplicate resolver bodies in workflow" \
  'resolve-active-image-tag\.sh "\$ENVIRONMENT"'

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
