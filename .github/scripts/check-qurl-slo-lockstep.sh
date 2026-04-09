#!/bin/bash
# check-qurl-slo-lockstep.sh
#
# Asserts that the qurl-api SLO target is consistent between two
# independently-edited files:
#
#   1. terraform/variables.tf — `qurl_alerts_slo_target_percent` default
#      (consumed by terraform/modules/grafana-dashboards/alerts.tf as the
#      burn-rate denominator).
#   2. terraform/modules/grafana-dashboards/dashboards/qurl-operations.json
#      — `slo_target` template variable's `current.value` (consumed by
#      every burn-rate panel and the budget-remaining stat).
#
# Why this exists
# ===============
#
# A typo in either value silently shifts the burn-rate denominator by
# orders of magnitude — a 99.99% target produces a 0.0001 budget; a
# 99.9% target produces 0.001 (10× looser); a 99% target produces 0.01
# (100× looser). The same burn-rate threshold (e.g., > 6) means very
# different things at different SLOs, and a panel that says "burn rate
# 5" can be either "fine" or "screaming" depending on which denominator
# Grafana used.
#
# A code comment in alerts.tf says "must match the dashboard template
# variable's default" but nothing enforces it. Comments rot. The
# 2026-03-24 incident's root cause was a comment-enforced contract
# between the qurl-service code and the terraform DynamoDB schema; this
# script exists so we don't repeat that pattern in the alerting layer.
#
# Behavior
# ========
#
# Exit 0: values match.
# Exit 1: values differ — prints both values and which file each came
#         from. The intended fix is to edit both files to the same value.
# Exit 2: parsing failure — one of the values couldn't be located.
#         Usually means somebody renamed a variable or restructured the
#         dashboard JSON; update this script to match.
#
# Tooling
# =======
#
# Requires `jq` (for the dashboard JSON) and `awk` (for the terraform
# variable default). Both are present on every GitHub Actions Linux
# runner image and on every developer machine in the repo's standard
# tooling baseline.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TF_VARS="${REPO_ROOT}/terraform/variables.tf"
DASHBOARD_JSON="${REPO_ROOT}/terraform/modules/grafana-dashboards/dashboards/qurl-operations.json"

if [[ ! -f "$TF_VARS" ]]; then
  echo "::error::expected terraform/variables.tf at $TF_VARS but it does not exist" >&2
  exit 2
fi
if [[ ! -f "$DASHBOARD_JSON" ]]; then
  echo "::error::expected dashboard JSON at $DASHBOARD_JSON but it does not exist" >&2
  exit 2
fi

# Extract the default of `qurl_alerts_slo_target_percent` from variables.tf.
# The awk program tracks the variable block and prints the value of the
# `default` line. Uses portable substitution (no gawk-only 3-arg match)
# so it runs on macOS BSD awk and Linux gawk identically.
TF_VALUE="$(awk '
  /^variable "qurl_alerts_slo_target_percent"/ { in_block = 1; next }
  in_block && /^}/                              { in_block = 0; next }
  in_block && /default[[:space:]]*=/ {
    sub(/^.*default[[:space:]]*=[[:space:]]*/, "")
    sub(/[[:space:]].*$/, "")
    print
    exit
  }
' "$TF_VARS")"

if [[ -z "$TF_VALUE" ]]; then
  echo "::error::could not find default value of qurl_alerts_slo_target_percent in $TF_VARS" >&2
  echo "If the variable was renamed or moved, update .github/scripts/check-qurl-slo-lockstep.sh." >&2
  exit 2
fi

# Extract slo_target.current.value from the dashboard JSON. The variable
# is in the templating.list array; we filter by name then read .current.value.
# Dashboard JSON stores the value as a string, hence tonumber for the compare.
JQ_ERR=""
DASHBOARD_VALUE="$(jq -r '
  (.templating.list // [])
  | map(select(.name == "slo_target"))
  | first
  | .current.value
' "$DASHBOARD_JSON" 2>&1)" || JQ_ERR="$?"

if [[ -n "$JQ_ERR" ]]; then
  echo "::error::jq failed to parse $DASHBOARD_JSON (exit $JQ_ERR): $DASHBOARD_VALUE" >&2
  echo "If the dashboard JSON structure changed, update .github/scripts/check-qurl-slo-lockstep.sh." >&2
  exit 2
fi

if [[ -z "$DASHBOARD_VALUE" || "$DASHBOARD_VALUE" == "null" ]]; then
  echo "::error::could not find slo_target.current.value in $DASHBOARD_JSON" >&2
  echo "If the dashboard JSON structure changed, update .github/scripts/check-qurl-slo-lockstep.sh." >&2
  exit 2
fi

# Numeric comparison. Both values are floats; bash arithmetic only handles
# integers, so use awk for the comparison. Tolerance is exact equality —
# the SLO target should be edited deliberately, not approximated.
if awk -v a="$TF_VALUE" -v b="$DASHBOARD_VALUE" 'BEGIN { exit (a == b) ? 0 : 1 }'; then
  echo "qurl SLO target lockstep check: OK ($TF_VALUE == $DASHBOARD_VALUE)"
  exit 0
fi

cat >&2 <<EOF
::error::qurl SLO target mismatch — alerts.tf and the operations dashboard would compute different burn-rate denominators

  terraform/variables.tf::qurl_alerts_slo_target_percent default = $TF_VALUE
  qurl-operations.json::slo_target template variable        = $DASHBOARD_VALUE

These two values feed the same burn-rate computation. A mismatch means
the alert thresholds and the dashboard panels use different SLO targets
and will disagree about whether the service is healthy.

Fix: edit both files to the same value, then re-run this check.

Background: the lockstep contract used to be enforced by a code comment.
Comments don't run in CI. See the 2026-03-24 GSI incident for the same
trust-the-comment failure mode in a different layer.
EOF
exit 1
