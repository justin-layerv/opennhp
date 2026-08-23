#!/usr/bin/env bash
# Topology-aware readiness authority for the attended durable-AOP recovery.
#
# It intentionally preserves the original cutover's real knock-readiness proof
# for cell0.  Cell1 is a server-only, non-assignable cell: it has no local AC
# fleet, and therefore can never make /health/knock-ready healthy.  For that
# one exact label, prove the reviewed replacement authority instead:
#   * the exact active ASG is fully healthy and its server is live;
#   * the strongly read public catalog row is active but not assignable; and
#   * the strongly read cell1 assignment table is physically empty.
#
# Usage is the same as verify-knock-ready.sh so this can be supplied through
# CUTOVER_VERIFY_KNOCK_READY_SCRIPT to the immutable original cutover.

set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 <asg-name> <cutover-cell0|cutover-cell1> <timeout-minutes> [check-nrestarts]" >&2
  exit 2
fi

ASG_NAME=$1
LABEL=$2
TIMEOUT_MINUTES=$3
CHECK_NRESTARTS=${4:-true}
AWS_REGION=${AWS_REGION:-us-east-2}
ORIGINAL_ROOT=${CUTOVER_ORIGINAL_SOURCE_ROOT:?CUTOVER_ORIGINAL_SOURCE_ROOT is required}
EXPECTED_CELL1_ASG=${CUTOVER_EXPECTED_CELL1_ASG:?CUTOVER_EXPECTED_CELL1_ASG is required}
EXPECTED_CELL1_COLOR=${CUTOVER_EXPECTED_CELL1_COLOR:?CUTOVER_EXPECTED_CELL1_COLOR is required}

[[ "$ASG_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$ ]] || {
  echo "cutover readiness ASG name is malformed" >&2
  exit 2
}
[[ "$TIMEOUT_MINUTES" =~ ^[1-9][0-9]*$ && "$TIMEOUT_MINUTES" -le 60 ]] || {
  echo "cutover readiness timeout must be an integer from 1 through 60 minutes" >&2
  exit 2
}
[[ "$CHECK_NRESTARTS" == true || "$CHECK_NRESTARTS" == false ]] || {
  echo "check-nrestarts must be true or false" >&2
  exit 2
}

case "$LABEL" in
  cutover-cell0)
    exec bash "$ORIGINAL_ROOT/.github/scripts/verify-knock-ready.sh" "$@"
    ;;
  cutover-cell1)
    ;;
  *)
    echo "topology-aware recovery refuses unknown readiness label '$LABEL'" >&2
    exit 2
    ;;
esac

[[ "$ASG_NAME" == "$EXPECTED_CELL1_ASG" ]] || {
  echo "cell1 readiness ASG '$ASG_NAME' differs from the exact persisted cutover ASG '$EXPECTED_CELL1_ASG'" >&2
  exit 1
}
[[ "$CHECK_NRESTARTS" == true ]] || {
  echo "cell1 recovery must retain the refreshed-fleet restart check" >&2
  exit 1
}

read_active_color() {
  aws ssm get-parameter \
    --name /sandbox-cell1/nhp/server/active-color \
    --query Parameter.Value --output text --region "$AWS_REGION"
}

read_catalog_item() {
  local response
  response=$(aws dynamodb get-item \
    --table-name layerv-nhp-sandbox-control-connector-authority \
    --key '{"pk":{"S":"REGISTRY"},"sk":{"S":"CELL#cell1"}}' \
    --consistent-read --output json --region "$AWS_REGION")
  jq -e '
      (.Item | type == "object") and
      (.Item.pk == {S:"REGISTRY"}) and
      (.Item.sk == {S:"CELL#cell1"}) and
      (.Item.cell_id == {S:"cell1"}) and
      (.Item.status == {S:"active"}) and
      (.Item.general_assignable == {BOOL:false}) and
      (.Item | has("ttl") | not)
    ' >/dev/null <<<"$response" || {
    echo "cell1 catalog authority is missing, malformed, assignable, inactive, or TTL-bearing" >&2
    return 1
  }
  jq -cS '.Item' <<<"$response"
}

assert_assignment_table_empty() {
  local response
  # No filter is used.  A single strongly consistent base-table row proves
  # non-empty, while an empty first page proves the physical table is empty.
  response=$(aws dynamodb scan \
    --table-name layerv-nhp-sandbox-cell1-cell1-ac-assignments \
    --consistent-read --limit 1 --no-paginate \
    --output json --region "$AWS_REGION")
  jq -e '
      .Count == 0 and .ScannedCount == 0 and
      ((.Items // []) | length == 0) and
      ((.LastEvaluatedKey // {}) | length == 0)
    ' >/dev/null <<<"$response" || {
    echo "cell1 assignment table is non-empty or its empty proof is malformed" >&2
    return 1
  }
}

assert_asg_capacity_healthy() {
  local response
  response=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" --output json --region "$AWS_REGION")
  jq -e --arg asg "$ASG_NAME" '
      (.AutoScalingGroups | type == "array" and length == 1) and
      (.AutoScalingGroups[0] as $g |
        ($g.AutoScalingGroupName == $asg) and
        ($g.MinSize | type == "number" and . > 0 and floor == .) and
        ($g.DesiredCapacity | type == "number" and . > 0 and floor == .) and
        ($g.MaxSize | type == "number" and . >= $g.DesiredCapacity and floor == .) and
        ($g.Instances | type == "array") and
        (($g.Instances | length) == $g.DesiredCapacity) and
        ($g.Instances | all(.LifecycleState == "InService" and .HealthStatus == "Healthy")))
    ' >/dev/null <<<"$response" || {
    echo "cell1 active ASG is missing, under capacity, or not fully InService/Healthy" >&2
    return 1
  }
}

before_color=$(read_active_color)
[[ "$before_color" == "$EXPECTED_CELL1_COLOR" ]] || {
  echo "cell1 active color '$before_color' differs from persisted cutover color '$EXPECTED_CELL1_COLOR'" >&2
  exit 1
}
before_catalog=$(read_catalog_item)

assert_asg_capacity_healthy
bash "$ORIGINAL_ROOT/.github/scripts/verify-asg-instances-healthy.sh" \
  "$ASG_NAME" cutover-cell1-server-live "$TIMEOUT_MINUTES" \
  'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
assert_assignment_table_empty

# Bracket the long health probe.  The shared non-expiring cutover lock fences
# workflow mutation; these exact rereads also fail closed if an operator or a
# runtime authority changed the catalog/color while recovery was proving it.
after_catalog=$(read_catalog_item)
after_color=$(read_active_color)
[[ "$after_catalog" == "$before_catalog" ]] || {
  echo "cell1 catalog authority changed during recovery readiness proof" >&2
  exit 1
}
[[ "$after_color" == "$before_color" ]] || {
  echo "cell1 active color changed during recovery readiness proof" >&2
  exit 1
}

echo "[cutover-cell1] exact server-only recovery authority is healthy, active/non-assignable, and assignment-empty"
