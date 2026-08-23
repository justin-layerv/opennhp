#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/classify-durable-aop-cutover-resume.sh"
IMAGE=0123456789012345678901234567890123456789
OWNER="nhp:77:durable-aop-cutover:${IMAGE}"

state() {
  jq -cn --arg image "$IMAGE" --arg owner "$OWNER" --arg phase "$1" \
    '{schema:2,image:$image,orchestrator_sha:$image,lock_owner:$owner,phase:$phase}'
}
ordinary=$(jq -cn --arg owner "$OWNER" '{owner:$owner,created_at:1,expires_at:2}')
hard=$(jq -cn --arg owner "$OWNER" --arg image "$IMAGE" \
  '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,
    orchestrator_sha:$image,created_at:1,expires_at:253402300799}')

[[ "$($SCRIPT "$IMAGE" "$IMAGE" "$OWNER" '' '')" == false ]]
[[ "$($SCRIPT "$IMAGE" "$IMAGE" "$OWNER" '' "$ordinary")" == true ]]
[[ "$($SCRIPT "$IMAGE" "$IMAGE" "$OWNER" "$(state prepared)" '')" == true ]]
[[ "$($SCRIPT "$IMAGE" "$IMAGE" "$OWNER" "$(state prepared)" "$hard")" == true ]]
[[ "$($SCRIPT "$IMAGE" "$IMAGE" "$OWNER" "$(state ponr)" "$hard")" == true ]]
if "$SCRIPT" "$IMAGE" "$IMAGE" "$OWNER" "$(state ponr)" '' >/dev/null 2>&1; then
  echo "forward-only state without its hardened lock was accepted" >&2
  exit 1
fi

if "$SCRIPT" "$IMAGE" "$IMAGE" "$OWNER" '' "$hard" >/dev/null 2>&1; then
  echo "recovery lock without cutover state was accepted" >&2
  exit 1
fi
other=$(jq -cn '{owner:"another-run",created_at:1,expires_at:2}')
if "$SCRIPT" "$IMAGE" "$IMAGE" "$OWNER" "$(state ponr)" "$other" >/dev/null 2>&1; then
  echo "another lock owner was accepted for recovery" >&2
  exit 1
fi
bad_state=$(jq -cn --arg image "$IMAGE" --arg phase ponr \
  '{schema:2,image:$image,orchestrator_sha:$image,lock_owner:"another-run",phase:$phase}')
if "$SCRIPT" "$IMAGE" "$IMAGE" "$OWNER" "$bad_state" "$hard" >/dev/null 2>&1; then
  echo "another state owner was accepted for recovery" >&2
  exit 1
fi

echo "classify-durable-aop-cutover-resume: all tests passed"
