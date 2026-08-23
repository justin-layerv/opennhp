#!/usr/bin/env bash
# Execute/resume the one-time cutover from the immutable parent workflow and
# release the shared lock only before destructive intent or after COMPLETE.

set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <exact-image/source-sha>" >&2
  exit 2
fi
image=$1
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
[[ "$GITHUB_SHA" == "$image" ]] || {
  echo "cutover image/source $image differs from immutable orchestrator $GITHUB_SHA" >&2
  exit 1
}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
param=/layerv-nhp-sandbox/qurl-live-env-lock
owner="nhp:${GITHUB_RUN_ID}:durable-aop-cutover:${GITHUB_SHA}"
export CUTOVER_LOCK_PARAM=$param CUTOVER_LOCK_OWNER=$owner CUTOVER_ORCHESTRATOR_SHA=$GITHUB_SHA

bash "$ROOT/.github/scripts/acquire-durable-aop-cutover-lock.sh" \
  "$param" "$owner" "$image" "$GITHUB_SHA"

result=failure
rc=1
for attempt in 1 2 3 4 5; do
  if bash "$ROOT/.github/scripts/durable-aop-cutover.sh" "$image"; then
    result=success
    rc=0
    break
  fi
  state=$(bash "$ROOT/scripts/ssm-read-optional.sh" /sandbox/nhp/cutovers/durable-aop-v1/state)
  phase=$(jq -r '.phase // empty' <<<"${state:-{}}")
  case "$phase" in
    ac_terminating|ponr|ac_switched|cell0_switched|cell1_switched|old_servers_terminated|validated)
      echo "Forward-only cutover attempt $attempt failed at phase=$phase; retrying exact source"
      ;;
    *) break ;;
  esac
done

state=$(bash "$ROOT/scripts/ssm-read-optional.sh" /sandbox/nhp/cutovers/durable-aop-v1/state)
lock=$(bash "$ROOT/scripts/ssm-read-optional.sh" "$param")
safe=$(bash "$ROOT/.github/scripts/classify-durable-aop-cutover-lock-release.sh" \
  "$result" "$image" "$GITHUB_SHA" "$owner" "$state" "$lock")
if [[ "$safe" == true ]]; then
  AWS_REGION=${AWS_REGION:?} bash "$ROOT/.github/scripts/ssm-live-env-lock.sh" \
    release "$param" "$owner" 14400 7200
else
  echo "Retaining non-expiring durable AOP recovery lock for attended rerun" >&2
fi
exit "$rc"
