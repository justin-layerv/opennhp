#!/usr/bin/env bash
# Acquire the shared sandbox mutation lock for the immutable parent run. Exact
# re-entry is allowed for the same run/source after a crash; every other owner
# sees the recovery record as a non-expiring ordinary lock.

set -euo pipefail

if [[ $# -ne 4 || ! "$4" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <lock-param> <owner> <image-sha> <orchestrator-sha>" >&2
  exit 2
fi
param=$1 owner=$2 image=$3 orchestrator=$4
[[ "$image" =~ ^[0-9a-f]{40}$ && -n "$owner" ]] || exit 2
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
current=$(bash "$ROOT/scripts/ssm-read-optional.sh" "$param")
if [[ -n "$current" ]]; then
  if jq -e --arg owner "$owner" --arg image "$image" --arg orchestrator "$orchestrator" '
      type == "object" and .owner == $owner and
      ((.kind == "durable-aop-cutover-recovery" and .schema == 1 and
        .image == $image and .orchestrator_sha == $orchestrator and
        .expires_at == 253402300799) or
       ((.kind // "ordinary") == "ordinary" and
        (.created_at | type == "number") and (.expires_at | type == "number")))
    ' >/dev/null <<<"$current"; then
    echo "Re-entered exact durable AOP cutover lock: $param owner=$owner"
    exit 0
  fi
fi
AWS_REGION=${AWS_REGION:?} bash "$ROOT/.github/scripts/ssm-live-env-lock.sh" \
  acquire "$param" "$owner" 14400 7200
