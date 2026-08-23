#!/usr/bin/env bash
# Fail closed before any ordinary sandbox mutation while the one-time durable
# AOP cutover is incomplete or its non-expiring recovery lock is installed.

set -euo pipefail

AWS_REGION=${AWS_REGION:-}
: "${AWS_REGION:?AWS_REGION is required}"
STATE_PARAM=${DURABLE_AOP_STATE_PARAM:-/sandbox/nhp/cutovers/durable-aop-v1/state}
LOCK_PARAM=${QURL_LIVE_ENV_LOCK_PARAM:-/layerv-nhp-sandbox/qurl-live-env-lock}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

state=$(bash "$ROOT/scripts/ssm-read-optional.sh" "$STATE_PARAM")
floor=$(bash "$ROOT/scripts/ssm-read-optional.sh" /sandbox/nhp/minimum-protocol-profile)
if [[ -z "$state" && -z "$floor" ]]; then
  : # Canonical pre-cut state.
elif [[ -n "$state" && "$floor" == durable-aop-v1 ]]; then
  phase=$(jq -er '
    select(type == "object" and .schema == 2 and
      (.image | type == "string" and test("^[0-9a-f]{40}$")) and
      .orchestrator_sha == .image and (.lock_owner | type == "string" and length > 0)) |
    .phase | select(. == "prepared" or . == "ac_terminating" or . == "ponr" or
      . == "ac_switched" or . == "cell0_switched" or . == "cell1_switched" or
      . == "old_servers_terminated" or . == "validated" or . == "complete")
  ' <<<"$state") || { echo "durable AOP cutover state is malformed" >&2; exit 1; }
  [[ "$phase" == complete ]] || {
    echo "durable AOP cutover is incomplete at phase=$phase; ordinary sandbox mutation denied" >&2
    exit 1
  }
else
  echo "durable AOP cutover state/profile marker is a noncanonical half-state" >&2
  exit 1
fi

lock=$(bash "$ROOT/scripts/ssm-read-optional.sh" "$LOCK_PARAM")
if [[ -n "$lock" ]]; then
  if jq -e '
      type == "object" and .schema == 1 and .kind == "durable-aop-cutover-recovery"
    ' >/dev/null <<<"$lock" 2>/dev/null; then
    echo "durable AOP recovery lock is installed; ordinary sandbox mutation denied" >&2
    exit 1
  fi
  jq -e '
    type == "object" and
    ((keys | sort) == ["created_at","expires_at","owner"] or
     (keys | sort) == ["created_at","expires_at","kind","owner"]) and
    ((.kind // "ordinary") == "ordinary") and
    (.owner | type == "string" and length > 0) and
    (.created_at | type == "number" and . > 0 and floor == .) and
    (.expires_at | type == "number" and . > 0 and floor == .) and
    (.expires_at > .created_at)
  ' >/dev/null <<<"$lock" 2>/dev/null || {
    echo "shared sandbox lock is malformed or has an unknown kind" >&2
    exit 1
  }
fi
