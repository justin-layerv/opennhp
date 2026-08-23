#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/classify-durable-aop-cutover-lock-release.sh"
IMAGE=0123456789012345678901234567890123456789
OWNER="nhp:123:durable-aop-cutover:${IMAGE}"

state() {
  jq -cn --arg image "$IMAGE" --arg phase "$1" \
    --arg owner "$OWNER" \
    '{schema:2,image:$image,orchestrator_sha:$image,lock_owner:$owner,phase:$phase}'
}

ordinary_lock=$(jq -cn --arg owner "$OWNER" '{owner:$owner,created_at:1,expires_at:2}')
hard_lock=$(jq -cn --arg owner "$OWNER" --arg image "$IMAGE" \
  '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,
    orchestrator_sha:$image,created_at:1,expires_at:253402300799}')

expect() {
  local want=$1 result=$2 value=$3 lock=${4:-$ordinary_lock} got
  got=$("$SCRIPT" "$result" "$IMAGE" "$IMAGE" "$OWNER" "$value" "$lock")
  [[ "$got" == "$want" ]] || {
    echo "result=$result state=$value: got $got, want $want" >&2
    exit 1
  }
}

expect true failure ''
expect false failure '' "$hard_lock"
expect true failure "$(state prepared)"
expect false failure "$(state prepared)" "$hard_lock"
expect true success "$(state complete)"

for phase in ac_terminating ponr ac_switched cell0_switched cell1_switched old_servers_terminated validated; do
  expect false failure "$(state "$phase")"
done

for bad in \
  '{"schema":1,"image":"wrong","phase":"complete"}' \
  "$(jq -cn --arg image "$IMAGE" '{schema:1,image:$image,phase:"unknown"}')"; do
  if "$SCRIPT" failure "$IMAGE" "$IMAGE" "$OWNER" "$bad" "$ordinary_lock" >/dev/null 2>&1; then
    echo "malformed state unexpectedly released the lock: $bad" >&2
    exit 1
  fi
done

if "$SCRIPT" success "$IMAGE" "$IMAGE" "$OWNER" '' "$ordinary_lock" >/dev/null 2>&1; then
  echo "success without a durable COMPLETE record unexpectedly released the lock" >&2
  exit 1
fi
if "$SCRIPT" success "$IMAGE" "$IMAGE" "$OWNER" "$(state prepared)" "$ordinary_lock" >/dev/null 2>&1; then
  echo "success at PREPARED unexpectedly released the lock" >&2
  exit 1
fi

echo "classify-durable-aop-cutover-lock-release: all tests passed"
