#!/usr/bin/env bash
# Classify whether the dedicated durable-AOP cutover may release the shared
# sandbox live-environment lock. No state and PREPARED precede every destructive
# call; AC_TERMINATING and every later incomplete phase retain the lock
# fail-closed. COMPLETE is terminal only for the exact image recorded by this
# run (the workflow also rechecks the irreversible profile marker).

set -euo pipefail

if [[ $# -ne 6 || ! "$2" =~ ^[0-9a-f]{40}$ || ! "$3" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <cutover-result> <image> <orchestrator-sha> <owner> <state-json-or-empty> <lock-json-or-empty>" >&2
  exit 2
fi

cutover_result=$1
image_tag=$2
orchestrator=$3
owner=$4
state=$5
lock=$6

hard=false
if [[ -n "$lock" ]]; then
  if jq -e --arg owner "$owner" --arg image "$image_tag" --arg orchestrator "$orchestrator" '
      type == "object" and .schema == 1 and .kind == "durable-aop-cutover-recovery" and
      .owner == $owner and .image == $image and .orchestrator_sha == $orchestrator and
      .expires_at == 253402300799
    ' >/dev/null <<<"$lock"; then
    hard=true
  elif ! jq -e --arg owner "$owner" '
      type == "object" and .owner == $owner and
      ((.kind // "ordinary") == "ordinary") and
      (.created_at | type == "number") and (.expires_at | type == "number")
    ' >/dev/null <<<"$lock"; then
    echo "cutover lock is malformed or belongs to another owner" >&2
    exit 1
  fi
fi

if [[ -z "$state" ]]; then
  [[ "$cutover_result" != success ]] || {
    echo "successful cutover has no durable state" >&2
    exit 1
  }
  [[ "$hard" == false ]] && printf 'true\n' || printf 'false\n'
  exit 0
fi

phase=$(jq -er --arg image "$image_tag" --arg orchestrator "$orchestrator" --arg owner "$owner" '
  select(type == "object" and .schema == 2 and .image == $image and
    .orchestrator_sha == $orchestrator and .lock_owner == $owner) |
  .phase |
  select(. == "prepared" or . == "ac_terminating" or . == "ponr" or . == "ac_switched" or
         . == "cell0_switched" or . == "cell1_switched" or
         . == "old_servers_terminated" or . == "validated" or
         . == "complete")
' <<<"$state") || {
  echo "cutover state is malformed or belongs to another image" >&2
  exit 1
}

case "$phase" in
  prepared)
    [[ "$cutover_result" != success ]] || {
      echo "successful cutover stopped at pre-PONR phase=prepared" >&2
      exit 1
    }
    [[ "$hard" == false ]] && printf 'true\n' || printf 'false\n'
    ;;
  complete)
    printf 'true\n'
    ;;
  ac_terminating|ponr|ac_switched|cell0_switched|cell1_switched|old_servers_terminated|validated)
    printf 'false\n'
    ;;
esac
