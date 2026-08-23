#!/usr/bin/env bash
# Decide whether the immutable parent run must skip cell1 prewarm and resume
# its already-started cutover. This is pure classification: the caller
# strong-reads STATE and the shared lock immediately before invoking it.

set -euo pipefail

if [[ $# -ne 5 || ! "$1" =~ ^[0-9a-f]{40}$ || ! "$2" =~ ^[0-9a-f]{40}$ || -z "$3" ]]; then
  echo "usage: $0 <image-sha> <orchestrator-sha> <owner> <state-or-empty> <lock-or-empty>" >&2
  exit 2
fi
image=$1 orchestrator=$2 owner=$3 state=$4 lock=$5
[[ "$image" == "$orchestrator" ]] || {
  echo "cutover image and orchestrator differ" >&2
  exit 1
}

ordinary_lock=false
hard_lock=false
if [[ -n "$lock" ]]; then
  if jq -e --arg owner "$owner" '
      type == "object" and
      ((keys | sort) == ["created_at","expires_at","owner"] or
       (keys | sort) == ["created_at","expires_at","kind","owner"]) and
      .owner == $owner and
      ((.kind // "ordinary") == "ordinary") and
      (.created_at | type == "number" and . > 0 and floor == .) and
      (.expires_at | type == "number" and . > 0 and floor == .) and
      (.expires_at > .created_at)
    ' >/dev/null <<<"$lock"; then
    ordinary_lock=true
  elif jq -e --arg owner "$owner" --arg image "$image" --arg orchestrator "$orchestrator" '
      type == "object" and .schema == 1 and .kind == "durable-aop-cutover-recovery" and
      .owner == $owner and .image == $image and .orchestrator_sha == $orchestrator and
      .expires_at == 253402300799 and
      (.created_at | type == "number" and . > 0 and floor == .)
    ' >/dev/null <<<"$lock"; then
    hard_lock=true
  else
    echo "shared sandbox lock does not belong to this exact cutover run" >&2
    exit 1
  fi
fi

if [[ -z "$state" ]]; then
  if [[ "$ordinary_lock" == true ]]; then
    # Crash after the parent acquired its ordinary lock but before the cutover
    # wrote PREPARED. Re-dispatch would deadlock on our own lock; direct resume
    # revalidates all three durable prepared-slot attestations before PONR.
    printf 'true\n'
  elif [[ "$hard_lock" == true ]]; then
    echo "non-expiring recovery lock exists without its cutover state" >&2
    exit 1
  else
    printf 'false\n'
  fi
  exit 0
fi

phase=$(jq -er --arg image "$image" --arg orchestrator "$orchestrator" --arg owner "$owner" '
    select(type == "object" and .schema == 2 and .image == $image and
    .orchestrator_sha == $orchestrator and .lock_owner == $owner and
    (.phase == "prepared" or .phase == "ac_terminating" or .phase == "ponr" or
     .phase == "ac_switched" or .phase == "cell0_switched" or
     .phase == "cell1_switched" or .phase == "old_servers_terminated" or
     .phase == "validated" or .phase == "complete")) |
    .phase
  ' <<<"$state") || {
  echo "cutover state does not belong to this exact parent run" >&2
  exit 1
}

case "$phase" in
  ac_terminating|ponr|ac_switched|cell0_switched|cell1_switched|old_servers_terminated|validated)
    [[ "$hard_lock" == true ]] || {
      echo "forward-only cutover state is missing its exact non-expiring recovery lock" >&2
      exit 1
    }
    ;;
esac

# PREPARED with an absent/ordinary lock is a pre-PONR retry after a released
# failure. PREPARED with the hard lock is the harden-before-phase-write crash
# window. Every later phase is forward-only. All must bypass child prewarm,
# whose unrelated lock owner cannot enter the retained recovery lock.
printf 'true\n'
