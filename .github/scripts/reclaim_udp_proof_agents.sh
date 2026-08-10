#!/usr/bin/env bash
# Reclaim the Connector Authority rows a UDP proof run binds.
#
# WHY THIS EXISTS
# Each proof run enrolls a connector, which binds three rows under the proof
# owner's partition and increments a counter:
#
#   pk=OWNER#<sha256>  sk=AGENT#<agent-id>
#   pk=OWNER#<sha256>  sk=DEVICE_CREDENTIAL#<...>
#   pk=OWNER#<sha256>  sk=COMPLETION#<...>
#   pk=OWNER#<sha256>  sk=META            assignment_count += 1
#
# Nothing released any of it. The cap is 25 per owner, so the proof bricked
# itself every 25 runs with
#
#   errCode="52112" ... agent assignment quota exceeded
#
# and the connector leg could not get past enrollment.
#
# THE COUNTER IS THE QUOTA -- DELETING ROWS IS NOT ENOUGH.
# The Authority reads META.assignment_count, not a live count of AGENT# rows.
# Observed 2026-08-10: all 25 AGENT# rows were deleted and registration was
# STILL denied nine minutes later, because assignment_count still read 25.
# qurl-service increments it (activationOwnerCountUpdate, SET assignment_count
# = :next on PlacementNew) and has no decrement path anywhere, so it only ever
# rises. Reclaim MUST reconcile the counter, and this script fails loudly if it
# cannot.
#
# SCOPING
# Deletes only rows under the proof owner's partition, and never META itself.
# A real tenant's rows live under a different owner hash and are untouched.
set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${PROOF_AUTHORITY_TABLE:?PROOF_AUTHORITY_TABLE is required}"
: "${PROOF_AGENT_OWNER_PK:?PROOF_AGENT_OWNER_PK is required}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

owner="$PROOF_AGENT_OWNER_PK"
table="$PROOF_AUTHORITY_TABLE"

# A FAILED query must never look like an empty partition. The whole reconcile
# is derived from this listing, so swallowing an error here would let a
# transient throttle produce remaining_agents=0 against a live observed=25 and
# drive a confident "SET assignment_count = 0" while 25 agents still exist. The
# condition-expression cannot catch that -- it only guards a concurrent WRITER,
# not a wrong input. Silent-but-wrong is precisely what this script exists to
# stop, so a listing failure is fatal.
query_sks() {
  local raw rc
  raw="$(
    aws dynamodb query \
      --table-name "$table" \
      --key-condition-expression 'pk = :o' \
      --expression-attribute-values "{\":o\":{\"S\":\"$owner\"}}" \
      --consistent-read \
      --region "$AWS_REGION" \
      --query 'Items[].sk.S' \
      --output text 2>"$work_dir/query.err"
  )" && rc=0 || rc=$?
  if [ "${rc:-0}" != "0" ]; then
    echo "::error::could not list rows under ${owner}; refusing to reconcile from an unknown state" >&2
    cat "$work_dir/query.err" >&2
    return 1
  fi
  printf '%s' "$raw" | tr '\t' '\n' | grep -v '^$' || true
}

# META is the counter row and must survive; the quota is reconciled on it below.
reclaimable() { grep -vE '^META$' || true; }

# jq -Rn does the JSON escaping; the previous form shelled out to python3 once
# per row purely for json.dumps, adding a hard interpreter dependency to a
# script that otherwise needs only the AWS CLI and jq.
delete_rows() {
  local sk key
  while IFS= read -r sk; do
    [ -z "$sk" ] && continue
    key="$(jq -cn --arg o "$owner" --arg s "$sk" \
      '{pk:{S:$o},sk:{S:$s}}')"
    aws dynamodb delete-item \
      --table-name "$table" \
      --key "$key" \
      --region "$AWS_REGION" >/dev/null
  done < "$1"
}

if ! query_sks > "$work_dir/all-sks.txt"; then exit 1; fi
reclaimable < "$work_dir/all-sks.txt" > "$work_dir/sks.txt"
count="$(wc -l < "$work_dir/sks.txt" | tr -d ' ')"
echo "reclaiming ${count} run-bound rows under ${owner}"
[ "$count" != "0" ] && delete_rows "$work_dir/sks.txt"

# Reconcile the counter to the number of AGENT# rows that actually remain.
# Conditional on the value just read so a concurrent activation is never
# clobbered -- it fails, and the next run reclaims instead.
if ! query_sks > "$work_dir/after.txt"; then exit 1; fi
remaining_agents="$(grep -c '^AGENT#' < "$work_dir/after.txt" || true)"
observed="$(
  aws dynamodb get-item \
    --table-name "$table" \
    --key "{\"pk\":{\"S\":\"$owner\"},\"sk\":{\"S\":\"META\"}}" \
    --consistent-read \
    --region "$AWS_REGION" \
    --query 'Item.assignment_count.N' --output text 2>/dev/null || echo "None"
)"

if [ "$observed" = "None" ] || [ -z "$observed" ]; then
  echo "no META assignment_count for ${owner}; nothing to reconcile"
  exit 0
fi

if [ "$observed" = "$remaining_agents" ]; then
  echo "assignment_count already reconciled at ${observed}"
  exit 0
fi

if ! aws dynamodb update-item \
  --table-name "$table" \
  --key "{\"pk\":{\"S\":\"$owner\"},\"sk\":{\"S\":\"META\"}}" \
  --update-expression 'SET assignment_count = :actual' \
  --condition-expression 'assignment_count = :observed' \
  --expression-attribute-values \
    "{\":actual\":{\"N\":\"${remaining_agents}\"},\":observed\":{\"N\":\"${observed}\"}}" \
  --region "$AWS_REGION" >/dev/null 2>"$work_dir/err"; then
  if grep -q 'ConditionalCheckFailedException' "$work_dir/err"; then
    # Someone activated between the read and the write. Leave it; the next run
    # reconciles. Silence here would let the counter drift up forever again.
    echo "::warning::assignment_count moved during reclaim; leaving it for the next run"
    exit 0
  fi
  echo "::error::could not reconcile assignment_count for ${owner}"
  cat "$work_dir/err" >&2
  exit 1
fi

echo "assignment_count reconciled ${observed} -> ${remaining_agents}"
