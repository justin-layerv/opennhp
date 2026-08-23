#!/usr/bin/env bash
# Fail-closed terminal proof for the repaired cell0 durable-AOP runtime.
# It brackets the exact TARGET/OWNER inventory across a stability window,
# requires every physical AC target READY with pending_count=0, proves the real
# knock path, and strongly validates the fresh assignable cell0 assignment.

set -euo pipefail

AWS_REGION=${AWS_REGION:-us-east-2}
AC_ID=${CUTOVER_AC_ID:-layerv-ac-tf}
CELL_ID=cell0
ASG=${CUTOVER_EXPECTED_CELL0_ASG:?CUTOVER_EXPECTED_CELL0_ASG is required}
STABILITY_SECONDS=${CUTOVER_STABILITY_SECONDS:-30}
ASSIGNMENT_MAX_AGE_SECONDS=${CUTOVER_ASSIGNMENT_MAX_AGE_SECONDS:-300}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ORIGINAL_ROOT=${CUTOVER_ORIGINAL_SOURCE_ROOT:-$ROOT}
SESSION_TABLE=layerv-nhp-sandbox-cell0-nhp-session-control
ASSIGNMENT_TABLE=layerv-nhp-sandbox-cell0-ac-assignments
CATALOG_TABLE=layerv-nhp-sandbox-control-connector-authority

[[ "$STABILITY_SECONDS" =~ ^[1-9][0-9]*$ && "$STABILITY_SECONDS" -le 300 ]] || { echo "stability window is invalid" >&2; exit 2; }
[[ "$ASSIGNMENT_MAX_AGE_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo "assignment max age is invalid" >&2; exit 2; }

asg_json=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$ASG" --output json --region "$AWS_REGION")
SERVER_COUNT=$(jq -er --arg asg "$ASG" '
  .AutoScalingGroups as $groups |
  ($groups | type == "array" and length == 1) and
  ($groups[0] as $g | $g.AutoScalingGroupName == $asg and
   ($g.DesiredCapacity | type == "number" and . > 0 and floor == .) and
   ($g.Instances | length) == $g.DesiredCapacity and
   ($g.Instances | all(.LifecycleState == "InService" and .HealthStatus == "Healthy"))) |
  $groups[0].DesiredCapacity
' <<<"$asg_json") || { echo "cell0 server ASG is not fully healthy" >&2; exit 1; }
SERVER_INSTANCE_IDS=$(jq -ce '
  [.AutoScalingGroups[0].Instances[].InstanceId] |
  select(length > 0 and (all(type == "string" and test("^i-[0-9A-Za-z-]+$"))) and
         (unique | length) == length) | sort
' <<<"$asg_json") || { echo "cell0 server ASG has malformed or duplicate instance identities" >&2; exit 1; }

ac_asg=$(aws ssm get-parameter --name /sandbox/nhp/ac/active-color --query Parameter.Value --output text --region "$AWS_REGION")
if [[ "$ac_asg" == green ]]; then ac_asg_param=/sandbox/nhp/ac/green-asg-name; else ac_asg_param=/sandbox/nhp/ac/asg-name; fi
ac_asg=$(aws ssm get-parameter --name "$ac_asg_param" --query Parameter.Value --output text --region "$AWS_REGION")
ac_json=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$ac_asg" --output json --region "$AWS_REGION")
AC_COUNT=$(jq -er '
  .AutoScalingGroups as $groups |
  ($groups | type == "array" and length == 1) and
  ($groups[0] as $g | ($g.DesiredCapacity | type == "number" and . > 0 and floor == .) and
   ($g.Instances | length) == $g.DesiredCapacity and
   ($g.Instances | all(.LifecycleState == "InService" and .HealthStatus == "Healthy"))) |
  $groups[0].DesiredCapacity
' <<<"$ac_json") || { echo "active AC ASG is not fully healthy" >&2; exit 1; }

target_pk="AC#$(printf '%s' "$AC_ID" | sha256sum | awk '{print $1}')"

owner_pk() {
  printf 'v1\0%s\0%s\0%s' "$CELL_ID" "$AC_ID" "$1" | sha256sum | awk '{print "TARGETWORK#" $1}'
}

read_inventory() {
  local query targets owners='[]' public_key pk owner
  query=$(aws dynamodb query --table-name "$SESSION_TABLE" --consistent-read \
    --key-condition-expression 'pk = :pk' \
    --expression-attribute-values "{\":pk\":{\"S\":\"$target_pk\"}}" \
    --output json --region "$AWS_REGION")
  targets=$(jq -ce --arg pk "$target_pk" --arg ac "$AC_ID" --arg cell "$CELL_ID" --argjson count "$AC_COUNT" '
    .Items as $items |
    if ((.LastEvaluatedKey == null or (.LastEvaluatedKey | length == 0)) and
    ($items | type == "array") and
    ([$items[] | select(.sk.S == "AUTHORITY" and .kind.S == "authority" and
       .schema_version.N == "1" and .pk.S == $pk and .ac_id.S == $ac and
       .control_cell_id.S == $cell and (.version.N | tonumber) > 0 and
       (.active_target_count.N | tonumber) == $count and
       (.created_at_ms.N | tonumber) > 0 and
       (.updated_at_ms.N | tonumber) >= (.created_at_ms.N | tonumber) and
       (. | has("ttl") | not))] | length == 1) and
    ([$items[] | select(.kind.S == "target")] | length == $count) and
    ($items | length) == ($count + 1) and
    ([$items[] | select(.kind.S == "target") | . as $t |
      ($t.pk.S == $pk and $t.schema_version.N == "2" and $t.ac_id.S == $ac and
       $t.control_cell_id.S == $cell and $t.state.S == "active" and
       $t.counted_active_slot.BOOL == true and ($t.public_key.S | length > 0) and
       ($t.boot_id.S | length > 0) and ($t.flush_generation.N | tonumber) > 0 and
       ($t.version.N | tonumber) > 0 and ($t.authority_version.N | tonumber) > 0 and
       ($t.activated_control_version.N | tonumber) > 0 and
       $t.ready_control_version.N == $t.activated_control_version.N and
       ($t.aak_enqueued_at_ms.N | tonumber) >= ($t.prepared_at_ms.N | tonumber) and
      ($t.aak_transaction_id.N | tonumber) > 0 and ($t | has("ttl") | not)) |
      select(.) | $t] | length == $count) and
    ([$items[] | select(.kind.S == "target") | .public_key.S] | unique | length == $count))
    then [$items[] | select(.kind.S == "target")] else empty end
  ' <<<"$query") || { echo "cell0 target partition is not an exact all-READY inventory" >&2; return 1; }

  while IFS= read -r public_key; do
    pk=$(owner_pk "$public_key")
    owner=$(aws dynamodb get-item --table-name "$SESSION_TABLE" --consistent-read \
      --key "{\"pk\":{\"S\":\"$pk\"},\"sk\":{\"S\":\"DIRECTORY\"}}" \
      --output json --region "$AWS_REGION")
    owner=$(jq -ce --arg pk "$pk" --arg ac "$AC_ID" --arg cell "$CELL_ID" --arg key "$public_key" '
      .Item as $o | select(
        ($o | type == "object") and $o.pk.S == $pk and $o.sk.S == "DIRECTORY" and
        $o.kind.S == "target_work_directory" and $o.schema_version.N == "1" and
        $o.cell_id.S == $cell and $o.ac_id.S == $ac and $o.public_key.S == $key and
        $o.phase.S == "ready" and $o.pending_count.N == "0" and
        ($o.task_count.N | tonumber) >= 0 and ($o.task_count.N | tonumber) <= 1025 and
        ($o.lifecycle_version.N | tonumber) > 0 and ($o.work_version.N | tonumber) > 0 and
        ($o.flush_generation.N | tonumber) > 0 and ($o.target_version.N | tonumber) > 0 and
        ($o.target_authority_version.N | tonumber) > 0 and
        $o.target_counted_active_slot.BOOL == true and
        ($o.activated_control_version.N | tonumber) > 0 and
        $o.ready_control_version.N == $o.activated_control_version.N and
        ($o.aak_enqueued_at_ms.N | tonumber) > 0 and ($o.aak_transaction_id.N | tonumber) > 0 and
        ($o | has("ttl") | not)
      ) | $o
    ' <<<"$owner") || { echo "cell0 owner for public key is not exact READY/pending0" >&2; return 1; }
    # Cross-bind every target lifecycle/audit field that OWNER duplicates.
    jq -e --arg key "$public_key" --argjson owner "$owner" '
      map(select(.public_key.S == $key))[0] as $t |
      $owner.boot_id.S == $t.boot_id.S and
      $owner.flush_generation.N == $t.flush_generation.N and
      $owner.target_version.N == $t.version.N and
      $owner.target_authority_version.N == $t.authority_version.N and
      $owner.activated_control_version.N == $t.activated_control_version.N and
      $owner.ready_control_version.N == $t.ready_control_version.N and
      $owner.aak_enqueued_at_ms.N == $t.aak_enqueued_at_ms.N and
      $owner.aak_transaction_id.N == $t.aak_transaction_id.N and
      $owner.target_created_at_ms.N == $t.created_at_ms.N and
      $owner.target_prepared_at_ms.N == $t.prepared_at_ms.N and
      $owner.target_updated_at_ms.N == $t.updated_at_ms.N
    ' >/dev/null <<<"$targets" || { echo "cell0 target/owner lifecycle authority is torn" >&2; return 1; }
    owners=$(jq -c --argjson row "$owner" '. + [$row]' <<<"$owners")
  done < <(jq -r '.[].public_key.S' <<<"$targets" | sort)
  jq -cS --argjson targets "$targets" --argjson owners "$owners" '{targets:$targets,owners:$owners}'
}

read_catalog() {
  aws dynamodb get-item --table-name "$CATALOG_TABLE" --consistent-read \
    --key '{"pk":{"S":"REGISTRY"},"sk":{"S":"CELL#cell0"}}' --output json --region "$AWS_REGION" |
    jq -ce '.Item as $i | select(
      ($i | type == "object") and $i.pk.S == "REGISTRY" and
      $i.sk.S == "CELL#cell0" and $i.cell_id.S == "cell0" and $i.status.S == "active" and
      ($i | has("general_assignable") | not) and ($i | has("ttl") | not)
    ) | $i'
}

read_assignment() {
  local now min_seen max_seen min_ttl max_ttl
  now=$(date -u +%s)
  min_seen=$((now - ASSIGNMENT_MAX_AGE_SECONDS))
  max_seen=$((now + 60))
  # Production writes assignment TTL as last_seen + 1,800 seconds.  Allow one
  # second for its two adjacent time.Now calls, but reject a synthetic far-
  # future row that could otherwise satisfy freshness forever.
  min_ttl=1799
  max_ttl=1801
  aws dynamodb get-item --table-name "$ASSIGNMENT_TABLE" --consistent-read \
    --key "{\"ac_id\":{\"S\":\"$AC_ID\"}}" --output json --region "$AWS_REGION" |
    jq -ce --arg ac "$AC_ID" --argjson now "$now" --argjson min_seen "$min_seen" --argjson max_seen "$max_seen" \
      --argjson min_ttl "$min_ttl" --argjson max_ttl "$max_ttl" --argjson count "$SERVER_COUNT" --argjson server_ids "$SERVER_INSTANCE_IDS" '
      .Item as $i | select(
        ($i | type == "object") and $i.ac_id.S == $ac and
        ($i.version.N | tonumber) > 0 and ($i.created_at.N | tonumber) > 0 and
        ($i.created_at.N | tonumber) <= ($i.last_seen.N | tonumber) and
        ($i.last_seen.N | tonumber) >= $min_seen and ($i.last_seen.N | tonumber) <= $max_seen and
        ($i.ttl.N | tonumber) > $now and
        ($i.ttl.N | tonumber) >= (($i.last_seen.N | tonumber) + $min_ttl) and
        ($i.ttl.N | tonumber) <= (($i.last_seen.N | tonumber) + $max_ttl) and
        ($i.assigned_servers.L | type == "array" and length == $count) and
        ($i.assigned_servers.L | all(.M.id.S | length > 0) and all(.M.internal_ip.S | length > 0) and
         all(.M | has("asg_name") | not)) and
        ([ $i.assigned_servers.L[].M.id.S ] | sort) == $server_ids
      ) | $i'
}

before_inventory=$(read_inventory)
before_catalog=$(read_catalog)
before_assignment=$(read_assignment)

bash "$ORIGINAL_ROOT/.github/scripts/verify-knock-ready.sh" "$ASG" cutover-cell0 15 true
sleep "$STABILITY_SECONDS"

after_inventory=$(read_inventory)
after_catalog=$(read_catalog)
after_assignment=$(read_assignment)
[[ "$after_inventory" == "$before_inventory" ]] || { echo "READY target/owner inventory changed during stability window" >&2; exit 1; }
[[ "$after_catalog" == "$before_catalog" ]] || { echo "cell0 catalog changed during stability window" >&2; exit 1; }
# A healthy assigned server refreshes only version/last_seen/ttl at most once
# per five minutes. That write may legitimately land inside this window. Each
# strong read above independently proves those three mutable fields fresh and
# bounded; compare the remaining physical authority so a heartbeat cannot
# create a false failure while any membership or identity drift still does.
before_assignment_authority=$(jq -cS 'del(.version,.last_seen,.ttl)' <<<"$before_assignment")
after_assignment_authority=$(jq -cS 'del(.version,.last_seen,.ttl)' <<<"$after_assignment")
assignment_heartbeat_is_forward=$(jq -en --argjson before "$before_assignment" --argjson after "$after_assignment" '
  ($before.version.N | tonumber) as $before_version |
  ($after.version.N | tonumber) as $after_version |
  ($before.last_seen.N | tonumber) as $before_seen |
  ($after.last_seen.N | tonumber) as $after_seen |
  ($before.ttl.N | tonumber) as $before_ttl |
  ($after.ttl.N | tonumber) as $after_ttl |
  (($after_version == $before_version and $after_seen == $before_seen and $after_ttl == $before_ttl) or
   ($after_version > $before_version and $after_seen >= $before_seen and $after_ttl >= $before_ttl))
') || {
  echo "cell0 assignment heartbeat moved backward or changed without a version advance" >&2
  exit 1
}
[[ "$assignment_heartbeat_is_forward" == true ]] || {
  echo "cell0 assignment heartbeat is not a canonical forward transition" >&2
  exit 1
}
[[ "$after_assignment_authority" == "$before_assignment_authority" ]] || {
  echo "cell0 assignment authority changed during stability window" >&2
  exit 1
}

echo "cell0 durable lifecycle is all-READY/pending0, stable, assignable, freshly assigned, and knock-ready"
