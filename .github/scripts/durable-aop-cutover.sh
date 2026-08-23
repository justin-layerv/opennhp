#!/usr/bin/env bash
# One-time, forward-only sandbox cutover from legacy AOP admission to the
# durable AOP profile. The exact prewarmed image is supplied by the caller.
#
# The point of no return is not an NLB listener mutation: it is the moment the
# entire legacy AC ASG is at desired=0 with no remaining instances. From then
# on there is no legacy AC capable of admitting for either server cell, so a
# retry must only advance the new profile. Every phase is durably recorded in
# SSM to make runner loss/cancellation resumable.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <exact-image-tag>" >&2
  exit 2
fi

IMAGE_TAG=$1
if [[ ! "$IMAGE_TAG" =~ ^[0-9a-f]{40}$ ]]; then
  echo "image tag must be one exact lowercase 40-hex commit SHA" >&2
  exit 2
fi

AWS_REGION=${AWS_REGION:-us-east-2}
export AWS_REGION
CUTOVER_POLL_INTERVAL=${CUTOVER_POLL_INTERVAL:-10}
CUTOVER_WAIT_SECONDS=${CUTOVER_WAIT_SECONDS:-900}
TARGET_PROFILE=durable-aop-v1
MINIMUM_PROFILE_PARAM=/sandbox/nhp/minimum-protocol-profile
STATE_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/state
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROFILE_ORDER="$SCRIPT_DIR/nhp-profile-order.sh"
SWITCH=${CUTOVER_SWITCH_SCRIPT:-$SCRIPT_DIR/blue-green-switch.sh}
CLEAR_ASSIGNMENTS=${CUTOVER_CLEAR_ASSIGNMENTS_SCRIPT:-$SCRIPT_DIR/clear-ac-assignments.sh}
VERIFY_KNOCK_READY=${CUTOVER_VERIFY_KNOCK_READY_SCRIPT:-$SCRIPT_DIR/verify-knock-ready.sh}
VERIFY_ASG_HEALTH=${CUTOVER_VERIFY_ASG_HEALTH_SCRIPT:-$SCRIPT_DIR/verify-asg-instances-healthy.sh}
VERIFY_PROVENANCE=${CUTOVER_VERIFY_PROVENANCE_SCRIPT:-$SCRIPT_DIR/verify-durable-aop-image-provenance.sh}
CUTOVER_LOCK_PARAM=${CUTOVER_LOCK_PARAM:?CUTOVER_LOCK_PARAM is required}
CUTOVER_LOCK_OWNER=${CUTOVER_LOCK_OWNER:?CUTOVER_LOCK_OWNER is required}
CUTOVER_ORCHESTRATOR_SHA=${CUTOVER_ORCHESTRATOR_SHA:?CUTOVER_ORCHESTRATOR_SHA is required}
[[ "$CUTOVER_ORCHESTRATOR_SHA" =~ ^[0-9a-f]{40}$ && "$CUTOVER_ORCHESTRATOR_SHA" == "$IMAGE_TAG" ]] || {
  echo "orchestrator SHA must exactly equal the cutover image/source SHA" >&2
  exit 2
}

get_param() {
  aws ssm get-parameter --name "$1" --query 'Parameter.Value' --output text \
    --region "$AWS_REGION"
}

get_optional_param() {
  bash "$SCRIPT_DIR/../../scripts/ssm-read-optional.sh" "$1"
}

put_param() {
  aws ssm put-parameter --name "$1" --value "$2" --type String --overwrite \
    --region "$AWS_REGION" >/dev/null
}

opposite_color() {
  case "$1" in
    blue) printf 'green\n' ;;
    green) printf 'blue\n' ;;
    *) echo "invalid active color: '$1'" >&2; return 1 ;;
  esac
}

phase_order() {
  case "$1" in
    prepared) printf '10\n' ;;
    ac_terminating) printf '15\n' ;;
    ponr) printf '20\n' ;;
    ac_switched) printf '30\n' ;;
    cell0_switched) printf '40\n' ;;
    cell1_switched) printf '50\n' ;;
    old_servers_terminated) printf '60\n' ;;
    validated) printf '70\n' ;;
    complete) printf '80\n' ;;
    *) echo "invalid cutover phase: '$1'" >&2; return 1 ;;
  esac
}

slot_image_param() {
  local env=$1 component=$2 color=$3
  if [[ "$color" == green ]]; then
    printf '/%s/nhp/%s/green-image-tag\n' "$env" "$component"
  else
    printf '/%s/nhp/%s/image-tag\n' "$env" "$component"
  fi
}

slot_asg_param() {
  local env=$1 component=$2 color=$3
  if [[ "$color" == green ]]; then
    printf '/%s/nhp/%s/green-asg-name\n' "$env" "$component"
  else
    printf '/%s/nhp/%s/asg-name\n' "$env" "$component"
  fi
}

slot_prepared_attestation_param() {
  local env=$1 component=$2 color=$3
  printf '/%s/nhp/%s/%s-prepared-slot-attestation\n' "$env" "$component" "$color"
}

slot_repository() {
  local env=$1 component=$2 repository
  repository=$(get_optional_param "/${env}/nhp/${component}/ecr-repo-name")
  if [[ -z "$repository" ]]; then
    printf 'layerv/nhp-%s\n' "$component"
  else
    printf '%s\n' "$repository"
  fi
}

assert_slot_asg() {
  local env=$1 component=$2 color=$3 expected=$4 actual
  actual=$(get_param "$(slot_asg_param "$env" "$component" "$color")")
  [[ "$actual" == "$expected" ]] || {
    echo "$env $component/$color ASG '$actual' != cutover ledger ASG '$expected'" >&2
    return 1
  }
}

assert_prepared_slot() {
  local env=$1 component=$2 color=$3 expected_asg=${4:-}
  local image record asg attestation expected_attestation state desired healthy repository provenance persisted=${5:-}
  image=$(get_param "$(slot_image_param "$env" "$component" "$color")")
  [[ "$image" == "$IMAGE_TAG" ]] || {
    echo "$env $component/$color image '$image' != exact cutover image '$IMAGE_TAG'" >&2
    return 1
  }
  record=$(get_param "/${env}/nhp/${component}/${color}-protocol-profile")
  "$PROFILE_ORDER" assert-record "$record" "$TARGET_PROFILE" "$IMAGE_TAG"
  asg=$(get_param "$(slot_asg_param "$env" "$component" "$color")")
  if [[ -n "$expected_asg" && "$asg" != "$expected_asg" ]]; then
    echo "$env $component/$color ASG '$asg' != cutover ledger ASG '$expected_asg'" >&2
    return 1
  fi
  # Desired image/profile parameters are written before an instance refresh,
  # so they are not evidence that the standby fleet actually completed that
  # refresh. blue-green-deploy deletes this attestation before either desired
  # state write and recreates it only after refresh plus per-instance health
  # succeed. Binding the exact profile/image/ASG also prevents a stale success
  # record from authorizing a later slot or image.
  repository=$(slot_repository "$env" "$component")
  provenance=$("$VERIFY_PROVENANCE" "$repository" "$IMAGE_TAG")
  expected_attestation="v2|${TARGET_PROFILE}|${provenance#v1|}|${asg}"
  attestation=$(get_param "$(slot_prepared_attestation_param "$env" "$component" "$color")")
  [[ "$attestation" == "$expected_attestation" ]] || {
    echo "$env $component/$color prepared-slot attestation does not bind the exact cutover profile/image/ASG" >&2
    return 1
  }
  if [[ -n "$persisted" && "$attestation" != "$persisted" ]]; then
    echo "$env $component/$color prepared-slot authority changed after the cutover ledger was created" >&2
    return 1
  fi
  LAST_PREPARED_ATTESTATION=$attestation
  # Backticks are JMESPath literals, not shell substitutions.
  # shellcheck disable=SC2016
  state=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$asg" \
    --query 'AutoScalingGroups[0].[DesiredCapacity,length(Instances[?LifecycleState==`InService` && HealthStatus==`Healthy`])]' \
    --output text --region "$AWS_REGION")
  read -r desired healthy <<<"$state"
  if [[ ! "$desired" =~ ^[1-9][0-9]*$ || "$healthy" != "$desired" ]]; then
    echo "$env $component/$color standby is not fully healthy: desired=$desired healthy=$healthy" >&2
    return 1
  fi
  if [[ "$component" == server ]]; then
    "$VERIFY_ASG_HEALTH" "$asg" "$env-$component-$color" 15 \
      'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
  else
    # The durable AC cannot complete its strict AOL/AAK lease handshake with a
    # still-serving legacy server. Pre-PONR validation therefore proves only
    # the exact standby image/profile/capacity above plus both AC processes and
    # Traefik's private ping. Requiring /nhp-ac/ready here deadlocks the cut:
    # that endpoint requires a healthy assigned-server registration, which can
    # only converge after both durable server cells are active and this AC has
    # been restarted below.
    "$VERIFY_ASG_HEALTH" "$asg" "$env-$component-$color" 15 \
      'systemctl is-active --quiet nhp-acd && systemctl is-active --quiet traefik && curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
  fi
}

assert_new_ac_admission_ready() {
  # This is the first point at which the durable AC is expected to hold a
  # strict session-control lease from a durable server. Keep this explicit in
  # addition to the two server knock-ready checks: /nhp-ac/ready proves every
  # new AC instance has a fresh assigned-server path after the controlled
  # restart, while knock-ready proves each server cell has published an AC.
  "$VERIFY_ASG_HEALTH" "$AC_NEW_ASG" "sandbox-ac-$AC_NEW_COLOR-admission" 15 \
    'systemctl is-active --quiet nhp-acd && curl -sfS -o /dev/null http://127.0.0.1:8888/nhp-ac/ready'
}

asg_state() {
  aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$1" \
    --query 'AutoScalingGroups[0].[MinSize,MaxSize,DesiredCapacity,length(Instances)]' \
    --output text --region "$AWS_REGION"
}

wait_asg_zero() {
  local asg=$1 deadline min max desired instances
  deadline=$((SECONDS + CUTOVER_WAIT_SECONDS))
  while :; do
    read -r min max desired instances <<<"$(asg_state "$asg")"
    if [[ "$min" == 0 && "$max" == 0 && "$desired" == 0 && "$instances" == 0 ]]; then
      echo "ASG is fully terminated: $asg"
      return 0
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for $asg to reach min=max=desired=instances=0 (last $min/$max/$desired/$instances)" >&2
      return 1
    fi
    sleep "$CUTOVER_POLL_INTERVAL"
  done
}

zero_asg() {
  local asg=$1 suspended expected_suspended
  # Fence every automatic launch/repair path first, but deliberately leave
  # Terminate active until the requested scale-in has drained the fleet.
  # Suspending every process up front also suspends Terminate and can strand
  # legacy instances indefinitely at desired=0.
  aws autoscaling suspend-processes --auto-scaling-group-name "$asg" \
    --scaling-processes Launch AlarmNotification ScheduledActions AZRebalance \
      ReplaceUnhealthy InstanceRefresh AddToLoadBalancer HealthCheck \
    --region "$AWS_REGION"
  # Do not assume Terminate was live before this run. Re-enable exactly that
  # process after every scale-out source is fenced so an old/manual suspension
  # cannot deadlock the irreversible drain.
  aws autoscaling resume-processes --auto-scaling-group-name "$asg" \
    --scaling-processes Terminate --region "$AWS_REGION"
  aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
    --min-size 0 --max-size 0 --desired-capacity 0 --region "$AWS_REGION"
  wait_asg_zero "$asg"
  aws autoscaling suspend-processes --auto-scaling-group-name "$asg" \
    --scaling-processes Terminate --region "$AWS_REGION"
  expected_suspended=AZRebalance,AddToLoadBalancer,AlarmNotification,HealthCheck,InstanceRefresh,Launch,ReplaceUnhealthy,ScheduledActions,Terminate
  # Backticks are JMESPath literals, not shell substitutions.
  # shellcheck disable=SC2016
  suspended=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$asg" \
    --query 'join(`,`, sort(AutoScalingGroups[0].SuspendedProcesses[].ProcessName))' \
    --output text --region "$AWS_REGION")
  [[ "$suspended" == "$expected_suspended" ]] || {
    echo "$asg scaling-process fence is incomplete: '$suspended'" >&2
    return 1
  }
  # Re-prove capacity after installing the final Terminate fence. This exact
  # 0/0/0/0 + suspended-process state is the durable non-resurrection proof.
  wait_asg_zero "$asg"
}

harden_recovery_lock() {
  local current current_owner created_at hard latest
  current=$(get_param "$CUTOVER_LOCK_PARAM")
  current_owner=$(jq -er '.owner | strings | select(length > 0)' <<<"$current") || {
    echo "shared sandbox lock is malformed before PONR" >&2
    return 1
  }
  [[ "$current_owner" == "$CUTOVER_LOCK_OWNER" ]] || {
    echo "shared sandbox lock owner changed before PONR" >&2
    return 1
  }
  if jq -e --arg image "$IMAGE_TAG" --arg orchestrator "$CUTOVER_ORCHESTRATOR_SHA" '
      .schema == 1 and .kind == "durable-aop-cutover-recovery" and
      .image == $image and .orchestrator_sha == $orchestrator and
      .expires_at == 253402300799
    ' >/dev/null <<<"$current"; then
    return 0
  fi
  created_at=$(jq -er '.created_at | numbers | select(. > 0 and floor == .)' <<<"$current")
  hard=$(jq -cn --arg owner "$CUTOVER_LOCK_OWNER" --arg image "$IMAGE_TAG" \
    --arg orchestrator "$CUTOVER_ORCHESTRATOR_SHA" --argjson created_at "$created_at" \
    '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,
      orchestrator_sha:$orchestrator,created_at:$created_at,expires_at:253402300799}')
  put_param "$CUTOVER_LOCK_PARAM" "$hard"
  latest=$(get_param "$CUTOVER_LOCK_PARAM")
  [[ "$latest" == "$hard" ]] || {
    echo "failed to strongly verify the non-expiring recovery lock" >&2
    return 1
  }
}

write_state() {
  local next_phase=$1
  STATE=$(jq -cn \
    --arg image "$IMAGE_TAG" --arg orchestrator_sha "$CUTOVER_ORCHESTRATOR_SHA" \
    --arg lock_owner "$CUTOVER_LOCK_OWNER" --arg phase "$next_phase" \
    --arg ac_old_color "$AC_OLD_COLOR" --arg ac_new_color "$AC_NEW_COLOR" \
    --arg ac_old_asg "$AC_OLD_ASG" --arg ac_new_asg "$AC_NEW_ASG" \
    --argjson ac_old_min "$AC_OLD_MIN" --argjson ac_old_max "$AC_OLD_MAX" \
    --argjson ac_old_desired "$AC_OLD_DESIRED" --arg ac_attestation "$AC_NEW_ATTESTATION" \
    --arg cell0_old_color "$CELL0_OLD_COLOR" --arg cell0_new_color "$CELL0_NEW_COLOR" \
    --arg cell0_old_asg "$CELL0_OLD_ASG" --arg cell0_new_asg "$CELL0_NEW_ASG" \
    --arg cell0_attestation "$CELL0_NEW_ATTESTATION" \
    --arg cell1_old_color "$CELL1_OLD_COLOR" --arg cell1_new_color "$CELL1_NEW_COLOR" \
    --arg cell1_old_asg "$CELL1_OLD_ASG" --arg cell1_new_asg "$CELL1_NEW_ASG" \
    --arg cell1_attestation "$CELL1_NEW_ATTESTATION" \
    '{schema:2,image:$image,orchestrator_sha:$orchestrator_sha,lock_owner:$lock_owner,phase:$phase,
      ac:{old_color:$ac_old_color,new_color:$ac_new_color,old_asg:$ac_old_asg,new_asg:$ac_new_asg,old_min:$ac_old_min,old_max:$ac_old_max,old_desired:$ac_old_desired,new_attestation:$ac_attestation},
      cell0:{old_color:$cell0_old_color,new_color:$cell0_new_color,old_asg:$cell0_old_asg,new_asg:$cell0_new_asg,new_attestation:$cell0_attestation},
      cell1:{old_color:$cell1_old_color,new_color:$cell1_new_color,old_asg:$cell1_old_asg,new_asg:$cell1_new_asg,new_attestation:$cell1_attestation}}')
  put_param "$STATE_PARAM" "$STATE"
  PHASE=$next_phase
  echo "durable AOP cutover phase: $PHASE"
}

load_state() {
  local raw=$1
  jq -e --arg image "$IMAGE_TAG" --arg orchestrator "$CUTOVER_ORCHESTRATOR_SHA" --arg owner "$CUTOVER_LOCK_OWNER" '
    type == "object" and .schema == 2 and .image == $image and
    .orchestrator_sha == $orchestrator and .lock_owner == $owner and
    (.phase | type == "string") and
    ([.ac,.cell0,.cell1] | all(type == "object")) and
    (.ac.old_min | type == "number" and . >= 0 and floor == .) and
    (.ac.old_max | type == "number" and . > 0 and floor == .) and
    (.ac.old_desired | type == "number" and . > 0 and floor == .) and
    (.ac.old_desired >= .ac.old_min and .ac.old_max >= .ac.old_desired) and
    ([.ac.new_attestation,.cell0.new_attestation,.cell1.new_attestation] |
      all(type == "string" and startswith("v2|durable-aop-v1|"))) and
    ([.ac.old_color,.ac.new_color,.cell0.old_color,.cell0.new_color,
      .cell1.old_color,.cell1.new_color] |
      all(. == "blue" or . == "green")) and
    (.ac.old_color != .ac.new_color) and
    (.cell0.old_color != .cell0.new_color) and
    (.cell1.old_color != .cell1.new_color) and
    ([.ac.old_asg,.ac.new_asg,.cell0.old_asg,.cell0.new_asg,
      .cell1.old_asg,.cell1.new_asg] | all(type == "string" and length > 0)) and
    (.ac.old_asg != .ac.new_asg) and
    (.cell0.old_asg != .cell0.new_asg) and
    (.cell1.old_asg != .cell1.new_asg)
  ' >/dev/null <<<"$raw" || {
    echo "cutover state is malformed or belongs to another image" >&2
    return 1
  }
  STATE=$raw
  PHASE=$(jq -r .phase <<<"$STATE")
  phase_order "$PHASE" >/dev/null
  AC_OLD_COLOR=$(jq -r .ac.old_color <<<"$STATE")
  AC_NEW_COLOR=$(jq -r .ac.new_color <<<"$STATE")
  AC_OLD_ASG=$(jq -r .ac.old_asg <<<"$STATE")
  AC_NEW_ASG=$(jq -r .ac.new_asg <<<"$STATE")
  AC_OLD_MIN=$(jq -r .ac.old_min <<<"$STATE")
  AC_OLD_MAX=$(jq -r .ac.old_max <<<"$STATE")
  AC_OLD_DESIRED=$(jq -r .ac.old_desired <<<"$STATE")
  AC_NEW_ATTESTATION=$(jq -r .ac.new_attestation <<<"$STATE")
  CELL0_OLD_COLOR=$(jq -r .cell0.old_color <<<"$STATE")
  CELL0_NEW_COLOR=$(jq -r .cell0.new_color <<<"$STATE")
  CELL0_OLD_ASG=$(jq -r .cell0.old_asg <<<"$STATE")
  CELL0_NEW_ASG=$(jq -r .cell0.new_asg <<<"$STATE")
  CELL0_NEW_ATTESTATION=$(jq -r .cell0.new_attestation <<<"$STATE")
  CELL1_OLD_COLOR=$(jq -r .cell1.old_color <<<"$STATE")
  CELL1_NEW_COLOR=$(jq -r .cell1.new_color <<<"$STATE")
  CELL1_OLD_ASG=$(jq -r .cell1.old_asg <<<"$STATE")
  CELL1_NEW_ASG=$(jq -r .cell1.new_asg <<<"$STATE")
  CELL1_NEW_ATTESTATION=$(jq -r .cell1.new_attestation <<<"$STATE")
}

assert_active_color() {
  local env=$1 component=$2 want=$3 got
  got=$(get_param "/${env}/nhp/${component}/active-color")
  [[ "$got" == "$want" ]] || {
    echo "$env $component active color '$got' != required '$want'" >&2
    return 1
  }
}

restart_new_ac() {
  local instances=() instance
  while IFS= read -r instance; do
    [[ -n "$instance" ]] && instances+=("$instance")
  done < <(aws autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$AC_NEW_ASG" \
      --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService' && HealthStatus=='Healthy'].InstanceId" \
      --output text --region "$AWS_REGION" | tr '\t' '\n' | grep -v '^$' | sort)
  ((${#instances[@]} > 0)) || { echo "new AC ASG has no healthy instances" >&2; return 1; }
  local command_id status deadline all_done
  command_id=$(aws ssm send-command --instance-ids "${instances[@]}" \
    --document-name AWS-RunShellScript --timeout-seconds 60 --max-errors 0 \
    --parameters 'commands=["systemctl restart nhp-acd && echo RESTART_OK"]' \
    --query 'Command.CommandId' --output text --region "$AWS_REGION")
  deadline=$((SECONDS + CUTOVER_WAIT_SECONDS))
  while :; do
    all_done=true
    for instance in "${instances[@]}"; do
      status=$(aws ssm get-command-invocation --command-id "$command_id" \
        --instance-id "$instance" --query Status --output text --region "$AWS_REGION" 2>/dev/null || true)
      case "$status" in
        Success) ;;
        Failed|TimedOut|Cancelled) echo "AC restart failed for $instance: $status" >&2; return 1 ;;
        *) all_done=false ;;
      esac
    done
    [[ "$all_done" == true ]] && return 0
    ((SECONDS < deadline)) || { echo "timed out waiting for AC restart" >&2; return 1; }
    sleep "$CUTOVER_POLL_INTERVAL"
  done
}

STATE=$(get_optional_param "$STATE_PARAM")
if [[ -n "$STATE" ]]; then
  load_state "$STATE"
else
  FLOOR=$(get_optional_param "$MINIMUM_PROFILE_PARAM")
  FLOOR=${FLOOR:-legacy-aop-v1}
  "$PROFILE_ORDER" assert-at-least "$TARGET_PROFILE" "$FLOOR"
  [[ "$FLOOR" != "$TARGET_PROFILE" ]] || {
    echo "minimum profile is already $TARGET_PROFILE but no completed cutover state exists" >&2
    exit 1
  }

  AC_OLD_COLOR=$(get_param /sandbox/nhp/ac/active-color)
  AC_NEW_COLOR=$(opposite_color "$AC_OLD_COLOR")
  CELL0_OLD_COLOR=$(get_param /sandbox/nhp/server/active-color)
  CELL0_NEW_COLOR=$(opposite_color "$CELL0_OLD_COLOR")
  CELL1_OLD_COLOR=$(get_param /sandbox-cell1/nhp/server/active-color)
  CELL1_NEW_COLOR=$(opposite_color "$CELL1_OLD_COLOR")
  AC_OLD_ASG=$(get_param "$(slot_asg_param sandbox ac "$AC_OLD_COLOR")")
  AC_NEW_ASG=$(get_param "$(slot_asg_param sandbox ac "$AC_NEW_COLOR")")
  read -r AC_OLD_MIN AC_OLD_MAX AC_OLD_DESIRED AC_OLD_INSTANCES <<<"$(asg_state "$AC_OLD_ASG")"
  [[ "$AC_OLD_MIN" =~ ^[1-9][0-9]*$ && "$AC_OLD_MAX" =~ ^[1-9][0-9]*$ && "$AC_OLD_DESIRED" =~ ^[1-9][0-9]*$ && "$AC_OLD_INSTANCES" =~ ^[1-9][0-9]*$ ]] || {
    echo "legacy AC ASG must be serving before the reversible cutover checkpoint" >&2
    exit 1
  }
  CELL0_OLD_ASG=$(get_param "$(slot_asg_param sandbox server "$CELL0_OLD_COLOR")")
  CELL0_NEW_ASG=$(get_param "$(slot_asg_param sandbox server "$CELL0_NEW_COLOR")")
  CELL1_OLD_ASG=$(get_param "$(slot_asg_param sandbox-cell1 server "$CELL1_OLD_COLOR")")
  CELL1_NEW_ASG=$(get_param "$(slot_asg_param sandbox-cell1 server "$CELL1_NEW_COLOR")")

  assert_prepared_slot sandbox ac "$AC_NEW_COLOR" "$AC_NEW_ASG"
  AC_NEW_ATTESTATION=$LAST_PREPARED_ATTESTATION
  assert_prepared_slot sandbox server "$CELL0_NEW_COLOR" "$CELL0_NEW_ASG"
  CELL0_NEW_ATTESTATION=$LAST_PREPARED_ATTESTATION
  assert_prepared_slot sandbox-cell1 server "$CELL1_NEW_COLOR" "$CELL1_NEW_ASG"
  CELL1_NEW_ATTESTATION=$LAST_PREPARED_ATTESTATION
  write_state prepared
fi

# Resume only against the exact six ASG identities captured before the first
# destructive action. A changed slot mapping is external state drift, not a
# reason to reinterpret which fleet the persisted cutover event owns.
assert_slot_asg sandbox ac "$AC_OLD_COLOR" "$AC_OLD_ASG"
assert_slot_asg sandbox ac "$AC_NEW_COLOR" "$AC_NEW_ASG"
assert_slot_asg sandbox server "$CELL0_OLD_COLOR" "$CELL0_OLD_ASG"
assert_slot_asg sandbox server "$CELL0_NEW_COLOR" "$CELL0_NEW_ASG"
assert_slot_asg sandbox-cell1 server "$CELL1_OLD_COLOR" "$CELL1_OLD_ASG"
assert_slot_asg sandbox-cell1 server "$CELL1_NEW_COLOR" "$CELL1_NEW_ASG"

if (( $(phase_order "$PHASE") < $(phase_order ac_terminating) )); then
  assert_prepared_slot sandbox ac "$AC_NEW_COLOR" "$AC_NEW_ASG" "$AC_NEW_ATTESTATION"
  assert_prepared_slot sandbox server "$CELL0_NEW_COLOR" "$CELL0_NEW_ASG" "$CELL0_NEW_ATTESTATION"
  assert_prepared_slot sandbox-cell1 server "$CELL1_NEW_COLOR" "$CELL1_NEW_ASG" "$CELL1_NEW_ATTESTATION"
  # Conservatively enter the forward-only state before the first destructive
  # API call. A runner may be cancelled after AWS accepts the scale-down but
  # before the zero-instance proof or next state write; recording this phase
  # first prevents that ambiguous window from releasing the shared lock.
  harden_recovery_lock
  write_state ac_terminating
fi

if (( $(phase_order "$PHASE") < $(phase_order ponr) )); then
  # Once this wait succeeds, legacy admission cannot resume without
  # deliberately rebuilding the old AC fleet.
  zero_asg "$AC_OLD_ASG"
  write_state ponr
else
  wait_asg_zero "$AC_OLD_ASG"
fi

if (( $(phase_order "$PHASE") < $(phase_order ac_switched) )); then
  assert_prepared_slot sandbox ac "$AC_NEW_COLOR" "$AC_NEW_ASG" "$AC_NEW_ATTESTATION"
  "$SWITCH" sandbox "$AC_NEW_COLOR" ac
  write_state ac_switched
else
  assert_active_color sandbox ac "$AC_NEW_COLOR"
fi

if (( $(phase_order "$PHASE") < $(phase_order cell0_switched) )); then
  assert_prepared_slot sandbox server "$CELL0_NEW_COLOR" "$CELL0_NEW_ASG" "$CELL0_NEW_ATTESTATION"
  "$SWITCH" sandbox "$CELL0_NEW_COLOR" server
  write_state cell0_switched
else
  assert_active_color sandbox server "$CELL0_NEW_COLOR"
fi

if (( $(phase_order "$PHASE") < $(phase_order cell1_switched) )); then
  assert_prepared_slot sandbox-cell1 server "$CELL1_NEW_COLOR" "$CELL1_NEW_ASG" "$CELL1_NEW_ATTESTATION"
  "$SWITCH" sandbox-cell1 "$CELL1_NEW_COLOR" server
  write_state cell1_switched
else
  assert_active_color sandbox-cell1 server "$CELL1_NEW_COLOR"
fi

if (( $(phase_order "$PHASE") < $(phase_order old_servers_terminated) )); then
  zero_asg "$CELL0_OLD_ASG"
  zero_asg "$CELL1_OLD_ASG"
  write_state old_servers_terminated
else
  wait_asg_zero "$CELL0_OLD_ASG"
  wait_asg_zero "$CELL1_OLD_ASG"
fi

if (( $(phase_order "$PHASE") < $(phase_order validated) )); then
  "$CLEAR_ASSIGNMENTS" sandbox cell0
  "$CLEAR_ASSIGNMENTS" sandbox-cell1 cell1
  restart_new_ac
  assert_new_ac_admission_ready
  "$VERIFY_KNOCK_READY" "$CELL0_NEW_ASG" cutover-cell0 15
  "$VERIFY_KNOCK_READY" "$CELL1_NEW_ASG" cutover-cell1 15
  write_state validated
fi

assert_active_color sandbox ac "$AC_NEW_COLOR"
assert_active_color sandbox server "$CELL0_NEW_COLOR"
assert_active_color sandbox-cell1 server "$CELL1_NEW_COLOR"
wait_asg_zero "$AC_OLD_ASG"
wait_asg_zero "$CELL0_OLD_ASG"
wait_asg_zero "$CELL1_OLD_ASG"

FLOOR=$(get_optional_param "$MINIMUM_PROFILE_PARAM")
FLOOR=${FLOOR:-legacy-aop-v1}
"$PROFILE_ORDER" assert-at-least "$TARGET_PROFILE" "$FLOOR"
if [[ "$FLOOR" != "$TARGET_PROFILE" ]]; then
  put_param "$MINIMUM_PROFILE_PARAM" "$TARGET_PROFILE"
fi
[[ "$(get_param "$MINIMUM_PROFILE_PARAM")" == "$TARGET_PROFILE" ]] || {
  echo "minimum profile marker did not converge to $TARGET_PROFILE" >&2
  exit 1
}
[[ "$PHASE" == complete ]] || write_state complete
echo "durable AOP sandbox cutover complete at image $IMAGE_TAG"
