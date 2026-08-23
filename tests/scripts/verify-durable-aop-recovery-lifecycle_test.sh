#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/verify-durable-aop-recovery-lifecycle.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/original/.github/scripts"
export FAKE_MODE=ok

cat >"$WORK/bin/date" <<'EOF'
#!/usr/bin/env bash
printf '1000\n'
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/bin/sleep"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/original/.github/scripts/verify-knock-ready.sh"

cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
svc=$1 op=$2; shift 2
opt() { local key=$1 prev=; shift; for arg in "$@"; do [[ "$prev" == "$key" ]] && { printf '%s' "$arg"; return; }; prev=$arg; done; }
case "$svc/$op" in
  autoscaling/describe-auto-scaling-groups)
    name=$(opt --auto-scaling-group-names "$@")
    jq -cn --arg name "$name" '{AutoScalingGroups:[{AutoScalingGroupName:$name,MinSize:1,MaxSize:4,DesiredCapacity:1,Instances:[{InstanceId:"i-1",LifecycleState:"InService",HealthStatus:"Healthy"}]}]}'
    ;;
  ssm/get-parameter)
    name=$(opt --name "$@")
    case "$name" in /sandbox/nhp/ac/active-color) echo green;; /sandbox/nhp/ac/green-asg-name) echo ac-new;; *) exit 99;; esac
    ;;
  dynamodb/query)
    state=active; [[ "$FAKE_MODE" != target_preparing ]] || state=preparing
    activated=10; ready=10; counted=true
    [[ "$state" == active ]] || { activated=0; ready=0; counted=false; }
    junk='[]'; [[ "$FAKE_MODE" != junk_target_row ]] || junk='[{pk:{S:"AC#authority"},sk:{S:"JUNK"},kind:{S:"junk"}}]'
    jq -cn --arg state "$state" --argjson activated "$activated" --argjson ready "$ready" --argjson counted "$counted" --argjson junk "$junk" '
      {Items:([
        {pk:{S:"AC#authority"},sk:{S:"AUTHORITY"},kind:{S:"authority"},schema_version:{N:"1"},
         ac_id:{S:"layerv-ac-tf"},control_cell_id:{S:"cell0"},version:{N:"4"},active_target_count:{N:"1"},
         created_at_ms:{N:"10"},updated_at_ms:{N:"30"}},
        {pk:{S:"AC#authority"},sk:{S:"TARGET#one"},kind:{S:"target"},schema_version:{N:"2"},
         ac_id:{S:"layerv-ac-tf"},public_key:{S:"public-key"},boot_id:{S:"boot-1"},flush_generation:{N:"2"},
         state:{S:$state},version:{N:"3"},authority_version:{N:"4"},counted_active_slot:{BOOL:$counted},
         control_cell_id:{S:"cell0"},activated_control_version:{N:($activated|tostring)},ready_control_version:{N:($ready|tostring)},
         aak_enqueued_at_ms:{N:"30"},aak_transaction_id:{N:"5"},created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"30"}}
      ] + $junk),Count:(2+($junk|length)),ScannedCount:(2+($junk|length))}'
    ;;
  dynamodb/get-item)
    table=$(opt --table-name "$@")
    case "$table" in
      *session-control)
        pending=0; [[ "$FAKE_MODE" != pending ]] || pending=1
        ttl='{}'; [[ "$FAKE_MODE" != owner_ttl ]] || ttl=',"ttl":{"N":"9999"}'
        jq -cn --argjson pending "$pending" --argjson ttl "$ttl" '
          {Item:{pk:{S:"TARGETWORK#owner"},sk:{S:"DIRECTORY"},kind:{S:"target_work_directory"},schema_version:{N:"1"},
           cell_id:{S:"cell0"},ac_id:{S:"layerv-ac-tf"},public_key:{S:"public-key"},lifecycle_version:{N:"1"},work_version:{N:"1"},
           task_count:{N:($pending|tostring)},pending_count:{N:($pending|tostring)},phase:{S:"ready"},boot_id:{S:"boot-1"},flush_generation:{N:"2"},
           target_version:{N:"3"},target_authority_version:{N:"4"},target_counted_active_slot:{BOOL:true},activated_control_version:{N:"10"},
           ready_control_version:{N:"10"},target_created_at_ms:{N:"10"},target_prepared_at_ms:{N:"20"},target_updated_at_ms:{N:"30"},
           aak_enqueued_at_ms:{N:"30"},aak_transaction_id:{N:"5"},created_at_ms:{N:"10"},updated_at_ms:{N:"30"}} + $ttl}'
        ;;
      *connector-authority)
        assignable='{}'; [[ "$FAKE_MODE" != catalog_explicit_assignable ]] || assignable=',"general_assignable":{"BOOL":true}'
        ttl='{}'; [[ "$FAKE_MODE" != catalog_ttl ]] || ttl=',"ttl":{"N":"9999"}'
        jq -cn --argjson assignable "$assignable" --argjson ttl "$ttl" \
          '{Item:({pk:{S:"REGISTRY"},sk:{S:"CELL#cell0"},cell_id:{S:"cell0"},status:{S:"active"}} + $assignable + $ttl)}'
        ;;
      *ac-assignments)
        read_index=$(wc -l <"$FAKE_ASSIGNMENT_READS")
        printf 'read\n' >>"$FAKE_ASSIGNMENT_READS"
        seen=999; [[ "$FAKE_MODE" != stale_assignment ]] || seen=1
        [[ "$FAKE_MODE" != future_assignment ]] || seen=2000
        ttl=2799; [[ "$FAKE_MODE" != expired_assignment ]] || ttl=999
        version=1
        if [[ "$FAKE_MODE" == assignment_heartbeat && "$read_index" -gt 0 ]]; then
          version=2; seen=1000; ttl=2800
        fi
        if [[ "$FAKE_MODE" == assignment_version_rollback && "$read_index" -eq 0 ]]; then version=2; fi
        if [[ "$FAKE_MODE" == assignment_time_rollback && "$read_index" -gt 0 ]]; then version=2; seen=998; ttl=2798; fi
        if [[ "$FAKE_MODE" == assignment_unversioned_heartbeat && "$read_index" -gt 0 ]]; then seen=1000; ttl=2800; fi
        server_id=i-1; [[ "$FAKE_MODE" != wrong_assignment_instance ]] || server_id=i-other
        asg='{}'; [[ "$FAKE_MODE" != persisted_asg_name ]] || asg=',"asg_name":{"S":"cell0-new"}'
        customer='{}'
        [[ "$FAKE_MODE" != assignment_structural_drift || "$read_index" -eq 0 ]] || customer=',"customer_id":{"S":"other-owner"}'
        jq -cn --argjson version "$version" --argjson seen "$seen" --argjson ttl "$ttl" --arg server_id "$server_id" \
          --argjson asg "$asg" --argjson customer "$customer" \
          '{Item:({ac_id:{S:"layerv-ac-tf"},version:{N:($version|tostring)},created_at:{N:"900"},last_seen:{N:($seen|tostring)},ttl:{N:($ttl|tostring)},
          assigned_servers:{L:[{M:({id:{S:$server_id},internal_ip:{S:"10.0.0.1"}} + $asg)}]}} + $customer)}'
        ;;
      *) exit 99 ;;
    esac
    ;;
  *) echo "unexpected aws $svc/$op $*" >&2; exit 99 ;;
esac
EOF
chmod +x "$WORK/bin/"* "$WORK/original/.github/scripts/verify-knock-ready.sh"

# Match production's canonical hashes rather than teaching the fake AWS script
# to accept arbitrary keys.
target_pk="AC#$(printf layerv-ac-tf | sha256sum | awk '{print $1}')"
owner_pk="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0public-key' | sha256sum | awk '{print $1}')"
sed -i.bak "s/AC#authority/$target_pk/g; s/TARGETWORK#owner/$owner_pk/g" "$WORK/bin/aws"; rm "$WORK/bin/aws.bak"

run() {
  : >"$WORK/assignment-reads"
  PATH="$WORK/bin:$PATH" FAKE_ASSIGNMENT_READS=$WORK/assignment-reads AWS_REGION=us-east-2 CUTOVER_EXPECTED_CELL0_ASG=cell0-new \
    CUTOVER_ORIGINAL_SOURCE_ROOT=$WORK/original CUTOVER_STABILITY_SECONDS=1 "$SCRIPT"
}

run >/dev/null
FAKE_MODE=assignment_heartbeat run >/dev/null
for mode in pending target_preparing junk_target_row owner_ttl catalog_explicit_assignable catalog_ttl \
  stale_assignment future_assignment expired_assignment wrong_assignment_instance persisted_asg_name \
  assignment_structural_drift assignment_version_rollback assignment_time_rollback assignment_unversioned_heartbeat; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then echo "lifecycle verifier accepted $mode authority" >&2; exit 1; fi
done

echo "verify-durable-aop-recovery-lifecycle: strict readiness tests passed"
