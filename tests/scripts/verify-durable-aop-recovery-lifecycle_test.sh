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
    if [[ "$name" == ac-new ]]; then
      jq -cn --arg name "$name" '{AutoScalingGroups:[{AutoScalingGroupName:$name,MinSize:3,MaxSize:6,DesiredCapacity:3,Instances:[
        {InstanceId:"i-ac1",LifecycleState:"InService",HealthStatus:"Healthy"},
        {InstanceId:"i-ac2",LifecycleState:"InService",HealthStatus:"Healthy"},
        {InstanceId:"i-ac3",LifecycleState:"InService",HealthStatus:"Healthy"}]}]}'
    else
      jq -cn --arg name "$name" '{AutoScalingGroups:[{AutoScalingGroupName:$name,MinSize:1,MaxSize:4,DesiredCapacity:1,Instances:[{InstanceId:"i-1",LifecycleState:"InService",HealthStatus:"Healthy"}]}]}'
    fi
    ;;
  ssm/get-parameter)
    name=$(opt --name "$@")
    case "$name" in /sandbox/nhp/ac/active-color) echo green;; /sandbox/nhp/ac/green-asg-name) echo ac-new;; *) exit 99;; esac
    ;;
  dynamodb/query)
    [[ $(opt --limit "$@") == 65 ]] || { echo "target inventory query limit is not 65" >&2; exit 97; }
    junk='[]'; [[ "$FAKE_MODE" != junk_target_row ]] || junk='[{pk:{S:"AC#authority"},sk:{S:"JUNK"},kind:{S:"junk"}}]'
    preparing='[]'; [[ "$FAKE_MODE" != target_preparing ]] || preparing='[{pk:{S:"AC#authority"},sk:{S:"TARGET#preparing"},kind:{S:"target"},schema_version:{N:"2"},ac_id:{S:"layerv-ac-tf"},public_key:{S:"preparing-key"},boot_id:{S:"boot-p"},flush_generation:{N:"1"},state:{S:"preparing"},version:{N:"1"},authority_version:{N:"8"},counted_active_slot:{BOOL:false},control_cell_id:{S:"cell0"},activated_control_version:{N:"0"},ready_control_version:{N:"0"},aak_enqueued_at_ms:{N:"0"},aak_transaction_id:{N:"0"},created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"20"}}]'
    history_count=0
    [[ "$FAKE_MODE" != terminal_64_items ]] || history_count=58
    [[ "$FAKE_MODE" != terminal_65_items ]] || history_count=59
    lek='null'; [[ "$FAKE_MODE" != paginated ]] || lek='{pk:{S:"next"}}'
    jq -cn --argjson junk "$junk" --argjson preparing "$preparing" --argjson history_count "$history_count" --argjson lek "$lek" '
      def ready($n):
        {pk:{S:"AC#authority"},sk:{S:("TARGET#ready"+($n|tostring))},kind:{S:"target"},schema_version:{N:"2"},
         ac_id:{S:"layerv-ac-tf"},public_key:{S:("ready-key-"+($n|tostring))},boot_id:{S:("boot-r"+($n|tostring))},flush_generation:{N:"2"},
         state:{S:"active"},version:{N:"3"},authority_version:{N:"8"},counted_active_slot:{BOOL:true},control_cell_id:{S:"cell0"},
         activated_control_version:{N:"10"},ready_control_version:{N:"10"},aak_enqueued_at_ms:{N:"30"},aak_transaction_id:{N:"5"},
         created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"30"}};
      def canceled_history($n):
        {pk:{S:"AC#authority"},sk:{S:("TARGET#history-"+($n|tostring))},kind:{S:"target"},schema_version:{N:"2"},
         ac_id:{S:"layerv-ac-tf"},public_key:{S:("history-key-"+($n|tostring))},boot_id:{S:("boot-history-"+($n|tostring))},flush_generation:{N:"2"},
         state:{S:"canceled"},version:{N:"7"},authority_version:{N:"8"},counted_active_slot:{BOOL:false},control_cell_id:{S:"cell0"},
         activated_control_version:{N:"0"},ready_control_version:{N:"0"},aak_enqueued_at_ms:{N:"0"},aak_transaction_id:{N:"0"},
         created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"30"}};
      [range(1; $history_count + 1) | canceled_history(.)] as $history |
      {Items:([
        {pk:{S:"AC#authority"},sk:{S:"AUTHORITY"},kind:{S:"authority"},schema_version:{N:"1"},
         ac_id:{S:"layerv-ac-tf"},control_cell_id:{S:"cell0"},version:{N:"8"},active_target_count:{N:"3"},
         created_at_ms:{N:"10"},updated_at_ms:{N:"30"}},
        ready(1),ready(2),ready(3),
        {pk:{S:"AC#authority"},sk:{S:"TARGET#retired"},kind:{S:"target"},schema_version:{N:"2"},
         ac_id:{S:"layerv-ac-tf"},public_key:{S:"retired-key"},boot_id:{S:"boot-retired"},flush_generation:{N:"2"},
         state:{S:"retired"},version:{N:"5"},authority_version:{N:"8"},counted_active_slot:{BOOL:false},control_cell_id:{S:"cell0"},
         activated_control_version:{N:"0"},ready_control_version:{N:"0"},aak_enqueued_at_ms:{N:"0"},aak_transaction_id:{N:"0"},
         created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"40"},retired_at_ms:{N:"40"}},
        {pk:{S:"AC#authority"},sk:{S:"TARGET#canceled"},kind:{S:"target"},schema_version:{N:"2"},
         ac_id:{S:"layerv-ac-tf"},public_key:{S:"canceled-key"},boot_id:{S:"boot-canceled"},flush_generation:{N:"2"},
         state:{S:"canceled"},version:{N:"7"},authority_version:{N:"8"},counted_active_slot:{BOOL:false},control_cell_id:{S:"cell0"},
         activated_control_version:{N:"0"},ready_control_version:{N:"0"},aak_enqueued_at_ms:{N:"0"},aak_transaction_id:{N:"0"},
         created_at_ms:{N:"10"},prepared_at_ms:{N:"20"},updated_at_ms:{N:"30"}}
      ] + $history + $preparing + $junk),Count:(6+($history|length)+($preparing|length)+($junk|length)),ScannedCount:(6+($history|length)+($preparing|length)+($junk|length)),LastEvaluatedKey:$lek}'
    ;;
  dynamodb/get-item)
    table=$(opt --table-name "$@")
    case "$table" in
      *session-control)
        key=$(opt --key "$@")
        case "$key" in
          *"$OWNER_READY1"*) public=ready-key-1; boot=boot-r1; phase=ready; version=3; counted=true; activated=10; ready=10; aak=30; tx=5; target_updated=30; retired=0;;
          *"$OWNER_READY2"*) public=ready-key-2; boot=boot-r2; phase=ready; version=3; counted=true; activated=10; ready=10; aak=30; tx=5; target_updated=30; retired=0;;
          *"$OWNER_READY3"*) public=ready-key-3; boot=boot-r3; phase=ready; version=3; counted=true; activated=10; ready=10; aak=30; tx=5; target_updated=30; retired=0;;
          *"$OWNER_RETIRED"*) public=retired-key; boot=boot-retired; phase=retired; version=5; counted=false; activated=0; ready=0; aak=0; tx=0; target_updated=40; retired=40;;
          *"$OWNER_CANCELED"*) public=canceled-key; boot=boot-canceled; phase=preparing; version=6; counted=false; activated=0; ready=0; aak=0; tx=0; target_updated=20; retired=0;;
          *)
            matched=false
            for n in $(seq 1 59); do
              candidate="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0history-key-%s' "$n" | sha256sum | awk '{print $1}')"
              if [[ "$key" == *"$candidate"* ]]; then
                public="history-key-$n"; boot="boot-history-$n"; phase=preparing; version=6; counted=false
                activated=0; ready=0; aak=0; tx=0; target_updated=20; retired=0; matched=true
                break
              fi
            done
            [[ "$matched" == true ]] || exit 98
            ;;
        esac
        pending=0; [[ "$FAKE_MODE" != pending ]] || pending=1
        [[ "$FAKE_MODE" != retired_owner_ready || "$public" != retired-key ]] || phase=ready
        [[ "$FAKE_MODE" != canceled_owner_version || "$public" != canceled-key ]] || version=5
        ttl='{}'; [[ "$FAKE_MODE" != owner_ttl ]] || ttl=',"ttl":{"N":"9999"}'
        jq -cn --arg pk "$(jq -r .pk.S <<<"$key")" --arg public "$public" --arg boot "$boot" --arg phase "$phase" \
          --argjson version "$version" --argjson counted "$counted" --argjson activated "$activated" --argjson ready "$ready" \
          --argjson aak "$aak" --argjson tx "$tx" --argjson target_updated "$target_updated" --argjson retired "$retired" \
          --argjson pending "$pending" --argjson ttl "$ttl" '
          {Item:({pk:{S:$pk},sk:{S:"DIRECTORY"},kind:{S:"target_work_directory"},schema_version:{N:"1"},
           cell_id:{S:"cell0"},ac_id:{S:"layerv-ac-tf"},public_key:{S:$public},lifecycle_version:{N:"2"},work_version:{N:"1"},
           task_count:{N:($pending|tostring)},pending_count:{N:($pending|tostring)},phase:{S:$phase},boot_id:{S:$boot},flush_generation:{N:"2"},
           target_version:{N:($version|tostring)},target_authority_version:{N:"8"},target_counted_active_slot:{BOOL:$counted},
           activated_control_version:{N:($activated|tostring)},ready_control_version:{N:($ready|tostring)},target_created_at_ms:{N:"10"},
           target_prepared_at_ms:{N:"20"},target_updated_at_ms:{N:($target_updated|tostring)},aak_enqueued_at_ms:{N:($aak|tostring)},
           aak_transaction_id:{N:($tx|tostring)},created_at_ms:{N:"10"},updated_at_ms:{N:(if $retired > 0 then ($retired|tostring) else "30" end)}} +
           (if $retired > 0 then {retired_at_ms:{N:($retired|tostring)}} else {} end) + $ttl)}'
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
sed -i.bak "s/AC#authority/$target_pk/g" "$WORK/bin/aws"; rm "$WORK/bin/aws.bak"
OWNER_READY1="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0ready-key-1' | sha256sum | awk '{print $1}')"
OWNER_READY2="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0ready-key-2' | sha256sum | awk '{print $1}')"
OWNER_READY3="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0ready-key-3' | sha256sum | awk '{print $1}')"
OWNER_RETIRED="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0retired-key' | sha256sum | awk '{print $1}')"
OWNER_CANCELED="TARGETWORK#$(printf 'v1\0cell0\0layerv-ac-tf\0canceled-key' | sha256sum | awk '{print $1}')"
export OWNER_READY1 OWNER_READY2 OWNER_READY3 OWNER_RETIRED OWNER_CANCELED

run() {
  : >"$WORK/assignment-reads"
  PATH="$WORK/bin:$PATH" FAKE_ASSIGNMENT_READS=$WORK/assignment-reads AWS_REGION=us-east-2 CUTOVER_EXPECTED_CELL0_ASG=cell0-new \
    CUTOVER_ORIGINAL_SOURCE_ROOT=$WORK/original CUTOVER_STABILITY_SECONDS=1 "$SCRIPT"
}

run >/dev/null
FAKE_MODE=assignment_heartbeat run >/dev/null
FAKE_MODE=terminal_64_items run >/dev/null
for mode in pending target_preparing junk_target_row paginated terminal_65_items retired_owner_ready canceled_owner_version owner_ttl catalog_explicit_assignable catalog_ttl \
  stale_assignment future_assignment expired_assignment wrong_assignment_instance persisted_asg_name \
  assignment_structural_drift assignment_version_rollback assignment_time_rollback assignment_unversioned_heartbeat; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then echo "lifecycle verifier accepted $mode authority" >&2; exit 1; fi
done

echo "verify-durable-aop-recovery-lifecycle: strict readiness tests passed"
