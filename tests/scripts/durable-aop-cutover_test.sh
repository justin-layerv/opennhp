#!/usr/bin/env bash
# shellcheck disable=SC2016 # Generated fake scripts intentionally use literal shell variables.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/durable-aop-cutover.sh"
IMAGE=0123456789012345678901234567890123456789
DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
OWNER="nhp:12345:durable-aop-cutover:${IMAGE}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

make_helpers() {
  local dir=$1
  mkdir -p "$dir"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'env=$1; color=$2; component=$3' \
    'echo "switch $env $color $component" >> "$FAKE_ACTIONS"' \
    'if [[ "${FAKE_FAIL_SWITCH_ENV:-}" == "$env/$component" && ! -e "$FAKE_FAIL_ONCE" ]]; then : > "$FAKE_FAIL_ONCE"; exit 71; fi' \
    'aws ssm put-parameter --name "/${env}/nhp/${component}/active-color" --value "$color" --type String --overwrite >/dev/null' \
    > "$dir/switch"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'echo "clear $*" >> "$FAKE_ACTIONS"' > "$dir/clear"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'echo "verify $*" >> "$FAKE_ACTIONS"' > "$dir/verify"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    '[[ "${FAKE_PROVENANCE_FAIL:-}" != "$1" ]] || exit 73' \
    'echo "provenance $*" >> "$FAKE_ACTIONS"' \
    'printf "v1|%s|%s|%s\n" "$2" "$1" "$FAKE_DIGEST"' > "$dir/provenance"
  chmod +x "$dir/switch" "$dir/clear" "$dir/verify" "$dir/provenance"
}

make_fake_aws() {
  local dir=$1
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '
svc=${1:-}; op=${2:-}; shift 2 || true
opt() { local want=$1 prev=; shift; for arg in "$@"; do [[ "$prev" == "$want" ]] && { printf "%s" "$arg"; return; }; prev=$arg; done; }
case "$svc/$op" in
  ssm/get-parameter)
    name=$(opt --name "$@")
    value=$(awk -F "\t" -v n="$name" '\''$1==n {print substr($0,index($0,"\t")+1); found=1} END {exit !found}'\'' "$FAKE_PARAMS") || { echo "ParameterNotFound" >&2; exit 254; }
    printf "%s\n" "$value"
    ;;
  ssm/put-parameter)
    name=$(opt --name "$@"); value=$(opt --value "$@")
    awk -F "\t" -v n="$name" '\''$1!=n'\'' "$FAKE_PARAMS" > "$FAKE_PARAMS.tmp"
    printf "%s\t%s\n" "$name" "$value" >> "$FAKE_PARAMS.tmp"
    mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
    echo "put $name $value" >> "$FAKE_ACTIONS"
    ;;
  ssm/delete-parameter)
    name=$(opt --name "$@")
    if ! awk -F "\t" -v n="$name" '\''$1==n {found=1} END {exit !found}'\'' "$FAKE_PARAMS"; then
      echo "ParameterNotFound" >&2
      exit 254
    fi
    awk -F "\t" -v n="$name" '\''$1!=n'\'' "$FAKE_PARAMS" > "$FAKE_PARAMS.tmp"
    mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
    echo "delete $name" >> "$FAKE_ACTIONS"
    ;;
  ssm/send-command) echo "restart" >> "$FAKE_ACTIONS"; printf "cmd-1\n" ;;
  ssm/get-command-invocation) printf "Success\n" ;;
  autoscaling/describe-auto-scaling-groups)
    name=$(opt --auto-scaling-group-names "$@"); query=$(opt --query "$@")
    read -r min max desired instances suspended < <(awk -v n="$name" '\''$1==n {print $2, $3, $4, $5, $6; found=1} END {exit !found}'\'' "$FAKE_ASGS")
    case "$query" in
      *SuspendedProcesses*) [[ "$suspended" == - ]] && suspended=; printf "%s\n" "$suspended" ;;
      *MinSize*) printf "%s\t%s\t%s\t%s\n" "$min" "$max" "$desired" "$instances" ;;
      *InstanceId*) ((desired > 0)) && printf "i-new-ac\n" ;;
      *) printf "%s\t%s\n" "$desired" "$desired" ;;
    esac
    ;;
  autoscaling/update-auto-scaling-group)
    name=$(opt --auto-scaling-group-name "$@"); min=$(opt --min-size "$@"); max=$(opt --max-size "$@"); desired=$(opt --desired-capacity "$@")
    suspended=$(awk -v n="$name" '\''$1==n {print $6; found=1} END {exit !found}'\'' "$FAKE_ASGS")
    # Model the real failure mode: desired=0 cannot drain instances after the
    # Terminate process has already been suspended.
    instances=$desired
    [[ ",$suspended," != *,Terminate,* ]] || instances=$(awk -v n="$name" '\''$1==n {print $5}'\'' "$FAKE_ASGS")
    awk -v n="$name" -v m="$min" -v x="$max" -v d="$desired" -v i="$instances" '\''$1==n {$2=m; $3=x; $4=d; $5=i} {print}'\'' "$FAKE_ASGS" > "$FAKE_ASGS.tmp"
    mv "$FAKE_ASGS.tmp" "$FAKE_ASGS"
    echo "asg $name $min $max $desired" >> "$FAKE_ACTIONS"
    if [[ "${FAKE_FAIL_ZERO_ASG:-}" == "$name" && ! -e "$FAKE_FAIL_ZERO_ONCE" ]]; then
      : > "$FAKE_FAIL_ZERO_ONCE"
      exit 72
    fi
    ;;
  autoscaling/suspend-processes)
    name=$(opt --auto-scaling-group-name "$@")
    processes=; collect=false
    for arg in "$@"; do
      case "$arg" in
        --scaling-processes) collect=true ;;
        --*) collect=false ;;
        *) [[ "$collect" == false ]] || processes="${processes:+$processes,}$arg" ;;
      esac
    done
    [[ -n "$processes" ]] || processes=AddToLoadBalancer,AlarmNotification,AZRebalance,HealthCheck,InstanceRefresh,Launch,ReplaceUnhealthy,ScheduledActions,Terminate
    current=$(awk -v n="$name" '\''$1==n {print $6; found=1} END {exit !found}'\'' "$FAKE_ASGS")
    [[ "$current" == - ]] && current=
    merged=$(printf "%s\n%s\n" "${current//,/$'\''\n'\''}" "${processes//,/$'\''\n'\''}" | sed '\''/^$/d'\'' | sort -u | paste -sd, -)
    awk -v n="$name" -v s="$merged" '\''$1==n {$6=s} {print}'\'' "$FAKE_ASGS" > "$FAKE_ASGS.tmp"
    mv "$FAKE_ASGS.tmp" "$FAKE_ASGS"
    echo "suspend $name $processes" >> "$FAKE_ACTIONS"
    ;;
  autoscaling/resume-processes)
    name=$(opt --auto-scaling-group-name "$@"); processes=; collect=false
    for arg in "$@"; do
      case "$arg" in
        --scaling-processes) collect=true ;;
        --*) collect=false ;;
        *) [[ "$collect" == false ]] || processes="${processes:+$processes,}$arg" ;;
      esac
    done
    current=$(awk -v n="$name" '\''$1==n {print $6; found=1} END {exit !found}'\'' "$FAKE_ASGS")
    [[ "$current" == - ]] && current=
    remaining=$(printf "%s\n" "${current//,/$'\''\n'\''}" | while IFS= read -r item; do
      [[ -z "$item" || ",$processes," == *",$item,"* ]] || printf "%s\n" "$item"
    done | sort -u | paste -sd, -)
    [[ -n "$remaining" ]] || remaining=-
    awk -v n="$name" -v s="$remaining" '\''$1==n {$6=s} {print}'\'' "$FAKE_ASGS" > "$FAKE_ASGS.tmp"
    mv "$FAKE_ASGS.tmp" "$FAKE_ASGS"
    echo "resume $name $processes" >> "$FAKE_ACTIONS"
    ;;
  autoscaling/set-desired-capacity)
    name=$(opt --auto-scaling-group-name "$@"); requested=$(opt --desired-capacity "$@")
    max=$(awk -v n="$name" '\''$1==n {print $3; found=1} END {exit !found}'\'' "$FAKE_ASGS")
    if ((requested > max)); then echo ValidationError >&2; exit 254; fi
    awk -v n="$name" -v d="$requested" '\''$1==n {$4=d; $5=d} {print}'\'' "$FAKE_ASGS" > "$FAKE_ASGS.tmp"
    mv "$FAKE_ASGS.tmp" "$FAKE_ASGS"
    ;;
  *) echo "unexpected aws call: $svc/$op $*" >&2; exit 99 ;;
esac' > "$dir/aws"
  chmod +x "$dir/aws"
}

seed() {
  : > "$FAKE_ACTIONS"
  : > "$FAKE_FAIL_ONCE"
  rm -f "$FAKE_FAIL_ONCE"
  : > "$FAKE_FAIL_ZERO_ONCE"
  rm -f "$FAKE_FAIL_ZERO_ONCE"
  {
    printf '/sandbox/nhp/ac/active-color\tblue\n'
    printf '/sandbox/nhp/ac/asg-name\tac-blue\n'
    printf '/sandbox/nhp/ac/green-asg-name\tac-green\n'
    printf '/sandbox/nhp/ac/green-image-tag\t%s\n' "$IMAGE"
    printf '/sandbox/nhp/ac/ecr-repo-name\tlayerv/nhp-ac\n'
    printf '/sandbox/nhp/ac/green-protocol-profile\tv1|durable-aop-v1|%s\n' "$IMAGE"
    printf '/sandbox/nhp/ac/green-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-ac|%s|ac-green\n' "$IMAGE" "$DIGEST"
    printf '/sandbox/nhp/server/active-color\tblue\n'
    printf '/sandbox/nhp/server/asg-name\tcell0-blue\n'
    printf '/sandbox/nhp/server/green-asg-name\tcell0-green\n'
    printf '/sandbox/nhp/server/green-image-tag\t%s\n' "$IMAGE"
    printf '/sandbox/nhp/server/ecr-repo-name\tlayerv/nhp-server\n'
    printf '/sandbox/nhp/server/green-protocol-profile\tv1|durable-aop-v1|%s\n' "$IMAGE"
    printf '/sandbox/nhp/server/green-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-server|%s|cell0-green\n' "$IMAGE" "$DIGEST"
    printf '/sandbox-cell1/nhp/server/active-color\tblue\n'
    printf '/sandbox-cell1/nhp/server/asg-name\tcell1-blue\n'
    printf '/sandbox-cell1/nhp/server/green-asg-name\tcell1-green\n'
    printf '/sandbox-cell1/nhp/server/green-image-tag\t%s\n' "$IMAGE"
    printf '/sandbox-cell1/nhp/server/ecr-repo-name\tlayerv/nhp-server\n'
    printf '/sandbox-cell1/nhp/server/green-protocol-profile\tv1|durable-aop-v1|%s\n' "$IMAGE"
    printf '/sandbox-cell1/nhp/server/green-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-server|%s|cell1-green\n' "$IMAGE" "$DIGEST"
    printf '/layerv-nhp-sandbox/qurl-live-env-lock\t%s\n' "$(jq -cn --arg owner "$OWNER" '{owner:$owner,created_at:1,expires_at:9999999999}')"
  } > "$FAKE_PARAMS"
  {
    printf 'ac-blue 3 10 3 3 -\nac-green 3 10 3 3 -\n'
    printf 'cell0-blue 3 10 3 3 -\ncell0-green 3 10 3 3 -\n'
    printf 'cell1-blue 1 4 1 1 -\ncell1-green 1 4 1 1 -\n'
  } > "$FAKE_ASGS"
}

BIN="$WORK/bin"; HELPERS="$WORK/helpers"
mkdir -p "$BIN"
make_fake_aws "$BIN"
make_helpers "$HELPERS"
export FAKE_PARAMS="$WORK/params" FAKE_ASGS="$WORK/asgs" FAKE_ACTIONS="$WORK/actions" FAKE_FAIL_ONCE="$WORK/fail-once"
export FAKE_FAIL_ZERO_ONCE="$WORK/fail-zero-once" FAKE_DIGEST="$DIGEST"

run_cutover() {
  PATH="$BIN:$PATH" AWS_REGION=us-east-2 CUTOVER_POLL_INTERVAL=0 CUTOVER_WAIT_SECONDS=5 \
    CUTOVER_SWITCH_SCRIPT="$HELPERS/switch" CUTOVER_CLEAR_ASSIGNMENTS_SCRIPT="$HELPERS/clear" \
    CUTOVER_VERIFY_KNOCK_READY_SCRIPT="$HELPERS/verify" CUTOVER_VERIFY_ASG_HEALTH_SCRIPT="$HELPERS/verify" \
    CUTOVER_VERIFY_PROVENANCE_SCRIPT="$HELPERS/provenance" \
    CUTOVER_LOCK_PARAM=/layerv-nhp-sandbox/qurl-live-env-lock CUTOVER_LOCK_OWNER="$OWNER" CUTOVER_ORCHESTRATOR_SHA="$IMAGE" \
    "$SCRIPT" "$IMAGE"
}

seed
run_cutover >/dev/null
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/minimum-protocol-profile"{print $2}' "$FAKE_PARAMS")" == durable-aop-v1 ]]
[[ "$(jq -r .phase <<<"$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")")" == complete ]]
grep -Fq 'systemctl is-active --quiet traefik && curl -sfS -o /dev/null http://127.0.0.1:8080/ping' "$FAKE_ACTIONS"
[[ "$(grep -Fc 'http://127.0.0.1:8888/nhp-ac/ready' "$FAKE_ACTIONS")" == 1 ]]
old_ac_zero=$(grep -n '^asg ac-blue 0 0 0$' "$FAKE_ACTIONS" | cut -d: -f1)
ac_switch=$(grep -n '^switch sandbox green ac$' "$FAKE_ACTIONS" | cut -d: -f1)
cell0_switch=$(grep -n '^switch sandbox green server$' "$FAKE_ACTIONS" | cut -d: -f1)
cell1_switch=$(grep -n '^switch sandbox-cell1 green server$' "$FAKE_ACTIONS" | cut -d: -f1)
ac_restart=$(grep -n '^restart$' "$FAKE_ACTIONS" | cut -d: -f1)
ac_ready=$(grep -n 'http://127.0.0.1:8888/nhp-ac/ready' "$FAKE_ACTIONS" | cut -d: -f1)
[[ "$old_ac_zero" -lt "$ac_switch" && "$ac_switch" -lt "$cell0_switch" && "$cell0_switch" -lt "$cell1_switch" ]]
old_ac_suspend=$(grep -n '^suspend ac-blue Launch,AlarmNotification,ScheduledActions,AZRebalance,ReplaceUnhealthy,InstanceRefresh,AddToLoadBalancer,HealthCheck$' "$FAKE_ACTIONS" | cut -d: -f1)
old_ac_terminate_resume=$(grep -n '^resume ac-blue Terminate$' "$FAKE_ACTIONS" | cut -d: -f1)
old_ac_terminate_suspend=$(grep -n '^suspend ac-blue Terminate$' "$FAKE_ACTIONS" | cut -d: -f1)
[[ "$old_ac_suspend" -lt "$old_ac_terminate_resume" && "$old_ac_terminate_resume" -lt "$old_ac_zero" && "$old_ac_zero" -lt "$old_ac_terminate_suspend" ]]
if PATH="$BIN:$PATH" aws autoscaling set-desired-capacity \
    --auto-scaling-group-name ac-blue --desired-capacity 1 >/dev/null 2>&1; then
  echo "legacy AC accepted a post-zero scale-out race" >&2
  exit 1
fi
[[ "$(awk '$1=="ac-blue"{print $2,$3,$4,$5}' "$FAKE_ASGS")" == '0 0 0 0' ]]
[[ "$cell1_switch" -lt "$ac_restart" && "$ac_restart" -lt "$ac_ready" ]]
[[ "$(grep -c '^restart$' "$FAKE_ACTIONS")" == 1 ]]

mutations=$(grep -Ec '^(asg|switch|restart|clear|verify) ' "$FAKE_ACTIONS" || true)
run_cutover >/dev/null
[[ "$(grep -Ec '^(asg|switch|restart|clear|verify) ' "$FAKE_ACTIONS" || true)" == "$mutations" ]]

# A failed prepare after writing desired image/profile deletes the previous
# attestation and never publishes a replacement. A later manual cutover must
# refuse before recording destructive intent or scaling the legacy AC.
seed
awk -F '\t' '$1!="/sandbox/nhp/ac/green-prepared-slot-attestation"' "$FAKE_PARAMS" > "$FAKE_PARAMS.tmp"
mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if run_cutover >/dev/null 2>&1; then
  echo "expected missing refresh-success attestation to fail" >&2
  exit 1
fi
if grep -q '^asg ac-blue 0 0 0$' "$FAKE_ACTIONS"; then exit 1; fi

# A manual profile/slot label cannot turn an image without exact signed source
# provenance into a durable cutover candidate.
seed
export FAKE_PROVENANCE_FAIL=layerv/nhp-ac
if run_cutover >/dev/null 2>&1; then
  echo "expected unverified legacy image labeled durable to fail" >&2
  exit 1
fi
unset FAKE_PROVENANCE_FAIL
if grep -q '^asg ac-blue 0 0 0$' "$FAKE_ACTIONS"; then exit 1; fi
if awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{found=1} END {exit !found}' "$FAKE_PARAMS"; then
  echo "failed prepare must not create a cutover state" >&2
  exit 1
fi

# A runner/API failure after accepting the first destructive scale-down must
# already be durably forward-only. Retrying resumes the same exact event.
seed
export FAKE_FAIL_ZERO_ASG=ac-blue
if run_cutover >/dev/null 2>&1; then
  echo "expected injected legacy AC scale-down response failure" >&2
  exit 1
fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == ac_terminating ]]
[[ "$(awk '$1=="ac-blue"{print $2,$3,$4,$5}' "$FAKE_ASGS")" == '0 0 0 0' ]]
lock=$(awk -F '\t' '$1=="/layerv-nhp-sandbox/qurl-live-env-lock"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$("$ROOT/.github/scripts/classify-durable-aop-cutover-lock-release.sh" failure "$IMAGE" "$IMAGE" "$OWNER" "$state" "$lock")" == false ]]
unset FAKE_FAIL_ZERO_ASG
run_cutover >/dev/null
[[ "$(jq -r .phase <<<"$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")")" == complete ]]

seed
export FAKE_FAIL_SWITCH_ENV=sandbox/server
if run_cutover >/dev/null 2>&1; then
  echo "expected first post-PONR cell0 switch failure" >&2
  exit 1
fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == ac_switched ]]
[[ "$(awk '$1=="ac-blue"{print $3,$4,$5}' "$FAKE_ASGS")" == '0 0 0' ]]
unset FAKE_FAIL_SWITCH_ENV
run_cutover >/dev/null
[[ "$(grep -c '^switch sandbox green ac$' "$FAKE_ACTIONS")" == 1 ]]
[[ "$(jq -r .phase <<<"$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state"{print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")")" == complete ]]

seed
awk -F '\t' '$1!="/sandbox-cell1/nhp/server/green-protocol-profile"' "$FAKE_PARAMS" > "$FAKE_PARAMS.tmp"
mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if run_cutover >/dev/null 2>&1; then
  echo "expected missing prepared profile record to fail" >&2
  exit 1
fi
if grep -q '^asg ac-blue 0 0 0$' "$FAKE_ACTIONS"; then exit 1; fi

# A preexisting/manual Terminate suspension must not strand the legacy fleet.
# The cutover first fences every scale-out path, resumes exactly Terminate,
# drains to zero, and suspends Terminate again in the terminal ASG proof.
seed
awk '$1=="ac-blue" {$6="Terminate"} {print}' "$FAKE_ASGS" > "$FAKE_ASGS.tmp"
mv "$FAKE_ASGS.tmp" "$FAKE_ASGS"
run_cutover >/dev/null
[[ "$(awk '$1=="ac-blue"{print $2,$3,$4,$5}' "$FAKE_ASGS")" == '0 0 0 0' ]]
grep -Fq 'resume ac-blue Terminate' "$FAKE_ACTIONS"

echo "durable-aop-cutover: all tests passed"
