#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/verify-durable-aop-cutover-recovery-ready.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/original/.github/scripts"
export FAKE_MODE=ok
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/original/.github/scripts/verify-knock-ready.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/original/.github/scripts/verify-asg-instances-healthy.sh"
cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
svc=$1 op=$2; shift 2
case "$svc/$op" in
  ssm/get-parameter) [[ "$FAKE_MODE" != color ]] && echo green || echo blue ;;
  autoscaling/describe-auto-scaling-groups)
    jq -cn '{AutoScalingGroups:[{AutoScalingGroupName:"cell1-new",MinSize:1,MaxSize:4,DesiredCapacity:1,Instances:[{LifecycleState:"InService",HealthStatus:"Healthy"}]}]}' ;;
  dynamodb/get-item)
    assignable=false; [[ "$FAKE_MODE" != assignable ]] || assignable=true
    jq -cn --argjson assignable "$assignable" '{Item:{pk:{S:"REGISTRY"},sk:{S:"CELL#cell1"},cell_id:{S:"cell1"},status:{S:"active"},general_assignable:{BOOL:$assignable}}}' ;;
  dynamodb/scan)
    if [[ "$FAKE_MODE" == assignment ]]; then
      jq -cn '{Count:1,ScannedCount:1,Items:[{ac_id:{S:"ac"}}]}'
    else
      jq -cn '{Count:0,ScannedCount:0,Items:[]}'
    fi ;;
  *) exit 99 ;;
esac
EOF
chmod +x "$WORK/bin/aws" "$WORK/original/.github/scripts/"*.sh

run() {
  PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 CUTOVER_ORIGINAL_SOURCE_ROOT=$WORK/original \
    CUTOVER_EXPECTED_CELL1_ASG=cell1-new CUTOVER_EXPECTED_CELL1_COLOR=green \
    "$SCRIPT" cell1-new cutover-cell1 1 true
}

run >/dev/null
for mode in assignable assignment color; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then echo "cell1 recovery verifier accepted $mode authority" >&2; exit 1; fi
done

echo "verify-durable-aop-cutover-recovery-ready: topology tests passed"
