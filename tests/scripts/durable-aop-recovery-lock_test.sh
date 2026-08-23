#!/usr/bin/env bash
# shellcheck disable=SC2016 # Fake scripts intentionally retain runtime variables.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMAGE=0123456789012345678901234567890123456789
OWNER="nhp:77:durable-aop-cutover:${IMAGE}"
PARAM=/layerv-nhp-sandbox/qurl-live-env-lock
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export FAKE_VALUE="$WORK/value" FAKE_ACTIONS="$WORK/actions"
: >"$FAKE_ACTIONS"
jq -cn --arg owner "$OWNER" --arg image "$IMAGE" \
  '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,
    orchestrator_sha:$image,created_at:1,expires_at:253402300799}' >"$FAKE_VALUE"

mkdir -p "$WORK/bin"
printf '%s\n' '#!/usr/bin/env bash' 'printf "20000000000\n"' >"$WORK/bin/date"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/bin/sleep"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '
svc=$1; op=$2; shift 2
case "$svc/$op" in
  ssm/get-parameter) cat "$FAKE_VALUE" ;;
  ssm/put-parameter)
    if [[ " $* " == *" --no-overwrite "* && -s "$FAKE_VALUE" ]]; then echo ParameterAlreadyExists >&2; exit 254; fi
    exit 99 ;;
  ssm/delete-parameter) echo delete >>"$FAKE_ACTIONS"; : >"$FAKE_VALUE" ;;
  cloudwatch/put-metric-data) exit 0 ;;
  *) echo "unexpected aws $svc/$op" >&2; exit 99 ;;
esac' >"$WORK/bin/aws"
chmod +x "$WORK/bin/date" "$WORK/bin/sleep" "$WORK/bin/aws"

PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 \
  bash "$ROOT/.github/scripts/acquire-durable-aop-cutover-lock.sh" \
  "$PARAM" "$OWNER" "$IMAGE" "$IMAGE" >/dev/null

if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 \
    bash "$ROOT/.github/scripts/ssm-live-env-lock.sh" acquire "$PARAM" unrelated 1 0 >/dev/null 2>&1; then
  echo "unrelated owner acquired the non-expiring recovery lock" >&2
  exit 1
fi
[[ ! -s "$FAKE_ACTIONS" ]] || { echo "recovery lock was stale-deleted" >&2; exit 1; }

# The converse race is equally important: once an infrastructure plan/apply
# owns the ordinary shared mutex, the cutover owner cannot acquire/harden it.
jq -cn '{owner:"nhp:88:1:deploy-sandbox-infra",created_at:1,expires_at:253402300799}' >"$FAKE_VALUE"
if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 \
    bash "$ROOT/.github/scripts/ssm-live-env-lock.sh" acquire "$PARAM" "$OWNER" 14400 0 >/dev/null 2>&1; then
  echo "cutover owner acquired the infrastructure plan/apply mutex" >&2
  exit 1
fi
[[ -s "$FAKE_VALUE" ]] || { echo "infrastructure plan/apply mutex was deleted" >&2; exit 1; }

# Restore the hard lock for the ordinary-mutation guard assertion below.
jq -cn --arg owner "$OWNER" --arg image "$IMAGE" \
  '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,
    orchestrator_sha:$image,created_at:1,expires_at:253402300799}' >"$FAKE_VALUE"

if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 \
    bash "$ROOT/.github/scripts/assert-durable-aop-mutation-allowed.sh" >/dev/null 2>&1; then
  echo "ordinary mutation passed a durable recovery lock" >&2
  exit 1
fi

echo "durable-aop-recovery-lock: all tests passed"
