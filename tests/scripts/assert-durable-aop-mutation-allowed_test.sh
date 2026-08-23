#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/assert-durable-aop-mutation-allowed.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export FAKE_PARAMS="$WORK/params"
mkdir -p "$WORK/bin"
cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
name=
prev=
for arg in "$@"; do
  [[ "$prev" == --name ]] && name=$arg
  prev=$arg
done
if value=$(awk -F '\t' -v n="$name" '$1==n {print substr($0,index($0,"\t")+1); found=1} END {exit !found}' "$FAKE_PARAMS"); then
  printf '%s\n' "$value"
else
  echo ParameterNotFound >&2
  exit 254
fi
EOF
chmod +x "$WORK/bin/aws"

run_guard() { PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 bash "$SCRIPT"; }
state=$(jq -cn '{schema:2,image:"0123456789012345678901234567890123456789",orchestrator_sha:"0123456789012345678901234567890123456789",lock_owner:"owner",phase:"complete"}')

: >"$FAKE_PARAMS"
run_guard
printf '/sandbox/nhp/minimum-protocol-profile\tdurable-aop-v1\n' >"$FAKE_PARAMS"
if run_guard >/dev/null 2>&1; then echo "marker without state was accepted" >&2; exit 1; fi
printf '/sandbox/nhp/cutovers/durable-aop-v1/state\t%s\n' "$state" >"$FAKE_PARAMS"
if run_guard >/dev/null 2>&1; then echo "state without marker was accepted" >&2; exit 1; fi
{
  printf '/sandbox/nhp/cutovers/durable-aop-v1/state\t%s\n' "$state"
  printf '/sandbox/nhp/minimum-protocol-profile\tdurable-aop-v1\n'
} >"$FAKE_PARAMS"
run_guard

for bad_lock in \
  '{"kind":"other","owner":"owner","created_at":1,"expires_at":2}' \
  '{"kind":"ordinary","owner":"","created_at":1,"expires_at":2}' \
  '{"kind":"ordinary","owner":"owner","created_at":2,"expires_at":1}' \
  '{"owner":"owner","created_at":1,"expires_at":2,"extra":true}'; do
  printf '/layerv-nhp-sandbox/qurl-live-env-lock\t%s\n' "$bad_lock" >"$FAKE_PARAMS"
  if run_guard >/dev/null 2>&1; then echo "malformed/unknown lock was accepted: $bad_lock" >&2; exit 1; fi
done

echo "assert-durable-aop-mutation-allowed: all tests passed"
