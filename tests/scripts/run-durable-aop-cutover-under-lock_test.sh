#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMAGE=0123456789012345678901234567890123456789
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/.github/scripts" "$WORK/scripts"
cp "$ROOT/.github/scripts/run-durable-aop-cutover-under-lock.sh" "$WORK/.github/scripts/"

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/.github/scripts/acquire-durable-aop-cutover-lock.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 71' >"$WORK/.github/scripts/durable-aop-cutover.sh"
printf '%s\n' '#!/usr/bin/env bash' 'printf "false\n"' >"$WORK/.github/scripts/classify-durable-aop-cutover-lock-release.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 99' >"$WORK/.github/scripts/ssm-live-env-lock.sh"
# The exact production incident: the state read is empty after the cutover
# child fails.  The wrapper must classify it as an unknown phase and retain the
# lock; it must not feed `}}` to jq and mask the original failure.
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/scripts/ssm-read-optional.sh"
chmod +x "$WORK/.github/scripts/"*.sh "$WORK/scripts/ssm-read-optional.sh"

set +e
output=$(cd "$WORK" && AWS_REGION=us-east-2 GITHUB_SHA="$IMAGE" GITHUB_RUN_ID=77 \
  bash .github/scripts/run-durable-aop-cutover-under-lock.sh "$IMAGE" 2>&1)
rc=$?
set -e
[[ "$rc" == 1 ]] || { echo "wrapper rc=$rc, want classified cutover failure 1" >&2; exit 1; }
[[ "$output" == *"Retaining non-expiring durable AOP recovery lock"* ]]
[[ "$output" != *"parse error"* ]]

echo "run-durable-aop-cutover-under-lock: empty-state classification passed"
