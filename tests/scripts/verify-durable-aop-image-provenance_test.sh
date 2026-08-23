#!/usr/bin/env bash
# shellcheck disable=SC2016 # Fake scripts intentionally retain runtime variables.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/verify-durable-aop-image-provenance.sh"
IMAGE=0123456789012345678901234567890123456789
DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
export FAKE_ARGS="$WORK/args" FAKE_DIGEST="$DIGEST"
: >"$FAKE_ARGS"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '
case "$1/$2" in
  sts/get-caller-identity) printf "123456789012\n" ;;
  ecr/describe-images) printf "%s\n" "$FAKE_DIGEST" ;;
  ecr/get-login-password) printf "password\n" ;;
  *) exit 99 ;;
esac' >"$WORK/bin/aws"
printf '%s\n' '#!/usr/bin/env bash' 'cat >/dev/null' >"$WORK/bin/docker"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" >>"$FAKE_ARGS"; printf "[{}]\n"' >"$WORK/bin/gh"
chmod +x "$WORK/bin/aws" "$WORK/bin/docker" "$WORK/bin/gh"

record=$(PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
  "$SCRIPT" layerv/nhp-server "$IMAGE")
[[ "$record" == "v1|${IMAGE}|layerv/nhp-server|${DIGEST}" ]]
args=$(cat "$FAKE_ARGS")
[[ "$args" == *"--source-digest $IMAGE"* ]]
[[ "$args" == *"--source-ref refs/heads/main"* ]]
[[ "$args" == *"build-and-push.yml@refs/heads/main"* ]]

# A legacy image can be manually labeled durable in SSM, but cannot produce
# an exact source-bound signed provenance result.
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$WORK/bin/gh"
if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
    "$SCRIPT" layerv/nhp-server "$IMAGE" >/dev/null 2>&1; then
  echo "unverified legacy image was accepted as durable" >&2
  exit 1
fi

echo "verify-durable-aop-image-provenance: all tests passed"
