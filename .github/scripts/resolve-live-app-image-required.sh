#!/bin/bash
# Resolve live sandbox app image drift from SSM.
#
# This workflow-facing wrapper gathers the active server/AC tags plus the relay
# image tag when relay is deployed, then asks resolve-app-image-required.sh
# whether those live image tags contain the target SHA's app tree.
#
# Fail-closed by design: if active server/AC tag reads fail, or relay's SSM
# read fails with anything other than ParameterNotFound, the deploy stops rather
# than marking a commit deployed against unknown app bytes.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <environment> <head-sha>" >&2
  exit 1
fi

ENVIRONMENT="$1"
HEAD_SHA="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$ENVIRONMENT" != "sandbox" ]]; then
  echo "::error::resolve-live-app-image-required.sh only supports sandbox today (got '$ENVIRONMENT')." >&2
  exit 1
fi

# Deliberately fail closed without retrying SSM. If the deploy cannot prove the
# active tags from the source of truth, it must not guess; rerun after AWS/SSM
# recovers instead of stamping deployed-commit against unknown live bytes.
SERVER_TAG=$("$SCRIPT_DIR/resolve-active-image-tag.sh" "$ENVIRONMENT" server)
AC_TAG=$("$SCRIPT_DIR/resolve-active-image-tag.sh" "$ENVIRONMENT" ac)
TAG_ARGS=("server=$SERVER_TAG" "ac=$AC_TAG")

relay_err=$(mktemp)
trap 'rm -f "$relay_err"' EXIT
# Relay is single-slot today, not blue/green, so this SSM image-tag parameter is
# its live app-tag source. If relay gains blue/green slots, route this through
# active-slot resolution like server and AC. Future migration is tracked in
# https://github.com/layervai/nhp/issues/3105.
relay_param="/${ENVIRONMENT}/nhp/relay/image-tag"
if RELAY_TAG=$(aws ssm get-parameter \
    --name "$relay_param" \
    --query "Parameter.Value" --output text --no-cli-pager 2>"$relay_err"); then
  TAG_ARGS+=("relay=$RELAY_TAG")
elif grep -q "(ParameterNotFound)" "$relay_err"; then
  # AWS CLI stderr text is the only portable signal here. Keep the literal
  # parenthesized code and re-verify this classifier after an AWS CLI major bump.
  RELAY_TAG=""
  echo "::notice::Relay image-tag SSM parameter absent; relay is dark, so app-drift detection ignores relay."
else
  echo "::error::Unexpected SSM error reading $relay_param:"
  cat "$relay_err"
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  # The pre-build workflow job only promotes app_image_required, but the
  # post-switch deployment-tracking gate points GITHUB_OUTPUT at a temp file and
  # consumes these tags for its fail-red diagnostic.
  {
    echo "server_tag=$SERVER_TAG"
    echo "ac_tag=$AC_TAG"
    echo "relay_tag=$RELAY_TAG"
  } >> "$GITHUB_OUTPUT"
fi

"$SCRIPT_DIR/resolve-app-image-required.sh" "$HEAD_SHA" "${TAG_ARGS[@]}"
