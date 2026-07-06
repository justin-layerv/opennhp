#!/usr/bin/env bash
# Fail closed unless live active app image tags contain the target app tree.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <environment> <target-sha>" >&2
  exit 2
fi

ENVIRONMENT="$1"
TARGET_SHA="$2"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESOLVE_LIVE_APP_IMAGE_REQUIRED="${RESOLVE_LIVE_APP_IMAGE_REQUIRED:-$SCRIPT_DIR/resolve-live-app-image-required.sh}"

DRIFT_OUT=$(mktemp)
trap 'rm -f "$DRIFT_OUT"' EXIT

GITHUB_OUTPUT="$DRIFT_OUT" "$RESOLVE_LIVE_APP_IMAGE_REQUIRED" "$ENVIRONMENT" "$TARGET_SHA"
if grep -q '^app_image_required=true$' "$DRIFT_OUT"; then
  SERVER_TAG=$(sed -n 's/^server_tag=//p' "$DRIFT_OUT")
  AC_TAG=$(sed -n 's/^ac_tag=//p' "$DRIFT_OUT")
  RELAY_TAG=$(sed -n 's/^relay_tag=//p' "$DRIFT_OUT")
  echo "::error::Refusing to update /$ENVIRONMENT/nhp/deploy/deployed-commit to $TARGET_SHA because one or more live app image tags still lag app changes through that SHA."
  echo "::error::server active tag: $SERVER_TAG"
  echo "::error::ac active tag:     $AC_TAG"
  if [[ -n "${RELAY_TAG:-}" ]]; then
    echo "::error::relay image tag:  $RELAY_TAG"
  fi
  exit 1
fi

echo "::notice::Live $ENVIRONMENT app image tags contain app tree for $TARGET_SHA."
