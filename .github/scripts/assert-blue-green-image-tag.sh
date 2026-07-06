#!/bin/bash
# Assert that a blue/green component's SSM slot resolves to the requested image
# tag before blue-green-deploy.yml reports success.
#
# Usage: assert-blue-green-image-tag.sh <environment> <component> <active|standby> <expected-tag>

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <environment> <component> <active|standby> <expected-tag>" >&2
  echo "  environment: sandbox" >&2
  echo "  component:   server | ac" >&2
  echo "  slot:        active | standby" >&2
  exit 1
fi

ENVIRONMENT="$1"
COMPONENT="$2"
SLOT="$3"
EXPECTED_TAG="$4"

case "$COMPONENT" in
  server)
    LABEL="Server"
    ;;
  ac)
    LABEL="AC"
    ;;
  *)
    echo "::error::Invalid component '$COMPONENT' (expected 'server' or 'ac')" >&2
    exit 1
    ;;
esac

case "$SLOT" in
  active|standby)
    ;;
  *)
    echo "::error::Invalid slot '$SLOT' (expected 'active' or 'standby')" >&2
    exit 1
    ;;
esac

if [[ "$ENVIRONMENT" != "sandbox" ]]; then
  echo "::notice::${LABEL} ${SLOT}-slot assertion skipped (env=$ENVIRONMENT; sandbox is the only environment using blue/green slot indirection today)."
  exit 0
fi

if [[ -z "$EXPECTED_TAG" ]]; then
  echo "::error::${LABEL} target image tag is empty; Validate Inputs should have failed earlier." >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESOLVER="${RESOLVE_ACTIVE_IMAGE_TAG_SCRIPT:-$SCRIPT_DIR/resolve-active-image-tag.sh}"

ACTUAL_TAG=$("$RESOLVER" "$ENVIRONMENT" "$COMPONENT" "$SLOT")

echo "$COMPONENT expected $SLOT tag: $EXPECTED_TAG"
echo "$COMPONENT resolved $SLOT tag: $ACTUAL_TAG"

if [[ "$ACTUAL_TAG" != "$EXPECTED_TAG" ]]; then
  if [[ "$SLOT" == "active" ]]; then
    REMEDIATION="Traffic may already be switched; inspect /${ENVIRONMENT}/nhp/${COMPONENT}/active-color and the matching {,green-}image-tag slot before re-running blue-green-deploy.yml for component=${COMPONENT}."
  else
    REMEDIATION="Traffic has not been switched by this assertion; inspect /${ENVIRONMENT}/nhp/${COMPONENT}/active-color and the standby {,green-}image-tag slot before re-running blue-green-deploy.yml for component=${COMPONENT}."
  fi
  echo "::error::${LABEL} ${SLOT} tag ($ACTUAL_TAG) != target tag ($EXPECTED_TAG). Refusing to report blue/green success against stale app bytes. $REMEDIATION" >&2
  exit 1
fi
