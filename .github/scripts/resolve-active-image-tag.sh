#!/bin/bash
# Resolve the currently-active image tag for a blue/green-deployed NHP
# component, following the active-color → slot indirection.
#
# Single source of truth for the active-tag lookup, shared by:
#   - build-and-push.yml's "Resolve Image Tag" step (sandbox dispatcher)
#   - promote-to-prod.yml's "Gather sandbox state" step
#   - blue-green-deploy.yml's cross-component active-tag assertion
#   - scripts/trigger-prod-deploy.sh's sandbox state read (prod promotion helper)
#
# Any caller that reads /<env>/nhp/<component>/image-tag or
# /<env>/nhp/<component>/green-image-tag directly is reading a slot, not
# the active tag, and will return the wrong value whenever active-color
# is "green" (image-tag) or "blue" (green-image-tag).
#
# Usage: resolve-active-image-tag.sh <environment> <component>
#
# Arguments:
#   environment  — currently only "sandbox" (the only env using blue/green
#                  for nhp components today; prod uses canary on a single
#                  /image-tag slot and should read it directly).
#   component    — "server" or "ac".
#
# Stdout: the active image tag (a SHA, or whatever value is stored).
# Stderr: ::error:: annotations on failure.
#
# Exit codes:
#   0 — printed an active tag on stdout
#   1 — input validation, SSM read, or colour-validation failure

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <environment> <component>" >&2
  echo "  environment: sandbox" >&2
  echo "  component:   server | ac" >&2
  exit 1
fi

ENVIRONMENT="$1"
COMPONENT="$2"

if [[ "$ENVIRONMENT" != "sandbox" ]]; then
  echo "::error::resolve-active-image-tag.sh only supports sandbox today (got '$ENVIRONMENT'). Prod uses canary on /prod/nhp/<component>/image-tag — read that slot directly." >&2
  exit 1
fi

if [[ "$COMPONENT" != "server" && "$COMPONENT" != "ac" ]]; then
  echo "::error::Invalid component '$COMPONENT' (expected 'server' or 'ac')" >&2
  exit 1
fi

BASE="/${ENVIRONMENT}/nhp/${COMPONENT}"

if ! COLOR=$(aws ssm get-parameter \
    --name "${BASE}/active-color" \
    --query "Parameter.Value" --output text --no-cli-pager 2>&1); then
  echo "::error::Failed to read ${BASE}/active-color from SSM: $COLOR" >&2
  exit 1
fi

# Reject any value other than the two known good colours so a corrupted /
# partially-written / typo'd active-color cannot silently fall through to
# the green branch and resolve to the wrong tag.
if [[ "$COLOR" != "blue" && "$COLOR" != "green" ]]; then
  echo "::error::Unexpected ${BASE}/active-color value: '$COLOR' (expected 'blue' or 'green')" >&2
  exit 1
fi

# Legacy slot naming: blue tag lives at ${BASE}/image-tag, green tag at
# ${BASE}/green-image-tag. Mirrors blue-green-switch.sh and the
# server-state / ac-state steps of blue-green-deploy.yml.
if [[ "$COLOR" == "blue" ]]; then
  PARAM="${BASE}/image-tag"
else
  PARAM="${BASE}/green-image-tag"
fi

if ! TAG=$(aws ssm get-parameter \
    --name "$PARAM" \
    --query "Parameter.Value" --output text --no-cli-pager 2>&1); then
  echo "::error::Failed to read $PARAM from SSM: $TAG" >&2
  exit 1
fi

printf '%s' "$TAG"
