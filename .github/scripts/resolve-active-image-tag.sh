#!/bin/bash
# Resolve an active or standby image tag for a blue/green-deployed NHP
# component, following the active-color → slot indirection.
#
# Single source of truth for the blue/green tag lookup, shared by:
#   - build-and-push.yml's "Resolve Image Tag" step (sandbox dispatcher)
#   - promote-to-prod.yml's "Gather sandbox state" step
#   - blue-green-deploy.yml's per-component slot assertions
#   - scripts/trigger-prod-deploy.sh's sandbox state read (prod promotion helper)
#
# Any caller that reads /<env>/nhp/<component>/image-tag or
# /<env>/nhp/<component>/green-image-tag directly is reading a slot, not
# the logical active/standby tag, and will return the wrong value whenever
# active-color is "green" (image-tag) or "blue" (green-image-tag).
#
# Usage: resolve-active-image-tag.sh <environment> <component> [active|standby]
#
# Arguments:
#   environment  — an *infrastructure* namespace using blue/green: "sandbox"
#                  (cell0) or "sandbox-cell1" (cell1). These are the terraform
#                  `environment` values, which is what /<env>/nhp/... SSM paths
#                  are keyed on — NOT the protocol environment (both sandbox
#                  cells share protocol environment "sandbox"). Prod uses
#                  canary on a single /image-tag slot and should read it
#                  directly.
#   component    — "server" or "ac". cell1 is server-only.
#   slot         — optional logical slot, "active" (default) or "standby".
#
# Stdout: the requested logical image tag (a SHA, or whatever value is stored).
# Stderr: ::error:: annotations on failure.
#
# Exit codes:
#   0 — printed a tag on stdout
#   1 — input validation, SSM read, or colour-validation failure

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <environment> <component> [active|standby]" >&2
  echo "  environment: sandbox | sandbox-cell1" >&2
  echo "  component:   server | ac" >&2
  echo "  slot:        active | standby (default: active)" >&2
  exit 1
fi

ENVIRONMENT="$1"
COMPONENT="$2"
SLOT="${3:-active}"

# Allowlist, not a prefix match: these are the two infrastructure namespaces
# that actually publish /<env>/nhp/<component>/active-color. Keep it in
# lockstep with the cell allowlist in blue-green-deploy.yml's
# "Validate Cell Identifier" step.
if [[ "$ENVIRONMENT" != "sandbox" && "$ENVIRONMENT" != "sandbox-cell1" ]]; then
  echo "::error::resolve-active-image-tag.sh supports sandbox (cell0) and sandbox-cell1 (cell1) today (got '$ENVIRONMENT'). Prod uses canary on /prod/nhp/<component>/image-tag — read that slot directly." >&2
  exit 1
fi

# cell1 is a server-only cell: it has no /sandbox-cell1/nhp/ac/* parameters,
# so an "ac" lookup there would fail deep in the SSM read with a confusing
# ParameterNotFound instead of naming the real problem.
if [[ "$ENVIRONMENT" == "sandbox-cell1" && "$COMPONENT" == "ac" ]]; then
  echo "::error::sandbox-cell1 (cell1) has no AC fleet — only component=server is valid there." >&2
  exit 1
fi

if [[ "$COMPONENT" != "server" && "$COMPONENT" != "ac" ]]; then
  echo "::error::Invalid component '$COMPONENT' (expected 'server' or 'ac')" >&2
  exit 1
fi

if [[ "$SLOT" != "active" && "$SLOT" != "standby" ]]; then
  echo "::error::Invalid slot '$SLOT' (expected 'active' or 'standby')" >&2
  exit 1
fi

BASE="/${ENVIRONMENT}/nhp/${COMPONENT}"

# Scratch file holding one read's stderr. Kept separate from the value rather
# than merged with 2>&1: the AWS CLI can emit a deprecation or
# credential-source warning on an otherwise-successful call, and merging the two
# splices that warning into the value. A polluted colour then fails the
# blue/green check below as "Unexpected active-color", failing the deploy over a
# parameter that is perfectly healthy — and a polluted tag propagates a
# non-existent image tag to the caller.
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

# ssm_error — the API error from the last read, not whatever the CLI happened to
# print first. Those same warnings are emitted at TLS/import time, ahead of the
# error line, so `head -1` would report the warning and drop the actual cause.
ssm_error() {
  grep -m1 'An error occurred' "$ERR_FILE" || tail -1 "$ERR_FILE"
}

if ! COLOR=$(aws ssm get-parameter \
    --name "${BASE}/active-color" \
    --query "Parameter.Value" --output text --no-cli-pager 2>"$ERR_FILE"); then
  echo "::error::Failed to read ${BASE}/active-color from SSM: $(ssm_error)" >&2
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
case "${SLOT}:${COLOR}" in
  active:blue|standby:green)
    PARAM="${BASE}/image-tag"
    ;;
  active:green|standby:blue)
    PARAM="${BASE}/green-image-tag"
    ;;
esac

if ! TAG=$(aws ssm get-parameter \
    --name "$PARAM" \
    --query "Parameter.Value" --output text --no-cli-pager 2>"$ERR_FILE"); then
  echo "::error::Failed to read $PARAM from SSM: $(ssm_error)" >&2
  exit 1
fi

printf '%s' "$TAG"
