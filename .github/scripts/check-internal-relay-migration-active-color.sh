#!/usr/bin/env bash
# Refuse the first internal-relay per-color TG migration while server active-color
# is green. In that state the live internal listener still points at the retained
# blue TG until a blue/green switch runs, while the apply would re-home green to
# its new TG. That transiently recreates standby relay routing.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <environment> <terraform-plan-json>" >&2
  exit 64
fi

ENVIRONMENT="$1"
PLAN_JSON="$2"
AWS_REGION="${AWS_REGION:-us-east-2}"

if [[ ! -f "$PLAN_JSON" ]]; then
  echo "::error::Terraform plan JSON not found: $PLAN_JSON" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "::error::jq is required to inspect Terraform plan JSON" >&2
  exit 1
fi

if ! jq -e '
  any(.resource_changes[]?;
    (.address | endswith("aws_lb_target_group.udp_internal_green[0]")) and
    ((.change.actions // []) | index("create") != null)
  )
' "$PLAN_JSON" >/dev/null; then
  echo "::notice::No green internal relay target-group create/replace in this plan; active-color migration guard not needed."
  exit 0
fi

ACTIVE_PARAM="/${ENVIRONMENT}/nhp/server/active-color"
ACTIVE_COLOR=$(aws ssm get-parameter \
  --region "$AWS_REGION" \
  --name "$ACTIVE_PARAM" \
  --query "Parameter.Value" \
  --output text 2>/dev/null || true)

if [[ -z "$ACTIVE_COLOR" || "$ACTIVE_COLOR" == "None" ]]; then
  echo "::notice::$ACTIVE_PARAM is absent/empty while creating the green internal relay TG; treating this as a greenfield blue/green apply, not a live green-active migration."
  exit 0
fi

case "$ACTIVE_COLOR" in
  blue)
    echo "::notice::Internal relay migration guard passed: $ACTIVE_PARAM is blue before creating/replacing the green internal relay TG."
    ;;
  green)
    cat >&2 <<EOF
::error::Refusing to apply the internal relay per-color TG migration while $ACTIVE_PARAM is green.
The plan creates/replaces aws_lb_target_group.udp_internal_green[0], but the retained
internal relay listener still points at the blue TG until the switch workflow runs.
Apply while active-color=blue, or first run a server blue/green switch so the live
listener and active-color are not split during the migration.
EOF
    exit 1
    ;;
  *)
    echo "::error::$ACTIVE_PARAM has unexpected value '$ACTIVE_COLOR' (want blue or green); refusing the internal relay TG migration." >&2
    exit 1
    ;;
esac
