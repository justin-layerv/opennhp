#!/usr/bin/env bash
# Prove that every assigned-cell server consumes the Authority colour selected
# by Control. Terraform materializes these alias ARNs into an S3 bootstrap
# object; the blue/green refresh then materializes that object into the active
# host env file and running container. All three layers must agree.

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <environment> <aws-account-id> [aws-region]" >&2
  exit 2
fi

ENVIRONMENT="$1"
AWS_ACCOUNT_ID="$2"
AWS_REGION_INPUT="${3:-us-east-2}"

if [[ ! "$ENVIRONMENT" =~ ^[a-z0-9-]+$ ]]; then
  echo "::error::environment must contain only lowercase letters, digits, and hyphens" >&2
  exit 2
fi
if [[ ! "$AWS_ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
  echo "::error::aws-account-id must be exactly 12 digits" >&2
  exit 2
fi
if [[ ! "$AWS_REGION_INPUT" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]]; then
  echo "::error::aws-region has an invalid shape" >&2
  exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VERIFY_ASG_INSTANCES_HEALTHY=${VERIFY_ASG_INSTANCES_HEALTHY:-"${SCRIPT_DIR}/verify-asg-instances-healthy.sh"}
INSTANCE_TIMEOUT_MINUTES=${INSTANCE_TIMEOUT_MINUTES:-4}

if [[ ! "$INSTANCE_TIMEOUT_MINUTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::INSTANCE_TIMEOUT_MINUTES must be a positive integer" >&2
  exit 2
fi

read_ssm() {
  local name="$1"
  local value
  if ! value=$(aws ssm get-parameter \
      --region "$AWS_REGION_INPUT" \
      --name "$name" \
      --query 'Parameter.Value' --output text); then
    echo "::error::Failed to read required SSM parameter ${name}." >&2
    return 1
  fi
  if [[ -z "$value" || "$value" == "None" ]]; then
    echo "::error::Required SSM parameter ${name} is empty." >&2
    return 1
  fi
  printf '%s' "$value"
}

AUTHORITY_COLOR=$(read_ssm "/${ENVIRONMENT}/nhp/control/authority/active-color")
if [[ "$AUTHORITY_COLOR" != "blue" && "$AUTHORITY_COLOR" != "green" ]]; then
  echo "::error::Authority active-color is '${AUTHORITY_COLOR}', expected blue or green." >&2
  exit 1
fi

# Closed inventory for the two assigned-cell roots deployed by build-and-push.
# Adding a cell requires adding its root/DAG edges and extending this list plus
# both maps; otherwise that new deployment is not eligible for this gate.
declare -a CELLS=("cell0" "cell1")
declare -A CELL_NAMESPACES=(
  [cell0]="$ENVIRONMENT"
  [cell1]="${ENVIRONMENT}-cell1"
)
declare -A CELL_BUCKETS=(
  [cell0]="layerv-nhp-${ENVIRONMENT}-plugins"
  [cell1]="layerv-nhp-${ENVIRONMENT}-cell1-plugins"
)
declare -A ALIAS_SUFFIXES=(
  [NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN]="iro"
  [NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN]="ar"
  [NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN]="cr"
  [NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN]="ccr"
  [NHP_CONNECTOR_RESOURCE_ALIAS_ARN]="creso"
)
declare -a ALIAS_KEYS=(
  NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN
  NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN
  NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN
  NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN
  NHP_CONNECTOR_RESOURCE_ALIAS_ARN
)

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

for cell_id in "${CELLS[@]}"; do
  namespace=${CELL_NAMESPACES[$cell_id]}
  bucket=${CELL_BUCKETS[$cell_id]}
  bootstrap_file="${tmp_dir}/${cell_id}-server-init.sh"

  if ! aws s3 cp \
      "s3://${bucket}/scripts/server-init.sh" "$bootstrap_file" \
      --region "$AWS_REGION_INPUT" --only-show-errors; then
    echo "::error::${cell_id} bootstrap object is unreadable." >&2
    exit 1
  fi

  runtime_command=""
  for key in "${ALIAS_KEYS[@]}"; do
    suffix=${ALIAS_SUFFIXES[$key]}
    expected="${key}=arn:aws:lambda:${AWS_REGION_INPUT}:${AWS_ACCOUNT_ID}:function:layerv-nhp-${ENVIRONMENT}-ca-${suffix}-${cell_id}:${AUTHORITY_COLOR}"
    mapfile -t bootstrap_assignments < <(grep -E "^${key}=" "$bootstrap_file" || true)

    if [[ ${#bootstrap_assignments[@]} -ne 1 ]]; then
      echo "::error::${cell_id} bootstrap has ${#bootstrap_assignments[@]} assignments for ${key}; expected exactly one selecting ${AUTHORITY_COLOR}." >&2
      exit 1
    fi
    if [[ "${bootstrap_assignments[0]}" != "$expected" ]]; then
      echo "::error::${cell_id} bootstrap does not select ${AUTHORITY_COLOR} for ${key}." >&2
      exit 1
    fi

    # The container env is authoritative for the process handling knocks. The
    # host file must also contain one unambiguous assignment so a container
    # restart cannot change the selection without an instance recycle.
    clause="test \$(grep -Ec '^${key}=' /opt/layerv/nhp-server/etc/env) -eq 1 && grep -Fqx '${expected}' /opt/layerv/nhp-server/etc/env && test \$(docker exec nhp-server env | grep -Ec '^${key}=') -eq 1 && docker exec nhp-server env | grep -Fqx '${expected}'"
    if [[ -n "$runtime_command" ]]; then
      runtime_command+=" && "
    fi
    runtime_command+="$clause"
  done

  server_color=$(read_ssm "/${namespace}/nhp/server/active-color")
  if [[ "$server_color" != "blue" && "$server_color" != "green" ]]; then
    echo "::error::${cell_id} server active-color is '${server_color}', expected blue or green." >&2
    exit 1
  fi
  active_asg=$(read_ssm "/${namespace}/nhp/server/${server_color}-asg-name")

  "$VERIFY_ASG_INSTANCES_HEALTHY" \
    "$active_asg" "AuthorityAlias-${cell_id}" "$INSTANCE_TIMEOUT_MINUTES" \
    "$runtime_command"
  echo "${cell_id}: bootstrap and every active runtime select Authority ${AUTHORITY_COLOR}"
done

FINAL_AUTHORITY_COLOR=$(read_ssm "/${ENVIRONMENT}/nhp/control/authority/active-color")
if [[ "$FINAL_AUTHORITY_COLOR" != "$AUTHORITY_COLOR" ]]; then
  echo "::error::Authority active-color changed from ${AUTHORITY_COLOR} to ${FINAL_AUTHORITY_COLOR} during consumer verification; refusing a mixed-time readback." >&2
  exit 1
fi

echo "Authority consumer convergence verified: pointer=${AUTHORITY_COLOR}, cells=${#CELLS[@]}"
