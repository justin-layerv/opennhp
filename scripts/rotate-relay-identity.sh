#!/usr/bin/env bash
# Guarded relay identity staging and promotion. This helper intentionally has no
# get-secret-value path: private key material remains inside Secrets Manager and
# the identity Lambda.

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  rotate-relay-identity.sh --environment ENV --region REGION status
  rotate-relay-identity.sh --environment ENV --region REGION sync-current
  rotate-relay-identity.sh --environment ENV --region REGION stage --token UUID
  rotate-relay-identity.sh --environment ENV --region REGION promote \
    --expected-current-id ID --expected-pending-id ID --confirm PROMOTE:ID
  rotate-relay-identity.sh --environment ENV --region REGION rollback \
    --expected-current-id ID --expected-previous-id ID --confirm ROLLBACK:ID

ENV must be sandbox or prod. Promotion is safe to retry after a partial failure.
USAGE
  exit 2
}

environment=""
region=""
token=""
expected_current_id=""
expected_pending_id=""
expected_previous_id=""
confirmation=""
action=""

while (($#)); do
  case "$1" in
    --environment) environment="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --token) token="${2:-}"; shift 2 ;;
    --expected-current-id) expected_current_id="${2:-}"; shift 2 ;;
    --expected-pending-id) expected_pending_id="${2:-}"; shift 2 ;;
    --expected-previous-id) expected_previous_id="${2:-}"; shift 2 ;;
    --confirm) confirmation="${2:-}"; shift 2 ;;
    status|sync-current|stage|promote|rollback)
      [[ -z "$action" ]] || usage
      action="$1"
      shift
      ;;
    *) usage ;;
  esac
done

[[ "$environment" =~ ^(sandbox|prod)$ ]] || { echo "ERROR: --environment must be sandbox or prod" >&2; exit 2; }
[[ "$region" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]] || { echo "ERROR: invalid --region" >&2; exit 2; }
[[ -n "$action" ]] || usage
command -v aws >/dev/null || { echo "ERROR: aws CLI is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 2; }

case "$action" in
  stage)
    [[ "$token" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || {
      echo "ERROR: stage requires --token with a UUIDv4" >&2
      exit 2
    }
    ;;
  promote)
    [[ -n "$expected_current_id" && -n "$expected_pending_id" ]] || {
      echo "ERROR: promote requires both expected version IDs" >&2
      exit 2
    }
    [[ "$expected_current_id" != "$expected_pending_id" ]] || {
      echo "ERROR: current and pending version IDs must differ" >&2
      exit 2
    }
    [[ "$confirmation" == "PROMOTE:${expected_pending_id}" ]] || {
      echo "ERROR: promotion requires --confirm PROMOTE:${expected_pending_id}" >&2
      exit 2
    }
    ;;
  rollback)
    [[ -n "$expected_current_id" && -n "$expected_previous_id" ]] || {
      echo "ERROR: rollback requires both expected version IDs" >&2
      exit 2
    }
    [[ "$expected_current_id" != "$expected_previous_id" ]] || {
      echo "ERROR: current and previous version IDs must differ" >&2
      exit 2
    }
    [[ "$confirmation" == "ROLLBACK:${expected_previous_id}" ]] || {
      echo "ERROR: rollback requires --confirm ROLLBACK:${expected_previous_id}" >&2
      exit 2
    }
    ;;
esac

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT INT TERM

account_id="$(aws sts get-caller-identity --query Account --output text)"
[[ "$account_id" =~ ^[0-9]{12}$ ]] || { echo "ERROR: invalid caller account" >&2; exit 1; }

secret_name="layerv-nhp-${environment}-relay"
function_name="layerv-nhp-${environment}-relay-keygen"
parameter_name="/${environment}/nhp/relay/identity/current-public-key"

secret_description="$(aws secretsmanager describe-secret --region "$region" --secret-id "$secret_name" --output json)"
secret_arn="$(jq -er '.ARN' <<<"$secret_description")"
actual_name="$(jq -er '.Name' <<<"$secret_description")"
[[ "$actual_name" == "$secret_name" ]] || { echo "ERROR: secret name mismatch" >&2; exit 1; }
[[ "$secret_arn" == "arn:aws:secretsmanager:${region}:${account_id}:secret:${secret_name}-"* ]] || {
  echo "ERROR: secret ARN account, region, or name mismatch" >&2
  exit 1
}

function_config="$(aws lambda get-function-configuration --region "$region" --function-name "$function_name" --output json)"
function_arn="$(jq -er '.FunctionArn' <<<"$function_config")"
[[ "$function_arn" == "arn:aws:lambda:${region}:${account_id}:function:${function_name}" ]] || {
  echo "ERROR: identity Lambda account, region, or name mismatch" >&2
  exit 1
}

invoke_identity() {
  local requested_action="$1"
  local requested_token="${2:-}"
  local payload_file="$tmp_dir/payload.json"
  local response_file="$tmp_dir/response.json"
  local metadata status_code error_file="$tmp_dir/lambda-invoke.err"

  jq -n \
    --arg action "$requested_action" \
    --arg secret "$secret_arn" \
    --arg env "$environment" \
    --arg parameter "$parameter_name" \
    --arg token "$requested_token" \
    '{Action:$action,ResourceProperties:{SecretId:$secret,Environment:$env,PublicKeyParameter:$parameter}} |
      if $token == "" then . else .ResourceProperties.ClientRequestToken = $token end' \
    >"$payload_file"

  # An SDK/client failure (including TooManyRequestsException) exits non-zero
  # before Lambda produces invocation metadata. Handle that separately from a
  # successful API call whose metadata contains FunctionError so operators are
  # never sent to inspect a response file that does not exist. Keep the raw AWS
  # error private: it is not needed to decide that no stage mutation is safe.
  if ! metadata="$(aws lambda invoke \
      --region "$region" \
      --function-name "$function_name" \
      --cli-binary-format raw-in-base64-out \
      --payload "fileb://${payload_file}" \
      "$response_file" 2>"$error_file")"; then
    echo "ERROR: unable to invoke identity Lambda (client/API error such as throttling); no Lambda response was processed" >&2
    return 1
  fi

  if ! status_code="$(jq -er '.StatusCode | select(type == "number")' <<<"$metadata")" || [[ "$status_code" != "200" ]]; then
    echo "ERROR: identity Lambda invocation did not return StatusCode 200" >&2
    return 1
  fi
  if [[ "$(jq -r '.FunctionError // empty' <<<"$metadata")" != "" ]]; then
    echo "ERROR: identity Lambda returned FunctionError" >&2
    return 1
  fi
  jq -e 'type == "object" and (.errorMessage | not)' "$response_file" >/dev/null || {
    echo "ERROR: invalid identity Lambda response" >&2
    return 1
  }
  jq -c . "$response_file"
}

read_published_key() {
  local value error_file="$tmp_dir/ssm-get-parameter.err" attempt

  # This read is a pre-mutation safety check. Absorb a bounded transient SSM
  # failure, but never retry an empty successful response and never proceed
  # after three failed reads. Promotion/rollback remain idempotent and fail
  # closed before changing any Secrets Manager stage.
  for attempt in 1 2 3; do
    if value="$(aws ssm get-parameter \
        --region "$region" \
        --name "$parameter_name" \
        --query 'Parameter.Value' \
        --output text 2>"$error_file")"; then
      if [[ -z "$value" || "$value" == "None" ]]; then
        echo "ERROR: public-key parameter $parameter_name returned an empty value; refusing to mutate identity stages" >&2
        return 1
      fi
      printf '%s' "$value"
      return 0
    fi
    if [[ "$attempt" -lt 3 ]]; then sleep "$((attempt * 3))"; fi
  done

  echo "ERROR: unable to read public-key parameter $parameter_name after 3 attempts; refusing to mutate identity stages" >&2
  return 1
}

case "$action" in
  status)
    invoke_identity status
    ;;
  sync-current)
    # Republish is deliberately non-generating: a missing AWSCURRENT is an
    # identity incident, not permission to mint a replacement.
    invoke_identity publish-current
    ;;
  stage)
    response="$(invoke_identity stage-pending "$token")"
    [[ "$(jq -r '.pendingVersionId' <<<"$response")" == "$token" ]] || {
      echo "ERROR: Lambda staged an unexpected version" >&2
      exit 1
    }
    jq -c . <<<"$response"
    ;;
  promote)
    status_json="$(invoke_identity status)"
    current_id="$(jq -r '.versions.AWSCURRENT.versionId // empty' <<<"$status_json")"
    pending_id="$(jq -r '.versions.AWSPENDING.versionId // empty' <<<"$status_json")"
    previous_id="$(jq -r '.versions.AWSPREVIOUS.versionId // empty' <<<"$status_json")"
    current_public_key="$(jq -r '.versions.AWSCURRENT.publicKey // empty' <<<"$status_json")"
    pending_public_key="$(jq -r '.versions.AWSPENDING.publicKey // empty' <<<"$status_json")"

    normal=false
    repair=false
    complete=false
    if [[ "$current_id" == "$expected_current_id" && "$pending_id" == "$expected_pending_id" ]]; then
      normal=true
    elif [[ "$current_id" == "$expected_pending_id" && "$previous_id" == "$expected_current_id" && "$pending_id" == "$expected_pending_id" ]]; then
      repair=true
    elif [[ "$current_id" == "$expected_pending_id" && "$previous_id" == "$expected_current_id" && -z "$pending_id" ]]; then
      complete=true
    else
      echo "ERROR: secret version topology does not match the expected promotion or repair state" >&2
      exit 1
    fi

    published_key="$(read_published_key)"
    if [[ "$normal" == true && "$published_key" != "$current_public_key" ]]; then
      echo "ERROR: public-key parameter does not match the expected current version" >&2
      exit 1
    fi
    if [[ "$complete" == true ]]; then
      [[ "$published_key" == "$current_public_key" ]] || {
        echo "ERROR: completed promotion has a stale public-key parameter" >&2
        exit 1
      }
      jq -n -c \
        --arg currentVersionId "$expected_pending_id" \
        --arg previousVersionId "$expected_current_id" \
        '{action:"promote",mode:"already-complete",currentVersionId:$currentVersionId,previousVersionId:$previousVersionId}'
      exit 0
    fi

    if [[ "$normal" == true ]]; then
      aws secretsmanager update-secret-version-stage \
        --region "$region" \
        --secret-id "$secret_arn" \
        --version-stage AWSCURRENT \
        --move-to-version-id "$expected_pending_id" \
        --remove-from-version-id "$expected_current_id" >/dev/null
    fi

    # In repair mode the new current key is returned under AWSCURRENT and under
    # AWSPENDING. In normal mode it is the pending public key.
    new_public_key="$pending_public_key"
    [[ -n "$new_public_key" ]] || new_public_key="$current_public_key"
    [[ -n "$new_public_key" ]] || { echo "ERROR: promoted public key is missing" >&2; exit 1; }

    aws ssm put-parameter \
      --region "$region" \
      --name "$parameter_name" \
      --type String \
      --value "$new_public_key" \
      --overwrite >/dev/null

    aws secretsmanager update-secret-version-stage \
      --region "$region" \
      --secret-id "$secret_arn" \
      --version-stage AWSPENDING \
      --remove-from-version-id "$expected_pending_id" >/dev/null

    jq -n -c \
      --arg currentVersionId "$expected_pending_id" \
      --arg previousVersionId "$expected_current_id" \
      --arg mode "$([[ "$repair" == true ]] && echo repair || echo promote)" \
      '{action:"promote",mode:$mode,currentVersionId:$currentVersionId,previousVersionId:$previousVersionId}'
    ;;
  rollback)
    status_json="$(invoke_identity status)"
    current_id="$(jq -r '.versions.AWSCURRENT.versionId // empty' <<<"$status_json")"
    previous_id="$(jq -r '.versions.AWSPREVIOUS.versionId // empty' <<<"$status_json")"
    current_public_key="$(jq -r '.versions.AWSCURRENT.publicKey // empty' <<<"$status_json")"
    previous_public_key="$(jq -r '.versions.AWSPREVIOUS.publicKey // empty' <<<"$status_json")"

    rollback_normal=false
    rollback_repair=false
    if [[ "$current_id" == "$expected_current_id" && "$previous_id" == "$expected_previous_id" ]]; then
      rollback_normal=true
      restored_public_key="$previous_public_key"
    elif [[ "$current_id" == "$expected_previous_id" && "$previous_id" == "$expected_current_id" ]]; then
      rollback_repair=true
      restored_public_key="$current_public_key"
    else
      echo "ERROR: secret version topology does not match the expected rollback or repair state" >&2
      exit 1
    fi
    [[ -n "$restored_public_key" ]] || { echo "ERROR: rollback public key is missing" >&2; exit 1; }

    published_key="$(read_published_key)"
    if [[ "$rollback_normal" == true && "$published_key" != "$current_public_key" ]]; then
      echo "ERROR: public-key parameter does not match the expected pre-rollback current version" >&2
      exit 1
    fi

    if [[ "$rollback_normal" == true ]]; then
      aws secretsmanager update-secret-version-stage \
        --region "$region" \
        --secret-id "$secret_arn" \
        --version-stage AWSCURRENT \
        --move-to-version-id "$expected_previous_id" \
        --remove-from-version-id "$expected_current_id" >/dev/null
    fi

    aws ssm put-parameter \
      --region "$region" \
      --name "$parameter_name" \
      --type String \
      --value "$restored_public_key" \
      --overwrite >/dev/null

    jq -n -c \
      --arg currentVersionId "$expected_previous_id" \
      --arg previousVersionId "$expected_current_id" \
      --arg mode "$([[ "$rollback_repair" == true ]] && echo repair || echo rollback)" \
      '{action:"rollback",mode:$mode,currentVersionId:$currentVersionId,previousVersionId:$previousVersionId}'
    ;;
esac
