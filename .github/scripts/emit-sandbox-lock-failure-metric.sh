#!/usr/bin/env bash
# Best-effort CloudWatch signal for a fail-closed sandbox lock condition.
set -uo pipefail

reason="${1:-}"
action="${2:-}"
region="${AWS_REGION:-}"

# Validate the region here even though ssm-live-env-lock.sh also does so: this
# helper is a standalone entrypoint used directly by workflow retention steps.
if [[ -z "$region" ]]; then
  echo "::error::AWS_REGION must be set before publishing a sandbox lock failure metric" >&2
  exit 2
fi
sanitize_actions_detail() {
  local detail="$1"

  # Keep the warning a single bounded workflow command even when the AWS CLI
  # emits multi-line diagnostics. Escape percent before applying the output
  # bound, then remove any partial %25 sequence left at the truncation edge.
  # The 1000-character bound sizes only this GitHub annotation payload; it is
  # unrelated to the 1024-character CloudWatch dimension-value ceiling the
  # reason guard enforces below.
  detail="${detail//$'\r'/ }"
  detail="${detail//$'\n'/ }"
  detail="${detail//%/%25}"
  detail="${detail:0:1000}"
  case "$detail" in
    *%2) detail="${detail%??}" ;;
    *%) detail="${detail%?}" ;;
  esac
  printf '%s' "$detail"
}

publish_metric() {
  local stream="$1"
  local metric_err
  local event_context=""
  shift

  # Metric publication must never weaken the primary fail-closed path. Each
  # stream is attempted independently, even when the other publication fails.
  if ! metric_err="$(aws cloudwatch put-metric-data \
    --region "$region" \
    --namespace "LayerV/QURLServiceCI" \
    --metric-name "SandboxLiveEnvLockFailure" \
    "$@" \
    --value 1 \
    --unit Count 2>&1 >/dev/null)"; then
    metric_err="$(sanitize_actions_detail "$metric_err")"
    # The alarm stream runs before diagnostic values are validated. Never put
    # those untrusted values into its Actions workflow command. The diagnostic
    # stream is called only after both values pass the guards below.
    if [[ "$stream" == "diagnostic" ]]; then
      event_context=" reason=$reason action=$action"
    fi
    echo "::warning title=Sandbox live-environment lock metric publish failed::Failed to publish SandboxLiveEnvLockFailure stream=$stream$event_context; continuing with fail-closed lock handling. AWS error: $metric_err" >&2
  fi
  return 0
}

# The zero-dimension series is the stable alarm target even when a future
# vendored caller violates the diagnostic contract. Region validation remains
# first so an empty region cannot trigger an ambient-region AWS call.
publish_metric "alarm"

# Reason and action are cross-repo diagnostic dimension contracts. Keep reason
# alphanumeric so vendored callers cannot inject comma- or equals-delimited
# dimensions into map shorthand; every new reason requires an explicit code and
# test update. Invalid diagnostic values fail after the alarm attempt and before
# the dimensioned call.
if (( ${#reason} < 1 || ${#reason} > 1024 )) || [[ ! "$reason" =~ ^[A-Za-z][A-Za-z0-9]*$ ]]; then
  echo "::error::sandbox lock metric reason must match ^[A-Za-z][A-Za-z0-9]*$ and be 1-1024 characters" >&2
  exit 2
fi
if [[ "$action" != "acquire" && "$action" != "release" ]]; then
  echo "::error::sandbox lock metric action must be acquire or release" >&2
  exit 2
fi

# The diagnostic series preserves exact Reason/Action attribution.
publish_metric "diagnostic" --dimensions "Reason=$reason,Action=$action"
