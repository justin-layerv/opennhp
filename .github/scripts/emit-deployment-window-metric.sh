#!/usr/bin/env bash
# Emit a short-lived deploy-window breadcrumb used by the revocation aged-out
# composite alarm. Keep dimensions to {Environment, Cell} so the alarm matches
# the nhp-server publisher's base stream exactly.
#
# Component and strategy are log-only breadcrumbs. Do not add them as dimensions:
# the CloudWatch alarm must remain keyed only by {Environment, Cell}.

emit_deployment_window_metric() {
  local environment="${1:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local cell_id="${2:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local component="${3:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local strategy="${4:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"

  DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED=0
  export DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED

  if ! aws cloudwatch put-metric-data \
    --cli-connect-timeout 5 \
    --cli-read-timeout 10 \
    --namespace "LayerV/NHP" \
    --metric-name "DeploymentWindow" \
    --dimensions Name=Environment,Value="$environment" Name=Cell,Value="$cell_id" \
    --value 1 \
    --unit Count; then
    echo "::warning::Failed to push DeploymentWindow metric (Environment=$environment Cell=$cell_id Component=$component Strategy=$strategy); continuing"
    return 0
  fi

  DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED=1
  export DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED
  echo "DeploymentWindow metric pushed (Environment=$environment Cell=$cell_id Component=$component Strategy=$strategy)"
}

emit_deployment_window_metric_throttled() {
  local environment="${DEPLOYMENT_WINDOW_ENVIRONMENT:-}"
  local cell_id="${DEPLOYMENT_WINDOW_CELL_ID:-}"
  local component="${DEPLOYMENT_WINDOW_COMPONENT:-}"
  local strategy="${DEPLOYMENT_WINDOW_STRATEGY:-}"
  local interval="${DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS:-60}"
  local last_emit="${DEPLOYMENT_WINDOW_LAST_EMIT_SECONDS:-0}"
  local last_emit_monotonic="${DEPLOYMENT_WINDOW_LAST_EMIT_MONOTONIC_SECONDS:-}"
  local last_emit_clock="${DEPLOYMENT_WINDOW_LAST_EMIT_CLOCK:-}"
  local now_seconds now_monotonic
  local throttle_clock=""
  local configured_count=0

  [[ -n "$environment" ]] && ((configured_count += 1))
  [[ -n "$cell_id" ]] && ((configured_count += 1))
  [[ -n "$component" ]] && ((configured_count += 1))
  [[ -n "$strategy" ]] && ((configured_count += 1))

  if ((configured_count == 0)); then
    return 0
  fi
  if ((configured_count < 4)); then
    if [[ "${DEPLOYMENT_WINDOW_PARTIAL_ENV_WARNED:-0}" != "1" ]]; then
      echo "::warning::DeploymentWindow heartbeat partially configured; set DEPLOYMENT_WINDOW_ENVIRONMENT, DEPLOYMENT_WINDOW_CELL_ID, DEPLOYMENT_WINDOW_COMPONENT, and DEPLOYMENT_WINDOW_STRATEGY to enable long-poll suppression"
      DEPLOYMENT_WINDOW_PARTIAL_ENV_WARNED=1
      export DEPLOYMENT_WINDOW_PARTIAL_ENV_WARNED
    fi
    return 0
  fi
  if [[ ! "$interval" =~ ^[0-9]+$ ]] || ((interval < 1)); then
    interval=60
  fi
  if [[ ! "$last_emit" =~ ^[0-9]+$ ]]; then
    last_emit=0
  fi

  if now_seconds=$(date +%s); then
    now_monotonic="${SECONDS:-0}"
    if [[ "$last_emit_clock" == "monotonic" && "$last_emit_monotonic" =~ ^[0-9]+$ ]] && ((now_monotonic - last_emit_monotonic < interval)); then
      return 0
    fi
    if ((now_seconds - last_emit < interval)); then
      return 0
    fi
    throttle_clock="epoch"
  else
    echo "::warning::date +%s failed while throttling DeploymentWindow heartbeat; using shell monotonic fallback"
    now_monotonic="${SECONDS:-0}"
    if [[ ! "$last_emit_monotonic" =~ ^[0-9]+$ ]]; then
      last_emit_monotonic=$((now_monotonic - interval))
    fi
    if ((now_monotonic - last_emit_monotonic < interval)); then
      return 0
    fi
    throttle_clock="monotonic"
  fi

  emit_deployment_window_metric "$environment" "$cell_id" "$component" "$strategy"
  if [[ "${DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED:-0}" == "1" ]]; then
    if [[ "$throttle_clock" == "epoch" ]]; then
      DEPLOYMENT_WINDOW_LAST_EMIT_SECONDS="$now_seconds"
      DEPLOYMENT_WINDOW_LAST_EMIT_MONOTONIC_SECONDS="${SECONDS:-0}"
      DEPLOYMENT_WINDOW_LAST_EMIT_CLOCK="epoch"
      export DEPLOYMENT_WINDOW_LAST_EMIT_SECONDS DEPLOYMENT_WINDOW_LAST_EMIT_MONOTONIC_SECONDS DEPLOYMENT_WINDOW_LAST_EMIT_CLOCK
    else
      DEPLOYMENT_WINDOW_LAST_EMIT_MONOTONIC_SECONDS="$now_monotonic"
      DEPLOYMENT_WINDOW_LAST_EMIT_CLOCK="monotonic"
      export DEPLOYMENT_WINDOW_LAST_EMIT_MONOTONIC_SECONDS DEPLOYMENT_WINDOW_LAST_EMIT_CLOCK
    fi
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  emit_deployment_window_metric "$@"
fi
