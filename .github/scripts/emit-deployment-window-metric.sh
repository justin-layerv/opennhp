#!/usr/bin/env bash
# Emit a short-lived deploy-window breadcrumb used by the revocation aged-out
# composite alarm. Keep dimensions to {Environment, Cell} so the alarm matches
# the nhp-server publisher's base stream exactly.
#
# Component and strategy are log-only breadcrumbs. Do not add them as dimensions:
# the CloudWatch alarm must remain keyed only by {Environment, Cell}.

if [[ -n "${DEPLOYMENT_WINDOW_METRIC_NAMESPACE+x}" &&
      "$DEPLOYMENT_WINDOW_METRIC_NAMESPACE" != "LayerV/NHP/Deploy" ]]; then
  echo "ERROR: DEPLOYMENT_WINDOW_METRIC_NAMESPACE has unexpected authority '$DEPLOYMENT_WINDOW_METRIC_NAMESPACE'" >&2
  if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 1
  fi
  exit 1
fi
if [[ -z "${DEPLOYMENT_WINDOW_METRIC_NAMESPACE+x}" ]]; then
  DEPLOYMENT_WINDOW_METRIC_NAMESPACE="LayerV/NHP/Deploy"
fi
# The refresh helper is sourced once per fleet by attended recovery. Re-marking
# an existing exact value readonly is idempotent; assigning to an existing
# readonly variable is not. A caller-provided exact mutable value is sealed here.
readonly DEPLOYMENT_WINDOW_METRIC_NAMESPACE

emit_deployment_window_metric() {
  local environment="${1:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local cell_id="${2:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local component="${3:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"
  local strategy="${4:?Usage: emit_deployment_window_metric <environment> <cell-id> <component> <strategy>}"

  DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED=0
  export DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED

  # Re-emit DeploymentWindowRun on every heartbeat so each 60s bucket is
  # self-pairing; the orphan watchdog only trips when the companion is absent.
  if ! aws cloudwatch put-metric-data \
    --cli-connect-timeout 5 \
    --cli-read-timeout 10 \
    --namespace "$DEPLOYMENT_WINDOW_METRIC_NAMESPACE" \
    --metric-data \
    "MetricName=DeploymentWindow,Dimensions=[{Name=Environment,Value=${environment}},{Name=Cell,Value=${cell_id}}],Value=1,Unit=Count" \
    "MetricName=DeploymentWindowRun,Dimensions=[{Name=Environment,Value=${environment}},{Name=Cell,Value=${cell_id}}],Value=1,Unit=Count"; then
    echo "::warning::Failed to push DeploymentWindow/DeploymentWindowRun metrics (Environment=$environment Cell=$cell_id Component=$component Strategy=$strategy); continuing"
    return 0
  fi

  DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED=1
  export DEPLOYMENT_WINDOW_LAST_PUT_SUCCEEDED
  echo "DeploymentWindow/DeploymentWindowRun metrics pushed (Environment=$environment Cell=$cell_id Component=$component Strategy=$strategy)"
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
