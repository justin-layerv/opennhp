"""
Status aggregator Lambda function.

Reads target group health from ELBv2 and alarm state from CloudWatch.
Returns a redacted public JSON summary suitable for API Gateway proxy
integration. Do not return deployment metadata, infrastructure identifiers,
alarm names, service names, or operational metric details from this public
endpoint.
"""

import json
import os
import time
import traceback
from datetime import datetime, timezone

import boto3

# Module-level clients for Lambda warm-start reuse
elbv2 = boto3.client("elbv2")
cloudwatch = boto3.client("cloudwatch")

# CORS allows all origins intentionally: the API contract below is a redacted
# public status summary. Restricting to the CloudFront domain would create a
# circular dependency because the CloudFront domain is not known when the module
# is first deployed.
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Content-Type": "application/json",
}
CACHE_TTL_SECONDS = 30
_STATUS_CACHE = {"expires_at": 0.0, "body": None}
# Legacy token fallbacks support bare ALARM_NAME_PREFIX deployments. Current
# Terraform passes explicit server/ac-owned prefixes, so prefix ownership wins.
SERVER_ALARM_TOKENS = (
    "-server-",
    "-canary-server-",
    "-green-",
    "-srv-int-",
    "-no-healthy-hosts",
    "-unhealthy-hosts",
    "-high-cpu",
    "-high-latency",
    "-low-instances",
    "-network-in-low",
    "-storage-health",
    "-tcp-resets",
)
AC_ALARM_TOKENS = (
    "-ac-",
    "-canary-ac-",
)
CELL_AC_ALARM_TOKENS = (
    # Keep in sync with cell-prefixed AC-impact alarms in terraform/modules/monitoring;
    # add new cell-scoped AC alarm suffixes here or move them under an AC-owned prefix.
    "-ac-peer-count-low",
    "-ac-registration-latency",
)
TRANSITIONAL_TARGET_STATES = {"draining", "initial", "unused"}


def handler(event, context):
    """Lambda entry point (API Gateway HTTP API v2.0 proxy integration)."""
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod", ""))
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body = _get_cached_status()
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps(body),
        }
    except Exception:
        print(f"ERROR: {traceback.format_exc()}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Internal server error"}),
        }


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _get_cached_status():
    """
    Return a short-lived per-container cache to reduce public Describe calls.

    The cache intentionally includes unknown/degraded results and their original
    timestamp; the status page accepts up to CACHE_TTL_SECONDS of staleness.
    """
    now = time.time()
    if _STATUS_CACHE["body"] is not None and now < _STATUS_CACHE["expires_at"]:
        return _STATUS_CACHE["body"]

    body = build_status()
    _STATUS_CACHE["body"] = body
    _STATUS_CACHE["expires_at"] = now + CACHE_TTL_SECONDS
    return body


def build_status():
    environment = os.environ.get("ENVIRONMENT", "unknown")
    alarm_prefixes = _parse_csv(os.environ.get("ALARM_NAME_PREFIXES", ""))
    if not alarm_prefixes:
        alarm_prefixes = _parse_csv(os.environ.get("ALARM_NAME_PREFIX", ""))
    server_alarm_prefixes = _parse_csv(os.environ.get("SERVER_ALARM_PREFIXES", ""))
    ac_alarm_prefixes = _parse_csv(os.environ.get("AC_ALARM_PREFIXES", ""))

    server_tg_arns = _parse_csv(os.environ.get("SERVER_NLB_TG_ARNS", ""))
    ac_tg_arns = _parse_csv(os.environ.get("AC_NLB_TG_ARNS", ""))

    server_health = _aggregate_target_health(server_tg_arns)
    ac_health = _aggregate_target_health(ac_tg_arns)

    alarms = _get_alarm_summary(alarm_prefixes, server_alarm_prefixes, ac_alarm_prefixes)

    server = _build_component(server_health, alarms["server_active"])
    ac = _build_component(ac_health, alarms["ac_active"])

    return {
        "environment": environment,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "components": {
            "server": server,
            "ac": ac,
        },
        # Coarse counts are the only public alarm signal; names and reasons stay private.
        "alarms": {
            "active_count": alarms["active_count"],
            "ok_count": alarms["ok_count"],
        },
    }


# ---------------------------------------------------------------------------
# Target group health
# ---------------------------------------------------------------------------

def _aggregate_target_health(tg_arns):
    """Return aggregate target health counts from a single pass of API calls."""
    agg_healthy = 0
    agg_unhealthy = 0
    agg_total = 0
    described = 0
    errors = 0

    for arn in tg_arns:
        tg_healthy = 0
        tg_unhealthy = 0
        tg_total = 0
        try:
            resp = elbv2.describe_target_health(TargetGroupArn=arn)
            described += 1
            for desc in resp.get("TargetHealthDescriptions", []):
                tg_total += 1
                state = desc.get("TargetHealth", {}).get("State", "")
                if state == "healthy":
                    tg_healthy += 1
                elif state not in TRANSITIONAL_TARGET_STATES:
                    tg_unhealthy += 1
        except Exception:
            errors += 1
            print(f"WARN: Failed to describe target health for {arn}: {traceback.format_exc()}")

        agg_healthy += tg_healthy
        agg_unhealthy += tg_unhealthy
        agg_total += tg_total

    return {
        "healthy": agg_healthy,
        "unhealthy": agg_unhealthy,
        "total": agg_total,
        "configured": len(tg_arns),
        "described": described,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# CloudWatch alarms
# ---------------------------------------------------------------------------

def _get_alarm_summary(prefixes, server_prefixes=None, ac_prefixes=None):
    """Return alarm counts and component-impact flags without alarm details."""
    summary = {
        "active_count": 0,
        "ok_count": 0,
        "server_active": False,
        "ac_active": False,
    }

    if isinstance(prefixes, str):
        prefixes = _parse_csv(prefixes)
    if isinstance(server_prefixes, str):
        server_prefixes = _parse_csv(server_prefixes)
    if isinstance(ac_prefixes, str):
        ac_prefixes = _parse_csv(ac_prefixes)

    if not prefixes:
        return summary

    seen_alarm_names = set()
    server_prefixes = {prefix.lower() for prefix in (server_prefixes or [])}
    ac_prefixes = {prefix.lower() for prefix in (ac_prefixes or [])}
    # Prefix ownership wins after alarm-name dedupe, so keep server/AC prefix
    # families disjoint. Legacy token fallback handles old single-prefix config.

    def _record_alarm(name, state, prefix):
        if name in seen_alarm_names:
            return
        seen_alarm_names.add(name)

        is_active = state == "ALARM"
        if is_active:
            summary["active_count"] += 1
            lower_name = name.lower()
            component = _component_for_alarm_name(
                lower_name,
                prefix.lower(),
                server_prefixes,
                ac_prefixes,
            )
            if component == "server":
                summary["server_active"] = True
            elif component == "ac":
                summary["ac_active"] = True
        else:
            summary["ok_count"] += 1

    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for prefix in prefixes:
            for page in paginator.paginate(AlarmNamePrefix=prefix):
                for alarm in page.get("MetricAlarms", []):
                    _record_alarm(alarm["AlarmName"], alarm["StateValue"], prefix)
                for alarm in page.get("CompositeAlarms", []):
                    _record_alarm(alarm["AlarmName"], alarm["StateValue"], prefix)
    except Exception:
        # Alarm-list failures intentionally under-report alarm impact instead
        # of turning telemetry unavailability into a public outage signal.
        # Target-health failures still drive unknown/degraded status above.
        print(f"WARN: Failed to describe alarms: {traceback.format_exc()}")

    return summary


def _component_for_alarm_name(
    lower_name,
    lower_prefix="",
    server_prefixes=(),
    ac_prefixes=(),
):
    """Map a redacted alarm to the public component impacted by its prefix."""
    if lower_prefix in server_prefixes and any(
        token in lower_name for token in CELL_AC_ALARM_TOKENS
    ):
        return "ac"
    if lower_prefix in ac_prefixes:
        return "ac"
    if lower_prefix in server_prefixes:
        return "server"
    # Token tables are a fallback for legacy single-prefix configuration.
    if any(token in lower_name for token in AC_ALARM_TOKENS):
        return "ac"
    if any(token in lower_name for token in SERVER_ALARM_TOKENS):
        return "server"
    return None


# ---------------------------------------------------------------------------
# Status derivation
# ---------------------------------------------------------------------------

def _build_component(health, has_alarm):
    """Build the public component status without exposing infrastructure shape."""
    return {"status": _derive_status(health, has_alarm)}


def _derive_status(health, has_alarm):
    """
    healthy  = all hosts healthy AND no active alarms
    degraded = some unhealthy hosts OR some active alarms
    unhealthy = no healthy hosts among known targets
    unknown = no target data, only transitional targets, or partial describe
              failure with no healthy signal
    """
    total = health.get("total", 0)
    healthy = health.get("healthy", 0)
    unhealthy = health.get("unhealthy", 0)
    configured = health.get("configured", 1 if total > 0 else 0)
    described = health.get("described", 1 if total > 0 else 0)
    errors = health.get("errors", 0)

    if configured == 0 or described == 0 or total == 0:
        # Empty/missing target data is ambiguous publicly; alarms provide impact.
        return "degraded" if has_alarm else "unknown"
    if healthy == 0 and unhealthy == 0:
        return "degraded" if has_alarm else "unknown"
    if errors > 0 and healthy == 0:
        # Partial describe failures stay unknown unless another TG proves healthy.
        return "degraded" if has_alarm else "unknown"
    if healthy == 0:
        return "unhealthy"
    if unhealthy > 0 or has_alarm:
        return "degraded"
    return "healthy"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _parse_csv(value):
    """Split a comma-separated string into a list, dropping empty entries."""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
