"""
Status aggregator Lambda function.

Reads deployment state from SSM, target group health from ELBv2,
and alarm states from CloudWatch. Returns a JSON summary suitable
for API Gateway proxy integration.
"""

import json
import os
import traceback
from datetime import datetime, timezone

import boto3

# Module-level clients for Lambda warm-start reuse
ssm = boto3.client("ssm")
elbv2 = boto3.client("elbv2")
cloudwatch = boto3.client("cloudwatch")

# CORS allows all origins intentionally: status data is public/read-only
# and restricting to CloudFront domain would create a circular dependency
# (CloudFront domain isn't known when the module is first deployed).
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Content-Type": "application/json",
}


def handler(event, context):
    """Lambda entry point (API Gateway HTTP API v2.0 proxy integration)."""
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod", ""))
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        body = build_status()
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

def build_status():
    environment = os.environ.get("ENVIRONMENT", "unknown")
    ssm_prefix = os.environ.get("SSM_PREFIX", "")
    alarm_prefix = os.environ.get("ALARM_NAME_PREFIX", "")

    server_tg_arns = _parse_csv(os.environ.get("SERVER_NLB_TG_ARNS", ""))
    ac_tg_arns = _parse_csv(os.environ.get("AC_NLB_TG_ARNS", ""))

    all_params = _get_all_ssm_params(ssm_prefix)

    server_params = {
        "active_color": all_params.get(f"{ssm_prefix}/server/active-color"),
        "image_tag": all_params.get(f"{ssm_prefix}/server/image-tag"),
        "green_image_tag": all_params.get(f"{ssm_prefix}/server/green-image-tag"),
        "last_switch_timestamp": all_params.get(f"{ssm_prefix}/server/last-switch-timestamp"),
        "deployed_commit": all_params.get(f"{ssm_prefix}/deploy/deployed-commit"),
        "deployed_at": all_params.get(f"{ssm_prefix}/deploy/deployed-at"),
    }
    ac_params = {
        "active_color": all_params.get(f"{ssm_prefix}/ac/active-color"),
        "image_tag": all_params.get(f"{ssm_prefix}/ac/image-tag"),
        "green_image_tag": all_params.get(f"{ssm_prefix}/ac/green-image-tag"),
        "last_switch_timestamp": all_params.get(f"{ssm_prefix}/ac/last-switch-timestamp"),
        "deployed_commit": all_params.get(f"{ssm_prefix}/deploy/deployed-commit"),
        "deployed_at": all_params.get(f"{ssm_prefix}/deploy/deployed-at"),
    }

    server_health = _aggregate_target_health(server_tg_arns)
    ac_health = _aggregate_target_health(ac_tg_arns)

    alarms = _get_alarm_states(alarm_prefix)

    server_has_alarm = any(
        a for a in alarms["active"]
        if "-server-" in a.lower()
    )
    ac_has_alarm = any(
        a for a in alarms["active"]
        if "-ac-" in a.lower()
    )

    return {
        "environment": environment,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "components": {
            "server": _build_component(server_params, server_health, server_has_alarm),
            "ac": _build_component(ac_params, ac_health, ac_has_alarm),
        },
        "alarms": alarms,
    }


# ---------------------------------------------------------------------------
# SSM helpers
# ---------------------------------------------------------------------------

def _get_all_ssm_params(prefix):
    """Batch-fetch all SSM parameters for both server and ac components.

    Makes a single ssm.get_parameters() call instead of individual calls.
    Returns a dict mapping SSM path -> value (or None for missing/empty/initial).
    """
    paths = [
        f"{prefix}/server/active-color",
        f"{prefix}/server/image-tag",
        f"{prefix}/server/green-image-tag",
        f"{prefix}/server/last-switch-timestamp",
        f"{prefix}/ac/active-color",
        f"{prefix}/ac/image-tag",
        f"{prefix}/ac/green-image-tag",
        f"{prefix}/ac/last-switch-timestamp",
        f"{prefix}/deploy/deployed-commit",
        f"{prefix}/deploy/deployed-at",
    ]

    try:
        resp = ssm.get_parameters(Names=paths)
    except Exception:
        print(f"WARN: Failed to batch-read SSM params: {traceback.format_exc()}")
        return {}

    invalid = set(resp.get("InvalidParameters", []))
    result = {p: None for p in paths}

    for param in resp.get("Parameters", []):
        value = param["Value"]
        if value in ("", "initial"):
            result[param["Name"]] = None
        else:
            result[param["Name"]] = value

    for p in invalid:
        result[p] = None

    return result


# ---------------------------------------------------------------------------
# Target group health
# ---------------------------------------------------------------------------

def _aggregate_target_health(tg_arns):
    """Return aggregated healthy / unhealthy / total counts across TG ARNs."""
    healthy = 0
    unhealthy = 0
    total = 0

    for arn in tg_arns:
        try:
            resp = elbv2.describe_target_health(TargetGroupArn=arn)
            for desc in resp.get("TargetHealthDescriptions", []):
                total += 1
                state = desc.get("TargetHealth", {}).get("State", "")
                if state == "healthy":
                    healthy += 1
                else:
                    unhealthy += 1
        except Exception:
            print(f"WARN: Failed to describe target health for {arn}: {traceback.format_exc()}")
            continue

    return {"healthy": healthy, "unhealthy": unhealthy, "total": total}


# ---------------------------------------------------------------------------
# CloudWatch alarms
# ---------------------------------------------------------------------------

def _get_alarm_states(prefix):
    """Return lists of active and ok alarm names matching the prefix."""
    active = []
    ok = []

    if not prefix:
        return {"active": active, "ok": ok}

    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmNamePrefix=prefix):
            for alarm in page.get("MetricAlarms", []):
                name = alarm["AlarmName"]
                if alarm["StateValue"] == "ALARM":
                    active.append(name)
                else:
                    ok.append(name)
            for alarm in page.get("CompositeAlarms", []):
                name = alarm["AlarmName"]
                if alarm["StateValue"] == "ALARM":
                    active.append(name)
                else:
                    ok.append(name)
    except Exception:
        print(f"WARN: Failed to describe alarms: {traceback.format_exc()}")

    return {"active": active, "ok": ok}


# ---------------------------------------------------------------------------
# Status derivation
# ---------------------------------------------------------------------------

def _build_component(params, health, has_alarm):
    """Combine SSM params, target health, and alarm state into a component dict."""
    status = _derive_status(health, has_alarm)
    return {
        "status": status,
        "active_color": params.get("active_color") or "blue",
        "image_tag": params.get("image_tag"),
        "deployed_at": params.get("deployed_at"),
        "deployed_commit": params.get("deployed_commit"),
        "healthy_hosts": health["healthy"],
        "unhealthy_hosts": health["unhealthy"],
        "total_hosts": health["total"],
    }


def _derive_status(health, has_alarm):
    """
    healthy  = all hosts healthy AND no active alarms
    degraded = some unhealthy hosts OR some active alarms
    unhealthy = no healthy hosts OR critical alarm
    """
    if health["total"] == 0:
        return "unhealthy"
    if health["healthy"] == 0:
        return "unhealthy"
    if health["unhealthy"] > 0 or has_alarm:
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
