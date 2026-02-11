"""
Status aggregator Lambda function.

Reads deployment state from SSM, target group health from ELBv2,
alarm states from CloudWatch, key metrics, ASG details, and SSL cert expiry.
Returns a JSON summary suitable for API Gateway proxy integration.
"""

import json
import os
import time
import traceback
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import boto3

# Module-level clients for Lambda warm-start reuse
ssm = boto3.client("ssm")
elbv2 = boto3.client("elbv2")
cloudwatch = boto3.client("cloudwatch")
autoscaling = boto3.client("autoscaling")
acm = boto3.client("acm")

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
    deployment_model = os.environ.get("DEPLOYMENT_MODEL", "blue_green")
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "unknown"))

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

    # Single pass: returns both aggregate counts and per-TG breakdown
    server_health, server_per_tg = _aggregate_target_health(server_tg_arns)
    ac_health, ac_per_tg = _aggregate_target_health(ac_tg_arns)

    alarms = _get_alarm_states(alarm_prefix)

    server_has_alarm = any(
        a for a in alarms["active"]
        if "-server-" in a["name"].lower()
    )
    ac_has_alarm = any(
        a for a in alarms["active"]
        if "-ac-" in a["name"].lower()
    )

    key_metrics = _get_key_metrics()
    asg_details = _get_asg_details()
    canary = _get_canary_state() if deployment_model == "canary" else None
    dependent_services = _check_dependent_services()
    ssl_certs = _get_ssl_cert_expiry()

    return {
        "environment": environment,
        "region": region,
        "deployment_model": deployment_model,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "components": {
            "server": _build_component(
                server_params, server_health, server_has_alarm,
                per_tg_health=server_per_tg,
            ),
            "ac": _build_component(
                ac_params, ac_health, ac_has_alarm,
                per_tg_health=ac_per_tg,
            ),
        },
        "alarms": alarms,
        "key_metrics": key_metrics,
        "asg_details": asg_details,
        "canary": canary,
        "dependent_services": dependent_services,
        "ssl_certs": ssl_certs,
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
    """Return aggregated and per-TG health from a single pass of API calls.

    Returns (aggregate, per_tg) where:
      aggregate = {"healthy": int, "unhealthy": int, "total": int}
      per_tg = [{"arn": str, "name": str, "healthy": int, "unhealthy": int, "total": int}, ...]
    """
    agg_healthy = 0
    agg_unhealthy = 0
    agg_total = 0
    per_tg = []

    for arn in tg_arns:
        # Extract TG name from ARN: ...targetgroup/<name>/<id>
        parts = arn.split("/")
        tg_name = parts[-2] if len(parts) >= 2 else arn

        tg_healthy = 0
        tg_unhealthy = 0
        tg_total = 0
        try:
            resp = elbv2.describe_target_health(TargetGroupArn=arn)
            for desc in resp.get("TargetHealthDescriptions", []):
                tg_total += 1
                state = desc.get("TargetHealth", {}).get("State", "")
                if state == "healthy":
                    tg_healthy += 1
                else:
                    tg_unhealthy += 1
        except Exception:
            print(f"WARN: Failed to describe target health for {arn}: {traceback.format_exc()}")

        agg_healthy += tg_healthy
        agg_unhealthy += tg_unhealthy
        agg_total += tg_total
        per_tg.append({
            "arn": arn,
            "name": tg_name,
            "healthy": tg_healthy,
            "unhealthy": tg_unhealthy,
            "total": tg_total,
        })

    aggregate = {"healthy": agg_healthy, "unhealthy": agg_unhealthy, "total": agg_total}
    return aggregate, per_tg


# ---------------------------------------------------------------------------
# CloudWatch alarms
# ---------------------------------------------------------------------------

def _get_alarm_states(prefix):
    """Return lists of active and ok alarm objects matching the prefix.

    Each alarm is a dict with: name, description, metric_name, namespace,
    threshold, comparison, state_reason.
    """
    active = []
    ok = []

    if not prefix:
        return {"active": active, "ok": ok}

    def _alarm_obj(alarm, is_composite=False):
        obj = {
            "name": alarm["AlarmName"],
            "description": alarm.get("AlarmDescription", ""),
            "state_reason": alarm.get("StateReason", ""),
        }
        if is_composite:
            obj["metric_name"] = None
            obj["namespace"] = None
            obj["threshold"] = None
            obj["comparison"] = None
        else:
            obj["metric_name"] = alarm.get("MetricName", "")
            obj["namespace"] = alarm.get("Namespace", "")
            obj["threshold"] = alarm.get("Threshold")
            obj["comparison"] = alarm.get("ComparisonOperator", "")
        return obj

    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmNamePrefix=prefix):
            for alarm in page.get("MetricAlarms", []):
                obj = _alarm_obj(alarm)
                if alarm["StateValue"] == "ALARM":
                    active.append(obj)
                else:
                    ok.append(obj)
            for alarm in page.get("CompositeAlarms", []):
                obj = _alarm_obj(alarm, is_composite=True)
                if alarm["StateValue"] == "ALARM":
                    active.append(obj)
                else:
                    ok.append(obj)
    except Exception:
        print(f"WARN: Failed to describe alarms: {traceback.format_exc()}")

    return {"active": active, "ok": ok}


# ---------------------------------------------------------------------------
# Key metrics (current values only)
# ---------------------------------------------------------------------------

def _get_key_metrics():
    """Fetch latest data point for key NHP metrics from CloudWatch.

    Returns a dict of metric_id -> current value, or None if no env vars configured.
    Only fetches the most recent data point (10-min window, 5-min period).
    """
    server_nlb = os.environ.get("SERVER_NLB_ARN_SUFFIX", "")
    ac_nlb = os.environ.get("AC_NLB_ARN_SUFFIX", "")
    server_asg = os.environ.get("SERVER_ASG_NAME", "")
    ac_asg = os.environ.get("AC_ASG_NAME", "")

    if not any([server_nlb, ac_nlb, server_asg, ac_asg]):
        return None

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)

    queries = []

    if server_nlb:
        queries.append({
            "Id": "server_active_flows",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/NetworkELB",
                    "MetricName": "ActiveFlowCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": server_nlb}],
                },
                "Period": 300,
                "Stat": "Sum",
            },
        })

    if ac_nlb:
        queries.append({
            "Id": "ac_active_flows",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/NetworkELB",
                    "MetricName": "ActiveFlowCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": ac_nlb}],
                },
                "Period": 300,
                "Stat": "Sum",
            },
        })

    # Custom NHP metrics (may not exist yet)
    queries.extend([
        {
            "Id": "knock_latency_p99",
            "MetricStat": {
                "Metric": {
                    "Namespace": "LayerV/NHP",
                    "MetricName": "KnockLatency",
                    "Dimensions": [],
                },
                "Period": 300,
                "Stat": "p99",
            },
        },
        {
            "Id": "auth_success",
            "MetricStat": {
                "Metric": {
                    "Namespace": "LayerV/NHP",
                    "MetricName": "AuthSuccess",
                    "Dimensions": [],
                },
                "Period": 300,
                "Stat": "Sum",
            },
        },
        {
            "Id": "auth_failure",
            "MetricStat": {
                "Metric": {
                    "Namespace": "LayerV/NHP",
                    "MetricName": "AuthFailure",
                    "Dimensions": [],
                },
                "Period": 300,
                "Stat": "Sum",
            },
        },
    ])

    if server_asg:
        queries.append({
            "Id": "server_cpu",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "AutoScalingGroupName", "Value": server_asg}],
                },
                "Period": 300,
                "Stat": "Average",
            },
        })

    if ac_asg:
        queries.append({
            "Id": "ac_cpu",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "AutoScalingGroupName", "Value": ac_asg}],
                },
                "Period": 300,
                "Stat": "Average",
            },
        })

    try:
        resp = cloudwatch.get_metric_data(
            MetricDataQueries=queries,
            StartTime=start,
            EndTime=now,
        )
    except Exception:
        print(f"WARN: Failed to get metric data: {traceback.format_exc()}")
        return None

    result = {}
    for metric_result in resp.get("MetricDataResults", []):
        metric_id = metric_result["Id"]
        values = metric_result.get("Values", [])
        result[metric_id] = values[0] if values else None

    return result


# ---------------------------------------------------------------------------
# ASG details
# ---------------------------------------------------------------------------

def _get_asg_details():
    """Fetch ASG capacity and instance details.

    Returns a dict with server and ac ASG info, or None if no ASG names configured.
    """
    server_asg = os.environ.get("SERVER_ASG_NAME", "")
    ac_asg = os.environ.get("AC_ASG_NAME", "")

    if not server_asg and not ac_asg:
        return None

    names = [n for n in [server_asg, ac_asg] if n]

    try:
        resp = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=names)
    except Exception:
        print(f"WARN: Failed to describe ASGs: {traceback.format_exc()}")
        return None

    asg_map = {}
    for asg in resp.get("AutoScalingGroups", []):
        asg_map[asg["AutoScalingGroupName"]] = {
            "desired_capacity": asg["DesiredCapacity"],
            "min_size": asg["MinSize"],
            "max_size": asg["MaxSize"],
            "instances": [
                {
                    "id": inst["InstanceId"],
                    "health_status": inst["HealthStatus"],
                    "lifecycle_state": inst["LifecycleState"],
                }
                for inst in asg.get("Instances", [])
            ],
        }

    result = {}
    if server_asg:
        result["server"] = asg_map.get(server_asg)
    if ac_asg:
        result["ac"] = asg_map.get(ac_asg)

    return result if result else None


# ---------------------------------------------------------------------------
# Canary deployment state
# ---------------------------------------------------------------------------

def _get_canary_state():
    """Read canary deployment state from SSM.

    Returns {"state": "idle|deploying|rolling_back"} or None.
    """
    param_name = os.environ.get("CANARY_STATE_SSM_PARAM", "")
    if not param_name:
        return None

    try:
        resp = ssm.get_parameter(Name=param_name)
        value = resp["Parameter"]["Value"]
        if value in ("", "initial"):
            return None
        return {"state": value}
    except Exception:
        print(f"WARN: Failed to read canary state from {param_name}: {traceback.format_exc()}")
        return None


# ---------------------------------------------------------------------------
# Dependent services health check
# ---------------------------------------------------------------------------

def _check_dependent_services():
    """Check health of dependent services via HTTP GET.

    Reads DEPENDENT_SERVICE_URLS env var (JSON map of name -> URL).
    Returns a dict of {name: {status, response_time_ms}} or None if unconfigured.
    """
    raw = os.environ.get("DEPENDENT_SERVICE_URLS", "")
    if not raw or raw == "{}":
        return None

    try:
        url_map = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        print(f"WARN: Invalid DEPENDENT_SERVICE_URLS: {raw}")
        return None

    if not url_map:
        return None

    results = {}
    for name, url in url_map.items():
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            results[name] = {"status": "unhealthy", "response_time_ms": 0}
            continue
        start = time.monotonic()
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "LayerV-StatusPage/1.0")
            with urllib.request.urlopen(req, timeout=3) as resp:
                elapsed_ms = round((time.monotonic() - start) * 1000)
                status_code = resp.getcode()
                results[name] = {
                    "status": "healthy" if 200 <= status_code < 400 else "unhealthy",
                    "response_time_ms": elapsed_ms,
                }
        except Exception:
            elapsed_ms = round((time.monotonic() - start) * 1000)
            results[name] = {
                "status": "unhealthy",
                "response_time_ms": elapsed_ms,
            }

    return results


# ---------------------------------------------------------------------------
# SSL certificate expiry
# ---------------------------------------------------------------------------

def _get_ssl_cert_expiry():
    """Check ACM certificate expiry for monitored domains.

    Reads SSL_CERT_ARNS env var (JSON map of label -> cert ARN).
    Returns a list of {domain, expires_at, days_remaining, status} or None.
    Status uses "ok" / "warning" / "critical" (distinct from component health
    which uses "healthy" / "degraded" / "unhealthy") since they represent
    different domains: cert validity vs service availability.
    """
    raw = os.environ.get("SSL_CERT_ARNS", "")
    if not raw or raw == "{}":
        return None

    try:
        cert_map = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        print(f"WARN: Invalid SSL_CERT_ARNS: {raw}")
        return None

    if not cert_map:
        return None

    now = datetime.now(timezone.utc)
    results = []

    for label, cert_arn in cert_map.items():
        try:
            resp = acm.describe_certificate(CertificateArn=cert_arn)
            cert = resp["Certificate"]
            not_after = cert.get("NotAfter")
            domain = cert.get("DomainName", label)

            if not_after:
                # NotAfter is already a datetime object from boto3
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                days_remaining = (not_after - now).days
                expires_at = not_after.strftime("%Y-%m-%dT%H:%M:%SZ")

                if days_remaining < 7:
                    status = "critical"
                elif days_remaining < 30:
                    status = "warning"
                else:
                    status = "ok"

                results.append({
                    "domain": domain,
                    "expires_at": expires_at,
                    "days_remaining": days_remaining,
                    "status": status,
                })
            else:
                results.append({
                    "domain": domain,
                    "expires_at": None,
                    "days_remaining": None,
                    "status": "unknown",
                })
        except Exception:
            print(f"WARN: Failed to describe cert {cert_arn}: {traceback.format_exc()}")
            results.append({
                "domain": label,
                "expires_at": None,
                "days_remaining": None,
                "status": "unknown",
            })

    return results if results else None


# ---------------------------------------------------------------------------
# Status derivation
# ---------------------------------------------------------------------------

def _build_component(params, health, has_alarm, per_tg_health=None):
    """Combine SSM params, target health, and alarm state into a component dict."""
    status = _derive_status(health, has_alarm)
    result = {
        "status": status,
        "active_color": params.get("active_color") or "blue",
        "image_tag": params.get("image_tag"),
        "deployed_at": params.get("deployed_at"),
        "deployed_commit": params.get("deployed_commit"),
        "healthy_hosts": health["healthy"],
        "unhealthy_hosts": health["unhealthy"],
        "total_hosts": health["total"],
        "green_image_tag": params.get("green_image_tag"),
        "last_switch_timestamp": params.get("last_switch_timestamp"),
    }
    if per_tg_health:
        result["per_tg_health"] = per_tg_health
    return result


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
