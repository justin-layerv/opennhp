"""
Status aggregator Lambda for the public LayerV status page.

The public contract is intentionally narrow: component ids, display-only markers,
coarse status values, history counters, and operator-published incidents.
Infrastructure details such as ARNs, regions, host counts, image tags, commit
SHAs, alarm names, and metric reasons must never leave this Lambda.
"""

import ipaddress
import json
import os
import socket
import time
import traceback
import unicodedata
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus, urlparse

import boto3
from botocore.exceptions import ClientError

# Module-level clients for Lambda warm-start reuse.
elbv2 = boto3.client("elbv2")
cloudwatch = boto3.client("cloudwatch")
s3 = boto3.client("s3")
ssm = boto3.client("ssm")

# CORS allows all origins intentionally: the payload is redacted public status.
# Restricting this to CloudFront would introduce a circular dependency because
# the CloudFront domain is not known when the module is first deployed.
PREFLIGHT_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
}
CORS_HEADERS = {
    **PREFLIGHT_HEADERS,
    "Content-Type": "application/json",
}

OPERATIONAL = "operational"
DEGRADED = "degraded"
MAJOR_OUTAGE = "major_outage"
UNKNOWN = "unknown"
_HISTORY_INDEX = {OPERATIONAL: 0, DEGRADED: 1, MAJOR_OUTAGE: 2}

HISTORY_KEY = "history.json"
INCIDENTS_KEY = "incidents.json"
STATUS_KEY = "status.json"
HTTP_RAW_STATUS_HISTORY_KEY = "http_component_raw_statuses"
HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY = "http_component_hard_outage_pending"
HISTORY_PUBLIC_DAYS = 90
HISTORY_RETENTION_DAYS = 92
INCIDENT_PUBLIC_DAYS = 14
INCIDENT_PUBLIC_LIMIT = 25
INCIDENT_RESOLVED_PUBLIC_LIMIT = 50
INCIDENT_INPUT_LIMIT = 100
INCIDENT_FUTURE_SKEW = timedelta(days=1)
# Bound private S3 read-model inputs before decoding. Public incidents are
# capped lower after sanitization; this prevents an operator-owned source object
# from exhausting memory before those public caps can apply.
JSON_OBJECT_READ_BYTES_LIMIT = 6 * 1024 * 1024
# Keep incidents well below Lambda proxy's 6 MB response cap while leaving
# headroom for history/components and JSON string escaping.
INCIDENT_PUBLIC_JSON_BYTES_LIMIT = 4 * 1024 * 1024

CACHE_TTL_SECONDS = 30
EMPTY_STATUS_CACHE_TTL_SECONDS = 5
# Keep the ordinary HEAD->GET retry budget and the rare non-retried
# Range-rejected HEAD->GET->GET path below the duration alarm and timeout.
URL_CHECK_TIMEOUT_SECONDS = 5
URL_CHECK_ATTEMPTS = 2
URL_CHECK_RETRY_DELAY_SECONDS = 0.4
URL_CHECK_MAX_WORKERS = 8
if URL_CHECK_ATTEMPTS < 1:
    raise ValueError("URL_CHECK_ATTEMPTS must be at least 1")
_DNS_RESOLVER_POOL = ThreadPoolExecutor(max_workers=URL_CHECK_MAX_WORKERS)
STATUS_METRIC_NAMESPACE = os.environ.get(
    "STATUS_METRIC_NAMESPACE",
    "LayerV/NHP/StatusPage",
)
HTTP_COMPONENT_NON_OPERATIONAL_METRIC = "HTTPComponentNonOperational"
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
CELL_SERVER_ALARM_SUFFIXES = (
    # Exact cell-prefixed server/NLB alarm suffixes from
    # terraform/modules/monitoring. Keep these exact so qURL/control-plane
    # alarms under the same cell prefix cannot collide on generic words such as
    # "high-latency". Drift is guarded by
    # test_monitoring_cell_alarms_are_classified_or_explicitly_ignored.
    "-high-cpu",
    "-unhealthy-hosts",
    "-no-healthy-hosts",
    "-tcp-resets",
    "-tcp-resets-https",
    "-tcp-resets-https-green",
    "-low-instances",
    "-network-in-low",
    "-storage-health",
    "-high-latency",
)
AC_ALARM_TOKENS = (
    "-ac-",
    "-canary-ac-",
)
CELL_AC_ALARM_TOKENS = (
    # Keep in sync with cell-prefixed AC-impact alarms in
    # terraform/modules/monitoring; add new cell-scoped AC alarm suffixes here
    # or move them under an AC-owned prefix. The monitoring-suffix drift test
    # fails if a new cell alarm is neither classified nor explicitly ignored.
    "-ac-peer-count-low",
    "-ac-registration-latency",
)
TRANSITIONAL_TARGET_STATES = {"draining", "initial", "unused"}

_INCIDENT_FIELDS = (
    "id",
    "title",
    "status",
    "impact",
    "components",
    "started_at",
    "resolved_at",
    "updates",
)
_INCIDENT_UPDATE_FIELDS = ("at", "status", "body")
_INCIDENT_STATUSES = {"investigating", "identified", "monitoring", "resolved"}
_INCIDENT_IMPACTS = {"minor", "major", "critical"}
_CORE_COMPONENT_IDS = {"nhp_server", "nhp_ac", "qurl_api", "qurl_link"}
_INCIDENT_STRING_LIMITS = {
    "id": 128,
    "title": 200,
    "started_at": 64,
    "resolved_at": 64,
    "body": 2000,
}
_INCIDENT_MAX_COMPONENTS = 12
_INCIDENT_MAX_UPDATES = 20


def handler(event, context):
    """Lambda entry point for API Gateway and EventBridge snapshots."""
    if not isinstance(event, dict):
        print("WARN: Ignoring non-dict event")
        # Invalid API Gateway invocations get the HTTP envelope; internal
        # EventBridge/S3 events are routed below and return plain Lambda dicts.
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Internal server error"}),
        }
    if event.get("task") == "snapshot":
        # Let failures raise so Lambda/EventBridge alarms see a real error.
        record_snapshot()
        return {"ok": True}
    if _is_incident_publish_event(event):
        refresh_status_incidents()
        return {"ok": True}
    if isinstance(event.get("Records"), list):
        print("WARN: Ignoring non-incident S3 event")
        return {"ok": True, "ignored": True}

    # Terraform currently routes only GET /status. These method guards keep the
    # handler conservative for direct tests and future API Gateway route changes.
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod", ""))
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": PREFLIGHT_HEADERS, "body": ""}
    if method and method != "GET":
        return {
            "statusCode": 405,
            "headers": {**CORS_HEADERS, "Allow": "GET, OPTIONS"},
            "body": json.dumps({"error": "Method not allowed"}),
        }

    try:
        body = _get_cached_status()
        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps(body, separators=(",", ":")),
        }
    except Exception:
        print(f"ERROR: {traceback.format_exc()}")
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": "Internal server error"}),
        }


def _get_cached_status():
    """Return a short-lived per-container cache of the S3-published status."""
    now = time.time()
    if _STATUS_CACHE["body"] is not None and now < _STATUS_CACHE["expires_at"]:
        return _STATUS_CACHE["body"]

    stale_body = _STATUS_CACHE["body"]
    body = _load_json(STATUS_KEY)
    cache_ttl = CACHE_TTL_SECONDS
    if not isinstance(body, dict):
        if isinstance(stale_body, dict):
            print("WARN: Serving stale cached status after status.json read miss")
            body = stale_body
        else:
            print("WARN: Serving empty status after status.json read miss")
            body = _empty_status_payload()
            cache_ttl = EMPTY_STATUS_CACHE_TTL_SECONDS
    # Cache stale-on-miss responses for the same short TTL as fresh reads; this
    # avoids hammering S3 during a brief read blip while keeping staleness bounded.
    # Cold empty fallbacks get only a brief negative-cache window so
    # pre-bootstrap direct API probes do not double-read S3 on every request,
    # while a newly readable status.json is still picked up quickly.
    # The S3 event path normally refreshes status.json on incident edits. The
    # compatibility API intentionally overlays live incidents as a fallback for
    # a dropped event or a warm container whose short cache predates the edit.
    # That real overhead is bounded by CACHE_TTL_SECONDS plus API Gateway
    # throttling; viewer traffic still reads only CloudFront/S3 status.json.
    body = _merge_live_incidents(body)
    _STATUS_CACHE["body"] = body
    _STATUS_CACHE["expires_at"] = now + cache_ttl
    return body


def _is_incident_publish_event(event):
    """Return true for S3 writes to incidents.json."""
    records = event.get("Records")
    if not isinstance(records, list):
        return False
    for record in records:
        if record.get("eventSource") != "aws:s3":
            continue
        raw_key = record.get("s3", {}).get("object", {}).get("key", "")
        if unquote_plus(raw_key) == INCIDENTS_KEY:
            return True
    return False


def _merge_live_incidents(body):
    """Overlay operator-published incidents onto a cached status payload.

    The compatibility API calls this even after reading status.json so a dropped
    S3 event or stale warm-container cache does not hide operator edits.
    """
    incidents_raw = _load_json(INCIDENTS_KEY)
    if incidents_raw is None:
        return body
    merged = dict(body)
    display_only_ids = _display_only_component_ids()
    merged["components"] = _public_components(merged.get("components", []), display_only_ids)
    incidents = _sanitize_incidents(incidents_raw)
    merged["incidents"] = incidents
    merged["overall"] = _derive_overall(merged.get("components", []), incidents, display_only_ids)
    return merged


def build_public_status(components=None, history_raw=None, incidents_raw=None):
    """Build the public payload for scheduled snapshot publication.

    components=None runs live component checks and emits HTTP component metrics;
    read paths should serve the cached status.json payload instead.
    """
    if components is None:
        components = build_components()
    if history_raw is None:
        history_raw = _load_json(HISTORY_KEY)
    if incidents_raw is None:
        incidents_raw = _load_json(INCIDENTS_KEY)
    incidents = _sanitize_incidents(incidents_raw)
    display_only_ids = _display_only_component_ids()
    components = _public_components(components, display_only_ids)
    return {
        "environment": os.environ.get("ENVIRONMENT", "unknown"),
        "timestamp": _now_iso(),
        "overall": _derive_overall(components, incidents, display_only_ids),
        "components": components,
        "history": _public_history(history_raw),
        "incidents": incidents,
    }


def _empty_status_payload():
    """Fallback used before the first EventBridge snapshot publishes status."""
    return {
        "environment": os.environ.get("ENVIRONMENT", "unknown"),
        "timestamp": _now_iso(),
        "overall": UNKNOWN,
        "components": [],
        "history": {},
        "incidents": [],
    }


def build_components():
    """Run all component checks and return [{"id", "status"}, ...]."""
    alarm_prefixes = _parse_csv(os.environ.get("ALARM_NAME_PREFIXES", ""))
    if not alarm_prefixes:
        alarm_prefixes = _parse_csv(os.environ.get("ALARM_NAME_PREFIX", ""))
    alarms = _get_alarm_summary(
        alarm_prefixes,
        _parse_csv(os.environ.get("SERVER_ALARM_PREFIXES", "")),
        _parse_csv(os.environ.get("AC_ALARM_PREFIXES", "")),
    )

    components = [
        _target_component(
            "nhp_server",
            _target_group_arns("SERVER"),
            alarms["server_active"],
        ),
        _target_component(
            "nhp_ac",
            _target_group_arns("AC"),
            alarms["ac_active"],
        ),
    ]

    url_map = _service_url_map()
    if url_map:
        names = list(url_map.keys())
        with ThreadPoolExecutor(max_workers=min(len(names), URL_CHECK_MAX_WORKERS)) as pool:
            statuses = list(pool.map(lambda name: _check_url(url_map[name]), names))
        http_components = []
        for name, status in zip(names, statuses):
            component = {"id": name, "status": status}
            components.append(component)
            http_components.append(component)
        # Metrics intentionally use raw probe results before record_snapshot()
        # applies customer-facing hard-outage debounce to status.json/history.
        _publish_http_component_metrics(http_components)

    return components


def _publish_http_component_metrics(components):
    """Publish coarse HTTP component health metrics for sustained-degraded alarms."""
    if not components:
        return

    metric_data = []
    environment = os.environ.get("ENVIRONMENT", "unknown")
    for component in components:
        component_id = component.get("id")
        if not isinstance(component_id, str):
            continue
        metric_data.append({
            "MetricName": HTTP_COMPONENT_NON_OPERATIONAL_METRIC,
            "Dimensions": [
                {"Name": "Environment", "Value": environment},
                {"Name": "ComponentId", "Value": component_id},
            ],
            "Unit": "Count",
            # UNKNOWN means the health URL is misconfigured or unreachable as a
            # probe target; page operators even though the public tile is gray.
            "Value": 0 if component.get("status") == OPERATIONAL else 1,
        })

    if not metric_data:
        return
    try:
        cloudwatch.put_metric_data(
            Namespace=STATUS_METRIC_NAMESPACE,
            MetricData=metric_data,
        )
    except Exception:
        # Metric publishing is observability only. Do not fail or distort the
        # customer-facing status snapshot because CloudWatch metrics is flaky.
        print(
            "WARN: Failed to publish HTTP component status metrics: "
            f"{traceback.format_exc()}"
        )


def _public_components(components, display_only_ids=None):
    """Return the redacted public component shape."""
    if display_only_ids is None:
        display_only_ids = _display_only_component_ids()
    public = []
    if not isinstance(components, list):
        return public
    for component in components:
        if not isinstance(component, dict):
            continue
        component_id = component.get("id")
        status = component.get("status")
        if not isinstance(component_id, str) or (
            status not in _HISTORY_INDEX and status != UNKNOWN
        ):
            continue
        public.append({
            "id": component_id,
            "status": status,
            "display_only": component_id in display_only_ids,
        })
    return public


def _derive_overall(components, incidents=None, display_only_ids=None):
    """Worst known rollup status from components plus active incidents."""
    statuses = [_derive_component_overall(components, display_only_ids)]
    incident_status = _derive_incident_overall(incidents)
    if incident_status:
        # Operator-authored incidents are manual severity signals and
        # intentionally override display-only component rollup exclusions.
        statuses.append(incident_status)
    return _max_status(statuses)


def _derive_component_overall(components, display_only_ids=None):
    """Worst rollup component status; unknown surfaces telemetry gaps."""
    if display_only_ids is None:
        display_only_ids = _display_only_component_ids()
    statuses = [
        c.get("status")
        for c in components
        if c.get("id") not in display_only_ids
    ]
    if not statuses:
        return UNKNOWN
    return _max_status(statuses)


def _derive_incident_overall(incidents):
    """Return the active incident impact as an overall status, if any."""
    if not isinstance(incidents, list):
        return None
    has_active = False
    for incident in incidents:
        if not isinstance(incident, dict) or incident.get("status") == "resolved":
            continue
        impact = incident.get("impact")
        if impact not in _INCIDENT_IMPACTS:
            continue
        has_active = True
        if impact == "critical":
            return MAJOR_OUTAGE
    # Product mapping: "critical" is the public outage banner; active "major"
    # and "minor" incidents intentionally publish amber/degraded.
    return DEGRADED if has_active else None


def _max_status(statuses):
    rank = {
        OPERATIONAL: 0,
        UNKNOWN: 1,
        DEGRADED: 2,
        MAJOR_OUTAGE: 3,
    }
    known = [status for status in statuses if status in rank]
    if not known:
        return UNKNOWN
    return max(known, key=lambda status: rank[status])


def _display_only_component_ids():
    return set(_parse_csv(os.environ.get("DISPLAY_ONLY_COMPONENT_IDS", "")))


# ---------------------------------------------------------------------------
# Target group health
# ---------------------------------------------------------------------------

def _target_component(component_id, tg_arns, has_alarm):
    """Return a public component from selected target groups and alarms."""
    if tg_arns is None:
        return {
            "id": component_id,
            "status": DEGRADED if has_alarm else UNKNOWN,
        }
    return {
        "id": component_id,
        "status": _derive_status(_aggregate_target_health(tg_arns), has_alarm),
    }


def _target_group_arns(component):
    """Return active-color target groups, or None when selection is unknown."""
    fallback = _parse_csv(os.environ.get(f"{component}_NLB_TG_ARNS", ""))
    by_color = _target_group_arns_by_color(component)
    parameter_name = os.environ.get(f"{component}_ACTIVE_COLOR_PARAMETER", "")
    if not by_color or not parameter_name:
        return fallback

    color = _active_color(parameter_name)
    if color in by_color and by_color[color]:
        return by_color[color]

    if color is None:
        print(f"WARN: Active color unavailable for {component.lower()} target groups")
    else:
        print(
            f"WARN: Active color {color!r} from {parameter_name} "
            f"has no configured {component.lower()} target groups"
        )
    return None


def _target_group_arns_by_color(component):
    """Parse {blue:[...], green:[...]} target group JSON from the environment."""
    raw = os.environ.get(f"{component}_NLB_TG_ARNS_BY_COLOR", "")
    if not raw or raw == "{}":
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        print(f"WARN: Invalid {component}_NLB_TG_ARNS_BY_COLOR: {raw}")
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        color: [arn for arn in arns if isinstance(arn, str) and arn.strip()]
        for color, arns in parsed.items()
        if color in {"blue", "green"} and isinstance(arns, list)
    }


def _active_color(parameter_name):
    """Read the current blue/green active color."""
    try:
        value = ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"].strip().lower()
    except Exception:
        print(f"WARN: Failed to read active color {parameter_name}: {traceback.format_exc()}")
        return None
    return value if value in {"blue", "green"} else None


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
    """Return component-impact flags without exposing alarm details."""
    summary = {
        "server_active": False,
        "ac_active": False,
    }

    if isinstance(prefixes, str):
        prefixes = _parse_csv(prefixes)
    if isinstance(server_prefixes, str):
        server_prefixes = _parse_csv(server_prefixes)
    if isinstance(ac_prefixes, str):
        ac_prefixes = _parse_csv(ac_prefixes)
    prefixes = list(prefixes or [])
    server_prefixes = list(server_prefixes or [])
    ac_prefixes = list(ac_prefixes or [])

    # Describe all owned prefixes even if a future root module wiring forgets to
    # include them in the broad ALARM_NAME_PREFIXES union. Collapse covered
    # prefixes so a broad env prefix and its server/ac-owned children do not
    # duplicate DescribeAlarms calls every snapshot.
    prefixes = _minimal_alarm_prefixes(
        dict.fromkeys(prefixes + server_prefixes + ac_prefixes)
    )
    if not prefixes:
        return summary

    seen_alarm_components = set()
    server_prefixes = {prefix.lower() for prefix in (server_prefixes or [])}
    ac_prefixes = {prefix.lower() for prefix in (ac_prefixes or [])}

    def _record_alarm(name, prefix):
        lower_name = name.lower()
        component = None
        for classification_prefix in _alarm_classification_prefixes(
            lower_name,
            prefix.lower(),
            server_prefixes,
            ac_prefixes,
        ):
            component = _component_for_alarm_name(
                lower_name,
                classification_prefix,
                server_prefixes,
                ac_prefixes,
            )
            if component is not None:
                break
        if component is None:
            return
        key = (name, component)
        if key in seen_alarm_components:
            return
        seen_alarm_components.add(key)
        if component == "server":
            summary["server_active"] = True
        elif component == "ac":
            summary["ac_active"] = True

    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for prefix in prefixes:
            for page in paginator.paginate(AlarmNamePrefix=prefix, StateValue="ALARM"):
                for alarm in page.get("MetricAlarms", []):
                    _record_alarm(alarm["AlarmName"], prefix)
                for alarm in page.get("CompositeAlarms", []):
                    _record_alarm(alarm["AlarmName"], prefix)
    except Exception:
        # Alarm-list failures under-report alarm impact instead of turning
        # telemetry unavailability into a public outage signal. If pagination
        # fails mid-stream, already-recorded alarm pages are still used.
        print(f"WARN: Failed to describe alarms: {traceback.format_exc()}")

    return summary


def _minimal_alarm_prefixes(prefixes):
    """Drop narrower prefixes when a broader one covers the same alarm names."""
    minimal = []
    for prefix in prefixes:
        if not prefix or any(prefix.startswith(existing) for existing in minimal):
            continue
        minimal = [existing for existing in minimal if not existing.startswith(prefix)]
        minimal.append(prefix)
    return minimal


def _alarm_classification_prefixes(
    lower_name,
    query_prefix,
    server_prefixes,
    ac_prefixes,
):
    """Prefer the most-specific owned prefix that matches the fetched alarm."""
    candidates = {
        prefix
        for prefix in server_prefixes | ac_prefixes
        if prefix and lower_name.startswith(prefix)
    }
    if query_prefix:
        candidates.add(query_prefix)
    return sorted(candidates, key=len, reverse=True)


def _component_for_alarm_name(
    lower_name,
    lower_prefix="",
    server_prefixes=(),
    ac_prefixes=(),
):
    """Map a redacted alarm to the public component impacted by its name."""
    if lower_prefix in server_prefixes and any(
        token in lower_name for token in CELL_AC_ALARM_TOKENS
    ):
        return "ac"
    if lower_prefix in ac_prefixes:
        return "ac"
    if lower_prefix in server_prefixes:
        if _server_alarm_matches_owned_prefix(lower_name, lower_prefix):
            return "server"
        return None
    if any(token in lower_name for token in AC_ALARM_TOKENS):
        return "ac"
    if any(token in lower_name for token in SERVER_ALARM_TOKENS):
        return "server"
    return None


def _server_alarm_matches_owned_prefix(lower_name, lower_prefix):
    """Return true for alarms owned by an explicit server prefix."""
    # These explicit trailing-hyphen prefixes are server-exclusive root-module
    # surfaces. Do not treat arbitrary trailing-hyphen prefixes as wildcards.
    # If a non-server alarm ever moves under one of them, either add an earlier
    # component-specific token match or split it onto its own owned prefix.
    if lower_prefix.endswith(("-green-", "-srv-int-", "-canary-server-")):
        return True
    if lower_name.startswith(f"{lower_prefix}-server-"):
        return True
    return any(lower_name == f"{lower_prefix}{suffix}" for suffix in CELL_SERVER_ALARM_SUFFIXES)


# ---------------------------------------------------------------------------
# Status derivation
# ---------------------------------------------------------------------------

def _derive_status(health, has_alarm):
    """
    operational = all known targets healthy and no active alarms
    degraded = partial health, active alarm, or alarm with no target data
    major_outage = zero healthy targets among known non-transitional targets
    unknown = no target data, only transitional targets, or failed lookup
    """
    total = health.get("total", 0)
    healthy = health.get("healthy", 0)
    unhealthy = health.get("unhealthy", 0)
    configured = health.get("configured", 1 if total > 0 else 0)
    described = health.get("described", 1 if total > 0 else 0)
    errors = health.get("errors", 0)

    if configured == 0 or described == 0 or total == 0:
        return DEGRADED if has_alarm else UNKNOWN
    if healthy == 0 and unhealthy == 0:
        return DEGRADED if has_alarm else UNKNOWN
    # Incomplete target-health telemetry may hide healthy targets, so avoid
    # publishing a hard outage from a partial describe failure.
    if errors > 0 and healthy == 0:
        return DEGRADED if has_alarm else UNKNOWN
    if healthy == 0:
        return MAJOR_OUTAGE
    if unhealthy > 0 or has_alarm:
        return DEGRADED
    # A partial describe failure with a healthy described group stays green:
    # blue/green standbys can be empty during rollout, and unknown telemetry
    # should not override a positive healthy signal.
    return OPERATIONAL


# ---------------------------------------------------------------------------
# HTTP service checks
# ---------------------------------------------------------------------------

def _service_url_map():
    """Parse DEPENDENT_SERVICE_URLS (JSON map of component id to URL)."""
    raw = os.environ.get("DEPENDENT_SERVICE_URLS", "")
    if not raw or raw == "{}":
        return {}
    try:
        url_map = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        print(f"WARN: Invalid DEPENDENT_SERVICE_URLS: {raw}")
        return {}
    if not isinstance(url_map, dict):
        return {}
    cleaned = {}
    for name, url in url_map.items():
        if isinstance(name, str) and isinstance(url, str):
            cleaned[name] = url
        else:
            print("WARN: Ignoring invalid DEPENDENT_SERVICE_URLS entry")
    return cleaned


def _check_url(url):
    """HTTP HEAD with GET fallback; 4xx degrades, 5xx/unreachable outages."""
    parsed = urlparse(url)
    invalid_reason = _unsafe_probe_url_reason(url, parsed)
    if invalid_reason is not None:
        print(f"WARN: Invalid service URL: {url} ({invalid_reason})")
        return UNKNOWN

    last_failure = "no successful response"
    last_status = MAJOR_OUTAGE
    attempts_used = 0
    for attempt_index in range(URL_CHECK_ATTEMPTS):
        attempts_used = attempt_index + 1
        try:
            with _open_health_url(url) as resp:
                code = resp.getcode()
                # Status code is the probe. Leave the HEAD-substitute GET body
                # unread even if an origin ignores Range and returns full 200.
                # The safe opener follows only public HTTPS redirects before
                # getcode(); the 3xx branch is retained for mocked transports
                # and any non-following opener.
                if 200 <= code < 400:
                    return OPERATIONAL
                last_failure = f"HTTP {code}"
                # Reachable client errors are published as amber immediately;
                # only hard red outages get the cross-snapshot debounce.
                last_status = _status_for_http_code(code)
                if not _should_retry_http_code(code):
                    break
        except urllib.error.HTTPError as exc:
            last_failure = f"HTTP {exc.code}"
            last_status = _status_for_http_code(exc.code)
            no_retry = getattr(exc, "_status_page_no_retry", False)
            if no_retry or not _should_retry_http_code(exc.code):
                break
        except _NonRetriableProbeFailure as exc:
            last_failure = exc.failure_name
            last_status = MAJOR_OUTAGE
            break
        except Exception as exc:
            last_failure = exc.__class__.__name__
            last_status = MAJOR_OUTAGE
        if attempt_index < URL_CHECK_ATTEMPTS - 1:
            time.sleep(URL_CHECK_RETRY_DELAY_SECONDS)

    safe_target = parsed.netloc + (parsed.path or "/")
    print(
        f"WARN: Service URL check failed after {attempts_used} "
        f"attempts for {safe_target}: {last_failure}"
    )
    return last_status


def _open_health_url(url):
    """Open a lightweight health probe, retrying GET when HEAD is rejected."""
    try:
        return _open_url(url, "HEAD")
    except urllib.error.HTTPError as exc:
        if (400 <= exc.code < 500 and exc.code != 429) or exc.code == 501:
            try:
                return _open_url(url, "GET", ranged=True)
            except urllib.error.HTTPError as get_exc:
                if get_exc.code == 416:
                    # Range support is deterministic per origin. Try one plain
                    # GET fallback, but do not repeat the expensive sequence.
                    try:
                        return _open_url(url, "GET")
                    except urllib.error.HTTPError as plain_exc:
                        plain_exc._status_page_no_retry = True
                        raise
                    except Exception as plain_exc:
                        raise _NonRetriableProbeFailure(plain_exc.__class__.__name__) from plain_exc
                raise
        raise


def _open_url(url, method, ranged=False):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "LayerV-StatusPage/2.0")
    req.add_header("Connection", "close")
    if ranged:
        req.add_header("Range", "bytes=0-0")
    return _urlopen(req)


class _NonRetriableProbeFailure(Exception):
    def __init__(self, failure_name):
        super().__init__(failure_name)
        self.failure_name = failure_name


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        invalid_reason = _unsafe_probe_url_reason(newurl)
        if invalid_reason is not None:
            raise urllib.error.URLError(f"unsafe redirect target: {invalid_reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_URL_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def _urlopen(req):
    return _URL_OPENER.open(req, timeout=URL_CHECK_TIMEOUT_SECONDS)


def _unsafe_probe_url_reason(url, parsed=None):
    """Return why a dependency probe URL is outside the public HTTPS boundary."""
    if parsed is None:
        parsed = urlparse(url)
    if parsed.scheme != "https":
        return "scheme must be https"
    if not parsed.netloc or not parsed.hostname:
        return "host is required"
    if parsed.username or parsed.password:
        return "credentials are not allowed"
    host = parsed.hostname.rstrip(".").lower()
    if not host:
        return "host is required"
    if host == "localhost" or host.endswith(".localhost"):
        return "localhost is not allowed"
    try:
        port = parsed.port or 443
    except ValueError:
        return "port is invalid"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Defense-in-depth for operator-owned Terraform URLs, not a resolver for
        # untrusted input: urllib still re-resolves at connect time, so a DNS
        # rebind after this validation remains possible.
        addresses, invalid_reason = _resolve_probe_host_addresses(host, port)
        if invalid_reason is not None:
            return invalid_reason
        if any(not address.is_global for address in addresses):
            return "hostname must resolve only to globally routable addresses"
        return None
    if not address.is_global:
        return "IP literal must be globally routable"
    return None


def _resolve_probe_host_addresses(host, port):
    """Resolve a probe hostname and return IP address objects plus any reason."""
    infos, invalid_reason = _getaddrinfo_with_timeout(host, port)
    if invalid_reason is not None:
        return [], invalid_reason
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except (IndexError, ValueError):
            return [], "hostname resolved to an invalid address"
    if not addresses:
        return [], "hostname must resolve"
    return addresses, None


def _getaddrinfo_with_timeout(host, port):
    # Keep resolver stalls isolated from the URL probe pool without creating a
    # new executor for every component URL. Timed-out resolver calls may keep a
    # shared DNS worker briefly, but fanout is still bounded by URL_CHECK_MAX_WORKERS.
    future = _DNS_RESOLVER_POOL.submit(
        socket.getaddrinfo,
        host,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    try:
        return future.result(timeout=URL_CHECK_TIMEOUT_SECONDS), None
    except FutureTimeoutError:
        future.cancel()
        return None, "hostname resolution timed out"
    except OSError:
        return None, "hostname must resolve"


def _status_for_http_code(code):
    """Map a reachable non-success HTTP response to a public status."""
    return DEGRADED if 400 <= code < 500 else MAJOR_OUTAGE


def _should_retry_http_code(code):
    """Retry transient rate-limit/server responses, not deterministic 4xx."""
    return code == 429 or code >= 500


# ---------------------------------------------------------------------------
# History snapshots
# ---------------------------------------------------------------------------

def record_snapshot():
    """Record component history and publish the public status read model."""
    now = datetime.now(timezone.utc)
    raw_components = build_components()

    incidents_raw = _load_snapshot_incidents()
    history = _load_snapshot_history()

    http_component_ids = set(_service_url_map().keys())
    components = _debounce_http_outages(
        raw_components,
        history,
        http_component_ids,
    )
    # Safe to co-locate with uptime counters: _public_history publishes only
    # "days", and CloudFront cannot read the private history.json object.
    _store_http_raw_statuses(history, raw_components, http_component_ids)
    # History mirrors the public status customers saw after debounce. A
    # first-snapshot hard HTTP failure is therefore counted as degraded rather
    # than outage, matching the page even if it is slightly optimistic.

    day = history["days"].setdefault(now.strftime("%Y-%m-%d"), {})
    for comp in components:
        idx = _HISTORY_INDEX.get(comp.get("status"))
        if idx is None:
            continue
        counts = day.setdefault(comp["id"], [0, 0, 0])
        counts[idx] += 1

    cutoff = (now - timedelta(days=HISTORY_RETENTION_DAYS)).strftime("%Y-%m-%d")
    history["days"] = {d: v for d, v in history["days"].items() if d >= cutoff}

    # EventBridge runs this on a 5-minute cadence. A rare overlapping manual or
    # retry invocation can last-write-wins one bucket, which is acceptable for
    # coarse public uptime history.
    # Write paths fail loud if Terraform omits STATUS_BUCKET. _load_json uses
    # .get only for pre-bootstrap read fallbacks and unit-test ergonomics.
    bucket = os.environ["STATUS_BUCKET"]
    status = build_public_status(
        components=components,
        history_raw=history,
        incidents_raw=incidents_raw,
    )
    # Publish status.json before private history.json so a failed public write
    # cannot advance history and let the EventBridge retry double-count a bucket.
    # If the history write fails after the public write, the retry republishes a
    # consistent status snapshot and self-heals history; Lambda errors still page.
    s3.put_object(
        Bucket=bucket,
        Key=STATUS_KEY,
        Body=json.dumps(status, separators=(",", ":")),
        ContentType="application/json",
        CacheControl="public, max-age=60",
    )
    s3.put_object(
        Bucket=bucket,
        Key=HISTORY_KEY,
        Body=json.dumps(history, separators=(",", ":")),
        ContentType="application/json",
    )
    return history


def _load_snapshot_history():
    """Load private uptime history without freezing current status publication."""
    # Transient read failures still fail the snapshot. Missing, malformed, or
    # oversized history starts a fresh window so status.json remains current.
    raw = _load_json(
        HISTORY_KEY,
        missing_ok=False,
        parse_error_ok=True,
        missing_traceback=False,
    )
    if isinstance(raw, dict) and isinstance(raw.get("days"), dict):
        return raw
    if raw is not None:
        print("WARN: Ignoring malformed history.json shape; starting fresh history")
    return {"version": 1, "days": {}}


def _load_snapshot_incidents():
    """Load operator incidents for scheduled snapshots.

    Malformed operator JSON should not halt uptime history. Reuse the last
    sanitized public incidents when possible so an edit typo does not clear an
    active banner before the operator fixes the source object.
    """
    incidents = _load_json(INCIDENTS_KEY, missing_ok=False, parse_error_ok=True)
    if isinstance(incidents, dict):
        return incidents
    previous = _previous_public_incidents_raw()
    if previous["incidents"]:
        print("WARN: Reusing previous public incidents after incidents.json load miss")
    return previous


def _previous_public_incidents_raw():
    """Return the last sanitized public incidents as an incidents.json-shaped dict."""
    status = _load_json(STATUS_KEY)
    if not isinstance(status, dict) or not isinstance(status.get("incidents"), list):
        return {"incidents": []}
    return {"incidents": status["incidents"]}


def refresh_status_incidents():
    """Publish incident edits without advancing scheduled uptime history."""
    status = _load_json(STATUS_KEY)
    if not isinstance(status, dict):
        status = _empty_status_payload()
    # Preserve timestamp/component freshness: an incident publish refreshes the
    # operator feed, but it does not rerun scheduled component telemetry checks.
    # If this races a scheduled snapshot write, last-writer-wins can briefly
    # preserve older component data; the next 5-minute snapshot self-heals it.
    status = _merge_live_incidents(status)
    s3.put_object(
        # Incident-refresh writes should also fail loud on broken Terraform
        # wiring instead of silently masking operator edits.
        Bucket=os.environ["STATUS_BUCKET"],
        Key=STATUS_KEY,
        Body=json.dumps(status, separators=(",", ":")),
        ContentType="application/json",
        CacheControl="public, max-age=60",
    )
    _STATUS_CACHE["body"] = status
    _STATUS_CACHE["expires_at"] = time.time() + CACHE_TTL_SECONDS
    return status


def _public_history(raw):
    """Trim stored history to the public 90-day window of day buckets."""
    if not isinstance(raw, dict) or not isinstance(raw.get("days"), dict):
        return {}
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=HISTORY_PUBLIC_DAYS - 1)).strftime("%Y-%m-%d")
    return {day: value for day, value in raw["days"].items() if day >= cutoff}


def _debounce_http_outages(components, history, http_component_ids):
    """Require two consecutive hard-fail snapshots before HTTP components go red."""
    if not http_component_ids:
        return components
    previous = _previous_http_raw_statuses(history)
    previous_pending = _previous_http_hard_outage_pending(history)
    debounced = []
    for component in components:
        if (
            component.get("id") in http_component_ids
            and component.get("status") == MAJOR_OUTAGE
            and previous.get(component.get("id")) != MAJOR_OUTAGE
            and not previous_pending.get(component.get("id"))
        ):
            updated = dict(component)
            updated["status"] = DEGRADED
            debounced.append(updated)
        else:
            debounced.append(component)
    return debounced


def _previous_http_raw_statuses(history):
    """Return component id => previous raw HTTP status from private history."""
    if not isinstance(history, dict):
        return {}
    statuses = history.get(HTTP_RAW_STATUS_HISTORY_KEY)
    if not isinstance(statuses, dict):
        return {}
    return {
        component_id: status
        for component_id, status in statuses.items()
        if isinstance(component_id, str)
        and (status in _HISTORY_INDEX or status == UNKNOWN)
    }


def _previous_http_hard_outage_pending(history):
    """Return HTTP component ids with a hard-fail streak awaiting confirmation."""
    if not isinstance(history, dict):
        return {}
    pending = history.get(HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY)
    if not isinstance(pending, dict):
        return {}
    return {
        component_id: True
        for component_id, value in pending.items()
        if isinstance(component_id, str) and value is True
    }


def _store_http_raw_statuses(history, components, http_component_ids):
    """Persist raw HTTP statuses for the next snapshot's debounce decision."""
    if not isinstance(history, dict):
        return
    if not http_component_ids:
        history.pop(HTTP_RAW_STATUS_HISTORY_KEY, None)
        history.pop(HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY, None)
        return
    previous_pending = _previous_http_hard_outage_pending(history)
    statuses = {}
    pending = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        component_id = component.get("id")
        status = component.get("status")
        if (
            component_id in http_component_ids
            and (status in _HISTORY_INDEX or status == UNKNOWN)
        ):
            statuses[component_id] = status
            if status == MAJOR_OUTAGE or (
                status == UNKNOWN and previous_pending.get(component_id)
            ):
                pending[component_id] = True
    if statuses:
        history[HTTP_RAW_STATUS_HISTORY_KEY] = statuses
    else:
        history.pop(HTTP_RAW_STATUS_HISTORY_KEY, None)
    if pending:
        history[HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY] = pending
    else:
        history.pop(HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY, None)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def _sanitize_incidents(raw):
    """Pass through incidents.json with strict field and value allowlists."""
    if not isinstance(raw, dict):
        return []
    items = raw.get("incidents")
    if not isinstance(items, list):
        return []

    incidents = []
    seen_ids = set()
    known_component_ids = _known_component_ids()
    if len(items) > INCIDENT_INPUT_LIMIT:
        print(f"WARN: Ignoring incidents beyond first {INCIDENT_INPUT_LIMIT} entries")
    for incident in items[:INCIDENT_INPUT_LIMIT]:
        if not isinstance(incident, dict):
            print("WARN: Skipping invalid incident entry: not an object")
            continue
        invalid_reason = _invalid_incident_reason(incident, known_component_ids)
        if invalid_reason is not None:
            print(f"WARN: Skipping invalid incident entry: {invalid_reason}")
            continue
        cleaned = {k: incident[k] for k in _INCIDENT_FIELDS if k in incident}
        cleaned["id"] = _clean_public_text(cleaned["id"])
        cleaned["title"] = _clean_public_text(cleaned["title"])
        updates = cleaned.get("updates")
        if isinstance(updates, list):
            cleaned["updates"] = _sanitize_incident_updates(updates)
        elif "updates" in cleaned:
            cleaned["updates"] = []
        if not _is_public_incident(cleaned):
            continue
        incident_id = cleaned["id"]
        if incident_id in seen_ids:
            print("WARN: Skipping duplicate incident id")
            continue
        seen_ids.add(incident_id)
        incidents.append(cleaned)
    return _limit_public_incidents(incidents)


def _invalid_incident_reason(incident, known_component_ids=None):
    """Return why an operator incident entry is unsafe to publish, if any."""
    if not _is_limited_string(
        _clean_public_text(incident.get("id")),
        _INCIDENT_STRING_LIMITS["id"],
    ):
        return "id must be a non-empty string <= 128 chars"
    if not _is_limited_string(
        _clean_public_text(incident.get("title")),
        _INCIDENT_STRING_LIMITS["title"],
    ):
        return "title must be a non-empty string <= 200 chars"
    if not _is_iso_timestamp(incident.get("started_at")):
        return "started_at must be a full ISO-8601 date-time with timezone"
    if _is_future_incident_timestamp(incident.get("started_at")):
        return "started_at cannot be more than 1 day in the future"
    if incident.get("status") not in _INCIDENT_STATUSES:
        return "status is not allowed"
    if incident.get("impact") not in _INCIDENT_IMPACTS:
        return "impact is not allowed"
    resolved_at = incident.get("resolved_at")
    if resolved_at is not None:
        if not _is_iso_timestamp(resolved_at):
            return "resolved_at must be a full ISO-8601 date-time with timezone"
        if _is_future_incident_timestamp(resolved_at):
            return "resolved_at cannot be more than 1 day in the future"
    components = incident.get("components")
    if components is not None and not _is_valid_incident_components(components, known_component_ids):
        return "components must be known public component ids"
    updates = incident.get("updates", [])
    if updates is not None and not isinstance(updates, list):
        return "updates must be a list"
    return None


def _sanitize_incident_updates(updates):
    """Return bounded, valid update entries from an incident."""
    cleaned = []
    for update in updates[:_INCIDENT_MAX_UPDATES]:
        if not _is_valid_incident_update(update):
            continue
        cleaned_update = {k: update[k] for k in _INCIDENT_UPDATE_FIELDS if k in update}
        cleaned_update["body"] = _clean_public_text(cleaned_update["body"])
        cleaned.append(cleaned_update)
    return cleaned


def _is_valid_incident_update(update):
    """Return true for update entries safe to publish."""
    if not isinstance(update, dict):
        return False
    if not _is_iso_timestamp(update.get("at")):
        return False
    if _is_future_incident_timestamp(update.get("at")):
        return False
    if update.get("status") not in _INCIDENT_STATUSES:
        return False
    return _is_limited_string(
        _clean_public_text(update.get("body")),
        _INCIDENT_STRING_LIMITS["body"],
    )


def _is_public_incident(incident):
    """Return true when an incident should be included in status.json."""
    if incident.get("status") != "resolved":
        return True
    reference = _resolved_incident_reference_time(incident)
    if reference is None:
        print("WARN: Skipping resolved incident without parseable started_at or resolved_at")
        return False
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=INCIDENT_PUBLIC_DAYS - 1)
    return reference.date() >= cutoff


def _resolved_incident_reference_time(incident):
    """Use resolution time for past-incident visibility, falling back to start."""
    started = _parse_iso_datetime(incident.get("started_at"))
    resolved = _parse_iso_datetime(incident.get("resolved_at"))
    if started is not None and resolved is not None:
        return max(started, resolved)
    return resolved if resolved is not None else started


def _limit_public_incidents(incidents):
    """Keep bounded active and resolved incidents in their source order."""
    active = [
        (idx, incident)
        for idx, incident in enumerate(incidents)
        if incident.get("status") != "resolved"
    ]
    resolved = [
        (idx, incident)
        for idx, incident in enumerate(incidents)
        if incident.get("status") == "resolved"
    ]
    keep_indexes = _newest_incident_indexes(
        active,
        INCIDENT_PUBLIC_LIMIT,
        lambda incident: _parse_iso_datetime(incident.get("started_at")),
    )
    keep_indexes.update(_newest_incident_indexes(
        resolved,
        INCIDENT_RESOLVED_PUBLIC_LIMIT,
        _resolved_incident_reference_time,
    ))
    bounded = [
        incident
        for idx, incident in enumerate(incidents)
        if idx in keep_indexes
    ]
    return _trim_incidents_to_public_bytes(bounded)


def _trim_incidents_to_public_bytes(incidents):
    """Drop resolved, then oldest incident entries until JSON is bounded."""
    trimmed = list(incidents)
    if not trimmed or _json_size_bytes(trimmed) <= INCIDENT_PUBLIC_JSON_BYTES_LIMIT:
        return trimmed

    drop_order = sorted(
        range(len(trimmed)),
        key=lambda idx: _incident_drop_key(trimmed[idx], idx),
    )
    low = 1
    high = len(drop_order)
    dropped = high

    while low <= high:
        mid = (low + high) // 2
        drop_indexes = set(drop_order[:mid])
        candidate = [
            incident
            for idx, incident in enumerate(trimmed)
            if idx not in drop_indexes
        ]
        if _json_size_bytes(candidate) <= INCIDENT_PUBLIC_JSON_BYTES_LIMIT:
            dropped = mid
            high = mid - 1
        else:
            low = mid + 1

    drop_indexes = set(drop_order[:dropped])
    trimmed = [
        incident
        for idx, incident in enumerate(trimmed)
        if idx not in drop_indexes
    ]
    if dropped:
        print(
            "WARN: Trimmed "
            f"{dropped} incident(s) to keep public status payload bounded"
        )
    return trimmed


def _incident_drop_key(incident, source_index):
    """Prefer dropping resolved incidents, then the oldest remaining entries."""
    if incident.get("status") == "resolved":
        reference = _resolved_incident_reference_time(incident)
        priority = 0
    else:
        reference = _parse_iso_datetime(incident.get("started_at"))
        priority = 1
    return (
        priority,
        reference or datetime.min.replace(tzinfo=timezone.utc),
        source_index,
    )


def _json_size_bytes(value):
    """Return the compact JSON byte size used by the API/S3 writers."""
    return len(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _newest_incident_indexes(indexed_incidents, limit, key_func):
    """Return the source indexes for the newest bounded incident entries."""
    if len(indexed_incidents) <= limit:
        return {idx for idx, _incident in indexed_incidents}
    newest = sorted(
        indexed_incidents,
        key=lambda item: key_func(item[1]) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:limit]
    return {idx for idx, _incident in newest}


def _is_valid_incident_components(components, known_component_ids=None):
    """Return true for the public component ids listed on an incident."""
    if not isinstance(components, list) or len(components) > _INCIDENT_MAX_COMPONENTS:
        return False
    if known_component_ids is None:
        known_component_ids = _known_component_ids()
    return all(
        _is_limited_string(component, 64) and component in known_component_ids
        for component in components
    )


def _known_component_ids():
    return _CORE_COMPONENT_IDS | set(_service_url_map().keys())


def _is_limited_string(value, limit):
    """Return true for non-empty strings within a public payload size cap."""
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


def _clean_public_text(value):
    """Strip control/format characters from operator-authored public copy."""
    if not isinstance(value, str):
        return value
    return "".join(
        ch for ch in value
        if unicodedata.category(ch) not in {"Cc", "Cf"}
    )


def _is_iso_timestamp(value):
    """Return true for bounded ISO-8601 date-time strings."""
    if not _is_limited_string(value, _INCIDENT_STRING_LIMITS["started_at"]):
        return False
    return _parse_iso_datetime(value) is not None


def _is_future_incident_timestamp(value):
    """Return true when an operator timestamp is implausibly far ahead."""
    parsed = _parse_iso_datetime(value)
    if parsed is None:
        return False
    return parsed > datetime.now(timezone.utc) + INCIDENT_FUTURE_SKEW


def _parse_iso_datetime(value):
    """Parse a bounded ISO-8601 date-time string as UTC."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        # Terraform pins this Lambda to python3.12; normalize Z explicitly so
        # operator incident timestamps keep working if the helper is reused.
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# S3 helpers and utilities
# ---------------------------------------------------------------------------

def _load_json(key, missing_ok=True, parse_error_ok=False, missing_traceback=True):
    """Read JSON from S3; missing keys always return None.

    missing_ok controls non-missing read/parse failures. parse_error_ok treats
    malformed or oversized JSON as absent when a caller can safely rebuild.
    """
    bucket = os.environ.get("STATUS_BUCKET", "")
    if not bucket:
        return None
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        content_length = resp.get("ContentLength")
        if (
            isinstance(content_length, int)
            and content_length > JSON_OBJECT_READ_BYTES_LIMIT
        ):
            raise _JsonObjectTooLarge(f"{key} is {content_length} bytes")
        body = resp["Body"].read(JSON_OBJECT_READ_BYTES_LIMIT + 1)
        if len(body) > JSON_OBJECT_READ_BYTES_LIMIT:
            raise _JsonObjectTooLarge(f"{key} exceeds {JSON_OBJECT_READ_BYTES_LIMIT} bytes")
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        if _is_missing_s3_key(exc):
            if missing_traceback:
                print(f"WARN: Missing {key}: {traceback.format_exc()}")
            else:
                print(f"WARN: Missing {key}")
            return None
        if parse_error_ok and isinstance(exc, (json.JSONDecodeError, _JsonObjectTooLarge)):
            print(f"WARN: Ignoring malformed {key}: {traceback.format_exc()}")
            return None
        if not missing_ok:
            print(f"ERROR: Failed to load required {key}: {traceback.format_exc()}")
            raise
        print(f"WARN: Failed to load {key}: {traceback.format_exc()}")
        return None


class _JsonObjectTooLarge(ValueError):
    pass


def _is_missing_s3_key(exc):
    if not isinstance(exc, ClientError):
        return False
    code = exc.response.get("Error", {}).get("Code")
    return code in {"NoSuchKey", "404"}


def _parse_csv(value):
    """Split a comma-separated string into a list, dropping empty entries."""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
