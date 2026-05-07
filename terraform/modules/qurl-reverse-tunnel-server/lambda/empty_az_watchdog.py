"""
Per-AZ qurl-reverse-tunnel-server Cloud Map empty-registration watchdog (#1542).

Runs every 5 minutes. Iterates the configured AZ suffix list, calls
ServiceDiscovery DiscoverInstances for each `frps-${suffix}` service, and
emits a `QurlFRPS/PerAZRegistrationCount` custom metric per AZ with the
`AZSuffix` dimension.

Why detection (this PR) vs. structural (PR #1549):

  PR #1539 makes the qurl-reverse-tunnel-server fleet run as a single ASG with min=max=
  desired=length(frps_az_suffixes). The ASG's AZ-balanced placement keeps
  the steady-state distribution at one instance per AZ — but a rebalance
  during an instance refresh, or an EC2 launch failure in one AZ, can
  silently produce a (2, 1, 0) distribution where one Cloud Map service
  is empty. Existing alarms (`GroupInServiceInstances < 1`) are satisfied
  at total count = 3, so they don't catch this. OwnerIDs that hash to the
  empty AZ resolve NXDOMAIN.

  PR #1549 ships the structural fence: one ASG per AZ, each pinned to a
  single subnet, min=max=desired=1 — making the (1,1,1) distribution
  invariant. Until that lands, this watchdog is the detection layer.

  Once #1549 is in steady state, this watchdog stays in place as defense
  in depth (a Cloud Map deregistration race or an out-of-band
  deregistration could still empty a service even with a one-ASG-per-AZ
  topology).

Failure modes the watchdog must NOT introduce:
- Single per-AZ DiscoverInstances failure must not black-hole the whole
  sweep — log, count, continue. The metric for the failed AZ stays at
  the prior value (no PutMetricData for that AZ this cycle); the alarm's
  `treat_missing_data = "missing"` keeps it on the prior decision.
- A throttle on PutMetricData must not silence the actual "empty AZ"
  signal: emit metrics in declared order so suffix `a` always gets a
  PutMetricData attempt before `b`/`c`, and a per-call exception is
  logged but does not abort the loop.

Total-failure escalation:
- A region-wide CloudWatch outage (every PutMetricData raises) or full
  ServiceDiscovery outage (every DiscoverInstances raises) is treated
  as a watchdog failure: the handler raises a `WatchdogTotalFailure`
  exception so the AWS/Lambda `Errors` metric increments and the
  self-failure alarm fires. Without this, an all-fail run would log
  per-call but return cleanly — every per-AZ alarm would transition to
  INSUFFICIENT_DATA via `treat_missing_data = "missing"` (which is NOT
  an ALARM state and would NOT page through `alarm_actions`), and the
  Lambda Errors / EventBridge FailedInvocations counters would stay
  at 0, leaving the outage entirely silent. Per-AZ partial failures
  (1-of-3) intentionally do NOT escalate — those are the transient
  blips the per-suffix isolation is designed to ride out.

Lambda warm-container caching:
- `AZ_SUFFIXES` is parsed at module import time. Lambda caches the
  import across warm invocations, so a Terraform apply that updates
  the `AZ_SUFFIXES` env var (e.g., adding a 4th AZ suffix) won't take
  effect on already-warm containers until they recycle. AWS publishes
  a new function configuration version on env-var change, which
  generally bounces the warm pool, but the rollout pace varies.
  Adding/removing suffixes is therefore not a hot-update — expect a
  ~5-15 min lag before the new fanout is visible in metrics.
"""

import logging
import os
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

NAMESPACE_NAME = os.environ['NAMESPACE_NAME']
# No `ENVIRONMENT` env var: alarm names carry env via `name_prefix`
# and `AZSuffix` is the only metric dimension. Adding one would only
# add a cold-start KeyError surface.


def _parse_suffixes(raw: str) -> list[str]:
    """Parse the AZ_SUFFIXES env var into a stripped, non-empty list.

    Post-#1539, the Terraform `frps_az_suffixes` validation blocks (root
    variables.tf and module variables.tf — see those for the regex /
    non-empty / dedupe rules) reject malformed input at plan time. The
    only remaining failure path this helper guards is a runtime-only
    edge case: a stale Lambda env var on in-place reconfig (e.g., manual
    `aws lambda update-function-configuration --environment` outside the
    Terraform-managed lifecycle), where the env var could carry extra
    whitespace or accidental empty entries. The strip+filter keeps the
    Lambda from misbehaving in that case rather than the watchdog
    crashing on a malformed value.

    Extracted as a named function so unit tests can drive it directly
    without going through the sys.modules-swap re-import dance.
    """
    return [s.strip() for s in raw.split(',') if s.strip()]


AZ_SUFFIXES = _parse_suffixes(os.environ['AZ_SUFFIXES'])

CLOUDWATCH_NAMESPACE = 'QurlFRPS'
CLOUDWATCH_METRIC = 'PerAZRegistrationCount'

# Pinned to the Lambda's own region — Cloud Map services and the alarms
# both live in the same region as this Lambda. No cross-region calls.
sd = boto3.client('servicediscovery')
cw = boto3.client('cloudwatch')


class WatchdogTotalFailure(RuntimeError):
    """Raised when every per-AZ call to one of the two AWS APIs failed.

    Distinct from a partial failure (1-of-N AZ blip), which is logged
    and absorbed so the remaining suffixes still publish. A *total*
    failure means the per-suffix alarms can't transition through ALARM
    on this cycle — every datapoint is missing or stale-zero — so the
    handler escalates by raising. The raise increments AWS/Lambda
    `Errors`, which fires `empty_az_watchdog_errors` and pages.
    Without this escalation an all-fail run would return cleanly and
    the outage would be silent until per-AZ alarms drifted into
    INSUFFICIENT_DATA (which is not an ALARM state).
    """


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    # CONSTRAINT: only an EventBridge schedule rule may invoke this
    # Lambda. The schedule sends a dataless trigger so the full event
    # is safe to log at INFO. If a future change wires a different
    # invocation source (manual `aws lambda invoke` with a payload,
    # SQS subscription, etc.), audit the new payload first — the
    # full-event INFO log would otherwise become a data-leak vector.
    # Drop to DEBUG and log only `aws_request_id` + suffix count if
    # the new source can carry tenant or user data.
    logger.info(
        'Invoked: event=%s aws_request_id=%s suffixes=%s',
        event,
        getattr(context, 'aws_request_id', None),
        AZ_SUFFIXES,
    )

    counts: dict[str, int] = {}
    discover_errors = 0
    put_errors = 0
    put_attempts = 0

    for suffix in AZ_SUFFIXES:
        service_name = f'frps-{suffix}'
        try:
            count = _count_instances(service_name)
        # Catch broadly: future boto3 response-shape changes might
        # raise types outside the (ClientError, BotoCoreError)
        # hierarchy (e.g., a json.JSONDecodeError on malformed
        # response, or a KeyError under `_count_instances` parsing).
        # The per-suffix isolation contract is "any single AZ failure
        # must not abort the sweep" — narrowing to ClientError/
        # BotoCoreError would let those slip through and propagate to
        # the handler's outer scope, killing the remaining AZs and
        # silencing real signal. The all-fail escalation in `handler`
        # below catches the case where every AZ fails by ANY cause.
        except Exception:  # noqa: BLE001
            # A single-AZ DiscoverInstances failure is logged and the
            # cycle continues. The alarm's `treat_missing_data = "missing"`
            # keeps the previous state until the next successful read.
            logger.exception(
                'DiscoverInstances failed for service=%s namespace=%s',
                service_name,
                NAMESPACE_NAME,
            )
            discover_errors += 1
            continue

        counts[suffix] = count
        put_attempts += 1
        if not _emit_metric(suffix, count):
            put_errors += 1

    logger.info(
        'Sweep complete: counts=%s discover_errors=%d put_errors=%d',
        counts,
        discover_errors,
        put_errors,
    )

    n = len(AZ_SUFFIXES)
    # Total-failure escalation: escalate when no AZ got a successful
    # publish on this cycle. A partial failure (1-of-N) is the transient
    # blip the per-suffix isolation is designed to ride out — that AZ's
    # per-AZ alarm holds prior state via `treat_missing_data = "missing"`
    # and the AZs that did publish keep their alarms current. An all-fail
    # cycle (every suffix had either a discover_error or a put_error)
    # means every per-AZ alarm goes stale together; without escalation
    # they all drift to INSUFFICIENT_DATA after `evaluation_periods`
    # cycles — silent, since INSUFFICIENT_DATA does not fire
    # `alarm_actions`. The single unified guard `total_errors == n`
    # correctly covers both pure-discover and pure-put outages plus the
    # mixed case (e.g., 2-of-3 discover failed and the 1 surviving
    # discover's publish also throttled — every AZ failed, escalate).
    # See WatchdogTotalFailure docstring for the full rationale.
    total_errors = discover_errors + put_errors
    if n > 0 and total_errors == n:
        raise WatchdogTotalFailure(
            f'no AZ got a successful publish this cycle '
            f'(discover_errors={discover_errors}, put_errors={put_errors}, '
            f'total_suffixes={n}) — every per-AZ alarm will go stale and '
            f'drift to INSUFFICIENT_DATA; escalating to fire Lambda '
            f'Errors alarm.'
        )

    # Lambda return value is consumed only by the EventBridge invocation
    # (logged in CloudTrail / CloudWatch but not asserted on). Returned
    # for parity with other watchdogs and to keep the test harness simple.
    return {
        'counts': counts,
        'discover_errors': discover_errors,
        'put_errors': put_errors,
    }


def _count_instances(service_name: str) -> int:
    # We pass `HealthStatus='ALL'` to future-proof the empty-detection
    # contract. Today every registered instance is implicitly HEALTHY
    # (the qurl-reverse-tunnel-server module declares `health_check_custom_config` on
    # `aws_service_discovery_service.frps_per_az` in main.tf but no
    # caller invokes `UpdateInstanceCustomHealthStatus` yet — that's
    # tracked in #1089), so `ALL` and `HEALTHY` return the same set
    # in 2026-Q2 reality. After #1089 lands, an UNHEALTHY-flagged
    # instance will stay in the WEIGHTED routing pool until it's
    # explicitly deregistered — so an AZ with one UNHEALTHY instance
    # is NOT empty by the alarm's contract, but would be undercounted
    # if we passed `HealthStatus='HEALTHY'`. The alarm semantic is
    # "did Cloud Map have any registration the resolver could return?",
    # which maps to ALL. Pinning ALL now means #1089 doesn't have to
    # remember to update this Lambda.
    response = sd.discover_instances(
        NamespaceName=NAMESPACE_NAME,
        ServiceName=service_name,
        HealthStatus='ALL',
        # DiscoverInstances supports MaxResults 1..1000 and does not
        # paginate. We pass 1000 (the API ceiling) so the response
        # always carries the true count — eliminating the silent
        # under-count window where the watchdog's metric reads OK
        # (any value > 0) while a real stale-registration leak past
        # 100 was capped invisibly. The `len(instances) == 1000`
        # warning below now genuinely flags an unprecedented
        # situation rather than just a cap chosen by us.
        MaxResults=1000,
    )
    instances = response.get('Instances', [])
    # `MaxResults=1000` is the API ceiling for this call. Hitting it
    # would mean a single Cloud Map service holds 1000 registrations,
    # which is far beyond any plausible scaling profile and indicates
    # a stale-registration leak so severe that the metric publish is
    # almost certainly the wrong response anyway. Logged loudly so
    # the operator sees it; alarming is filed as #1566.
    if len(instances) == 1000:
        logger.warning(
            'DiscoverInstances API ceiling of 1000 reached for service=%s — '
            'unprecedented registration count, almost certainly a stale-'
            'registration leak. Investigate manually.',
            service_name,
        )
    return len(instances)


def _emit_metric(suffix: str, count: int) -> bool:
    """Publish the per-AZ count. Returns True on success, False on AWS error.

    One call per suffix instead of batching: PutMetricData is atomic,
    so a batched throttle would silence every AZ at once and defeat
    the partial-failure isolation contract the per-suffix counter
    accounting depends on.
    """
    try:
        cw.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=[
                {
                    'MetricName': CLOUDWATCH_METRIC,
                    'Dimensions': [{'Name': 'AZSuffix', 'Value': suffix}],
                    # CloudWatch accepts int and float; `len()` is always
                    # int so no cast needed.
                    'Value': count,
                    'Unit': 'Count',
                }
            ],
        )
        return True
    # Broad catch (see handler's same-pattern justification): any
    # exception type out of CloudWatch — future response-shape change,
    # network blip, IAM regression — must not abort the per-suffix
    # sweep. The all-fail escalation in `handler` covers the case
    # where every put fails.
    except Exception:  # noqa: BLE001
        # PutMetricData throttle / IAM blip: log and continue so the next
        # suffix in the loop still gets a publish attempt. The alarm's
        # `treat_missing_data = "missing"` carries the prior state until
        # the next cycle. Caller (handler) tracks per-attempt failures
        # under `put_errors` and escalates if every attempt failed.
        logger.exception(
            'PutMetricData failed for suffix=%s count=%d', suffix, count
        )
        return False
