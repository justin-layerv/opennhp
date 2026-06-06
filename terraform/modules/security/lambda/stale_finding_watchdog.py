"""
GuardDuty stale-finding watchdog (#1137).

Runs on a schedule. Lists non-archived GuardDuty findings at or above the
alert severity threshold whose UpdatedAt is older than STALE_AGE_DAYS, and
re-publishes a summary to SNS. The Slack topic (if configured) gets a
Chatbot CustomNotification; the email topic (if configured) gets plain text.

Why: a HIGH-severity finding sat Archived=false for ~2 months (nhp#1137).
The initial EventBridge -> SNS alert fired once and was missed. This watchdog
re-alerts on the configured schedule (default: weekly) until an operator
archives the finding, so "no one noticed" stops being a failure mode.
"""

import json
import logging
import os
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _parse_severity_threshold(raw: str) -> int:
    """Coerce env-var string to int for GuardDuty ListFindings.

    botocore rejects float for severity.Gte. int(float(raw)) (not
    bare int) tolerates a "4.0"-style env var; fractional input
    is fail-safe (TF floor() validation is the real fence).
    """
    parsed = float(raw)
    coerced = int(parsed)
    if coerced != parsed:
        logger.warning(
            "SEVERITY_THRESHOLD=%r truncated to %d at module load; "
            "TF floor()-validation should have rejected this at plan time.",
            raw,
            coerced,
        )
    return coerced


ENVIRONMENT = os.environ['ENVIRONMENT']
ALERTS_SNS_TOPIC_ARN = os.environ.get('ALERTS_SNS_TOPIC_ARN', '')
EMAIL_SNS_TOPIC_ARN = os.environ.get('EMAIL_SNS_TOPIC_ARN', '')
SEVERITY_THRESHOLD = _parse_severity_threshold(os.environ['SEVERITY_THRESHOLD'])
STALE_AGE_DAYS = int(os.environ['STALE_AGE_DAYS'])
# Triage-runbook link appended to alert bodies. Sourced from the
# guardduty_triage_runbook_url Terraform local so the EventBridge alert
# templates and this watchdog stay in lockstep. Under Terraform this is always
# set (runbook_base_url is validation-guaranteed non-empty), so the empty-string
# guard below is belt-and-suspenders for standalone / raw-JSON-replay invocation
# rather than a reachable TF deploy state — it omits the line instead of
# emitting a blank `<|Triage runbook>` link.
TRIAGE_RUNBOOK_URL = os.environ.get('TRIAGE_RUNBOOK_URL', '')

# get_findings caps at 50 IDs per call per the AWS API contract.
GET_FINDINGS_BATCH = 50

# Top-N findings included verbatim in the alert body. More than this and
# the Slack message gets unwieldy; the rest are summarised as "and N more".
ALERT_SHOWN_MAX = 10

# Hard cap on pages fetched from list_findings.paginate. The
# updatedAt pushdown keeps the common case empty; this cap bounds
# the pathological case (thousands of simultaneously stale findings)
# well inside the 120-second Lambda timeout.
LIST_FINDINGS_MAX_PAGES = 20

# Pinned to the Lambda's own region. DescribeRegions is effectively
# global (returns the full opt-in list regardless of which region
# asks), so single-region binding is fine here.
ec2 = boto3.client('ec2')
sns = boto3.client('sns')
cw = boto3.client('cloudwatch')


def handler(event, context):
    # Scheduled-rule payloads carry no user data, so full-event
    # logging is safe. If this Lambda is ever wired to a reactive
    # trigger with tenant/user data, redact or drop the event here.
    logger.info('Invoked: event=%s aws_request_id=%s', event, getattr(context, 'aws_request_id', None))
    # Compute cutoff once per invocation so every region/detector
    # sees the same staleness boundary — avoids sub-second skew
    # across a fleet-wide sweep.
    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_AGE_DAYS)
    stale = []
    region_errors = 0
    for region in _list_enabled_regions():
        # A transient 5xx in one region must not black-hole the whole
        # sweep — that would shift the "no one noticed" failure mode
        # from GuardDuty to the watchdog itself. Log, count, and
        # continue; RegionCheckErrors gives ops a signal if the
        # failure rate is sustained.
        try:
            region_stale, detector_errors = _check_region(region, cutoff)
            stale.extend(region_stale)
            region_errors += detector_errors
        except Exception:
            region_errors += 1
            logger.exception('Failed to check region %s', region)

    # Publish BEFORE metric emission: a CloudWatch throttle on
    # PutMetricData must not silence the actual stale-finding alert
    # — that would recreate the exact "no one noticed" failure shape
    # this watchdog exists to close. _emit_metric wraps its own
    # exception as further defense.
    if stale:
        logger.warning('Found %d stale GuardDuty finding(s) (%d region error(s)).', len(stale), region_errors)
        _publish_alert(stale)
    else:
        logger.info('No stale GuardDuty findings (%d region error(s)).', region_errors)

    _emit_metric(len(stale))
    if region_errors:
        _emit_region_error_metric(region_errors)

    return {
        'stale_count': len(stale),
        'finding_ids': [f['Id'] for f in stale],
        'region_errors': region_errors,
    }


def _list_enabled_regions():
    """Enumerate the regions GuardDuty can run in.
    DescribeRegions returns every region this account is opted into, so
    multi-region GuardDuty footprints (the AWS-recommended default) are
    covered without requiring ops to hard-code the region set. Falls
    back to the Lambda's own region if the call fails OR returns an
    empty list — an empty response would otherwise silently emit
    metric=0 and re-introduce the "no one noticed" failure mode.
    """
    fallback = [os.environ.get('AWS_REGION', 'us-east-1')]
    try:
        resp = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in resp.get('Regions', []) if r.get('RegionName')]
    except Exception as exc:
        logger.warning('describe_regions failed, falling back to Lambda region: %s', exc)
        return fallback
    if not regions:
        logger.warning('describe_regions returned empty, falling back to Lambda region')
        return fallback
    return regions


def _check_region(region, cutoff):
    """Return (findings, detector_errors) for one region. No detector
    (GuardDuty not enabled in this region) is a no-op, not an error —
    greenfield accounts frequently have GD enabled in only a subset
    of regions. A per-detector try/except preserves findings already
    collected from earlier detectors even if a later one fails; the
    whole point of this watchdog is that silent data loss is the
    failure mode we're closing.
    """
    gd = boto3.client('guardduty', region_name=region)
    detector_ids = gd.list_detectors().get('DetectorIds', [])
    if not detector_ids:
        return [], 0

    stale = []
    errors = 0
    for detector_id in detector_ids:
        try:
            stale.extend(_find_stale_findings(gd, detector_id, region, cutoff))
        except Exception:
            errors += 1
            logger.exception('Failed to fetch findings for %s/%s', region, detector_id)
    return stale, errors


def _find_stale_findings(gd, detector_id, region, cutoff):
    """Return findings that are non-archived, at or above the severity
    threshold, and last updated more than STALE_AGE_DAYS ago. Staleness
    is pushed into ListFindings.FindingCriteria as an updatedAt Lte
    filter so the common case (no stale findings) returns zero IDs and
    skips GetFindings entirely - preventing a multi-thousand-finding
    account from timing out the watchdog.

    SortCriteria is updatedAt ASC on purpose: when LIST_FINDINGS_MAX_PAGES
    truncates, the oldest stale findings stay and the newly-stale ones
    drop off. That matches the watchdog's intent (the multi-month-old
    finding is the shape we're guarding against), and
    StaleGuardDutyFindingsTruncated makes truncation alarmable. Do NOT
    flip this to DESC without rethinking that policy.
    """
    cutoff_millis = int(cutoff.timestamp() * 1000)
    finding_ids = []

    paginator = gd.get_paginator('list_findings')
    pages = paginator.paginate(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'service.archived': {'Eq': ['false']},
                # botocore rejects float for severity.Gte.
                'severity': {'Gte': SEVERITY_THRESHOLD},
                'updatedAt': {'Lte': cutoff_millis},
            },
        },
        SortCriteria={'AttributeName': 'updatedAt', 'OrderBy': 'ASC'},
    )
    # Truncation detection: iterate up to MAX_PAGES+1. If the
    # paginator yields a page beyond the cap we know more data
    # exists; discard that extra page's IDs and flag truncated. If
    # the iterator exhausts at exactly MAX_PAGES, no truncation
    # happened — this avoids the false-positive metric the prior
    # `page_num >= MAX` check produced on exactly-full result sets.
    truncated = False
    for page_num, page in enumerate(pages, start=1):
        if page_num > LIST_FINDINGS_MAX_PAGES:
            logger.warning(
                'list_findings page cap (%d) hit in %s/%s; results truncated',
                LIST_FINDINGS_MAX_PAGES, region, detector_id,
            )
            truncated = True
            break
        finding_ids.extend(page.get('FindingIds', []))
    if truncated:
        _emit_truncation_metric()

    if not finding_ids:
        return []

    findings = []
    for i in range(0, len(finding_ids), GET_FINDINGS_BATCH):
        batch = finding_ids[i:i + GET_FINDINGS_BATCH]
        resp = gd.get_findings(DetectorId=detector_id, FindingIds=batch)
        for f in resp.get('Findings', []):
            # The console deep-link is region-scoped; stamping the
            # finding's region on the dict lets _finding_url route
            # operators straight to the right console without a
            # second environment lookup.
            f['_region'] = region
            findings.append(f)

    return findings


# Sentinel used so a malformed UpdatedAt sorts to the top of the
# list (most-stale-first in _publish_alert) instead of crashing the
# sort. If a finding is malformed we'd rather show it first than
# drop the whole alert.
_MIN_TIMESTAMP = datetime.min.replace(tzinfo=timezone.utc)


def _parse_timestamp(value):
    if value is None:
        return _MIN_TIMESTAMP
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return _MIN_TIMESTAMP


def _format_timestamp(value):
    # boto3 normalises GuardDuty timestamp fields into datetime
    # objects at unmarshal time, but the test fixtures (and raw JSON
    # replay) hand us ISO strings. Normalise both into a single
    # isoformat so dev and prod output render identically. The
    # `== _MIN_TIMESTAMP` branch is a parse-failure fallback — a
    # legitimate `0001-01-01T00:00:00Z` finding would collide, but
    # AWS wasn't around in year 1, so this is fine in practice.
    if value is None:
        return '?'
    parsed = _parse_timestamp(value)
    if parsed == _MIN_TIMESTAMP:
        return str(value)
    return parsed.isoformat()


def _publish_alert(stale):
    # Sort by severity desc, then oldest-updated first. Parsing
    # UpdatedAt to a datetime instead of comparing ISO-8601 strings
    # insulates us from a future AWS-side switch from `Z` suffix to
    # `+00:00` offset (the two sort differently lexicographically).
    ordered = sorted(
        stale,
        # `or 0` instead of default=0 handles a null Severity field
        # gracefully — defence against a partially-constructed finding
        # we'd rather sort than crash on.
        key=lambda f: (-float(f.get('Severity') or 0), _parse_timestamp(f.get('UpdatedAt'))),
    )
    shown = ordered[:ALERT_SHOWN_MAX]
    overflow = len(ordered) - len(shown)

    # Isolate per-channel failures: a throttle or transient 5xx
    # publishing to Slack must not suppress the email path (and vice
    # versa). Errors in either path still surface via the
    # AWS/Lambda Errors alarm; this just keeps one failing channel
    # from silencing the other.
    if ALERTS_SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=ALERTS_SNS_TOPIC_ARN,
                Subject=_subject(len(stale)),
                Message=json.dumps(_slack_message(shown, overflow, len(stale))),
            )
        except Exception:
            logger.exception('Failed to publish Slack alert')
    if EMAIL_SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=EMAIL_SNS_TOPIC_ARN,
                Subject=_subject(len(stale)),
                Message=_email_message(shown, overflow, len(stale)),
            )
        except Exception:
            logger.exception('Failed to publish email alert')


def _subject(count):
    return f'[{ENVIRONMENT}] {count} stale GuardDuty finding(s)'


def _finding_url(finding_id, region):
    # `macros=current&fId=<id>` opens the detail pane directly rather
    # than a list filtered by a substring match, so an operator paged
    # at 02:00 lands on the finding's own page, not a search result.
    # urllib.parse.quote is cheap insurance against a future AWS-side
    # change to finding-ID format that includes URL-unsafe bytes.
    return (
        f'https://{region}.console.aws.amazon.com/guardduty/home'
        f'?region={region}#/findings?macros=current&fId={urllib.parse.quote(finding_id, safe="")}'
    )


def _slack_message(shown, overflow, total):
    lines = [
        f'*{total} GuardDuty finding(s) un-archived for >= {STALE_AGE_DAYS} days in `{ENVIRONMENT}`*',
        '',
    ]
    for f in shown:
        # Slack's link syntax is <url|text>; a `|` in the finding title
        # breaks the link parser. GuardDuty titles are AWS-authored so
        # the risk is cosmetic, but swap to a dash defensively so a
        # future AWS-side format change can't silently garble the
        # alert.
        title = f.get('Title', '(no title)').replace('|', '-')
        sev = f.get('Severity', 0)
        updated = _format_timestamp(f.get('UpdatedAt'))
        region = f.get('_region', '?')
        lines.append(f"- `{region}` Severity `{sev}` - <{_finding_url(f['Id'], region)}|{title}> (updated `{updated}`)")
    if overflow > 0:
        lines.append(f'... and {overflow} more')

    next_steps = [
        'Investigate each finding at the linked console page.',
        'Archive via `aws guardduty archive-findings` once triaged, or remediate the underlying issue.',
    ]
    if TRIAGE_RUNBOOK_URL:
        next_steps.append(f'<{TRIAGE_RUNBOOK_URL}|Triage runbook>')

    return {
        'version': '1.0',
        'source': 'custom',
        'content': {
            'textType': 'client-markdown',
            'title': f':rotating_light: Stale GuardDuty findings - {ENVIRONMENT}',
            'description': '\n'.join(lines),
            'nextSteps': next_steps,
        },
    }


def _email_message(shown, overflow, total):
    lines = [
        f'{total} GuardDuty finding(s) un-archived for >= {STALE_AGE_DAYS} days in {ENVIRONMENT}.',
        '',
    ]
    for f in shown:
        region = f.get('_region', '?')
        lines.extend([
            f"- {f.get('Title', '(no title)')}",
            f"  Severity: {f.get('Severity', 0)}",
            f"  Region:   {region}",
            f"  Updated:  {_format_timestamp(f.get('UpdatedAt'))}",
            f"  Id:       {f['Id']}",
            f"  Console:  {_finding_url(f['Id'], region)}",
        ])
    if overflow > 0:
        lines.append(f'... and {overflow} more')
    lines.extend([
        '',
        'Archive via `aws guardduty archive-findings` once triaged, or remediate the underlying issue.',
    ])
    if TRIAGE_RUNBOOK_URL:
        lines.append(f'Triage runbook: {TRIAGE_RUNBOOK_URL}')
    return '\n'.join(lines)


def _emit_metric(count):
    _safe_put_metric('StaleGuardDutyFindings', count)


def _emit_region_error_metric(count):
    _safe_put_metric('StaleGuardDutyFindingsRegionErrors', count)


def _emit_truncation_metric():
    # Emitted only when LIST_FINDINGS_MAX_PAGES truncates a region's
    # result set (>=1000 stale findings in a single detector). Gives
    # ops an alarmable signal without having to grep CloudWatch Logs.
    # Fires per-detector, not per-region: a dashboard looking at rate
    # divides by detector-count, not region-count.
    _safe_put_metric('StaleGuardDutyFindingsTruncated', 1)


def _safe_put_metric(name, value):
    # Swallow exceptions so a CloudWatch throttle or transient 5xx
    # can't raise out of handler and suppress the stale-finding
    # publish — that would recreate the "no one noticed" failure
    # mode this watchdog closes. Errors land in the Lambda log and
    # the AWS/Lambda Errors alarm already trips on any raise, so
    # observability isn't lost.
    try:
        cw.put_metric_data(
            Namespace='LayerV/NHP/Security',
            MetricData=[{
                'MetricName': name,
                'Value': value,
                'Unit': 'Count',
                'Dimensions': [{'Name': 'Environment', 'Value': ENVIRONMENT}],
            }],
        )
    except Exception:
        logger.exception('Failed to emit %s metric', name)
