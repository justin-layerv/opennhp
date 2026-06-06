"""
IAM MFA audit (#1138).

Runs on a schedule. Lists IAM users and the MFA devices attached to each, and
publishes an alert naming any user with zero MFA devices. The Slack topic (if
configured) gets a Chatbot CustomNotification; the email topic (if configured)
gets plain text. Emits IAMUsersWithoutMFA to CloudWatch so the count stays
alarmable between runs.

Why: a purple-team CloudTrail review (nhp#1138) found human console logins
without MFA. AWS Config's IAM_USER_MFA_ENABLED rule records the same state but
never pages anyone, so a password-only user can sit unnoticed. This audit
re-alerts on the configured schedule until every user has MFA, so "no one
noticed" stops being a failure mode — mirroring the GuardDuty stale-finding
watchdog (#1137).

Pure read + publish: iam:ListUsers + iam:ListMFADevices + sns:Publish +
cloudwatch:PutMetricData. Never mutates IAM.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ENVIRONMENT = os.environ['ENVIRONMENT']
ALERTS_SNS_TOPIC_ARN = os.environ.get('ALERTS_SNS_TOPIC_ARN', '')
EMAIL_SNS_TOPIC_ARN = os.environ.get('EMAIL_SNS_TOPIC_ARN', '')

# Top-N users named verbatim in the alert; the rest are summarised as
# "and N more" so a large backlog can't produce an unreadable Slack message.
ALERT_SHOWN_MAX = 20

iam = boto3.client('iam')
sns = boto3.client('sns')
cw = boto3.client('cloudwatch')


def handler(event, context):
    # Scheduled-rule payloads carry no user data, so full-event logging is
    # safe. If this Lambda is ever wired to a reactive trigger with
    # tenant/user data, redact or drop the event here.
    logger.info('Invoked: event=%s aws_request_id=%s', event, getattr(context, 'aws_request_id', None))

    users = _list_users()
    without_mfa = []
    checked = 0
    check_errors = 0
    for user in users:
        name = user.get('UserName')
        try:
            # MFA-on-console-login only matters for users that can reach the
            # console. Programmatic-only users (e.g. the auth0_ses SES SMTP
            # user) have no login profile and can never enroll an MFA device,
            # so flagging them would page every run forever and train operators
            # to ignore the alarm — the exact alert-fatigue failure mode this
            # audit exists to prevent. Skip them.
            if not _has_console_access(name):
                continue
            # Resolve MFA before incrementing `checked` so a user whose
            # _has_mfa lookup throws lands in check_errors only, not in both
            # checked and check_errors.
            has_mfa = _has_mfa(name)
            checked += 1
            if not has_mfa:
                without_mfa.append(name)
        except Exception:
            # A transient IAM 5xx on one user must not abort the sweep — that
            # would shift the silent-failure mode from "user has no MFA" to
            # "audit never finished". Count and continue; the
            # IAMMfaAuditCheckErrors metric gives ops a signal if the failure
            # rate is sustained.
            check_errors += 1
            logger.exception('Failed to check MFA for user %s', name)

    # Publish BEFORE metric emission: a CloudWatch throttle on PutMetricData
    # must not silence the actual alert. _emit_metric wraps its own exception
    # as further defense.
    publish_errors = 0
    if without_mfa:
        logger.warning('%d console IAM user(s) without MFA (%d check error(s)).', len(without_mfa), check_errors)
        publish_errors = _publish_alert(without_mfa)
    else:
        logger.info('All %d console IAM user(s) have MFA (%d check error(s)).', checked, check_errors)

    # Emit all three metrics every run (0 when clean) so each alarm self-clears
    # on the next clean weekly run. check-errors closes the all-users-failed
    # false-green; publish-errors closes the all-channels-failed one: if a real
    # finding exists but every SNS publish throws, the alert is dropped — and
    # because the per-channel excepts are CAUGHT, the handler returns normally,
    # so the AWS/Lambda Errors alarm never fires. IAMMfaAuditPublishErrors is the
    # only signal that the page was lost.
    _emit_metric(len(without_mfa))
    _emit_check_error_metric(check_errors)
    _emit_publish_error_metric(publish_errors)

    return {
        'users_total': len(users),
        'console_users_checked': checked,
        'users_without_mfa': sorted(without_mfa),
        'check_errors': check_errors,
        'publish_errors': publish_errors,
    }


def _list_users():
    users = []
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        users.extend(page.get('Users', []))
    return users


def _has_console_access(user_name):
    # A user with no login profile is programmatic-only (access keys, no console
    # password) and cannot enroll an MFA device, so it is out of scope for an
    # MFA-on-console-login audit. get_login_profile raises NoSuchEntity for such
    # users; any other ClientError propagates to the per-user handler so it is
    # counted as a check error rather than silently treated as "no console".
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'NoSuchEntity':
            return False
        raise


def _has_mfa(user_name):
    # ListMFADevices returns both virtual and hardware devices for a user, so
    # a single non-empty page means at least one factor is enrolled — return
    # early without draining the paginator.
    paginator = iam.get_paginator('list_mfa_devices')
    for page in paginator.paginate(UserName=user_name):
        if page.get('MFADevices'):
            return True
    return False


def _publish_alert(without_mfa):
    """Publish the finding to every configured channel. Returns the number of
    channels whose publish FAILED, which the handler emits as
    IAMMfaAuditPublishErrors. A caught publish exception does NOT increment the
    AWS/Lambda Errors metric (only an uncaught raise does), so without this
    return value an all-channels-failed run would drop the page silently and
    nothing would alarm.
    """
    ordered = sorted(without_mfa)
    shown = ordered[:ALERT_SHOWN_MAX]
    overflow = len(ordered) - len(shown)

    attempted = 0
    publish_errors = 0
    # Isolate per-channel failures: a throttle or transient 5xx publishing to
    # Slack must not suppress the email path (and vice versa). Each failure is
    # counted (not just logged) so the caller can alarm on a dropped alert.
    if ALERTS_SNS_TOPIC_ARN:
        attempted += 1
        try:
            sns.publish(
                TopicArn=ALERTS_SNS_TOPIC_ARN,
                Subject=_subject(len(ordered)),
                Message=json.dumps(_slack_message(shown, overflow, len(ordered))),
            )
        except Exception:
            publish_errors += 1
            logger.exception('Failed to publish Slack alert')
    if EMAIL_SNS_TOPIC_ARN:
        attempted += 1
        try:
            sns.publish(
                TopicArn=EMAIL_SNS_TOPIC_ARN,
                Subject=_subject(len(ordered)),
                Message=_email_message(shown, overflow, len(ordered)),
            )
        except Exception:
            publish_errors += 1
            logger.exception('Failed to publish email alert')

    if attempted and publish_errors == attempted:
        # Every channel failed: the finding was NOT delivered. The log line is a
        # last resort; IAMMfaAuditPublishErrors (emitted by the caller) is the
        # alarmable signal.
        logger.error('ALL %d alert channel(s) failed — the no-MFA finding was not delivered', attempted)
    return publish_errors


def _subject(count):
    return f'[{ENVIRONMENT}] {count} console IAM user(s) without MFA'


def _slack_message(shown, overflow, total):
    lines = [
        f'*{total} console IAM user(s) have no MFA device in `{ENVIRONMENT}`*',
        '',
    ]
    for name in shown:
        # `name` is an IAM user name; backtick-wrap so Slack renders it as
        # code and an awkward character can't garble the line.
        lines.append(f'- `{name}`')
    if overflow > 0:
        lines.append(f'... and {overflow} more')

    return {
        'version': '1.0',
        'source': 'custom',
        'content': {
            'textType': 'client-markdown',
            'title': f':rotating_light: Console IAM users without MFA - {ENVIRONMENT}',
            'description': '\n'.join(lines),
            'nextSteps': [
                'Enroll an MFA device for each user, or remove the user if unused.',
                'Attach the require_mfa policy so a session without MFA cannot act.',
            ],
        },
    }


def _email_message(shown, overflow, total):
    lines = [
        f'{total} console IAM user(s) have no MFA device in {ENVIRONMENT}.',
        '',
    ]
    for name in shown:
        lines.append(f'- {name}')
    if overflow > 0:
        lines.append(f'... and {overflow} more')
    lines.extend([
        '',
        'Enroll an MFA device for each user, or remove the user if unused.',
        'Attach the require_mfa policy so a session without MFA cannot act.',
    ])
    return '\n'.join(lines)


def _emit_metric(count):
    _safe_put_metric('IAMUsersWithoutMFA', count)


def _emit_check_error_metric(count):
    _safe_put_metric('IAMMfaAuditCheckErrors', count)


def _emit_publish_error_metric(count):
    _safe_put_metric('IAMMfaAuditPublishErrors', count)


def _safe_put_metric(name, value):
    # Swallow exceptions so a CloudWatch throttle or transient 5xx can't raise
    # out of handler and suppress the alert publish — that would recreate the
    # "no one noticed" failure mode this audit closes. Errors land in the
    # Lambda log and the AWS/Lambda Errors alarm trips on any raise, so
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
