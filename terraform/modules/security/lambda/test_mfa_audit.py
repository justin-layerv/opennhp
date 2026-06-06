"""
Tests for the IAM MFA audit Lambda (#1138).

Run with: python3 -m pytest terraform/modules/security/lambda/test_mfa_audit.py -v
Run this file in ITS OWN process (not a directory-wide `discover`/`pytest`):
the import-time `sys.modules['boto3']` swap plus the `assert 'boto3' not in
sys.modules` guard below trip if another lambda test (e.g.
test_stale_finding_watchdog.py) is imported into the same process first. CI
invokes the two files as separate pytest runs for exactly this reason.
Mirrors test_stale_finding_watchdog.py: stdlib unittest.mock drives boto3.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

os.environ.update({
    'ENVIRONMENT': 'test',
    'ALERTS_SNS_TOPIC_ARN': 'arn:aws:sns:us-east-2:123456789012:test-alerts',
    'EMAIL_SNS_TOPIC_ARN': 'arn:aws:sns:us-east-2:123456789012:test-email',
    'AWS_REGION': 'us-east-2',
})


# sys.modules swap is load-bearing: mfa_audit calls boto3.client(...) at
# import time (iam/sns/cw module globals). A per-test patch would be too late.
# The assert turns a silent regression — something pulling boto3 transitively
# before this file runs — into a loud test-time failure.
assert 'boto3' not in sys.modules, (
    'boto3 imported before test module loaded; the sys.modules swap below is '
    'no longer load-bearing and mfa_audit will construct real AWS clients at '
    'import time.'
)
_IMPORT_TIME_BOTO = MagicMock()
_IMPORT_TIME_BOTO.client.return_value = MagicMock()
sys.modules['boto3'] = _IMPORT_TIME_BOTO

import mfa_audit  # noqa: E402


def _users(*names):
    return [{'UserName': n} for n in names]


def _users_paginator(*names):
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{'Users': _users(*names)}])
    return paginator


def _mfa_paginator_for(devices_by_user):
    """A list_mfa_devices paginator whose pages depend on the UserName kwarg.

    devices_by_user maps user name -> list of device dicts. A user absent
    from the map (or mapped to []) is treated as having no MFA device.
    """
    def paginate(UserName, **_):
        return iter([{'MFADevices': devices_by_user.get(UserName, [])}])

    paginator = MagicMock()
    paginator.paginate.side_effect = paginate
    return paginator


def _login_profile_for(console_users):
    """get_login_profile side_effect: returns a profile for console_users and
    raises NoSuchEntity (programmatic-only, e.g. auth0_ses) for everyone else.
    """
    def get_login_profile(UserName, **_):
        if UserName in console_users:
            return {'LoginProfile': {'UserName': UserName}}
        raise ClientError(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'Login Profile not found'}},
            'GetLoginProfile',
        )

    return get_login_profile


class MfaAuditTestCase(unittest.TestCase):
    def setUp(self):
        self.iam = MagicMock(name='iam')
        self.sns = MagicMock(name='sns')
        self.cw = MagicMock(name='cloudwatch')
        mfa_audit.iam = self.iam
        mfa_audit.sns = self.sns
        mfa_audit.cw = self.cw

    def _wire(self, names, devices_by_user, console_users=None):
        # console_users defaults to "all names have a console login profile";
        # pass a subset to exercise the programmatic-only exclusion.
        def get_paginator(op):
            if op == 'list_users':
                return _users_paginator(*names)
            if op == 'list_mfa_devices':
                return _mfa_paginator_for(devices_by_user)
            raise AssertionError(f'unexpected paginator {op}')

        self.iam.get_paginator.side_effect = get_paginator
        self.iam.get_login_profile.side_effect = _login_profile_for(
            set(names) if console_users is None else set(console_users)
        )

    def test_flags_user_without_mfa(self):
        self._wire(['alice', 'bob'], {'alice': [{'SerialNumber': 'x'}]})
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_total'], 2)
        self.assertEqual(result['users_without_mfa'], ['bob'])
        self.assertEqual(result['check_errors'], 0)
        # Both channels published exactly once.
        self.assertEqual(self.sns.publish.call_count, 2)
        # Metric emitted with the count of un-MFA'd users.
        emitted = self._emitted_metric('IAMUsersWithoutMFA')
        self.assertEqual(emitted, 1)

    def test_no_alert_when_all_have_mfa(self):
        self._wire(
            ['alice', 'bob'],
            {'alice': [{'SerialNumber': 'x'}], 'bob': [{'SerialNumber': 'y'}]},
        )
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_without_mfa'], [])
        self.sns.publish.assert_not_called()
        self.assertEqual(self._emitted_metric('IAMUsersWithoutMFA'), 0)
        # check-errors metric is emitted every run (0 here) so its alarm
        # self-clears on a clean run rather than sticking via missing-data.
        self.assertEqual(self._emitted_metric('IAMMfaAuditCheckErrors'), 0)

    def test_check_error_isolated_and_counted(self):
        # bob's MFA lookup raises; alice still gets evaluated and the run
        # completes rather than aborting the whole sweep.
        def get_paginator(op):
            if op == 'list_users':
                return _users_paginator('alice', 'bob')
            if op == 'list_mfa_devices':
                paginator = MagicMock()

                def paginate(UserName, **_):
                    if UserName == 'bob':
                        raise RuntimeError('throttled')
                    return iter([{'MFADevices': []}])

                paginator.paginate.side_effect = paginate
                return paginator
            raise AssertionError(f'unexpected paginator {op}')

        self.iam.get_paginator.side_effect = get_paginator
        self.iam.get_login_profile.side_effect = _login_profile_for({'alice', 'bob'})
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_without_mfa'], ['alice'])
        self.assertEqual(result['check_errors'], 1)
        # bob's _has_mfa threw, so he is counted as a check error only — not in
        # console_users_checked (which counts successful MFA evaluations).
        self.assertEqual(result['console_users_checked'], 1)
        self.assertEqual(self._emitted_metric('IAMMfaAuditCheckErrors'), 1)

    def test_excludes_programmatic_only_user(self):
        # svc has no console login profile (e.g. auth0_ses) and no MFA device.
        # It must NOT be flagged — only console-enabled alice (also no MFA) is.
        self._wire(['alice', 'svc'], {}, console_users={'alice'})
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_total'], 2)
        self.assertEqual(result['console_users_checked'], 1)
        self.assertEqual(result['users_without_mfa'], ['alice'])
        self.assertEqual(result['check_errors'], 0)
        # svc was never MFA-checked: get_paginator('list_mfa_devices') is only
        # reached for console users.
        self.assertEqual(self._emitted_metric('IAMUsersWithoutMFA'), 1)

    def test_console_access_error_isolated_and_counted(self):
        # A non-NoSuchEntity error from get_login_profile (e.g. a missing
        # iam:GetLoginProfile grant or an account-wide throttle) must count as a
        # check error — not silently exclude the user, and not abort the sweep.
        # This is the path that would otherwise make EVERY user a false "no
        # console" exclusion, which the IAMMfaAuditCheckErrors alarm exists to
        # catch.
        self._wire(['alice'], {})
        self.iam.get_login_profile.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'not authorized'}},
            'GetLoginProfile',
        )
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['console_users_checked'], 0)
        self.assertEqual(result['users_without_mfa'], [])
        self.assertEqual(result['check_errors'], 1)
        self.assertEqual(self._emitted_metric('IAMMfaAuditCheckErrors'), 1)

    def test_overflow_truncation(self):
        names = [f'user{i:02d}' for i in range(mfa_audit.ALERT_SHOWN_MAX + 5)]
        self._wire(names, {})
        mfa_audit.handler({}, None)

        slack = json.loads(self._publish_to(os.environ['ALERTS_SNS_TOPIC_ARN']).kwargs['Message'])
        desc = slack['content']['description']
        self.assertIn('... and 5 more', desc)
        self.assertIn(f'{len(names)} console IAM user(s)', desc)

    def test_empty_user_list(self):
        self._wire([], {})
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_total'], 0)
        self.assertEqual(result['users_without_mfa'], [])
        self.sns.publish.assert_not_called()
        self.assertEqual(self._emitted_metric('IAMUsersWithoutMFA'), 0)

    def test_email_only_channel(self):
        # Slack topic unset (email-only deployment): exactly one publish, to
        # the email topic, with a plain-text body — exercises the EMAIL branch
        # independently of the Slack branch.
        self._set_topics(alerts='', email=os.environ['EMAIL_SNS_TOPIC_ARN'])
        self._wire(['erin'], {})
        mfa_audit.handler({}, None)

        self.assertEqual(self.sns.publish.call_count, 1)
        call = self._publish_to(os.environ['EMAIL_SNS_TOPIC_ARN'])
        body = call.kwargs['Message']
        self.assertIn('erin', body)
        self.assertIn('Enroll an MFA device', body)
        # Plain text, not Chatbot JSON.
        with self.assertRaises(json.JSONDecodeError):
            json.loads(body)

    def test_metric_throttle_does_not_suppress_alert(self):
        # A PutMetricData failure must not raise out of handler or stop the
        # SNS publish — the alert is the whole point.
        self._wire(['carol'], {})
        self.cw.put_metric_data.side_effect = RuntimeError('cw down')
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_without_mfa'], ['carol'])
        self.assertEqual(self.sns.publish.call_count, 2)

    def test_per_channel_publish_isolation(self):
        # A failure publishing to the Slack channel must not stop the email
        # publish (the per-channel try/except in _publish_alert) or crash the
        # handler. Slack is attempted first, so a Slack failure is the
        # meaningful direction: prove email is still attempted afterwards.
        self._wire(['frank'], {})

        def fail_slack(TopicArn, **_):
            if TopicArn == os.environ['ALERTS_SNS_TOPIC_ARN']:
                raise RuntimeError('slack down')
            return {}

        self.sns.publish.side_effect = fail_slack
        result = mfa_audit.handler({}, None)  # must not raise

        attempted = {c.kwargs['TopicArn'] for c in self.sns.publish.call_args_list}
        self.assertIn(os.environ['ALERTS_SNS_TOPIC_ARN'], attempted)
        self.assertIn(os.environ['EMAIL_SNS_TOPIC_ARN'], attempted)
        self.assertEqual(self.sns.publish.call_count, 2)
        # The failed Slack channel is counted (email succeeded), but the alert
        # was still delivered via email.
        self.assertEqual(result['publish_errors'], 1)
        self.assertEqual(self._emitted_metric('IAMMfaAuditPublishErrors'), 1)

    def test_all_channels_failed_is_alarmable(self):
        # If EVERY publish throws, the alert is dropped. The handler must NOT
        # crash (per-channel excepts catch it), but IAMMfaAuditPublishErrors must
        # be non-zero so the dropped page is alarmable rather than silent.
        self._wire(['grace'], {})
        self.sns.publish.side_effect = RuntimeError('SNS regional event')
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['users_without_mfa'], ['grace'])
        self.assertEqual(result['publish_errors'], 2)
        self.assertEqual(self._emitted_metric('IAMMfaAuditPublishErrors'), 2)

    def test_no_publish_errors_on_clean_run(self):
        # No finding => no publish attempted => publish-errors metric emits 0 so
        # its alarm self-clears.
        self._wire(['heidi'], {'heidi': [{'SerialNumber': 'x'}]})
        result = mfa_audit.handler({}, None)

        self.assertEqual(result['publish_errors'], 0)
        self.assertEqual(self._emitted_metric('IAMMfaAuditPublishErrors'), 0)

    def test_slack_message_is_valid_chatbot_json(self):
        self._wire(['dave'], {})
        mfa_audit.handler({}, None)
        slack_call = self._publish_to(os.environ['ALERTS_SNS_TOPIC_ARN'])
        body = json.loads(slack_call.kwargs['Message'])
        self.assertEqual(body['version'], '1.0')
        self.assertIn('dave', body['content']['description'])

    # ---- helpers ----

    def _set_topics(self, alerts, email):
        # mfa_audit reads the topic ARNs into module globals at import time, so
        # override the globals (and restore after the test) to exercise
        # single-channel deployments.
        for attr, value in (('ALERTS_SNS_TOPIC_ARN', alerts), ('EMAIL_SNS_TOPIC_ARN', email)):
            original = getattr(mfa_audit, attr)
            setattr(mfa_audit, attr, value)
            self.addCleanup(setattr, mfa_audit, attr, original)

    def _emitted_metric(self, name):
        for call in self.cw.put_metric_data.call_args_list:
            for datum in call.kwargs['MetricData']:
                if datum['MetricName'] == name:
                    return datum['Value']
        return None

    def _publish_to(self, topic_arn):
        for call in self.sns.publish.call_args_list:
            if call.kwargs['TopicArn'] == topic_arn:
                return call
        raise AssertionError(f'no publish to {topic_arn}')


if __name__ == '__main__':
    unittest.main()
