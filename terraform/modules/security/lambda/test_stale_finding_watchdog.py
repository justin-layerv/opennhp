"""
Tests for the GuardDuty stale-finding watchdog Lambda (#1137).

Run with: python3 -m unittest discover -s terraform/modules/security/lambda -p "test_*.py" -v
No external dependencies - stdlib unittest.mock drives boto3.
"""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

os.environ.update({
    'ENVIRONMENT': 'test',
    'ALERTS_SNS_TOPIC_ARN': 'arn:aws:sns:us-east-2:123456789012:test-alerts',
    'EMAIL_SNS_TOPIC_ARN': 'arn:aws:sns:us-east-2:123456789012:test-email',
    'SEVERITY_THRESHOLD': '4',
    'STALE_AGE_DAYS': '7',
    'AWS_REGION': 'us-east-2',
})


# sys.modules swap is load-bearing: the watchdog module calls
# boto3.client(...) at import time (ec2/sns/cw module globals). A
# per-test patch would be too late — by the time setUp runs, the
# real client has already attempted to hit AWS. Do not "clean up"
# into a per-test patch without also switching the watchdog to
# lazy client construction. The assert below turns a silent
# regression — where something pulls boto3 transitively before this
# file runs — into a loud test-time failure.
assert 'boto3' not in sys.modules, (
    'boto3 imported before test module loaded; the sys.modules swap '
    'below is no longer load-bearing and the watchdog will construct '
    'real AWS clients at import time.'
)
_IMPORT_TIME_BOTO = MagicMock()
_IMPORT_TIME_BOTO.client.return_value = MagicMock()
sys.modules['boto3'] = _IMPORT_TIME_BOTO

import stale_finding_watchdog as watchdog  # noqa: E402
from stale_finding_watchdog import LIST_FINDINGS_MAX_PAGES  # noqa: E402


def _finding(fid, severity=7, days_ago=10, region='us-east-2'):
    updated = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        'Id': fid,
        'Title': f'Test finding {fid}',
        'Severity': severity,
        'UpdatedAt': updated.isoformat().replace('+00:00', 'Z'),
        '_region': region,
    }


def _paginator_for(pages):
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


class WatchdogTestCase(unittest.TestCase):
    """setUp wires a fresh per-region GD client factory plus fresh ec2/
    sns/cw mocks, then resets the module's published-ARN globals to
    their post-import values. Any mutation inside a test dies at
    tearDown, so a raised exception in one test can't poison a later
    one — the test-state-leakage concern called out in cr round 2.
    """

    def setUp(self):
        self.ec2 = MagicMock(name='ec2')
        self.sns = MagicMock(name='sns')
        self.cw = MagicMock(name='cloudwatch')
        self.ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-2'}]}

        self._region_clients = {}
        watchdog.ec2 = self.ec2
        watchdog.sns = self.sns
        watchdog.cw = self.cw

        self._boto3_patch = patch.object(
            watchdog.boto3, 'client', side_effect=self._boto3_client_factory
        )
        self._boto3_patch.start()
        self.addCleanup(self._boto3_patch.stop)

        self._alerts_patch = patch.object(
            watchdog, 'ALERTS_SNS_TOPIC_ARN',
            'arn:aws:sns:us-east-2:123456789012:test-alerts',
        )
        self._alerts_patch.start()
        self.addCleanup(self._alerts_patch.stop)

        self._email_patch = patch.object(
            watchdog, 'EMAIL_SNS_TOPIC_ARN',
            'arn:aws:sns:us-east-2:123456789012:test-email',
        )
        self._email_patch.start()
        self.addCleanup(self._email_patch.stop)

    def _boto3_client_factory(self, service, region_name=None, **_kwargs):
        if service == 'guardduty':
            region = region_name or 'us-east-2'
            if region not in self._region_clients:
                gd = MagicMock(name=f'guardduty({region})')
                gd.list_detectors.return_value = {'DetectorIds': ['det-1']}
                gd.get_paginator.return_value = _paginator_for([{'FindingIds': []}])
                self._region_clients[region] = gd
            return self._region_clients[region]
        raise AssertionError(f'unexpected boto3.client call: {service}')

    def gd_for(self, region='us-east-2'):
        return self._boto3_client_factory('guardduty', region_name=region)


class TestHandler(WatchdogTestCase):
    def test_describe_regions_failure_falls_back_to_lambda_region(self):
        self.ec2.describe_regions.side_effect = RuntimeError('network down')
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 0)
        # Fallback region is intentionally NOT counted as an error —
        # the sweep degrades to single-region mode and continues.
        # Pinning region_errors == 0 here prevents a future refactor
        # from quietly reclassifying the fallback as a failure.
        self.assertEqual(result['region_errors'], 0)
        self.cw.put_metric_data.assert_called_once()
        # Fallback region comes from AWS_REGION env var (set to
        # us-east-2 in this test module's environ). The assertion
        # pins that the fallback path actually queried GuardDuty,
        # not that it picked a specific region.
        self.gd_for(os.environ['AWS_REGION']).list_detectors.assert_called_once()

    def test_no_detectors_in_region_is_silent(self):
        self.gd_for('us-east-2').list_detectors.return_value = {'DetectorIds': []}
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 0)
        self.sns.publish.assert_not_called()
        # Emit the metric even when no region has a detector so
        # dashboards see a zero rather than a gap that looks like the
        # watchdog silently skipped a run.
        self.cw.put_metric_data.assert_called_once()

    def test_no_findings_no_publish(self):
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 0)
        self.sns.publish.assert_not_called()
        call_args = self.cw.put_metric_data.call_args
        self.assertEqual(call_args.kwargs['MetricData'][0]['Value'], 0)

    def test_server_side_filter_skips_get_findings(self):
        watchdog.handler({}, None)
        self.gd_for('us-east-2').get_findings.assert_not_called()

    def test_find_criteria_is_load_bearing(self):
        # All three criteria are load-bearing for keeping the common
        # case cheap — drop any one and the Lambda fans out to
        # get_findings on every non-archived detection in the account.
        watchdog.handler({}, None)
        paginate_kwargs = self.gd_for('us-east-2').get_paginator.return_value.paginate.call_args.kwargs
        criterion = paginate_kwargs['FindingCriteria']['Criterion']
        self.assertEqual(criterion['service.archived'], {'Eq': ['false']})
        # Float-preserving: decimal thresholds like 4.5 must flow
        # through unchanged so the watchdog filter stays in lockstep
        # with the EventBridge rule's numeric comparator. See
        # stale_finding_watchdog.py `'severity': {'Gte': ...}`.
        self.assertEqual(criterion['severity'], {'Gte': 4.0})
        self.assertIn('updatedAt', criterion)
        self.assertIn('Lte', criterion['updatedAt'])
        self.assertIsInstance(criterion['updatedAt']['Lte'], int)
        self.assertEqual(paginate_kwargs['SortCriteria'], {'AttributeName': 'updatedAt', 'OrderBy': 'ASC'})

    def test_partial_detector_failure_preserves_first_detector_findings(self):
        # Multiple detectors per region is rare but legal. If
        # detector #2 fails AFTER detector #1's findings were
        # collected, the earlier findings must not be discarded —
        # silent data loss is the failure mode this PR closes.
        gd = self.gd_for('us-east-2')
        gd.list_detectors.return_value = {'DetectorIds': ['det-1', 'det-2']}

        call_count = [0]

        def paginator_per_detector(_name):
            call_count[0] += 1
            if call_count[0] == 1:
                return _paginator_for([{'FindingIds': ['f1']}])
            p = MagicMock()
            p.paginate.side_effect = RuntimeError('5xx on det-2')
            return p

        gd.get_paginator.side_effect = paginator_per_detector
        gd.get_findings.return_value = {'Findings': [_finding('f1')]}
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 1)
        self.assertEqual(result['region_errors'], 1)

    def test_single_region_failure_does_not_halt_sweep(self):
        # A 5xx in us-east-2 must not black-hole the sweep — the
        # watchdog still checks us-west-2 and emits metrics, so a
        # flaky region can't degrade to the "no one noticed" failure
        # mode the PR is closing.
        self.ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-2'}, {'RegionName': 'us-west-2'}],
        }
        self.gd_for('us-east-2').list_detectors.side_effect = RuntimeError('5xx')
        gd_west = self.gd_for('us-west-2')
        gd_west.get_paginator.return_value = _paginator_for([{'FindingIds': ['west-1']}])
        gd_west.get_findings.return_value = {'Findings': [_finding('west-1', region='us-west-2')]}

        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 1)
        self.assertEqual(result['region_errors'], 1)
        metric_names = [
            call.kwargs['MetricData'][0]['MetricName']
            for call in self.cw.put_metric_data.call_args_list
        ]
        self.assertIn('StaleGuardDutyFindings', metric_names)
        self.assertIn('StaleGuardDutyFindingsRegionErrors', metric_names)

    def test_multi_region_fan_out(self):
        self.ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-2'}, {'RegionName': 'us-west-2'}],
        }
        gd_east = self.gd_for('us-east-2')
        gd_east.get_paginator.return_value = _paginator_for([{'FindingIds': ['east-1']}])
        gd_east.get_findings.return_value = {'Findings': [_finding('east-1', region='us-east-2')]}
        gd_west = self.gd_for('us-west-2')
        gd_west.get_paginator.return_value = _paginator_for([{'FindingIds': ['west-1']}])
        gd_west.get_findings.return_value = {'Findings': [_finding('west-1', region='us-west-2')]}

        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 2)
        finding_ids = result['finding_ids']
        assert isinstance(finding_ids, list)
        self.assertEqual(set(finding_ids), {'east-1', 'west-1'})

    def test_page_cap_emits_truncation_metric(self):
        # Page cap firing is a rare alarmable event — emit a dedicated
        # metric so ops can alarm without parsing CloudWatch Logs.
        def many_empty_pages():
            for _ in range(LIST_FINDINGS_MAX_PAGES * 2):
                yield {'FindingIds': []}

        paginator = MagicMock()
        paginator.paginate.return_value = many_empty_pages()
        self.gd_for('us-east-2').get_paginator.return_value = paginator
        watchdog.handler({}, None)
        metric_names = {
            call.kwargs['MetricData'][0]['MetricName']
            for call in self.cw.put_metric_data.call_args_list
        }
        self.assertIn('StaleGuardDutyFindingsTruncated', metric_names)

    def test_exactly_cap_pages_does_not_emit_truncation(self):
        # Truncation must be a real "more pages existed" signal — a
        # paginator that yields exactly MAX_PAGES and then exhausts
        # must NOT trigger the metric, or a future >0 alarm on it
        # would false-positive on full-but-fitting result sets.
        def exactly_cap_pages():
            for _ in range(LIST_FINDINGS_MAX_PAGES):
                yield {'FindingIds': []}

        paginator = MagicMock()
        paginator.paginate.return_value = exactly_cap_pages()
        self.gd_for('us-east-2').get_paginator.return_value = paginator
        watchdog.handler({}, None)
        metric_names = {
            call.kwargs['MetricData'][0]['MetricName']
            for call in self.cw.put_metric_data.call_args_list
        }
        self.assertNotIn('StaleGuardDutyFindingsTruncated', metric_names)

    def test_describe_regions_empty_falls_back_to_lambda_region(self):
        # An empty Regions list from DescribeRegions would otherwise
        # iterate nothing and emit metric=0, re-introducing "no one
        # noticed." Treat it identically to the exception fallback.
        self.ec2.describe_regions.return_value = {'Regions': []}
        watchdog.handler({}, None)
        self.gd_for(os.environ['AWS_REGION']).list_detectors.assert_called_once()

    def test_page_cap_caps_list_findings(self):
        # Generator surfaces how many pages the Lambda actually
        # consumes. The loop peeks at one page beyond MAX_PAGES to
        # detect truncation, so the expected count is MAX_PAGES + 1
        # when more pages remain. If a future refactor drops the
        # peek, the count drops and this test fails loudly.
        consumed = [0]

        def counting_pages():
            for _ in range(LIST_FINDINGS_MAX_PAGES * 2):
                consumed[0] += 1
                yield {'FindingIds': []}

        paginator = MagicMock()
        paginator.paginate.return_value = counting_pages()
        self.gd_for('us-east-2').get_paginator.return_value = paginator
        watchdog.handler({}, None)
        self.assertEqual(consumed[0], LIST_FINDINGS_MAX_PAGES + 1)

    def test_stale_findings_publish_to_both_topics(self):
        self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
        self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 1)
        self.assertEqual(self.sns.publish.call_count, 2)
        topics = {call.kwargs['TopicArn'] for call in self.sns.publish.call_args_list}
        self.assertEqual(topics, {
            'arn:aws:sns:us-east-2:123456789012:test-alerts',
            'arn:aws:sns:us-east-2:123456789012:test-email',
        })

    def test_alerts_only_when_email_unconfigured(self):
        with patch.object(watchdog, 'EMAIL_SNS_TOPIC_ARN', ''):
            self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
            self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}
            watchdog.handler({}, None)
        self.assertEqual(self.sns.publish.call_count, 1)
        self.assertEqual(
            self.sns.publish.call_args.kwargs['TopicArn'],
            'arn:aws:sns:us-east-2:123456789012:test-alerts',
        )

    def test_cw_throttle_does_not_silence_alert(self):
        # CW throttle on PutMetricData must not suppress the
        # stale-finding publish — that would recreate the "no one
        # noticed" failure mode this watchdog closes. _safe_put_metric
        # swallows and logs; handler still calls _publish_alert.
        self.cw.put_metric_data.side_effect = RuntimeError('cw throttle')
        self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
        self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}
        result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 1)
        # Both channels still received the publish despite the CW
        # error — this is the invariant that protects the alert from
        # metric-emission failures.
        self.assertEqual(self.sns.publish.call_count, 2)

    def test_slack_publish_failure_does_not_block_email(self):
        # Per-channel isolation: a Slack publish failure (throttle,
        # transient IAM) must not suppress the email path or the
        # other subscribers lose that week's signal.
        self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
        self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}

        def publish_side_effect(TopicArn, **_):
            if TopicArn == watchdog.ALERTS_SNS_TOPIC_ARN:
                raise RuntimeError('slack throttle')

        self.sns.publish.side_effect = publish_side_effect
        watchdog.handler({}, None)
        # 2 attempts: Slack (raises) + email (succeeds because its
        # publish is wrapped in its own try).
        self.assertEqual(self.sns.publish.call_count, 2)
        topics = {call.kwargs['TopicArn'] for call in self.sns.publish.call_args_list}
        self.assertIn(watchdog.EMAIL_SNS_TOPIC_ARN, topics)

    def test_email_only_when_alerts_unconfigured(self):
        with patch.object(watchdog, 'ALERTS_SNS_TOPIC_ARN', ''):
            self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
            self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}
            watchdog.handler({}, None)
        self.assertEqual(self.sns.publish.call_count, 1)
        self.assertEqual(
            self.sns.publish.call_args.kwargs['TopicArn'],
            'arn:aws:sns:us-east-2:123456789012:test-email',
        )

    def test_no_channels_is_silent(self):
        # Terraform gates the Lambda on having at least one channel;
        # this is guardrail defense only. A future refactor that breaks
        # the gate should still emit the metric and return, not crash.
        with patch.object(watchdog, 'ALERTS_SNS_TOPIC_ARN', ''), \
             patch.object(watchdog, 'EMAIL_SNS_TOPIC_ARN', ''):
            self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ['f1']}])
            self.gd_for('us-east-2').get_findings.return_value = {'Findings': [_finding('f1')]}
            result = watchdog.handler({}, None)
        self.assertEqual(result['stale_count'], 1)
        self.sns.publish.assert_not_called()
        self.cw.put_metric_data.assert_called_once()

    def test_decimal_severity_threshold_flows_through(self):
        # Decimal thresholds like 4.5 must not truncate to int — that
        # would let severity-4 findings into watchdog alerts without
        # having tripped the EventBridge initial alert (>= 4.5).
        with patch.object(watchdog, 'SEVERITY_THRESHOLD', 4.5):
            watchdog.handler({}, None)
        paginate_kwargs = self.gd_for('us-east-2').get_paginator.return_value.paginate.call_args.kwargs
        self.assertEqual(paginate_kwargs['FindingCriteria']['Criterion']['severity'], {'Gte': 4.5})

    def test_get_findings_batches_above_50(self):
        ids = [f'f{i}' for i in range(75)]
        self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': ids}])
        self.gd_for('us-east-2').get_findings.side_effect = [
            {'Findings': [_finding(fid) for fid in ids[:50]]},
            {'Findings': [_finding(fid) for fid in ids[50:]]},
        ]
        watchdog.handler({}, None)
        self.assertEqual(self.gd_for('us-east-2').get_findings.call_count, 2)
        first_batch = self.gd_for('us-east-2').get_findings.call_args_list[0].kwargs['FindingIds']
        second_batch = self.gd_for('us-east-2').get_findings.call_args_list[1].kwargs['FindingIds']
        self.assertEqual(len(first_batch), 50)
        self.assertEqual(len(second_batch), 25)

    def test_metric_has_environment_dimension(self):
        watchdog.handler({}, None)
        metric = self.cw.put_metric_data.call_args.kwargs['MetricData'][0]
        self.assertEqual(metric['MetricName'], 'StaleGuardDutyFindings')
        dimensions = {d['Name']: d['Value'] for d in metric['Dimensions']}
        self.assertEqual(dimensions, {'Environment': 'test'})


class TestMessageFormat(WatchdogTestCase):
    def test_slack_message_has_chatbot_shape(self):
        msg = watchdog._slack_message([_finding('f1')], 0, 1)
        self.assertEqual(msg['version'], '1.0')
        self.assertEqual(msg['source'], 'custom')
        self.assertEqual(msg['content']['textType'], 'client-markdown')
        self.assertIn('Stale GuardDuty findings', msg['content']['title'])
        self.assertIn('test', msg['content']['title'])
        self.assertIn('f1', msg['content']['description'])
        self.assertIn('nextSteps', msg['content'])

    def test_slack_message_truncates_with_overflow(self):
        findings = [_finding(f'f{i}') for i in range(watchdog.ALERT_SHOWN_MAX)]
        msg = watchdog._slack_message(findings, 5, watchdog.ALERT_SHOWN_MAX + 5)
        self.assertIn('and 5 more', msg['content']['description'])

    def test_slack_title_pipe_escaped(self):
        stuffed = _finding('f1')
        stuffed['Title'] = 'bad|title'
        msg = watchdog._slack_message([stuffed], 0, 1)
        description = msg['content']['description']
        self.assertIn('bad-title', description)
        self.assertNotIn('bad|title', description)

    def test_slack_message_ascii_only(self):
        # Chatbot renders markdown but SNS.publish serialises via
        # json.dumps (default ensure_ascii=True), which escapes
        # non-ASCII codepoints. Feed a deliberately non-ASCII finding
        # title to prove the output still renders as ASCII-only
        # content (json.dumps will have escaped any high codepoints
        # before SNS publishes — the content stays legible).
        unicode_finding = _finding('f1')
        unicode_finding['Title'] = 'Suspicious activity from cafe\u00e9 \U0001f680'
        msg = watchdog._slack_message([unicode_finding], 3, 15)
        published = json.dumps(msg)
        self.assertEqual(published, published.encode('ascii', 'strict').decode('ascii'))

    def test_finding_url_is_detail_pane(self):
        url = watchdog._finding_url('abc123', 'us-west-2')
        self.assertIn('us-west-2.console.aws.amazon.com/guardduty', url)
        self.assertIn('macros=current', url)
        self.assertIn('fId=abc123', url)

    def test_email_message_plaintext(self):
        body = watchdog._email_message([_finding('f1', region='us-west-2')], 0, 1)
        self.assertIn('f1', body)
        self.assertIn('Test finding f1', body)
        self.assertIn('us-west-2', body)
        self.assertIn('archive', body.lower())
        self.assertNotIn('client-markdown', body)

    def test_format_timestamp_normalises_datetime_and_string(self):
        # boto3 hands Python `datetime` objects for GuardDuty
        # UpdatedAt; tests and raw JSON replay hand ISO strings.
        # Both must render identically in the alert body.
        dt = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(
            watchdog._format_timestamp(dt),
            watchdog._format_timestamp(dt.isoformat().replace('+00:00', 'Z')),
        )

    def test_null_severity_sorts_without_crashing(self):
        # `Severity: None` would make float(None) raise. _publish_alert
        # uses `or 0` instead of a default= so a partially-constructed
        # finding degrades to sort-as-severity-0 rather than crashing
        # the whole run.
        with_severity = _finding('high', severity=8)
        without = _finding('null')
        without['Severity'] = None
        msg = watchdog._slack_message([with_severity, without], 0, 2)
        self.assertIn('high', msg['content']['description'])
        self.assertIn('null', msg['content']['description'])

    def test_parse_timestamp_malformed_sorts_without_crashing(self):
        # _parse_timestamp returns _MIN_TIMESTAMP on bad input so the
        # sort keeps working even if GuardDuty ever emits a malformed
        # timestamp — the alert degrades rather than the whole run
        # crashing.
        good = _finding('good', severity=7, days_ago=10)
        bad = _finding('bad', severity=7, days_ago=10)
        bad['UpdatedAt'] = 'not-a-date'
        msg = watchdog._slack_message([good, bad], 0, 2)
        self.assertIn('good', msg['content']['description'])
        self.assertIn('bad', msg['content']['description'])

    def test_sort_worst_severity_first(self):
        findings = [
            _finding('low', severity=4),
            _finding('high', severity=8),
            _finding('mid', severity=6),
        ]
        self.gd_for('us-east-2').get_paginator.return_value = _paginator_for([{'FindingIds': [f['Id'] for f in findings]}])
        self.gd_for('us-east-2').get_findings.return_value = {'Findings': findings}
        watchdog.handler({}, None)
        slack_call = next(
            call for call in self.sns.publish.call_args_list
            if call.kwargs['TopicArn'] == watchdog.ALERTS_SNS_TOPIC_ARN
        )
        body = json.loads(slack_call.kwargs['Message'])['content']['description']
        self.assertLess(body.index('high'), body.index('mid'))
        self.assertLess(body.index('mid'), body.index('low'))


if __name__ == '__main__':
    unittest.main()
