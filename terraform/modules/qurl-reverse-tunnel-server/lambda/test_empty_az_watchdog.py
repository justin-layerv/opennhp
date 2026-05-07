"""
Tests for the qurl-reverse-tunnel-server per-AZ Cloud Map empty-registration watchdog (#1542).

Run with:
    python3 -m unittest discover -s terraform/modules/qurl-reverse-tunnel-server/lambda \
        -p "test_*.py" -v

No external dependencies - stdlib unittest.mock drives boto3.

Order constraint (CRITICAL — affects test correctness):

  This module's import-time block does three things in strict order:
    1. `os.environ.update({'AZ_SUFFIXES': ' a , , b ,c ', ...})`
    2. Runtime check `if 'boto3' in sys.modules: raise RuntimeError(...)`
       (must be `if/raise` — `python -O` strips `assert`)
    3. `sys.modules['boto3'] = MagicMock()` swap
    4. `import empty_az_watchdog as watchdog`

  All four steps MUST happen in this order at module-top, before any
  test class is defined. Reorganising — moving any of them into
  setUpModule, a test method, a fixture, or a separate helper module —
  silently breaks one of the load-bearing properties:
    - The malformed AZ_SUFFIXES value pins `_parse_suffixes` as
      load-bearing on import (clean 'a,b,c' would mask a regression
      that drops the helper).
    - The boto3 stub MUST be in place before the watchdog imports,
      or it constructs real AWS clients at module load.
    - The runtime check guards against a future
      conftest.py / pytest plugin that imports boto3 transitively
      before this module loads — that would silently bypass the swap.

  CI runs this file with `python -m pytest test_empty_az_watchdog.py`
  in its own subshell (see .github/workflows/build-and-push.yml), so
  no other Lambda module's transitive imports leak into the runner.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Test-only env vars. The watchdog module reads `NAMESPACE_NAME` and
# `AZ_SUFFIXES` at import time (module globals), so they must be set
# before the import below. Pinned to test-only strings so a leak into a
# combined test runner cannot accidentally point production code at a
# real ServiceDiscovery namespace; tearDownModule then restores prior
# values so this module's import-time `os.environ.update` does not
# bleed into another lambda's tests.
#
# `AZ_SUFFIXES` is deliberately set to a value with extra whitespace
# AND an empty entry — that exercises the `_parse_suffixes` strip+filter
# contract on import. With a clean `'a,b,c'` value an inline regression
# (e.g., `AZ_SUFFIXES = os.environ['AZ_SUFFIXES'].split(',')` without
# the strip+filter) would still produce `['a','b','c']` and the
# `test_module_parsed_suffixes_match_test_env` assertion would silently
# pass. The malformed value here pins the helper as load-bearing on
# import — a regression that drops the helper would produce
# `[' a ', '', 'b', '  c']` and fail the assertion.
_TEST_ENV_KEYS = ('NAMESPACE_NAME', 'AZ_SUFFIXES')
_PRIOR_ENV = {k: os.environ.get(k) for k in _TEST_ENV_KEYS}
os.environ.update({
    'NAMESPACE_NAME': 'nhp.test.internal',
    'AZ_SUFFIXES': ' a , , b ,c ',
})


def tearDownModule():  # noqa: N802 — unittest hook name
    for key, prior in _PRIOR_ENV.items():
        if prior is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = prior


# Same sys.modules swap pattern as security/test_stale_finding_watchdog.py:
# the watchdog module calls boto3.client() at import time (sd, cw module
# globals), so a per-test patch would be too late. The runtime check
# below turns a silent regression (transitive boto3 import before this
# test module) into a loud failure. NOTE: this is a runtime `if/raise`
# rather than `assert` — `python -O` strips assertions, which would
# turn the safety check into a no-op and the watchdog would construct
# real AWS clients at import time without anyone noticing.
if 'boto3' in sys.modules:
    raise RuntimeError(
        'boto3 imported before test module loaded; the sys.modules swap '
        'below is no longer load-bearing and the watchdog will construct '
        'real AWS clients at import time.'
    )

_IMPORT_TIME_BOTO = MagicMock()
_IMPORT_TIME_BOTO.client.return_value = MagicMock()
sys.modules['boto3'] = _IMPORT_TIME_BOTO

# botocore.exceptions is stubbed because THIS test file imports
# `ClientError` to construct fake throttles for the watchdog under test.
# The watchdog itself catches `Exception` broadly (no boto-specific
# imports), so the stub is purely for the tests' convenience.
_botocore_exceptions = MagicMock()
_botocore_exceptions.ClientError = type('ClientError', (Exception,), {})
_botocore_exceptions.BotoCoreError = type('BotoCoreError', (Exception,), {})
sys.modules.setdefault('botocore', MagicMock())
sys.modules['botocore.exceptions'] = _botocore_exceptions

import empty_az_watchdog as watchdog  # noqa: E402

# `botocore.exceptions` is stubbed via `sys.modules` above so `ClientError`
# is available at module top — saves repeating the import inside every
# test method that needs to construct a fake throttle.
from botocore.exceptions import ClientError  # noqa: E402


class HandlerTests(unittest.TestCase):
    def setUp(self):
        # Patch module-global clients per test (the import-time clients are
        # MagicMocks via the boto3 stub above; replace them here so each test
        # asserts against fresh call counts).
        self.sd_patch = patch.object(watchdog, 'sd', MagicMock())
        self.cw_patch = patch.object(watchdog, 'cw', MagicMock())
        self.sd = self.sd_patch.start()
        self.cw = self.cw_patch.start()
        self.addCleanup(self.sd_patch.stop)
        self.addCleanup(self.cw_patch.stop)

    def _set_counts(self, counts_by_suffix):
        """Configure sd.discover_instances to return len(...) instances per service.

        Uses **kwargs (rather than named params) so a future refactor that
        adds a new boto3 kwarg to the discover_instances call doesn't
        break every test using this helper with `unexpected keyword
        argument`. The actual contract assertions live in
        `test_discover_passes_health_status_all` etc., not here.
        """

        def _side_effect(**kwargs):
            # ServiceName format is 'frps-${suffix}'
            suffix = kwargs['ServiceName'].split('-', 1)[1]
            n = counts_by_suffix.get(suffix, 0)
            return {'Instances': [{'Id': f'i-{suffix}-{i}'} for i in range(n)]}

        self.sd.discover_instances.side_effect = _side_effect

    def test_emits_one_metric_per_suffix(self):
        # Healthy distribution: each AZ has 1 registration.
        self._set_counts({'a': 1, 'b': 1, 'c': 1})

        result = watchdog.handler({}, MagicMock(aws_request_id='test-1'))

        self.assertEqual(result['counts'], {'a': 1, 'b': 1, 'c': 1})
        self.assertEqual(result['discover_errors'], 0)
        self.assertEqual(result['put_errors'], 0)
        self.assertEqual(self.cw.put_metric_data.call_count, 3)
        # Verify dimension shape on the first emit.
        first_call = self.cw.put_metric_data.call_args_list[0].kwargs
        self.assertEqual(first_call['Namespace'], 'QurlFRPS')
        metric = first_call['MetricData'][0]
        self.assertEqual(metric['MetricName'], 'PerAZRegistrationCount')
        self.assertEqual(metric['Dimensions'], [{'Name': 'AZSuffix', 'Value': 'a'}])
        # `Value` is the raw int from `len()`, not a float — no cast.
        self.assertEqual(metric['Value'], 1)
        # Pin the full per-call AZSuffix sequence so a regression that
        # accidentally publishes the wrong dimension (e.g., always 'a',
        # or skips 'c') would fail loudly. Without this assertion, a
        # bug like `_emit_metric(suffix=AZ_SUFFIXES[0], count=count)`
        # for every iteration would still produce 3 PutMetricData calls
        # and pass the count-only check.
        emitted_suffixes = [
            call.kwargs['MetricData'][0]['Dimensions'][0]['Value']
            for call in self.cw.put_metric_data.call_args_list
        ]
        self.assertEqual(emitted_suffixes, ['a', 'b', 'c'])

    def test_discover_passes_health_status_all(self):
        # `HealthStatus='ALL'` is load-bearing: under MULTIVALUE
        # routing with custom checks, UNHEALTHY-flagged registrations
        # still resolve via DNS, so excluding them would mis-count
        # "empty AZ" cases. The docstring on `_count_instances` calls
        # this out — pin it via the test so a refactor that switches
        # to 'HEALTHY' fails this test rather than silently regressing
        # the alarm semantic.
        self._set_counts({'a': 1, 'b': 1, 'c': 1})

        watchdog.handler({}, MagicMock(aws_request_id='health-status'))

        for call in self.sd.discover_instances.call_args_list:
            self.assertEqual(call.kwargs['HealthStatus'], 'ALL')

    def test_empty_az_emits_zero(self):
        # The (2, 1, 0) failure mode the watchdog is built to detect.
        self._set_counts({'a': 2, 'b': 1, 'c': 0})

        result = watchdog.handler({}, MagicMock(aws_request_id='test-2'))

        self.assertEqual(result['counts'], {'a': 2, 'b': 1, 'c': 0})
        # Confirm the empty AZ produced a PutMetricData(Value=0) — the
        # alarm depends on this. A bug that skipped emission for empty
        # services would silently green the alarm.
        c_call = next(
            call for call in self.cw.put_metric_data.call_args_list
            if call.kwargs['MetricData'][0]['Dimensions'][0]['Value'] == 'c'
        )
        c_metric = c_call.kwargs['MetricData'][0]
        self.assertEqual(c_metric['Value'], 0)
        # Pin `Unit: Count` — a regression to `Unit: 'None'` (or any
        # other unit) would make the metric a different timeseries
        # from CloudWatch's perspective, and the alarm pinned on
        # `MetricName=PerAZRegistrationCount` without a Unit filter
        # would still match — but a future dashboard query that did
        # filter on Unit would silently miss the new series.
        self.assertEqual(c_metric['Unit'], 'Count')

    def test_discover_partial_failure_does_not_abort_sweep(self):
        # First call (suffix 'a') raises; remaining must still publish.
        # Without the per-suffix try/except the sweep would abort and
        # b/c would never get a PutMetricData this cycle, allowing a
        # transient ServiceDiscovery blip to silence real signal.
        # 1-of-3 fail does NOT escalate to WatchdogTotalFailure — that
        # path is only for an all-fail region-wide outage.
        call_count = {'n': 0}

        def _side_effect(**kwargs):
            call_count['n'] += 1
            if kwargs['ServiceName'] == 'frps-a':
                raise ClientError({'Error': {'Code': 'Throttling'}}, 'DiscoverInstances')
            suffix = kwargs['ServiceName'].split('-', 1)[1]
            return {'Instances': [{'Id': f'i-{suffix}-0'}]}

        self.sd.discover_instances.side_effect = _side_effect

        result = watchdog.handler({}, MagicMock(aws_request_id='test-3'))

        self.assertEqual(result['discover_errors'], 1)
        self.assertEqual(result['put_errors'], 0)
        self.assertNotIn('a', result['counts'])
        self.assertEqual(result['counts'].get('b'), 1)
        self.assertEqual(result['counts'].get('c'), 1)
        # Two emits (b, c), not three.
        self.assertEqual(self.cw.put_metric_data.call_count, 2)

    def test_putmetricdata_partial_failure_does_not_abort_sweep(self):
        # PutMetricData throttle on the first AZ must not silence the rest.
        # 1-of-3 fail: log + count under put_errors, do NOT escalate.
        self._set_counts({'a': 0, 'b': 1, 'c': 1})

        call_count = {'n': 0}

        def _put_side_effect(**kwargs):
            call_count['n'] += 1
            if call_count['n'] == 1:
                raise ClientError({'Error': {'Code': 'Throttling'}}, 'PutMetricData')

        self.cw.put_metric_data.side_effect = _put_side_effect

        result = watchdog.handler({}, MagicMock(aws_request_id='test-4'))

        # All three suffixes still got a discover hit; first emit raised.
        self.assertEqual(result['counts'], {'a': 0, 'b': 1, 'c': 1})
        self.assertEqual(self.cw.put_metric_data.call_count, 3)
        # PutMetricData failures live under their own counter and
        # MUST NOT increment `discover_errors` — the two counters are
        # the contract dashboards / future alarms read against, and
        # confusing them would let a CloudWatch outage silently
        # masquerade as a ServiceDiscovery outage.
        self.assertEqual(result['discover_errors'], 0)
        self.assertEqual(result['put_errors'], 1)
        # Pin per-call suffix sequence — a regression that retried
        # the failed publish in-place rather than continuing to the
        # next suffix would still hit call_count == 3 but lose the
        # 'b'/'c' invocations.
        emitted_suffixes = [
            call.kwargs['MetricData'][0]['Dimensions'][0]['Value']
            for call in self.cw.put_metric_data.call_args_list
        ]
        self.assertEqual(emitted_suffixes, ['a', 'b', 'c'])

    def test_all_discover_failures_escalate(self):
        # Full ServiceDiscovery outage: every per-AZ DiscoverInstances
        # raises. Two invariants:
        #   1. Handler MUST raise WatchdogTotalFailure so AWS/Lambda
        #      Errors > 0 and the self-failure alarm fires. Without
        #      this, every per-AZ alarm transitions to INSUFFICIENT_DATA
        #      via treat_missing_data="missing" — silent.
        #   2. PutMetricData MUST NOT have been called. A regression
        #      that publishes Value=0 on discover failure would silently
        #      green every per-suffix alarm on the cycle that follows.
        self.sd.discover_instances.side_effect = ClientError(
            {'Error': {'Code': 'Throttling'}}, 'DiscoverInstances',
        )

        with self.assertRaises(watchdog.WatchdogTotalFailure):
            watchdog.handler({}, MagicMock(aws_request_id='all-discover-fail'))

        self.cw.put_metric_data.assert_not_called()

    def test_mixed_failures_covering_all_azs_escalate(self):
        # Mixed-cause total failure: 2-of-3 DiscoverInstances fail and
        # the surviving suffix's PutMetricData also throttles. Every AZ
        # ended this cycle without a successful publish — by the
        # "no AZ got fresh data" criterion, the unified guard
        # `discover_errors + put_errors == n` MUST escalate. Without
        # this test the partial-vs-total split is ambiguous between
        # the pure cases (test_all_discover_failures_escalate covers
        # discover_errors==n=put_attempts==0; test_all_putmetricdata_
        # failures_escalate covers put_errors==put_attempts==n;
        # neither pins the mixed case).
        def _disc_side_effect(**kwargs):
            if kwargs['ServiceName'] in ('frps-a', 'frps-b'):
                raise ClientError(
                    {'Error': {'Code': 'Throttling'}}, 'DiscoverInstances',
                )
            return {'Instances': [{'Id': 'i-c-0'}]}

        self.sd.discover_instances.side_effect = _disc_side_effect
        self.cw.put_metric_data.side_effect = ClientError(
            {'Error': {'Code': 'Throttling'}}, 'PutMetricData',
        )

        with self.assertRaises(watchdog.WatchdogTotalFailure):
            watchdog.handler({}, MagicMock(aws_request_id='mixed-fail'))

        # Surviving discover (suffix 'c') was the only put attempted,
        # and it failed — so put was called exactly once.
        self.assertEqual(self.cw.put_metric_data.call_count, 1)

    def test_partial_discover_with_one_put_failure_does_not_escalate(self):
        # Inverse of the mixed-fail case: 2-of-3 discover succeed, and
        # 1 of those publishes throttles. discover_errors=1,
        # put_errors=1, total=2 < n=3 → must NOT escalate. This is the
        # specific edge case cr round 9 flagged: under the old guard
        # `put_attempts > 0 and put_errors == put_attempts` this would
        # escalate when put_attempts happened to equal 1 with a 1-of-1
        # put failure, which was a false-positive escalation. The
        # unified `total_errors == n` guard correctly sees 2 != 3 and
        # holds the line.
        def _disc_side_effect(**kwargs):
            if kwargs['ServiceName'] == 'frps-a':
                raise ClientError(
                    {'Error': {'Code': 'Throttling'}}, 'DiscoverInstances',
                )
            suffix = kwargs['ServiceName'].split('-', 1)[1]
            return {'Instances': [{'Id': f'i-{suffix}-0'}]}

        self.sd.discover_instances.side_effect = _disc_side_effect

        # Throttle only the FIRST put (which will be for suffix 'b').
        put_calls = {'n': 0}

        def _put_side_effect(**kwargs):
            put_calls['n'] += 1
            if put_calls['n'] == 1:
                raise ClientError(
                    {'Error': {'Code': 'Throttling'}}, 'PutMetricData',
                )

        self.cw.put_metric_data.side_effect = _put_side_effect

        # MUST NOT raise — at least one AZ ('c') got fresh data.
        result = watchdog.handler({}, MagicMock(aws_request_id='no-escalate'))

        self.assertEqual(result['discover_errors'], 1)
        self.assertEqual(result['put_errors'], 1)
        # Sweep continued: 2 put attempts (one per surviving discover).
        self.assertEqual(self.cw.put_metric_data.call_count, 2)

    def test_non_boto_exception_in_discover_does_not_abort_sweep(self):
        # The per-suffix isolation contract MUST hold for any exception,
        # not just (ClientError, BotoCoreError). A future boto3 response-
        # shape change or any unexpected error type (RuntimeError, KeyError,
        # JSONDecodeError) on the FIRST suffix would otherwise propagate
        # to the handler's outer scope and kill the remaining suffixes —
        # the exact failure mode the per-suffix try/except is designed
        # to prevent. Pin the broad-catch contract so a refactor that
        # narrows the except clause back to (ClientError, BotoCoreError)
        # fails this test.
        def _disc_side_effect(**kwargs):
            if kwargs['ServiceName'] == 'frps-a':
                raise RuntimeError('unexpected response shape from boto3')
            suffix = kwargs['ServiceName'].split('-', 1)[1]
            return {'Instances': [{'Id': f'i-{suffix}-0'}]}

        self.sd.discover_instances.side_effect = _disc_side_effect

        result = watchdog.handler({}, MagicMock(aws_request_id='non-boto'))

        # 'a' raised; b/c proceeded.
        self.assertEqual(result['discover_errors'], 1)
        self.assertEqual(result['put_errors'], 0)
        self.assertNotIn('a', result['counts'])
        self.assertEqual(result['counts'].get('b'), 1)
        self.assertEqual(result['counts'].get('c'), 1)

    def test_empty_suffixes_does_not_escalate(self):
        # Defensive: if `_parse_suffixes` returned `[]` from a stale
        # env var (`AZ_SUFFIXES=",,,"`) the handler must NOT raise
        # `WatchdogTotalFailure`. Both escalation guards check
        # `n > 0` / `put_attempts > 0`; a regression that flipped
        # either to `>= 0` would fire the self-failure alarm on every
        # cycle in a misconfigured env. Patch the module global to
        # exercise the guard rather than re-importing under a tweaked
        # env (the sys.modules-swap pattern makes re-import
        # expensive).
        with patch.object(watchdog, 'AZ_SUFFIXES', []):
            result = watchdog.handler({}, MagicMock(aws_request_id='empty-suffixes'))

        # Sweep loop never iterated.
        self.sd.discover_instances.assert_not_called()
        self.cw.put_metric_data.assert_not_called()
        # Counters are zero; no escalation.
        self.assertEqual(result['discover_errors'], 0)
        self.assertEqual(result['put_errors'], 0)
        self.assertEqual(result['counts'], {})

    def test_all_putmetricdata_failures_escalate(self):
        # Region-wide CloudWatch outage: every PutMetricData raises.
        # Symmetric to the all-discover-fails case — the handler MUST
        # raise so the self-failure alarm pages, otherwise an all-fail
        # would log per-call but return cleanly and the per-AZ alarms
        # would drift to INSUFFICIENT_DATA without paging.
        self._set_counts({'a': 1, 'b': 1, 'c': 1})
        self.cw.put_metric_data.side_effect = ClientError(
            {'Error': {'Code': 'Throttling'}}, 'PutMetricData',
        )

        with self.assertRaises(watchdog.WatchdogTotalFailure):
            watchdog.handler({}, MagicMock(aws_request_id='all-put-fail'))

        # All 3 attempts ran (per-suffix isolation kept the loop alive)
        # before the handler escalated.
        self.assertEqual(self.cw.put_metric_data.call_count, 3)

    def test_discover_returns_api_ceiling_logs_warning(self):
        # `_count_instances` calls DiscoverInstances with the API
        # ceiling (MaxResults=1000); hitting that in a real
        # deployment is unprecedented and indicates a stale-
        # registration leak. The warning surfaces it via logs
        # (alarm follow-up tracked in #1566). Pin the warning so a
        # regression dropping the check fails this test.
        self.sd.discover_instances.side_effect = lambda **kwargs: {
            'Instances': [{'Id': f'i-{i}'} for i in range(1000)]
        }

        with self.assertLogs(watchdog.logger, level='WARNING') as cm:
            result = watchdog.handler({}, MagicMock(aws_request_id='ceiling'))

        self.assertEqual(result['counts'], {'a': 1000, 'b': 1000, 'c': 1000})
        # One warning per service hitting the API ceiling.
        cap_warnings = [m for m in cm.output if 'ceiling of 1000 reached' in m]
        self.assertEqual(len(cap_warnings), 3)


class EmitMetricTests(unittest.TestCase):
    """Direct tests for `_emit_metric` independent of `handler`.

    `handler`'s tests already cover the happy/failure paths via the full
    sweep loop, but those go through the put_errors counter and the
    escalation guard. The bool return contract from `_emit_metric` is
    private but load-bearing on `handler.put_errors` accounting — pin
    it directly so a refactor that changes the return shape breaks
    here rather than silently breaking handler accounting.
    """

    def setUp(self):
        self.cw_patch = patch.object(watchdog, 'cw', MagicMock())
        self.cw = self.cw_patch.start()
        self.addCleanup(self.cw_patch.stop)

    def test_returns_true_on_success(self):
        result = watchdog._emit_metric('a', 1)
        self.assertTrue(result)
        self.cw.put_metric_data.assert_called_once()

    def test_returns_false_on_aws_error(self):
        self.cw.put_metric_data.side_effect = ClientError(
            {'Error': {'Code': 'Throttling'}}, 'PutMetricData',
        )
        result = watchdog._emit_metric('a', 1)
        self.assertFalse(result)

    def test_returns_false_on_arbitrary_exception(self):
        # Mirrors the broad-except in the implementation: any
        # exception type, not just boto3 ones, must return False so
        # the caller's put_errors counter increments correctly.
        self.cw.put_metric_data.side_effect = RuntimeError('unexpected')
        result = watchdog._emit_metric('a', 1)
        self.assertFalse(result)


class EnvParseTests(unittest.TestCase):
    """Pin the AZ_SUFFIXES env-var parsing contract.

    The Lambda's `_parse_suffixes` is purely defensive — Terraform's
    `frps_az_suffixes` validation block (root + module) rejects
    malformed input at plan time. But until PR #1539's root validation
    is on every consumer, this filter is the only guard against a
    stale runtime config like `AZ_SUFFIXES=",,a, ,b,"`. The function
    is extracted on the watchdog module so this test calls it directly
    rather than re-implementing the parse expression — a refactor that
    drops the strip+filter would fail this test rather than masquerading
    as a tautology against a duplicated implementation.
    """

    def test_strip_drops_whitespace_and_empties(self):
        self.assertEqual(watchdog._parse_suffixes('a,,b, ,c'), ['a', 'b', 'c'])
        self.assertEqual(watchdog._parse_suffixes(' a , b , c '), ['a', 'b', 'c'])
        self.assertEqual(watchdog._parse_suffixes(',,,'), [])
        self.assertEqual(watchdog._parse_suffixes('a'), ['a'])
        # Literal empty string: `''.split(',')` returns `['']`, then
        # the strip+filter drops the empty entry, yielding `[]`. Same
        # path as `',,,'` but worth pinning explicitly so a future
        # refactor can't silently degrade the empty case.
        self.assertEqual(watchdog._parse_suffixes(''), [])

    def test_module_parsed_suffixes_match_test_env(self):
        # Confirm the module-load parse used the same function the
        # tests above pin — i.e., the extracted helper is actually
        # what's running on the Lambda, not a separate inline
        # expression that drifted from the helper.
        self.assertEqual(watchdog.AZ_SUFFIXES, ['a', 'b', 'c'])


if __name__ == '__main__':
    unittest.main()
