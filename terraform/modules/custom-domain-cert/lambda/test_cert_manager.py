"""Tests for custom_domain_cert_manager Lambda.

Covers verify_dns_ownership(), renewal_scan(), provision_pending_domains(),
list_cert_meta_params(), store_certificate(), trigger_cert_sync() command
injection hardening, and _acquire/_release_provisioning_lock idempotency lock.

Uses unittest.mock to patch boto3 clients — no moto dependency needed.
"""

# Lambda code is imported lazily because `custom_domain_cert_manager` creates
# boto3 clients at import time, and AWS_DEFAULT_REGION must be set before that
# happens. Pyright cannot resolve the import without the runtime side effect.
# Tests that stack @patch decorators to suppress side effects (real boto3
# calls) but don't assert on the resulting mocks use `del` to mark the
# parameter as intentionally unused (Python idiom).
# pyright: reportMissingImports=false
import json
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import call, patch, MagicMock

import pytest
from botocore.exceptions import ClientError


# Set required env vars before import. AWS_DEFAULT_REGION is required because
# custom_domain_cert_manager creates boto3 clients at module load time, and
# botocore raises NoRegionError when no region is configured anywhere on the
# host (e.g. clean CI runners with no ~/.aws/config and no AWS_REGION env).
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-2')
os.environ.setdefault('ACME_ZONE_ID', 'Z0000000000000')
os.environ.setdefault('ACME_ZONE_NAME', 'acme.example.com')
os.environ.setdefault('SSM_CERT_PREFIX', '/nhp/certs')
os.environ.setdefault('QURL_DOMAINS_TABLE', 'test-qurl-domains')
os.environ.setdefault('ENVIRONMENT', 'test')
os.environ.setdefault('CELL_ID', 'cell0')

import custom_domain_cert_manager as cm


def _self_signed_cert_pair(common_name='example.com'):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return key_pem, cert_pem


def test_required_env_fails_loud(monkeypatch):
    monkeypatch.delenv('ENVIRONMENT', raising=False)

    with pytest.raises(RuntimeError, match='Missing required environment variable ENVIRONMENT'):
        cm._required_env('ENVIRONMENT')


def _metric_values(mock_put_metric_data):
    values = {}
    for call in mock_put_metric_data.call_args_list:
        for metric in call.kwargs['MetricData']:
            values[metric['MetricName']] = metric['Value']
    return values


def _metric_dimensions(mock_put_metric_data):
    dimensions = {}
    for call in mock_put_metric_data.call_args_list:
        for metric in call.kwargs['MetricData']:
            dimensions[metric['MetricName']] = {
                dim['Name']: dim['Value'] for dim in metric.get('Dimensions', [])
            }
    return dimensions


def _assert_renewal_metric_dimensions(mock_put_metric_data):
    expected = {'Environment': 'test', 'CellID': 'cell0'}
    dimensions = _metric_dimensions(mock_put_metric_data)
    for metric_name in (
        cm.CW_METRIC_RENEWAL_SCAN_RUNS,
        cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES,
        cm.CW_METRIC_RENEWAL_ORPHANED_CERTS,
        cm.CW_METRIC_RENEWAL_PROCESSING_FAILURES,
        cm.CW_METRIC_RENEWAL_STATUS_RECOVERED,
    ):
        assert dimensions[metric_name] == expected


def _hcl_block(text, marker):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 0
    index = brace
    in_string = False
    escape = False
    in_line_comment = False
    in_block_comment = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ''

        if in_line_comment:
            if char == '\n':
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            if char == '*' and next_char == '/':
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
        elif char == '#':
            in_line_comment = True
        elif char == '/' and next_char == '/':
            in_line_comment = True
            index += 1
        elif char == '/' and next_char == '*':
            in_block_comment = True
            index += 1
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
        index += 1
    raise AssertionError(f"unterminated HCL block for {marker}")


def test_hcl_block_ignores_braces_inside_strings_and_comments():
    text = '''
resource "aws_cloudwatch_metric_alarm" "example" {
  alarm_description = "literal { brace"
  # comment with } brace
  dimensions = {
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "next" {
  metric_name = "Other"
}
'''

    block = _hcl_block(text, 'resource "aws_cloudwatch_metric_alarm" "example"')

    assert 'literal { brace' in block
    assert 'comment with } brace' in block
    assert 'dimensions = {' in block
    assert 'metric_name = "Other"' not in block


def test_renewal_metric_contract_matches_terraform_alarms():
    """Guard the Python metric publisher and Terraform alarms from drifting."""
    module_main = Path(__file__).resolve().parents[1] / 'main.tf'
    terraform = module_main.read_text()
    renewal_metrics = _hcl_block(terraform, 'renewal_scan_metrics = {')
    count_alarm = _hcl_block(
        terraform,
        'resource "aws_cloudwatch_metric_alarm" "cert_renewal_scan_counts"',
    )
    heartbeat_alarm = _hcl_block(
        terraform,
        'resource "aws_cloudwatch_metric_alarm" "cert_renewal_scan_heartbeat"',
    )

    expected_count_alarm_contract = {
        cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES: {
            'period': 900,
            'evaluation_periods': 1,
            'datapoints_to_alarm': 1,
        },
        cm.CW_METRIC_RENEWAL_ORPHANED_CERTS: {
            'period': 900,
            'evaluation_periods': 2,
            'datapoints_to_alarm': 2,
        },
        cm.CW_METRIC_RENEWAL_PROCESSING_FAILURES: {
            'period': 900,
            'evaluation_periods': 2,
            'datapoints_to_alarm': 2,
        },
        cm.CW_METRIC_RENEWAL_STATUS_RECOVERED: {
            'period': 900,
            'evaluation_periods': 1,
            'datapoints_to_alarm': 1,
        },
    }
    for metric_name, contract in expected_count_alarm_contract.items():
        assert f'"{metric_name}" = {{' in renewal_metrics
        metric_block = _hcl_block(renewal_metrics, f'"{metric_name}" = {{')
        for attr, expected in contract.items():
            assert re.search(rf'\b{attr}\s*=\s*{expected}\b', metric_block)

    assert re.search(r'metric_name\s*=\s*each\.key\b', count_alarm)
    assert re.search(
        rf'metric_name\s*=\s*"{re.escape(cm.CW_METRIC_RENEWAL_SCAN_RUNS)}"',
        heartbeat_alarm,
    )
    for alarm_block in (count_alarm, heartbeat_alarm):
        assert re.search(rf'namespace\s*=\s*"{re.escape(cm.CW_NAMESPACE)}"', alarm_block)
        dimensions = _hcl_block(alarm_block, 'dimensions = {')
        assert re.search(r'\bEnvironment\s*=\s*var\.environment\b', dimensions)
        assert re.search(r'\bCellID\s*=\s*var\.cell_id\b', dimensions)

    assert re.search(r'\bevaluation_periods\s*=\s*3\b', heartbeat_alarm)
    assert re.search(r'\bdatapoints_to_alarm\s*=\s*3\b', heartbeat_alarm)
    assert re.search(r'\bperiod\s*=\s*900\b', heartbeat_alarm)


@pytest.fixture(autouse=True)
def _no_unmocked_cloudwatch_metrics(monkeypatch):
    mock_put_metric_data = MagicMock(name='unmocked_put_metric_data')
    monkeypatch.setattr(cm.cloudwatch_client, 'put_metric_data', mock_put_metric_data)
    yield
    # This only fences CloudWatch metrics. Other AWS clients still rely on
    # per-test mocks plus the workflow's dummy credentials backstop. Check
    # after the test body so metric helpers that swallow ordinary exceptions
    # still surface any unmocked CloudWatch write.
    assert mock_put_metric_data.call_count == 0, (
        'unit tests must patch CloudWatch metric writes explicitly; '
        f'unmocked calls: {mock_put_metric_data.call_args_list}'
    )


# Pinned payload schema for qurl-service's DomainCleanupEvent. This struct
# definition is the cross-repo contract and is owned by qurl-service at
# internal/events/domain_event_publisher.go. The Python keys MUST match the
# Go struct's `json:"..."` tags exactly. If qurl-service updates its struct,
# update this fixture in the same PR and re-run these tests — a key rename
# in either repo without the other surfaces here as a KeyError or as the
# handler silently ignoring the field.
_CONTRACT_FIXTURE = {
    'event_type': 'domain.cleanup',
    'domain_name': 'gone.example.com',
    'owner_id': 'auth0|abc',
    'acme_cname_target': 'gone--example--com.acme.example.com',
    'cert_param_prefix': '/nhp/certs/gone.example.com',
    'timestamp': '2026-05-18T06:00:00+00:00',
}


class TestIsValidDomain(unittest.TestCase):
    """Tests for is_valid_domain() helper."""

    def test_valid_domains(self):
        assert cm.is_valid_domain('example.com')
        assert cm.is_valid_domain('sub.example.com')
        assert cm.is_valid_domain('a.b.c.d.example.com')
        assert cm.is_valid_domain('example-site.com')

    def test_rejects_path_traversal(self):
        assert not cm.is_valid_domain('../../etc/passwd')
        assert not cm.is_valid_domain('foo..bar.com')

    def test_rejects_injection(self):
        assert not cm.is_valid_domain('foo; rm -rf /')
        assert not cm.is_valid_domain('$(whoami).com')
        assert not cm.is_valid_domain('')

    def test_rejects_wildcards(self):
        assert not cm.is_valid_domain('*.example.com')


class TestIsSyntheticDomain(unittest.TestCase):
    """Tests for is_synthetic_domain() — RFC-reserved test/example names only."""

    def test_reserved_tlds_are_synthetic(self):
        assert cm.is_synthetic_domain('smoke-cleanup-abc.example.invalid')
        assert cm.is_synthetic_domain('foo.test')
        assert cm.is_synthetic_domain('bar.localhost')
        assert cm.is_synthetic_domain('baz.example')
        assert cm.is_synthetic_domain('SMOKE.EXAMPLE.INVALID')  # case-insensitive
        assert cm.is_synthetic_domain('trailing.invalid.')      # trailing dot

    def test_reserved_doc_domains_are_synthetic(self):
        assert cm.is_synthetic_domain('example.com')
        assert cm.is_synthetic_domain('sub.example.org')
        assert cm.is_synthetic_domain('a.b.example.net')

    def test_real_customer_domains_are_NOT_synthetic(self):
        # Each MUST be False — a true here would silently blind the real
        # customer-cert-failure alarm, which is strictly worse than a cosmetic
        # monitor failure. Includes the company zone (NOT suppressed by design)
        # and near-miss strings that must not match the reserved patterns.
        assert not cm.is_synthetic_domain('secure.acme.com')
        assert not cm.is_synthetic_domain('links.bigcorp.io')
        assert not cm.is_synthetic_domain('cd-smoke-tok-123.layerv.xyz')
        assert not cm.is_synthetic_domain('notexample.com')
        assert not cm.is_synthetic_domain('example.com.evil.net')
        assert not cm.is_synthetic_domain('myinvalid.com')
        assert not cm.is_synthetic_domain('')


class TestSsmComment(unittest.TestCase):
    """Tests for _ssm_comment() — clamps to AWS SendCommand's 100-char limit."""

    def test_short_comment_unchanged(self):
        c = 'Cert sync triggered for custom domain: short.example.com'
        assert cm._ssm_comment(c) == c

    def test_long_comment_truncated_to_100(self):
        long_domain = 'smoke-cleanup-43b4b748-e2d7-4c22-b99f-a2aab5300383.example.invalid'
        c = f'Cert delete triggered for custom domain: {long_domain}'
        assert len(c) > 100  # the bug precondition
        out = cm._ssm_comment(c)
        assert len(out) <= 100
        assert out == c[:100]


class TestPublishFailureMetricSynthetic(unittest.TestCase):
    """publish_failure_metric() suppresses prod failures for synthetic domains ONLY."""

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_skips_synthetic_domain(self, mock_cw):
        cm.publish_failure_metric(cm.FAILURE_CERT_SYNC, domain='smoke-cleanup-x.example.invalid')
        mock_cw.assert_not_called()

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_emits_for_real_domain(self, mock_cw):
        cm.publish_failure_metric(cm.FAILURE_CERT_SYNC, domain='secure.customer.com')
        assert mock_cw.called

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_emits_when_no_domain(self, mock_cw):
        cm.publish_failure_metric(cm.FAILURE_CERT_SYNC)
        assert mock_cw.called


class TestPublishRecoveryMetricSynthetic(unittest.TestCase):
    """publish_recovery_metric() suppresses recoveries for synthetic domains so a
    non-customer domain can't feed the cert_recovery_storm alarm (mirrors
    publish_failure_metric)."""

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_skips_synthetic_domain(self, mock_cw):
        cm.publish_recovery_metric(domain='smoke-cleanup-x.example.invalid')
        mock_cw.assert_not_called()

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_emits_for_real_domain(self, mock_cw):
        cm.publish_recovery_metric(domain='secure.customer.com')
        assert mock_cw.called

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    def test_emits_when_no_domain(self, mock_cw):
        cm.publish_recovery_metric()
        assert mock_cw.called


class TestDomainToAcmeSubdomain(unittest.TestCase):
    """Tests for domain_to_acme_subdomain() helper."""

    def test_simple_domain(self):
        assert cm.domain_to_acme_subdomain('example.com') == 'example--com'

    def test_subdomain(self):
        assert cm.domain_to_acme_subdomain('sub.example.com') == 'sub--example--com'

    def test_deep_subdomain(self):
        assert cm.domain_to_acme_subdomain('a.b.c.example.com') == 'a--b--c--example--com'


class TestListCertMetaParams(unittest.TestCase):
    """Tests for list_cert_meta_params()."""

    @patch.object(cm.ssm_client, 'get_paginator')
    def test_returns_only_meta_params(self, mock_paginator):
        """Should filter to only /meta params, skipping /key and /chain."""
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                'Parameters': [
                    {'Name': '/nhp/certs/example.com/key', 'Value': 'key-data'},
                    {'Name': '/nhp/certs/example.com/chain', 'Value': 'chain-data'},
                    {'Name': '/nhp/certs/example.com/meta', 'Value': '{"expires_at": "2026-06-01"}'},
                    {'Name': '/nhp/certs/foo.org/meta', 'Value': '{"expires_at": "2026-07-01"}'},
                    {'Name': '/nhp/certs/foo.org/key', 'Value': 'key-data'},
                ]
            }
        ]
        mock_paginator.return_value = paginator

        result = cm.list_cert_meta_params()
        assert len(result) == 2
        assert all(p['Name'].endswith('/meta') for p in result)

    @patch.object(cm.ssm_client, 'get_paginator')
    def test_returns_empty_when_no_params(self, mock_paginator):
        paginator = MagicMock()
        paginator.paginate.return_value = [{'Parameters': []}]
        mock_paginator.return_value = paginator

        result = cm.list_cert_meta_params()
        assert result == []


class TestProvisionPendingDomains(unittest.TestCase):
    """Tests for provision_pending_domains()."""

    def test_returns_early_when_no_table(self):
        """Should return immediately if QURL_DOMAINS_TABLE is not set."""
        original = cm.QURL_DOMAINS_TABLE
        cm.QURL_DOMAINS_TABLE = None
        try:
            result = cm.provision_pending_domains()
            assert result == {'provisioned': 0, 'failed': 0, 'timed_out': 0, 'recovered': 0, 'skipped': 0}
        finally:
            cm.QURL_DOMAINS_TABLE = original

    @patch.object(cm.dynamodb_client, 'query')
    def test_returns_zero_when_no_pending(self, mock_query):
        """Should return zeros when no domains are in provisioning_tls status."""
        mock_query.return_value = {'Items': []}

        result = cm.provision_pending_domains()
        assert result['provisioned'] == 0
        assert result['failed'] == 0

        # Verify it queried the status-index GSI with the correct status constant
        call_kwargs = mock_query.call_args.kwargs
        assert call_kwargs['IndexName'] == 'status-index'
        assert call_kwargs['ExpressionAttributeValues'][':status'] == {'S': cm.STATUS_PROVISIONING_TLS}

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_provisions_pending_domains(self, mock_query, mock_provision, mock_sync):
        """Should provision each pending domain and trigger batch sync."""
        mock_query.return_value = {
            'Items': [
                {'domain': {'S': 'example.com'}},
                {'domain': {'S': 'test.org'}},
            ]
        }
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.provision_pending_domains()
        assert result['provisioned'] == 2
        assert result['failed'] == 0

        # Should call provision with skip_sync=True (batched)
        for call in mock_provision.call_args_list:
            assert call.kwargs.get('skip_sync') is True

        # Should trigger a single batch sync
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_PROVISION)

    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_skips_invalid_domains(self, mock_query, mock_provision, mock_sync, mock_status, mock_metric):
        """Should auto-fail domains that fail validation and count them as failures."""
        del mock_sync  # @patch supplies this; the test asserts on mock_status / mock_metric instead
        mock_query.return_value = {
            'Items': [
                {'domain': {'S': 'good.com'}},
                {'domain': {'S': '../../etc/passwd'}},
                {'domain': {'S': 'also-good.org'}},
            ]
        }
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.provision_pending_domains()
        assert result['provisioned'] == 2
        assert result['failed'] == 1
        assert mock_provision.call_count == 2
        # The invalid domain should be marked failed so it leaves the
        # provisioning_tls partition.
        mock_status.assert_called_once()
        assert mock_status.call_args.args[0] == '../../etc/passwd'
        assert mock_status.call_args.args[1] == cm.STATUS_FAILED
        mock_metric.assert_called_once_with(cm.FAILURE_DOMAIN_VALIDATION)

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_counts_failures(self, mock_query, mock_provision, mock_sync):
        """Should count failed provisions and still sync successful ones."""
        mock_query.return_value = {
            'Items': [
                {'domain': {'S': 'good.com'}},
                {'domain': {'S': 'bad.com'}},
            ]
        }
        mock_provision.side_effect = [
            {'status': 'provisioned'},
            Exception('ACME failed'),
        ]

        result = cm.provision_pending_domains()
        assert result['provisioned'] == 1
        assert result['failed'] == 1
        mock_sync.assert_called_once()



class TestProvisioningTimeout(unittest.TestCase):
    """Tests for the auto-fail-on-stuck-provisioning behavior."""

    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_auto_fails_stuck_domain(self, mock_get_param, mock_query, mock_status, mock_metric, mock_alert):
        # No cert in SSM → the nhp#977 recovery check finds nothing, so the
        # auto-fail proceeds exactly as before.
        mock_get_param.side_effect = cm.ssm_client.exceptions.ParameterNotFound(
            {'Error': {'Code': 'ParameterNotFound', 'Message': 'not found'}}, 'GetParameter')
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        mock_query.return_value = {
            'Items': [
                {
                    'domain': {'S': 'stuck.example.com'},
                    'provisioning_started_at': {'S': old_time},
                }
            ]
        }
        result = cm.provision_pending_domains()
        assert result['timed_out'] == 1
        assert result['provisioned'] == 0
        assert result['recovered'] == 0
        mock_status.assert_called_once()
        assert mock_status.call_args.args[0] == 'stuck.example.com'
        assert mock_status.call_args.args[1] == cm.STATUS_FAILED
        # Customer-facing reason: plain English, actionable, no
        # implementation details. The customer sees this in the
        # dashboard so it must be readable.
        customer_reason = mock_status.call_args.kwargs['error']
        assert "Certificate provisioning didn't complete within" in customer_reason
        assert 'DNS records' in customer_reason
        assert 'try again' in customer_reason
        # Customer reason MUST NOT leak operational details.
        assert 'started_at' not in customer_reason
        assert 'threshold' not in customer_reason
        mock_metric.assert_called_once_with(cm.FAILURE_PROVISIONING_TIMEOUT)
        mock_alert.assert_called_once()
        # Operator-facing reason: implementation details for triage,
        # delivered via SNS alert. Goes to on-call, not the customer.
        operator_reason = mock_alert.call_args.args[0]
        assert 'auto-failed' in operator_reason.lower()
        assert 'timed out after' in operator_reason
        assert 'started_at' in operator_reason
        assert 'threshold' in operator_reason

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_provisions_domain_within_timeout(self, mock_query, mock_provision, mock_sync):
        recent_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        mock_query.return_value = {
            'Items': [
                {
                    'domain': {'S': 'recent.example.com'},
                    'provisioning_started_at': {'S': recent_time},
                }
            ]
        }
        mock_provision.return_value = {'status': 'provisioned'}
        result = cm.provision_pending_domains()
        assert result['provisioned'] == 1
        assert result['timed_out'] == 0
        mock_provision.assert_called_once()
        assert mock_provision.call_args.args[0] == 'recent.example.com'

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_provisions_domain_without_timestamp(self, mock_query, mock_provision, mock_sync):
        mock_query.return_value = {'Items': [{'domain': {'S': 'new.example.com'}}]}
        mock_provision.return_value = {'status': 'provisioned'}
        result = cm.provision_pending_domains()
        assert result['provisioned'] == 1

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_handles_invalid_timestamp(self, mock_query, mock_provision, mock_sync):
        mock_query.return_value = {
            'Items': [
                {
                    'domain': {'S': 'bad.example.com'},
                    'provisioning_started_at': {'S': 'not-a-date'},
                }
            ]
        }
        mock_provision.return_value = {'status': 'provisioned'}
        result = cm.provision_pending_domains()
        assert result['provisioned'] == 1
        assert result['timed_out'] == 0

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.dynamodb_client, 'update_item')
    def test_does_not_pre_write_provisioning_started_at(self, mock_update, mock_query, mock_sync):
        """Regression test: provision_pending_domains must not write
        provisioning_started_at before calling provision_certificate.

        Doing so would defeat the conditional write in
        _acquire_provisioning_lock and cause every invocation to be skipped.
        Here we verify that the only update_item calls observed during a normal
        provisioning attempt come from inside _acquire_provisioning_lock /
        update_domain_status, never as a pre-write to set the timestamp.
        """
        mock_query.return_value = {'Items': [{'domain': {'S': 'example.com'}}]}

        # Make _acquire_provisioning_lock succeed (first update_item) but
        # then short-circuit by raising in lazy_import_acme so we don't call
        # the real ACME stack.
        with patch('custom_domain_cert_manager.lazy_import_acme', side_effect=Exception('stop')):
            with patch('custom_domain_cert_manager.send_alert'):
                with patch('custom_domain_cert_manager.publish_failure_metric'):
                    cm.provision_pending_domains()

        # The first update_item must be the conditional lock acquisition,
        # NOT a plain SET that would clobber the lock.
        assert mock_update.call_count >= 1
        first_call = mock_update.call_args_list[0]
        assert 'ConditionExpression' in first_call.kwargs, (
            "First update_item must be the conditional lock acquisition; "
            "got an unconditional update which would defeat the lock."
        )


class TestProvisioningTimeoutRecovery(unittest.TestCase):
    """Tests for the pre-auto-fail cert recovery path (_recover_provisioned_cert, nhp#977).

    A domain can be stuck in provisioning_tls because update_domain_status(active)
    lost a race with a DynamoDB blip *after* the cert was issued and stored in SSM.
    Before auto-failing such a domain, provision_pending_domains() reconciles it
    against SSM and recovers the row to active when a healthy cert exists.
    """

    @staticmethod
    def _param_not_found():
        return cm.ssm_client.exceptions.ParameterNotFound(
            {'Error': {'Code': 'ParameterNotFound', 'Message': 'not found'}}, 'GetParameter')

    @staticmethod
    def _throttle_error():
        return ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'slow down'}}, 'GetParameter')

    @staticmethod
    def _meta_response(days_until_expiry, now=None):
        """Build a get_parameter response for a cert expiring in N days.

        Returns (response, expires_at_str) so callers can assert the exact
        expires_at threaded into update_domain_status. Pass ``now`` to anchor
        the expiry to a caller-supplied clock with no drift — needed to pin the
        boundary exactly at RENEWAL_DAYS_BEFORE_EXPIRY; otherwise it defaults to
        the current time.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=days_until_expiry)).isoformat()
        response = {'Parameter': {'Value': json.dumps({
            'domain': 'whatever.example.com',
            'expires_at': expires_at,
            'acme_subdomain': 'whatever--example--com',
        })}}
        return response, expires_at

    # ---- helper-level branch logic ----

    @patch('custom_domain_cert_manager.publish_recovery_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_recovers_valid_cert(self, mock_get, mock_status, mock_recovery_metric):
        now = datetime.now(timezone.utc)
        resp, expires_at = self._meta_response(89)
        mock_get.return_value = resp
        outcome = cm._recover_provisioned_cert('valid.example.com', now)
        assert outcome == cm.RECOVER_RECOVERED
        mock_status.assert_called_once_with(
            'valid.example.com', cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/valid.example.com', cert_expires_at=expires_at)
        # /meta is a plain String param — recovery must not pay a KMS decrypt.
        assert mock_get.call_args.kwargs['WithDecryption'] is False
        assert mock_get.call_args.kwargs['Name'] == '/nhp/certs/valid.example.com/meta'
        # Recovery is metered (with the domain, for synthetic-domain suppression)
        # so the #977 race is measurable in prod.
        mock_recovery_metric.assert_called_once_with('valid.example.com')

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_cert_on_parameter_not_found(self, mock_get, mock_status):
        mock_get.side_effect = self._param_not_found()
        outcome = cm._recover_provisioned_cert('missing.example.com', datetime.now(timezone.utc))
        assert outcome == cm.RECOVER_NO_CERT
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_defers_on_transient_ssm_error(self, mock_get, mock_status):
        mock_get.side_effect = self._throttle_error()
        outcome = cm._recover_provisioned_cert('throttled.example.com', datetime.now(timezone.utc))
        assert outcome == cm.RECOVER_DEFER
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_recover_when_cert_near_expiry(self, mock_get, mock_status):
        now = datetime.now(timezone.utc)
        resp, _ = self._meta_response(cm.RENEWAL_DAYS_BEFORE_EXPIRY - 5)
        mock_get.return_value = resp
        outcome = cm._recover_provisioned_cert('expiring.example.com', now)
        assert outcome == cm.RECOVER_NO_CERT
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.publish_recovery_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_recover_at_exactly_renewal_threshold(self, mock_get, mock_status, mock_recovery_metric):
        """days_until_expiry == RENEWAL_DAYS_BEFORE_EXPIRY is <= threshold, so it
        is NOT recovered. Pins the `<=` boundary (one day either side flips it)."""
        now = datetime.now(timezone.utc)
        # Anchor expiry to `now` so it lands exactly on the threshold (no drift).
        mock_get.return_value, _ = self._meta_response(cm.RENEWAL_DAYS_BEFORE_EXPIRY, now=now)
        outcome = cm._recover_provisioned_cert('boundary.example.com', now)
        assert outcome == cm.RECOVER_NO_CERT
        mock_status.assert_not_called()
        mock_recovery_metric.assert_not_called()

    @patch('custom_domain_cert_manager.publish_recovery_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_recovers_just_above_renewal_threshold(self, mock_get, mock_status, mock_recovery_metric):
        """One day past the threshold flips to recovery — the other side of `<=`."""
        now = datetime.now(timezone.utc)
        mock_get.return_value, _ = self._meta_response(cm.RENEWAL_DAYS_BEFORE_EXPIRY + 1, now=now)
        outcome = cm._recover_provisioned_cert('boundary.example.com', now)
        assert outcome == cm.RECOVER_RECOVERED
        mock_status.assert_called_once()
        mock_recovery_metric.assert_called_once_with('boundary.example.com')

    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.publish_recovery_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_defers_when_recovery_write_raises(self, mock_get, mock_status, mock_recovery_metric, mock_failure_metric):
        """If the recovery write raises (defensive against a future
        update_domain_status contract change), defer rather than crash the scan
        or miscount the domain as recovered — and emit a DynamoDB failure metric
        so the defer-on-raise path isn't a dashboard blind spot."""
        now = datetime.now(timezone.utc)
        resp, _ = self._meta_response(89)
        mock_get.return_value = resp
        mock_status.side_effect = RuntimeError('ddb unavailable')
        outcome = cm._recover_provisioned_cert('writefail.example.com', now)
        assert outcome == cm.RECOVER_DEFER
        mock_recovery_metric.assert_not_called()
        mock_failure_metric.assert_called_once_with(cm.FAILURE_DYNAMODB)

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_recover_on_malformed_meta(self, mock_get, mock_status):
        mock_get.return_value = {'Parameter': {'Value': 'not-json{'}}
        outcome = cm._recover_provisioned_cert('garbled.example.com', datetime.now(timezone.utc))
        assert outcome == cm.RECOVER_NO_CERT
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_recover_on_non_object_meta(self, mock_get, mock_status):
        """Valid JSON that isn't an object (null/number/string/array) must fall
        through to auto-fail, not crash the scan with AttributeError on .get()."""
        for value in ('null', '42', '"a-string"', '[1, 2, 3]'):
            with self.subTest(value=value):
                mock_status.reset_mock()
                mock_get.return_value = {'Parameter': {'Value': value}}
                outcome = cm._recover_provisioned_cert('nonobj.example.com', datetime.now(timezone.utc))
                assert outcome == cm.RECOVER_NO_CERT
                mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_helper_no_recover_when_expires_at_missing(self, mock_get, mock_status):
        mock_get.return_value = {'Parameter': {'Value': json.dumps(
            {'domain': 'noexp.example.com', 'acme_subdomain': 'noexp--example--com'})}}
        outcome = cm._recover_provisioned_cert('noexp.example.com', datetime.now(timezone.utc))
        assert outcome == cm.RECOVER_NO_CERT
        mock_status.assert_not_called()

    # ---- integration through provision_pending_domains ----

    @patch('custom_domain_cert_manager.publish_recovery_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_recovers_stuck_domain_with_valid_cert(
        self, mock_get, mock_query, mock_status, mock_metric, mock_alert, mock_sync, mock_recovery_metric,
    ):
        """A timed-out domain whose cert is already in SSM is recovered to active,
        not auto-failed — and a full cert sync fires so the AC fleet picks up the
        cert the failed provisioning never synced."""
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        mock_query.return_value = {
            'Items': [{
                'domain': {'S': 'recovered.example.com'},
                'provisioning_started_at': {'S': old_time},
            }]
        }
        resp, expires_at = self._meta_response(89)
        mock_get.return_value = resp

        result = cm.provision_pending_domains()

        assert result['recovered'] == 1
        assert result['timed_out'] == 0
        assert result['failed'] == 0
        # Row reconciled to active with the existing cert values...
        mock_status.assert_called_once_with(
            'recovered.example.com', cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/recovered.example.com', cert_expires_at=expires_at)
        # ...not auto-failed: no timeout metric, no SNS alert (recovery only logs WARNING).
        mock_metric.assert_not_called()
        mock_alert.assert_not_called()
        # Recovery is metered, and exactly once for the one recovered domain.
        mock_recovery_metric.assert_called_once_with('recovered.example.com')
        # The original provisioning's sync never ran; recovery must trigger one.
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_PROVISION)

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_defers_stuck_domain_on_transient_ssm_error(
        self, mock_get, mock_query, mock_status, mock_metric, mock_alert, mock_sync,
    ):
        """A transient SSM read error must NOT auto-fail the domain — leave it in
        provisioning_tls so the next scan re-evaluates."""
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        mock_query.return_value = {
            'Items': [{
                'domain': {'S': 'blip.example.com'},
                'provisioning_started_at': {'S': old_time},
            }]
        }
        mock_get.side_effect = self._throttle_error()

        result = cm.provision_pending_domains()

        assert result['recovered'] == 0
        assert result['timed_out'] == 0
        # Neither recovered nor failed — the row is left untouched this round.
        mock_status.assert_not_called()
        mock_metric.assert_not_called()
        mock_alert.assert_not_called()
        mock_sync.assert_not_called()

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_within_timeout_row_skips_recovery_ssm_read(self, mock_get, mock_query, mock_provision, mock_sync):
        """Recovery (and its /meta read) runs only on timed-out rows. A
        within-timeout row goes straight to provision_certificate and must NOT
        touch SSM via the recovery path — locks the `if timeout_check is not None`
        guard."""
        recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        mock_query.return_value = {
            'Items': [{
                'domain': {'S': 'fresh.example.com'},
                'provisioning_started_at': {'S': recent},
            }]
        }
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.provision_pending_domains()

        assert result['provisioned'] == 1
        assert result['recovered'] == 0
        assert result['timed_out'] == 0
        mock_provision.assert_called_once()
        mock_get.assert_not_called()
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_PROVISION)

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'query')
    @patch.object(cm.ssm_client, 'get_parameter')
    def test_auto_fails_when_cert_near_expiry(
        self, mock_get, mock_query, mock_status, mock_metric, mock_alert, mock_sync,
    ):
        """A stale cert inside the renewal window is not papered over — auto-fail
        so the reprovision path mints a fresh one."""
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        mock_query.return_value = {
            'Items': [{
                'domain': {'S': 'stale.example.com'},
                'provisioning_started_at': {'S': old_time},
            }]
        }
        resp, _ = self._meta_response(cm.RENEWAL_DAYS_BEFORE_EXPIRY - 5)
        mock_get.return_value = resp

        result = cm.provision_pending_domains()

        assert result['recovered'] == 0
        assert result['timed_out'] == 1
        assert mock_status.call_args.args[0] == 'stale.example.com'
        assert mock_status.call_args.args[1] == cm.STATUS_FAILED
        mock_metric.assert_called_once_with(cm.FAILURE_PROVISIONING_TIMEOUT)
        # Auto-fail still pages on-call with the operator-facing reason.
        assert 'auto-failed' in mock_alert.call_args.args[0].lower()
        mock_sync.assert_not_called()


class TestStoreCertificate(unittest.TestCase):
    """Tests for store_certificate() SSM parameter storage."""

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_stores_three_params(self, mock_put):
        """Should store key, chain, and meta as separate SSM parameters."""
        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with patch('custom_domain_cert_manager._get_existing_ssm_secure_param', return_value=None):
                result = cm.store_certificate(
                    domain='example.com',
                    private_key_pem='test-key-pem-data',
                    cert_pem='test-cert-pem-data',
                    chain_pem='test-chain-pem-data',
                    expires_at='2026-06-01T00:00:00+00:00',
                    acme_subdomain='example--com',
                )

        assert mock_put.call_count == 3
        assert result == '/nhp/certs/example.com'

        # Verify parameter names
        names = [call.kwargs['Name'] for call in mock_put.call_args_list]
        assert '/nhp/certs/example.com/key' in names
        assert '/nhp/certs/example.com/chain' in names
        assert '/nhp/certs/example.com/meta' in names

        # Lock the write-order invariant: /meta MUST be written last. The
        # nhp#977 recovery path (_recover_provisioned_cert) trusts a present
        # /meta as proof that key+chain were already stored; if a refactor wrote
        # /meta first, recovery could mark a row active before its cert material
        # exists. This pins that contract so such a reorder fails the suite.
        assert names[-1].endswith('/meta'), (
            "meta must be the final SSM write — nhp#977 recovery depends on it")

        # Verify key and chain are SecureString, meta is String
        for call in mock_put.call_args_list:
            if call.kwargs['Name'].endswith('/meta'):
                assert call.kwargs['Type'] == 'String'
            else:
                assert call.kwargs['Type'] == 'SecureString'

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_chain_is_fullchain(self, mock_put):
        """Chain param should contain cert + chain concatenated."""
        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with patch('custom_domain_cert_manager._get_existing_ssm_secure_param', return_value=None):
                cm.store_certificate(
                    domain='test.org',
                    private_key_pem='key-pem',
                    cert_pem='cert-pem',
                    chain_pem='chain-pem',
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        chain_call = [c for c in mock_put.call_args_list if c.kwargs['Name'].endswith('/chain')][0]
        assert chain_call.kwargs['Value'] == 'cert-pemchain-pem'

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_rejects_key_cert_mismatch_before_any_ssm_write(self, mock_put):
        """A renewal must not poison live SSM params with a key for another cert."""
        # Keep the certificate from one pair, then pass a key from another pair.
        _, cert_pem = _self_signed_cert_pair('example.com')
        wrong_key, _ = _self_signed_cert_pair('other.example.com')

        with pytest.raises(ValueError, match='does not match leaf certificate'):
            cm.store_certificate(
                domain='example.com',
                private_key_pem=wrong_key,
                cert_pem=cert_pem,
                chain_pem='',
                expires_at='2026-06-01T00:00:00+00:00',
            )

        mock_put.assert_not_called()

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_rejects_oversized_secure_value_before_any_ssm_write(self, mock_put):
        """Preflight must catch values beyond SSM's advanced limit before writes."""
        oversized_chain = 'x' * (cm.SSM_ADVANCED_PARAMETER_VALUE_MAX_BYTES + 1)

        with patch('custom_domain_cert_manager._validate_certificate_key_pair'):
            with pytest.raises(ValueError, match='advanced limit'):
                cm.store_certificate(
                    domain='example.com',
                    private_key_pem='key-pem',
                    cert_pem='cert-pem',
                    chain_pem=oversized_chain,
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        mock_put.assert_not_called()

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_uses_advanced_tier_for_large_fullchain(self, mock_put):
        """Large fullchains should renew instead of failing after key overwrite."""
        large_chain = 'c' * (cm.SSM_STANDARD_PARAMETER_VALUE_MAX_BYTES + 1)

        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with patch('custom_domain_cert_manager._get_existing_ssm_secure_param', return_value=None):
                cm.store_certificate(
                    domain='large.example.com',
                    private_key_pem='key-pem',
                    cert_pem='cert-pem',
                    chain_pem=large_chain,
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        key_call = [c for c in mock_put.call_args_list if c.kwargs['Name'].endswith('/key')][0]
        chain_call = [c for c in mock_put.call_args_list if c.kwargs['Name'].endswith('/chain')][0]
        assert key_call.kwargs['Tier'] == 'Standard'
        assert chain_call.kwargs['Tier'] == 'Advanced'

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_preserves_advanced_tier_when_fullchain_later_fits_standard(self, mock_put):
        """SSM rejects Advanced -> Standard; renewal should keep Advanced and continue."""
        def put_parameter(**kwargs):
            if kwargs['Name'].endswith('/chain') and kwargs['Tier'] == 'Standard':
                raise ClientError(
                    {'Error': {
                        'Code': 'ValidationException',
                        'Message': 'Cannot change advanced parameter to standard tier',
                    }},
                    'PutParameter',
                )

        mock_put.side_effect = put_parameter

        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with patch('custom_domain_cert_manager._get_existing_ssm_secure_param', return_value='old-value'):
                cm.store_certificate(
                    domain='large.example.com',
                    private_key_pem='key-pem',
                    cert_pem='cert-pem',
                    chain_pem='small-chain-pem',
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        chain_tiers = [
            c.kwargs['Tier']
            for c in mock_put.call_args_list
            if c.kwargs['Name'].endswith('/chain')
        ]
        assert chain_tiers == ['Standard', 'Advanced']
        meta_call = mock_put.call_args_list[-1]
        assert meta_call.kwargs['Name'] == '/nhp/certs/large.example.com/meta'

    @patch.object(cm.ssm_client, 'get_parameter')
    @patch.object(cm.ssm_client, 'put_parameter')
    def test_restores_previous_pair_when_key_write_fails(self, mock_put, mock_get):
        """If one SSM write fails, restore the old key+chain pair."""
        def get_parameter(**kwargs):
            if kwargs['Name'].endswith('/key'):
                return {'Parameter': {'Value': 'old-key-pem'}}
            if kwargs['Name'].endswith('/chain'):
                return {'Parameter': {'Value': 'old-fullchain-pem'}}
            raise AssertionError(f"unexpected get_parameter call: {kwargs}")

        def put_parameter(**kwargs):
            if kwargs['Name'].endswith('/key') and kwargs['Value'] == 'new-key-pem':
                raise ClientError(
                    {'Error': {'Code': 'InternalServerError', 'Message': 'transient'}},
                    'PutParameter',
                )

        mock_get.side_effect = get_parameter
        mock_put.side_effect = put_parameter

        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with pytest.raises(ClientError):
                cm.store_certificate(
                    domain='example.com',
                    private_key_pem='new-key-pem',
                    cert_pem='new-cert-pem',
                    chain_pem='new-chain-pem',
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        writes = [(c.kwargs['Name'], c.kwargs['Value']) for c in mock_put.call_args_list]
        assert writes == [
            ('/nhp/certs/example.com/chain', 'new-cert-pemnew-chain-pem'),
            ('/nhp/certs/example.com/key', 'new-key-pem'),
            ('/nhp/certs/example.com/chain', 'old-fullchain-pem'),
            ('/nhp/certs/example.com/key', 'old-key-pem'),
        ]
        assert not any(name.endswith('/meta') for name, _ in writes)

    @patch.object(cm.ssm_client, 'delete_parameter')
    @patch.object(cm.ssm_client, 'get_parameter')
    @patch.object(cm.ssm_client, 'put_parameter')
    def test_first_issuance_key_write_failure_deletes_orphan_chain(
            self, mock_put, mock_get, mock_delete):
        """If first issuance writes chain but not key, rollback deletes the orphan."""
        mock_get.side_effect = cm.ssm_client.exceptions.ParameterNotFound(
            {'Error': {'Code': 'ParameterNotFound', 'Message': 'not found'}},
            'GetParameter',
        )

        def put_parameter(**kwargs):
            if kwargs['Name'].endswith('/key') and kwargs['Value'] == 'new-key-pem':
                raise ClientError(
                    {'Error': {'Code': 'InternalServerError', 'Message': 'key write failed'}},
                    'PutParameter',
                )

        mock_put.side_effect = put_parameter

        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with pytest.raises(ClientError, match='key write failed'):
                cm.store_certificate(
                    domain='first.example.com',
                    private_key_pem='new-key-pem',
                    cert_pem='new-cert-pem',
                    chain_pem='new-chain-pem',
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        writes = [(c.kwargs['Name'], c.kwargs['Value']) for c in mock_put.call_args_list]
        assert writes == [
            ('/nhp/certs/first.example.com/chain', 'new-cert-pemnew-chain-pem'),
            ('/nhp/certs/first.example.com/key', 'new-key-pem'),
        ]
        mock_delete.assert_has_calls([
            call(Name='/nhp/certs/first.example.com/chain'),
            call(Name='/nhp/certs/first.example.com/key'),
        ])
        assert not any(name.endswith('/meta') for name, _ in writes)

    @patch('custom_domain_cert_manager.publish_metric')
    @patch.object(cm.ssm_client, 'get_parameter')
    @patch.object(cm.ssm_client, 'put_parameter')
    def test_restore_attempts_key_even_when_chain_restore_fails(
            self, mock_put, mock_get, mock_publish_metric):
        """Rollback restore should attempt each param independently."""
        def get_parameter(**kwargs):
            if kwargs['Name'].endswith('/key'):
                return {'Parameter': {'Value': 'old-key-pem'}}
            if kwargs['Name'].endswith('/chain'):
                return {'Parameter': {'Value': 'old-fullchain-pem'}}
            raise AssertionError(f"unexpected get_parameter call: {kwargs}")

        def put_parameter(**kwargs):
            if kwargs['Name'].endswith('/key') and kwargs['Value'] == 'new-key-pem':
                raise ClientError(
                    {'Error': {'Code': 'InternalServerError', 'Message': 'key write failed'}},
                    'PutParameter',
                )
            if kwargs['Name'].endswith('/chain') and kwargs['Value'] == 'old-fullchain-pem':
                raise ClientError(
                    {'Error': {'Code': 'InternalServerError', 'Message': 'chain restore failed'}},
                    'PutParameter',
                )

        mock_get.side_effect = get_parameter
        mock_put.side_effect = put_parameter

        with patch('custom_domain_cert_manager._preflight_certificate_storage'):
            with pytest.raises(ClientError, match='key write failed'):
                cm.store_certificate(
                    domain='example.com',
                    private_key_pem='new-key-pem',
                    cert_pem='new-cert-pem',
                    chain_pem='new-chain-pem',
                    expires_at='2026-06-01T00:00:00+00:00',
                )

        writes = [(c.kwargs['Name'], c.kwargs['Value']) for c in mock_put.call_args_list]
        assert writes == [
            ('/nhp/certs/example.com/chain', 'new-cert-pemnew-chain-pem'),
            ('/nhp/certs/example.com/key', 'new-key-pem'),
            ('/nhp/certs/example.com/chain', 'old-fullchain-pem'),
            ('/nhp/certs/example.com/key', 'old-key-pem'),
        ]
        mock_publish_metric.assert_called_once_with(cm.CW_METRIC_CERT_PAIR_ROLLBACK_FAILURES, 1)


class TestRenewalScan(unittest.TestCase):
    """Tests for renewal_scan() certificate expiry scanning."""

    def setUp(self):
        # renewal_scan now calls check_orphan_for_meta() per-domain (Option B
        # from nhp#1990), which does a GetItem on qurl-domains. Default to a
        # valid managed row so existing tests in this class — which are not
        # exercising the orphan path — don't accidentally trip the orphan
        # branch and skip the renewal logic they actually care about.
        self._get_item_patcher = patch.object(cm.dynamodb_client, 'get_item')
        self.mock_get_item = self._get_item_patcher.start()
        self.mock_get_item.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_ACTIVE},
                'verification_token': {'S': 'lv_verify_test_token'},
            }
        }

    def tearDown(self):
        self._get_item_patcher.stop()

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_renews_expiring_certs(self, mock_list, mock_cw, mock_provision, mock_sync):
        """Should renew certs expiring within RENEWAL_DAYS_BEFORE_EXPIRY."""
        del mock_cw  # @patch suppresses real CloudWatch calls; not asserted here
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/expiring.com/meta',
                'Value': json.dumps({
                    'expires_at': '2026-03-15T00:00:00+00:00',
                    'acme_subdomain': 'expiring--com',
                }),
            },
        ]
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.renewal_scan()
        assert result['renewed'] == 1
        assert result['scanned'] == 1
        mock_provision.assert_called_once_with(
            'expiring.com',
            'expiring--com',
            skip_sync=True,
            emit_per_domain_signals=False,
            mark_failed_on_error=False,
            expected_verification_token='lv_verify_test_token',
        )
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_due_renewal_falls_back_when_preloaded_domain_row_is_unavailable(
        self, mock_list, mock_cw, mock_provision, mock_sync,
    ):
        """A transient pre-read DDB blip should not be counted as DNS ownership drift."""
        del mock_cw
        self.mock_get_item.side_effect = ClientError(
            {'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 'throttled'}},
            'GetItem',
        )
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/expiring.com/meta',
                'Value': json.dumps({
                    'expires_at': '2026-03-15T00:00:00+00:00',
                    'acme_subdomain': 'expiring--com',
                }),
            },
        ]
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.renewal_scan()

        assert result['renewed'] == 1
        assert result['dns_ownership_failed'] == 0
        assert result['orphaned'] == 0
        mock_provision.assert_called_once_with(
            'expiring.com',
            'expiring--com',
            skip_sync=True,
            emit_per_domain_signals=False,
            mark_failed_on_error=False,
        )
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_skips_valid_certs(self, mock_list, mock_cw, mock_provision, mock_sync):
        """Should skip certs that are not near expiry."""
        del mock_cw  # @patch suppresses real CloudWatch calls; not asserted here
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/valid.com/meta',
                'Value': json.dumps({
                    'expires_at': '2026-12-01T00:00:00+00:00',
                    'acme_subdomain': 'valid--com',
                }),
            },
        ]

        result = cm.renewal_scan()
        assert result['renewed'] == 0
        assert result['skipped'] == 1
        mock_provision.assert_not_called()
        mock_sync.assert_not_called()

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_handles_missing_expires_at(self, mock_list, mock_cw):
        """Should skip params with missing expires_at field."""
        del mock_cw  # @patch suppresses real CloudWatch calls; not asserted here
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/broken.com/meta',
                'Value': json.dumps({'acme_subdomain': 'broken--com'}),
            },
        ]

        result = cm.renewal_scan()
        assert result['skipped'] == 1
        assert result['renewed'] == 0

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_handles_malformed_meta(self, mock_list, mock_cw):
        """Should count params with invalid JSON as failures."""
        del mock_cw  # @patch suppresses real CloudWatch calls; not asserted here
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/bad.com/meta',
                'Value': 'not-json',
            },
        ]

        result = cm.renewal_scan()
        assert result['failed'] == 1

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_derives_acme_subdomain_when_missing(self, mock_list, mock_cw, mock_provision, mock_sync):
        """Should derive acme_subdomain from domain name if not in meta."""
        del mock_cw, mock_sync  # @patch suppresses side effects; not asserted here
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/no-acme.com/meta',
                'Value': json.dumps({
                    'expires_at': '2026-03-10T00:00:00+00:00',
                }),
            },
        ]
        mock_provision.return_value = {'status': 'provisioned'}

        cm.renewal_scan()
        # Should have called provision with derived acme_subdomain
        mock_provision.assert_called_once_with(
            'no-acme.com',
            'no-acme--com',
            skip_sync=True,
            emit_per_domain_signals=False,
            mark_failed_on_error=False,
            expected_verification_token='lv_verify_test_token',
        )

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_heartbeat_publishes_before_scan_work(self, mock_list, mock_cw):
        """RenewalScanRuns should mean the scheduled scanner was invoked."""
        mock_list.side_effect = RuntimeError('ssm pagination timeout')

        with pytest.raises(RuntimeError, match='ssm pagination timeout'):
            cm.renewal_scan()

        mock_cw.assert_called_once()
        assert mock_cw.call_args.kwargs['MetricData'] == [
            {
                'MetricName': cm.CW_METRIC_RENEWAL_SCAN_RUNS,
                'Dimensions': cm.RENEWAL_SCAN_METRIC_DIMENSIONS,
                'Value': 1,
                'Unit': 'Count',
            },
        ]

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_final_count_metric_publish_retries_transient_cloudwatch_failure(
        self, mock_list, mock_cw,
    ):
        """A transient final metric blip should not force an async full re-scan."""
        mock_list.return_value = []
        mock_cw.side_effect = [
            None,  # start-of-scan heartbeat
            Exception('cloudwatch blip 1'),
            Exception('cloudwatch blip 2'),
            None,
        ]

        with patch('custom_domain_cert_manager.time.sleep') as mock_sleep:
            result = cm.renewal_scan()

        assert result['heartbeat_publish_failed'] is False
        assert result['metric_publish_failed'] is False
        assert [
            metric_call.kwargs['MetricData'][0]['MetricName']
            for metric_call in mock_cw.call_args_list
        ] == [
            cm.CW_METRIC_RENEWAL_SCAN_RUNS,
            cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES,
            cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES,
            cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES,
        ]
        mock_sleep.assert_has_calls([
            call(cm.RENEWAL_SCAN_METRIC_RETRY_DELAYS_SECONDS[0]),
            call(cm.RENEWAL_SCAN_METRIC_RETRY_DELAYS_SECONDS[1]),
        ])

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_successful_renewal_suppresses_per_domain_alerts(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Scheduled renewal success should sync once without per-domain alerting."""
        del mock_cw
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/renewed.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'renewed--com',
                }),
            },
        ]
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_ACTIVE},
                'verification_token': {'S': 'lv_verify_renewed'},
            }
        }
        mock_provision.return_value = {'status': cm.RESULT_PROVISIONED}

        result = cm.renewal_scan()

        assert result['renewed'] == 1
        assert result['failed'] == 0
        assert result['dns_ownership_failed'] == 0
        assert result['orphaned'] == 0
        mock_provision.assert_called_once_with(
            'renewed.com',
            'renewed--com',
            skip_sync=True,
            emit_per_domain_signals=False,
            mark_failed_on_error=False,
            expected_verification_token='lv_verify_renewed',
        )
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_metric_publish_failure_does_not_skip_renewal_sync(
        self, mock_list, mock_cw, mock_provision, mock_sync,
    ):
        """Telemetry failure should be recorded only after renewal sync can run."""
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/renewed.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'renewed--com',
                }),
            },
        ]
        mock_provision.return_value = {'status': cm.RESULT_PROVISIONED}
        mock_cw.side_effect = Exception('cloudwatch denied')

        with patch('custom_domain_cert_manager.time.sleep'):
            result = cm.renewal_scan()

        assert result['renewed'] == 1
        assert result['heartbeat_publish_failed'] is True
        assert result['metric_publish_failed'] is True
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_dns_ownership_failure_is_scan_aggregate(
        self, mock_list, mock_cw, mock_provision, mock_sync, mock_failure_metric, mock_alert,
    ):
        """Scheduled renewal DNS drift should count once, not page per domain."""
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/drifted.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'drifted--com',
                }),
            },
        ]
        mock_provision.side_effect = cm.DnsOwnershipError('TXT mismatch')

        result = cm.renewal_scan()

        assert result['dns_ownership_failed'] == 1
        assert result['failed'] == 0
        assert result['renewed'] == 0
        assert result['orphaned'] == 0
        mock_sync.assert_not_called()
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        metric_values = _metric_values(mock_cw)
        assert metric_values[cm.CW_METRIC_RENEWAL_SCAN_RUNS] == 1
        assert metric_values[cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES] == 1
        assert metric_values[cm.CW_METRIC_RENEWAL_ORPHANED_CERTS] == 0
        _assert_renewal_metric_dimensions(mock_cw)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch('custom_domain_cert_manager.recover_failed_domain_with_valid_cert')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_processing_failure_is_scan_aggregate(
        self, mock_list, mock_cw, mock_recover, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Scheduled renewal infra faults should aggregate without per-domain paging."""
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/failed.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'failed--com',
                }),
            },
        ]
        mock_recover.return_value = False
        mock_provision.side_effect = Exception('kms throttle')

        result = cm.renewal_scan()

        assert result['status_recovered'] == 0
        assert result['failed'] == 1
        assert result['dns_ownership_failed'] == 0
        assert result['renewed'] == 0
        assert result['orphaned'] == 0
        mock_sync.assert_not_called()
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        metric_values = _metric_values(mock_cw)
        assert metric_values[cm.CW_METRIC_RENEWAL_SCAN_RUNS] == 1
        assert metric_values[cm.CW_METRIC_RENEWAL_ORPHANED_CERTS] == 0
        assert metric_values[cm.CW_METRIC_RENEWAL_PROCESSING_FAILURES] == 1
        assert metric_values[cm.CW_METRIC_RENEWAL_STATUS_RECOVERED] == 0
        _assert_renewal_metric_dimensions(mock_cw)
        mock_recover.assert_called_once()

    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_recovery_dns_resolution_fault_does_not_skip_due_renewal(
        self, mock_list, mock_cw, mock_provision, mock_sync, mock_verify_txt,
    ):
        del mock_cw
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        self.mock_get_item.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_FAILED},
                'verification_token': {'S': 'lv_verify_test_token'},
            }
        }
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/failed-due.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'failed-due--com',
                }),
            },
        ]
        mock_verify_txt.side_effect = cm.DnsOwnershipResolutionError('SERVFAIL')
        mock_provision.return_value = {'status': 'provisioned'}

        result = cm.renewal_scan()

        assert result['status_recovered'] == 0
        assert result['failed'] == 0
        assert result['renewed'] == 1
        mock_verify_txt.assert_called_once_with('failed-due.com', 'lv_verify_test_token')
        mock_provision.assert_called_once_with(
            'failed-due.com',
            'failed-due--com',
            skip_sync=True,
            emit_per_domain_signals=False,
            mark_failed_on_error=False,
            expected_verification_token='lv_verify_test_token',
        )
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch('custom_domain_cert_manager.recover_failed_domain_with_valid_cert')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_recovered_domain_still_attempts_due_renewal_and_records_aggregate_failure(
        self, mock_list, mock_cw, mock_recover, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/recovered.com/meta',
                'Value': json.dumps({
                    'expires_at': expiring,
                    'acme_subdomain': 'recovered--com',
                }),
            },
        ]
        mock_recover.return_value = True
        mock_provision.side_effect = Exception('kms throttle')

        result = cm.renewal_scan()

        assert result['status_recovered'] == 1
        assert result['failed'] == 1
        assert result['renewed'] == 0
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        metric_values = _metric_values(mock_cw)
        assert metric_values[cm.CW_METRIC_RENEWAL_STATUS_RECOVERED] == 1
        assert metric_values[cm.CW_METRIC_RENEWAL_PROCESSING_FAILURES] == 1
        _assert_renewal_metric_dimensions(mock_cw)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch('custom_domain_cert_manager.recover_failed_domain_with_valid_cert')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_recovered_domain_syncs_even_when_not_due_for_renewal(
        self, mock_list, mock_cw, mock_recover, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        mock_list.return_value = [
            {
                'Name': '/nhp/certs/recovered-valid.com/meta',
                'Value': json.dumps({
                    'expires_at': future,
                    'acme_subdomain': 'recovered-valid--com',
                }),
            },
        ]
        mock_recover.return_value = True

        result = cm.renewal_scan()

        assert result['status_recovered'] == 1
        assert result['renewed'] == 0
        assert result['skipped'] == 1
        mock_provision.assert_not_called()
        mock_sync.assert_called_once_with(cm.BATCH_SYNC_RENEWAL)
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        metric_values = _metric_values(mock_cw)
        assert metric_values[cm.CW_METRIC_RENEWAL_STATUS_RECOVERED] == 1
        _assert_renewal_metric_dimensions(mock_cw)

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_empty_scan(self, mock_list, mock_cw):
        """Should handle no certs gracefully."""
        mock_list.return_value = []

        result = cm.renewal_scan()
        assert result['scanned'] == 0
        assert result['renewed'] == 0
        assert _metric_values(mock_cw) == {
            cm.CW_METRIC_RENEWAL_SCAN_RUNS: 1,
            cm.CW_METRIC_RENEWAL_DNS_OWNERSHIP_FAILURES: 0,
            cm.CW_METRIC_RENEWAL_ORPHANED_CERTS: 0,
            cm.CW_METRIC_RENEWAL_PROCESSING_FAILURES: 0,
            cm.CW_METRIC_RENEWAL_STATUS_RECOVERED: 0,
        }
        _assert_renewal_metric_dimensions(mock_cw)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.provision_pending_domains')
    @patch('custom_domain_cert_manager.renewal_scan')
    def test_handler_raises_after_pending_when_scan_metrics_fail(
        self, mock_scan, mock_pending, mock_failure_metric, mock_alert,
    ):
        """Metric publish failure should trip only Lambda Errors after renewal work."""
        mock_scan.return_value = {
            'renewed': 1,
            'metric_publish_failed': True,
        }
        mock_pending.return_value = {'provisioned': 0, 'failed': 0}

        with pytest.raises(cm.RenewalScanMetricPublishError):
            cm.handler({'type': cm.EVENT_RENEWAL_SCAN}, None)

        mock_pending.assert_called_once()
        mock_alert.assert_not_called()
        mock_failure_metric.assert_not_called()

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.provision_pending_domains')
    @patch('custom_domain_cert_manager.renewal_scan')
    def test_handler_returns_after_pending_when_scan_metrics_succeed(
        self, mock_scan, mock_pending, mock_failure_metric, mock_alert,
    ):
        """Successful scan metric publish should not trip the Lambda Errors backstop."""
        mock_scan.return_value = {
            'renewed': 1,
            'metric_publish_failed': False,
        }
        mock_pending.return_value = {'provisioned': 1, 'failed': 0}

        result = cm.handler({'type': cm.EVENT_RENEWAL_SCAN}, None)

        assert result['renewed'] == 1
        assert result['metric_publish_failed'] is False
        assert result['pending'] == {'provisioned': 1, 'failed': 0}
        mock_pending.assert_called_once()
        mock_alert.assert_not_called()
        mock_failure_metric.assert_not_called()

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.provision_pending_domains')
    @patch('custom_domain_cert_manager.renewal_scan')
    def test_pending_error_takes_precedence_after_scan_metrics_fail(
        self, mock_scan, mock_pending, mock_failure_metric, mock_alert,
    ):
        """Pending work keeps its own invocation error even if scan metrics failed."""
        mock_scan.return_value = {
            'renewed': 1,
            'metric_publish_failed': True,
        }
        mock_pending.side_effect = RuntimeError('pending ddb throttle')

        with pytest.raises(RuntimeError, match='pending ddb throttle'):
            cm.handler({'type': cm.EVENT_RENEWAL_SCAN}, None)

        mock_pending.assert_called_once()
        mock_alert.assert_called_once_with('Custom domain cert manager FAILED: pending ddb throttle')
        mock_failure_metric.assert_called_once_with()


class TestCheckOrphanForMeta(unittest.TestCase):
    """Tests for check_orphan_for_meta() — Option B reconciliation helper."""

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_returns_none_when_table_not_configured(self, mock_get):
        original = cm.QURL_DOMAINS_TABLE
        cm.QURL_DOMAINS_TABLE = None
        try:
            assert cm.check_orphan_for_meta('any.com') is None
            mock_get.assert_not_called()
        finally:
            cm.QURL_DOMAINS_TABLE = original

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_returns_none_for_valid_managed_row(self, mock_get):
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_ACTIVE},
                'verification_token': {'S': 'lv_verify_abc'},
            }
        }
        assert cm.check_orphan_for_meta('managed.com') is None
        reason, item = cm._managed_domain_row_for_meta('managed.com')
        assert reason is None
        assert item == mock_get.return_value['Item']

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_orphan_when_row_missing(self, mock_get):
        # GetItem returns no Item key — row does not exist.
        mock_get.return_value = {}
        reason = cm.check_orphan_for_meta('orphan.com')
        assert reason is not None
        assert 'verification_token' in reason

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_orphan_when_projected_attribute_absent(self, mock_get):
        # Row exists but verification_token attribute is missing — the
        # post-incident partial-row shape from update_domain_status writes.
        mock_get.return_value = {'Item': {}}
        reason = cm.check_orphan_for_meta('partial.com')
        assert reason is not None

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_orphan_when_attribute_value_is_python_none_synthetic_guardrail(self, mock_get):
        # Synthetic shape: boto3 low-level client never returns a Python None
        # for an attribute value (it omits the key or returns a typed dict).
        # This locks in the defensive guard against that impossible shape so
        # an upstream boto3 change can't silently bypass orphan detection.
        mock_get.return_value = {'Item': {'verification_token': None}}
        reason = cm.check_orphan_for_meta('null.com')
        assert reason == 'verification_token attribute missing'

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_orphan_when_attribute_is_not_typed_dict_synthetic_guardrail(self, mock_get):
        # Synthetic shape: boto3 low-level client always wraps attribute values
        # in a typed dict ({'S': ...}, {'N': ...}, etc.). This covers the
        # `else ''` branch on the `isinstance(token_attr, dict)` guard so an
        # upstream boto3 change that returned a bare string would surface as
        # "verification_token empty" rather than a TypeError.
        mock_get.return_value = {'Item': {'verification_token': 'plain-string'}}
        reason = cm.check_orphan_for_meta('bare-string.com')
        assert reason == 'verification_token empty'

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_orphan_when_token_empty(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': ''}}}
        reason = cm.check_orphan_for_meta('empty.com')
        assert reason == 'verification_token empty'

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_returns_none_on_client_error_to_avoid_spurious_alerts(self, mock_get):
        # Transient DDB errors must NOT classify a domain as orphan —
        # that would page operators every 15 min during a DDB blip.
        mock_get.side_effect = ClientError(
            {'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 'throttled'}},
            'GetItem',
        )
        assert cm.check_orphan_for_meta('throttled.com') is None


class TestRenewalScanOrphanDetection(unittest.TestCase):
    """Tests for renewal_scan() Option B orphan detection branch."""

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_orphan_short_circuits_renewal(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Orphan detection runs BEFORE expiry check and prevents renewal."""
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {'Name': '/nhp/certs/orphan.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'orphan--com',
            })},
        ]
        # Row missing — orphan.
        mock_get.return_value = {}

        result = cm.renewal_scan()

        assert result['orphaned'] == 1
        assert result['renewed'] == 0
        assert result['scanned'] == 1
        # The expensive paths must NOT run for orphans.
        mock_provision.assert_not_called()
        mock_sync.assert_not_called()
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        assert _metric_values(mock_cw)[cm.CW_METRIC_RENEWAL_ORPHANED_CERTS] == 1
        _assert_renewal_metric_dimensions(mock_cw)

        detail = result['details'][0]
        assert detail['action'] == 'orphaned'
        assert detail['domain'] == 'orphan.com'

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_managed_domain_proceeds_to_renewal(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """A valid managed row should NOT trip orphan detection."""
        del mock_cw, mock_sync
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {'Name': '/nhp/certs/managed.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'managed--com',
            })},
        ]
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_managed'}}}
        mock_provision.return_value = {'status': cm.RESULT_PROVISIONED}

        result = cm.renewal_scan()

        assert result['orphaned'] == 0
        assert result['renewed'] == 1
        mock_provision.assert_called_once()
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_mixed_orphan_and_managed_domains(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Orphans and managed certs in the same scan are counted separately."""
        del mock_sync
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        not_expiring = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()
        mock_list.return_value = [
            {'Name': '/nhp/certs/orphan.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'orphan--com',
            })},
            {'Name': '/nhp/certs/expiring.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'expiring--com',
            })},
            {'Name': '/nhp/certs/healthy.com/meta', 'Value': json.dumps({
                'expires_at': not_expiring, 'acme_subdomain': 'healthy--com',
            })},
        ]

        def get_item_side_effect(**kwargs):
            key_domain = kwargs['Key']['domain']['S']
            if key_domain == 'orphan.com':
                return {}  # orphan
            return {'Item': {'verification_token': {'S': f'lv_verify_{key_domain}'}}}

        mock_get.side_effect = get_item_side_effect
        mock_provision.return_value = {'status': cm.RESULT_PROVISIONED}

        result = cm.renewal_scan()

        assert result['scanned'] == 3
        assert result['orphaned'] == 1
        assert result['renewed'] == 1   # expiring.com
        assert result['skipped'] == 1   # healthy.com (not in renewal window)
        mock_provision.assert_called_once()
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        assert _metric_values(mock_cw)[cm.CW_METRIC_RENEWAL_ORPHANED_CERTS] == 1
        _assert_renewal_metric_dimensions(mock_cw)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_multiple_orphans_emit_single_scan_metric(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Many orphans in one scan → one scan-level metric, no per-domain signals."""
        del mock_sync, mock_provision
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {'Name': f'/nhp/certs/orphan{i}.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': f'orphan{i}--com',
            })}
            for i in range(3)
        ]
        mock_get.return_value = {}  # all rows missing — all orphans

        result = cm.renewal_scan()

        assert result['orphaned'] == 3
        mock_failure_metric.assert_not_called()
        mock_alert.assert_not_called()
        assert _metric_values(mock_cw)[cm.CW_METRIC_RENEWAL_ORPHANED_CERTS] == 3
        _assert_renewal_metric_dimensions(mock_cw)


class TestTriggerCertSync(unittest.TestCase):
    """Tests for trigger_cert_sync() command injection hardening."""

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_single_domain_is_shell_quoted(self, mock_send):
        """Domain should be shell-quoted in the sync command."""
        mock_send.return_value = {'Command': {'CommandId': 'test-123'}}

        cm.trigger_cert_sync('example.com')

        cmd = mock_send.call_args.kwargs['Parameters']['commands'][1]
        assert '--domain' in cmd
        assert 'example.com' in cmd

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_batch_uses_full_sync(self, mock_send):
        """Batch triggers should use full sync (no --domain flag)."""
        mock_send.return_value = {'Command': {'CommandId': 'test-123'}}

        cm.trigger_cert_sync(cm.BATCH_SYNC_RENEWAL)

        cmd = mock_send.call_args.kwargs['Parameters']['commands'][1]
        assert '--domain' not in cmd

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_rejects_invalid_domain(self, mock_send):
        """Should not send command for domains with path traversal or injection."""
        cm.trigger_cert_sync('../../etc/passwd')
        mock_send.assert_not_called()

        cm.trigger_cert_sync('foo; rm -rf /')
        mock_send.assert_not_called()

    @patch.object(cm.ssm_client, 'send_command')
    def test_skips_when_no_tag(self, mock_send):
        """Should skip when AC_INSTANCE_TAG is not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('AC_INSTANCE_TAG', None)
            cm.trigger_cert_sync('example.com')
            mock_send.assert_not_called()

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_long_domain_comment_is_clamped(self, mock_send):
        """Regression guard at the SendCommand boundary: a long domain must
        reach AWS with the Comment clamped to the 100-char limit. TestSsmComment
        proves _ssm_comment() truncates; this proves trigger_cert_sync actually
        routes the Comment through it — an unwrapped Comment= would trip AWS's
        ValidationException and emit a spurious CertSyncError metric (#2300)."""
        mock_send.return_value = {'Command': {'CommandId': 'test-123'}}
        # Multi-label domain whose total length alone exceeds SSM_COMMENT_MAX,
        # so any unclamped Comment= overflows regardless of annotation text
        # (format-agnostic guard). Each label is well under the DNS 63-char
        # limit, so the fixture stays valid — and keeps reaching send_command —
        # even if DOMAIN_REGEX is ever tightened to enforce per-label length.
        long_domain = 'sub.' * 30 + 'customer.net'
        self.assertGreater(len(long_domain), cm.SSM_COMMENT_MAX)

        cm.trigger_cert_sync(long_domain)

        comment = mock_send.call_args.kwargs['Comment']
        assert len(comment) <= cm.SSM_COMMENT_MAX
        # Domain leads the annotation, so the surviving text is the domain head.
        assert long_domain.startswith(comment)


class TestTriggerCertDelete(unittest.TestCase):
    """Tests for trigger_cert_delete() — the per-domain incremental cleanup
    introduced in #1994. The full-mode-per-event behavior it replaces is
    covered by the TestHandleDomainCleanup assertions on the new helper.
    """

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_emits_delete_flag_with_shell_quoted_domain(self, mock_send):
        """The script invocation must include --delete and a shell-quoted
        domain. Without --delete the script runs the upsert path; without
        shlex.quote a malicious domain could inject shell. is_valid_domain
        is the first line of defense; this is the second."""
        mock_send.return_value = {'Command': {'CommandId': 'test-123'}}

        cm.trigger_cert_delete('example.com')

        cmd = mock_send.call_args.kwargs['Parameters']['commands'][1]
        assert '--delete' in cmd
        assert 'example.com' in cmd
        # Must NOT slip into the --domain (upsert) path.
        assert '--domain ' not in cmd

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_rejects_invalid_domain(self, mock_send):
        """Path traversal, shell injection, and wildcards must all be
        refused before SSM SendCommand is reached. Mirrors trigger_cert_sync
        — the cleanup handler validates upstream, but the AC script is on
        the hot path so we re-validate at the dispatch boundary."""
        cm.trigger_cert_delete('../../etc/passwd')
        mock_send.assert_not_called()

        cm.trigger_cert_delete('foo; rm -rf /')
        mock_send.assert_not_called()

        cm.trigger_cert_delete('*.example.com')
        mock_send.assert_not_called()

    @patch.object(cm.ssm_client, 'send_command')
    def test_skips_when_no_tag(self, mock_send):
        """Should skip when AC_INSTANCE_TAG is not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('AC_INSTANCE_TAG', None)
            cm.trigger_cert_delete('example.com')
            mock_send.assert_not_called()

    @patch.dict(os.environ, {'AC_INSTANCE_TAG': 'nhp-ac'})
    @patch.object(cm.ssm_client, 'send_command')
    def test_long_domain_comment_is_clamped(self, mock_send):
        """Same SendCommand-boundary guard as TestTriggerCertSync, for the
        delete path — the comment-overflow bug (#2300) tripped on cleanup
        domains, so the clamp wiring here is the one that actually regressed."""
        mock_send.return_value = {'Command': {'CommandId': 'test-123'}}
        # Multi-label long domain (see TestTriggerCertSync) — valid even under a
        # stricter per-label regex, so it always reaches send_command.
        long_domain = 'sub.' * 30 + 'customer.net'
        self.assertGreater(len(long_domain), cm.SSM_COMMENT_MAX)

        cm.trigger_cert_delete(long_domain)

        comment = mock_send.call_args.kwargs['Comment']
        assert len(comment) <= cm.SSM_COMMENT_MAX
        assert long_domain.startswith(comment)


class _StubDnsException(Exception):
    """Base for stubbed dnspython exceptions used in unit tests."""


class _StubNXDOMAIN(_StubDnsException):
    pass


class _StubNoAnswer(_StubDnsException):
    pass


class _StubTimeout(_StubDnsException):
    pass


def _install_dns_stubs():
    """Install minimal dns_resolver / dns_exception stubs on the cert manager.

    Mirrors the attributes that ``verify_dns_ownership`` actually touches
    (Resolver class plus the NXDOMAIN/NoAnswer exception classes on the
    resolver module, and Timeout/DNSException on dns.exception).
    """
    stub_resolver = MagicMock()
    stub_resolver.NXDOMAIN = _StubNXDOMAIN
    stub_resolver.NoAnswer = _StubNoAnswer

    stub_exception = MagicMock()
    stub_exception.Timeout = _StubTimeout
    stub_exception.DNSException = _StubDnsException

    cm.dns_resolver = stub_resolver
    cm.dns_exception = stub_exception
    return stub_resolver, stub_exception


def _reset_dns_stubs():
    cm.dns_resolver = None
    cm.dns_exception = None


class TestVerifyDnsOwnership(unittest.TestCase):
    """Tests for verify_dns_ownership() TOCTOU mitigation."""

    def tearDown(self):
        # Always reset module-level DNS stubs so a failing test doesn't bleed
        # into the next.
        _reset_dns_stubs()

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_skips_when_no_table(self, mock_get):
        original = cm.QURL_DOMAINS_TABLE
        cm.QURL_DOMAINS_TABLE = None
        try:
            cm.verify_dns_ownership('example.com')
            mock_get.assert_not_called()
        finally:
            cm.QURL_DOMAINS_TABLE = original

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_domain_not_in_dynamodb(self, mock_get):
        mock_get.return_value = {}
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('missing.com')
        assert 'not found in DynamoDB' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_verification_token_is_empty(self, mock_get):
        # Attribute exists but the string is empty — stronger signal of
        # active tampering than a missing attribute. Distinct error
        # message so operators get the right incident-response path.
        mock_get.return_value = {'Item': {'verification_token': {'S': ''}}}
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('no-token.com')
        msg = str(ctx.exception)
        assert 'empty' in msg
        assert 'tampering' in msg

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_verification_token_attr_missing(self, mock_get):
        # Item exists (domain key is always returned) but the projected
        # verification_token attribute is absent — e.g. a legacy row written
        # before the column existed, or a corrupted state. Distinct error
        # message from the empty-string case.
        mock_get.return_value = {'Item': {'domain': {'S': 'legacy.com'}}}
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('legacy.com')
        msg = str(ctx.exception)
        assert 'attribute missing' in msg
        assert 'legacy' in msg or 'corrupted' in msg

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_dynamodb_fails_with_client_error(self, mock_get):
        mock_get.side_effect = ClientError(
            {'Error': {'Code': 'InternalServerError', 'Message': 'boom'}},
            'GetItem',
        )
        with self.assertRaises(cm.DnsOwnershipResolutionError) as ctx:
            cm.verify_dns_ownership('example.com')
        msg = str(ctx.exception)
        assert 'Failed to fetch' in msg
        # AWS error code is surfaced for operators but the raw exception
        # repr is NOT included in the customer-visible failure_reason.
        assert 'InternalServerError' in msg
        assert 'boom' not in msg

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_dynamodb_unexpected_exception_propagates(self, mock_get):
        # Non-ClientError exceptions (e.g. unexpected botocore bug) should
        # propagate so the caller's broader handler can publish the right
        # metric — they are NOT silently re-wrapped as DnsOwnershipError.
        mock_get.side_effect = RuntimeError("unexpected")
        with self.assertRaises(RuntimeError):
            cm.verify_dns_ownership('example.com')

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_nxdomain_with_specific_message(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()
        stub_resolver.Resolver.return_value.resolve.side_effect = _StubNXDOMAIN()
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('no-txt.com')
        msg = str(ctx.exception)
        assert 'NXDOMAIN' in msg
        assert 'does not exist' in msg

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_no_answer_with_specific_message(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()
        stub_resolver.Resolver.return_value.resolve.side_effect = _StubNoAnswer()
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('no-answer.com')
        assert 'no TXT records' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_timeout_with_specific_message(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()
        stub_resolver.Resolver.return_value.resolve.side_effect = _StubTimeout()
        with self.assertRaises(cm.DnsOwnershipResolutionError) as ctx:
            cm.verify_dns_ownership('slow.com')
        assert 'timed out' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_generic_dns_exception(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()

        class _NoNameservers(_StubDnsException):
            pass

        stub_resolver.Resolver.return_value.resolve.side_effect = _NoNameservers()
        with self.assertRaises(cm.DnsOwnershipResolutionError) as ctx:
            cm.verify_dns_ownership('broken.com')
        assert 'could not resolve' in str(ctx.exception)
        # Type name surfaces but raw exception args do not.
        assert '_NoNameservers' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_txt_mismatch(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_expected'}}}
        stub_resolver, _ = _install_dns_stubs()
        mock_rdata = MagicMock()
        mock_rdata.strings = (b'lv_verify_wrong',)
        stub_resolver.Resolver.return_value.resolve.return_value = [mock_rdata]
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('mismatch.com')
        assert 'does not match' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_passes_when_txt_matches(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()
        mock_rdata = MagicMock()
        mock_rdata.strings = (b'lv_verify_abc123',)
        stub_resolver.Resolver.return_value.resolve.return_value = [mock_rdata]
        cm.verify_dns_ownership('good.com')

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_passes_with_preloaded_token_without_dynamodb_read(self, mock_get):
        stub_resolver, _ = _install_dns_stubs()
        mock_rdata = MagicMock()
        mock_rdata.strings = (b'lv_verify_preloaded',)
        stub_resolver.Resolver.return_value.resolve.return_value = [mock_rdata]

        cm.verify_dns_ownership('good.com', 'lv_verify_preloaded')

        mock_get.assert_not_called()

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_passes_with_multistring_txt(self, mock_get):
        # RFC 7208 / RFC 1035: TXT can contain multiple character-strings
        # that must be concatenated without separators.
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_concatenated'}}}
        stub_resolver, _ = _install_dns_stubs()
        mock_rdata = MagicMock()
        mock_rdata.strings = (b'lv_verify_', b'concatenated')
        stub_resolver.Resolver.return_value.resolve.return_value = [mock_rdata]
        cm.verify_dns_ownership('multi.com')

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_matches_among_multiple_txt_records(self, mock_get):
        # If multiple TXT records exist on the name, only one needs to match.
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_target'}}}
        stub_resolver, _ = _install_dns_stubs()
        wrong = MagicMock()
        wrong.strings = (b'something-else',)
        right = MagicMock()
        right.strings = (b'lv_verify_target',)
        stub_resolver.Resolver.return_value.resolve.return_value = [wrong, right]
        cm.verify_dns_ownership('multirec.com')

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_immediate_ownership_failure_publishes_per_domain_signals(
        self, mock_get, mock_status, mock_alert, mock_metric, mock_lock, mock_release
    ):
        del mock_status, mock_lock  # @patch suppresses side effects only
        mock_get.return_value = {}
        with self.assertRaises(cm.DnsOwnershipError):
            cm.provision_certificate("missing.com", "missing--com")
        mock_alert.assert_called_once()
        assert "missing.com" in mock_alert.call_args.args[0]
        mock_metric.assert_called_once_with(cm.FAILURE_DNS_OWNERSHIP)
        mock_release.assert_called_once_with("missing.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_ownership_failure_not_double_counted_in_handler(
        self, mock_get, mock_status, mock_alert, mock_metric, mock_lock, mock_release
    ):
        del mock_status, mock_alert, mock_lock, mock_release  # @patch suppresses side effects only
        mock_get.return_value = {}
        with self.assertRaises(cm.DnsOwnershipError):
            cm.handler({'type': 'provision', 'domain': 'missing.com', 'acme_subdomain': 'missing--com'}, None)
        mock_metric.assert_called_once_with(cm.FAILURE_DNS_OWNERSHIP)

    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_success_does_not_publish_failure_metric(self, mock_get, mock_metric):
        """Success path must NOT publish FAILURE_DNS_OWNERSHIP. Guards against
        accidental metric drift where a future refactor adds an unconditional
        publish before the success return."""
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc'}}}
        stub_resolver, _ = _install_dns_stubs()
        mock_rdata = MagicMock()
        mock_rdata.strings = (b'lv_verify_abc',)
        stub_resolver.Resolver.return_value.resolve.return_value = [mock_rdata]
        cm.verify_dns_ownership('good.com')
        mock_metric.assert_not_called()

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_when_resolver_returns_empty_list(self, mock_get):
        """dnspython usually raises NoAnswer for an empty rrset, but the
        contract on resolve() does not strictly guarantee it. Make sure the
        empty-list path produces an explicit operator-friendly message rather
        than 'Found: []'."""
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc'}}}
        stub_resolver, _ = _install_dns_stubs()
        # Resolver returns an iterable with zero rdata items. Bind __iter__
        # via MagicMock.return_value so we don't need a lambda with an
        # unused `self` parameter that static analyzers flag.
        empty_answers = MagicMock()
        empty_answers.__iter__.return_value = iter([])
        empty_answers.rrset = None
        stub_resolver.Resolver.return_value.resolve.return_value = empty_answers
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('empty.com')
        msg = str(ctx.exception)
        assert 'no TXT values returned' in msg
        # The default unspecific message must NOT be used here.
        assert 'Found: []' not in msg


class TestTxtRdataToString(unittest.TestCase):
    """Tests for _txt_rdata_to_string TXT decoding helper."""

    def test_single_string(self):
        rdata = MagicMock()
        rdata.strings = (b'lv_verify_abc',)
        assert cm._txt_rdata_to_string(rdata) == 'lv_verify_abc'

    def test_multistring_concatenates_without_separator(self):
        rdata = MagicMock()
        rdata.strings = (b'foo', b'bar', b'baz')
        assert cm._txt_rdata_to_string(rdata) == 'foobarbaz'

    def test_falls_back_to_str_when_no_strings_attr(self):
        # Plain object with __str__ returning quoted form. Used as a safety
        # net for any rdata-like object that doesn't expose .strings.
        class _LegacyRdata:
            def __str__(self):
                return '"legacy"'

        assert cm._txt_rdata_to_string(_LegacyRdata()) == 'legacy'

    def test_handles_invalid_utf8(self):
        rdata = MagicMock()
        rdata.strings = (b'\xff\xfe', b'invalid')
        # Should not raise; replace bad bytes
        result = cm._txt_rdata_to_string(rdata)
        assert 'invalid' in result
        # The Python codec contract guarantees U+FFFD is the replacement
        # character used by errors='replace'.
        assert '\ufffd' in result

    def test_warns_on_replacement_character(self):
        """Operators should see a WARNING when a TXT record contains
        invalid UTF-8 — that's almost always a customer copy-paste error
        and being able to point at it from logs saves a support round."""
        rdata = MagicMock()
        rdata.strings = (b'\xff\xfe', b'_v=test')
        # The lambda logs to the root logger (Lambda runtime convention)
        # so assertLogs has to target the root logger to catch it.
        with self.assertLogs(level='WARNING') as logs:
            cm._txt_rdata_to_string(rdata)
        joined = '\n'.join(logs.output)
        assert 'invalid UTF-8' in joined
        assert 'replacement characters' in joined

    def test_no_warning_on_clean_utf8(self):
        """Clean ASCII TXT records must NOT trigger the replacement
        warning — the warning is only for genuinely-broken records."""
        rdata = MagicMock()
        rdata.strings = (b'lv_verify_clean_token',)
        # The lambda logs to the root logger; assertNoLogs (Python 3.10+)
        # against the root logger catches any warning anywhere.
        with self.assertNoLogs(level='WARNING'):
            cm._txt_rdata_to_string(rdata)


class TestFailureCategoryMetrics(unittest.TestCase):
    """Tests for per-category failure metric routing."""

    def _mock_cryptography(self):
        """Return a mock cryptography dict that satisfies provision_certificate."""
        mock_key = MagicMock()
        mock_key.private_bytes.return_value = b'key-pem'
        mock_rsa = MagicMock()
        mock_rsa.generate_private_key.return_value = mock_key
        mock_x509 = MagicMock()
        mock_x509.load_pem_x509_certificate.return_value = MagicMock(
            not_valid_after_utc=MagicMock(isoformat=MagicMock(return_value='2026-06-01T00:00:00+00:00'))
        )
        return {
            'rsa': mock_rsa,
            'default_backend': MagicMock(),
            'serialization': MagicMock(
                Encoding=MagicMock(PEM='PEM'),
                PrivateFormat=MagicMock(TraditionalOpenSSL='PKCS1'),
                NoEncryption=MagicMock(),
            ),
            'x509': mock_x509,
            'hashes': MagicMock(),
        }

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.request_certificate')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_dns_validation_failure_publishes_correct_category(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_request, mock_status, mock_alert, mock_metric, mock_release
    ):
        """DNS validation failures should publish FAILURE_DNS_VALIDATION exactly once."""
        del mock_verify, mock_import, mock_lock, mock_acme, mock_status, mock_alert  # @patch suppresses side effects only
        mock_request.side_effect = cm.DnsValidationError("TXT record not found")

        with patch.object(cm, 'cryptography', self._mock_cryptography()):
            with self.assertRaises(cm.DnsValidationError):
                cm.provision_certificate("example.com", "example--com")

        mock_metric.assert_called_once_with(cm.FAILURE_DNS_VALIDATION)
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_acme_account_failure_publishes_correct_category(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_status, mock_alert, mock_metric, mock_release
    ):
        """ACME account failures should publish FAILURE_ACME_ACCOUNT."""
        del mock_verify, mock_import, mock_lock, mock_status, mock_alert  # @patch suppresses side effects only
        mock_acme.side_effect = Exception("ACME account error")

        with self.assertRaises(Exception):
            cm.provision_certificate("example.com", "example--com")

        mock_metric.assert_called_once_with(cm.FAILURE_ACME_ACCOUNT)
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.store_certificate')
    @patch('custom_domain_cert_manager.request_certificate')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_cert_storage_failure_publishes_correct_category(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_request, mock_store, mock_status, mock_alert, mock_metric, mock_release
    ):
        """Certificate storage failures should publish FAILURE_CERT_STORAGE."""
        del mock_verify, mock_import, mock_lock, mock_acme, mock_status, mock_alert  # @patch suppresses side effects only
        mock_request.return_value = ('cert-pem', 'chain-pem')
        mock_store.side_effect = Exception("SSM write failed")

        with patch.object(cm, 'cryptography', self._mock_cryptography()):
            with self.assertRaises(Exception):
                cm.provision_certificate("example.com", "example--com")

        mock_metric.assert_called_once_with(cm.FAILURE_CERT_STORAGE)
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.record_domain_renewal_failure')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.request_certificate')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_renewal_acme_failure_preserves_active_status(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_request,
        mock_status, mock_alert, mock_metric, mock_record, mock_release,
    ):
        """Renewal ACME failures must not mark an otherwise-valid domain failed."""
        del mock_verify, mock_import, mock_lock, mock_acme  # @patch suppresses side effects only
        mock_request.side_effect = Exception("rateLimited: duplicate certificate limit")

        with patch.object(cm, 'cryptography', self._mock_cryptography()):
            with self.assertRaises(Exception):
                cm.provision_certificate(
                    "example.com",
                    "example--com",
                    emit_per_domain_signals=False,
                    mark_failed_on_error=False,
                )

        mock_status.assert_not_called()
        mock_record.assert_called_once_with("example.com", "rateLimited: duplicate certificate limit")
        mock_alert.assert_not_called()
        mock_metric.assert_not_called()
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.record_domain_renewal_failure')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.request_certificate')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_renewal_dns_validation_failure_preserves_active_status(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_request,
        mock_status, mock_alert, mock_metric, mock_record, mock_release,
    ):
        """Renewal DNS-01 validation faults are operational, not a reason to demote status."""
        del mock_verify, mock_import, mock_lock, mock_acme  # @patch suppresses side effects only
        mock_request.side_effect = cm.DnsValidationError("TXT record not found")

        with patch.object(cm, 'cryptography', self._mock_cryptography()):
            with self.assertRaises(cm.DnsValidationError):
                cm.provision_certificate(
                    "example.com",
                    "example--com",
                    emit_per_domain_signals=False,
                    mark_failed_on_error=False,
                )

        mock_status.assert_not_called()
        mock_record.assert_called_once_with("example.com", "TXT record not found")
        mock_alert.assert_not_called()
        mock_metric.assert_not_called()
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.record_domain_renewal_failure')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_renewal_dns_resolution_failure_preserves_active_status(
        self, mock_verify, mock_lock, mock_status, mock_alert, mock_metric,
        mock_record, mock_release,
    ):
        """Resolver outages during renewal are operational faults, not ownership drift."""
        del mock_lock
        mock_verify.side_effect = cm.DnsOwnershipResolutionError("SERVFAIL")

        with self.assertRaises(cm.DnsOwnershipResolutionError):
            cm.provision_certificate(
                "example.com",
                "example--com",
                emit_per_domain_signals=False,
                mark_failed_on_error=False,
            )

        mock_status.assert_not_called()
        mock_record.assert_called_once_with("example.com", "SERVFAIL")
        mock_alert.assert_not_called()
        mock_metric.assert_not_called()
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.record_domain_renewal_failure')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_renewal_dns_ownership_failure_still_marks_failed(
        self, mock_verify, mock_lock, mock_status, mock_alert, mock_metric,
        mock_record, mock_release,
    ):
        """Ownership drift is security-relevant, so renewal mode still fails closed."""
        del mock_lock  # @patch suppresses side effects only
        mock_verify.side_effect = cm.DnsOwnershipError("TXT mismatch")

        with self.assertRaises(cm.DnsOwnershipError):
            cm.provision_certificate(
                "example.com",
                "example--com",
                emit_per_domain_signals=False,
                mark_failed_on_error=False,
            )

        mock_status.assert_called_once_with("example.com", cm.STATUS_FAILED, error="TXT mismatch")
        mock_record.assert_not_called()
        mock_alert.assert_not_called()
        mock_metric.assert_not_called()
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'query')
    def test_dynamodb_failure_in_provision_pending_publishes_metric(
        self, mock_query, mock_metric
    ):
        """DynamoDB errors in provision_pending_domains should publish FAILURE_DYNAMODB."""
        mock_query.side_effect = Exception("DynamoDB timeout")

        result = cm.provision_pending_domains()
        assert 'error' in result
        mock_metric.assert_called_once_with(cm.FAILURE_DYNAMODB)

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_early_failure_publishes_acme_account_category(
        self, mock_verify, mock_import, mock_lock, mock_status, mock_alert, mock_metric, mock_release
    ):
        """Failures before first category reassignment default to FAILURE_ACME_ACCOUNT."""
        del mock_verify, mock_lock, mock_status, mock_alert  # @patch suppresses side effects only
        mock_import.side_effect = Exception("import failed")

        with self.assertRaises(Exception):
            cm.provision_certificate("example.com", "example--com")

        mock_metric.assert_called_once_with(cm.FAILURE_ACME_ACCOUNT)
        mock_release.assert_called_once_with("example.com")

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager.publish_failure_metric')
    @patch('custom_domain_cert_manager.send_alert')
    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.request_certificate')
    @patch('custom_domain_cert_manager.get_or_create_acme_account')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=True)
    @patch('custom_domain_cert_manager.lazy_import_acme')
    @patch('custom_domain_cert_manager.verify_dns_ownership')
    def test_dns_validation_not_double_counted_in_handler(
        self, mock_verify, mock_import, mock_lock, mock_acme, mock_request, mock_status, mock_alert, mock_metric, mock_release
    ):
        """DnsValidationError should not cause double metric publishing through handler."""
        del mock_verify, mock_import, mock_lock, mock_acme, mock_status, mock_alert, mock_release  # @patch suppresses side effects only
        mock_request.side_effect = cm.DnsValidationError("TXT record not found")

        with patch.object(cm, 'cryptography', self._mock_cryptography()):
            with self.assertRaises(cm.DnsValidationError):
                cm.handler({'type': 'provision', 'domain': 'example.com', 'acme_subdomain': 'example--com'}, None)

        # Should be called exactly once (in provision_certificate), not twice
        mock_metric.assert_called_once_with(cm.FAILURE_DNS_VALIDATION)


class TestRenewalFailureDiagnostics(unittest.TestCase):
    """Tests for recording renewal failures without changing domain status."""

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_records_renewal_failure_without_status_update(self, mock_update):
        cm.record_domain_renewal_failure('example.com', 'rateLimited' * 100)

        kw = mock_update.call_args.kwargs
        assert kw['TableName'] == cm.QURL_DOMAINS_TABLE
        assert kw['Key'] == {'domain': {'S': 'example.com'}}
        assert kw['ConditionExpression'] == 'attribute_exists(#d)'
        assert kw['ExpressionAttributeNames']['#d'] == 'domain'
        assert '#s' not in kw['ExpressionAttributeNames']
        assert 'status' not in kw['ExpressionAttributeNames'].values()
        assert cm.FIELD_LAST_RENEWAL_FAILED_AT in kw['ExpressionAttributeNames'].values()
        assert cm.FIELD_LAST_RENEWAL_FAILURE_REASON in kw['ExpressionAttributeNames'].values()
        assert len(kw['ExpressionAttributeValues'][':reason']['S']) == 500

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_renewal_failure_diagnostics_skip_deleted_rows(self, mock_update):
        mock_update.side_effect = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': ''}},
            'UpdateItem',
        )

        with patch.object(cm, 'logger') as mock_logger:
            cm.record_domain_renewal_failure('example.com', 'rateLimited')

        mock_logger.info.assert_called_once()
        mock_logger.error.assert_not_called()

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_active_status_clears_stale_failure_reason(self, mock_update):
        cm.update_domain_status(
            'example.com',
            cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/example.com',
            cert_expires_at='2026-07-20T21:02:09+00:00',
        )

        kw = mock_update.call_args.kwargs
        assert '#err' in kw['ExpressionAttributeNames']
        assert kw['ExpressionAttributeNames']['#err'] == 'failure_reason'
        assert kw['ExpressionAttributeNames']['#lrfa'] == cm.FIELD_LAST_RENEWAL_FAILED_AT
        assert kw['ExpressionAttributeNames']['#lrfr'] == cm.FIELD_LAST_RENEWAL_FAILURE_REASON
        assert 'REMOVE' in kw['UpdateExpression']
        assert '#err' in kw['UpdateExpression']
        assert '#lrfa' in kw['UpdateExpression']
        assert '#lrfr' in kw['UpdateExpression']

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_active_status_can_be_conditioned_on_failed_status(self, mock_update):
        updated = cm.update_domain_status(
            'example.com',
            cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/example.com',
            cert_expires_at='2026-07-20T21:02:09+00:00',
            expected_status=cm.STATUS_FAILED,
        )

        assert updated is True
        kw = mock_update.call_args.kwargs
        assert kw['ConditionExpression'] == '#s = :expected_status'
        assert kw['ExpressionAttributeNames']['#s'] == 'status'
        assert kw['ExpressionAttributeValues'][':expected_status'] == {'S': cm.STATUS_FAILED}

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_active_status_can_preserve_original_activation_time(self, mock_update):
        updated = cm.update_domain_status(
            'example.com',
            cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/example.com',
            cert_expires_at='2026-07-20T21:02:09+00:00',
            set_activated_at=False,
        )

        assert updated is True
        kw = mock_update.call_args.kwargs
        assert '#aa' not in kw['ExpressionAttributeNames']
        assert ':activated_at' not in kw['ExpressionAttributeValues']
        assert 'activated_at' not in kw['UpdateExpression']

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_update_domain_status_returns_false_on_conditional_race(self, mock_update):
        mock_update.side_effect = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': ''}},
            'UpdateItem',
        )

        with patch.object(cm, 'logger') as mock_logger:
            updated = cm.update_domain_status(
                'example.com',
                cm.STATUS_ACTIVE,
                cert_param_prefix='/nhp/certs/example.com',
                cert_expires_at='2026-07-20T21:02:09+00:00',
                expected_status=cm.STATUS_FAILED,
            )

        assert updated is False
        mock_logger.info.assert_called_once()
        mock_logger.error.assert_not_called()


class TestFailedDomainRecovery(unittest.TestCase):
    """Tests for recovering failed rows that still have valid cert material."""

    @patch.object(cm.ssm_client, 'get_parameter')
    def test_cert_material_exists_checks_key_and_chain_without_decryption(self, mock_get):
        mock_get.return_value = {'Parameter': {'Name': 'present'}}

        assert cm.cert_material_exists('example.com') is True

        assert mock_get.call_args_list == [
            call(Name='/nhp/certs/example.com/key', WithDecryption=False),
            call(Name='/nhp/certs/example.com/chain', WithDecryption=False),
        ]

    @patch.object(cm.ssm_client, 'get_parameter')
    def test_cert_material_exists_returns_false_when_key_or_chain_missing(self, mock_get):
        mock_get.side_effect = ClientError(
            {'Error': {'Code': 'ParameterNotFound', 'Message': 'missing'}},
            'GetParameter',
        )

        assert cm.cert_material_exists('example.com') is False

    @patch.object(cm.ssm_client, 'get_parameter')
    def test_cert_material_exists_returns_false_on_non_client_ssm_error(self, mock_get):
        mock_get.side_effect = RuntimeError('network unavailable')

        assert cm.cert_material_exists('example.com') is False

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.cert_material_exists')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_recovers_failed_row_with_valid_cert_and_dns_ownership(
        self, mock_get, mock_verify_txt, mock_material_exists, mock_status,
    ):
        mock_material_exists.return_value = True
        mock_status.return_value = True
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        expires_at_str = expires_at.isoformat()
        domain_item = {
            'status': {'S': cm.STATUS_FAILED},
            'verification_token': {'S': 'lv_verify_test'},
        }

        recovered = cm.recover_failed_domain_with_valid_cert(
            'example.com',
            expires_at,
            expires_at_str,
            datetime.now(timezone.utc),
            domain_item,
        )

        assert recovered is True
        mock_get.assert_not_called()
        mock_verify_txt.assert_called_once_with('example.com', 'lv_verify_test')
        mock_material_exists.assert_called_once_with('example.com')
        mock_status.assert_called_once_with(
            'example.com',
            cm.STATUS_ACTIVE,
            cert_param_prefix='/nhp/certs/example.com',
            cert_expires_at=expires_at_str,
            expected_status=cm.STATUS_FAILED,
            set_activated_at=False,
        )

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_does_not_recover_failed_row_when_dns_ownership_fails(
        self, mock_get, mock_verify_txt, mock_status,
    ):
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_FAILED},
                'verification_token': {'S': 'lv_verify_test'},
            }
        }
        mock_verify_txt.side_effect = cm.DnsOwnershipError('TXT mismatch')

        recovered = cm.recover_failed_domain_with_valid_cert(
            'example.com',
            expires_at,
            expires_at.isoformat(),
            datetime.now(timezone.utc),
        )

        assert recovered is False
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.cert_material_exists')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_does_not_raise_when_recovery_dns_resolution_is_unavailable(
        self, mock_get, mock_verify_txt, mock_material_exists, mock_status,
    ):
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_FAILED},
                'verification_token': {'S': 'lv_verify_test'},
            }
        }
        mock_verify_txt.side_effect = cm.DnsOwnershipResolutionError('SERVFAIL')

        recovered = cm.recover_failed_domain_with_valid_cert(
            'example.com',
            expires_at,
            expires_at.isoformat(),
            datetime.now(timezone.utc),
        )

        assert recovered is False
        mock_verify_txt.assert_called_once_with('example.com', 'lv_verify_test')
        mock_material_exists.assert_not_called()
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_does_not_recover_non_failed_or_expired_rows(
        self, mock_get, mock_verify_txt, mock_status,
    ):
        mock_get.return_value = {'Item': {'status': {'S': cm.STATUS_ACTIVE}}}
        future = datetime.now(timezone.utc) + timedelta(days=10)
        expired = datetime.now(timezone.utc) - timedelta(minutes=1)

        assert cm.recover_failed_domain_with_valid_cert(
            'example.com', future, future.isoformat(), datetime.now(timezone.utc)) is False
        assert cm.recover_failed_domain_with_valid_cert(
            'example.com', expired, expired.isoformat(), datetime.now(timezone.utc)) is False
        mock_verify_txt.assert_not_called()
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.cert_material_exists')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_does_not_recover_failed_row_when_cert_material_is_missing(
        self, mock_get, mock_verify_txt, mock_material_exists, mock_status,
    ):
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_FAILED},
                'verification_token': {'S': 'lv_verify_test'},
            }
        }
        mock_material_exists.return_value = False

        recovered = cm.recover_failed_domain_with_valid_cert(
            'example.com',
            expires_at,
            expires_at.isoformat(),
            datetime.now(timezone.utc),
        )

        assert recovered is False
        mock_verify_txt.assert_called_once_with('example.com', 'lv_verify_test')
        mock_status.assert_not_called()

    @patch('custom_domain_cert_manager.update_domain_status')
    @patch('custom_domain_cert_manager.cert_material_exists')
    @patch('custom_domain_cert_manager._verify_dns_ownership_txt')
    @patch.object(cm.dynamodb_client, 'get_item')
    def test_does_not_report_recovered_when_status_write_loses_race(
        self, mock_get, mock_verify_txt, mock_material_exists, mock_status,
    ):
        expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        mock_get.return_value = {
            'Item': {
                'status': {'S': cm.STATUS_FAILED},
                'verification_token': {'S': 'lv_verify_test'},
            }
        }
        mock_material_exists.return_value = True
        mock_status.return_value = False

        recovered = cm.recover_failed_domain_with_valid_cert(
            'example.com',
            expires_at,
            expires_at.isoformat(),
            datetime.now(timezone.utc),
        )

        assert recovered is False
        mock_verify_txt.assert_called_once_with('example.com', 'lv_verify_test')
        mock_material_exists.assert_called_once_with('example.com')


class TestProvisioningIdempotencyLock(unittest.TestCase):
    """Tests for _acquire_provisioning_lock() and _release_provisioning_lock()."""

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_acquire_lock_succeeds_first_time(self, mock_update):
        mock_update.return_value = {}
        result = cm._acquire_provisioning_lock('example.com')
        assert result is True
        kw = mock_update.call_args.kwargs
        assert 'attribute_not_exists(provisioning_started_at)' in kw['ConditionExpression']

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_acquire_lock_fails_when_held(self, mock_update):
        mock_update.side_effect = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': ''}}, 'UpdateItem')
        assert cm._acquire_provisioning_lock('example.com') is False

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_acquire_lock_propagates_unexpected_errors(self, mock_update):
        mock_update.side_effect = ClientError(
            {'Error': {'Code': 'InternalServerError', 'Message': ''}}, 'UpdateItem')
        with self.assertRaises(ClientError):
            cm._acquire_provisioning_lock('example.com')

    def test_acquire_lock_skips_when_no_table(self):
        orig = cm.QURL_DOMAINS_TABLE
        cm.QURL_DOMAINS_TABLE = None
        try:
            assert cm._acquire_provisioning_lock('example.com') is True
        finally:
            cm.QURL_DOMAINS_TABLE = orig

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_acquire_lock_stale_threshold(self, mock_update):
        mock_update.return_value = {}
        cm._acquire_provisioning_lock('example.com')
        kw = mock_update.call_args.kwargs
        now_dt = datetime.fromisoformat(kw['ExpressionAttributeValues'][':now']['S'])
        stale_dt = datetime.fromisoformat(kw['ExpressionAttributeValues'][':stale']['S'])
        assert abs((now_dt - stale_dt).total_seconds() - 1800) < 2

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_release_lock_removes_attribute(self, mock_update):
        mock_update.return_value = {}
        cm._release_provisioning_lock('example.com')
        assert mock_update.call_args.kwargs['UpdateExpression'] == 'REMOVE provisioning_started_at'

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_release_lock_is_best_effort(self, mock_update):
        mock_update.side_effect = Exception("fail")
        cm._release_provisioning_lock('example.com')  # Should not raise

    def test_release_lock_skips_when_no_table(self):
        orig = cm.QURL_DOMAINS_TABLE
        cm.QURL_DOMAINS_TABLE = None
        try:
            cm._release_provisioning_lock('example.com')
        finally:
            cm.QURL_DOMAINS_TABLE = orig

    @patch('custom_domain_cert_manager._release_provisioning_lock')
    @patch('custom_domain_cert_manager._acquire_provisioning_lock', return_value=False)
    def test_provision_skips_when_lock_held(self, mock_acquire, mock_release):
        del mock_acquire  # @patch return_value=False is the only contract needed
        result = cm.provision_certificate('example.com', 'example--com')
        assert result['status'] == cm.RESULT_SKIPPED
        assert 'concurrent' in result['reason']
        mock_release.assert_not_called()

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_pending_does_not_count_skipped(self, mock_query, mock_provision, mock_sync):
        del mock_sync  # @patch suppresses real cert sync; not asserted here
        mock_query.return_value = {'Items': [{'domain': {'S': 'a.com'}}, {'domain': {'S': 'b.com'}}]}
        mock_provision.side_effect = [
            {'status': cm.RESULT_SKIPPED, 'domain': 'a.com', 'reason': 'concurrent'},
            {'status': cm.RESULT_PROVISIONED, 'domain': 'b.com'},
        ]
        result = cm.provision_pending_domains()
        assert result['provisioned'] == 1
        assert result['failed'] == 0
        assert result['skipped'] == 1


class TestRenewalScanSkipped(unittest.TestCase):
    """Tests for renewal_scan() handling of RESULT_SKIPPED."""

    def setUp(self):
        # See TestRenewalScan.setUp for why the orphan-check GetItem needs a
        # default valid-row mock.
        self._get_item_patcher = patch.object(cm.dynamodb_client, 'get_item')
        self.mock_get_item = self._get_item_patcher.start()
        self.mock_get_item.return_value = {
            'Item': {'verification_token': {'S': 'lv_verify_test_token'}}
        }

    def tearDown(self):
        self._get_item_patcher.stop()

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_renewal_scan_does_not_count_skipped_as_renewed(
        self, mock_list, mock_cw, mock_provision, mock_sync
    ):
        """Domains skipped due to lock should not inflate the renewed count."""
        del mock_sync, mock_cw  # @patch suppresses side effects only
        expiring = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        mock_list.return_value = [
            {'Name': '/nhp/certs/a.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'a--com',
            })},
            {'Name': '/nhp/certs/b.com/meta', 'Value': json.dumps({
                'expires_at': expiring, 'acme_subdomain': 'b--com',
            })},
        ]
        mock_provision.side_effect = [
            {'status': cm.RESULT_SKIPPED, 'domain': 'a.com', 'reason': 'concurrent'},
            {'status': cm.RESULT_PROVISIONED, 'domain': 'b.com'},
        ]

        result = cm.renewal_scan()
        assert result['renewed'] == 1
        assert result['skipped'] >= 1  # At least 1 skipped due to lock


class TestStaleLockRecovery(unittest.TestCase):
    """Integration-style test: simulates a Lambda crash leaving a stale lock,
    then verifies a subsequent invocation can acquire the lock after the
    stale threshold expires."""

    @patch.object(cm.dynamodb_client, 'update_item')
    def test_stale_lock_allows_new_invocation(self, mock_update):
        """First call acquires lock. Second call fails (lock held).
        Third call succeeds because the lock timestamp is beyond the stale threshold."""

        call_count = 0
        captured_values = []

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            captured_values.append(kwargs.get('ExpressionAttributeValues', {}))

            if call_count == 1:
                # First invocation: lock acquired
                return {}
            elif call_count == 2:
                # Second invocation: lock still held (not stale yet)
                raise ClientError(
                    {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': ''}},
                    'UpdateItem',
                )
            else:
                # Third invocation: lock is stale, DynamoDB allows the conditional write
                return {}

        mock_update.side_effect = side_effect

        # Invocation 1: acquires the lock
        assert cm._acquire_provisioning_lock('example.com') is True

        # Invocation 2: lock is held by invocation 1 (simulated crash — no release)
        assert cm._acquire_provisioning_lock('example.com') is False

        # Invocation 3: lock is now stale, new invocation can acquire
        assert cm._acquire_provisioning_lock('example.com') is True

        # Verify all 3 calls passed the correct stale threshold
        for vals in captured_values:
            stale_ts = vals.get(':stale', {}).get('S', '')
            now_ts = vals.get(':now', {}).get('S', '')
            assert stale_ts and now_ts
            stale_dt = datetime.fromisoformat(stale_ts)
            now_dt = datetime.fromisoformat(now_ts)
            delta_seconds = (now_dt - stale_dt).total_seconds()
            assert abs(delta_seconds - cm.PROVISIONING_LOCK_STALE_MINUTES * 60) < 2


class TestIsSnsEvent(unittest.TestCase):
    """Tests for _is_sns_event() envelope detection."""

    def test_rejects_eventbridge_renewal_event(self):
        assert not cm._is_sns_event({'type': 'renewal_scan'})

    def test_rejects_eventbridge_provision_event(self):
        assert not cm._is_sns_event({'type': 'provision', 'domain': 'x.com'})

    def test_rejects_empty_records(self):
        assert not cm._is_sns_event({'Records': []})

    def test_rejects_non_sns_records(self):
        # e.g. SQS / Kinesis would have a different EventSource.
        assert not cm._is_sns_event({'Records': [{'EventSource': 'aws:sqs'}]})

    def test_accepts_sns_record(self):
        event = {'Records': [{'EventSource': 'aws:sns', 'Sns': {'Message': '{}'}}]}
        assert cm._is_sns_event(event)

    def test_rejects_non_dict_first_record(self):
        # Defensive: a malformed Records[0]=None must not crash dispatch.
        assert not cm._is_sns_event({'Records': [None]})


class TestHandleDomainCleanup(unittest.TestCase):
    """Tests for handle_domain_cleanup() and its DDB/SSM/Route53 helpers.

    The handler does a conditional DDB DeleteItem first — that single
    operation is both the race guard and the partial-row cleanup. SSM
    and Route53 only execute when DDB returned 'deleted' or 'absent'.
    """

    def _payload(self, **overrides):
        base = dict(_CONTRACT_FIXTURE)
        base.update(overrides)
        return base

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm, 'publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    @patch.object(cm.route53_client, 'change_resource_record_sets')
    def test_happy_path_deletes_ssm_and_triggers_incremental_delete(
        self, mock_rr53_change, mock_rr53_list, mock_ssm_delete,
        mock_ddb_delete, mock_failure_metric, mock_delete,
    ):
        # qurl-service already deleted the row — DeleteItem is a no-op
        # (ALL_OLD returns no Attributes).
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.return_value = {
            'DeletedParameters': [
                '/nhp/certs/gone.example.com/key',
                '/nhp/certs/gone.example.com/chain',
                '/nhp/certs/gone.example.com/meta',
            ],
            'InvalidParameters': [],
        }
        mock_rr53_list.return_value = {'ResourceRecordSets': []}

        result = cm.handle_domain_cleanup(self._payload())

        assert result['status'] == cm.RESULT_CLEANED
        assert result['domain'] == 'gone.example.com'
        assert result['ddb_result'] == 'absent'
        assert len(result['ssm_deleted']) == 3
        # Per-#1994: cleanup events fire trigger_cert_delete(domain) so the
        # AC fleet evicts only the offboarded domain instead of doing a
        # full-mode sync per event. Regression here would re-fan-out the
        # fleet-wide rebuild that #1994 was written to remove.
        mock_delete.assert_called_once_with('gone.example.com')
        # No Route53 record to delete in this scenario.
        mock_rr53_change.assert_not_called()
        mock_failure_metric.assert_not_called()
        # Conditional check must be present and target the right attribute.
        ddb_kwargs = mock_ddb_delete.call_args.kwargs
        assert 'verification_token' in ddb_kwargs['ConditionExpression']
        assert ddb_kwargs['ReturnValues'] == 'ALL_OLD'

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm, 'publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_deletes_partial_failed_row(
        self, mock_ssm_delete, mock_ddb_delete, mock_failure_metric, mock_delete,
    ):
        # Reconciliation scan wrote a partial row after qurl-service's delete;
        # the conditional DeleteItem removes it and returns the old attributes.
        mock_ddb_delete.return_value = {'Attributes': {
            'domain': {'S': 'gone.example.com'},
            'status': {'S': 'failed'},
        }}
        mock_ssm_delete.return_value = {'DeletedParameters': [], 'InvalidParameters': []}

        result = cm.handle_domain_cleanup(self._payload(acme_cname_target=''))

        assert result['status'] == cm.RESULT_CLEANED
        assert result['ddb_result'] == cm.DDB_DELETED
        mock_ssm_delete.assert_called_once()
        mock_delete.assert_called_once_with('gone.example.com')
        mock_failure_metric.assert_not_called()
        # Canary: the verification_token ConditionExpression is the only
        # protection against deleting a re-registered row. A regression
        # that loosens or drops it must trip this assertion.
        ddb_kwargs = mock_ddb_delete.call_args.kwargs
        assert 'verification_token' in ddb_kwargs['ConditionExpression']
        assert ddb_kwargs['ReturnValues'] == 'ALL_OLD'

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm, 'publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_aborts_when_re_registered_with_token(
        self, mock_ssm_delete, mock_ddb_delete, mock_failure_metric, mock_delete,
    ):
        # Customer re-onboarded — row has a fresh verification_token. The
        # conditional DeleteItem fails and the handler aborts BEFORE touching
        # SSM, Route53, or the AC cert delete trigger. This is the race guard.
        mock_ddb_delete.side_effect = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'race'}},
            'DeleteItem',
        )

        result = cm.handle_domain_cleanup(self._payload())

        assert result['status'] == cm.RESULT_ABORTED
        assert result['reason'] == cm.REASON_RACE_RE_REGISTERED
        mock_ssm_delete.assert_not_called()
        mock_delete.assert_not_called()
        mock_failure_metric.assert_not_called()

    @patch.object(cm, 'publish_failure_metric')
    def test_rejects_invalid_domain(self, mock_failure_metric):
        result = cm.handle_domain_cleanup(self._payload(domain_name='../../etc/passwd'))
        assert result['status'] == cm.RESULT_REJECTED
        assert result['reason'] == cm.REASON_INVALID_DOMAIN
        mock_failure_metric.assert_called_once_with(cm.FAILURE_DOMAIN_VALIDATION)

    @patch.object(cm, 'publish_failure_metric')
    def test_rejects_missing_domain_field(self, mock_failure_metric):
        result = cm.handle_domain_cleanup(self._payload(domain_name=''))
        assert result['status'] == cm.RESULT_REJECTED
        mock_failure_metric.assert_called_once_with(cm.FAILURE_DOMAIN_VALIDATION)

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    def test_ssm_partial_not_found_is_idempotent(
        self, mock_rr53_list, mock_ssm_delete, mock_ddb_delete, mock_delete,
    ):
        # Some SSM params already gone (e.g. a manual half-cleanup or an SNS
        # retry of a partial run). delete_parameters lists the missing ones in
        # InvalidParameters rather than raising — treat as success.
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.return_value = {
            'DeletedParameters': ['/nhp/certs/gone.example.com/key'],
            'InvalidParameters': [
                '/nhp/certs/gone.example.com/chain',
                '/nhp/certs/gone.example.com/meta',
            ],
        }
        mock_rr53_list.return_value = {'ResourceRecordSets': []}

        result = cm.handle_domain_cleanup(self._payload())

        assert result['status'] == cm.RESULT_CLEANED
        assert result['ssm_deleted'] == ['/nhp/certs/gone.example.com/key']
        mock_delete.assert_called_once_with('gone.example.com')

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    @patch.object(cm.route53_client, 'change_resource_record_sets')
    def test_deletes_route53_txt_when_record_exists(
        self, mock_rr53_change, mock_rr53_list, mock_ssm_delete,
        mock_ddb_delete, mock_delete,
    ):
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.return_value = {'DeletedParameters': [], 'InvalidParameters': []}
        # Defensive sweep finds an orphan TXT record at the CNAME target.
        target = 'gone--example--com.acme.example.com'
        mock_rr53_list.return_value = {
            'ResourceRecordSets': [{
                'Name': f'{target}.',
                'Type': 'TXT',
                'TTL': 60,
                'ResourceRecords': [{'Value': '"abc"'}],
            }],
        }

        result = cm.handle_domain_cleanup(self._payload())

        assert result['route53_deleted'] is True
        # AC delete trigger still runs on the happy path.
        mock_delete.assert_called_once_with('gone.example.com')
        # Confirm the change-batch issued a DELETE for the same record.
        change = mock_rr53_change.call_args.kwargs['ChangeBatch']['Changes'][0]
        assert change['Action'] == 'DELETE'
        assert change['ResourceRecordSet']['Name'].rstrip('.') == target

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_raises_transient_error_when_ddb_unavailable(
        self, mock_ssm_delete, mock_ddb_delete, mock_delete,
    ):
        # A non-conditional DDB ClientError (throttle, internal error) means
        # the race guard couldn't run — proceeding would risk wiping a
        # re-registered cert. The handler must raise so the Lambda
        # invocation is marked failed and SNS's async retry kicks in.
        mock_ddb_delete.side_effect = ClientError(
            {'Error': {'Code': 'ProvisionedThroughputExceededException', 'Message': 't'}},
            'DeleteItem',
        )

        with self.assertRaises(cm.TransientCleanupError):
            cm.handle_domain_cleanup(self._payload(acme_cname_target=''))

        mock_ssm_delete.assert_not_called()
        mock_delete.assert_not_called()

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm, 'publish_failure_metric')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_raises_transient_error_when_ssm_delete_fails(
        self, mock_ssm_delete, mock_ddb_delete, mock_failure_metric, mock_delete,
    ):
        # SSM threw a real ClientError. The cert is still in SSM — reporting
        # RESULT_CLEANED would be a lie. Raise so SNS retries the message
        # (its built-in async retry policy is what triggers, not a return
        # value).
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 't'}},
            'DeleteParameters',
        )

        with self.assertRaises(cm.TransientCleanupError):
            cm.handle_domain_cleanup(self._payload(acme_cname_target=''))

        mock_delete.assert_not_called()
        # The internal-failure metric must fire so operators see SSM trouble.
        mock_failure_metric.assert_called_once_with(cm.FAILURE_CERT_STORAGE)

    def test_raises_transient_error_when_qurl_domains_table_unset(self):
        # Misconfigured environment: no QURL_DOMAINS_TABLE means no race
        # guard. Raise so SNS retries — silently returning RESULT_ABORTED
        # would let SNS treat the message as delivered.
        with patch.object(cm, 'QURL_DOMAINS_TABLE', None):
            with self.assertRaises(cm.TransientCleanupError):
                cm.handle_domain_cleanup(self._payload(acme_cname_target=''))


class TestHandlerSnsDispatch(unittest.TestCase):
    """Tests for handler() routing of SNS-delivered events."""

    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_routes_domain_cleanup_to_handler(self, mock_cleanup):
        mock_cleanup.return_value = {'status': cm.RESULT_CLEANED}
        sns_event = {
            'Records': [{
                'EventSource': 'aws:sns',
                'Sns': {
                    'Message': json.dumps({
                        'event_type': cm.EVENT_DOMAIN_CLEANUP,
                        'domain_name': 'gone.com',
                    }),
                    'MessageAttributes': {
                        'event_type': {'Type': 'String', 'Value': cm.EVENT_DOMAIN_CLEANUP},
                    },
                },
            }],
        }
        result = cm.handler(sns_event, None)
        assert result == {'records': [{'status': cm.RESULT_CLEANED}]}
        mock_cleanup.assert_called_once()

    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_ignores_unknown_sns_event_type(self, mock_cleanup):
        sns_event = {
            'Records': [{
                'EventSource': 'aws:sns',
                'Sns': {
                    'Message': '{}',
                    'MessageAttributes': {
                        'event_type': {'Type': 'String', 'Value': 'unknown.thing'},
                    },
                },
            }],
        }
        result = cm.handler(sns_event, None)
        assert result['records'][0]['status'] == cm.RESULT_IGNORED
        mock_cleanup.assert_not_called()

    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_records_invalid_payload_without_aborting_batch(
        self, mock_cleanup, mock_failure_metric,
    ):
        sns_event = {
            'Records': [{
                'EventSource': 'aws:sns',
                'Sns': {
                    'Message': 'not-json',
                    'MessageAttributes': {
                        'event_type': {'Type': 'String', 'Value': cm.EVENT_DOMAIN_CLEANUP},
                    },
                },
            }],
        }
        result = cm.handler(sns_event, None)
        assert result['records'][0]['status'] == cm.RESULT_INVALID_PAYLOAD
        mock_cleanup.assert_not_called()
        # SNS JSON-decode failures get their own metric — distinct from
        # invalid-domain payloads, so operators can tell publisher-side
        # corruption apart from per-domain validation failures.
        mock_failure_metric.assert_called_once_with(cm.FAILURE_SNS_DECODE)

    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_skips_non_dict_record_entries(self, mock_cleanup):
        # SNS-to-Lambda is always 1 well-formed Record today, but the
        # dispatcher iterates the list. Belt-and-suspenders: a malformed
        # subsequent entry must not poison the batch.
        mock_cleanup.return_value = {'status': cm.RESULT_CLEANED}
        sns_event = {
            'Records': [
                {
                    'EventSource': 'aws:sns',
                    'Sns': {
                        'Message': json.dumps({'event_type': cm.EVENT_DOMAIN_CLEANUP}),
                        'MessageAttributes': {
                            'event_type': {'Type': 'String', 'Value': cm.EVENT_DOMAIN_CLEANUP},
                        },
                    },
                },
                None,
            ],
        }

        result = cm.handler(sns_event, None)
        # Non-dict entry is silently skipped; the good record still runs.
        assert len(result['records']) == 1
        assert result['records'][0]['status'] == cm.RESULT_CLEANED

    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_processes_multiple_records_independently(
        self, mock_cleanup, mock_failure_metric,
    ):
        # SNS-to-Lambda is always 1 Record today, but the dispatcher tolerates
        # batches. Lock that semantics: a malformed first record must not
        # block the second record from running.
        mock_cleanup.return_value = {'status': cm.RESULT_CLEANED, 'domain': 'good.com'}
        sns_event = {
            'Records': [
                {
                    'EventSource': 'aws:sns',
                    'Sns': {
                        'Message': 'not-json',
                        'MessageAttributes': {
                            'event_type': {'Type': 'String', 'Value': cm.EVENT_DOMAIN_CLEANUP},
                        },
                    },
                },
                {
                    'EventSource': 'aws:sns',
                    'Sns': {
                        'Message': json.dumps({
                            'event_type': cm.EVENT_DOMAIN_CLEANUP,
                            'domain_name': 'good.com',
                        }),
                        'MessageAttributes': {
                            'event_type': {'Type': 'String', 'Value': cm.EVENT_DOMAIN_CLEANUP},
                        },
                    },
                },
            ],
        }

        result = cm.handler(sns_event, None)

        assert len(result['records']) == 2
        assert result['records'][0]['status'] == cm.RESULT_INVALID_PAYLOAD
        assert result['records'][1]['status'] == cm.RESULT_CLEANED
        mock_cleanup.assert_called_once()
        mock_failure_metric.assert_called_once_with(cm.FAILURE_SNS_DECODE)


class TestDeleteAcmeTxtRecord(unittest.TestCase):
    """Locks the post-refactor return shape and Type-filter contract.

    `delete_acme_txt_record` is now used by two callers: the canonical
    post-DNS-01 cleanup AND the domain.cleanup defensive sweep. The Type
    filter is the only thing that prevents Route53's lexical-order
    list_resource_record_sets from returning a same-name non-TXT record
    and letting us DELETE it by accident.
    """

    @patch.object(cm.route53_client, 'change_resource_record_sets')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    def test_skips_when_no_record_exists(self, mock_list, mock_change):
        mock_list.return_value = {'ResourceRecordSets': []}
        assert cm.delete_acme_txt_record('missing.acme.example.com') is False
        mock_change.assert_not_called()

    @patch.object(cm.route53_client, 'change_resource_record_sets')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    def test_skips_when_same_name_record_is_not_txt(self, mock_list, mock_change):
        # ListResourceRecordSets returns >= the start name in lexical order,
        # so a non-TXT record sharing the name could be returned. The Type
        # filter rejects it — without it, we'd happily DELETE a CNAME or A
        # record someone else owns.
        mock_list.return_value = {
            'ResourceRecordSets': [{
                'Name': 'gone--example--com.acme.example.com.',
                'Type': 'CNAME',
                'TTL': 60,
                'ResourceRecords': [{'Value': 'sneaky-target.example.net'}],
            }],
        }
        assert cm.delete_acme_txt_record('gone--example--com.acme.example.com') is False
        mock_change.assert_not_called()

    @patch.object(cm.route53_client, 'change_resource_record_sets')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    def test_returns_true_when_txt_deleted(self, mock_list, mock_change):
        mock_list.return_value = {
            'ResourceRecordSets': [{
                'Name': 'a.acme.example.com.',
                'Type': 'TXT',
                'TTL': 60,
                'ResourceRecords': [{'Value': '"abc"'}],
            }],
        }
        assert cm.delete_acme_txt_record('a.acme.example.com') is True
        mock_change.assert_called_once()

    @patch.object(cm.route53_client, 'list_resource_record_sets')
    def test_returns_false_when_acme_zone_id_unset(self, mock_list):
        # Misconfigured env: never make the Route53 call at all.
        with patch.object(cm, 'ACME_ZONE_ID', ''):
            assert cm.delete_acme_txt_record('any.acme.example.com') is False
        mock_list.assert_not_called()


class TestContractFixtureKeys(unittest.TestCase):
    """Locks the cross-repo payload contract.

    qurl-service publishes a DomainCleanupEvent with JSON field names defined
    by its Go struct. handle_domain_cleanup reads those same keys. If either
    side renames a key, _CONTRACT_FIXTURE here must update to match — and the
    test will surface the drift loudly. Update in lockstep with
    qurl-service/internal/events/domain_event_publisher.go.
    """

    def test_fixture_contains_all_keys_the_handler_reads(self):
        expected_keys = {
            'event_type',         # routing key (MessageAttributes mirror)
            'domain_name',        # required: deletion target
            'cert_param_prefix',  # optional: SSM prefix override
            'acme_cname_target',  # optional: Route53 record to sweep
            'owner_id',           # ignored by lambda but part of payload
            'timestamp',          # unused after race-guard refactor; retained for audit
        }
        assert set(_CONTRACT_FIXTURE.keys()) == expected_keys, (
            "Cross-repo payload schema drift: keys diverged from "
            "qurl-service DomainCleanupEvent. Update _CONTRACT_FIXTURE "
            "and the handler in lockstep."
        )

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_cert_param_prefix_fallback_uses_conventional_path(
        self, mock_ssm_delete, mock_ddb_delete, mock_sync,
    ):
        del mock_sync  # asserted-not-called surface covered by other tests
        # Empty cert_param_prefix in the payload must reconstruct the
        # conventional SSM_CERT_PREFIX/<domain>/{key,chain,meta} names.
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.return_value = {'DeletedParameters': [], 'InvalidParameters': []}

        cm.handle_domain_cleanup({
            'event_type': cm.EVENT_DOMAIN_CLEANUP,
            'domain_name': 'fb.example.com',
            'cert_param_prefix': '',
            'acme_cname_target': '',
        })

        # Names sent to delete_parameters must match the conventional shape.
        names_arg = mock_ssm_delete.call_args.kwargs['Names']
        prefix = cm.SSM_CERT_PREFIX.rstrip('/')
        assert set(names_arg) == {
            f"{prefix}/fb.example.com/key",
            f"{prefix}/fb.example.com/chain",
            f"{prefix}/fb.example.com/meta",
        }

    @patch('custom_domain_cert_manager.trigger_cert_delete')
    @patch.object(cm.route53_client, 'list_resource_record_sets')
    @patch.object(cm.dynamodb_client, 'delete_item')
    @patch.object(cm.ssm_client, 'delete_parameters')
    def test_full_contract_fixture_yields_clean_run(
        self, mock_ssm_delete, mock_ddb_delete, mock_rr53_list, mock_delete,
    ):
        # Positive integration check: hand the full _CONTRACT_FIXTURE to the
        # handler with every consumer mocked, and assert non-rejection. If
        # someone renames a key the handler reads (e.g. domain_name → domain),
        # this trips even when the hardcoded key-set assertion above stays
        # green — the fixture provides the old key but the handler would
        # silently treat it as missing.
        mock_ddb_delete.return_value = {}
        mock_ssm_delete.return_value = {'DeletedParameters': [], 'InvalidParameters': []}
        mock_rr53_list.return_value = {'ResourceRecordSets': []}

        result = cm.handle_domain_cleanup(dict(_CONTRACT_FIXTURE))

        assert result['status'] == cm.RESULT_CLEANED
        assert result['domain'] == _CONTRACT_FIXTURE['domain_name']
        mock_delete.assert_called_once_with(_CONTRACT_FIXTURE['domain_name'])


class TestAcmeStackCompat(unittest.TestCase):
    """Mock-free fence for the acme/josepy/pyOpenSSL CSR-parsing contract.

    pyOpenSSL>=24.0 removed OpenSSL.crypto.X509Req and load_certificate_request.
    acme<3 (through josepy<2's ComparableX509) called them inside
    ClientV2.new_order(), so with the pinned pyOpenSSL==26.3.0 every real cert
    provision/renewal crashed with "module 'OpenSSL.crypto' has no attribute
    'X509Req'" and marked custom domains `failed` — while pip resolution and the
    fully-mocked tests above stayed green (none call the real new_order()).
    acme>=3 / josepy>=2 parse CSRs with `cryptography` instead.

    This drives a real CSR (built like request_certificate: single CN + SAN)
    through the pinned acme's new_order() with only the HTTP transport mocked,
    so a future dependency bump that reintroduces the removed pyOpenSSL APIs
    fails here instead of silently in production.

    Scope: it guards the specific CSR-parse crash site (new_order). The wider
    acme surface the handler uses (account registration, DNS-01 challenge,
    poll_and_finalize, fullchain_pem) stays mock-covered here and was verified
    by hand against acme 5.6.0 for this bump.
    """

    def test_new_order_parses_csr_without_pyopenssl_x509req(self):
        cm.lazy_import_acme()  # exercise the Lambda's own import path
        from acme import client, messages
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # josepy>=2 dropped the pyOpenSSL ComparableX509 wrapper.
        self.assertFalse(hasattr(cm.josepy, 'ComparableX509'))

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        domain = 'regression.example.com'
        csr_pem = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )

        acme_client = client.ClientV2(
            messages.Directory({'newOrder': 'https://acme.test/new-order'}),
            net=client.ClientNetwork(cm.josepy.JWKRSA(key=key)),
        )

        # new_order() parses the CSR into an order (the historic X509Req crash
        # site) before its first _post. Assert our domain survived the parse —
        # not merely that _post was reached — so the guard holds even if a future
        # acme reorders parse vs. that _post.
        class _StopBeforeHTTP(Exception):
            pass

        with patch.object(acme_client, '_post', side_effect=_StopBeforeHTTP) as mock_post:
            with self.assertRaises(_StopBeforeHTTP):
                acme_client.new_order(csr_pem)

        # new_order() calls self._post(url, order) positionally, so args[1] is the
        # order it built from the CSR. Coupled to the pinned acme's convention: a
        # future acme passing order= as a kwarg would break this line, not the
        # handler — fine for a version-pinned fence.
        order = mock_post.call_args.args[1]
        self.assertIn(domain, [ident.value for ident in order.identifiers])

    def test_handler_acme_surface_resolves(self):
        """The renewal path calls a wider acme surface than new_order (account
        registration, DNS-01 challenge, poll_and_finalize) that stays fully
        MOCKED in the tests above. Across the 2.11->5.6 jump (skipping 3.x/4.x)
        any of these could have been renamed or removed — which would crash the
        handler at runtime exactly like the X509Req bug, invisibly to the mocked
        tests. Resolve every symbol the handler binds to so a drift fails in CI
        instead of in production. This does NOT assert parameter names, so full
        behaviour still rests on the mocked tests + hand verification against
        acme 5.6.0."""
        cm.lazy_import_acme()
        import inspect
        from acme import challenges, client, errors, messages

        # (owner, attribute, signature_check) for every acme/josepy symbol the
        # handler binds to. hasattr/callable catch a rename or removal; for the
        # callables the handler passes arguments to, inspect.signature() also
        # catches a replacement that is no longer introspectable (it does not
        # check parameter names). Skip it for the exception/message classes.
        for obj, attr, sig_check in [
            (client, 'ClientNetwork', False), (client, 'ClientV2', False),
            (client.ClientV2, 'new_order', True), (client.ClientV2, 'new_account', True),
            (client.ClientV2, 'query_registration', True),
            (client.ClientV2, 'answer_challenge', True), (client.ClientV2, 'poll_and_finalize', True),
            (messages, 'Directory', False), (messages.Directory, 'from_json', True),
            (messages, 'NewRegistration', False), (messages.NewRegistration, 'from_data', True),
            (messages, 'RegistrationResource', False), (messages, 'Registration', False),
            (challenges, 'DNS01', False), (errors, 'ConflictError', False),
            (cm.josepy, 'JWKRSA', False),
        ]:
            self.assertTrue(hasattr(obj, attr), f'{obj!r} no longer has {attr}')
            member = getattr(obj, attr)
            self.assertTrue(callable(member), f'{attr} is not callable')
            if sig_check:
                inspect.signature(member)


if __name__ == '__main__':
    unittest.main()
