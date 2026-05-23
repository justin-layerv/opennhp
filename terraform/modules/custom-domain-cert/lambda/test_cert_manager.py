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
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

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

import custom_domain_cert_manager as cm


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
            assert result == {'provisioned': 0, 'failed': 0, 'timed_out': 0, 'skipped': 0}
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
    def test_auto_fails_stuck_domain(self, mock_query, mock_status, mock_metric, mock_alert):
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


class TestStoreCertificate(unittest.TestCase):
    """Tests for store_certificate() SSM parameter storage."""

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_stores_three_params(self, mock_put):
        """Should store key, chain, and meta as separate SSM parameters."""
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

        # Verify key and chain are SecureString, meta is String
        for call in mock_put.call_args_list:
            if call.kwargs['Name'].endswith('/meta'):
                assert call.kwargs['Type'] == 'String'
            else:
                assert call.kwargs['Type'] == 'SecureString'

    @patch.object(cm.ssm_client, 'put_parameter')
    def test_chain_is_fullchain(self, mock_put):
        """Chain param should contain cert + chain concatenated."""
        cm.store_certificate(
            domain='test.org',
            private_key_pem='key-pem',
            cert_pem='cert-pem',
            chain_pem='chain-pem',
            expires_at='2026-06-01T00:00:00+00:00',
        )

        chain_call = [c for c in mock_put.call_args_list if c.kwargs['Name'].endswith('/chain')][0]
        assert chain_call.kwargs['Value'] == 'cert-pemchain-pem'


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
            'Item': {'verification_token': {'S': 'lv_verify_test_token'}}
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
        mock_provision.assert_called_once()
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
        mock_provision.assert_called_once_with('no-acme.com', 'no-acme--com', skip_sync=True)

    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_empty_scan(self, mock_list, mock_cw):
        """Should handle no certs gracefully."""
        mock_list.return_value = []

        result = cm.renewal_scan()
        assert result['scanned'] == 0
        assert result['renewed'] == 0
        mock_cw.assert_not_called()


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
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc'}}}
        assert cm.check_orphan_for_meta('managed.com') is None

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
        del mock_cw  # only suppressed, not asserted
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
        mock_failure_metric.assert_called_once_with(cm.FAILURE_ORPHANED_CERT)
        # Operator-facing alert references the manual cleanup path.
        assert mock_alert.called
        alert_msg = mock_alert.call_args[0][0]
        assert 'orphan.com' in alert_msg
        assert 'manual cleanup' in alert_msg.lower()

        detail = result['details'][0]
        assert detail['action'] == 'orphaned'
        assert detail['domain'] == 'orphan.com'

        # Aggregated summary alert: a single send_alert call regardless of count.
        assert mock_alert.call_count == 1

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
        del mock_cw, mock_sync, mock_alert
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
        # Exactly one orphan metric publish, for orphan.com.
        mock_failure_metric.assert_called_once_with(cm.FAILURE_ORPHANED_CERT)

    @patch.object(cm, 'send_alert')
    @patch.object(cm, 'publish_failure_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.cloudwatch_client, 'put_metric_data')
    @patch.object(cm.dynamodb_client, 'get_item')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_multiple_orphans_emit_single_summary_alert(
        self, mock_list, mock_get, mock_cw, mock_provision, mock_sync,
        mock_failure_metric, mock_alert,
    ):
        """Many orphans in one scan → one summary SNS, N metric publishes."""
        del mock_cw, mock_sync, mock_provision
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
        # Metric still fires per-orphan so the alarm reflects the true count.
        assert mock_failure_metric.call_count == 3
        # SNS publish is aggregated to a single message.
        assert mock_alert.call_count == 1
        msg = mock_alert.call_args[0][0]
        for i in range(3):
            assert f'orphan{i}.com' in msg


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
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
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
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
            cm.verify_dns_ownership('slow.com')
        assert 'timed out' in str(ctx.exception)

    @patch.object(cm.dynamodb_client, 'get_item')
    def test_raises_generic_dns_exception(self, mock_get):
        mock_get.return_value = {'Item': {'verification_token': {'S': 'lv_verify_abc123'}}}
        stub_resolver, _ = _install_dns_stubs()

        class _NoNameservers(_StubDnsException):
            pass

        stub_resolver.Resolver.return_value.resolve.side_effect = _NoNameservers()
        with self.assertRaises(cm.DnsOwnershipError) as ctx:
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
    def test_ownership_failure_publishes_correct_metric(
        self, mock_get, mock_status, mock_alert, mock_metric, mock_lock, mock_release
    ):
        del mock_status, mock_alert, mock_lock  # @patch suppresses side effects only
        mock_get.return_value = {}
        with self.assertRaises(cm.DnsOwnershipError):
            cm.provision_certificate("missing.com", "missing--com")
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

    @patch('custom_domain_cert_manager.publish_metric')
    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch('custom_domain_cert_manager.list_cert_meta_params')
    def test_renewal_scan_does_not_count_skipped_as_renewed(
        self, mock_list, mock_provision, mock_sync, mock_metric
    ):
        """Domains skipped due to lock should not inflate the renewed count."""
        del mock_sync, mock_metric  # @patch suppresses side effects only
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

    @patch('custom_domain_cert_manager.handle_domain_cleanup')
    def test_handler_processes_multiple_records_independently(self, mock_cleanup):
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


if __name__ == '__main__':
    unittest.main()
