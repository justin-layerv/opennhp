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
            assert result == {'provisioned': 0, 'failed': 0}
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

    @patch('custom_domain_cert_manager.trigger_cert_sync')
    @patch('custom_domain_cert_manager.provision_certificate')
    @patch.object(cm.dynamodb_client, 'query')
    def test_skips_invalid_domains(self, mock_query, mock_provision, mock_sync):
        """Should skip domains that fail validation and count them as failures."""
        del mock_sync  # @patch supplies this; assertion isn't needed for this case
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


if __name__ == '__main__':
    unittest.main()
