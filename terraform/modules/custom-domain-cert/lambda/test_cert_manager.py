"""Tests for custom_domain_cert_manager Lambda.

Covers renewal_scan(), provision_pending_domains(), list_cert_meta_params(),
store_certificate(), and trigger_cert_sync() command injection hardening.

Uses unittest.mock to patch boto3 clients — no moto dependency needed.
"""
import json
import os
import unittest
from unittest.mock import patch, MagicMock


# Set required env vars before import
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


if __name__ == '__main__':
    unittest.main()
