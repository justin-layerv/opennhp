"""
Unit tests for ACME Certificate Manager Lambda

Run with: pytest test_acme_cert_manager.py -v

These tests mock all external dependencies (AWS, ACME) to verify
the handler logic without requiring actual infrastructure.
"""

import json
import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock

# Set required environment variables before importing the module
os.environ.setdefault('DOMAINS', 'test.example.com,*.test.example.com')
os.environ.setdefault('SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789:secret:test')
os.environ.setdefault('ACME_ACCOUNT_SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789:secret:acme')
os.environ.setdefault('KMS_KEY_ARN', 'arn:aws:kms:us-east-1:123456789:key/test')
os.environ.setdefault('ACME_EMAIL', 'test@example.com')
os.environ.setdefault('ACME_DIRECTORY', 'https://acme-staging-v02.api.letsencrypt.org/directory')
os.environ.setdefault('HOSTED_ZONE_ID', 'Z1234567890')
os.environ.setdefault('RENEWAL_DAYS_BEFORE_EXPIRY', '30')
os.environ.setdefault('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789:test')


class TestHandler:
    """Tests for the main Lambda handler."""

    @patch('acme_cert_manager.check_certificate_status')
    def test_handler_check_status(self, mock_check):
        """Handler routes check_status events correctly."""
        from acme_cert_manager import handler

        mock_check.return_value = {'status': 'valid', 'days_until_expiry': 60}

        result = handler({'type': 'check_status'}, None)

        mock_check.assert_called_once()
        assert result['status'] == 'valid'

    @patch('acme_cert_manager.renew_certificate')
    def test_handler_force_renew(self, mock_renew):
        """Handler routes force_renew events correctly."""
        from acme_cert_manager import handler

        mock_renew.return_value = {'status': 'renewed'}

        result = handler({'type': 'force_renew'}, None)

        mock_renew.assert_called_once_with(force=True)
        assert result['status'] == 'renewed'

    @patch('acme_cert_manager.renew_certificate')
    def test_handler_scheduled(self, mock_renew):
        """Handler routes scheduled events correctly."""
        from acme_cert_manager import handler

        mock_renew.return_value = {'status': 'skipped'}

        result = handler({'type': 'scheduled'}, None)

        mock_renew.assert_called_once_with(force=False)

    @patch('acme_cert_manager.renew_certificate')
    def test_handler_default_is_scheduled(self, mock_renew):
        """Handler defaults to scheduled behavior."""
        from acme_cert_manager import handler

        mock_renew.return_value = {'status': 'skipped'}

        result = handler({}, None)

        mock_renew.assert_called_once_with(force=False)

    @patch('acme_cert_manager.send_alert')
    @patch('acme_cert_manager.renew_certificate')
    def test_handler_error_sends_alert(self, mock_renew, mock_alert):
        """Handler sends alert on error."""
        from acme_cert_manager import handler

        mock_renew.side_effect = Exception('Test error')

        with pytest.raises(Exception, match='Test error'):
            handler({'type': 'scheduled'}, None)

        mock_alert.assert_called_once()
        assert 'FAILED' in mock_alert.call_args[0][0]


class TestCheckCertificateStatus:
    """Tests for certificate status checking."""

    @patch('acme_cert_manager.get_current_secret')
    def test_missing_secret(self, mock_get):
        """Returns missing status when secret doesn't exist."""
        from acme_cert_manager import check_certificate_status

        mock_get.return_value = None

        result = check_certificate_status()

        assert result['status'] == 'missing'

    @patch('acme_cert_manager.get_current_secret')
    def test_invalid_secret(self, mock_get):
        """Returns invalid status when secret has no certificate."""
        from acme_cert_manager import check_certificate_status

        mock_get.return_value = {'private_key': 'xxx'}  # No certificate

        result = check_certificate_status()

        assert result['status'] == 'invalid'

    @patch('acme_cert_manager.publish_expiry_metric')
    @patch('acme_cert_manager.get_current_secret')
    def test_valid_certificate(self, mock_get, mock_metric):
        """Returns valid status with certificate details."""
        from acme_cert_manager import check_certificate_status

        # Create a self-signed test certificate
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        mock_get.return_value = {'certificate': cert_pem}

        result = check_certificate_status()

        assert result['status'] == 'valid'
        assert 'days_until_expiry' in result
        assert result['days_until_expiry'] > 80  # ~90 days
        mock_metric.assert_called_once()


class TestDNSRecord:
    """Tests for DNS record management."""

    @patch('acme_cert_manager.route53_client')
    def test_create_dns_record(self, mock_r53):
        """Creates TXT record for ACME challenge."""
        from acme_cert_manager import create_dns_record

        create_dns_record('_acme-challenge.test.example.com', 'token123')

        mock_r53.change_resource_record_sets.assert_called_once()
        call_args = mock_r53.change_resource_record_sets.call_args
        changes = call_args[1]['ChangeBatch']['Changes']
        assert len(changes) == 1
        assert changes[0]['Action'] == 'UPSERT'
        assert changes[0]['ResourceRecordSet']['Type'] == 'TXT'

    @patch('acme_cert_manager.route53_client')
    def test_create_dns_record_strips_wildcard(self, mock_r53):
        """Strips wildcard from challenge record name."""
        from acme_cert_manager import create_dns_record

        create_dns_record('_acme-challenge.*.test.example.com', 'token123')

        call_args = mock_r53.change_resource_record_sets.call_args
        record_name = call_args[1]['ChangeBatch']['Changes'][0]['ResourceRecordSet']['Name']
        assert '*' not in record_name
        assert record_name == '_acme-challenge.test.example.com'


class TestStoreCertificate:
    """Tests for certificate storage."""

    @patch('acme_cert_manager.secrets_client')
    def test_store_certificate(self, mock_secrets):
        """Stores certificate with all required fields."""
        from acme_cert_manager import store_certificate

        # Use placeholder strings that won't trigger pre-commit private key detection
        store_certificate(
            private_key_pem='-----BEGIN RSA KEY-----\ntest\n-----END RSA KEY-----\n',
            cert_pem='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n',
            chain_pem='-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n'
        )

        mock_secrets.put_secret_value.assert_called_once()
        call_args = mock_secrets.put_secret_value.call_args
        secret_data = json.loads(call_args[1]['SecretString'])

        assert 'private_key' in secret_data
        assert 'certificate' in secret_data
        assert 'chain' in secret_data
        assert 'fullchain' in secret_data
        assert 'renewed_at' in secret_data
        assert 'domains' in secret_data


class TestSendAlert:
    """Tests for SNS alerting."""

    @patch('acme_cert_manager.sns_client')
    def test_send_alert(self, mock_sns):
        """Sends alert to SNS topic."""
        from acme_cert_manager import send_alert

        send_alert('Test message', is_error=True)

        mock_sns.publish.assert_called_once()
        call_args = mock_sns.publish.call_args
        assert 'ERROR' in call_args[1]['Subject']

    @patch('acme_cert_manager.sns_client')
    def test_send_alert_info(self, mock_sns):
        """Sends info alert with correct subject."""
        from acme_cert_manager import send_alert

        send_alert('Success message', is_error=False)

        call_args = mock_sns.publish.call_args
        assert 'INFO' in call_args[1]['Subject']

    @patch('acme_cert_manager.SNS_TOPIC_ARN', None)
    def test_send_alert_no_topic(self):
        """Skips alert when no topic configured."""
        from acme_cert_manager import send_alert

        # Should not raise
        send_alert('Test message')


class TestMultiZoneSupport:
    """Tests for multi-zone and cross-account Route53 support."""

    def test_get_zone_for_domain_exact_match(self):
        """Matches domain exactly in zone mappings."""
        import acme_cert_manager as acm

        # Save original values
        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('qurl.site')

            assert zone_id == 'Z_QURL_SITE'
            assert client == acm.route53_client
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_suffix_match(self):
        """Matches subdomain by suffix."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('app.qurl.site')

            assert zone_id == 'Z_QURL_SITE'
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_longest_match_wins(self):
        """Longer suffix match takes precedence."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'site': {'zone_id': 'Z_SITE', 'cross_account': False},
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('app.qurl.site')

            # qurl.site (10 chars) should win over site (4 chars)
            assert zone_id == 'Z_QURL_SITE'
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_falls_back_to_default(self):
        """Uses HOSTED_ZONE_ID when no mapping matches."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('example.com')

            assert zone_id == 'Z_DEFAULT'
            assert client == acm.route53_client
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_strips_acme_challenge_prefix(self):
        """Strips _acme-challenge. prefix before matching."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('_acme-challenge.qurl.site')

            assert zone_id == 'Z_QURL_SITE'
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_strips_wildcard(self):
        """Strips wildcard prefix before matching."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'zone_id': 'Z_QURL_SITE', 'cross_account': False}
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('_acme-challenge.*.qurl.site')

            assert zone_id == 'Z_QURL_SITE'
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_plain_string_mapping(self):
        """Plain string mapping defaults to same-account (cross_account=False)."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            # Plain string (not dict) should default to cross_account=False
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': 'Z_QURL_SITE'  # Plain string, not dict
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('qurl.site')

            assert zone_id == 'Z_QURL_SITE'
            # Should use default client (not cross-account) since cross_account defaults to False
            assert client == acm.route53_client
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    def test_get_zone_for_domain_missing_zone_id_falls_back(self):
        """Falls back to default zone when zone_id is missing from mapping."""
        import acme_cert_manager as acm

        orig_mappings = acm.DOMAIN_ZONE_MAPPINGS
        orig_zone = acm.HOSTED_ZONE_ID

        try:
            acm.DOMAIN_ZONE_MAPPINGS = {
                'qurl.site': {'cross_account': False}  # Missing zone_id
            }
            acm.HOSTED_ZONE_ID = 'Z_DEFAULT'

            zone_id, client = acm.get_zone_for_domain('qurl.site')

            # Should fall back to default zone
            assert zone_id == 'Z_DEFAULT'
        finally:
            acm.DOMAIN_ZONE_MAPPINGS = orig_mappings
            acm.HOSTED_ZONE_ID = orig_zone

    @patch('acme_cert_manager.boto3')
    def test_cross_account_client_uses_assumed_role(self, mock_boto3):
        """Creates client with STS assumed role credentials."""
        import acme_cert_manager as acm

        # Reset cached client
        acm._cross_account_route53_client = None
        acm._cross_account_credentials_expiry = None
        orig_role_arn = acm.CROSS_ACCOUNT_ROLE_ARN

        try:
            acm.CROSS_ACCOUNT_ROLE_ARN = 'arn:aws:iam::123456789:role/test-role'

            # Mock STS assume_role response
            mock_sts = MagicMock()
            mock_sts.assume_role.return_value = {
                'Credentials': {
                    'AccessKeyId': 'AKIATEST',
                    'SecretAccessKey': 'secret',
                    'SessionToken': 'token',
                    'Expiration': datetime.now(timezone.utc) + timedelta(hours=1)
                }
            }
            mock_boto3.client.side_effect = lambda svc, **kwargs: (
                mock_sts if svc == 'sts' else MagicMock()
            )

            client = acm.get_cross_account_route53_client()

            # Verify STS was called with correct role
            mock_sts.assume_role.assert_called_once()
            call_kwargs = mock_sts.assume_role.call_args[1]
            assert call_kwargs['RoleArn'] == 'arn:aws:iam::123456789:role/test-role'
            assert call_kwargs['RoleSessionName'] == 'acme-cert-manager'

            # Verify Route53 client was created with assumed credentials
            assert client is not None
        finally:
            acm.CROSS_ACCOUNT_ROLE_ARN = orig_role_arn
            acm._cross_account_route53_client = None
            acm._cross_account_credentials_expiry = None

    def test_cross_account_client_returns_none_without_role_arn(self):
        """Returns None when CROSS_ACCOUNT_ROLE_ARN is not set."""
        import acme_cert_manager as acm

        acm._cross_account_route53_client = None
        acm._cross_account_credentials_expiry = None
        orig_role_arn = acm.CROSS_ACCOUNT_ROLE_ARN

        try:
            acm.CROSS_ACCOUNT_ROLE_ARN = None

            client = acm.get_cross_account_route53_client()

            assert client is None
        finally:
            acm.CROSS_ACCOUNT_ROLE_ARN = orig_role_arn

    @patch('acme_cert_manager.boto3')
    def test_cross_account_client_refreshes_expired_credentials(self, mock_boto3):
        """Refreshes credentials when they're near expiry."""
        import acme_cert_manager as acm

        acm._cross_account_route53_client = MagicMock()  # Existing client
        acm._cross_account_credentials_expiry = datetime.now(timezone.utc) + timedelta(minutes=2)  # Expiring soon
        orig_role_arn = acm.CROSS_ACCOUNT_ROLE_ARN

        try:
            acm.CROSS_ACCOUNT_ROLE_ARN = 'arn:aws:iam::123456789:role/test-role'

            mock_sts = MagicMock()
            mock_sts.assume_role.return_value = {
                'Credentials': {
                    'AccessKeyId': 'AKIANEW',
                    'SecretAccessKey': 'newsecret',
                    'SessionToken': 'newtoken',
                    'Expiration': datetime.now(timezone.utc) + timedelta(hours=1)
                }
            }
            mock_boto3.client.side_effect = lambda svc, **kwargs: (
                mock_sts if svc == 'sts' else MagicMock()
            )

            client = acm.get_cross_account_route53_client()

            # Should have refreshed (called assume_role again)
            mock_sts.assume_role.assert_called_once()
        finally:
            acm.CROSS_ACCOUNT_ROLE_ARN = orig_role_arn
            acm._cross_account_route53_client = None
            acm._cross_account_credentials_expiry = None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
