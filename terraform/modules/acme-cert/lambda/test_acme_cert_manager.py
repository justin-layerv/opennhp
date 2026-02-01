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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
