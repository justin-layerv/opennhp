"""
Tests for QURL Developer Credential Provisioner Lambda.

Run with: pytest terraform/modules/developer-portal/lambda/test_credential_provisioner.py -v
"""

import pytest
import json
import hashlib
import hmac
import time
from unittest.mock import MagicMock, patch, ANY


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_module():
    """Import the module with mocked AWS clients."""
    with patch('boto3.resource'), patch('boto3.client'):
        import sys
        if 'credential_provisioner' in sys.modules:
            del sys.modules['credential_provisioner']


@pytest.fixture
def mock_dynamodb():
    """Mock DynamoDB table operations."""
    with patch('credential_provisioner.credentials_table') as mock_cred_table, \
         patch('credential_provisioner.rate_table') as mock_rate_table:
        mock_cred_table.put_item = MagicMock()
        mock_cred_table.get_item = MagicMock(return_value={})
        mock_cred_table.update_item = MagicMock()
        mock_rate_table.get_item = MagicMock(return_value={})
        mock_rate_table.put_item = MagicMock()
        mock_rate_table.update_item = MagicMock()
        yield {'credentials_table': mock_cred_table, 'rate_table': mock_rate_table}


@pytest.fixture
def mock_ses():
    """Mock SES email operations."""
    with patch('credential_provisioner.ses') as mock:
        mock.send_email = MagicMock()
        yield mock


@pytest.fixture
def mock_aws(mock_dynamodb, mock_ses):
    """Combined AWS mocks."""
    return {**mock_dynamodb, 'ses': mock_ses}


@pytest.fixture
def mock_auth0():
    """Mock Auth0 Management API calls."""
    with patch('credential_provisioner.create_auth0_m2m_app') as mock_create, \
         patch('credential_provisioner.authorize_auth0_app') as mock_auth:
        mock_create.return_value = {
            'client_id': 'test_client_id_abc',
            'client_secret': 'test_client_secret_xyz'
        }
        mock_auth.return_value = None
        yield {'create': mock_create, 'authorize': mock_auth}


@pytest.fixture
def register_event():
    """Base registration event."""
    return {
        'requestContext': {
            'http': {
                'method': 'POST',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/credentials/register',
        'headers': {'origin': 'https://layerv.ai'},
        'body': json.dumps({
            'email': 'developer@example.com'
        })
    }


@pytest.fixture
def verify_event():
    """Base verification event."""
    return {
        'requestContext': {
            'http': {
                'method': 'GET',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/credentials/verify',
        'headers': {'origin': 'https://layerv.ai'},
        'queryStringParameters': {
            'token': 'test-token-123',
            'email': 'developer@example.com'
        }
    }


@pytest.fixture
def health_event():
    """Base health check event."""
    return {
        'requestContext': {
            'http': {
                'method': 'GET',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/credentials/health',
        'headers': {'origin': 'https://layerv.ai'},
        'body': None
    }


# ---------------------------------------------------------------------------
# Routing Tests
# ---------------------------------------------------------------------------

class TestRouting:
    """Tests for request routing."""

    def test_register_routed(self, mock_aws, register_event):
        """Verify POST /credentials/register routes correctly."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            response = cp.lambda_handler(register_event, None)
            assert response['statusCode'] == 200

    def test_verify_routed(self, mock_aws, mock_auth0, verify_event):
        """Verify GET /credentials/verify routes correctly."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            response = cp.lambda_handler(verify_event, None)
            assert response['statusCode'] == 200

    def test_health_routed(self, health_event):
        """Verify GET /credentials/health returns healthy status."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            response = cp.lambda_handler(health_event, None)
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['status'] == 'healthy'
            assert body['service'] == 'credential-provisioner'

    def test_unknown_path_returns_404(self):
        """Verify unknown paths return 404."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            event = {
                'requestContext': {'http': {'method': 'GET', 'sourceIp': '1.2.3.4'}},
                'rawPath': '/credentials/unknown',
                'headers': {'origin': 'https://layerv.ai'},
                'body': None
            }

            response = cp.lambda_handler(event, None)
            assert response['statusCode'] == 404

    def test_options_returns_200(self):
        """Verify OPTIONS preflight returns 200."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            event = {
                'requestContext': {'http': {'method': 'OPTIONS', 'sourceIp': '1.2.3.4'}},
                'rawPath': '/credentials/register',
                'headers': {'origin': 'https://layerv.ai'},
                'body': None
            }

            response = cp.lambda_handler(event, None)
            assert response['statusCode'] == 200

    def test_prod_prefix_stripped(self, health_event):
        """Verify /prod prefix is stripped from path."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            health_event['rawPath'] = '/prod/credentials/health'

            response = cp.lambda_handler(health_event, None)
            assert response['statusCode'] == 200


# ---------------------------------------------------------------------------
# Registration Tests
# ---------------------------------------------------------------------------

class TestRegistration:
    """Tests for the registration flow."""

    def test_successful_registration(self, mock_aws, register_event):
        """Verify successful registration stores record and sends email."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            response = cp.handle_register(register_event)

            assert response['statusCode'] == 200
            assert mock_aws['credentials_table'].put_item.called
            assert mock_aws['ses'].send_email.called

            # Verify token is hashed before storage
            call_args = mock_aws['credentials_table'].put_item.call_args
            item = call_args[1]['Item']
            assert 'token_hash' in item
            assert 'token' not in item  # No plaintext token
            assert len(item['token_hash']) == 64  # SHA256 hex

    def test_registration_normalizes_email(self, mock_aws, register_event):
        """Verify email is normalized to lowercase."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            register_event['body'] = json.dumps({'email': 'DEV@EXAMPLE.COM'})
            cp.handle_register(register_event)

            call_args = mock_aws['credentials_table'].put_item.call_args
            item = call_args[1]['Item']
            assert item['email'] == 'dev@example.com'

    def test_registration_rejects_invalid_email(self, mock_aws, register_event):
        """Verify invalid email formats are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            invalid_emails = [
                'notanemail',
                '@nodomain.com',
                'no@domain',
                '',
                'spaces in@email.com',
            ]

            for email in invalid_emails:
                register_event['body'] = json.dumps({'email': email})
                response = cp.handle_register(register_event)
                assert response['statusCode'] == 400, f"Should reject: {email}"

    def test_registration_rejects_invalid_json(self, mock_aws, register_event):
        """Verify malformed JSON body is rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            register_event['body'] = 'not valid json{'
            response = cp.handle_register(register_event)
            assert response['statusCode'] == 400

    def test_registration_honeypot(self, mock_aws, register_event):
        """Verify honeypot field triggers silent fake success."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            register_event['body'] = json.dumps({
                'email': 'bot@spam.com',
                'website': 'http://spam.com'  # Honeypot
            })

            response = cp.handle_register(register_event)

            # Should return 200 to fool bots
            assert response['statusCode'] == 200
            # But should NOT store or send
            assert not mock_aws['credentials_table'].put_item.called
            assert not mock_aws['ses'].send_email.called

    def test_registration_already_provisioned_same_message(self, mock_aws, register_event):
        """Verify already-provisioned email gets same response (no enumeration)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            # Simulate existing provisioned record
            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'provisioned',
                    'auth0_client_id': 'existing_id'
                }
            }

            response = cp.handle_register(register_event)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'Check your email' in body['message']

    def test_registration_rate_limited(self, mock_aws, register_event):
        """Verify registration rate limiting works."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(
                return_value='Too many registration attempts. Please try again later.'
            )

            response = cp.handle_register(register_event)
            assert response['statusCode'] == 429

    def test_registration_ses_failure(self, mock_aws, register_event):
        """Verify SES failure returns 500."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']
            mock_aws['ses'].send_email.side_effect = Exception('SES timeout')

            response = cp.handle_register(register_event)
            assert response['statusCode'] == 500


# ---------------------------------------------------------------------------
# Verification Tests
# ---------------------------------------------------------------------------

class TestVerification:
    """Tests for the verification and credential provisioning flow."""

    def test_successful_verification_provisions_credentials(self, mock_aws, mock_auth0, verify_event):
        """Verify successful verification creates Auth0 app and returns credentials."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'data' in body
            assert body['data']['client_id'] == 'test_client_id_abc'
            assert body['data']['client_secret'] == 'test_client_secret_xyz'
            assert 'token_endpoint' in body['data']

            # Verify Auth0 was called
            mock_auth0['create'].assert_called_once_with('developer@example.com')
            mock_auth0['authorize'].assert_called_once_with('test_client_id_abc')

    def test_verification_updates_dynamodb(self, mock_aws, mock_auth0, verify_event):
        """Verify successful verification updates DynamoDB record."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            cp.handle_verify(verify_event)

            # Verify update removes token_hash and TTL
            update_call = mock_aws['credentials_table'].update_item.call_args
            expr = update_call[1]['UpdateExpression']
            assert 'REMOVE' in expr
            assert '#th' in expr
            assert '#ttl' in expr
            assert 'auth0_client_id' in expr

    def test_verification_sends_credentials_email(self, mock_aws, mock_auth0, verify_event):
        """Verify credentials email is sent after provisioning."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            cp.handle_verify(verify_event)

            # Should have sent at least 2 emails: credentials + notification
            assert mock_aws['ses'].send_email.call_count >= 2

    def test_verification_constant_time_comparison(self):
        """Verify hmac.compare_digest is used for timing-safe comparison."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            import inspect

            source = inspect.getsource(cp.handle_verify)
            assert 'hmac.compare_digest' in source, \
                "handle_verify must use hmac.compare_digest for timing-safe comparison"

    def test_verification_rejects_invalid_token(self, mock_aws, verify_event):
        """Verify invalid tokens are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': 'completely-different-hash',
                    'ttl': int(time.time()) + 3600
                }
            }

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400

    def test_verification_rejects_expired_token(self, mock_aws, verify_event):
        """Verify expired tokens are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) - 3600  # Expired
                }
            }

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400
            # Auth0 should NOT have been called
            # (no mock_auth0 fixture here, so no assertion needed)

    def test_verification_missing_email_rejected(self, mock_aws, verify_event):
        """Verify missing email returns error."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            verify_event['queryStringParameters'] = {'token': 'abc123'}

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400

    def test_verification_missing_token_rejected(self, mock_aws, verify_event):
        """Verify missing token returns error."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            verify_event['queryStringParameters'] = {'email': 'dev@example.com'}

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400

    def test_verification_nonexistent_email(self, mock_aws, verify_event):
        """Verify non-existent email returns generic error."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            mock_aws['credentials_table'].get_item.return_value = {}

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'invalid or has expired' in body['error']

    def test_verification_already_provisioned(self, mock_aws, verify_event):
        """Verify already-provisioned email returns generic error to prevent enumeration."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'provisioned',
                    'auth0_client_id': 'existing_client_id'
                }
            }

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            # Should return same generic error as invalid token (no enumeration)
            assert 'invalid or has expired' in body['error']
            assert 'client_id' not in body.get('data', {})

    def test_verification_rate_limited(self, mock_aws, verify_event):
        """Verify verification rate limiting works."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_verify_rate_limits = MagicMock(
                return_value='Too many verification attempts.'
            )

            response = cp.handle_verify(verify_event)
            assert response['statusCode'] == 429

    def test_auth0_failure_returns_500(self, mock_aws, verify_event):
        """Verify Auth0 API failure returns 500."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            with patch('credential_provisioner.create_auth0_m2m_app',
                        side_effect=RuntimeError('Auth0 API error: 500')):
                response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 500
            body = json.loads(response['body'])
            assert 'Failed to provision' in body['error']


# ---------------------------------------------------------------------------
# Error Uniformity Tests
# ---------------------------------------------------------------------------

class TestErrorUniformity:
    """Tests to ensure error messages don't leak information."""

    def test_verify_errors_are_uniform(self, mock_aws, verify_event):
        """Verify all verification failures return the same error message."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            expected_error = 'This verification link is invalid or has expired.'

            # Test 1: Email not found
            mock_aws['credentials_table'].get_item.return_value = {}
            response = cp.handle_verify(verify_event)
            body = json.loads(response['body'])
            assert body['error'] == expected_error

            # Test 2: Invalid token
            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': 'different-hash-value',
                    'ttl': int(time.time()) + 3600
                }
            }
            response = cp.handle_verify(verify_event)
            body = json.loads(response['body'])
            assert body['error'] == expected_error

            # Test 3: Expired TTL
            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) - 3600  # Expired
                }
            }
            response = cp.handle_verify(verify_event)
            body = json.loads(response['body'])
            assert body['error'] == expected_error


# ---------------------------------------------------------------------------
# Rate Limiting Tests
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """Tests for rate limiting functionality (atomic conditional updates)."""

    def _make_conditional_check_exception(self, mock_table):
        """Create a ConditionalCheckFailedException from a mock table."""
        from botocore.exceptions import ClientError
        return ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'Condition not met'}},
            'UpdateItem'
        )

    def test_registration_ip_rate_limit(self, mock_dynamodb):
        """Verify per-IP registration rate limit rejects at-limit requests."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.rate_table = mock_dynamodb['rate_table']

            # First update (window reset) fails — window is current
            # Second update (increment) fails — at limit
            exc = self._make_conditional_check_exception(mock_dynamodb['rate_table'])
            mock_dynamodb['rate_table'].update_item.side_effect = [exc, exc]
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(exc)

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is not None
            assert 'Too many' in result

    def test_registration_allows_within_limit(self, mock_dynamodb):
        """Verify requests within limit are allowed (window reset succeeds)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.rate_table = mock_dynamodb['rate_table']
            # First update succeeds — window was expired/new, counter reset to 1
            mock_dynamodb['rate_table'].update_item.return_value = {}
            mock_dynamodb['rate_table'].meta = MagicMock()

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is None

    def test_registration_allows_increment_within_limit(self, mock_dynamodb):
        """Verify requests within current window are allowed when under limit."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            from botocore.exceptions import ClientError

            cp.rate_table = mock_dynamodb['rate_table']

            exc = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'Condition not met'}},
                'UpdateItem'
            )
            # First update fails (window is current), second update succeeds (under limit)
            mock_dynamodb['rate_table'].update_item.side_effect = [exc, {}]
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(exc)

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is None

    def test_verify_ip_rate_limit(self, mock_dynamodb):
        """Verify per-IP verification rate limit rejects at-limit requests."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.rate_table = mock_dynamodb['rate_table']

            exc = self._make_conditional_check_exception(mock_dynamodb['rate_table'])
            mock_dynamodb['rate_table'].update_item.side_effect = [exc, exc]
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(exc)

            result = cp.check_verify_rate_limits('203.0.113.1')
            assert result is not None

    def test_rate_limit_fails_open(self, mock_dynamodb):
        """Verify rate limiting fails open on unexpected DynamoDB errors."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.rate_table = mock_dynamodb['rate_table']
            mock_dynamodb['rate_table'].update_item.side_effect = Exception('DynamoDB timeout')
            mock_dynamodb['rate_table'].meta = MagicMock()

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is None  # Should fail open


# ---------------------------------------------------------------------------
# Auth0 Management API Tests
# ---------------------------------------------------------------------------

class TestAuth0Management:
    """Tests for Auth0 Management API interactions."""

    def test_mgmt_token_cached(self):
        """Verify management token is cached after first fetch."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            # Reset cache
            cp._mgmt_token = None
            cp._mgmt_token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'mgmt_id',
                    'client_secret': 'mgmt_secret'
                })
            }

            token_response = json.dumps({
                'access_token': 'mgmt-token-abc',
                'expires_in': 86400
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = token_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', return_value=mock_resp):
                token = cp.get_mgmt_token()

            assert token == 'mgmt-token-abc'
            assert cp._mgmt_token == 'mgmt-token-abc'

    def test_cached_mgmt_token_returned(self):
        """Verify cached management token is returned without API call."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._mgmt_token = 'cached-mgmt-token'
            cp._mgmt_token_expires_at = time.time() + 3600

            with patch('boto3.client') as mock_client:
                token = cp.get_mgmt_token()

            assert token == 'cached-mgmt-token'
            mock_client.assert_not_called()

    def test_create_auth0_app_sends_correct_payload(self):
        """Verify Auth0 app creation sends the correct payload."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._mgmt_token = 'test-mgmt-token'
            cp._mgmt_token_expires_at = time.time() + 3600

            app_response = json.dumps({
                'client_id': 'new_client_id',
                'client_secret': 'new_client_secret'
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = app_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('urllib.request.urlopen', return_value=mock_resp) as mock_urlopen:
                result = cp.create_auth0_m2m_app('dev@example.com')

            assert result['client_id'] == 'new_client_id'
            assert result['client_secret'] == 'new_client_secret'

            # Verify the request payload
            call_args = mock_urlopen.call_args
            req = call_args[0][0]
            payload = json.loads(req.data)
            assert payload['app_type'] == 'non_interactive'
            assert 'dev@example.com' in payload['name']

    def test_authorize_app_sends_correct_grant(self):
        """Verify Auth0 grant creation sends correct payload."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._mgmt_token = 'test-mgmt-token'
            cp._mgmt_token_expires_at = time.time() + 3600
            cp.QURL_API_AUDIENCE = 'https://api.layerv.xyz'

            grant_response = json.dumps({
                'id': 'grant_id',
                'client_id': 'test_client',
                'audience': 'https://api.layerv.xyz'
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = grant_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('urllib.request.urlopen', return_value=mock_resp) as mock_urlopen:
                cp.authorize_auth0_app('test_client')

            call_args = mock_urlopen.call_args
            req = call_args[0][0]
            payload = json.loads(req.data)
            assert payload['client_id'] == 'test_client'
            assert payload['audience'] == 'https://api.layerv.xyz'

    def test_authorize_skipped_without_audience(self):
        """Verify grant creation raises error if audience is not configured."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.QURL_API_AUDIENCE = ''

            with pytest.raises(RuntimeError, match='QURL_API_AUDIENCE not configured'):
                cp.authorize_auth0_app('test_client')

    def test_authorize_failure_triggers_rollback_delete(self, mock_aws, verify_event):
        """Verify failed authorize_auth0_app triggers delete_auth0_app rollback."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            with patch('credential_provisioner.create_auth0_m2m_app') as mock_create, \
                 patch('credential_provisioner.authorize_auth0_app') as mock_auth, \
                 patch('credential_provisioner.delete_auth0_app') as mock_delete:
                mock_create.return_value = {
                    'client_id': 'orphan_client_id',
                    'client_secret': 'orphan_secret'
                }
                mock_auth.side_effect = RuntimeError('Auth0 grant error: 403')

                response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 500
            mock_delete.assert_called_once_with('orphan_client_id')

    def test_authorize_failure_rollback_delete_also_fails(self, mock_aws, verify_event):
        """Verify failed rollback delete is handled gracefully (no crash)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            with patch('credential_provisioner.create_auth0_m2m_app') as mock_create, \
                 patch('credential_provisioner.authorize_auth0_app') as mock_auth, \
                 patch('credential_provisioner.delete_auth0_app') as mock_delete:
                mock_create.return_value = {
                    'client_id': 'orphan_client_id',
                    'client_secret': 'orphan_secret'
                }
                mock_auth.side_effect = RuntimeError('Auth0 grant error: 403')
                mock_delete.side_effect = RuntimeError('Delete also failed')

                response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 500
            mock_delete.assert_called_once_with('orphan_client_id')
            body = json.loads(response['body'])
            assert 'Failed to provision' in body['error']


# ---------------------------------------------------------------------------
# CORS Tests
# ---------------------------------------------------------------------------

class TestCORS:
    """Tests for CORS origin handling."""

    def test_allowed_origin_reflected(self):
        """Verify allowed origins are reflected in response."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            allowed_origins = [
                'https://layerv.ai',
                'https://www.layerv.ai',
                'https://staging.layerv.ai',
            ]

            for origin in allowed_origins:
                event = {'headers': {'origin': origin}}
                result = cp.get_cors_origin(event)
                assert result == origin, f"Should reflect allowed origin: {origin}"

    def test_unknown_origin_gets_default(self):
        """Verify unknown origins get default, not reflection."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            event = {'headers': {'origin': 'https://evil.com'}}
            result = cp.get_cors_origin(event)
            assert result != 'https://evil.com'
            assert 'layerv.ai' in result

    def test_cors_headers_on_registration_response(self, mock_aws, register_event):
        """Verify CORS headers present on registration response."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.check_registration_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            response = cp.handle_register(register_event)
            headers = response['headers']

            assert 'Access-Control-Allow-Origin' in headers
            assert headers['Access-Control-Allow-Origin'] == 'https://layerv.ai'
            assert headers['Content-Type'] == 'application/json'

    def test_cors_headers_on_error_response(self, mock_aws, register_event):
        """Verify CORS headers present on error responses."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            register_event['body'] = json.dumps({'email': 'invalid'})
            response = cp.handle_register(register_event)

            assert response['statusCode'] == 400
            assert 'Access-Control-Allow-Origin' in response['headers']


# ---------------------------------------------------------------------------
# Email Template Tests
# ---------------------------------------------------------------------------

class TestEmailTemplates:
    """Tests for email template generation."""

    def test_verification_email_contains_link(self):
        """Verify verification email HTML contains the verify link."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            html = cp._verification_email_html('https://api.layerv.ai/credentials/verify?token=abc&email=test')
            assert 'https://api.layerv.ai/credentials/verify?token=abc' in html
            assert 'Verify' in html

    def test_credentials_email_contains_credentials(self):
        """Verify credentials email contains client_id and client_secret."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            html = cp._credentials_email_html('my_client_id', 'my_client_secret')
            assert 'my_client_id' in html
            assert 'my_client_secret' in html

    def test_credentials_text_email_contains_credentials(self):
        """Verify plain text credentials email contains credentials."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            text = cp._credentials_email_text('my_client_id', 'my_client_secret')
            assert 'my_client_id' in text
            assert 'my_client_secret' in text
            assert 'token' in text.lower()  # Should mention token endpoint


# ---------------------------------------------------------------------------
# Security Coverage Tests
# ---------------------------------------------------------------------------

class TestSecurityCoverage:
    """Tests for security-critical validation paths."""

    def test_verify_provisioning_race_condition(self, mock_aws, mock_auth0, verify_event):
        """Simulate race: two concurrent verify requests.

        The atomic pending->provisioning conditional update should cause the
        second request to get a ConditionalCheckFailedException, returning
        400 with the generic error message (not a 500 or duplicate credentials).
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            from botocore.exceptions import ClientError

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            # Simulate the second concurrent request: the atomic
            # pending->provisioning conditional update fails
            exc = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException',
                           'Message': 'The conditional request failed'}},
                'UpdateItem'
            )
            mock_aws['credentials_table'].update_item.side_effect = exc
            mock_aws['credentials_table'].meta = MagicMock()
            mock_aws['credentials_table'].meta.client.exceptions.ConditionalCheckFailedException = type(exc)

            response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'invalid or has expired' in body['error']
            # Auth0 should NOT have been called since the claim failed
            mock_auth0['create'].assert_not_called()

    def test_verify_provisioning_status_returns_generic_error(self, mock_aws, verify_event):
        """Item with status='provisioning' should return 400 with generic error.

        This covers the case where a request is in-flight (being provisioned)
        and another verify attempt arrives. It should look identical to an
        invalid token response to prevent enumeration.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'provisioning',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert body['error'] == 'This verification link is invalid or has expired.'

    def test_honeypot_company_field(self, mock_aws, register_event):
        """Sending company field (honeypot) should return 200 silently.

        The 'company' field is a hidden honeypot -- bots auto-fill it.
        The handler should return a fake success with no DynamoDB or SES calls.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            register_event['body'] = json.dumps({
                'email': 'bot@spam.com',
                'company': 'spam'
            })

            response = cp.handle_register(register_event)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'Check your email' in body['message']
            # No DynamoDB writes or emails should have been sent
            assert not mock_aws['credentials_table'].put_item.called
            assert not mock_aws['ses'].send_email.called

    def test_honeypot_website_field(self, mock_aws, register_event):
        """Sending website field (backward-compat honeypot) should behave identically.

        The 'website' field is the original honeypot. Both 'company' and
        'website' should trigger the silent trap.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            register_event['body'] = json.dumps({
                'email': 'bot@spam.com',
                'website': 'http://spam.com'
            })

            response = cp.handle_register(register_event)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'Check your email' in body['message']
            assert not mock_aws['credentials_table'].put_item.called
            assert not mock_aws['ses'].send_email.called

    def test_audience_empty_raises_error(self):
        """authorize_auth0_app with empty QURL_API_AUDIENCE should raise RuntimeError.

        This prevents silently creating apps without an audience grant,
        which would result in unusable credentials.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.QURL_API_AUDIENCE = ''

            with pytest.raises(RuntimeError, match='QURL_API_AUDIENCE not configured'):
                cp.authorize_auth0_app('test_client_id')

    def test_null_headers_no_crash(self):
        """Event with headers: None should not crash get_cors_origin.

        API Gateway can send None for headers in edge cases (e.g., health
        checks from infrastructure). The function should handle this gracefully.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            result = cp.get_cors_origin({'headers': None})

            # Should return a valid default origin, not crash
            assert result is not None
            assert 'layerv.ai' in result

    def test_verify_returns_audience_in_response(self, mock_aws, mock_auth0, verify_event):
        """Successful verification should include audience field in response data.

        The audience is needed by developers to configure their token requests.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            token = 'test-token-123'
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            cp.check_verify_rate_limits = MagicMock(return_value=None)
            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']

            mock_aws['credentials_table'].get_item.return_value = {
                'Item': {
                    'email': 'developer@example.com',
                    'status': 'pending',
                    'token_hash': token_hash,
                    'ttl': int(time.time()) + 3600
                }
            }

            response = cp.handle_verify(verify_event)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'data' in body
            assert 'audience' in body['data']
            assert body['data']['audience'] == cp.QURL_API_AUDIENCE


# ---------------------------------------------------------------------------
# Token Refresh Race Condition Tests
# ---------------------------------------------------------------------------

class TestTokenRefreshRace:
    """Tests for concurrent management token refresh behavior."""

    def test_concurrent_mgmt_token_refresh(self):
        """Verify concurrent calls to get_mgmt_token with expired cache both succeed.

        When two Lambda invocations hit an expired token simultaneously, both
        should be able to fetch a new token. The second call overwrites the
        cache but returns a valid token either way.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._mgmt_token = None
            cp._mgmt_token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'mgmt_id',
                    'client_secret': 'mgmt_secret'
                })
            }

            token_response = json.dumps({
                'access_token': 'concurrent-mgmt-token',
                'expires_in': 86400
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = token_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', return_value=mock_resp):
                token1 = cp.get_mgmt_token()
                # Reset cache to simulate second concurrent call
                cp._mgmt_token = None
                cp._mgmt_token_expires_at = 0
                token2 = cp.get_mgmt_token()

            assert token1 == 'concurrent-mgmt-token'
            assert token2 == 'concurrent-mgmt-token'

    def test_auth0_mgmt_token_endpoint_failure_raises(self):
        """Verify Auth0 management token endpoint failure raises RuntimeError."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            import urllib.error

            cp._mgmt_token = None
            cp._mgmt_token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'mgmt_id',
                    'client_secret': 'mgmt_secret'
                })
            }

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', side_effect=urllib.error.URLError('Connection refused')):
                with pytest.raises(RuntimeError, match='Failed to obtain Auth0 management token'):
                    cp.get_mgmt_token()


# ---------------------------------------------------------------------------
# DynamoDB Throttling Tests
# ---------------------------------------------------------------------------

class TestDynamoDBThrottling:
    """Tests for DynamoDB throttling behavior in rate limiting."""

    def test_registration_rate_limit_throttling_fails_open(self, mock_dynamodb):
        """Verify ProvisionedThroughputExceededException fails open on registration rate check."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            from botocore.exceptions import ClientError

            cp.rate_table = mock_dynamodb['rate_table']

            # Use a distinct subclass for ConditionalCheckFailed so
            # throttle errors (plain ClientError) are NOT caught by
            # the inner except clause
            class MockCondCheckFailed(ClientError):
                pass

            throttle_err = ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException',
                           'Message': 'Rate exceeded'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].update_item.side_effect = throttle_err
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = MockCondCheckFailed

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is None  # Should fail open

    def test_verify_rate_limit_throttling_fails_open(self, mock_dynamodb):
        """Verify ProvisionedThroughputExceededException fails open on verify rate check."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            from botocore.exceptions import ClientError

            cp.rate_table = mock_dynamodb['rate_table']

            class MockCondCheckFailed(ClientError):
                pass

            throttle_err = ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException',
                           'Message': 'Rate exceeded'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].update_item.side_effect = throttle_err
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = MockCondCheckFailed

            result = cp.check_verify_rate_limits('203.0.113.1')
            assert result is None  # Should fail open

    def test_dynamodb_internal_error_fails_open(self, mock_dynamodb):
        """Verify DynamoDB InternalServerError fails open on registration rate check."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            from botocore.exceptions import ClientError

            cp.rate_table = mock_dynamodb['rate_table']

            class MockCondCheckFailed(ClientError):
                pass

            internal_err = ClientError(
                {'Error': {'Code': 'InternalServerError',
                           'Message': 'Internal error'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].update_item.side_effect = internal_err
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = MockCondCheckFailed

            result = cp.check_registration_rate_limits('203.0.113.1')
            assert result is None  # Should fail open
