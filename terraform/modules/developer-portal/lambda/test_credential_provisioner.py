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
    import sys
    # Remove module so it gets re-imported within the patched context
    sys.modules.pop('credential_provisioner', None)
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import credential_provisioner
        importlib.reload(credential_provisioner)
        yield


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
# API Key Generation Tests
# ---------------------------------------------------------------------------

class TestGenerateApiKey:
    """Tests for generate_api_key() function."""

    def test_key_has_correct_prefix(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            result = cp.generate_api_key()
            assert result['api_key'].startswith('lv_live_')

    def test_key_hash_is_sha256(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            result = cp.generate_api_key()
            expected = hashlib.sha256(result['api_key'].encode()).hexdigest()
            assert result['key_hash'] == expected

    def test_key_prefix_masks_random_portion(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            result = cp.generate_api_key()
            # Prefix should start with "lv_live_", show 4 random chars, end with "..."
            assert result['key_prefix'].startswith('lv_live_')
            assert result['key_prefix'].endswith('...')
            # Should not expose more than 4 chars of the random portion
            assert len(result['key_prefix']) == len('lv_live_') + 4 + 3  # prefix + 4 chars + "..."

    def test_key_id_has_prefix(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            result = cp.generate_api_key()
            assert result['key_id'].startswith('key_')

    def test_keys_are_unique(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            key1 = cp.generate_api_key()
            key2 = cp.generate_api_key()
            assert key1['api_key'] != key2['api_key']
            assert key1['key_hash'] != key2['key_hash']

    def test_key_length_is_sufficient(self):
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            result = cp.generate_api_key()
            # lv_live_ (8) + token_urlsafe(32) (~43) = ~51 chars minimum
            assert len(result['api_key']) > 40


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

    def test_verify_routed(self, mock_aws, verify_event):
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

    def test_successful_verification_provisions_api_key(self, mock_aws, verify_event):
        """Verify successful verification generates API key and returns it."""
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
            assert body['data']['api_key'].startswith('lv_live_')
            assert 'api_url' in body['data']
            assert 'note' in body['data']

    def test_verification_updates_dynamodb(self, mock_aws, verify_event):
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

            # Verify update removes token_hash and TTL, stores api_key_id
            # update_item is called twice: first for pending→provisioning, then for final update
            calls = mock_aws['credentials_table'].update_item.call_args_list
            final_call = calls[-1]
            expr = final_call[1]['UpdateExpression']
            assert 'REMOVE' in expr
            assert '#th' in expr
            assert '#ttl' in expr
            assert 'api_key_id' in expr

    def test_verification_sends_credentials_email(self, mock_aws, verify_event):
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

            # Should have sent at least 2 emails: API key + notification
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

    def test_key_generation_failure_returns_500(self, mock_aws, verify_event):
        """Verify API key generation failure returns 500."""
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

            with patch('credential_provisioner.generate_api_key',
                        side_effect=RuntimeError('Key generation error')):
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
# _atomic_rate_check Direct Unit Tests
# ---------------------------------------------------------------------------

class TestAtomicRateCheck:
    """Direct tests for _atomic_rate_check edge cases.

    The rate limiting tests above exercise _atomic_rate_check through the
    check_*_rate_limits wrappers. These tests exercise the function directly
    to cover specific edge cases and verify the two-phase DynamoDB logic.
    """

    def _setup_rate_table(self, mock_dynamodb, side_effects):
        """Configure rate_table mock and return (cp, exc_class)."""
        from botocore.exceptions import ClientError
        exc = ClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'Condition not met'}},
            'UpdateItem',
        )
        mock_dynamodb['rate_table'].update_item.side_effect = side_effects(exc)
        mock_dynamodb['rate_table'].meta = MagicMock()
        mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(exc)
        return type(exc)

    def test_new_key_resets_window_and_allows(self, mock_dynamodb):
        """First request for a key: window reset succeeds → allowed."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            # First update (window reset) succeeds — new key or expired window
            mock_dynamodb['rate_table'].update_item.return_value = {}
            mock_dynamodb['rate_table'].meta = MagicMock()

            result = cp._atomic_rate_check('test:key', 5, 3600)
            assert result is True
            # Only one call — didn't need to increment
            assert mock_dynamodb['rate_table'].update_item.call_count == 1

    def test_current_window_increment_succeeds(self, mock_dynamodb):
        """Window is current, under limit: increment succeeds → allowed."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            self._setup_rate_table(mock_dynamodb, lambda exc: [exc, {}])

            result = cp._atomic_rate_check('test:key', 5, 3600)
            assert result is True
            assert mock_dynamodb['rate_table'].update_item.call_count == 2

    def test_current_window_at_limit_rejected(self, mock_dynamodb):
        """Window is current, at limit: increment fails → rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            self._setup_rate_table(mock_dynamodb, lambda exc: [exc, exc])

            result = cp._atomic_rate_check('test:key', 5, 3600)
            assert result is False

    def test_window_reset_sets_correct_ttl(self, mock_dynamodb):
        """Window reset sets TTL to now + window_seconds."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            mock_dynamodb['rate_table'].update_item.return_value = {}
            mock_dynamodb['rate_table'].meta = MagicMock()

            cp._atomic_rate_check('test:key', 5, 3600)

            call_kwargs = mock_dynamodb['rate_table'].update_item.call_args[1]
            ttl_val = call_kwargs['ExpressionAttributeValues'][':ttl']
            now_val = call_kwargs['ExpressionAttributeValues'][':now']
            assert ttl_val == now_val + 3600

    def test_increment_passes_correct_limit(self, mock_dynamodb):
        """Increment phase passes the limit value in ConditionExpression."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            self._setup_rate_table(mock_dynamodb, lambda exc: [exc, {}])

            cp._atomic_rate_check('test:key', 42, 3600)

            # Second call is the increment
            second_call = mock_dynamodb['rate_table'].update_item.call_args_list[1]
            assert second_call[1]['ExpressionAttributeValues'][':limit'] == 42

    def test_unexpected_error_on_reset_propagates(self, mock_dynamodb):
        """Non-ConditionalCheck error on first update propagates to caller."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp
            cp.rate_table = mock_dynamodb['rate_table']

            mock_dynamodb['rate_table'].update_item.side_effect = Exception('InternalServerError')
            mock_dynamodb['rate_table'].meta = MagicMock()
            cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = cond_exc

            # The exception propagates (caller's try/except handles it)
            with pytest.raises(Exception, match='InternalServerError'):
                cp._atomic_rate_check('test:key', 5, 3600)


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

    def test_credentials_email_contains_api_key(self):
        """Verify credentials email contains the API key."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            html = cp._credentials_email_html('lv_live_test_key_abc')
            assert 'lv_live_test_key_abc' in html
            assert 'API Key' in html

    def test_credentials_text_email_contains_api_key(self):
        """Verify plain text credentials email contains the API key."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            text = cp._credentials_email_text('lv_live_test_key_abc')
            assert 'lv_live_test_key_abc' in text
            assert 'API Key' in text


# ---------------------------------------------------------------------------
# Security Coverage Tests
# ---------------------------------------------------------------------------

class TestSecurityCoverage:
    """Tests for security-critical validation paths."""

    def test_verify_provisioning_race_condition(self, mock_aws, verify_event):
        """Simulate race: two concurrent verify requests.

        The atomic pending->provisioning conditional update should cause the
        second request to get a ConditionalCheckFailedException, returning
        400 with the generic error message (not a 500 or duplicate keys).
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

    def test_verify_returns_api_url_in_response(self, mock_aws, verify_event):
        """Successful verification should include api_url field in response data.

        The API URL is needed by developers to configure their API calls.
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
            assert 'api_url' in body['data']
            assert body['data']['api_url'] == cp.QURL_API_URL


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


# ---------------------------------------------------------------------------
# CI Bypass Tests
# ---------------------------------------------------------------------------

class TestCIBypass:
    """Tests for CI bypass key functionality."""

    def test_ci_bypass_with_valid_key(self):
        """Verify CI bypass returns True when X-CI-Key matches."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = 'test-secret-key'
            cp._ci_bypass_key_expires_at = time.time() + 300
            cp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'x-ci-key': 'test-secret-key'},
            }

            assert cp._is_ci_bypass(event) is True

    def test_ci_bypass_with_invalid_key(self):
        """Verify CI bypass returns False when X-CI-Key doesn't match."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = 'test-secret-key'
            cp._ci_bypass_key_expires_at = time.time() + 300
            cp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'x-ci-key': 'wrong-key'},
            }

            assert cp._is_ci_bypass(event) is False

    def test_ci_bypass_with_no_header(self):
        """Verify CI bypass returns False when header is missing."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = 'test-secret-key'
            cp._ci_bypass_key_expires_at = time.time() + 300
            cp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'origin': 'https://layerv.ai'},
            }

            assert cp._is_ci_bypass(event) is False

    def test_ci_bypass_disabled_when_no_secret_name(self):
        """Verify CI bypass returns False when CI_BYPASS_SECRET_NAME is empty."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = None
            cp._ci_bypass_key_expires_at = 0
            cp.CI_BYPASS_SECRET_NAME = ''

            event = {
                'headers': {'x-ci-key': 'some-key'},
            }

            assert cp._is_ci_bypass(event) is False

    def test_ci_bypass_skips_rate_limiting_register(self, mock_aws, register_event):
        """Verify that CI bypass skips rate limiting on register."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp.credentials_table = mock_aws['credentials_table']
            cp.ses = mock_aws['ses']
            cp._ci_bypass_key = 'ci-key-123'
            cp._ci_bypass_key_expires_at = time.time() + 300
            cp.CI_BYPASS_SECRET_NAME = 'some-secret'

            # Set rate limiter to always reject
            cp.check_registration_rate_limits = MagicMock(return_value='Rate limited')

            # Add CI bypass header
            register_event['headers']['x-ci-key'] = 'ci-key-123'

            response = cp.handle_register(register_event)
            # Should NOT be 429 — bypass skips rate limiting
            assert response['statusCode'] != 429
            # Rate limit function should not have been called
            cp.check_registration_rate_limits.assert_not_called()

    def test_ci_bypass_key_ttl_expiry(self):
        """Verify expired key triggers re-fetch from Secrets Manager."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = 'old-key'
            cp._ci_bypass_key_expires_at = time.time() - 1  # Expired
            cp.CI_BYPASS_SECRET_NAME = 'my-secret'

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {'SecretString': 'new-key'}

            with patch('credential_provisioner.boto3.client', return_value=mock_sm):
                result = cp._get_ci_bypass_key()

            assert result == 'new-key'
            assert cp._ci_bypass_key == 'new-key'
            mock_sm.get_secret_value.assert_called_once_with(SecretId='my-secret')

    def test_ci_bypass_key_cached_within_ttl(self):
        """Verify cached key is returned within TTL without SM call."""
        with patch('boto3.resource'), patch('boto3.client'):
            import credential_provisioner as cp

            cp._ci_bypass_key = 'cached-key'
            cp._ci_bypass_key_expires_at = time.time() + 300
            cp.CI_BYPASS_SECRET_NAME = 'my-secret'

            with patch('credential_provisioner.boto3.client') as mock_boto:
                result = cp._get_ci_bypass_key()

            assert result == 'cached-key'
            mock_boto.assert_not_called()
