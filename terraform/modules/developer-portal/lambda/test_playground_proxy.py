"""
Tests for QURL Playground Proxy Lambda.

Run with: pytest terraform/modules/developer-portal/lambda/test_playground_proxy.py -v
"""

import pytest
import json
import socket
import time
import io
import urllib.error
from unittest.mock import MagicMock, patch, ANY


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_module():
    """Import the module with mocked AWS clients."""
    with patch('boto3.resource'), patch('boto3.client'):
        import sys
        if 'playground_proxy' in sys.modules:
            del sys.modules['playground_proxy']


@pytest.fixture
def mock_dynamodb():
    """Mock DynamoDB table operations."""
    with patch('playground_proxy.rate_table') as mock_rate_table:
        mock_rate_table.get_item = MagicMock(return_value={})
        mock_rate_table.put_item = MagicMock()
        mock_rate_table.update_item = MagicMock()
        yield {'rate_table': mock_rate_table}


@pytest.fixture
def mock_token():
    """Mock the M2M token retrieval."""
    with patch('playground_proxy.get_m2m_token', return_value='test-m2m-token'):
        yield


@pytest.fixture
def mock_proxy():
    """Mock the QURL API proxy calls."""
    with patch('playground_proxy.proxy_to_qurl_api') as mock:
        mock.return_value = (200, {'data': {'resource_id': 'r_test123', 'qurl_link': 'https://qurl.link/#at_test'}})
        yield mock


@pytest.fixture
def create_event():
    """Base event for creating a QURL."""
    return {
        'requestContext': {
            'http': {
                'method': 'POST',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/qurl',
        'headers': {'origin': 'https://layerv.ai'},
        'pathParameters': None,
        'body': json.dumps({
            'target_url': 'https://example.com',
            'expires_in': '15m',
            'description': 'Test QURL'
        })
    }


@pytest.fixture
def get_event():
    """Base event for getting QURL status."""
    return {
        'requestContext': {
            'http': {
                'method': 'GET',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/qurl/r_test123',
        'headers': {'origin': 'https://layerv.ai'},
        'pathParameters': {'id': 'r_test123'},
        'body': None
    }


@pytest.fixture
def delete_event():
    """Base event for deleting/revoking a QURL."""
    return {
        'requestContext': {
            'http': {
                'method': 'DELETE',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/qurl/r_test123',
        'headers': {'origin': 'https://layerv.ai'},
        'pathParameters': {'id': 'r_test123'},
        'body': None
    }


@pytest.fixture
def mint_event():
    """Base event for minting a link."""
    return {
        'requestContext': {
            'http': {
                'method': 'POST',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/qurl/r_test123/mint',
        'headers': {'origin': 'https://layerv.ai'},
        'pathParameters': {'id': 'r_test123'},
        'body': json.dumps({})
    }


@pytest.fixture
def health_event():
    """Base event for health check."""
    return {
        'requestContext': {
            'http': {
                'method': 'GET',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/health',
        'headers': {'origin': 'https://layerv.ai'},
        'pathParameters': None,
        'body': None
    }


# ---------------------------------------------------------------------------
# URL Validation Tests
# ---------------------------------------------------------------------------

class TestURLValidation:
    """Tests for target URL validation."""

    def test_valid_https_url(self):
        """Verify valid HTTPS URLs are accepted."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            valid_urls = [
                'https://example.com',
                'https://example.com/path/to/resource',
                'https://subdomain.example.com',
                'https://example.com:8443/path',
                'https://example.com/path?query=value',
            ]

            # Mock DNS resolution to return a public IP
            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs):
                for url in valid_urls:
                    is_valid, error = pp.validate_target_url(url)
                    assert is_valid, f"Should accept: {url}, got error: {error}"

    def test_reject_http_url(self):
        """Verify HTTP (non-TLS) URLs are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            is_valid, error = pp.validate_target_url('http://example.com')
            assert not is_valid
            assert 'HTTPS' in error

    def test_reject_other_schemes(self):
        """Verify non-HTTP(S) schemes are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            schemes = [
                'ftp://example.com',
                'javascript:alert(1)',
                'data:text/html,<h1>hi</h1>',
                'file:///etc/passwd',
            ]

            for url in schemes:
                is_valid, error = pp.validate_target_url(url)
                assert not is_valid, f"Should reject: {url}"

    def test_reject_private_ipv4(self):
        """Verify private IPv4 addresses are rejected (SSRF prevention)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            private_ips = [
                'https://10.0.0.1',
                'https://10.255.255.255',
                'https://172.16.0.1',
                'https://172.31.255.255',
                'https://192.168.1.1',
                'https://192.168.0.1',
            ]

            for url in private_ips:
                is_valid, error = pp.validate_target_url(url)
                assert not is_valid, f"Should reject private IP: {url}"
                assert 'Private' in error or 'internal' in error.lower()

    def test_reject_loopback(self):
        """Verify loopback addresses are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            loopback_urls = [
                'https://127.0.0.1',
                'https://127.0.0.1:8080',
            ]

            for url in loopback_urls:
                is_valid, error = pp.validate_target_url(url)
                assert not is_valid, f"Should reject loopback: {url}"

    def test_reject_localhost(self):
        """Verify localhost hostname is rejected (before DNS resolution)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            # localhost should be blocked by hostname check, DNS should NOT be called
            with patch('socket.getaddrinfo') as mock_dns:
                is_valid, error = pp.validate_target_url('https://localhost')
                assert not is_valid
                assert 'Internal' in error
                mock_dns.assert_not_called()

    def test_reject_metadata_service(self):
        """Verify cloud metadata service addresses are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            metadata_urls = [
                'https://metadata.google.internal',
                'https://169.254.169.254',
            ]

            for url in metadata_urls:
                is_valid, error = pp.validate_target_url(url)
                assert not is_valid, f"Should reject metadata URL: {url}"

    def test_reject_internal_hostnames(self):
        """Verify .internal and .local hostnames are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            internal_urls = [
                'https://server.nhp.sandbox.internal',
                'https://myservice.local',
            ]

            for url in internal_urls:
                is_valid, error = pp.validate_target_url(url)
                assert not is_valid, f"Should reject internal hostname: {url}"

    def test_reject_empty_url(self):
        """Verify empty URL is rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            is_valid, error = pp.validate_target_url('')
            assert not is_valid

            is_valid, error = pp.validate_target_url(None)
            assert not is_valid

    def test_reject_no_hostname(self):
        """Verify URLs without hostname are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            is_valid, error = pp.validate_target_url('https://')
            assert not is_valid


# ---------------------------------------------------------------------------
# TTL Capping Tests
# ---------------------------------------------------------------------------

class TestTTLCapping:
    """Tests for TTL/duration capping logic."""

    def test_ttl_within_limit_unchanged(self):
        """Verify TTL within limit passes through unchanged."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            assert pp.cap_ttl('15m') == '15m'
            assert pp.cap_ttl('30m') == '30m'
            assert pp.cap_ttl('5m') == '5m'
            assert pp.cap_ttl('1800s') == '1800s'  # 30 minutes in seconds

    def test_ttl_exceeding_limit_capped(self):
        """Verify TTL exceeding 30m is capped to 30m."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            assert pp.cap_ttl('1h') == '30m'
            assert pp.cap_ttl('2h') == '30m'
            assert pp.cap_ttl('168h') == '30m'
            assert pp.cap_ttl('45m') == '30m'
            assert pp.cap_ttl('31m') == '30m'

    def test_ttl_empty_or_none_gets_default(self):
        """Verify empty/None TTL gets the max default."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            assert pp.cap_ttl('') == '30m'
            assert pp.cap_ttl(None) == '30m'

    def test_ttl_unparseable_gets_default(self):
        """Verify unparseable TTL strings get the max default."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            assert pp.cap_ttl('invalid') == '30m'
            assert pp.cap_ttl('forever') == '30m'

    def test_duration_parsing(self):
        """Verify duration string parsing works correctly."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            assert pp.parse_duration_minutes('30m') == 30
            assert pp.parse_duration_minutes('1h') == 60
            assert pp.parse_duration_minutes('1h30m') == 90
            assert pp.parse_duration_minutes('90s') == 1.5
            assert pp.parse_duration_minutes('') is None
            assert pp.parse_duration_minutes(None) is None
            assert pp.parse_duration_minutes('invalid') is None


# ---------------------------------------------------------------------------
# Rate Limiting Tests
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """Tests for rate limiting functionality."""

    def test_ip_rate_limit_exceeded(self, mock_dynamodb):
        """Verify per-IP rate limit blocks when exceeded."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            # Simulate atomic rate check: window is current (first update fails condition),
            # then increment fails because count >= limit
            from botocore.exceptions import ClientError
            cond_err = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'condition'}},
                'UpdateItem'
            )
            # First call: window reset fails (window is current)
            # Second call: increment fails (at limit)
            mock_dynamodb['rate_table'].update_item.side_effect = [cond_err, cond_err]
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(cond_err)

            result = pp.check_rate_limits('203.0.113.1')
            assert result is not None
            assert 'Too many requests' in result

    def test_global_rate_limit_exceeded(self, mock_dynamodb):
        """Verify global rate limit blocks when exceeded."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            from botocore.exceptions import ClientError
            cond_err = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'condition'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(cond_err)

            call_count = [0]
            def mock_update_item(**kwargs):
                call_count[0] += 1
                # First two calls: IP rate check (window reset fails, increment succeeds)
                if call_count[0] == 1:
                    raise cond_err  # IP window reset fails (current window)
                if call_count[0] == 2:
                    return  # IP increment succeeds (under limit)
                # Next two calls: global rate check (window reset fails, increment fails)
                if call_count[0] == 3:
                    raise cond_err  # Global window reset fails (current window)
                if call_count[0] == 4:
                    raise cond_err  # Global increment fails (at limit)

            mock_dynamodb['rate_table'].update_item.side_effect = mock_update_item

            result = pp.check_rate_limits('203.0.113.1')
            assert result is not None
            assert 'temporarily unavailable' in result.lower()

    def test_rate_limit_allows_within_limits(self, mock_dynamodb):
        """Verify requests within limits are allowed."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            from botocore.exceptions import ClientError
            cond_err = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'condition'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(cond_err)

            # Window reset fails (current window), but increment succeeds (under limit)
            def mock_update(**kwargs):
                if 'ConditionExpression' in kwargs:
                    expr = kwargs['ConditionExpression']
                    if 'window_start' in str(expr):
                        raise cond_err  # Window is current
                return {}  # Increment succeeds

            mock_dynamodb['rate_table'].update_item.side_effect = mock_update

            result = pp.check_rate_limits('203.0.113.1')
            assert result is None  # Not rate limited

    def test_rate_limit_expired_window_allows(self, mock_dynamodb):
        """Verify expired rate limit windows are treated as fresh (reset succeeds)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            from botocore.exceptions import ClientError
            cond_err = ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'condition'}},
                'UpdateItem'
            )
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = type(cond_err)

            # Window reset succeeds (expired window) for all calls
            mock_dynamodb['rate_table'].update_item.return_value = {}

            result = pp.check_rate_limits('203.0.113.1')
            assert result is None  # Expired window, should allow

    def test_rate_limit_fails_open(self, mock_dynamodb):
        """Verify rate limiting fails open on DynamoDB errors."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            from botocore.exceptions import ClientError
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = ClientError
            mock_dynamodb['rate_table'].update_item.side_effect = Exception('DynamoDB timeout')

            result = pp.check_rate_limits('203.0.113.1')
            assert result is None  # Should fail open

    def test_rate_limit_increments_counters(self, mock_dynamodb):
        """Verify rate limit check calls update_item for both IP and global counters."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            from botocore.exceptions import ClientError
            mock_dynamodb['rate_table'].meta = MagicMock()
            mock_dynamodb['rate_table'].meta.client.exceptions.ConditionalCheckFailedException = ClientError

            # All updates succeed (new keys or expired windows)
            mock_dynamodb['rate_table'].update_item.return_value = {}

            pp.check_rate_limits('203.0.113.1')

            # Each rate check does 1 update_item (window reset succeeds).
            # IP check = 1 call, Global check = 1 call = 2 total
            assert mock_dynamodb['rate_table'].update_item.call_count == 2


# ---------------------------------------------------------------------------
# Token Caching Tests
# ---------------------------------------------------------------------------

class TestTokenCaching:
    """Tests for Auth0 M2M token caching."""

    def test_token_cached_on_first_call(self):
        """Verify token is fetched and cached on first call."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            # Reset cache
            pp._cached_token = None
            pp._token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'test_id',
                    'client_secret': 'test_secret',
                    'audience': 'https://api.layerv.xyz'
                })
            }

            token_response = json.dumps({
                'access_token': 'fresh-token-abc',
                'expires_in': 86400
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = token_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', return_value=mock_resp):
                token = pp.get_m2m_token()

            assert token == 'fresh-token-abc'
            assert pp._cached_token == 'fresh-token-abc'
            assert pp._token_expires_at > time.time()

    def test_cached_token_returned_on_subsequent_calls(self):
        """Verify cached token is returned without API call."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._cached_token = 'cached-token-xyz'
            pp._token_expires_at = time.time() + 3600  # Valid for 1 more hour

            with patch('boto3.client') as mock_client:
                token = pp.get_m2m_token()

            assert token == 'cached-token-xyz'
            # Should NOT have created a new secrets manager client
            mock_client.assert_not_called()

    def test_expired_token_refreshed(self):
        """Verify expired token triggers a new token fetch."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._cached_token = 'expired-token'
            pp._token_expires_at = time.time() - 100  # Already expired

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'test_id',
                    'client_secret': 'test_secret',
                    'audience': 'https://api.layerv.xyz'
                })
            }

            token_response = json.dumps({
                'access_token': 'new-fresh-token',
                'expires_in': 86400
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = token_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', return_value=mock_resp):
                token = pp.get_m2m_token()

            assert token == 'new-fresh-token'


# ---------------------------------------------------------------------------
# Endpoint Routing Tests
# ---------------------------------------------------------------------------

class TestEndpointRouting:
    """Tests for request routing to correct handlers."""

    def test_create_qurl_routed(self, mock_dynamodb, mock_proxy, create_event):
        """Verify POST /playground/qurl routes to create handler."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once()
            call_args = mock_proxy.call_args
            assert call_args[0][0] == 'POST'
            assert call_args[0][1] == '/v1/qurl'

    def test_get_qurl_routed(self, mock_dynamodb, mock_proxy, get_event):
        """Verify GET /playground/qurl/{id} routes to get handler."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(get_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once()
            call_args = mock_proxy.call_args
            assert call_args[0][0] == 'GET'
            assert '/v1/qurls/r_test123' in call_args[0][1]

    def test_delete_qurl_routed(self, mock_dynamodb, mock_proxy, delete_event):
        """Verify DELETE /playground/qurl/{id} routes to delete handler."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(delete_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once()
            call_args = mock_proxy.call_args
            assert call_args[0][0] == 'DELETE'
            assert '/v1/qurls/r_test123' in call_args[0][1]

    def test_mint_link_routed(self, mock_dynamodb, mock_proxy, mint_event):
        """Verify POST /playground/qurl/{id}/mint routes to mint handler."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(mint_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once()
            call_args = mock_proxy.call_args
            assert call_args[0][0] == 'POST'
            assert '/v1/qurls/r_test123/mint_link' in call_args[0][1]

    def test_health_check_routed(self, health_event):
        """Verify GET /playground/health returns healthy status."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            response = pp.lambda_handler(health_event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['status'] == 'healthy'
            assert body['service'] == 'qurl-playground-proxy'

    def test_unknown_path_returns_404(self):
        """Verify unknown paths return 404."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            event = {
                'requestContext': {'http': {'method': 'GET', 'sourceIp': '1.2.3.4'}},
                'rawPath': '/unknown/path',
                'headers': {'origin': 'https://layerv.ai'},
                'pathParameters': None,
                'body': None
            }

            response = pp.lambda_handler(event, None)
            assert response['statusCode'] == 404

    def test_options_returns_200(self):
        """Verify OPTIONS preflight returns 200."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            event = {
                'requestContext': {'http': {'method': 'OPTIONS', 'sourceIp': '1.2.3.4'}},
                'rawPath': '/playground/qurl',
                'headers': {'origin': 'https://layerv.ai'},
                'pathParameters': None,
                'body': None
            }

            response = pp.lambda_handler(event, None)
            assert response['statusCode'] == 200

    def test_prod_prefix_stripped(self, mock_dynamodb, health_event):
        """Verify /prod prefix is stripped from path."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            health_event['rawPath'] = '/prod/playground/health'

            response = pp.lambda_handler(health_event, None)
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['status'] == 'healthy'


# ---------------------------------------------------------------------------
# Create Handler Tests
# ---------------------------------------------------------------------------

class TestCreateHandler:
    """Tests for the create QURL handler logic."""

    def test_create_enforces_playground_metadata(self, mock_dynamodb, mock_proxy, create_event):
        """Verify all created QURLs are tagged with playground source."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            pp.lambda_handler(create_event, None)

            call_args = mock_proxy.call_args
            body = call_args[1]['body'] if 'body' in call_args[1] else call_args[0][2]
            assert body['metadata']['source'] == 'playground'

    def test_create_caps_ttl(self, mock_dynamodb, mock_proxy, create_event):
        """Verify TTL is capped to 30m on create."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            # Request with 2h TTL
            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '2h'
            })

            pp.lambda_handler(create_event, None)

            call_args = mock_proxy.call_args
            body = call_args[1]['body'] if 'body' in call_args[1] else call_args[0][2]
            assert body['expires_in'] == '30m'

    def test_create_rejects_http_url(self, mock_dynamodb, create_event):
        """Verify HTTP URLs are rejected on create."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'http://example.com',
                'expires_in': '15m'
            })

            response = pp.lambda_handler(create_event, None)
            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'HTTPS' in body['error']

    def test_create_rejects_invalid_json(self, mock_dynamodb, create_event):
        """Verify invalid JSON body is rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            create_event['body'] = 'not valid json{'

            response = pp.lambda_handler(create_event, None)
            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'Invalid JSON' in body['error']

    def test_create_rejects_private_ip(self, mock_dynamodb, create_event):
        """Verify private IP target URLs are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://192.168.1.1',
                'expires_in': '15m'
            })

            response = pp.lambda_handler(create_event, None)
            assert response['statusCode'] == 400

    def test_create_rate_limited(self, mock_dynamodb, create_event):
        """Verify create endpoint enforces rate limiting."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            pp.check_rate_limits = MagicMock(return_value='Too many requests. Please try again later.')

            response = pp.lambda_handler(create_event, None)
            assert response['statusCode'] == 429

    def test_create_truncates_long_description(self, mock_dynamodb, mock_proxy, create_event):
        """Verify long descriptions are truncated to 500 chars."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'description': 'x' * 1000
            })

            pp.lambda_handler(create_event, None)

            call_args = mock_proxy.call_args
            body = call_args[1]['body'] if 'body' in call_args[1] else call_args[0][2]
            assert len(body['description']) == 500


# ---------------------------------------------------------------------------
# CORS Tests
# ---------------------------------------------------------------------------

class TestCORS:
    """Tests for CORS origin handling."""

    def test_allowed_origin_reflected(self):
        """Verify allowed origins are reflected in response."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            allowed_origins = [
                'https://layerv.ai',
                'https://www.layerv.ai',
                'https://staging.layerv.ai',
            ]

            for origin in allowed_origins:
                event = {
                    'headers': {'origin': origin}
                }
                result = pp.get_cors_origin(event)
                assert result == origin, f"Should reflect allowed origin: {origin}"

    def test_unknown_origin_gets_default(self):
        """Verify unknown origins get default, not reflection."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            event = {
                'headers': {'origin': 'https://evil.com'}
            }
            result = pp.get_cors_origin(event)
            assert result != 'https://evil.com'
            assert 'layerv.ai' in result

    def test_cors_headers_present_on_success(self, mock_dynamodb, mock_proxy, create_event):
        """Verify CORS headers are present on successful responses."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(create_event, None)
            headers = response['headers']

            assert 'Access-Control-Allow-Origin' in headers
            assert 'Access-Control-Allow-Methods' in headers
            assert 'DELETE' in headers['Access-Control-Allow-Methods']
            assert headers['Content-Type'] == 'application/json'

    def test_cors_headers_present_on_error(self, mock_dynamodb, create_event):
        """Verify CORS headers are present on error responses."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            # Trigger a validation error
            create_event['body'] = json.dumps({
                'target_url': 'http://not-https.com'
            })

            response = pp.lambda_handler(create_event, None)
            assert response['statusCode'] == 400
            assert 'Access-Control-Allow-Origin' in response['headers']


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for error handling and upstream failures."""

    def test_upstream_error_returns_502(self, mock_dynamodb, create_event):
        """Verify upstream errors are returned as 502."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            with patch('playground_proxy.proxy_to_qurl_api',
                       return_value=(502, {'error': {'detail': 'Upstream error: Connection refused'}})):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 502

    def test_upstream_4xx_passed_through(self, mock_dynamodb, create_event):
        """Verify upstream 4xx errors are passed through."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            with patch('playground_proxy.proxy_to_qurl_api',
                       return_value=(404, {'error': {'detail': 'QURL not found'}})):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 404

    def test_token_failure_returns_502(self, mock_dynamodb, create_event):
        """Verify M2M token failure returns 502."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            with patch('playground_proxy.proxy_to_qurl_api',
                       return_value=(502, {'error': {'detail': 'Failed to obtain M2M token'}})):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 502


# ---------------------------------------------------------------------------
# Proxy Function Tests
# ---------------------------------------------------------------------------

class TestProxyFunction:
    """Tests for the proxy_to_qurl_api helper."""

    def test_proxy_sends_auth_header(self, mock_token):
        """Verify proxy includes Authorization header."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = json.dumps({'data': {}}).encode()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('urllib.request.urlopen', return_value=mock_resp) as mock_urlopen:
                pp.proxy_to_qurl_api('GET', '/v1/qurls/r_123')

                # Verify the request was made with auth header
                call_args = mock_urlopen.call_args
                req = call_args[0][0]
                assert req.get_header('Authorization') == 'Bearer test-m2m-token'

    def test_proxy_handles_http_error(self, mock_token):
        """Verify proxy handles HTTPError from upstream."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            error_body = json.dumps({'error': {'detail': 'Not found'}}).encode()
            http_error = urllib.error.HTTPError(
                url='https://api.layerv.xyz/v1/qurls/bad',
                code=404,
                msg='Not Found',
                hdrs={},
                fp=io.BytesIO(error_body)
            )

            with patch('urllib.request.urlopen', side_effect=http_error):
                status, body = pp.proxy_to_qurl_api('GET', '/v1/qurls/bad')

            assert status == 404
            assert 'error' in body

    def test_proxy_handles_connection_error(self, mock_token):
        """Verify proxy handles connection errors gracefully."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            with patch('urllib.request.urlopen', side_effect=ConnectionError('refused')):
                status, body = pp.proxy_to_qurl_api('GET', '/v1/qurls/r_123')

            assert status == 502
            assert 'Upstream service unavailable' in body['error']['detail']


# ---------------------------------------------------------------------------
# Validation Coverage Tests
# ---------------------------------------------------------------------------

class TestValidationCoverage:
    """Tests for validation edge cases that previously lacked coverage."""

    def test_max_sessions_rejects_boolean(self, mock_dynamodb, create_event):
        """Verify max_sessions rejects boolean values (bool is subclass of int in Python)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'max_sessions': True
            })

            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs), \
                 patch('playground_proxy.get_m2m_token', return_value='test-token'):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'max_sessions' in body['error']

    def test_duration_empty_string_gets_default(self):
        """Verify empty string expires_in gets capped to 30m default."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            result = pp.cap_ttl('')
            assert result == '30m'

    def test_duration_whitespace_only_gets_default(self):
        """Verify whitespace-only expires_in gets capped to 30m default."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            result = pp.cap_ttl('   ')
            assert result == '30m'

    def test_null_headers_no_crash(self):
        """Verify event with headers: null does not crash get_cors_origin."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            result = pp.get_cors_origin({'headers': None})
            # Should return a valid origin, not crash
            assert result is not None
            assert 'layerv.ai' in result

    def test_reject_link_local_ip(self):
        """Verify link-local IP addresses are rejected by validate_target_url."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            is_valid, error = pp.validate_target_url('https://169.254.1.1')
            assert not is_valid
            assert 'Private' in error or 'internal' in error.lower()

    def test_reject_ipv4_mapped_ipv6(self):
        """Verify IPv4-mapped IPv6 loopback addresses are rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            is_valid, error = pp.validate_target_url('https://[::ffff:127.0.0.1]')
            assert not is_valid
            assert 'Private' in error or 'internal' in error.lower()

    def test_qurl_id_path_traversal_rejected(self, mock_dynamodb):
        """Verify QURL ID containing path traversal characters is rejected."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            event = {
                'requestContext': {'http': {'method': 'GET', 'sourceIp': '203.0.113.1'}},
                'rawPath': '/playground/qurl/../../../etc/passwd',
                'headers': {'origin': 'https://layerv.ai'},
                'pathParameters': {'id': '../../../etc/passwd'},
                'body': None
            }

            response = pp.lambda_handler(event, None)
            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'Invalid QURL ID' in body['error']

    def test_access_policy_rejects_non_dict(self, mock_dynamodb, create_event):
        """Verify access_policy as a string returns 400."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'access_policy': 'string'
            })

            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs), \
                 patch('playground_proxy.get_m2m_token', return_value='test-token'):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'access_policy' in body['error']

    def test_access_policy_rejects_invalid_allowed_ips(self, mock_dynamodb, create_event):
        """Verify access_policy with non-list allowed_ips returns 400."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'access_policy': {'allowed_ips': 'not-a-list'}
            })

            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs), \
                 patch('playground_proxy.get_m2m_token', return_value='test-token'):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'allowed_ips' in body['error']

    def test_one_time_use_rejects_string(self, mock_dynamodb, create_event):
        """Verify one_time_use as a string returns 400."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'one_time_use': 'true'
            })

            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs), \
                 patch('playground_proxy.get_m2m_token', return_value='test-token'):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'one_time_use' in body['error']

    def test_description_rejects_non_string(self, mock_dynamodb, create_event):
        """Verify description as a non-string returns 400."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m',
                'description': 123
            })

            mock_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            with patch('socket.getaddrinfo', return_value=mock_addrs), \
                 patch('playground_proxy.get_m2m_token', return_value='test-token'):
                response = pp.lambda_handler(create_event, None)

            assert response['statusCode'] == 400
            body = json.loads(response['body'])
            assert 'description' in body['error']

    def test_error_messages_no_internal_details(self, mock_token):
        """Verify proxy error responses do not leak internal URLs or stack traces."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            with patch('urllib.request.urlopen', side_effect=ConnectionError('Connection refused')):
                status, body = pp.proxy_to_qurl_api('POST', '/v1/qurl', body={'target_url': 'https://example.com'})

            assert status == 502
            response_text = json.dumps(body)
            # Must not contain the internal QURL API URL
            assert pp.QURL_API_URL not in response_text
            # Must not contain Python traceback indicators
            assert 'Traceback' not in response_text
            assert 'File "' not in response_text

    def test_dns_double_resolve(self):
        """Verify DNS rebinding mitigation: safe on first resolve, private on second, should reject."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            public_addrs = [(2, 1, 6, '', ('93.184.216.34', 0))]
            private_addrs = [(2, 1, 6, '', ('10.0.0.1', 0))]

            call_count = [0]

            def mock_getaddrinfo(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return public_addrs
                return private_addrs

            with patch('socket.getaddrinfo', side_effect=mock_getaddrinfo):
                is_valid, error = pp.validate_target_url('https://rebinding.example.com')

            assert not is_valid
            assert 'Private' in error or 'internal' in error.lower()
            # Verify two DNS lookups were made
            assert call_count[0] == 2

    def test_dns_resolution_timeout(self):
        """Verify DNS resolution timeout returns an error instead of crashing."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            with patch('socket.getaddrinfo', side_effect=socket.timeout('DNS resolution timed out')):
                is_valid, error = pp.validate_target_url('https://slow-dns.example.com')

            assert not is_valid
            # Should be caught by the generic Exception handler
            assert error is not None


# ---------------------------------------------------------------------------
# Token Refresh Race Condition Tests
# ---------------------------------------------------------------------------

class TestTokenRefreshRace:
    """Tests for concurrent token refresh behavior."""

    def test_concurrent_token_refresh_returns_same_token(self):
        """Verify concurrent calls to get_m2m_token with expired cache both succeed.

        When two Lambda invocations hit an expired token simultaneously, both
        should be able to fetch a new token. The second call overwrites the
        cache but returns a valid token either way.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._cached_token = None
            pp._token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'test_id',
                    'client_secret': 'test_secret',
                    'audience': 'https://api.layerv.xyz'
                })
            }

            token_response = json.dumps({
                'access_token': 'concurrent-token',
                'expires_in': 86400
            }).encode()

            mock_resp = MagicMock()
            mock_resp.read.return_value = token_response
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', return_value=mock_resp):
                # Simulate two concurrent calls
                token1 = pp.get_m2m_token()
                # Reset cache to simulate second concurrent call
                pp._cached_token = None
                pp._token_expires_at = 0
                token2 = pp.get_m2m_token()

            assert token1 == 'concurrent-token'
            assert token2 == 'concurrent-token'

    def test_auth0_token_endpoint_failure_raises(self):
        """Verify Auth0 token endpoint returning error raises RuntimeError."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._cached_token = None
            pp._token_expires_at = 0

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {
                'SecretString': json.dumps({
                    'client_id': 'test_id',
                    'client_secret': 'test_secret',
                    'audience': 'https://api.layerv.xyz'
                })
            }

            with patch('boto3.client', return_value=mock_sm), \
                 patch('urllib.request.urlopen', side_effect=urllib.error.URLError('Connection refused')):
                with pytest.raises(RuntimeError, match='Failed to obtain M2M token'):
                    pp.get_m2m_token()


# ---------------------------------------------------------------------------
# DynamoDB Throttling Tests
# ---------------------------------------------------------------------------

class TestDynamoDBThrottling:
    """Tests for DynamoDB throttling behavior in rate limiting."""

    def test_rate_limit_throttling_error_fails_open(self, mock_dynamodb):
        """Verify ProvisionedThroughputExceededException is treated as fail-open."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            from botocore.exceptions import ClientError

            pp.rate_table = mock_dynamodb['rate_table']

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

            result = pp.check_rate_limits('203.0.113.1')
            assert result is None  # Should fail open

    def test_rate_limit_internal_server_error_fails_open(self, mock_dynamodb):
        """Verify DynamoDB InternalServerError is treated as fail-open."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            from botocore.exceptions import ClientError

            pp.rate_table = mock_dynamodb['rate_table']

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

            result = pp.check_rate_limits('203.0.113.1')
            assert result is None  # Should fail open


# ---------------------------------------------------------------------------
# CI Bypass Tests
# ---------------------------------------------------------------------------

class TestCIBypass:
    """Tests for CI bypass key functionality."""

    def test_ci_bypass_with_valid_key(self):
        """Verify CI bypass returns True when X-CI-Key matches."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = 'test-secret-key'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'x-ci-key': 'test-secret-key'},
            }

            assert pp._is_ci_bypass(event) is True

    def test_ci_bypass_with_invalid_key(self):
        """Verify CI bypass returns False when X-CI-Key doesn't match."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = 'test-secret-key'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'x-ci-key': 'wrong-key'},
            }

            assert pp._is_ci_bypass(event) is False

    def test_ci_bypass_with_no_header(self):
        """Verify CI bypass returns False when header is missing."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = 'test-secret-key'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'some-secret'

            event = {
                'headers': {'origin': 'https://layerv.ai'},
            }

            assert pp._is_ci_bypass(event) is False

    def test_ci_bypass_disabled_when_no_secret_name(self):
        """Verify CI bypass returns False when CI_BYPASS_SECRET_NAME is empty."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = None
            pp._ci_bypass_key_expires_at = 0
            pp.CI_BYPASS_SECRET_NAME = ''

            event = {
                'headers': {'x-ci-key': 'some-key'},
            }

            assert pp._is_ci_bypass(event) is False

    def test_ci_bypass_skips_rate_limiting(self, mock_dynamodb, mock_proxy, create_event):
        """Verify that CI bypass skips rate limiting on create."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            pp._ci_bypass_key = 'ci-key-123'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'some-secret'

            # Set rate limiter to always reject
            pp.check_rate_limits = MagicMock(return_value='Rate limited')

            # Add CI bypass header
            create_event['headers']['x-ci-key'] = 'ci-key-123'

            response = pp.lambda_handler(create_event, None)
            # Should NOT be 429 — bypass skips rate limiting
            assert response['statusCode'] != 429
            # Rate limit function should not have been called
            pp.check_rate_limits.assert_not_called()

    def test_ci_bypass_key_ttl_expiry(self):
        """Verify expired key triggers re-fetch from Secrets Manager."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = 'old-key'
            pp._ci_bypass_key_expires_at = time.time() - 1  # Expired
            pp.CI_BYPASS_SECRET_NAME = 'my-secret'

            mock_sm = MagicMock()
            mock_sm.get_secret_value.return_value = {'SecretString': 'new-key'}

            with patch('playground_proxy.boto3.client', return_value=mock_sm):
                result = pp._get_ci_bypass_key()

            assert result == 'new-key'
            assert pp._ci_bypass_key == 'new-key'
            mock_sm.get_secret_value.assert_called_once_with(SecretId='my-secret')

    def test_ci_bypass_key_cached_within_ttl(self):
        """Verify cached key is returned within TTL without SM call."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp._ci_bypass_key = 'cached-key'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'my-secret'

            with patch('playground_proxy.boto3.client') as mock_boto:
                result = pp._get_ci_bypass_key()

            assert result == 'cached-key'
            mock_boto.assert_not_called()
