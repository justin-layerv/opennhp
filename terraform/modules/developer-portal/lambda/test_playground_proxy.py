"""
Tests for QURL Playground Proxy Lambda.

Run with: pytest terraform/modules/developer-portal/lambda/test_playground_proxy.py -v
"""

import pytest
import base64
import json
import socket
import time
import io
import urllib.error
from unittest.mock import MagicMock, patch, ANY


def _make_multipart_body(filename='hello.txt', content=b'hello world',
                          content_type='text/plain', boundary='boundary123'):
    """
    Build a minimal multipart/form-data body matching what a browser
    sends to POST /playground/upload (single 'file' field).

    Returns (content_type_header, base64_body) so the test can drop them
    straight into a Lambda event with isBase64Encoded=True.
    """
    part_headers = b'\r\n'.join(line.encode() for line in [
        f'--{boundary}',
        f'Content-Disposition: form-data; name="file"; filename="{filename}"',
        f'Content-Type: {content_type}',
        '',  # blank line ends the part headers
    ]) + b'\r\n'
    body = part_headers + content + b'\r\n' + f'--{boundary}--\r\n'.encode()
    return f'multipart/form-data; boundary={boundary}', base64.b64encode(body).decode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _import_module():
    """
    Import the module with mocked AWS clients.

    Test-isolation contract: this fixture deletes
    `sys.modules['playground_proxy']` and re-imports before EVERY test,
    which re-runs the module's source and resets module-level globals
    (CONNECTOR_BASE_URL, MAX_UPLOAD_BYTES, check_rate_limits, etc.).
    That means tests that mutate `pp.<attr>` for setup don't need their
    own save/restore — the next test sees pristine defaults.

    Verified by running this file under pytest-randomly (deliberately
    re-orders tests across runs); see PR #2049 cycle 19 reply.
    """
    import sys
    for mod in [k for k in sys.modules if k.startswith('playground_proxy')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import playground_proxy as _mod
        importlib.reload(_mod)


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


@pytest.fixture
def upload_event():
    """
    Base event for POST /playground/upload.

    HTTP API v2 (payload format 2.0) base64-encodes binary bodies and sets
    isBase64Encoded=True, so test events MUST set both — the handler
    rejects bodies that aren't flagged as base64.
    """
    content_type, b64 = _make_multipart_body()
    return {
        'requestContext': {
            'http': {
                'method': 'POST',
                'sourceIp': '203.0.113.1'
            }
        },
        'rawPath': '/playground/upload',
        'headers': {
            'origin': 'https://layerv.ai',
            'content-type': content_type,
        },
        'pathParameters': None,
        'body': b64,
        'isBase64Encoded': True,
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
            assert call_args[0][1] == '/v1/qurls'

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

    def test_delete_qurl_204_normalized(self, mock_dynamodb, mock_proxy, delete_event):
        """Verify upstream 204 No Content is normalized to 200 with a body."""
        mock_proxy.return_value = (204, {})
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(delete_event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['data']['resource_id'] == 'r_test123'
            assert body['data']['status'] == 'revoked'

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

    def test_mint_link_no_body(self, mock_dynamodb, mock_proxy, mint_event):
        """Verify mint sends empty dict body when frontend sends no body."""
        mint_event['body'] = None  # Frontend sends POST with no body
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            response = pp.lambda_handler(mint_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once()
            # body kwarg should be empty dict, not None
            assert mock_proxy.call_args.kwargs.get('body') == {}

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
# Fixed-Resource Demo Tests
# ---------------------------------------------------------------------------

DEMO_TARGET = 'https://hidden-app.example'
DEMO_RESOURCE_ID = 'r_demo1234567'
DEMO_QURL_SITE = 'https://r_demo1234567.qurl.site'


def _enable_demo(pp):
    """Configure the fixed-resource demo on a freshly imported module."""
    pp.PLAYGROUND_DEMO_TARGET_URL = DEMO_TARGET
    pp.PLAYGROUND_DEMO_RESOURCE_ID = DEMO_RESOURCE_ID
    pp.PLAYGROUND_DEMO_QURL_SITE = DEMO_QURL_SITE


def _demo_mint_upstream(qurl_link='https://qurl.link/#at_demo', qurl_id='q_minted1',
                        expires_at='2026-07-14T12:00:00Z'):
    """A successful upstream mint_link response body."""
    return {'data': {'qurl_link': qurl_link, 'qurl_id': qurl_id,
                     'expires_at': expires_at, 'type': 'tunnel'}}


class TestDemoFixedResource:
    """Tests for the fixed-resource demo mint path."""

    def _demo_event(self, create_event, **overrides):
        body = {'target_url': DEMO_TARGET, 'expires_in': '15m', 'one_time_use': True}
        body.update(overrides)
        create_event['body'] = json.dumps(body)
        return create_event

    def test_demo_mint_happy_path(self, mock_dynamodb, mock_proxy, create_event):
        """A create for exactly the demo URL mints from the fixed resource."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            response = pp.lambda_handler(self._demo_event(create_event), None)

            mock_proxy.assert_called_once_with(
                'POST', f'/v1/qurls/{DEMO_RESOURCE_ID}/mint_link',
                body={'expires_in': '15m', 'one_time_use': True})
            assert response['statusCode'] == 201
            data = json.loads(response['body'])['data']
            assert data == {
                'resource_id': DEMO_RESOURCE_ID,
                'qurl_id': 'q_minted1',
                'qurl_link': 'https://qurl.link/#at_demo',
                'qurl_site': DEMO_QURL_SITE,
                'expires_at': '2026-07-14T12:00:00Z',
            }

    def test_demo_mint_caps_ttl(self, mock_dynamodb, mock_proxy, create_event):
        """The playground TTL cap applies to demo mints too."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            pp.lambda_handler(self._demo_event(create_event, expires_in='2h'), None)

            assert mock_proxy.call_args[1]['body']['expires_in'] == '30m'

    def test_demo_mint_defaults_ttl_when_absent(self, mock_dynamodb, mock_proxy, create_event):
        """Missing expires_in falls back to the playground max."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            create_event['body'] = json.dumps({'target_url': DEMO_TARGET})
            pp.lambda_handler(create_event, None)

            assert mock_proxy.call_args[1]['body'] == {'expires_in': '30m'}

    def test_demo_mint_rejects_non_bool_one_time_use(self, mock_dynamodb, mock_proxy, create_event):
        """one_time_use is validated exactly like the create path."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)

            response = pp.lambda_handler(
                self._demo_event(create_event, one_time_use='yes'), None)

            assert response['statusCode'] == 400
            assert 'one_time_use' in json.loads(response['body'])['error']
            mock_proxy.assert_not_called()

    def test_demo_mint_passes_upstream_error_through(self, mock_dynamodb, mock_proxy, create_event):
        """Upstream mint errors pass through so the client can fall back."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (404, {'error': {'detail': 'Resource not found'}})

            response = pp.lambda_handler(self._demo_event(create_event), None)

            assert response['statusCode'] == 404
            assert json.loads(response['body']) == {'error': {'detail': 'Resource not found'}}

    def test_demo_mint_2xx_without_link_is_502(self, mock_dynamodb, mock_proxy, create_event):
        """A malformed upstream success cannot produce a linkless demo response."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, {'data': {'qurl_id': 'q_minted1'}})

            response = pp.lambda_handler(self._demo_event(create_event), None)

            assert response['statusCode'] == 502

    def test_demo_mint_rate_limited(self, mock_dynamodb, mock_proxy, create_event):
        """Rate limits are enforced before the demo mint."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            pp.check_rate_limits = MagicMock(return_value='Too many requests. Please try again later.')

            response = pp.lambda_handler(self._demo_event(create_event), None)

            assert response['statusCode'] == 429
            mock_proxy.assert_not_called()

    def test_demo_target_normalizes_trailing_slash_and_case(self, mock_dynamodb, mock_proxy, create_event):
        """The two likely drift footguns — trailing slash and case — still match."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            for variant in (DEMO_TARGET + '/', DEMO_TARGET.upper()):
                mock_proxy.reset_mock()
                pp.lambda_handler(self._demo_event(create_event, target_url=variant), None)
                assert mock_proxy.call_args[0][:2] == (
                    'POST', f'/v1/qurls/{DEMO_RESOURCE_ID}/mint_link'
                ), variant

    def test_demo_mint_failure_logs_operator_signal(self, mock_dynamodb, mock_proxy, create_event, caplog):
        """Upstream failures emit the exact literal the metric filter alarms on."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (404, {'error': {'code': 'resource_not_found',
                                                       'detail': 'Resource not found'}})

            with caplog.at_level('WARNING'):
                pp.lambda_handler(self._demo_event(create_event), None)

            records = [r for r in caplog.records if r.message == 'Demo mint upstream failure']
            assert len(records) == 1
            assert records[0].resource_id == DEMO_RESOURCE_ID
            assert records[0].status == 404
            assert records[0].error_code == 'resource_not_found'

    def test_demo_requires_exact_target_match(self, mock_dynamodb, mock_proxy, create_event):
        """A non-demo target stays on the normal create path."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)

            create_event['body'] = json.dumps({
                'target_url': 'https://example.com',
                'expires_in': '15m'
            })
            pp.lambda_handler(create_event, None)

            assert mock_proxy.call_args[0][:2] == ('POST', '/v1/qurls')

    def test_demo_url_with_path_is_not_demo(self, mock_dynamodb, mock_proxy, create_event):
        """Only the exact demo URL triggers the mint path — not sub-paths."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)

            with patch('socket.getaddrinfo', side_effect=socket.gaierror):
                response = pp.lambda_handler(
                    self._demo_event(create_event, target_url=DEMO_TARGET + '/admin'), None)

            assert response['statusCode'] == 400
            assert 'resolve' in json.loads(response['body'])['error']
            mock_proxy.assert_not_called()

    def test_demo_disabled_by_default(self, mock_dynamodb, mock_proxy, create_event):
        """Without config, the demo URL hits normal validation (and fails DNS)."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']

            with patch('socket.getaddrinfo', side_effect=socket.gaierror):
                response = pp.lambda_handler(self._demo_event(create_event), None)

            assert response['statusCode'] == 400
            assert 'resolve' in json.loads(response['body'])['error']
            mock_proxy.assert_not_called()

    def test_demo_partially_configured_stays_disabled(self, mock_dynamodb, mock_proxy, create_event):
        """A half-set config (e.g. missing qurl_site) never mints."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            pp.PLAYGROUND_DEMO_TARGET_URL = DEMO_TARGET
            pp.PLAYGROUND_DEMO_RESOURCE_ID = DEMO_RESOURCE_ID

            with patch('socket.getaddrinfo', side_effect=socket.gaierror):
                response = pp.lambda_handler(self._demo_event(create_event), None)

            assert response['statusCode'] == 400
            mock_proxy.assert_not_called()

    def test_delete_demo_resource_forbidden(self, mock_dynamodb, mock_proxy, delete_event):
        """The public demo resource id must not be revocable anonymously."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)

            delete_event['rawPath'] = f'/playground/qurl/{DEMO_RESOURCE_ID}'
            delete_event['pathParameters'] = {'id': DEMO_RESOURCE_ID}
            response = pp.lambda_handler(delete_event, None)

            assert response['statusCode'] == 403
            assert 'cannot be revoked' in json.loads(response['body'])['error']
            mock_proxy.assert_not_called()

    def test_delete_other_id_still_proxied(self, mock_dynamodb, mock_proxy, delete_event):
        """Non-demo deletes keep working when the demo is configured."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (204, {})

            response = pp.lambda_handler(delete_event, None)

            assert response['statusCode'] == 200
            mock_proxy.assert_called_once_with('DELETE', '/v1/qurls/r_test123')

    def _direct_mint_event(self, qurl_id, body):
        return {
            'requestContext': {'http': {'method': 'POST', 'sourceIp': '203.0.113.1'}},
            'rawPath': f'/playground/qurl/{qurl_id}/mint',
            'headers': {'origin': 'https://layerv.ai'},
            'pathParameters': {'id': qurl_id},
            'body': json.dumps(body),
        }

    def test_direct_mint_of_demo_id_is_clamped(self, mock_dynamodb, mock_proxy):
        """The public demo id cannot mint uncapped or absolute-expiry links via /mint."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            event = self._direct_mint_event(DEMO_RESOURCE_ID, {
                'expires_in': '30d',
                'expires_at': '2027-01-01T00:00:00Z',
                'max_sessions': 0,
                'session_duration': '24h',
                'one_time_use': False,
            })
            pp.lambda_handler(event, None)

            mock_proxy.assert_called_once_with(
                'POST', f'/v1/qurls/{DEMO_RESOURCE_ID}/mint_link',
                body={'expires_in': '30m', 'one_time_use': False})

    def test_direct_mint_of_demo_id_validates_one_time_use(self, mock_dynamodb, mock_proxy):
        """Demo-id mints via /mint validate one_time_use like the demo path."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)

            event = self._direct_mint_event(DEMO_RESOURCE_ID, {'one_time_use': 'yes'})
            response = pp.lambda_handler(event, None)

            assert response['statusCode'] == 400
            mock_proxy.assert_not_called()

    def test_direct_mint_of_other_id_stays_raw_passthrough(self, mock_dynamodb, mock_proxy):
        """Non-demo ids keep the existing raw mint passthrough."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            pp.rate_table = mock_dynamodb['rate_table']
            _enable_demo(pp)
            mock_proxy.return_value = (201, _demo_mint_upstream())

            body = {'expires_in': '7d', 'label': 'for a friend'}
            pp.lambda_handler(self._direct_mint_event('r_other123', body), None)

            mock_proxy.assert_called_once_with(
                'POST', '/v1/qurls/r_other123/mint_link', body=body)


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

    def test_proxy_handles_empty_response_body(self, mock_token):
        """Verify proxy handles 204 No Content (empty body) from upstream."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            mock_resp = MagicMock()
            mock_resp.status = 204
            mock_resp.read.return_value = b''
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            with patch('urllib.request.urlopen', return_value=mock_resp):
                status, body = pp.proxy_to_qurl_api('DELETE', '/v1/qurls/r_123')

            assert status == 204
            assert body == {}

    def test_proxy_handles_connection_error(self, mock_token):
        """Verify proxy handles connection errors gracefully."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            with patch('urllib.request.urlopen', side_effect=ConnectionError('refused')):
                status, body = pp.proxy_to_qurl_api('GET', '/v1/qurls/r_123')

            assert status == 502
            assert 'Upstream service unavailable' in body['error']['detail']

    def test_proxy_logs_unparseable_upstream_error(self, mock_token):
        """Verify unparseable upstream errors are logged with raw body."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            http_error = urllib.error.HTTPError(
                url='https://api.layerv.xyz/v1/qurls/r_123/mint_link',
                code=400,
                msg='Bad Request',
                hdrs={},
                fp=io.BytesIO(b'')  # Empty body, not parseable as JSON
            )

            with patch('urllib.request.urlopen', side_effect=http_error), \
                 patch.object(pp.logger, 'error') as mock_logger:
                status, body = pp.proxy_to_qurl_api('POST', '/v1/qurls/r_123/mint_link', body={})

            assert status == 400
            assert body == {'error': {'detail': 'Upstream request failed'}}
            mock_logger.assert_called_once()
            log_extra = mock_logger.call_args.kwargs.get('extra', {})
            assert log_extra['status'] == 400
            assert log_extra['path'] == '/v1/qurls/r_123/mint_link'


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
                status, body = pp.proxy_to_qurl_api('POST', '/v1/qurls', body={'target_url': 'https://example.com'})

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


# ---------------------------------------------------------------------------
# Upload Handler Tests (POST /playground/upload)
# ---------------------------------------------------------------------------

def _mock_connector_response(status, payload):
    """Build a context-manager-style mock that mimics urllib.request.urlopen."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestUploadHandler:
    """Tests for the /playground/upload file-mode handler."""

    def test_upload_chains_upload_then_mint_with_one_time_use(self, mock_dynamodb, upload_event):
        """
        The advertised "self-destructs after the first access" contract is
        delivered by the SECOND connector call. Verify (a) /api/upload is
        forwarded the verbatim multipart body, and (b) /api/mint_link/{id}
        is called with one_time_use=true.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            connector_calls = []

            def fake_urlopen(req, timeout=None):
                connector_calls.append({
                    'url': req.full_url,
                    'method': req.get_method(),
                    'data': req.data,
                    'content_type': req.get_header('Content-type'),
                })
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        'resource_id': 'res_abc123',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r_abc.qurl.site',
                    })
                if '/api/mint_link/' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        'links': [{
                            'qurl_id': 'q_one_time',
                            'qurl_link': 'https://qurl.link/#at_onetime',
                            'expires_at': '2099-01-01T00:00:00Z',
                        }],
                    })
                raise AssertionError(f'unexpected URL: {req.full_url}')

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])

            # The reusable upload-issued link must NOT leak; only the
            # one-time minted link is returned.
            assert body['data']['qurl_link'] == 'https://qurl.link/#at_onetime'
            assert body['data']['qurl_link'] != 'https://qurl.link/REUSABLE'
            assert body['data']['qurl_site'] == 'https://r_abc.qurl.site'
            assert body['data']['resource_id'] == 'res_abc123'

            assert len(connector_calls) == 2
            assert connector_calls[0]['url'].endswith('/api/upload')
            assert connector_calls[0]['method'] == 'POST'
            assert connector_calls[0]['content_type'].startswith('multipart/form-data')
            assert connector_calls[1]['url'].endswith('/api/mint_link/res_abc123')
            mint_payload = json.loads(connector_calls[1]['data'])
            assert mint_payload == {'n': 1, 'one_time_use': True}

    def test_upload_rate_limited_returns_429(self, mock_dynamodb, upload_event):
        """Per-IP rate limit applies to uploads identically to URL mode."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            pp.check_rate_limits = MagicMock(return_value='Too many requests.')

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 429
            mock_urlopen.assert_not_called()

    def test_upload_rejects_oversize_body(self, mock_dynamodb, upload_event):
        """Bodies above PLAYGROUND_MAX_UPLOAD_BYTES are rejected with 413."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            # Shrink the cap to 100 bytes so a normal hello body trips it
            pp.MAX_UPLOAD_BYTES = 100

            # Build a body bigger than 100 bytes (after base64 decode)
            big_ct, big_b64 = _make_multipart_body(content=b'x' * 200)
            upload_event['headers']['content-type'] = big_ct
            upload_event['body'] = big_b64

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 413
            mock_urlopen.assert_not_called()

    def test_upload_rejects_non_multipart_content_type(self, mock_dynamodb, upload_event):
        """JSON to /playground/upload should be rejected — multipart only."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            upload_event['headers']['content-type'] = 'application/json'
            upload_event['body'] = base64.b64encode(b'{"foo":"bar"}').decode()

            response = pp.lambda_handler(upload_event, None)
            assert response['statusCode'] == 400
            assert 'multipart' in json.loads(response['body'])['error']

    def test_upload_rejects_non_base64_body(self, mock_dynamodb, upload_event):
        """
        HTTP API v2 always sets isBase64Encoded=True for multipart; if it's
        missing the handler should refuse rather than silently corrupt
        bytes by latin-1 re-encoding.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            upload_event['isBase64Encoded'] = False
            upload_event['body'] = 'plain text not base64'

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 400
            mock_urlopen.assert_not_called()

    def test_upload_surfaces_connector_4xx_verbatim(self, mock_dynamodb, upload_event):
        """
        Connector 4xx errors (e.g. file-type rejection, oversized for the
        connector's own cap) should pass through with their error detail
        so the demo's error renderer can show something specific.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                # Simulate a 400 from the connector
                err_body = json.dumps({'success': False, 'error': 'No file provided'}).encode()
                raise urllib.error.HTTPError(
                    url=req.full_url, code=400, msg='Bad Request',
                    hdrs={}, fp=io.BytesIO(err_body),
                )

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 400
            assert json.loads(response['body'])['error'] == 'No file provided'

    def test_upload_filters_unknown_connector_error_strings(self, mock_dynamodb, upload_event):
        """
        Defense-in-depth: a 4xx with an unrecognized error shape ("Upload
        failed: <s3 bucket name>") gets a generic "Upload failed" message
        instead of being reflected to the browser. Pins the allowlist
        contract in _safe_error_string.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                # Simulate the connector returning a 5xx with an error
                # string that's NOT on our allowlist (could contain
                # bucket name, internal IPs, etc.).
                err_body = json.dumps({
                    'success': False,
                    'error': 'Upload failed: NoSuchBucket: bucket "internal-bucket-name" does not exist',
                }).encode()
                raise urllib.error.HTTPError(
                    url=req.full_url, code=500, msg='Internal Server Error',
                    hdrs={}, fp=io.BytesIO(err_body),
                )

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            # 500 maps to 502 (per `502 if upload_status >= 500 else upload_status`)
            assert response['statusCode'] == 502
            body_text = response['body']
            # The internal bucket name MUST NOT leak.
            assert 'internal-bucket-name' not in body_text
            assert 'NoSuchBucket' not in body_text
            # User sees exactly the generic message — pinning the
            # fallback string so future copy changes are deliberate.
            assert json.loads(response['body'])['error'] == 'Upload failed'

    def test_upload_rejects_non_https_qurl_link(self, mock_dynamodb, upload_event):
        """
        qurl_link is the load-bearing user-clickable URL the demo
        renders as a link target — even higher-value than qurl_site.
        Unlike qurl_site (which gets nulled), a non-https / malformed
        qurl_link fails 502 because the operation has no usable output
        otherwise.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                # Mint returns a malicious scheme as qurl_link
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{
                        'qurl_link': 'javascript:alert(1)',  # XSS attempt
                        'expires_at': '2099-01-01T00:00:00Z',
                    }],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            assert 'malformed' in json.loads(response['body'])['error']
            # The malicious link MUST NOT appear in the body anywhere.
            assert 'javascript' not in response['body'].lower()

    def test_upload_drops_non_https_qurl_site(self, mock_dynamodb, upload_event):
        """
        Defense-in-depth: a buggy/compromised connector returning
        `javascript:` or another non-HTTPS scheme for qurl_site must
        NOT be reflected to the browser as a link target.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'javascript:alert(1)',  # malicious
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{
                        'qurl_id': 'q',
                        'qurl_link': 'https://qurl.link/#onetime',
                        'expires_at': '2099-01-01T00:00:00Z',
                    }],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            # Request still succeeds — the upload completed; we just
            # null out the unsafe qurl_site so the frontend doesn't
            # render it. (qurl_link still works; qurl_site is the
            # observability/preview UI.)
            assert response['statusCode'] == 200
            data = json.loads(response['body'])['data']
            assert data['qurl_link'] == 'https://qurl.link/#onetime'
            assert data['qurl_site'] is None  # dropped
            assert 'javascript' not in response['body']

    def test_upload_fails_loud_when_mint_fails_after_successful_upload(self, mock_dynamodb, upload_event):
        """
        If the mint step fails after the upload succeeded, we MUST NOT
        fall back to the reusable upload-issued qurl_link — that would
        silently break the one-time contract the demo advertises.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        'resource_id': 'res_xyz',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r_xyz.qurl.site',
                    })
                # mint_link path: simulate a 502 from the connector
                raise urllib.error.HTTPError(
                    url=req.full_url, code=502, msg='Bad Gateway',
                    hdrs={}, fp=io.BytesIO(b'{"success":false,"error":"upstream timeout"}'),
                )

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            body_text = response['body']
            # The reusable link must not be present anywhere in the response.
            assert 'REUSABLE' not in body_text

    def test_upload_502_when_upload_response_missing_resource_id(self, mock_dynamodb, upload_event):
        """A 200 upload that omits resource_id is a connector bug — fail."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {'success': True, 'qurl_site': 'x'})
                raise AssertionError('mint should never be called without a resource_id')

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502

    def test_upload_route_present_in_router(self, mock_dynamodb, upload_event):
        """Sanity: POST /playground/upload reaches handle_upload, not 404."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            with patch('playground_proxy.handle_upload', return_value={
                'statusCode': 200, 'headers': {}, 'body': '{}'
            }) as mock_handler:
                pp.lambda_handler(upload_event, None)
                mock_handler.assert_called_once()

    def test_upload_global_rate_limit_returns_429(self, mock_dynamodb, upload_event):
        """
        Global (not per-IP) rate limit also gates uploads. Patch
        check_rate_limits directly with the global-rejection message
        rather than the internal _atomic_rate_check call sequence —
        tightly coupling to the per-IP→global ordering would mean a
        future refactor of that helper silently tests the wrong path.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            pp.check_rate_limits = MagicMock(
                return_value='Service temporarily unavailable. Please try again later.'
            )

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 429
            body = json.loads(response['body'])
            assert 'temporarily unavailable' in body['error']
            mock_urlopen.assert_not_called()

    def test_upload_ci_bypass_skips_rate_limits(self, mock_dynamodb, upload_event):
        """X-CI-Key bypass must apply to uploads, not just URL mode."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            pp._ci_bypass_key = 'ci-key-upload'
            pp._ci_bypass_key_expires_at = time.time() + 300
            pp.CI_BYPASS_SECRET_NAME = 'some-secret'
            # If the bypass works, this stub will never be invoked.
            pp.check_rate_limits = MagicMock(return_value='Too many requests.')

            upload_event['headers']['x-ci-key'] = 'ci-key-upload'

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_ci',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r_ci.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{'qurl_id': 'q', 'qurl_link': 'https://qurl.link/#onetime',
                               'expires_at': '2099-01-01T00:00:00Z'}],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            pp.check_rate_limits.assert_not_called()

    def test_upload_rejects_empty_body(self, mock_dynamodb, upload_event):
        """Zero-byte body is rejected before forwarding."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            upload_event['body'] = base64.b64encode(b'').decode()

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 400
            assert 'Empty' in json.loads(response['body'])['error']
            mock_urlopen.assert_not_called()

    def test_module_globals_reset_between_tests_part1(self, mock_dynamodb):
        """
        Smoke-test the isolation contract from `_import_module`: this
        test mutates `pp.MAX_UPLOAD_BYTES` to a low value, and
        `_part2` (below) asserts the default value is back. If a
        future maintainer accidentally drops the autouse fixture's
        reload, one of these two tests fails immediately.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.MAX_UPLOAD_BYTES = 1  # deliberate vandalism

    def test_module_globals_reset_between_tests_part2(self, mock_dynamodb):
        """See `_part1` — together they pin the autouse-fixture reset."""
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            assert pp.MAX_UPLOAD_BYTES == 4 * 1024 * 1024, (
                'isolation broke — _import_module no longer resets module globals '
                'between tests. Restore the autouse fixture or convert callers to '
                'monkeypatch.setattr.'
            )

    def test_upload_passes_source_ip_to_rate_limiter(self, mock_dynamodb, upload_event):
        """
        Pin that check_rate_limits is invoked with the request's
        sourceIp — a future refactor that drops the argument would
        silently rate-limit globally (everyone shares one bucket).
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            pp.check_rate_limits = MagicMock(return_value=None)
            upload_event['requestContext']['http']['sourceIp'] = '198.51.100.7'

            with patch('urllib.request.urlopen') as mock_urlopen:
                mock_urlopen.side_effect = lambda req, timeout=None: _mock_connector_response(
                    200, {'success': True, 'resource_id': 'res_x',
                          'qurl_link': 'https://q/REUSABLE',
                          'qurl_site': 'https://r.qurl.site'}
                ) if '/api/upload' in req.full_url else _mock_connector_response(
                    200, {'success': True,
                          'links': [{'qurl_link': 'https://q/#onetime',
                                     'expires_at': '2099-01-01T00:00:00Z'}]}
                )
                pp.lambda_handler(upload_event, None)

            pp.check_rate_limits.assert_called_once_with('198.51.100.7')

    def test_upload_route_does_not_accept_non_post(self, mock_dynamodb):
        """
        Sanity: GET / PUT against /playground/upload should 404 (the
        router only registers the POST route), not surface as a
        weird-method invocation.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            for method in ('GET', 'PUT', 'DELETE', 'PATCH'):
                ev = {
                    'requestContext': {'http': {'method': method, 'sourceIp': '203.0.113.1'}},
                    'rawPath': '/playground/upload',
                    'headers': {'origin': 'https://layerv.ai'},
                    'pathParameters': None,
                    'body': None,
                }
                response = pp.lambda_handler(ev, None)
                assert response['statusCode'] == 404, f'{method} should 404'

    def test_upload_mint_url_quotes_resource_id(self, mock_dynamodb, upload_event):
        """
        Belt-and-braces: even though QURL_ID_RE restricts the alphabet
        today, the mint URL builder should `urllib.parse.quote` the
        resource_id so a future regex widening doesn't reintroduce a
        path-injection vector.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            mint_urls = []

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        # Real connector IDs are 13 chars; pad to use
                        # a couple underscore/hyphen characters.
                        'resource_id': 'r_abc_DEF-12x',
                        'qurl_link': 'https://q/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                mint_urls.append(req.full_url)
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{'qurl_link': 'https://q/#onetime',
                               'expires_at': '2099-01-01T00:00:00Z'}],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            assert len(mint_urls) == 1
            # The encoded ID appears intact — quote() with safe='' is
            # a no-op on the current allowed alphabet, so this also
            # pins that legitimate IDs round-trip cleanly.
            assert mint_urls[0].endswith('/api/mint_link/r_abc_DEF-12x')

    def test_upload_rejects_crlf_in_content_type(self, mock_dynamodb, upload_event):
        """
        Defense-in-depth against header injection: a Content-Type with
        embedded CRLF would otherwise be forwarded into the connector's
        outbound HTTP request. CPython's http.client also rejects this,
        but the doctrine is validate at the boundary so a stdlib
        relaxation can't silently introduce an injection vector.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            for evil_ct in (
                'multipart/form-data; boundary=foo\r\nX-Evil: bar',
                'multipart/form-data; boundary=foo\nX-Evil: bar',
                'multipart/form-data; boundary=foo\rX-Evil: bar',
            ):
                ev = dict(upload_event)
                ev['headers'] = dict(upload_event['headers'])
                ev['headers']['content-type'] = evil_ct
                with patch('urllib.request.urlopen') as mock_urlopen:
                    response = pp.lambda_handler(ev, None)
                assert response['statusCode'] == 400, f'should reject {evil_ct!r}'
                mock_urlopen.assert_not_called()

    def test_upload_rate_limit_fires_before_csrf(self, mock_dynamodb, upload_event):
        """
        Pin the order: a cross-origin request should ALSO trip the
        per-IP rate limit (so an attacker can't burn invocations
        unmitigated by 403'ing forever). Patch rate-limit to reject;
        verify the 429 fires even when Origin is malicious.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']
            pp.check_rate_limits = MagicMock(return_value='Too many requests.')

            upload_event['headers']['origin'] = 'https://evil.example.com'

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            # 429 (rate-limit) wins over 403 (CSRF) — rate-limit ran first.
            assert response['statusCode'] == 429
            pp.check_rate_limits.assert_called_once()
            mock_urlopen.assert_not_called()

    def test_upload_rejects_lookalike_content_type(self, mock_dynamodb, upload_event):
        """
        `multipart/form-datazoo` and `multipart/form-data-fake` would
        slip through a bare `startswith('multipart/form-data')` check.
        Strict regex rejects them.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            for evil_ct in (
                'multipart/form-datazoo; boundary=xyz',
                'multipart/form-data-fake; boundary=xyz',
                'multipart/form-dataX',
            ):
                ev = dict(upload_event)
                ev['headers'] = dict(upload_event['headers'])
                ev['headers']['content-type'] = evil_ct
                with patch('urllib.request.urlopen') as mock_urlopen:
                    response = pp.lambda_handler(ev, None)
                assert response['statusCode'] == 400, f'should reject {evil_ct!r}'
                mock_urlopen.assert_not_called()

    def test_upload_accepts_content_type_with_charset_parameter(self, mock_dynamodb, upload_event):
        """
        Real browser uploads append parameters like `charset=utf-8`
        after the boundary. `startswith('multipart/form-data')` already
        handles this — pin it so a future "tighten the check" change
        doesn't reject legitimate clients.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            base_ct, _ = _make_multipart_body()
            upload_event['headers']['content-type'] = f'{base_ct}; charset=utf-8'

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{'qurl_link': 'https://qurl.link/#onetime',
                               'expires_at': '2099-01-01T00:00:00Z'}],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200

    def test_upload_preserves_content_type_boundary_when_forwarding(self, mock_dynamodb, upload_event):
        """
        The connector's multipart parser depends on the boundary value
        in Content-Type. Verify it survives byte-for-byte through the
        proxy — a future Content-Type normalization step would silently
        break uploads.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            unique_boundary = 'unique-boundary-9c2e1a'
            ct, b64 = _make_multipart_body(boundary=unique_boundary)
            upload_event['headers']['content-type'] = ct
            upload_event['body'] = b64

            forwarded_cts = []

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    forwarded_cts.append(req.get_header('Content-type'))
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{'qurl_link': 'https://qurl.link/#onetime',
                               'expires_at': '2099-01-01T00:00:00Z'}],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            # Boundary value (the load-bearing bit for parsing) survives
            # verbatim through the proxy.
            assert len(forwarded_cts) == 1
            assert unique_boundary in forwarded_cts[0]

    def test_upload_400_when_base64_body_has_embedded_whitespace(self, mock_dynamodb, upload_event):
        """
        `base64.b64decode(..., validate=True)` rejects whitespace inside
        the encoded body. API Gateway HTTP API doesn't inject newlines
        today, but a future WAF / edge proxy re-encoding could —
        pinning the behavior here so the next "let's be permissive"
        change can't quietly slip through.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            # Insert a newline into the middle of the valid base64 body
            valid_b64 = upload_event['body']
            mid = len(valid_b64) // 2
            upload_event['body'] = valid_b64[:mid] + '\n' + valid_b64[mid:]

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            # Either pre-check trips (413 for inflated length) or
            # b64decode trips (400 invalid base64). Both are acceptable
            # rejections; what matters is no upload is forwarded.
            assert response['statusCode'] in (400, 413)
            mock_urlopen.assert_not_called()

    def test_upload_502_when_connector_returns_non_dict_body(self, mock_dynamodb, upload_event):
        """
        Connector 200 with a non-dict body must surface as 502 — the
        upstream didn't speak our contract, and mirroring 200 with an
        error envelope is misleading for monitoring + callers.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                resp = MagicMock()
                resp.status = 200
                resp.read.return_value = b'["unexpected", "list"]'
                resp.__enter__ = MagicMock(return_value=resp)
                resp.__exit__ = MagicMock(return_value=False)
                return resp

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            body = json.loads(response['body'])
            assert 'error' in body

    @pytest.mark.parametrize('expires_at,expected_pass', [
        ('2099-01-01T00:00:00Z', True),         # canonical RFC 3339
        ('2099-01-01T00:00:00+00:00', True),    # explicit offset
        ('2099-01-01 00:00:00+00:00', True),    # space separator (RFC 3339 allows)
        ('2099-01-01T00:00:00', False),         # naive — no tz
        ('not-a-date', False),
        ('<script>alert(1)</script>', False),
    ])
    def test_iso8601_acceptance_shapes(self, expires_at, expected_pass):
        """
        Pin the exact shapes _is_valid_iso8601 accepts vs. rejects.
        Future "let's be permissive" or "let's be strict RFC 3339"
        changes would otherwise slip past the broader expires_at tests.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            assert pp._is_valid_iso8601(expires_at) is expected_pass

    def test_upload_drops_naive_expires_at(self, mock_dynamodb, upload_event):
        """
        RFC 3339 requires a timezone designator. A connector returning
        a naive datetime ('2099-01-01T00:00:00' — no Z, no offset)
        would render as an ambiguous time in the demo. Drop it.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{
                        'qurl_link': 'https://qurl.link/#onetime',
                        # Naive — no Z, no offset.
                        'expires_at': '2099-01-01T00:00:00',
                    }],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            data = json.loads(response['body'])['data']
            assert data['expires_at'] is None

    def test_upload_drops_invalid_expires_at(self, mock_dynamodb, upload_event):
        """
        Parallel to qurl_site validation: a buggy/compromised connector
        returning anything that isn't ISO 8601 in `expires_at` must be
        dropped to None before forwarding to the browser. Pins the
        _is_valid_iso8601 gate so a future "let's accept any string"
        change can't sneak through.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{
                        'qurl_link': 'https://qurl.link/#onetime',
                        # Not ISO 8601 — could be an injection attempt
                        # or a buggy connector. Must be dropped.
                        'expires_at': '<script>alert(1)</script>',
                    }],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200
            data = json.loads(response['body'])['data']
            assert data['qurl_link'] == 'https://qurl.link/#onetime'
            assert data['expires_at'] is None
            assert 'script' not in response['body'].lower()

    def test_upload_502_when_connector_200_with_success_false(self, mock_dynamodb, upload_event):
        """
        Connector 200 with `{success: false}` is also a gateway failure
        — the upstream returned 2xx but said the operation didn't
        happen. Force 502 instead of mirroring the misleading 200.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                return _mock_connector_response(200, {
                    'success': False,
                    'error': 'No file provided',  # safe-allowlisted prefix
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            body = json.loads(response['body'])
            # Allowlisted error string still surfaces — the upgrade to
            # 502 is independent of the message redaction.
            assert body['error'] == 'No file provided'

    def test_upload_500_when_connector_base_url_is_not_https(self, mock_dynamodb, upload_event):
        """
        Defense-in-depth: tf validation requires https://, but a
        console-edited env var would otherwise let plaintext through.
        Scoped to the upload handler (not module import) so the URL-
        mode routes and /playground/health stay green for on-call
        diagnostics even if the upload-side env var is misconfigured.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            original = pp.CONNECTOR_BASE_URL
            pp.CONNECTOR_BASE_URL = 'http://insecure.example.com'
            try:
                with patch('urllib.request.urlopen') as mock_urlopen:
                    response = pp.lambda_handler(upload_event, None)
                assert response['statusCode'] == 500
                assert 'misconfigured' in json.loads(response['body'])['error']
                mock_urlopen.assert_not_called()
            finally:
                pp.CONNECTOR_BASE_URL = original

    def test_health_still_works_when_connector_base_url_is_bad(self, mock_dynamodb):
        """
        Scoping the https check to handle_upload means /playground/health
        must remain available even when CONNECTOR_BASE_URL is broken —
        on-call needs SOMETHING to ping to verify Lambda init.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            original = pp.CONNECTOR_BASE_URL
            pp.CONNECTOR_BASE_URL = 'http://insecure.example.com'
            try:
                event = {
                    'requestContext': {'http': {'method': 'GET', 'sourceIp': '1.2.3.4'}},
                    'rawPath': '/playground/health',
                    'headers': {'origin': 'https://layerv.ai'},
                    'pathParameters': None,
                    'body': None,
                }
                response = pp.lambda_handler(event, None)
                assert response['statusCode'] == 200
                assert json.loads(response['body'])['status'] == 'healthy'
            finally:
                pp.CONNECTOR_BASE_URL = original

    def test_upload_rejects_cross_origin_request(self, mock_dynamodb, upload_event):
        """
        CSRF defense: multipart/form-data is CORS-simple (no preflight),
        so a malicious site can submit an upload from a victim browser.
        Reject when Origin is set but not in ALLOWED_ORIGINS. Absent
        Origin (curl etc.) still works — CSRF only applies to browsers.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            upload_event['headers']['origin'] = 'https://evil.example.com'

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 403
            assert 'Origin not allowed' in json.loads(response['body'])['error']
            mock_urlopen.assert_not_called()

    def test_get_cors_origin_case_insensitive(self):
        """
        get_cors_origin reads via _get_header so it accepts both
        `origin` (HTTP API v2's normal case) and `Origin` (canonical
        case). Pin both so a future change to the helper can't drift
        the CSRF gate away from the ACAO echo.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.ALLOWED_ORIGINS = ['https://layerv.ai']

            for header_key in ('origin', 'Origin'):
                event = {'headers': {header_key: 'https://layerv.ai'}}
                assert pp.get_cors_origin(event) == 'https://layerv.ai', f'failed for {header_key!r}'

    def test_upload_rejects_origin_null(self, mock_dynamodb, upload_event):
        """
        Browsers send `Origin: null` for sandboxed iframes, file://,
        and data: URLs. The literal string 'null' is truthy and not in
        the allowlist → 403. Pin this so a future "accept any non-
        https origin" change can't quietly regress the gate.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            upload_event['headers']['origin'] = 'null'

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 403
            mock_urlopen.assert_not_called()

    def test_upload_allows_missing_origin(self, mock_dynamodb, upload_event):
        """
        Non-browser callers (curl, Discord bot, etc.) don't send an
        Origin header. They must NOT be blocked by the CSRF check —
        CSRF only applies to browser-initiated requests.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            del upload_event['headers']['origin']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_abc',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r.qurl.site',
                    })
                return _mock_connector_response(200, {
                    'success': True,
                    'links': [{'qurl_link': 'https://qurl.link/#onetime',
                               'expires_at': '2099-01-01T00:00:00Z'}],
                })

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 200

    def test_upload_integration_timeout_budget_fits(self, mock_dynamodb):
        """
        API Gateway's default integration timeout is 30s. The Lambda
        timeout (60s) is just an upper bound — the LIVE budget for any
        request is gated by the integration. Assert the default
        outbound caps fit comfortably under 30s with headroom.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp

            # 5s headroom for base64 decode + DynamoDB rate-limit writes
            # + cold-start M2M fetch + transport setup.
            assert (pp.UPLOAD_FORWARD_TIMEOUT_S + pp.MINT_FORWARD_TIMEOUT_S) <= 25, (
                f'upload {pp.UPLOAD_FORWARD_TIMEOUT_S}s + mint '
                f'{pp.MINT_FORWARD_TIMEOUT_S}s exceeds the 25s budget '
                f'(API GW integration timeout = 30s, with 5s headroom)'
            )

    def test_upload_rejects_unsafe_resource_id_from_connector(self, mock_dynamodb, upload_event):
        """
        Defense-in-depth: an attacker-controlled connector returning a
        resource_id with `/`, `?`, `#`, or path-traversal sequences
        could let the mint_link URL escape the connector's own
        namespace. Reject with 502 before forwarding.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            mint_called = []

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True,
                        'resource_id': '../../etc/passwd',  # malicious shape
                        'qurl_site': 'https://r.qurl.site',
                    })
                mint_called.append(req.full_url)
                return _mock_connector_response(200, {'success': True, 'links': [{}]})

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            assert 'invalid resource_id' in json.loads(response['body'])['error']
            assert mint_called == []  # mint MUST NOT be reached

    def test_upload_rejects_missing_is_base64_encoded(self, mock_dynamodb, upload_event):
        """
        HTTP API v2 sets isBase64Encoded=True for multipart bodies. A
        request missing the key entirely (not just False) must still
        be rejected — current behavior treats missing as falsy.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            del upload_event['isBase64Encoded']

            with patch('urllib.request.urlopen') as mock_urlopen:
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 400
            mock_urlopen.assert_not_called()

    def test_upload_502_when_connector_unreachable(self, mock_dynamodb, upload_event):
        """
        Network failure raising socket.timeout / URLError / etc. must
        translate to 502 with 'Upstream service unavailable' — pins
        the narrowed exception catch in _do_connector_call.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            with patch('urllib.request.urlopen', side_effect=socket.timeout()):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            body = json.loads(response['body'])
            assert 'Upload failed' in body['error'] or 'Upstream service unavailable' in body['error']

    def test_upload_502_when_connector_returns_non_json(self, mock_dynamodb, upload_event):
        """
        Connector 200 with a non-JSON body must surface as 502 — we
        can't tell whether the upstream operation actually succeeded,
        and propagating the 2xx would let handle_upload's status
        check pass on garbage.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                resp = MagicMock()
                resp.status = 200
                resp.read.return_value = b'<html>upstream proxy error page</html>'
                resp.__enter__ = MagicMock(return_value=resp)
                resp.__exit__ = MagicMock(return_value=False)
                return resp

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502
            body = json.loads(response['body'])
            assert 'error' in body

    @pytest.mark.parametrize('mint_payload,case', [
        ({'success': True}, 'links_key_absent'),
        ({'success': True, 'links': []}, 'links_empty'),
        ({'success': True, 'links': 'not-a-list'}, 'links_wrong_type'),
        ({'success': True, 'links': [{'expires_at': '...'}]}, 'first_link_missing_qurl_link'),
        ({'success': True, 'links': [{'qurl_link': ''}]}, 'first_link_empty_qurl_link'),
        ({'success': True, 'links': ['not-a-dict']}, 'first_link_not_a_dict'),
    ])
    def test_upload_502_on_malformed_mint_response(self, mock_dynamodb, upload_event,
                                                    mint_payload, case):
        """
        Mint-side response-shape contract — all malformed shapes return
        502 rather than crashing or surfacing the reusable upload-issued
        link. One parametrized test covers six branches that all share
        the same "first minted link is unusable" code shape.
        """
        with patch('boto3.resource'), patch('boto3.client'):
            import playground_proxy as pp
            pp.rate_table = mock_dynamodb['rate_table']

            def fake_urlopen(req, timeout=None):
                if '/api/upload' in req.full_url:
                    return _mock_connector_response(200, {
                        'success': True, 'resource_id': 'res_x',
                        'qurl_link': 'https://qurl.link/REUSABLE',
                        'qurl_site': 'https://r_x.qurl.site',
                    })
                return _mock_connector_response(200, mint_payload)

            with patch('urllib.request.urlopen', side_effect=fake_urlopen):
                response = pp.lambda_handler(upload_event, None)

            assert response['statusCode'] == 502, f'case={case}'
            assert 'REUSABLE' not in response['body'], f'case={case}'
