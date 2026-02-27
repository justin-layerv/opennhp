"""
QURL Playground Proxy Lambda

Proxies playground requests to the QURL sandbox API using server-side M2M
credentials. Enforces playground constraints: TTL cap (30m), rate limiting,
URL validation, and metadata tagging.

Endpoints:
    POST   /playground/qurl          - Create a playground QURL
    GET    /playground/qurl/{id}     - Get QURL status
    DELETE /playground/qurl/{id}     - Revoke a QURL
    POST   /playground/qurl/{id}/mint - Mint a link for a QURL
    GET    /playground/health        - Health check
"""

import json
import boto3
import hmac
import logging
import time
import os
import re
import ipaddress
import socket
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse

# JSON logging for CloudWatch Insights
_LOG_BUILTIN_KEYS = {
    'name', 'msg', 'args', 'created', 'filename', 'funcName', 'levelname',
    'levelno', 'lineno', 'module', 'msecs', 'pathname', 'process',
    'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName',
    'exc_info', 'exc_text', 'message', 'asctime', 'taskName',
}


class JSONFormatter(logging.Formatter):
    def format(self, record):
        record.message = record.getMessage()
        log = {
            'level': record.levelname,
            'message': record.message,
            'timestamp': self.formatTime(record),
        }
        for key, val in record.__dict__.items():
            if key not in _LOG_BUILTIN_KEYS:
                log[key] = val
        if record.exc_info and record.exc_info[0]:
            log['exception'] = self.formatException(record.exc_info)
        return json.dumps(log, default=str)


logger = logging.getLogger()
logger.setLevel(logging.INFO)
if logger.handlers:
    logger.handlers[0].setFormatter(JSONFormatter())
else:
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

# AWS clients
dynamodb = boto3.resource('dynamodb')

# Configuration from environment
QURL_API_URL = os.environ.get('QURL_API_URL', 'https://api.layerv.xyz')
M2M_SECRET_NAME = os.environ.get('M2M_SECRET_NAME', 'layerv/qurl-playground-m2m-credentials')
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', 'auth.layerv.ai')
RATE_TABLE_NAME = os.environ.get('RATE_TABLE_NAME', 'layerv-rate-limits')
ALLOWED_ORIGINS = os.environ.get(
    'ALLOWED_ORIGINS',
    'https://layerv.ai,https://www.layerv.ai,https://staging.layerv.ai'
).split(',')

# Rate limits for playground (configurable via env vars)
PLAYGROUND_IP_RATE_LIMIT = int(os.environ.get('PLAYGROUND_IP_RATE_LIMIT', '20'))
PLAYGROUND_GLOBAL_RATE_LIMIT = int(os.environ.get('PLAYGROUND_GLOBAL_RATE_LIMIT', '500'))
RATE_WINDOW = int(os.environ.get('RATE_WINDOW', '3600'))

# CI bypass key — loaded from Secrets Manager with 5-minute cache TTL
CI_BYPASS_SECRET_NAME = os.environ.get('CI_BYPASS_SECRET_NAME', '')
_ci_bypass_key = None
_ci_bypass_key_expires_at = 0
CI_BYPASS_CACHE_TTL = 300  # 5 minutes

# Playground constraints
MAX_TTL_MINUTES = 30
MAX_TTL_DURATION = '30m'
MAX_ACTIVE_QURLS_PER_IP = 10  # max active QURLs per IP per hour

# DynamoDB tables
rate_table = dynamodb.Table(RATE_TABLE_NAME)

# Duration parsing regex: accepts formats like "30m", "1h", "1h30m", "90s"
DURATION_RE = re.compile(r'^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$')

# Safe ID pattern: alphanumeric, hyphens, underscores only (max 64 chars)
QURL_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

# Module-level M2M token cache (persists across warm Lambda invocations)
_cached_token = None
_token_expires_at = 0


def lambda_handler(event, context):
    """Main Lambda entry point with method/path routing."""
    method = event.get('requestContext', {}).get('http', {}).get('method', '')

    # Handle CORS preflight
    if method == 'OPTIONS':
        return cors_response(event, 200, {})

    # Strip /prod prefix (API Gateway stage)
    path = event.get('rawPath', '')
    if path.startswith('/prod'):
        path = path[5:]

    # Extract path parameters (API Gateway v2 populates these for {id} patterns)
    path_params = event.get('pathParameters', {}) or {}
    qurl_id = path_params.get('id', '')

    # Validate qurl_id to prevent path traversal
    if qurl_id and not QURL_ID_RE.match(qurl_id):
        return cors_response(event, 400, {'error': 'Invalid QURL ID'})

    # Route to handlers
    if path == '/playground/health' and method == 'GET':
        return handle_health(event)
    elif path == '/playground/qurl' and method == 'POST':
        return handle_create_qurl(event)
    elif qurl_id and path == f'/playground/qurl/{qurl_id}' and method == 'GET':
        return handle_get_qurl(event, qurl_id)
    elif qurl_id and path == f'/playground/qurl/{qurl_id}' and method == 'DELETE':
        return handle_delete_qurl(event, qurl_id)
    elif qurl_id and path == f'/playground/qurl/{qurl_id}/mint' and method == 'POST':
        return handle_mint_link(event, qurl_id)
    else:
        return cors_response(event, 404, {'error': 'Not found'})


# ---------------------------------------------------------------------------
# Route Handlers
# ---------------------------------------------------------------------------

def handle_health(event):
    """Health check endpoint - verifies Lambda is running."""
    return cors_response(event, 200, {
        'status': 'healthy',
        'service': 'qurl-playground-proxy',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


def handle_create_qurl(event):
    """
    Create a playground QURL with enforced constraints.

    Validates target URL, caps TTL, tags with playground metadata,
    checks rate limits, then proxies to the QURL API.
    """
    # Parse request body
    try:
        body = json.loads(event.get('body', '{}'))
    except (json.JSONDecodeError, TypeError):
        return cors_response(event, 400, {'error': 'Invalid JSON'})

    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    # Rate limit check (per-IP and global) — skipped for CI bypass
    if not _is_ci_bypass(event):
        rate_error = check_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    # Validate target URL (must be HTTPS, no private/internal IPs)
    target_url = body.get('target_url', '')
    valid, error_msg = validate_target_url(target_url)
    if not valid:
        return cors_response(event, 400, {'error': error_msg})

    # Cap TTL to maximum allowed for playground
    expires_in = body.get('expires_in', MAX_TTL_DURATION)
    expires_in = cap_ttl(expires_in)

    # Build the proxied request body with playground constraints
    proxy_body = {
        'target_url': target_url,
        'expires_in': expires_in,
        'metadata': {
            'source': 'playground',
            'source_ip': source_ip,
        },
    }

    # Pass through optional fields if provided
    if 'max_sessions' in body:
        max_sessions = body['max_sessions']
        if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions < 1 or max_sessions > 100:
            return cors_response(event, 400, {'error': 'max_sessions must be an integer between 1 and 100'})
        proxy_body['max_sessions'] = max_sessions
    if 'description' in body:
        if not isinstance(body['description'], str):
            return cors_response(event, 400, {'error': 'description must be a string'})
        proxy_body['description'] = body['description'][:500]
    if 'one_time_use' in body:
        if not isinstance(body['one_time_use'], bool):
            return cors_response(event, 400, {'error': 'one_time_use must be a boolean'})
        proxy_body['one_time_use'] = body['one_time_use']
    if 'access_policy' in body:
        policy = body['access_policy']
        if not isinstance(policy, dict):
            return cors_response(event, 400, {'error': 'access_policy must be an object'})
        if 'allowed_ips' in policy:
            if not isinstance(policy['allowed_ips'], list) or \
               not all(isinstance(ip, str) for ip in policy['allowed_ips']):
                return cors_response(event, 400, {'error': 'access_policy.allowed_ips must be a list of strings'})
        if 'geo_restriction' in policy:
            if not isinstance(policy['geo_restriction'], str):
                return cors_response(event, 400, {'error': 'access_policy.geo_restriction must be a string'})
        proxy_body['access_policy'] = policy

    # Proxy to QURL API
    status, response_body = proxy_to_qurl_api('POST', '/v1/qurl', body=proxy_body)
    return cors_response(event, status, response_body)


def handle_get_qurl(event, qurl_id):
    """Get QURL status by ID."""
    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    if not _is_ci_bypass(event):
        rate_error = check_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    status, response_body = proxy_to_qurl_api('GET', f'/v1/qurls/{qurl_id}')
    return cors_response(event, status, response_body)


def handle_delete_qurl(event, qurl_id):
    """Revoke/delete a QURL by ID."""
    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    if not _is_ci_bypass(event):
        rate_error = check_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    status, response_body = proxy_to_qurl_api('DELETE', f'/v1/qurls/{qurl_id}')
    return cors_response(event, status, response_body)


def handle_mint_link(event, qurl_id):
    """Mint a new link for an existing QURL."""
    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    if not _is_ci_bypass(event):
        rate_error = check_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    # Parse optional body for mint parameters
    try:
        body = json.loads(event.get('body', '{}'))
    except (json.JSONDecodeError, TypeError):
        body = {}

    status, response_body = proxy_to_qurl_api('POST', f'/v1/qurls/{qurl_id}/mint_link', body=body)
    return cors_response(event, status, response_body)


# ---------------------------------------------------------------------------
# Auth0 M2M Token Management
# ---------------------------------------------------------------------------

def get_m2m_token():
    """
    Fetch or return cached Auth0 M2M token.

    On cold start, retrieves credentials from Secrets Manager and requests
    a new token from Auth0. Caches the token in a module-level variable
    until 60 seconds before expiry to avoid edge-case failures.
    """
    global _cached_token, _token_expires_at
    now = time.time()

    # Return cached token if still valid
    if _cached_token and now < _token_expires_at:
        return _cached_token

    # Fetch credentials from Secrets Manager
    sm = boto3.client('secretsmanager')
    secret = json.loads(
        sm.get_secret_value(SecretId=M2M_SECRET_NAME)['SecretString']
    )

    # Request token from Auth0
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': secret['client_id'],
        'client_secret': secret['client_secret'],
        'audience': secret['audience'],
    }).encode()

    req = urllib.request.Request(
        f'https://{AUTH0_DOMAIN}/oauth/token',
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_data = json.loads(resp.read())
    except Exception as e:
        logger.error("Auth0 token request failed", extra={"error": str(e)})
        raise RuntimeError('Failed to obtain M2M token') from e

    _cached_token = token_data['access_token']
    # Cache until 60s before expiry to avoid using an about-to-expire token
    _token_expires_at = now + token_data.get('expires_in', 3600) - 60
    return _cached_token


# ---------------------------------------------------------------------------
# QURL API Proxy
# ---------------------------------------------------------------------------

def proxy_to_qurl_api(method, path, body=None, _retry=False):
    """
    Proxy a request to the QURL API with M2M token.

    Returns (status_code, response_body) tuple. On 401, invalidates the
    cached token and retries once with a fresh token.
    """
    try:
        token = get_m2m_token()
    except RuntimeError as e:
        logger.error("M2M token error", extra={"error": str(e)})
        return 502, {'error': {'detail': 'Authentication service unavailable'}}

    url = f"{QURL_API_URL}{path}"

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            response_body = json.loads(raw) if raw else {}
            return resp.status, response_body
    except urllib.error.HTTPError as e:
        # On 401, invalidate cached token and retry once
        if e.code == 401 and not _retry:
            global _cached_token, _token_expires_at
            _cached_token = None
            _token_expires_at = 0
            logger.warning("QURL API returned 401, retrying with fresh token")
            return proxy_to_qurl_api(method, path, body, _retry=True)
        raw_body = e.read()
        try:
            error_body = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            logger.error("Upstream error with unparseable body",
                         extra={"status": e.code, "path": path, "body": raw_body.decode('utf-8', errors='replace')[:500]})
            error_body = {'error': {'detail': 'Upstream request failed'}}
        return e.code, error_body
    except Exception as e:
        logger.error("QURL API proxy error", extra={"error": str(e)})
        return 502, {'error': {'detail': 'Upstream service unavailable'}}


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------

def _is_ip_safe(ip):
    """
    Check if an IP address is safe (not private/internal/loopback/link-local/reserved).

    Also checks IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) by extracting
    the mapped IPv4 address and validating it separately.
    """
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        return False
    # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.0.1)
    if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped:
        mapped = ip.ipv4_mapped
        if mapped.is_private or mapped.is_loopback or mapped.is_reserved or mapped.is_link_local:
            return False
    return True


def validate_target_url(url):
    """
    Validate target URL is safe for playground use.

    Requirements:
    - Must use HTTPS scheme
    - Must have a valid hostname
    - Must not point to private/internal/loopback/reserved IPs
    - Must not use internal hostnames (localhost, metadata services, etc.)

    Returns (is_valid, error_message) tuple.
    """
    if not url:
        return False, 'Target URL is required'

    try:
        parsed = urlparse(url)

        # Must be HTTPS
        if parsed.scheme != 'https':
            return False, 'Target URL must use HTTPS'

        if not parsed.hostname:
            return False, 'Invalid URL'

        # Block common internal hostnames first (before DNS resolution)
        hostname_lower = parsed.hostname.lower()
        blocked_hostnames = (
            'localhost',
            'metadata.google.internal',
            'instance-data',
            '169.254.169.254',
        )
        if hostname_lower in blocked_hostnames:
            return False, 'Internal hostnames are not allowed'

        # Block link-local addresses that might bypass the IP check
        if hostname_lower.endswith('.internal') or hostname_lower.endswith('.local'):
            return False, 'Internal hostnames are not allowed'

        # Block private/reserved IPs (prevents SSRF)
        # Note: This Lambda proxies to a trusted QURL API, not to the target URL
        # directly. This validation is defense-in-depth to prevent storing QURLs
        # that point to internal resources.
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if not _is_ip_safe(ip):
                return False, 'Private/internal URLs are not allowed'
        except ValueError:
            # Not an IP literal — resolve hostname and check all resolved IPs
            # Double-resolve to mitigate DNS rebinding (attacker DNS alternating
            # between public and private IPs across lookups)
            try:
                addrs1 = socket.getaddrinfo(parsed.hostname, None, proto=socket.IPPROTO_TCP)
                addrs2 = socket.getaddrinfo(parsed.hostname, None, proto=socket.IPPROTO_TCP)
                all_ips = {addr[4][0] for addr in addrs1} | {addr[4][0] for addr in addrs2}
                if not all_ips:
                    return False, 'Could not resolve hostname'
                for ip_str in all_ips:
                    resolved_ip = ipaddress.ip_address(ip_str)
                    if not _is_ip_safe(resolved_ip):
                        return False, 'Private/internal URLs are not allowed'
            except socket.gaierror:
                return False, 'Could not resolve hostname'

        return True, None

    except Exception:
        return False, 'Invalid URL format'


# ---------------------------------------------------------------------------
# TTL Capping
# ---------------------------------------------------------------------------

def parse_duration_minutes(duration_str):
    """
    Parse a duration string (e.g. "30m", "1h", "1h30m", "90s") into minutes.

    Returns the duration in minutes, or None if parsing fails.
    """
    if not duration_str or not isinstance(duration_str, str):
        return None

    match = DURATION_RE.match(duration_str.strip())
    if not match or not any(match.groups()):
        return None

    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)

    total_minutes = hours * 60 + minutes + (seconds / 60)
    return total_minutes


def cap_ttl(expires_in):
    """
    Cap the TTL to the maximum allowed for playground QURLs.

    If the provided duration exceeds MAX_TTL_MINUTES (30m), clamp it down.
    If the duration is unparseable, use the max as a safe default.
    """
    if not expires_in:
        return MAX_TTL_DURATION

    total_minutes = parse_duration_minutes(str(expires_in))

    if total_minutes is None:
        # Unparseable duration, use the cap as default
        return MAX_TTL_DURATION

    if total_minutes > MAX_TTL_MINUTES:
        return MAX_TTL_DURATION

    return str(expires_in)


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

_cloudwatch = None


def _get_ci_bypass_key():
    """Load CI bypass key from Secrets Manager (cached with 5-minute TTL)."""
    global _ci_bypass_key, _ci_bypass_key_expires_at
    if _ci_bypass_key is not None and time.time() < _ci_bypass_key_expires_at:
        return _ci_bypass_key
    if not CI_BYPASS_SECRET_NAME:
        return ''
    try:
        sm = boto3.client('secretsmanager')
        resp = sm.get_secret_value(SecretId=CI_BYPASS_SECRET_NAME)
        _ci_bypass_key = resp.get('SecretString', '')
        _ci_bypass_key_expires_at = time.time() + CI_BYPASS_CACHE_TTL
        return _ci_bypass_key
    except Exception as e:
        logger.warning("Failed to load CI bypass key", extra={"error": str(e)})
        return ''


def _is_ci_bypass(event):
    """Check if request has a valid CI bypass header to skip rate limiting."""
    bypass_key = _get_ci_bypass_key()
    if not bypass_key:
        return False
    headers = event.get('headers', {}) or {}
    ci_key = headers.get('x-ci-key', '')
    if ci_key and hmac.compare_digest(ci_key, bypass_key):
        source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')
        logger.info("CI bypass: rate limiting skipped", extra={"source_ip": source_ip})
        return True
    return False


def _emit_rate_limit_fail_open_metric(function_name):
    """Emit a CloudWatch metric when rate limiting fails open (DynamoDB error)."""
    global _cloudwatch
    try:
        if _cloudwatch is None:
            _cloudwatch = boto3.client('cloudwatch')
        _cloudwatch.put_metric_data(
            Namespace='LayerV/DeveloperPortal',
            MetricData=[{
                'MetricName': 'RateLimitFailOpen',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'FunctionName', 'Value': function_name},
                ],
            }]
        )
    except Exception as metric_err:
        logger.warning("Failed to emit fail-open metric",
                        extra={"error": str(metric_err)})


def _atomic_rate_check(key, limit, window_seconds):
    """
    Atomically check and increment a rate limit counter.

    Uses conditional DynamoDB updates to prevent race conditions where
    concurrent requests could both read under-limit and then both increment.

    Returns True if allowed, False if rate limited.
    """
    now = int(time.time())
    window_start = now - window_seconds

    try:
        # If window has expired, reset the counter
        try:
            rate_table.update_item(
                Key={'ip': key},
                UpdateExpression='SET #c = :one, #ws = :now, #ttl = :ttl',
                ConditionExpression='attribute_not_exists(#ws) OR #ws < :window_start',
                ExpressionAttributeNames={
                    '#c': 'count',
                    '#ws': 'window_start',
                    '#ttl': 'ttl'
                },
                ExpressionAttributeValues={
                    ':one': 1,
                    ':now': now,
                    ':ttl': now + window_seconds,
                    ':window_start': window_start,
                }
            )
            return True  # Window was expired or new key, reset and allowed
        except rate_table.meta.client.exceptions.ConditionalCheckFailedException:
            pass  # Window is still current, proceed to increment

        # Window is current — increment with limit check
        rate_table.update_item(
            Key={'ip': key},
            UpdateExpression='SET #c = #c + :inc, #ttl = :ttl',
            ConditionExpression='#c < :limit',
            ExpressionAttributeNames={
                '#c': 'count',
                '#ttl': 'ttl'
            },
            ExpressionAttributeValues={
                ':inc': 1,
                ':ttl': now + window_seconds,
                ':limit': limit,
            }
        )
        return True  # Under limit, allowed

    except rate_table.meta.client.exceptions.ConditionalCheckFailedException:
        return False  # At or over limit


def check_rate_limits(ip):
    """
    Check per-IP and global rate limits for playground requests.

    Uses atomic conditional updates to prevent race conditions.
    Returns error message if rate limited, None if allowed.
    """
    try:
        ip_key = f"playground:ip:{ip}"
        if not _atomic_rate_check(ip_key, PLAYGROUND_IP_RATE_LIMIT, RATE_WINDOW):
            logger.warning("Playground IP rate limit exceeded", extra={"ip": ip})
            return 'Too many requests. Please try again later.'

        global_key = 'playground:global'
        if not _atomic_rate_check(global_key, PLAYGROUND_GLOBAL_RATE_LIMIT, RATE_WINDOW):
            logger.warning("Playground global rate limit exceeded")
            return 'Service temporarily unavailable. Please try again later.'

        return None  # Not rate limited

    except Exception as e:
        logger.error("Rate limit check error", extra={"error": str(e)})
        _emit_rate_limit_fail_open_metric('playground')
        return None  # Fail open (allow request if rate limiting fails)


# ---------------------------------------------------------------------------
# CORS Helpers
# ---------------------------------------------------------------------------

def get_cors_origin(event):
    """Return allowed origin if request origin is in whitelist, else first allowed origin."""
    origin = (event.get('headers') or {}).get('origin', '')
    if origin in ALLOWED_ORIGINS:
        return origin
    return ALLOWED_ORIGINS[0] if ALLOWED_ORIGINS else 'https://layerv.ai'


def cors_response(event, status, body):
    """Build a JSON response with CORS headers."""
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Access-Control-Allow-Origin': get_cors_origin(event),
            'Access-Control-Allow-Methods': 'POST, GET, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        },
        'body': json.dumps(body)
    }
