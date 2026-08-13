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
    POST   /playground/upload        - Upload a file and return a one-time qURL
    GET    /playground/health        - Health check
"""

import base64
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
# NOTE: MAX_ACTIVE_QURLS_PER_IP is declared but not enforced anywhere
# in this module — the active live cap is `check_rate_limits` (which
# counts ALL playground requests per-IP, regardless of route or
# resulting resource lifetime). Both URL-mode and /playground/upload
# share that counter. Kept here as documentation of an aspirational
# control; removing would require flagging a future cap implementation.
MAX_ACTIVE_QURLS_PER_IP = 10  # max active QURLs per IP per hour (unused — see note above)

# Fixed-resource demo (the /qurl LiveDemo's "hidden app"). The demo publishes
# one constant protected-resource URL whose hostname is deliberately dark (no
# DNS record — invisibility is the point), so the normal create path can never
# resolve or SSRF-validate it. When all three values are set, a create request
# for EXACTLY that URL instead mints a fresh link for the pre-provisioned
# connector resource that serves the hidden page. Any value empty (the
# default) disables the demo path entirely.
PLAYGROUND_DEMO_TARGET_URL = os.environ.get('PLAYGROUND_DEMO_TARGET_URL', '')
PLAYGROUND_DEMO_RESOURCE_ID = os.environ.get('PLAYGROUND_DEMO_RESOURCE_ID', '')
PLAYGROUND_DEMO_QURL_SITE = os.environ.get('PLAYGROUND_DEMO_QURL_SITE', '')

# File upload constraints (POST /playground/upload).
# Cap below Lambda's 6 MB sync payload limit so a base64-encoded multipart
# body still fits with envelope overhead. Tune via env if Lambda is moved
# behind a Function URL (10 MB sync limit) or async invocation.
CONNECTOR_BASE_URL = os.environ.get('CONNECTOR_BASE_URL', 'https://getqurllink.layerv.ai')
MAX_UPLOAD_BYTES = int(os.environ.get('PLAYGROUND_MAX_UPLOAD_BYTES', str(4 * 1024 * 1024)))
UPLOAD_FORWARD_TIMEOUT_S = int(os.environ.get('PLAYGROUND_UPLOAD_TIMEOUT', '15'))
MINT_FORWARD_TIMEOUT_S = int(os.environ.get('PLAYGROUND_MINT_TIMEOUT', '8'))

# Connector error strings that are safe to pass through to the browser.
# The connector's other 5xx-flavored messages have the shape "Upload
# failed: <storage error>" or "qURL creation failed: <upstream error>"
# — those can contain bucket names, S3 error codes, qURL API stack
# detail; render them as a generic message instead of reflecting raw.
# Source: qurl-integrations-infra/qurl-s3-connector/API.md.
#
# CONNECTOR RESPONSIBILITY: matching is by PREFIX, but the full string
# is reflected to the browser. The connector MUST NOT append sensitive
# context to these prefixes (e.g. "Type not allowed: rejected by
# av-scanner@av.internal:8080" would leak an internal hostname). If a
# new allowlisted prefix is added here, audit the connector's complete
# error message shape, not just its lead token.
_CONNECTOR_SAFE_ERROR_PREFIXES = (
    'No file provided',
    'File too large',
    'Type not allowed',
    # `viewer_ttl_seconds must be a finite decimal at least 0.5` /
    # `viewer_ttl_seconds value too long (max 32 characters)` —
    # connector validation errors that name the field as their lead
    # token. Pinning the `must` / `value` suffix would over-fit on
    # the current strings; the broader `viewer_ttl_seconds` prefix
    # accepts any future copy edit of those messages as long as the
    # connector keeps the field name at the front (verified in
    # qurl-s3-connector/internal/handler/handler.go upload error
    # paths).
    'viewer_ttl_seconds ',
)

# DynamoDB tables
rate_table = dynamodb.Table(RATE_TABLE_NAME)

# Duration parsing regex: accepts formats like "30m", "1h", "1h30m", "90s"
DURATION_RE = re.compile(r'^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$')

# Safe ID pattern: alphanumeric, hyphens, underscores only (max 64 chars)
QURL_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

# Strict multipart Content-Type check: the literal token followed by
# end-of-string OR a separator (`;`, whitespace). Case-insensitive.
# Rejects pathological values like `multipart/form-datazoo` that
# would slip through a bare `startswith`. Used with `re.match`, so no
# leading `^` needed (re.match already anchors at the start).
_MULTIPART_CT_RE = re.compile(r'multipart/form-data(\s*$|\s*;)', re.IGNORECASE)

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
    elif path == '/playground/upload' and method == 'POST':
        return handle_upload(event)
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

    target_url = body.get('target_url', '')

    # Fixed-resource demo: a dark hostname can never pass validate_target_url,
    # so a create for exactly the demo URL mints from the pre-provisioned
    # resource instead (rate limits above still applied).
    if _is_demo_target(target_url):
        return handle_demo_mint(event, body)

    # Validate target URL (must be HTTPS, no private/internal IPs)
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
    status, response_body = proxy_to_qurl_api('POST', '/v1/qurls', body=proxy_body)
    return cors_response(event, status, response_body)


def _is_demo_target(target_url):
    """
    True when the fixed-resource demo is configured and target_url is its URL.

    The comparison is a deliberate coupled contract with the website LiveDemo
    constant (layervai/website PR #630's PROTECTED_RESOURCE_URL). Trailing
    slashes and letter case are normalized away — the two most likely drift
    footguns — but nothing else is: any other variant silently falls through
    to validate_target_url and the client's simulated-link fallback. The
    config side is regex-pinned to a bare lowercase-scheme https host.
    """
    if not (PLAYGROUND_DEMO_TARGET_URL and PLAYGROUND_DEMO_RESOURCE_ID and PLAYGROUND_DEMO_QURL_SITE):
        return False
    if not isinstance(target_url, str):
        return False
    return target_url.rstrip('/').lower() == PLAYGROUND_DEMO_TARGET_URL.rstrip('/').lower()


def _demo_mint_body(body):
    """
    Clamp a caller body to the demo mint contract: capped TTL, validated
    one_time_use, and nothing else. The demo resource's id is public, so
    caller-controlled expiry (`expires_in` beyond the cap, or the absolute
    `expires_at` escape hatch) and session/policy parameters must never
    reach the upstream mint for it.

    Returns (mint_body, None) on success or (None, error_body) for a 400.
    """
    if not isinstance(body, dict):
        body = {}
    mint_body = {'expires_in': cap_ttl(body.get('expires_in', MAX_TTL_DURATION))}
    if 'one_time_use' in body:
        if not isinstance(body['one_time_use'], bool):
            return None, {'error': 'one_time_use must be a boolean'}
        mint_body['one_time_use'] = body['one_time_use']
    return mint_body, None


def handle_demo_mint(event, body):
    """
    Mint a link for the pre-provisioned fixed demo resource.

    Reuses the create request/response contract so the demo client needs no
    special casing: TTL is capped like create, one_time_use is validated like
    create, and the response carries the same envelope. Create-only options
    (description, max_sessions, access_policy) are ignored — mint_link is a
    different upstream contract and the demo resource's policy is not
    caller-controlled.
    """
    mint_body, error_body = _demo_mint_body(body)
    if error_body is not None:
        return cors_response(event, 400, error_body)

    status, upstream = proxy_to_qurl_api(
        'POST', f'/v1/qurls/{PLAYGROUND_DEMO_RESOURCE_ID}/mint_link', body=mint_body)
    if not 200 <= status < 300:
        # Pass upstream errors through untouched; the demo client falls back
        # to a simulated link on any failure — which means this branch firing
        # persistently is INVISIBLE to end users (they just get fake links).
        # Log loudly: the exact message literal feeds the
        # PlaygroundDemoMintFailures metric filter + alarm in playground.tf.
        error_code = None
        if isinstance(upstream, dict) and isinstance(upstream.get('error'), dict):
            error_code = upstream['error'].get('code')
        logger.warning("Demo mint upstream failure", extra={
            "resource_id": PLAYGROUND_DEMO_RESOURCE_ID,
            "status": status,
            "error_code": error_code,
        })
        return cors_response(event, status, upstream)

    data = upstream.get('data') if isinstance(upstream, dict) else None
    qurl_link = data.get('qurl_link') if isinstance(data, dict) else None
    if not qurl_link:
        logger.error("Demo mint returned 2xx without qurl_link",
                     extra={"status": status,
                            "keys": sorted(data.keys()) if isinstance(data, dict) else None})
        return cors_response(event, 502, {'error': {'detail': 'Upstream request failed'}})

    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')
    logger.info("Playground demo mint", extra={
        "resource_id": PLAYGROUND_DEMO_RESOURCE_ID,
        "qurl_id": data.get('qurl_id'),
        "source_ip": source_ip,
    })

    return cors_response(event, status, {'data': {
        'resource_id': PLAYGROUND_DEMO_RESOURCE_ID,
        'qurl_id': data.get('qurl_id'),
        'qurl_link': qurl_link,
        'qurl_site': PLAYGROUND_DEMO_QURL_SITE,
        'expires_at': data.get('expires_at'),
    }})


def handle_get_qurl(event, qurl_id):
    """
    Get QURL status by ID.

    Deliberately NOT guarded for the public demo resource id (unlike DELETE,
    and unlike the mint clamp): this is read-only, rate-limited, and the demo
    resource's identity and site are already public by design — its upstream
    status reveals nothing sensitive, while a guard would special-case the
    one id for no concrete risk reduction.
    """
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

    # The fixed demo resource's id is public (every demo response includes
    # it), so the shared long-lived resource must not be revocable through
    # the anonymous playground. Other ids stay deletable as before — their
    # creators are the only ones who learn them. Unlike _is_demo_target,
    # this deliberately keys on the id alone (not the all-or-none trio):
    # protecting the resource must survive any out-of-band env drift.
    if PLAYGROUND_DEMO_RESOURCE_ID and qurl_id == PLAYGROUND_DEMO_RESOURCE_ID:
        return cors_response(event, 403, {'error': 'The demo resource cannot be revoked'})

    status, response_body = proxy_to_qurl_api('DELETE', f'/v1/qurls/{qurl_id}')
    # Upstream returns 204 No Content on success; normalize to 200 with a body
    # so the browser can parse the JSON response.
    if status == 204:
        status = 200
        response_body = {'data': {'resource_id': qurl_id, 'status': 'revoked'}}
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

    # The fixed demo resource's id is public (every demo response includes
    # it), and this raw passthrough would otherwise let anonymous callers
    # mint links to the hidden app with an uncapped TTL (via expires_in OR
    # the absolute expires_at) and arbitrary session/policy parameters.
    # Clamp demo-id mints to the same contract as handle_demo_mint. Other
    # ids DELIBERATELY keep the raw passthrough: they are unguessable
    # (r_ + random) and known only to their creators, so the playground
    # 30m cap is not enforced on this route for them today — whether it
    # should be is tracked separately (see the issue referenced in the
    # PR that added this clamp).
    if PLAYGROUND_DEMO_RESOURCE_ID and qurl_id == PLAYGROUND_DEMO_RESOURCE_ID:
        body, error_body = _demo_mint_body(body)
        if error_body is not None:
            return cors_response(event, 400, error_body)

    # Response stays raw passthrough even for the demo id — the clamp above
    # hardens the REQUEST only. handle_demo_mint's 502-normalization of a
    # linkless 2xx is deliberately not mirrored here: this route's contract
    # is the true upstream response, and it is not the LiveDemo client path.
    status, response_body = proxy_to_qurl_api('POST', f'/v1/qurls/{qurl_id}/mint_link', body=body)
    return cors_response(event, status, response_body)


def handle_upload(event):
    """
    Upload a file and return a one-time-use qURL.

    Browser → playground proxy:
        POST /playground/upload  (multipart/form-data, single "file" field)

    The proxy rate-limits per-IP, enforces a size cap, then chains two
    server-side calls against the S3 connector:
        1. POST {CONNECTOR_BASE_URL}/api/upload      — stores the file in S3
                                                      and creates a qURL.
        2. POST {CONNECTOR_BASE_URL}/api/mint_link/{resource_id}
                                                      — mints a single-use
                                                      qURL link against
                                                      that resource.

    The /api/upload-issued qurl_link is discarded; only the minted one-time
    link is returned to the browser. This is the contract advertised by the
    /demo page ("self-destructs after the first access"). See the connector
    /api/upload API docs for why one_time_use is opt-in via mint_link.

    Response (playground envelope, matches POST /playground/qurl shape):
        {"data": {
            "qurl_link": "<one-time link from mint_link>",
            "qurl_site": "<invisible-by-default site from /api/upload>",
            "resource_id": "<connector resource id>",
            "expires_at": "<minted link expiry, ISO 8601>"
        }}
    """
    # Defense-in-depth: terraform validation also requires https://,
    # but an out-of-band env-var change (console edit, manual SAM
    # deploy) would otherwise let plaintext through. Scoped to this
    # handler (not module-import) so /playground/health and the URL-
    # mode routes stay green for on-call diagnostics even if the
    # upload-side env var is misconfigured.
    if not CONNECTOR_BASE_URL.startswith('https://'):
        logger.error("CONNECTOR_BASE_URL must use https://",
                     extra={"prefix": CONNECTOR_BASE_URL[:16]})
        return cors_response(event, 500, {'error': 'Server misconfigured'})

    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    # Rate limit FIRST. A cross-origin or no-origin attacker still
    # consumes Lambda invocations + log lines per request; running the
    # rate-limit increment ahead of the CSRF gate makes per-IP flood
    # protection actually bound the abuse rate.
    # Trade-off: a CSRF amplification attack from evil.example.com
    # burns the *victim's* per-IP bucket — legitimate users sharing
    # the NAT can lose /playground/qurl access too. Cost containment
    # wins here over fair-sharing; revisit if the demo grows.
    if not _is_ci_bypass(event):
        rate_error = check_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    # CSRF defense: multipart/form-data is a CORS "simple" content type,
    # so browsers do NOT preflight a cross-origin POST of an upload.
    # A malicious site could otherwise submit a form against this route
    # from a victim browser and create real qURLs charged to the
    # victim's per-IP rate-limit bucket. Reject when an Origin header
    # is present but not in our allowlist; absent Origin (curl,
    # non-browser clients) is fine since CSRF only applies to browsers.
    # Note: this is CSRF defense, not auth — the route is still
    # anonymous, and rate limiting remains the abuse control.
    headers = event.get('headers') or {}
    origin = _get_header(headers, 'Origin')
    if origin and origin not in ALLOWED_ORIGINS:
        logger.warning("Upload rejected: cross-origin", extra={"origin": origin[:128]})
        return cors_response(event, 403, {'error': 'Origin not allowed'})

    # Validate cheap things first (header shape, body presence, body size)
    # before paying for the base64 decode of up to a multi-MB body.
    content_type = _get_header(headers, 'Content-Type')
    # Strict match: "multipart/form-data" followed by end-of-string,
    # whitespace, or `;`. `startswith` alone would let pathological
    # values like `multipart/form-datazoo` through (no real browser
    # emits that, but be explicit).
    if not _MULTIPART_CT_RE.match(content_type):
        return cors_response(event, 400, {'error': 'Content-Type must be multipart/form-data'})

    # Defense-in-depth: reject embedded CR/LF in Content-Type before
    # we forward it as an outbound header. CPython's http.client also
    # rejects CRLF (InvalidHeader), but our doctrine is "validate at
    # the boundary" — and a future stdlib change relaxing this would
    # be a silent header-injection vector against the connector.
    if '\r' in content_type or '\n' in content_type:
        logger.warning("Upload rejected: CRLF in Content-Type")
        return cors_response(event, 400, {'error': 'Invalid Content-Type'})

    # Empty body is the cheapest, most-accurate reject — fire before
    # the base64-encoding check so a zero-byte upload doesn't get told
    # "Expected base64-encoded …".
    raw_body = event.get('body') or ''
    if not raw_body:
        return cors_response(event, 400, {'error': 'Empty request body'})

    # API Gateway HTTP API (payload v2.0) base64-encodes binary bodies.
    # Reject non-base64 bodies for multipart so we never silently corrupt
    # the file by re-encoding text bytes — the route is multipart-only.
    if not event.get('isBase64Encoded', False):
        return cors_response(event, 400, {'error': 'Expected base64-encoded multipart/form-data body'})

    # Pre-check the encoded length against the decoded cap before
    # decoding so an oversize request short-circuits without paying
    # for the multi-MB base64 → bytes allocation. Base64 inflates by
    # 4/3, so the encoded body of a MAX_UPLOAD_BYTES file is at most
    # (MAX + 2) // 3 * 4 bytes (round up for padding).
    max_encoded_len = ((MAX_UPLOAD_BYTES + 2) // 3) * 4
    if len(raw_body) > max_encoded_len:
        return cors_response(event, 413, {
            'error': f'File too large; max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB'
        })

    # validate=True rejects ANY whitespace inside the encoded body.
    # API Gateway HTTP API doesn't inject newlines today, but a future
    # WAF / edge proxy re-encoding could surface as a 400 here.
    try:
        file_bytes = base64.b64decode(raw_body, validate=True)
    except (ValueError, TypeError):
        return cors_response(event, 400, {'error': 'Invalid base64 request body'})

    if not file_bytes:
        # raw_body=='' was rejected upstream; this fires for inputs
        # like "====" (pure base64 padding that decodes to empty).
        # Distinct message so logs make the path obvious.
        return cors_response(event, 400, {'error': 'Empty multipart body after decode'})
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        # Belt-and-braces — encoded pre-check above usually catches this.
        return cors_response(event, 413, {
            'error': f'File too large; max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB'
        })

    # Filename + Content-Disposition header values come from the
    # browser and are forwarded byte-for-byte. Sanitization is the
    # connector's job (it owns the S3 key construction); intentionally
    # NOT adding defense-in-depth here so legitimate Unicode filenames
    # aren't broken by a well-meaning future filter. The connector's
    # behavior is asserted by its own tests (see qurl-s3-connector's
    # handler_test.go); a future loosening of THAT sanitizer is a
    # contract change this Lambda's owner needs to be told about.
    #
    # Step 1: forward multipart to the connector's upload endpoint.
    upload_status, upload_body = _forward_to_connector_upload(content_type, file_bytes)
    # Connector contract (qurl-s3-connector/API.md §1): a successful
    # `/api/upload` returns `{"success": true, ...}`. Failures return
    # `{"success": false, "error": "..."}`. Missing `success` (or a
    # non-dict body) is treated as failure-shape — defense-in-depth
    # against contract drift.
    body_is_failure_shape = (
        not isinstance(upload_body, dict) or not upload_body.get('success')
    )
    if upload_status != 200 or body_is_failure_shape:
        # Browser sees ONLY connector errors with vetted prefixes (size
        # cap, type cap, missing file). Strings like "Upload failed:
        # NoSuchBucket: bucket 'internal-bucket-name' does not exist"
        # are mapped to a generic message. CloudWatch logs see the raw
        # string (clipped) so on-call still has the diagnostic signal.
        raw_detail = upload_body.get('error') if isinstance(upload_body, dict) else None
        safe_detail = _safe_error_string(raw_detail)
        logger.warning(
            "Connector /api/upload failed",
            extra={
                "status": upload_status,
                "raw_detail": (raw_detail[:200] if isinstance(raw_detail, str) else None),
                "safe_detail": safe_detail,
            },
        )
        # Connector 2xx with a failure-shaped body is a gateway failure
        # — we couldn't trust the response, so we surface 502 instead
        # of mirroring the upstream's misleading 200. Connector 4xx
        # passes through (rate limit, type rejection, etc. are
        # user-actionable). 5xx maps to 502. (We've already entered
        # this block because status != 200 OR body_is_failure_shape, so
        # `upload_status == 200` implies body_is_failure_shape — no
        # need to repeat the conjunction.)
        if upload_status >= 500 or upload_status == 200:
            proxy_status = 502
        else:
            proxy_status = upload_status
        return cors_response(event, proxy_status, {
            'error': safe_detail or 'Upload failed'
        })

    resource_id = upload_body.get('resource_id')
    qurl_site = upload_body.get('qurl_site')

    # qurl_site flows into the response as a link target — require
    # https + non-empty hostname so a compromised connector can't
    # reflect a `javascript:` scheme. Per-env VIEW_DOMAIN is
    # configurable so we don't pin the exact host.
    if isinstance(qurl_site, str):
        qs_parsed = urlparse(qurl_site)
        if qs_parsed.scheme != 'https' or not qs_parsed.hostname:
            logger.error("Connector returned non-https or malformed qurl_site",
                         extra={"resource_id_present": bool(resource_id)})
            qurl_site = None
    else:
        qurl_site = None

    if not resource_id:
        # Log identifying keys only — never the full body. The connector's
        # success payload contains a presigned resource_url + qurl_link
        # that should not land in CloudWatch logs.
        logger.error("Connector upload returned no resource_id",
                     extra={"keys": sorted(upload_body.keys())})
        return cors_response(event, 502, {'error': 'Upload response missing resource_id'})

    # Defense-in-depth: the connector forwards an `r_<11 chars>` ID
    # generated by the qURL service (`domain.GenerateResourceID`:
    # prefix "r_" + 8 random bytes base64-RawURL-encoded + lowercased,
    # alphabet [a-z0-9_-]). Our QURL_ID_RE upper bound (64 chars) +
    # alphabet [a-zA-Z0-9_-] both accommodate the current format with
    # headroom. The check is a path-traversal guard, not a strict
    # format pin — if the qURL service ever widens the resource_id
    # alphabet (e.g., adds `.`), update QURL_ID_RE here too.
    if not QURL_ID_RE.match(resource_id):
        logger.error("Connector upload returned unsafe resource_id",
                     extra={"resource_id_len": len(resource_id)})
        return cors_response(event, 502, {'error': 'Upload response has invalid resource_id'})

    # Step 2: mint a one-time-use link for the resource.
    mint_status, mint_body = _forward_to_connector_mint_link(resource_id)
    if mint_status != 200 or not isinstance(mint_body, dict) or not mint_body.get('success'):
        # The upload succeeded but the mint did not — surfacing the
        # connector's reusable qurl_link here would silently break the
        # advertised "self-destructs after the first access" contract,
        # so fail loudly instead. S3 lifecycle on the connector's
        # bucket (qurl-integrations-infra/qurl-s3-connector/terraform/
        # s3-security.tf:565, prefix=uploads/) garbage-collects the
        # orphan within the configured retention window.
        # Mint-side errors all flow through the same upstream qURL API
        # ("n must not exceed 10", "qURL mint_link API error (NNN):
        # ..."); none are user-actionable, so always render generic.
        # CloudWatch still gets the raw upstream detail for triage.
        raw_detail = mint_body.get('error') if isinstance(mint_body, dict) else None
        logger.error(
            "Connector /api/mint_link failed after successful upload",
            extra={
                "status": mint_status,
                "raw_detail": (raw_detail[:200] if isinstance(raw_detail, str) else None),
                "resource_id": resource_id,
            },
        )
        return cors_response(event, 502, {
            'error': 'Failed to create one-time access link'
        })

    links = mint_body.get('links') or []
    if not links or not isinstance(links, list):
        logger.error("Mint response missing links array",
                     extra={"resource_id": resource_id, "keys": sorted(mint_body.keys())})
        return cors_response(event, 502, {'error': 'Mint response missing links'})

    minted = links[0]
    one_time_link = minted.get('qurl_link') if isinstance(minted, dict) else None
    if not one_time_link:
        # Only log shape, not the link object — defensive against future
        # connector fields that might contain sensitive values.
        logger.error("First minted link missing qurl_link",
                     extra={"resource_id": resource_id,
                            "link_keys": sorted(minted.keys()) if isinstance(minted, dict) else type(minted).__name__})
        return cors_response(event, 502, {'error': 'Minted link missing qurl_link'})

    # qurl_link is the user-clickable URL. Same scheme/host check as
    # qurl_site, but fails 502 (no usable fallback) instead of nulling.
    # No host allowlist: QURL_DOMAIN is per-env, and the trust model is
    # scheme/shape — not hostname pinning.
    qlink_parsed = urlparse(one_time_link)
    if qlink_parsed.scheme != 'https' or not qlink_parsed.hostname:
        logger.error("Minted link is not a valid https URL",
                     extra={"resource_id": resource_id,
                            "link_scheme": qlink_parsed.scheme or '<empty>'})
        return cors_response(event, 502, {'error': 'Minted link is malformed'})

    # `minted` is provably a dict at this point — `one_time_link` is a
    # truthy string pulled from `minted.get(...)` via the isinstance
    # gate above. Direct .get() instead of the redundant ternary.
    #
    # expires_at is also forwarded to the browser. Sanity-check that
    # it parses as ISO 8601 (matching the connector API contract — see
    # qurl-s3-connector/API.md) so a buggy/compromised connector
    # injecting arbitrary content doesn't reach the demo. Null out if
    # invalid; the upload still succeeded.
    minted_expires_at = minted.get('expires_at')
    if not _is_valid_iso8601(minted_expires_at):
        logger.warning("Minted link has invalid expires_at; dropping",
                       extra={"resource_id": resource_id})
        minted_expires_at = None

    return cors_response(event, 200, {
        'data': {
            'qurl_link': one_time_link,
            'qurl_site': qurl_site,
            'resource_id': resource_id,
            'expires_at': minted_expires_at,
        }
    })


def _forward_to_connector_upload(content_type, file_bytes):
    """
    POST the raw multipart body to the S3 connector's /api/upload.

    No Authorization header — the connector falls back to its own
    QURL_API_TOKEN service token, which is the same anonymous-caller path
    the browser used before this proxy existed.
    """
    req = urllib.request.Request(
        f'{CONNECTOR_BASE_URL}/api/upload',
        data=file_bytes,
        headers={'Content-Type': content_type},
        method='POST',
    )
    return _do_connector_call(req, UPLOAD_FORWARD_TIMEOUT_S, label='upload')


def _forward_to_connector_mint_link(resource_id):
    """
    POST {n:1, one_time_use:true} to the connector's mint_link endpoint.

    This is THE step that delivers the one-time-use semantics — the upload
    endpoint itself returns a multi-use link by default (see connector
    API.md note on one_time_use being opt-in via mint_link).
    """
    payload = json.dumps({'n': 1, 'one_time_use': True}).encode()
    # QURL_ID_RE already restricts resource_id to [a-zA-Z0-9_-]{1,64}
    # so quote() is a no-op today. Belt-and-braces against a future
    # widening of that regex: validate at the boundary AND escape at
    # use, matching the doctrine elsewhere in this module.
    req = urllib.request.Request(
        f'{CONNECTOR_BASE_URL}/api/mint_link/{urllib.parse.quote(resource_id, safe="")}',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    return _do_connector_call(req, MINT_FORWARD_TIMEOUT_S, label='mint_link')


def _is_valid_iso8601(value):
    """
    Return True if `value` is a tz-aware string that
    `datetime.fromisoformat` parses (a superset of RFC 3339, the
    connector's documented contract). The goal is shape-checking
    connector-returned `expires_at` so an injected `<script>...</script>`
    payload doesn't reach the browser — strict RFC 3339 conformance
    would also work but isn't needed for that. Python 3.11+
    `fromisoformat` accepts trailing `Z` natively, and the Lambda
    runtime is pinned to 3.12 (`playground.tf:runtime = "python3.12"`).
    """
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return False
    return parsed.tzinfo is not None


def _get_header(headers, name):
    """
    Case-insensitive header lookup. HTTP API v2 lowercases header keys
    per spec, but defensively check both forms so a test or future API
    change supplying the canonical-case variant doesn't break the
    handler. Used by both the CSRF gate (origin) and Content-Type
    check in handle_upload, AND by get_cors_origin's ACAO echo — keep
    these two in sync via this single helper rather than duplicating
    the dual-lookup pattern.
    """
    return headers.get(name.lower()) or headers.get(name) or ''


def _safe_error_string(err):
    """
    Return `err` iff it's a string that starts with a known-safe
    connector-error prefix — a user-actionable message we've vetted
    as not containing internal detail. Anything else returns None and
    the caller renders a generic error string.

    Takes the error string directly (not the wrapping dict) so callers
    can compute it once for both logging (raw, clipped) and the
    browser response (safe).
    """
    if not isinstance(err, str):
        return None
    stripped = err.strip()
    if not stripped:
        return None
    return stripped if stripped.startswith(_CONNECTOR_SAFE_ERROR_PREFIXES) else None


def _do_connector_call(req, timeout, label):
    """
    Execute an outbound urllib request to the S3 connector.

    Returns (status, parsed_body). `parsed_body` is whatever
    `json.loads` produces — typically a dict, but no shape is
    enforced (it could be a list / str / number / bool). Callers
    that depend on dict shape MUST gate on `isinstance(body, dict)`
    before reaching into it.

    On non-JSON 2xx → returns (502, {'error': 'Invalid connector
    response'}); on network error → (502, {'error': 'Upstream service
    unavailable'}). Both 502 paths return a dict, matching
    proxy_to_qurl_api's convention so callers don't need to
    special-case the failure shape.
    """
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                body = json.loads(raw) if raw else {}
            except (json.JSONDecodeError, ValueError):
                # Upstream returned 2xx with a non-JSON body — we can't
                # tell whether the operation actually succeeded, so
                # surface this as a gateway failure (502) rather than
                # propagating the upstream's 2xx, which would let
                # handle_upload's `if status != 200` check pass and
                # send the caller back garbage. Log only shape info
                # (Content-Type + length) rather than the raw body —
                # an unparseable payload from a proxy / edge / WAF
                # could contain presigned URLs or internal hostnames.
                logger.error(
                    f"Connector {label} returned non-JSON body",
                    extra={
                        "status": resp.status,
                        "length": len(raw),
                        "content_type": resp.headers.get('Content-Type', '<missing>'),
                    },
                )
                return 502, {'error': 'Invalid connector response'}
            return resp.status, body
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            body = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, ValueError):
            # Unparseable 4xx/5xx — clip the decoded body for diagnostic
            # purposes since by definition it's not a JSON envelope we
            # control. Kept short (200 chars) to bound exposure.
            body = {'error': raw.decode('utf-8', errors='replace')[:200] or 'Upstream error'}
        return e.code, body
    except (socket.timeout, urllib.error.URLError, ConnectionError, OSError) as e:
        # Narrow catch (was `Exception`): network-failure cases map to
        # 502 cleanly. Letting MemoryError / KeyboardInterrupt /
        # SystemExit propagate is correct — they indicate something the
        # Lambda runtime should handle, not silently translate to 502.
        logger.error(f"Connector {label} call failed", extra={"error": str(e)})
        return 502, {'error': 'Upstream service unavailable'}


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
    origin = _get_header(event.get('headers') or {}, 'Origin')
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
