"""
QURL Developer Credential Provisioner Lambda

Provides self-service API key provisioning for developers.
Implements email verification flow before issuing credentials.

Flow:
    1. Developer registers with email (POST /credentials/register)
    2. Verification email sent with a one-time token link
    3. Developer clicks link, token is verified (GET /credentials/verify)
    4. API key (lv_live_...) is generated, hashed, and stored in DynamoDB
    5. Plaintext key is shown once and emailed to the developer

Endpoints:
    POST /credentials/register  - Accept email, send verification link
    GET  /credentials/verify    - Verify email token, provision API key
    GET  /credentials/health    - Health check
"""

import json
import boto3
import hashlib
import hmac
import html as html_module
import logging
import secrets
import time
import re
import os
from datetime import datetime, timezone
from urllib.parse import quote

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
ses = boto3.client('ses', region_name=os.environ.get('SES_REGION', 'us-east-1'))

# Configuration from environment
CREDENTIALS_TABLE_NAME = os.environ.get('CREDENTIALS_TABLE_NAME', 'layerv-developer-credentials')
RATE_TABLE_NAME = os.environ.get('RATE_TABLE_NAME', 'layerv-rate-limits')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@layerv.ai')
SITE_URL = os.environ.get('SITE_URL', 'https://layerv.ai')
VERIFY_URL = os.environ.get('VERIFY_URL', 'https://api.layerv.ai')
ALLOWED_ORIGINS = os.environ.get(
    'ALLOWED_ORIGINS',
    'https://layerv.ai,https://www.layerv.ai,https://staging.layerv.ai'
).split(',')
NOTIFY_EMAIL = os.environ.get('NOTIFY_EMAIL', 'team@layerv.ai')
API_KEYS_TABLE_NAME = os.environ.get('API_KEYS_TABLE_NAME', '')
CUSTOMERS_TABLE_NAME = os.environ.get('CUSTOMERS_TABLE_NAME', '')
QURL_API_URL = os.environ.get('QURL_API_URL', 'https://api.layerv.xyz')

# Rate limiting (configurable via env vars)
REGISTRATION_RATE_LIMIT_IP = int(os.environ.get('REGISTRATION_RATE_LIMIT_IP', '5'))
REGISTRATION_RATE_WINDOW = int(os.environ.get('REGISTRATION_RATE_WINDOW', '86400'))
VERIFY_RATE_LIMIT_IP = int(os.environ.get('VERIFY_RATE_LIMIT_IP', '10'))
VERIFY_RATE_WINDOW = int(os.environ.get('VERIFY_RATE_WINDOW', '3600'))

# CI bypass key — loaded from Secrets Manager with 5-minute cache TTL
CI_BYPASS_SECRET_NAME = os.environ.get('CI_BYPASS_SECRET_NAME', '')
_ci_bypass_key = None
_ci_bypass_key_expires_at = 0
CI_BYPASS_CACHE_TTL = 300  # 5 minutes

# Email validation regex (compiled for performance)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# DynamoDB tables
credentials_table = dynamodb.Table(CREDENTIALS_TABLE_NAME)
rate_table = dynamodb.Table(RATE_TABLE_NAME)
api_keys_table = dynamodb.Table(API_KEYS_TABLE_NAME) if API_KEYS_TABLE_NAME else None
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None


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

    # Route to handlers
    if path == '/credentials/register' and method == 'POST':
        return handle_register(event)
    elif path == '/credentials/verify' and method == 'GET':
        return handle_verify(event)
    elif path == '/credentials/health' and method == 'GET':
        return handle_health(event)
    else:
        return cors_response(event, 404, {'error': 'Not found'})


# ---------------------------------------------------------------------------
# Route Handlers
# ---------------------------------------------------------------------------

def handle_register(event):
    """
    Handle developer registration requests.

    1. Validate email format
    2. Check if already provisioned
    3. Rate limit check
    4. Generate verification token
    5. Store in DynamoDB with TTL
    6. Send verification email
    """
    # Parse request body
    try:
        body = json.loads(event.get('body', '{}'))
    except (json.JSONDecodeError, TypeError):
        return cors_response(event, 400, {'error': 'Invalid JSON'})

    # Honeypot check (silent success for bots)
    # Frontend sends a hidden 'company' field — bots auto-fill it
    if body.get('company') or body.get('website'):
        return cors_response(event, 200, {'message': 'Check your email to verify and receive credentials.'})

    email = body.get('email', '').strip().lower()
    name = body.get('name', '').strip()[:200]  # Optional name, cap length

    # Email validation
    if not email or not EMAIL_REGEX.match(email):
        return cors_response(event, 400, {'error': 'Invalid email address'})

    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    # Rate limit check (per-IP, 5/day) — skipped for CI bypass
    if not _is_ci_bypass(event):
        rate_error = check_registration_rate_limits(source_ip)
        if rate_error:
            return cors_response(event, 429, {'error': rate_error})

    # Check if email already has provisioned credentials
    try:
        existing = credentials_table.get_item(Key={'email': email})
        item = existing.get('Item')
        if item and item.get('status') == 'provisioned':
            # Don't reveal whether email exists - same success message
            return cors_response(event, 200, {
                'message': 'Check your email to verify and receive credentials.'
            })
    except Exception as e:
        logger.error("DynamoDB lookup error", extra={"error": str(e)})
        # Continue - don't block registration on lookup failure

    # Generate verification token and store hash
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        credentials_table.put_item(
            Item={
                'email': email,
                'status': 'pending',
                'token_hash': token_hash,
                'name': name if name else 'N/A',
                'source_ip': source_ip,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'ttl': int(time.time()) + (48 * 3600)  # 48 hours to verify
            },
            ConditionExpression='attribute_not_exists(email) OR #s <> :provisioned',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':provisioned': 'provisioned'}
        )
    except credentials_table.meta.client.exceptions.ConditionalCheckFailedException:
        # Already provisioned - don't reveal, return same message
        return cors_response(event, 200, {
            'message': 'Check your email to verify and receive credentials.'
        })

    # Build verification link — VERIFY_URL points to the keys page which reads
    # token/email from query params on mount (KeysForm.tsx useEffect)
    verify_link = f"{VERIFY_URL}?token={token}&email={quote(email)}"

    # Send verification email
    try:
        ses.send_email(
            Source=FROM_EMAIL,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Verify your email for LayerV API credentials'},
                'Body': {
                    'Html': {'Data': _verification_email_html(verify_link)},
                    'Text': {'Data': _verification_email_text(verify_link)}
                }
            }
        )
    except Exception as e:
        logger.error("SES send error", extra={"error": str(e)})
        return cors_response(event, 500, {
            'error': 'Failed to send verification email. Please try again.'
        })

    return cors_response(event, 200, {
        'message': 'Check your email to verify and receive credentials.'
    })


def handle_verify(event):
    """
    Handle email verification and API key provisioning.

    1. Validate token + email
    2. Constant-time hash comparison
    3. Generate API key (lv_live_...)
    4. Store key hash in qurl-api-keys DynamoDB table
    5. Lazy-provision customer record in qurl-customers table
    6. Send API key email
    7. Return plaintext API key (shown once)
    """
    # Uniform error message to prevent enumeration
    VERIFY_ERROR = 'This verification link is invalid or has expired.'

    params = event.get('queryStringParameters', {}) or {}
    token = params.get('token', '')
    email = params.get('email', '').strip().lower()

    if not token or not email:
        return cors_response(event, 400, {'error': VERIFY_ERROR})

    source_ip = event.get('requestContext', {}).get('http', {}).get('sourceIp', 'unknown')

    # Rate limit verification attempts to prevent brute force — skipped for CI bypass
    if not _is_ci_bypass(event):
        verify_error = check_verify_rate_limits(source_ip)
        if verify_error:
            return cors_response(event, 429, {'error': 'Too many attempts. Please try again later.'})

    try:
        response = credentials_table.get_item(Key={'email': email})
        item = response.get('Item')

        # Missing record
        if not item:
            return cors_response(event, 400, {'error': VERIFY_ERROR})

        # Already provisioned or being provisioned — return same error as invalid token
        # to prevent email enumeration via the verify endpoint
        if item.get('status') in ('provisioned', 'provisioning'):
            return cors_response(event, 400, {'error': VERIFY_ERROR})

        # Check TTL explicitly (don't rely solely on DynamoDB TTL cleanup)
        if item.get('ttl') and int(item.get('ttl')) < int(time.time()):
            return cors_response(event, 400, {'error': VERIFY_ERROR})

        # Constant-time comparison of token hashes to prevent timing attacks
        provided_hash = hashlib.sha256(token.encode()).hexdigest()
        stored_hash = item.get('token_hash', '')

        if not stored_hash or not hmac.compare_digest(provided_hash, stored_hash):
            return cors_response(event, 400, {'error': VERIFY_ERROR})

        # Atomically claim the pending→provisioning transition to prevent
        # concurrent verify requests from both generating API keys
        try:
            credentials_table.update_item(
                Key={'email': email},
                UpdateExpression='SET #s = :provisioning, updated_at = :now',
                ConditionExpression='#s = :pending',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':pending': 'pending',
                    ':provisioning': 'provisioning',
                    ':now': datetime.now(timezone.utc).isoformat(),
                }
            )
        except credentials_table.meta.client.exceptions.ConditionalCheckFailedException:
            # Another request already claimed this — return generic error
            return cors_response(event, 400, {'error': VERIFY_ERROR})

        # Token is valid and claimed — generate API key
        try:
            key_data = generate_api_key()
            api_key = key_data['api_key']

            # Derive owner_id for bridge keys (email-based, pre-Auth0 login)
            email_hash = hashlib.sha256(email.encode()).hexdigest()
            owner_id = f"email:{email_hash}"
            now_iso = datetime.now(timezone.utc).isoformat()

            # Write to qurl-api-keys table
            if api_keys_table:
                api_keys_table.put_item(Item={
                    'key_hash': key_data['key_hash'],
                    'key_id': key_data['key_id'],
                    'key_prefix': key_data['key_prefix'],
                    'owner_id': owner_id,
                    'email': email,
                    'name': 'Default',
                    'scopes': ['qurl:read', 'qurl:write'],
                    'status': 'active',
                    'created_at': now_iso,
                    'last_used_at': now_iso,
                    'expires_at': '',  # Empty = never expires
                })

            # Write/update qurl-customers table (lazy provisioning)
            if customers_table:
                try:
                    customers_table.put_item(
                        Item={
                            'auth0_subject': owner_id,
                            'email': email,
                            'tier': 'free',
                            'created_at': now_iso,
                            'updated_at': now_iso,
                        },
                        ConditionExpression='attribute_not_exists(auth0_subject)'
                    )
                except customers_table.meta.client.exceptions.ConditionalCheckFailedException:
                    pass  # Customer already exists, that's fine

        except Exception as e:
            logger.error("API key provisioning error", extra={"error": str(e)})
            # Reset status so the user can retry verification
            try:
                credentials_table.update_item(
                    Key={'email': email},
                    UpdateExpression='SET #s = :pending, updated_at = :now',
                    ExpressionAttributeNames={'#s': 'status'},
                    ExpressionAttributeValues={
                        ':pending': 'pending',
                        ':now': datetime.now(timezone.utc).isoformat(),
                    }
                )
            except Exception:
                logger.error("Failed to reset provisioning state", extra={"email": email})
            return cors_response(event, 500, {
                'error': 'Failed to provision credentials. Please try again or contact support.'
            })

        # Update DynamoDB record: mark as provisioned, remove token, store key_id
        credentials_table.update_item(
            Key={'email': email},
            UpdateExpression='SET #s = :provisioned, updated_at = :now, '
                            'api_key_id = :kid, provisioned_at = :now '
                            'REMOVE #ttl, #th',
            ExpressionAttributeNames={
                '#s': 'status',
                '#ttl': 'ttl',
                '#th': 'token_hash'
            },
            ExpressionAttributeValues={
                ':provisioned': 'provisioned',
                ':now': now_iso,
                ':kid': key_data['key_id'],
            }
        )

        # Send API key email (non-blocking)
        try:
            ses.send_email(
                Source=FROM_EMAIL,
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': 'Your LayerV API Key'},
                    'Body': {
                        'Html': {'Data': _credentials_email_html(api_key)},
                        'Text': {'Data': _credentials_email_text(api_key)}
                    }
                }
            )
        except Exception as e:
            logger.warning("API key email failed (non-critical)", extra={"error": str(e)})

        # Notify team (non-blocking)
        try:
            ses.send_email(
                Source=FROM_EMAIL,
                Destination={'ToAddresses': [NOTIFY_EMAIL]},
                Message={
                    'Subject': {'Data': f'New API key provisioned: {email}'},
                    'Body': {
                        'Text': {'Data': (
                            f'New API key provisioned:\n\n'
                            f'Email: {email}\n'
                            f'Name: {item.get("name", "N/A")}\n'
                            f'Key ID: {key_data["key_id"]}\n'
                            f'Key Prefix: {key_data["key_prefix"]}\n'
                            f'Time: {now_iso} UTC'
                        )}
                    }
                }
            )
        except Exception as e:
            logger.warning("Notification email failed (non-critical)", extra={"error": str(e)})

        return cors_response(event, 200, {
            'message': 'API key provisioned successfully.',
            'data': {
                'api_key': api_key,
                'api_url': QURL_API_URL,
                'note': 'Save your API key now. It will not be shown again.',
                'usage': f'curl -H "Authorization: Bearer {key_data["key_prefix"]}..." {QURL_API_URL}/v1/qurl'
            }
        })

    except Exception as e:
        logger.error("Verify error", extra={"error": str(e)})
        return cors_response(event, 500, {'error': 'Something went wrong. Please try again.'})


def handle_health(event):
    """Health check endpoint - verifies Lambda is running."""
    return cors_response(event, 200, {
        'status': 'healthy',
        'service': 'credential-provisioner',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# ---------------------------------------------------------------------------
# API Key Generation
# ---------------------------------------------------------------------------

def generate_api_key():
    """
    Generate a custom API key with lv_live_ prefix.

    Returns dict with:
      - api_key: full plaintext key (shown once, never stored)
      - key_hash: SHA-256 hash (stored in DynamoDB)
      - key_id: public identifier for CRUD operations
      - key_prefix: first 12 chars for display
    """
    raw = secrets.token_urlsafe(32)
    api_key = f"lv_live_{raw}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_id = f"key_{secrets.token_urlsafe(9)}"  # 12 chars of randomness
    key_prefix = f"lv_live_{raw[:4]}..."  # "lv_live_a3x9..." — shows prefix only
    return {
        'api_key': api_key,
        'key_hash': key_hash,
        'key_id': key_id,
        'key_prefix': key_prefix,
    }


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
        raw = resp.get('SecretString', '')
        # Handle both JSON ({"key": "..."}) and raw string formats
        try:
            parsed = json.loads(raw)
            _ci_bypass_key = parsed.get('key', '') if isinstance(parsed, dict) else raw
        except (json.JSONDecodeError, TypeError):
            _ci_bypass_key = raw
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


def check_registration_rate_limits(ip):
    """
    Check per-IP rate limits for registration (5/IP/day).

    Uses atomic conditional updates to prevent race conditions.
    Returns error message if rate limited, None if allowed.
    """
    try:
        ip_key = f"credentials:register:ip:{ip}"
        if not _atomic_rate_check(ip_key, REGISTRATION_RATE_LIMIT_IP, REGISTRATION_RATE_WINDOW):
            logger.warning("Registration IP rate limit exceeded", extra={"ip": ip})
            return 'Too many registration attempts. Please try again later.'
        return None
    except Exception as e:
        logger.error("Rate limit check error", extra={"error": str(e)})
        _emit_rate_limit_fail_open_metric('credential-provisioner')
        return None  # Fail open


def check_verify_rate_limits(ip):
    """
    Check per-IP rate limits for verification attempts (10/IP/hour).

    Uses atomic conditional updates to prevent race conditions.
    Returns error message if rate limited, None if allowed.
    """
    try:
        ip_key = f"credentials:verify:ip:{ip}"
        if not _atomic_rate_check(ip_key, VERIFY_RATE_LIMIT_IP, VERIFY_RATE_WINDOW):
            logger.warning("Verify IP rate limit exceeded", extra={"ip": ip})
            return 'Too many verification attempts.'
        return None
    except Exception as e:
        logger.error("Rate limit check error", extra={"error": str(e)})
        _emit_rate_limit_fail_open_metric('credential-provisioner')
        return None  # Fail open


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
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        },
        'body': json.dumps(body)
    }


# ---------------------------------------------------------------------------
# Email Templates
# ---------------------------------------------------------------------------

def _verification_email_html(verify_link):
    """HTML template for verification email."""
    safe_link = html_module.escape(verify_link, quote=True)
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px; color: #1a1a2e;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1; font-size: 24px; margin: 0;">LayerV</h1>
  </div>

  <h2 style="font-size: 20px; margin-bottom: 16px;">Verify your email</h2>

  <p>Click the button below to verify your email and receive your QURL API credentials.</p>

  <div style="text-align: center; margin: 32px 0;">
    <a href="{safe_link}"
       style="background-color: #6366f1; color: white; padding: 14px 32px;
              text-decoration: none; border-radius: 8px; font-weight: 600;
              display: inline-block;">
      Verify &amp; Get Credentials
    </a>
  </div>

  <p style="font-size: 14px; color: #64748b;">
    This link expires in 48 hours. If you didn't request API credentials,
    you can safely ignore this email.
  </p>

  <p style="font-size: 12px; color: #94a3b8; margin-top: 40px; text-align: center;">
    LayerV &mdash; Network Hiding Protocol
  </p>
</body>
</html>"""


def _verification_email_text(verify_link):
    """Plain text template for verification email."""
    return f"""LayerV - Verify Your Email

Click the link below to verify your email and receive your QURL API credentials:

{verify_link}

This link expires in 48 hours.

If you didn't request API credentials, you can safely ignore this email.

-- LayerV"""


def _credentials_email_html(api_key):
    """HTML template for API key delivery email."""
    esc = html_module.escape
    safe_key = esc(api_key)
    safe_api_url = esc(QURL_API_URL)
    safe_site = esc(SITE_URL)
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px; color: #1a1a2e;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1; font-size: 24px; margin: 0;">LayerV</h1>
  </div>

  <h2 style="font-size: 20px; margin-bottom: 16px;">Your QURL API Key</h2>

  <p>Your API key has been provisioned. Save it now &mdash;
  it will not be shown again.</p>

  <div style="background: #f1f5f9; border-radius: 8px; padding: 20px; margin: 24px 0;
              font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px;">
    <p style="margin: 4px 0;"><strong>API Key:</strong> <code>{safe_key}</code></p>
    <p style="margin: 4px 0;"><strong>API URL:</strong> <code>{safe_api_url}</code></p>
  </div>

  <h3 style="font-size: 16px; margin-top: 28px;">Quick Start</h3>
  <div style="background: #1e293b; border-radius: 8px; padding: 16px; margin: 16px 0;
              font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px;
              color: #e2e8f0; overflow-x: auto;">
    <pre style="margin: 0; white-space: pre-wrap;">curl -H "Authorization: Bearer {safe_key}" \\
  {safe_api_url}/v1/qurl</pre>
  </div>

  <p style="font-size: 14px; color: #64748b;">
    See the <a href="{safe_site}/docs/qurl-api" style="color: #6366f1;">QURL API documentation</a>
    for full usage details.
  </p>

  <p style="font-size: 12px; color: #94a3b8; margin-top: 40px; text-align: center;">
    LayerV &mdash; Network Hiding Protocol
  </p>
</body>
</html>"""


def _credentials_email_text(api_key):
    """Plain text template for API key delivery email."""
    return f"""LayerV - Your QURL API Key

Your API key has been provisioned. Save it now -- it will not be shown again.

API Key: {api_key}
API URL: {QURL_API_URL}

Quick Start:

curl -H "Authorization: Bearer {api_key}" {QURL_API_URL}/v1/qurl

See {SITE_URL}/docs/qurl-api for full usage details.

-- LayerV"""
