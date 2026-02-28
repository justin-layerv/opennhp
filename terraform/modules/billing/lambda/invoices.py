"""
Invoices Lambda

Returns a customer's invoices from Stripe. Auth via API Gateway JWT
authorizer.

Endpoint:
    GET /billing/invoices  - List customer invoices
    GET /billing/invoices?limit=N  - List last N invoices (default 10, max 100)
"""

import json
import boto3
import logging
import os
import time
import urllib.request
import urllib.parse
import urllib.error

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

# Configuration from environment
STRIPE_SECRET_NAME = os.environ.get('STRIPE_SECRET_NAME', '')
CUSTOMERS_TABLE_NAME = os.environ.get('CUSTOMERS_TABLE_NAME', '')
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://layerv.ai').split(',')
STRIPE_API_BASE_URL = os.environ.get('STRIPE_API_BASE_URL', 'https://api.stripe.com')

# Module-level cache for Stripe key
_stripe_key = None
_stripe_key_expires_at = 0
STRIPE_CACHE_TTL = 300  # 5 minutes

# AWS clients
dynamodb = boto3.resource('dynamodb')
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None

# Defaults
DEFAULT_LIMIT = 10
MAX_LIMIT = 100


def lambda_handler(event, context):
    """Main Lambda entry point."""
    method = event.get('requestContext', {}).get('http', {}).get('method', '')

    if method == 'OPTIONS':
        return cors_response(event, 200, {})

    # Extract Auth0 subject from JWT (validated by API Gateway)
    auth0_sub = (event.get('requestContext', {})
                 .get('authorizer', {})
                 .get('jwt', {})
                 .get('claims', {})
                 .get('sub', ''))
    if not auth0_sub:
        return cors_response(event, 401, {
            'error': {
                'type': 'https://api.qurl.link/problems/unauthorized',
                'title': 'Unauthorized',
                'status': 401,
                'code': 'unauthorized',
            }
        })

    if method == 'GET':
        return handle_list_invoices(event, auth0_sub)
    else:
        return cors_response(event, 405, {'error': 'Method not allowed'})


def handle_list_invoices(event, auth0_sub):
    """List customer invoices from Stripe."""
    # Get customer from DDB
    customer = _get_customer(auth0_sub)
    if not customer or not customer.get('stripe_customer_id'):
        return cors_response(event, 200, {
            'data': {
                'invoices': [],
                'has_more': False,
            }
        })

    # Parse limit from query params
    params = event.get('queryStringParameters', {}) or {}
    try:
        limit = min(int(params.get('limit', DEFAULT_LIMIT)), MAX_LIMIT)
        limit = max(limit, 1)
    except (ValueError, TypeError):
        limit = DEFAULT_LIMIT

    # Fetch invoices from Stripe
    stripe_key = _get_stripe_key()
    if not stripe_key:
        logger.error("Failed to load Stripe key for invoice listing")
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    query_params = urllib.parse.urlencode({
        'customer': customer['stripe_customer_id'],
        'limit': str(limit),
    })

    result = _stripe_api_get(f'/v1/invoices?{query_params}', stripe_key)
    if result is None:
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    # Transform Stripe invoices to our format
    invoices = []
    for inv in result.get('data', []):
        invoices.append({
            'id': inv.get('id', ''),
            'number': inv.get('number', ''),
            'status': inv.get('status', ''),
            'amount_due': inv.get('amount_due', 0),
            'amount_paid': inv.get('amount_paid', 0),
            'currency': inv.get('currency', 'usd'),
            'period_start': inv.get('period_start'),
            'period_end': inv.get('period_end'),
            'created': inv.get('created'),
            'hosted_invoice_url': inv.get('hosted_invoice_url', ''),
            'invoice_pdf': inv.get('invoice_pdf', ''),
        })

    return cors_response(event, 200, {
        'data': {
            'invoices': invoices,
            'has_more': result.get('has_more', False),
        }
    })


# ---------------------------------------------------------------------------
# Stripe API Helpers
# ---------------------------------------------------------------------------

def _get_stripe_key():
    """Load Stripe secret key from Secrets Manager (cached)."""
    global _stripe_key, _stripe_key_expires_at
    if _stripe_key and time.time() < _stripe_key_expires_at:
        return _stripe_key
    try:
        sm = boto3.client('secretsmanager')
        secret = json.loads(
            sm.get_secret_value(SecretId=STRIPE_SECRET_NAME)['SecretString']
        )
        _stripe_key = secret.get('secret_key', '')
        _stripe_key_expires_at = time.time() + STRIPE_CACHE_TTL
        return _stripe_key
    except Exception as e:
        logger.error("Failed to load Stripe key", extra={"error": str(e)})
        return None


def _stripe_api_get(path, api_key):
    """Call Stripe API GET using urllib (no SDK dependency)."""
    url = f'{STRIPE_API_BASE_URL}{path}'
    req = urllib.request.Request(url, method='GET', headers={
        'Authorization': f'Bearer {api_key}',
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, 'read') else str(e)
        logger.error("Stripe API error", extra={
            "status": e.code, "response": body[:500], "path": path,
        })
        return None
    except Exception as e:
        logger.error("Stripe API error", extra={"error": str(e), "path": path})
        return None


# ---------------------------------------------------------------------------
# DynamoDB Helpers
# ---------------------------------------------------------------------------

def _get_customer(auth0_sub):
    """Get customer record from DynamoDB."""
    if not customers_table:
        return None
    try:
        resp = customers_table.get_item(Key={'auth0_subject': auth0_sub})
        return resp.get('Item')
    except Exception as e:
        logger.error("DynamoDB get customer error", extra={"error": str(e)})
        return None


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
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
        'body': json.dumps(body),
    }
