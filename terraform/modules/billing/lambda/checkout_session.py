"""
Stripe Checkout & Portal Session Lambda

Creates Stripe Checkout sessions for plan upgrades and Portal sessions
for subscription management. Auth via API Gateway JWT authorizer.

Endpoints:
    POST /billing/checkout-session  - Create Stripe Checkout session
    POST /billing/portal-session    - Create Stripe Customer Portal session
"""

import json
import boto3
import logging
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

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
GROWTH_PRICE_ID = os.environ.get('GROWTH_PRICE_ID', '')
BASE_FEE_PRICE_ID = os.environ.get('BASE_FEE_PRICE_ID', '')
SUCCESS_URL = os.environ.get('SUCCESS_URL', '')
CANCEL_URL = os.environ.get('CANCEL_URL', '')
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://layerv.ai').split(',')
STRIPE_API_BASE_URL = os.environ.get('STRIPE_API_BASE_URL', 'https://api.stripe.com')

# Module-level cache for Stripe key
_stripe_key = None
_stripe_key_expires_at = 0
STRIPE_CACHE_TTL = 300  # 5 minutes

# AWS clients
dynamodb = boto3.resource('dynamodb')
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None


def lambda_handler(event, context):
    """Main Lambda entry point with method/path routing."""
    method = event.get('requestContext', {}).get('http', {}).get('method', '')
    path = event.get('rawPath', '')

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

    if path.endswith('/checkout-session') and method == 'POST':
        return handle_checkout_session(event, auth0_sub)
    elif path.endswith('/portal-session') and method == 'POST':
        return handle_portal_session(event, auth0_sub)
    else:
        return cors_response(event, 404, {'error': 'Not found'})


# ---------------------------------------------------------------------------
# Route Handlers
# ---------------------------------------------------------------------------

def handle_checkout_session(event, auth0_sub):
    """Create Stripe Checkout session for Growth plan upgrade."""
    stripe_key = _get_stripe_key()
    if not stripe_key:
        logger.error("Failed to load Stripe key for checkout session")
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    # Get or create Stripe customer
    customer = _get_or_create_customer(auth0_sub, stripe_key)
    if not customer:
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    # Build line items
    line_items = []
    if BASE_FEE_PRICE_ID:
        line_items.append({'price': BASE_FEE_PRICE_ID, 'quantity': 1})
    if GROWTH_PRICE_ID:
        line_items.append({'price': GROWTH_PRICE_ID})  # metered -- no quantity

    if not line_items:
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'no_price_configured',
                'detail': 'No price IDs configured for checkout',
            }
        })

    # Create Checkout Session via Stripe API
    params = {
        'customer': customer['stripe_customer_id'],
        'mode': 'subscription',
        'success_url': SUCCESS_URL,
        'cancel_url': CANCEL_URL,
        'automatic_tax[enabled]': 'true',
        'customer_update[address]': 'auto',
    }
    for i, item in enumerate(line_items):
        params[f'line_items[{i}][price]'] = item['price']
        if 'quantity' in item:
            params[f'line_items[{i}][quantity]'] = str(item['quantity'])

    result = _stripe_api('POST', '/v1/checkout/sessions', params, stripe_key)
    if not result:
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    logger.info("Checkout session created", extra={
        "auth0_sub": auth0_sub,
        "session_id": result.get('id', ''),
    })

    return cors_response(event, 200, {
        'data': {'checkout_url': result.get('url')}
    })


def handle_portal_session(event, auth0_sub):
    """Create Stripe Customer Portal session."""
    stripe_key = _get_stripe_key()
    if not stripe_key:
        logger.error("Failed to load Stripe key for portal session")
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })
    customer = _get_customer(auth0_sub)
    if not customer or not customer.get('stripe_customer_id'):
        return cors_response(event, 400, {
            'error': {
                'type': 'https://api.qurl.link/problems/no_subscription',
                'title': 'No Subscription',
                'status': 400,
                'code': 'no_subscription',
                'detail': 'No active subscription found',
            }
        })

    result = _stripe_api('POST', '/v1/billing_portal/sessions', {
        'customer': customer['stripe_customer_id'],
        'return_url': SUCCESS_URL,
    }, stripe_key)

    if not result:
        return cors_response(event, 500, {
            'error': {
                'type': 'https://api.qurl.link/problems/internal',
                'title': 'Internal Error',
                'status': 500,
                'code': 'internal_error',
            }
        })

    logger.info("Portal session created", extra={
        "auth0_sub": auth0_sub,
    })

    return cors_response(event, 200, {
        'data': {'portal_url': result.get('url')}
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


def _stripe_api(method, path, params, api_key):
    """Call Stripe API using urllib (no SDK dependency)."""
    url = f'{STRIPE_API_BASE_URL}{path}'
    data = urllib.parse.urlencode(params).encode() if params else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/x-www-form-urlencoded',
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
# Customer Helpers
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


def _get_or_create_customer(auth0_sub, stripe_key):
    """Get existing customer or create Stripe customer + DDB record.

    Uses a conditional DynamoDB update to prevent race conditions: if two
    concurrent requests both see no stripe_customer_id, both create Stripe
    customers, but only one wins the conditional write. The loser re-reads
    the record to use the winner's Stripe customer ID.
    """
    customer = _get_customer(auth0_sub)
    if customer and customer.get('stripe_customer_id'):
        return customer

    # Create Stripe customer
    email = customer.get('email', '') if customer else ''
    stripe_cust = _stripe_api('POST', '/v1/customers', {
        'email': email,
        'metadata[auth0_subject]': auth0_sub,
    }, stripe_key)

    if not stripe_cust:
        return None

    # Conditional update: only write if no stripe_customer_id exists yet.
    # This prevents two concurrent requests from both overwriting with
    # different Stripe customer IDs (orphaning one in Stripe).
    try:
        now = datetime.now(timezone.utc).isoformat()
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression='SET stripe_customer_id = :sid, updated_at = :now',
            ConditionExpression=(
                'attribute_not_exists(stripe_customer_id) OR '
                'stripe_customer_id = :empty'
            ),
            ExpressionAttributeValues={
                ':sid': stripe_cust['id'],
                ':now': now,
                ':empty': '',
            }
        )
    except customers_table.meta.client.exceptions.ConditionalCheckFailedException:
        # Another request won the race — re-read to get the winning Stripe ID
        logger.warning("Stripe customer race: orphaned customer created", extra={
            "auth0_sub": auth0_sub,
            "orphaned_stripe_id": stripe_cust['id'],
        })
        winner = _get_customer(auth0_sub)
        if winner and winner.get('stripe_customer_id'):
            return winner
        # Shouldn't happen, but fall through to return our ID
    except Exception as e:
        logger.error("Failed to update customer with Stripe ID", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })

    return {
        'auth0_subject': auth0_sub,
        'stripe_customer_id': stripe_cust['id'],
        'email': email,
    }


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
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
        'body': json.dumps(body),
    }
