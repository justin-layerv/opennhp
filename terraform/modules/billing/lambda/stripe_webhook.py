"""
Stripe Webhook Lambda

Receives and processes Stripe webhook events. Verifies webhook signature
using HMAC-SHA256 (no Stripe SDK dependency). Updates customer billing
state in DynamoDB.

Endpoint:
    POST /billing/webhook  - Stripe webhook receiver (no JWT auth)

Handled events:
    - checkout.session.completed       -> upgrade tier to growth
    - customer.subscription.updated    -> update tier/period
    - customer.subscription.deleted    -> downgrade to free
    - invoice.payment_failed           -> set payment grace deadline
    - invoice.paid                     -> clear grace deadline/frozen
"""

import json
import boto3
import hashlib
import hmac
import logging
import os
import time
import uuid
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta

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
STRIPE_WEBHOOK_SECRET_NAME = os.environ.get('STRIPE_WEBHOOK_SECRET_NAME', '')
CUSTOMERS_TABLE_NAME = os.environ.get('CUSTOMERS_TABLE_NAME', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://layerv.ai').split(',')
WEBHOOK_DEDUP_TABLE_NAME = os.environ.get('WEBHOOK_DEDUP_TABLE_NAME', '')

# Payment grace period: configurable, default 7 days after failed payment
GRACE_PERIOD_DAYS = int(os.environ.get('GRACE_PERIOD_DAYS', '7'))
STRIPE_API_BASE_URL = os.environ.get('STRIPE_API_BASE_URL', 'https://api.stripe.com')

# Module-level cache for webhook signing secret
_webhook_secret = None
_webhook_secret_expires_at = 0
WEBHOOK_SECRET_CACHE_TTL = 300  # 5 minutes

# AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns') if SNS_TOPIC_ARN else None
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None
dedup_table = dynamodb.Table(WEBHOOK_DEDUP_TABLE_NAME) if WEBHOOK_DEDUP_TABLE_NAME else None

BILLING_AUDIT_TABLE_NAME = os.environ.get('BILLING_AUDIT_TABLE_NAME', '')
audit_table = dynamodb.Table(BILLING_AUDIT_TABLE_NAME) if BILLING_AUDIT_TABLE_NAME else None


def lambda_handler(event, context):
    """Main Lambda entry point for Stripe webhooks."""
    method = event.get('requestContext', {}).get('http', {}).get('method', '')

    if method == 'OPTIONS':
        return cors_response(event, 200, {})

    if method != 'POST':
        return cors_response(event, 405, {'error': 'Method not allowed'})

    # Get raw body for signature verification
    body = event.get('body', '')
    if event.get('isBase64Encoded', False):
        import base64
        body = base64.b64decode(body).decode('utf-8')

    # Verify Stripe signature
    headers = event.get('headers', {}) or {}
    sig_header = headers.get('stripe-signature', '')
    if not sig_header:
        logger.warning("Missing stripe-signature header")
        return cors_response(event, 400, {'error': 'Missing signature'})

    webhook_secret = _get_webhook_secret()
    if not webhook_secret:
        logger.error("Failed to load webhook signing secret")
        return cors_response(event, 500, {'error': 'Internal error'})

    if not _verify_stripe_signature(body, sig_header, webhook_secret):
        logger.warning("Invalid Stripe webhook signature")
        return cors_response(event, 400, {'error': 'Invalid signature'})

    # Parse event
    try:
        stripe_event = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return cors_response(event, 400, {'error': 'Invalid JSON'})

    event_type = stripe_event.get('type', '')
    event_data = stripe_event.get('data', {}).get('object', {})
    event_id = stripe_event.get('id', '')

    logger.info("Stripe webhook received", extra={
        "event_type": event_type,
        "event_id": event_id,
    })

    # Atomic idempotency: claim event or skip if already processed
    if not _claim_event(event_id, event_type):
        logger.info("Duplicate event skipped", extra={"event_id": event_id})
        return cors_response(event, 200, {'received': True, 'duplicate': True})

    # Route to event handlers
    customer_changed = False
    try:
        if event_type == 'checkout.session.completed':
            _handle_checkout_completed(event_data)
            customer_changed = True
        elif event_type == 'customer.subscription.updated':
            _handle_subscription_updated(event_data)
            customer_changed = True
        elif event_type == 'customer.subscription.deleted':
            _handle_subscription_deleted(event_data)
            customer_changed = True
        elif event_type == 'invoice.payment_failed':
            _handle_payment_failed(event_data)
            customer_changed = True
        elif event_type == 'invoice.paid':
            _handle_payment_succeeded(event_data)
            customer_changed = True
        else:
            logger.info("Unhandled event type", extra={"event_type": event_type})
    except Exception as e:
        logger.error("Webhook handler error", extra={
            "event_type": event_type,
            "event_id": event_id,
            "error": str(e),
        })
        # Return 500 so Stripe retries the event
        return cors_response(event, 500, {'error': 'handler_error'})

    # Publish SNS notification so QURL service can invalidate cached customer data
    if customer_changed:
        _publish_customer_updated(event_type, event_data)

    return cors_response(event, 200, {'received': True})


# ---------------------------------------------------------------------------
# Idempotency Helpers
# ---------------------------------------------------------------------------

# TTL for dedup records: 48 hours (Stripe retries for up to 72h, 48h covers most)
DEDUP_TTL_SECONDS = 48 * 3600


def _claim_event(event_id, event_type):
    """
    Atomically claim an event for processing (idempotency).

    Uses conditional put_item with attribute_not_exists to prevent race
    conditions where two concurrent webhook deliveries both pass a
    get_item check before either writes.

    Returns True if this invocation claimed the event (proceed with handling).
    Returns False if already claimed by another invocation (skip).
    """
    if not dedup_table:
        logger.warning("Webhook dedup table not configured — idempotency disabled")
        return True
    if not event_id:
        return True  # No event_id — proceed without dedup
    try:
        dedup_table.put_item(
            Item={
                'event_id': event_id,
                'event_type': event_type,
                'processed_at': datetime.now(timezone.utc).isoformat(),
                'ttl': int(time.time()) + DEDUP_TTL_SECONDS,
            },
            ConditionExpression='attribute_not_exists(event_id)',
        )
        return True  # Successfully claimed
    except dedup_table.meta.client.exceptions.ConditionalCheckFailedException:
        return False  # Already claimed by another invocation
    except Exception as e:
        # Dedup check failed — proceed to avoid dropping events
        logger.warning("Dedup claim failed, proceeding", extra={
            "event_id": event_id, "error": str(e),
        })
        return True


# ---------------------------------------------------------------------------
# Stripe Signature Verification
# ---------------------------------------------------------------------------

def _verify_stripe_signature(payload, sig_header, secret):
    """
    Verify Stripe webhook signature using HMAC-SHA256.

    Stripe signature format: t=timestamp,v1=signature[,v1=signature...]
    Signed payload: "{timestamp}.{payload}"

    Tolerance: 300 seconds (5 minutes) to prevent replay attacks.
    """
    try:
        # Parse signature header
        elements = {}
        for item in sig_header.split(','):
            key, _, value = item.strip().partition('=')
            if key == 't':
                elements['t'] = value
            elif key == 'v1':
                elements.setdefault('v1', []).append(value)

        timestamp = elements.get('t', '')
        signatures = elements.get('v1', [])

        if not timestamp or not signatures:
            return False

        # Check timestamp tolerance (5 minutes)
        try:
            ts = int(timestamp)
            if abs(time.time() - ts) > 300:
                logger.warning("Webhook timestamp outside tolerance", extra={
                    "timestamp": ts, "now": int(time.time()),
                })
                return False
        except (ValueError, TypeError):
            return False

        # Compute expected signature
        signed_payload = f"{timestamp}.{payload}"
        expected = hmac.new(
            secret.encode('utf-8'),
            signed_payload.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

        # Compare against all v1 signatures (Stripe may include multiple)
        for sig in signatures:
            if hmac.compare_digest(expected, sig):
                return True

        return False

    except Exception as e:
        logger.error("Signature verification error", extra={"error": str(e)})
        return False


# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

def _handle_checkout_completed(session):
    """
    Handle checkout.session.completed event.

    Updates customer tier to growth, stores Stripe subscription and
    customer IDs.
    """
    customer_id = session.get('customer', '')
    subscription_id = session.get('subscription', '')
    auth0_sub = session.get('metadata', {}).get('auth0_subject', '')

    if not customer_id:
        logger.warning("checkout.session.completed missing customer ID")
        return

    # Find customer by stripe_customer_id if auth0_sub not in metadata
    if not auth0_sub:
        auth0_sub = _find_auth0_sub_by_stripe_id(customer_id)
        if not auth0_sub:
            logger.error("Cannot find customer for checkout", extra={
                "stripe_customer_id": customer_id,
            })
            return

    # Retrieve subscription details for sub_item_id and period start
    sub_item_id = ''
    current_period_start = None
    if subscription_id:
        stripe_key = _get_stripe_key_for_api()
        if stripe_key:
            sub_details = _stripe_api_get(
                f'/v1/subscriptions/{subscription_id}', stripe_key,
            )
            if sub_details:
                items = sub_details.get('items', {}).get('data', [])
                sub_item_id = items[0].get('id', '') if items else ''
                current_period_start = sub_details.get('current_period_start')

    now = datetime.now(timezone.utc).isoformat()
    update_expr = (
        'SET tier = :tier, stripe_customer_id = :cid, '
        'stripe_subscription_id = :sid, updated_at = :now'
    )
    expr_values = {
        ':tier': 'growth',
        ':cid': customer_id,
        ':sid': subscription_id,
        ':now': now,
    }

    if sub_item_id:
        update_expr += ', stripe_sub_item_id = :siid'
        expr_values[':siid'] = sub_item_id

    if current_period_start is not None:
        update_expr += ', current_period_start = :cps, current_period_usage = :zero'
        expr_values[':cps'] = current_period_start
        expr_values[':zero'] = 0

    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
        logger.info("Customer upgraded to growth", extra={
            "auth0_sub": auth0_sub,
            "stripe_customer_id": customer_id,
            "stripe_sub_item_id": sub_item_id,
        })
        _write_audit(auth0_sub, 'tier_upgraded', {
            'tier': 'growth',
            'stripe_customer_id': customer_id,
        })
    except Exception as e:
        logger.error("Failed to update customer after checkout", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        raise


def _handle_subscription_updated(subscription):
    """
    Handle customer.subscription.updated event.

    Updates tier based on subscription status. Stores subscription item ID
    for metered billing.
    """
    customer_id = subscription.get('customer', '')
    status = subscription.get('status', '')
    subscription_id = subscription.get('id', '')

    auth0_sub = _find_auth0_sub_by_stripe_id(customer_id)
    if not auth0_sub:
        logger.warning("subscription.updated: customer not found", extra={
            "stripe_customer_id": customer_id,
        })
        return

    # Extract subscription item ID for metered usage reporting
    items = subscription.get('items', {}).get('data', [])
    sub_item_id = items[0].get('id', '') if items else ''

    # Map Stripe status to tier
    tier = 'growth' if status in ('active', 'trialing') else 'free'

    now = datetime.now(timezone.utc).isoformat()
    update_expr = (
        'SET tier = :tier, stripe_subscription_id = :sid, '
        'stripe_sub_item_id = :siid, updated_at = :now'
    )
    expr_values = {
        ':tier': tier,
        ':sid': subscription_id,
        ':siid': sub_item_id,
        ':now': now,
    }

    # If subscription has a new billing period, reset usage counter
    current_period_start = subscription.get('current_period_start')
    if current_period_start:
        update_expr += ', current_period_start = :cps, current_period_usage = :zero'
        expr_values[':cps'] = current_period_start
        expr_values[':zero'] = 0

    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
        logger.info("Subscription updated", extra={
            "auth0_sub": auth0_sub,
            "status": status,
            "tier": tier,
        })
    except Exception as e:
        logger.error("Failed to update subscription", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        raise


def _handle_subscription_deleted(subscription):
    """
    Handle customer.subscription.deleted event.

    Downgrades customer to free tier.
    """
    customer_id = subscription.get('customer', '')

    auth0_sub = _find_auth0_sub_by_stripe_id(customer_id)
    if not auth0_sub:
        logger.warning("subscription.deleted: customer not found", extra={
            "stripe_customer_id": customer_id,
        })
        return

    now = datetime.now(timezone.utc).isoformat()
    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=(
                'SET tier = :tier, updated_at = :now '
                'REMOVE stripe_subscription_id, stripe_sub_item_id, '
                'current_period_start, current_period_usage'
            ),
            ExpressionAttributeValues={
                ':tier': 'free',
                ':now': now,
            }
        )
        logger.info("Customer downgraded to free", extra={
            "auth0_sub": auth0_sub,
            "stripe_customer_id": customer_id,
        })
        _write_audit(auth0_sub, 'tier_downgraded', {
            'previous_tier': 'growth',
            'stripe_customer_id': customer_id,
        })
    except Exception as e:
        logger.error("Failed to downgrade customer", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        raise


def _handle_payment_failed(invoice):
    """
    Handle invoice.payment_failed event.

    Sets a payment grace deadline (now + 7 days). The payment_grace Lambda
    will freeze accounts that pass the deadline.
    """
    customer_id = invoice.get('customer', '')

    auth0_sub = _find_auth0_sub_by_stripe_id(customer_id)
    if not auth0_sub:
        logger.warning("invoice.payment_failed: customer not found", extra={
            "stripe_customer_id": customer_id,
        })
        return

    grace_deadline = (
        datetime.now(timezone.utc) + timedelta(days=GRACE_PERIOD_DAYS)
    ).isoformat()
    now = datetime.now(timezone.utc).isoformat()

    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=(
                'SET payment_grace_deadline = :deadline, updated_at = :now'
            ),
            ExpressionAttributeValues={
                ':deadline': grace_deadline,
                ':now': now,
            }
        )
        logger.info("Payment grace deadline set", extra={
            "auth0_sub": auth0_sub,
            "grace_deadline": grace_deadline,
        })
        _write_audit(auth0_sub, 'grace_started', {
            'grace_period_days': int(GRACE_PERIOD_DAYS),
            'stripe_customer_id': customer_id,
        })
    except Exception as e:
        logger.error("Failed to set grace deadline", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        raise


def _handle_payment_succeeded(invoice):
    """
    Handle invoice.paid event.

    Clears payment grace deadline and frozen flag.
    """
    customer_id = invoice.get('customer', '')

    auth0_sub = _find_auth0_sub_by_stripe_id(customer_id)
    if not auth0_sub:
        logger.warning("invoice.paid: customer not found", extra={
            "stripe_customer_id": customer_id,
        })
        return

    now = datetime.now(timezone.utc).isoformat()
    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=(
                'SET updated_at = :now '
                'REMOVE payment_grace_deadline, frozen, frozen_reason, frozen_at'
            ),
            ExpressionAttributeValues={
                ':now': now,
            }
        )
        logger.info("Payment succeeded, grace cleared", extra={
            "auth0_sub": auth0_sub,
            "stripe_customer_id": customer_id,
        })
        _write_audit(auth0_sub, 'grace_cleared', {
            'stripe_customer_id': customer_id,
        })
    except Exception as e:
        logger.error("Failed to clear grace deadline", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        raise


# ---------------------------------------------------------------------------
# Customer Lookup Helpers
# ---------------------------------------------------------------------------

def _find_auth0_sub_by_stripe_id(stripe_customer_id):
    """
    Find auth0_subject by stripe_customer_id using a GSI query.

    Uses the stripe-customer-id-index GSI for O(1) lookup instead of
    a full table scan.
    """
    if not customers_table or not stripe_customer_id:
        return None

    gsi_name = os.environ.get('CUSTOMERS_GSI_NAME', 'stripe-customer-id-index')

    try:
        resp = customers_table.query(
            IndexName=gsi_name,
            KeyConditionExpression='stripe_customer_id = :cid',
            ExpressionAttributeValues={':cid': stripe_customer_id},
            Limit=1,
        )
        items = resp.get('Items', [])
        if items:
            return items[0].get('auth0_subject')
    except Exception as e:
        logger.error("Customer lookup by Stripe ID failed", extra={
            "error": str(e), "error_type": type(e).__name__,
            "stripe_customer_id": stripe_customer_id,
        })

    return None


# ---------------------------------------------------------------------------
# Audit Helpers
# ---------------------------------------------------------------------------

def _write_audit(owner_id, event_type, details):
    """Write an entry to the billing audit table."""
    if not audit_table:
        return
    try:
        now = datetime.now(timezone.utc)
        audit_table.put_item(Item={
            'owner_id': owner_id,
            'event_id': f"{now.isoformat()}#{uuid.uuid4()}",
            'event_type': event_type,
            'timestamp': now.isoformat(),
            'ttl': int((now + timedelta(days=730)).timestamp()),
            'details': details,
        })
    except Exception as e:
        logger.warning("Failed to write audit entry", extra={
            "error": str(e), "owner_id": owner_id, "event_type": event_type,
        })


# ---------------------------------------------------------------------------
# SNS Notification
# ---------------------------------------------------------------------------

def _publish_customer_updated(event_type, event_data):
    """Publish customer.updated event to SNS for cache invalidation."""
    if not sns or not SNS_TOPIC_ARN:
        return

    # All handled events have 'customer' as a top-level field on the data object
    customer_id = event_data.get('customer', '')

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='customer.updated',
            Message=json.dumps({
                'event_type': event_type,
                'stripe_customer_id': customer_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }),
            MessageAttributes={
                'event_type': {
                    'DataType': 'String',
                    'StringValue': 'customer.updated',
                },
            },
        )
        logger.info("Published customer.updated to SNS", extra={
            "event_type": event_type,
            "stripe_customer_id": customer_id,
        })
    except Exception as e:
        # Non-fatal — webhook already updated DynamoDB
        logger.warning("Failed to publish SNS notification", extra={
            "error": str(e), "event_type": event_type,
        })


# ---------------------------------------------------------------------------
# Stripe API Helpers (for subscription lookups)
# ---------------------------------------------------------------------------

# Module-level cache for Stripe secret key (separate from webhook signing secret)
_stripe_api_key = None
_stripe_api_key_expires_at = 0
STRIPE_SECRET_NAME = os.environ.get('STRIPE_SECRET_NAME', '')


def _get_stripe_key_for_api():
    """Load Stripe secret key from Secrets Manager (cached)."""
    global _stripe_api_key, _stripe_api_key_expires_at
    if _stripe_api_key and time.time() < _stripe_api_key_expires_at:
        return _stripe_api_key
    if not STRIPE_SECRET_NAME:
        return None
    try:
        sm = boto3.client('secretsmanager')
        secret = json.loads(
            sm.get_secret_value(SecretId=STRIPE_SECRET_NAME)['SecretString']
        )
        _stripe_api_key = secret.get('secret_key', '')
        _stripe_api_key_expires_at = time.time() + WEBHOOK_SECRET_CACHE_TTL
        return _stripe_api_key
    except Exception as e:
        logger.error("Failed to load Stripe API key", extra={"error": str(e)})
        return None


def _stripe_api_get(path, api_key):
    """GET request to Stripe API."""
    url = f'{STRIPE_API_BASE_URL}{path}'
    headers = {
        'Authorization': f'Bearer {api_key}',
    }
    req = urllib.request.Request(url, method='GET', headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, 'read') else str(e)
        logger.error("Stripe API GET error", extra={
            "status": e.code, "response": body[:500], "path": path,
        })
        return None
    except Exception as e:
        logger.error("Stripe API GET error", extra={"error": str(e), "path": path})
        return None


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------

def _get_webhook_secret():
    """Load Stripe webhook signing secret from Secrets Manager (cached)."""
    global _webhook_secret, _webhook_secret_expires_at
    if _webhook_secret and time.time() < _webhook_secret_expires_at:
        return _webhook_secret
    try:
        sm = boto3.client('secretsmanager')
        secret = json.loads(
            sm.get_secret_value(SecretId=STRIPE_WEBHOOK_SECRET_NAME)['SecretString']
        )
        _webhook_secret = secret.get('signing_secret', '')
        _webhook_secret_expires_at = time.time() + WEBHOOK_SECRET_CACHE_TTL
        return _webhook_secret
    except Exception as e:
        logger.error("Failed to load webhook secret", extra={"error": str(e)})
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
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        },
        'body': json.dumps(body),
    }
