"""
Usage Reporter Lambda (SQS Consumer)

Processes usage events from the SQS queue and reports metered usage to
Stripe. Each event represents one QURL resolution that should be counted
against the customer's subscription.

Trigger: SQS event source mapping (batch_size=10)

SQS message format:
    {
        "owner_id": "auth0|abc123",
        "idempotency_key": "usage-xxx-yyy",
        "event_type": "qurl_resolve",
        "timestamp": "2024-01-15T10:30:00Z"
    }
"""

import json
import boto3
import logging
import os
import time
import uuid
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
BILLING_AUDIT_TABLE_NAME = os.environ.get('BILLING_AUDIT_TABLE_NAME', '')
STRIPE_API_BASE_URL = os.environ.get('STRIPE_API_BASE_URL', 'https://api.stripe.com')

# Module-level cache for Stripe key
_stripe_key = None
_stripe_key_expires_at = 0
STRIPE_CACHE_TTL = 300  # 5 minutes

# AWS clients
dynamodb = boto3.resource('dynamodb')
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None
audit_table = dynamodb.Table(BILLING_AUDIT_TABLE_NAME) if BILLING_AUDIT_TABLE_NAME else None


def lambda_handler(event, context):
    """Process SQS usage events and report to Stripe."""
    records = event.get('Records', [])
    if not records:
        return {'statusCode': 200, 'body': 'No records'}

    failures = []

    for record in records:
        message_id = record.get('messageId', '')
        try:
            body = json.loads(record['body'])
            owner_id = body.get('owner_id', '')
            idempotency_key = body.get('idempotency_key', '')
            event_type = body.get('event_type', 'qurl_resolve')

            if not owner_id:
                logger.warning("Skipping usage event - missing owner_id", extra={
                    "message_id": message_id,
                })
                continue

            # Look up customer's stripe_sub_item_id
            customer = _get_customer(owner_id)
            if not customer:
                logger.warning("Skipping usage report - customer not found", extra={
                    "owner_id": owner_id,
                    "message_id": message_id,
                })
                continue

            if not customer.get('stripe_sub_item_id'):
                logger.warning("Skipping usage report - no subscription item", extra={
                    "owner_id": owner_id,
                    "message_id": message_id,
                })
                continue

            # Check if customer is on a paid tier
            tier = customer.get('tier', 'free')
            if tier == 'free':
                logger.info("Skipping usage report - free tier", extra={
                    "owner_id": owner_id,
                })
                continue

            # Report to Stripe
            stripe_key = _get_stripe_key()
            if not stripe_key:
                logger.error("Failed to load Stripe key", extra={
                    "owner_id": owner_id, "message_id": message_id,
                })
                failures.append({'itemIdentifier': message_id})
                continue

            sub_item_id = customer['stripe_sub_item_id']

            params = {
                'quantity': '1',
                'timestamp': str(int(time.time())),
                'action': 'increment',
            }

            # Add idempotency key as Stripe header if available
            result = _stripe_api(
                'POST',
                f'/v1/subscription_items/{sub_item_id}/usage_records',
                params,
                stripe_key,
                idempotency_key=idempotency_key,
            )

            if result:
                logger.info("Usage reported to Stripe", extra={
                    "owner_id": owner_id,
                    "stripe_usage_id": result.get('id', ''),
                    "sub_item_id": sub_item_id,
                })

                # Increment local usage counter
                _increment_usage_counter(owner_id)

                # Write to billing audit table
                _write_audit(owner_id, event_type, {
                    'stripe_usage_id': result.get('id', ''),
                    'idempotency_key': idempotency_key,
                    'quantity': 1,
                    'message_id': message_id,
                })
            else:
                logger.error("Failed to report usage to Stripe", extra={
                    "owner_id": owner_id,
                    "sub_item_id": sub_item_id,
                    "message_id": message_id,
                })
                failures.append({'itemIdentifier': message_id})

        except Exception as e:
            logger.error("Usage event processing error", extra={
                "error": str(e),
                "message_id": message_id,
            })
            failures.append({'itemIdentifier': message_id})

    # Return partial batch failure response
    if failures:
        return {'batchItemFailures': failures}

    return {'statusCode': 200, 'body': f'Processed {len(records)} records'}


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


def _stripe_api(method, path, params, api_key, idempotency_key=''):
    """Call Stripe API using urllib (no SDK dependency)."""
    url = f'{STRIPE_API_BASE_URL}{path}'
    data = urllib.parse.urlencode(params).encode() if params else None
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    if idempotency_key:
        headers['Idempotency-Key'] = idempotency_key

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
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

def _get_customer(owner_id):
    """Get customer record from DynamoDB."""
    if not customers_table:
        return None
    try:
        resp = customers_table.get_item(Key={'auth0_subject': owner_id})
        return resp.get('Item')
    except Exception as e:
        logger.error("DynamoDB get customer error", extra={"error": str(e)})
        return None


def _increment_usage_counter(owner_id):
    """Atomically increment the current_period_usage counter."""
    if not customers_table:
        return
    try:
        customers_table.update_item(
            Key={'auth0_subject': owner_id},
            UpdateExpression='SET current_period_usage = if_not_exists(current_period_usage, :zero) + :inc',
            ExpressionAttributeValues={
                ':inc': 1,
                ':zero': 0,
            }
        )
    except Exception as e:
        logger.warning("Failed to increment usage counter", extra={
            "error": str(e), "owner_id": owner_id,
        })


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
            'details': details,
        })
    except Exception as e:
        logger.warning("Failed to write audit entry", extra={
            "error": str(e), "owner_id": owner_id,
        })
