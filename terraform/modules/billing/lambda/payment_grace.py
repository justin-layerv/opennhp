"""
Payment Grace Period Lambda

Runs hourly via EventBridge. Scans for customers past their payment grace
deadline, freezes their accounts, and downgrades after 30 days of
non-payment.

Trigger: EventBridge rule (rate: 1 hour)

Grace period timeline:
    Day 0:  invoice.payment_failed -> payment_grace_deadline set (now + 7 days)
    Day 7:  This Lambda freezes the account (frozen = true, frozen_reason = "payment_failed")
    Day 37: This Lambda downgrades to free tier (30 days after freeze)
"""

import json
import boto3
import botocore.exceptions
import logging
import os
import time
import uuid
import urllib.request
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
CUSTOMERS_TABLE_NAME = os.environ.get('CUSTOMERS_TABLE_NAME', '')
FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@layerv.ai')
SES_REGION = os.environ.get('SES_REGION', 'us-east-1')
STRIPE_SECRET_NAME = os.environ.get('STRIPE_SECRET_NAME', '')
METRICS_NAMESPACE = os.environ.get('METRICS_NAMESPACE', 'LayerV/Billing')
STRIPE_API_BASE_URL = os.environ.get('STRIPE_API_BASE_URL', 'https://api.stripe.com')
BILLING_AUDIT_TABLE_NAME = os.environ.get('BILLING_AUDIT_TABLE_NAME', '')

# Downgrade after N days of frozen state (configurable, default 30)
DOWNGRADE_AFTER_DAYS = int(os.environ.get('DOWNGRADE_AFTER_DAYS', '30'))

# Module-level cache for Stripe secret key
_stripe_api_key = None
_stripe_api_key_expires_at = 0
STRIPE_SECRET_CACHE_TTL = 300  # 5 minutes

# AWS clients
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses', region_name=SES_REGION)
cloudwatch = boto3.client('cloudwatch')
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None
audit_table = dynamodb.Table(BILLING_AUDIT_TABLE_NAME) if BILLING_AUDIT_TABLE_NAME else None


def lambda_handler(event, context):
    """Run hourly payment grace period check."""
    logger.info("Starting payment grace check")

    if not customers_table:
        logger.error("CUSTOMERS_TABLE_NAME not configured")
        return {'statusCode': 500, 'body': 'Not configured'}

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # Find customers with payment_grace_deadline that has passed
    customers = _get_customers_past_deadline(now_iso)

    frozen_count = 0
    downgraded_count = 0

    for customer in customers:
        auth0_sub = customer.get('auth0_subject', '')
        email = customer.get('email', '')
        is_frozen = customer.get('frozen', False)
        frozen_at = customer.get('frozen_at', '')

        if not auth0_sub:
            continue

        if not is_frozen:
            # Freeze the account
            if _freeze_account(auth0_sub, now_iso):
                frozen_count += 1
                _write_audit(auth0_sub, 'account_frozen', {
                    'reason': 'payment_failed',
                    'payment_grace_deadline': customer.get('payment_grace_deadline', ''),
                })

                # Send notification email
                if email:
                    _send_freeze_notification(email)

                logger.info("Account frozen", extra={
                    "auth0_sub": auth0_sub,
                    "email": email,
                })

        elif is_frozen and frozen_at:
            # Check if frozen for more than DOWNGRADE_AFTER_DAYS
            try:
                frozen_dt = datetime.fromisoformat(frozen_at)
                if now - frozen_dt > timedelta(days=DOWNGRADE_AFTER_DAYS):
                    if _downgrade_account(auth0_sub, now_iso):
                        downgraded_count += 1
                        _write_audit(auth0_sub, 'account_downgraded', {
                            'reason': 'grace_period_expired',
                            'frozen_at': frozen_at,
                            'days_frozen': (now - frozen_dt).days,
                        })

                        if email:
                            _send_downgrade_notification(email)

                        logger.info("Account downgraded after grace period", extra={
                            "auth0_sub": auth0_sub,
                            "email": email,
                            "frozen_at": frozen_at,
                        })
            except (ValueError, TypeError) as e:
                logger.warning("Invalid frozen_at timestamp", extra={
                    "auth0_sub": auth0_sub,
                    "frozen_at": frozen_at,
                    "error": str(e),
                })

    # Emit metrics
    _emit_metric('AccountsFrozen', frozen_count)
    _emit_metric('AccountsDowngraded', downgraded_count)

    logger.info("Payment grace check complete", extra={
        "accounts_frozen": frozen_count,
        "accounts_downgraded": downgraded_count,
    })

    return {
        'statusCode': 200,
        'body': json.dumps({
            'accounts_frozen': frozen_count,
            'accounts_downgraded': downgraded_count,
        }),
    }


# ---------------------------------------------------------------------------
# DynamoDB Helpers
# ---------------------------------------------------------------------------

def _get_customers_past_deadline(now_iso):
    """Scan for customers whose payment_grace_deadline has passed."""
    if not customers_table:
        return []

    try:
        items = []
        params = {
            'FilterExpression': (
                'attribute_exists(payment_grace_deadline) AND '
                'payment_grace_deadline < :now AND '
                'tier = :tier'
            ),
            'ExpressionAttributeValues': {
                ':now': now_iso,
                ':tier': 'growth',
            },
        }

        while True:
            resp = customers_table.scan(**params)
            items.extend(resp.get('Items', []))
            last_key = resp.get('LastEvaluatedKey')
            if not last_key:
                break
            params['ExclusiveStartKey'] = last_key

        return items
    except Exception as e:
        logger.error("Failed to scan for past-deadline customers", extra={
            "error": str(e),
        })
        return []


def _freeze_account(auth0_sub, now_iso):
    """Freeze a customer's account. Returns True on success.

    Uses a conditional update to prevent race conditions — only freezes
    if the account is not already frozen.
    """
    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=(
                'SET frozen = :frozen, frozen_reason = :reason, '
                'frozen_at = :now, updated_at = :now'
            ),
            ConditionExpression='attribute_not_exists(frozen) OR frozen = :false',
            ExpressionAttributeValues={
                ':frozen': True,
                ':false': False,
                ':reason': 'payment_failed',
                ':now': now_iso,
            }
        )
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.info("Account already frozen, skipping", extra={
                "auth0_sub": auth0_sub,
            })
            return False
        logger.error("Failed to freeze account", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        return False
    except Exception as e:
        logger.error("Failed to freeze account", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        return False


def _downgrade_account(auth0_sub, now_iso):
    """Downgrade a customer's account to free tier. Returns True on success.

    Cancels the Stripe subscription (if any) before updating DynamoDB.
    """
    # Look up the subscription ID before removing it from DynamoDB
    subscription_id = _get_customer_subscription_id(auth0_sub)

    # Cancel Stripe subscription first (if exists)
    if subscription_id:
        if not _cancel_stripe_subscription(subscription_id):
            logger.warning("Stripe cancellation failed, proceeding with downgrade", extra={
                "auth0_sub": auth0_sub,
                "subscription_id": subscription_id,
            })
            # Emit metric so operators can investigate and manually cancel in Stripe
            _emit_metric('StripeCancellationFailed', 1)

    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression=(
                'SET tier = :tier, updated_at = :now '
                'REMOVE frozen, frozen_reason, frozen_at, payment_grace_deadline, '
                'stripe_subscription_id, stripe_sub_item_id, '
                'current_period_start, current_period_usage'
            ),
            ExpressionAttributeValues={
                ':tier': 'free',
                ':now': now_iso,
            }
        )
        return True
    except Exception as e:
        logger.error("Failed to downgrade account", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        return False


def _get_customer_subscription_id(auth0_sub):
    """Get Stripe subscription ID for a customer."""
    try:
        resp = customers_table.get_item(Key={'auth0_subject': auth0_sub})
        item = resp.get('Item', {})
        return item.get('stripe_subscription_id', '')
    except Exception as e:
        logger.warning("Failed to get subscription ID", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })
        return ''


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
# Email Notifications
# ---------------------------------------------------------------------------

def _send_freeze_notification(email):
    """Send account freeze notification email."""
    try:
        ses.send_email(
            Source=FROM_EMAIL,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {
                    'Data': 'LayerV - Action Required: Payment Failed'
                },
                'Body': {
                    'Html': {'Data': _freeze_email_html()},
                    'Text': {'Data': _freeze_email_text()},
                }
            }
        )
    except Exception as e:
        logger.warning("Failed to send freeze notification", extra={
            "error": str(e), "email": email,
        })


def _send_downgrade_notification(email):
    """Send account downgrade notification email."""
    try:
        ses.send_email(
            Source=FROM_EMAIL,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {
                    'Data': 'LayerV - Account Downgraded to Free Plan'
                },
                'Body': {
                    'Html': {'Data': _downgrade_email_html()},
                    'Text': {'Data': _downgrade_email_text()},
                }
            }
        )
    except Exception as e:
        logger.warning("Failed to send downgrade notification", extra={
            "error": str(e), "email": email,
        })


def _freeze_email_html():
    """HTML template for account freeze notification."""
    return """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px; color: #1a1a2e;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1; font-size: 24px; margin: 0;">LayerV</h1>
  </div>

  <h2 style="font-size: 20px; margin-bottom: 16px;">Payment Failed - Action Required</h2>

  <p>We were unable to process payment for your LayerV Growth plan subscription.
  Your account has been temporarily frozen.</p>

  <p>While frozen:</p>
  <ul>
    <li>Existing QURLs will continue to work</li>
    <li>You cannot create new QURLs</li>
    <li>API key creation is disabled</li>
  </ul>

  <p>Please update your payment method to restore full access. If payment is not
  resolved within 30 days, your account will be downgraded to the Free plan.</p>

  <p style="font-size: 12px; color: #94a3b8; margin-top: 40px; text-align: center;">
    LayerV &mdash; Network Hiding Protocol
  </p>
</body>
</html>"""


def _freeze_email_text():
    """Plain text template for account freeze notification."""
    return """LayerV - Payment Failed - Action Required

We were unable to process payment for your LayerV Growth plan subscription.
Your account has been temporarily frozen.

While frozen:
- Existing QURLs will continue to work
- You cannot create new QURLs
- API key creation is disabled

Please update your payment method to restore full access. If payment is not
resolved within 30 days, your account will be downgraded to the Free plan.

-- LayerV"""


def _downgrade_email_html():
    """HTML template for account downgrade notification."""
    return """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px; color: #1a1a2e;">
  <div style="text-align: center; margin-bottom: 30px;">
    <h1 style="color: #6366f1; font-size: 24px; margin: 0;">LayerV</h1>
  </div>

  <h2 style="font-size: 20px; margin-bottom: 16px;">Account Downgraded to Free Plan</h2>

  <p>Due to an unresolved payment issue, your LayerV account has been
  downgraded to the Free plan.</p>

  <p>Your existing QURLs may be affected by Free plan limits. You can
  upgrade again at any time from your account settings.</p>

  <p style="font-size: 12px; color: #94a3b8; margin-top: 40px; text-align: center;">
    LayerV &mdash; Network Hiding Protocol
  </p>
</body>
</html>"""


def _downgrade_email_text():
    """Plain text template for account downgrade notification."""
    return """LayerV - Account Downgraded to Free Plan

Due to an unresolved payment issue, your LayerV account has been
downgraded to the Free plan.

Your existing QURLs may be affected by Free plan limits. You can
upgrade again at any time from your account settings.

-- LayerV"""


# ---------------------------------------------------------------------------
# Stripe API Helpers
# ---------------------------------------------------------------------------

def _get_stripe_key():
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
        _stripe_api_key_expires_at = time.time() + STRIPE_SECRET_CACHE_TTL
        return _stripe_api_key
    except Exception as e:
        logger.error("Failed to load Stripe API key", extra={"error": str(e)})
        return None


def _cancel_stripe_subscription(subscription_id):
    """Cancel a Stripe subscription. Returns True on success."""
    api_key = _get_stripe_key()
    if not api_key:
        logger.error("No Stripe API key available for subscription cancellation")
        return False

    url = f'{STRIPE_API_BASE_URL}/v1/subscriptions/{subscription_id}'
    headers = {
        'Authorization': f'Bearer {api_key}',
    }

    req = urllib.request.Request(url, method='DELETE', headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            logger.info("Stripe subscription cancelled", extra={
                "subscription_id": subscription_id,
                "status": result.get('status', ''),
            })
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, 'read') else str(e)
        logger.error("Stripe subscription cancellation failed", extra={
            "subscription_id": subscription_id,
            "status": e.code,
            "response": body[:500],
        })
        return False
    except Exception as e:
        logger.error("Stripe API error during cancellation", extra={
            "subscription_id": subscription_id,
            "error": str(e),
        })
        return False


# ---------------------------------------------------------------------------
# CloudWatch Metrics
# ---------------------------------------------------------------------------

def _emit_metric(metric_name, value):
    """Emit a CloudWatch metric to the LayerV/Billing namespace."""
    try:
        cloudwatch.put_metric_data(
            Namespace=METRICS_NAMESPACE,
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Service', 'Value': 'billing-payment-grace'},
                ],
            }]
        )
    except Exception as e:
        logger.warning("Failed to emit metric", extra={
            "error": str(e), "metric_name": metric_name,
        })
