"""
Billing Reconciliation Lambda

Runs daily via EventBridge. Compares the current_period_usage counter in the
customers table against actual counts in the billing audit table. Logs
discrepancies as CloudWatch metrics for alerting.

Trigger: EventBridge rule (rate: 1 day)
"""

import json
import boto3
import logging
import os
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
CUSTOMERS_TABLE_NAME = os.environ.get('CUSTOMERS_TABLE_NAME', '')
BILLING_AUDIT_TABLE_NAME = os.environ.get('BILLING_AUDIT_TABLE_NAME', '')
METRICS_NAMESPACE = os.environ.get('METRICS_NAMESPACE', 'LayerV/Billing')

# AWS clients
dynamodb = boto3.resource('dynamodb')
cloudwatch = boto3.client('cloudwatch')
customers_table = dynamodb.Table(CUSTOMERS_TABLE_NAME) if CUSTOMERS_TABLE_NAME else None
audit_table = dynamodb.Table(BILLING_AUDIT_TABLE_NAME) if BILLING_AUDIT_TABLE_NAME else None


def lambda_handler(event, context):
    """Run daily usage reconciliation."""
    logger.info("Starting billing reconciliation")

    if not customers_table:
        logger.error("CUSTOMERS_TABLE_NAME not configured")
        return {'statusCode': 500, 'body': 'Not configured'}

    # Scan for all growth-tier customers with active subscriptions
    customers = _get_growth_customers()
    if not customers:
        logger.info("No growth customers found for reconciliation")
        _emit_metric('ReconciliationCustomersChecked', 0)
        return {'statusCode': 200, 'body': 'No customers to reconcile'}

    total_checked = 0
    total_discrepancies = 0

    for customer in customers:
        auth0_sub = customer.get('auth0_subject', '')
        reported_usage = int(customer.get('current_period_usage', 0))
        period_start = customer.get('current_period_start')

        if not auth0_sub or not period_start:
            continue

        # Count actual audit entries for this period
        actual_count = _count_audit_entries(auth0_sub, period_start)
        if actual_count is None:
            # Audit table not available or query failed
            continue

        total_checked += 1

        # Compare
        discrepancy = abs(reported_usage - actual_count)
        if discrepancy > 0:
            total_discrepancies += 1

            # Auto-correct small discrepancies (< 1% of actual count)
            discrepancy_pct = (discrepancy / max(actual_count, 1)) * 100
            if discrepancy_pct < 1.0 and actual_count > 0:
                _auto_correct_usage(auth0_sub, actual_count)
                logger.info("Auto-corrected small usage discrepancy", extra={
                    "auth0_sub": auth0_sub,
                    "reported_usage": reported_usage,
                    "actual_count": actual_count,
                    "discrepancy": discrepancy,
                    "discrepancy_pct": round(discrepancy_pct, 2),
                })
            else:
                logger.warning("Usage discrepancy detected", extra={
                    "auth0_sub": auth0_sub,
                    "reported_usage": reported_usage,
                    "actual_count": actual_count,
                    "discrepancy": discrepancy,
                    "discrepancy_pct": round(discrepancy_pct, 2),
                })

            _emit_metric('UsageDiscrepancy', discrepancy, [
                {'Name': 'CustomerId', 'Value': auth0_sub},
            ])

    # Emit summary metrics
    _emit_metric('ReconciliationCustomersChecked', total_checked)
    _emit_metric('ReconciliationDiscrepanciesFound', total_discrepancies)

    logger.info("Billing reconciliation complete", extra={
        "customers_checked": total_checked,
        "discrepancies_found": total_discrepancies,
    })

    return {
        'statusCode': 200,
        'body': json.dumps({
            'customers_checked': total_checked,
            'discrepancies_found': total_discrepancies,
        }),
    }


# ---------------------------------------------------------------------------
# DynamoDB Helpers
# ---------------------------------------------------------------------------

def _get_growth_customers():
    """Scan for all customers on the growth tier with active subscriptions."""
    if not customers_table:
        return []

    try:
        items = []
        params = {
            'FilterExpression': 'tier = :tier AND attribute_exists(stripe_subscription_id)',
            'ExpressionAttributeValues': {':tier': 'growth'},
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
        logger.error("Failed to scan growth customers", extra={"error": str(e)})
        return []


def _count_audit_entries(owner_id, period_start):
    """Count usage audit entries for a customer since the period start."""
    if not audit_table:
        return None

    try:
        # Convert period_start (Unix timestamp) to ISO string for comparison
        if isinstance(period_start, (int, float)):
            period_start_iso = datetime.fromtimestamp(
                period_start, tz=timezone.utc
            ).isoformat()
        else:
            period_start_iso = str(period_start)

        count = 0
        params = {
            # event_id format: "{ISO-timestamp}#{uuid}" — string comparison
            # on the sort key works because ISO 8601 is lexicographically ordered.
            'KeyConditionExpression': 'owner_id = :oid AND event_id >= :start',
            'FilterExpression': 'event_type = :etype',
            'ExpressionAttributeValues': {
                ':oid': owner_id,
                ':start': period_start_iso,
                ':etype': 'qurl_resolve',
            },
            'Select': 'COUNT',
        }

        while True:
            resp = audit_table.query(**params)
            count += resp.get('Count', 0)
            last_key = resp.get('LastEvaluatedKey')
            if not last_key:
                break
            params['ExclusiveStartKey'] = last_key

        return count
    except Exception as e:
        logger.error("Failed to count audit entries", extra={
            "error": str(e), "owner_id": owner_id,
        })
        return None


def _auto_correct_usage(auth0_sub, actual_count):
    """Auto-correct the current_period_usage counter to match audit count."""
    if not customers_table:
        return
    try:
        customers_table.update_item(
            Key={'auth0_subject': auth0_sub},
            UpdateExpression='SET current_period_usage = :count',
            ExpressionAttributeValues={':count': actual_count},
        )
    except Exception as e:
        logger.warning("Failed to auto-correct usage", extra={
            "error": str(e), "auth0_sub": auth0_sub,
        })


# ---------------------------------------------------------------------------
# CloudWatch Metrics
# ---------------------------------------------------------------------------

def _emit_metric(metric_name, value, extra_dimensions=None):
    """Emit a CloudWatch metric to the LayerV/Billing namespace."""
    try:
        dimensions = [
            {'Name': 'Service', 'Value': 'billing-reconciliation'},
        ]
        if extra_dimensions:
            dimensions.extend(extra_dimensions)

        cloudwatch.put_metric_data(
            Namespace=METRICS_NAMESPACE,
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': 'Count',
                'Dimensions': dimensions,
            }]
        )
    except Exception as e:
        logger.warning("Failed to emit metric", extra={
            "error": str(e), "metric_name": metric_name,
        })
