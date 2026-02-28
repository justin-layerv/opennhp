"""
Tests for Usage Reporter Lambda (SQS consumer).

Covers: SQS message processing, Stripe usage reporting, partial batch failure,
        usage counter increment, audit trail.

Run with: pytest terraform/modules/billing/lambda/test_usage_reporter.py -v
"""

import json

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _import_module():
    import sys
    for mod in [k for k in sys.modules if k.startswith('usage_reporter')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import usage_reporter as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import usage_reporter
    return usage_reporter


# ---------------------------------------------------------------------------
# Handler Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:

    def test_no_records_returns_200(self, mod):
        resp = mod.lambda_handler({'Records': []}, None)
        assert resp['statusCode'] == 200

    def test_missing_owner_id_skipped(self, mod):
        event = {
            'Records': [{
                'messageId': 'msg-1',
                'body': json.dumps({'owner_id': '', 'idempotency_key': 'k1'}),
            }]
        }
        resp = mod.lambda_handler(event, None)
        # No failure — skipped record
        assert 'batchItemFailures' not in resp

    def test_free_tier_skipped(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'tier': 'free', 'stripe_sub_item_id': 'si_1'}
        with patch.object(mod, '_get_customer', return_value=customer):
            event = {
                'Records': [{
                    'messageId': 'msg-1',
                    'body': json.dumps({'owner_id': 'auth0|u1', 'idempotency_key': 'k1'}),
                }]
            }
            resp = mod.lambda_handler(event, None)
            assert 'batchItemFailures' not in resp

    def test_successful_stripe_report(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'tier': 'growth',
            'stripe_sub_item_id': 'si_123',
        }
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test_key'), \
             patch.object(mod, '_stripe_api', return_value={'id': 'usage_rec_1'}), \
             patch.object(mod, '_increment_usage_counter') as mock_inc, \
             patch.object(mod, '_write_audit') as mock_audit:

            event = {
                'Records': [{
                    'messageId': 'msg-1',
                    'body': json.dumps({
                        'owner_id': 'auth0|u1',
                        'idempotency_key': 'usage-123',
                        'event_type': 'qurl_resolve',
                    }),
                }]
            }
            resp = mod.lambda_handler(event, None)

            assert 'batchItemFailures' not in resp
            mock_inc.assert_called_once_with('auth0|u1')
            mock_audit.assert_called_once()

    def test_stripe_failure_returns_batch_failure(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'tier': 'growth',
            'stripe_sub_item_id': 'si_123',
        }
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api', return_value=None):

            event = {
                'Records': [{
                    'messageId': 'msg-fail',
                    'body': json.dumps({
                        'owner_id': 'auth0|u1',
                        'idempotency_key': 'k1',
                    }),
                }]
            }
            resp = mod.lambda_handler(event, None)
            assert len(resp['batchItemFailures']) == 1
            assert resp['batchItemFailures'][0]['itemIdentifier'] == 'msg-fail'

    def test_missing_sub_item_skipped(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'tier': 'growth'}
        with patch.object(mod, '_get_customer', return_value=customer):
            event = {
                'Records': [{
                    'messageId': 'msg-1',
                    'body': json.dumps({'owner_id': 'auth0|u1', 'idempotency_key': 'k1'}),
                }]
            }
            resp = mod.lambda_handler(event, None)
            assert 'batchItemFailures' not in resp


# ---------------------------------------------------------------------------
# Helper Tests
# ---------------------------------------------------------------------------

class TestGetCustomer:

    def test_returns_item(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            'Item': {'auth0_subject': 'auth0|u1', 'tier': 'growth'}
        }
        with patch.object(mod, 'customers_table', mock_table):
            result = mod._get_customer('auth0|u1')
            assert result['tier'] == 'growth'

    def test_returns_none_when_not_found(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._get_customer('auth0|missing') is None

    def test_returns_none_on_error(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._get_customer('auth0|u1') is None


class TestIncrementUsageCounter:

    def test_atomic_increment(self, mod):
        mock_table = MagicMock()
        with patch.object(mod, 'customers_table', mock_table):
            mod._increment_usage_counter('auth0|u1')
            mock_table.update_item.assert_called_once()
            call_kwargs = mock_table.update_item.call_args[1]
            assert 'current_period_usage' in call_kwargs['UpdateExpression']

    def test_handles_error_gracefully(self, mod):
        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table):
            # Should not raise
            mod._increment_usage_counter('auth0|u1')
