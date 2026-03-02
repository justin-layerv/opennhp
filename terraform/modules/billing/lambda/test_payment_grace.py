"""
Tests for Payment Grace Period Lambda.

Covers: grace period scanning, account freezing, downgrade after 30 days,
        email notifications, CloudWatch metrics.

Run with: pytest terraform/modules/billing/lambda/test_payment_grace.py -v
"""

import json

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call


@pytest.fixture(autouse=True)
def _import_module():
    import sys
    for mod in [k for k in sys.modules if k.startswith('payment_grace')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import payment_grace as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import payment_grace
    return payment_grace


# ---------------------------------------------------------------------------
# Freeze Logic Tests
# ---------------------------------------------------------------------------

class TestFreezeAccount:

    def test_sets_frozen_and_reason(self, mod):
        mock_table = MagicMock()
        with patch.object(mod, 'customers_table', mock_table):
            result = mod._freeze_account('auth0|u1', '2026-01-15T00:00:00+00:00')

            assert result is True
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['ExpressionAttributeValues'][':frozen'] is True
            assert call_kwargs['ExpressionAttributeValues'][':reason'] == 'payment_failed'
            assert 'frozen_reason' in call_kwargs['UpdateExpression']

    def test_conditional_expression_prevents_double_freeze(self, mod):
        mock_table = MagicMock()
        with patch.object(mod, 'customers_table', mock_table):
            mod._freeze_account('auth0|u1', '2026-01-15T00:00:00+00:00')
            call_kwargs = mock_table.update_item.call_args[1]
            assert 'ConditionExpression' in call_kwargs
            assert 'frozen' in call_kwargs['ConditionExpression']

    def test_already_frozen_returns_false(self, mod):
        import botocore.exceptions
        mock_table = MagicMock()
        error_response = {'Error': {'Code': 'ConditionalCheckFailedException', 'Message': 'Condition not met'}}
        mock_table.update_item.side_effect = botocore.exceptions.ClientError(error_response, 'UpdateItem')
        with patch.object(mod, 'customers_table', mock_table):
            result = mod._freeze_account('auth0|u1', '2026-01-15T00:00:00+00:00')
            assert result is False

    def test_returns_false_on_error(self, mod):
        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table):
            result = mod._freeze_account('auth0|u1', '2026-01-15T00:00:00+00:00')
            assert result is False


class TestDowngradeAccount:

    def test_sets_free_tier_and_removes_fields(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': {'stripe_subscription_id': ''}}
        with patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_cancel_stripe_subscription') as mock_cancel:
            result = mod._downgrade_account('auth0|u1', '2026-01-15T00:00:00+00:00')

            assert result is True
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['ExpressionAttributeValues'][':tier'] == 'free'
            expr = call_kwargs['UpdateExpression']
            assert 'REMOVE frozen, frozen_reason, frozen_at' in expr
            assert 'stripe_subscription_id' in expr
            mock_cancel.assert_not_called()  # No sub ID = no cancellation

    def test_cancels_stripe_subscription_before_downgrade(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            'Item': {'stripe_subscription_id': 'sub_123'}
        }
        with patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_cancel_stripe_subscription', return_value=True) as mock_cancel:
            result = mod._downgrade_account('auth0|u1', '2026-01-15T00:00:00+00:00')

            assert result is True
            mock_cancel.assert_called_once_with('sub_123')

    def test_continues_downgrade_if_cancellation_fails(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            'Item': {'stripe_subscription_id': 'sub_456'}
        }
        with patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_cancel_stripe_subscription', return_value=False), \
             patch.object(mod, '_emit_metric') as mock_metric:
            result = mod._downgrade_account('auth0|u1', '2026-01-15T00:00:00+00:00')
            assert result is True  # Downgrade proceeds despite cancellation failure
            mock_metric.assert_called_once_with('StripeCancellationFailed', 1)

    def test_returns_false_on_ddb_error(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {'Item': {'stripe_subscription_id': ''}}
        mock_table.update_item.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_cancel_stripe_subscription'):
            result = mod._downgrade_account('auth0|u1', '2026-01-15T00:00:00+00:00')
            assert result is False


# ---------------------------------------------------------------------------
# Stripe Subscription Cancellation Tests
# ---------------------------------------------------------------------------

class TestCancelStripeSubscription:

    def test_successful_cancellation(self, mod):
        response_body = json.dumps({'id': 'sub_123', 'status': 'canceled'}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(mod, '_get_stripe_key', return_value='sk_test_123'), \
             patch('urllib.request.urlopen', return_value=mock_resp):
            assert mod._cancel_stripe_subscription('sub_123') is True

    def test_no_stripe_key_returns_false(self, mod):
        with patch.object(mod, '_get_stripe_key', return_value=None):
            assert mod._cancel_stripe_subscription('sub_123') is False

    def test_http_error_returns_false(self, mod):
        import urllib.error
        with patch.object(mod, '_get_stripe_key', return_value='sk_test_123'), \
             patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError(
                 'https://api.stripe.com/v1/subscriptions/sub_123',
                 404, 'Not Found', {}, None
             )):
            assert mod._cancel_stripe_subscription('sub_123') is False

    def test_network_error_returns_false(self, mod):
        import socket
        with patch.object(mod, '_get_stripe_key', return_value='sk_test_123'), \
             patch('urllib.request.urlopen', side_effect=socket.timeout("timed out")):
            assert mod._cancel_stripe_subscription('sub_123') is False


# ---------------------------------------------------------------------------
# Stripe Key Loading Tests
# ---------------------------------------------------------------------------

class TestGetStripeKey:

    def test_loads_from_secrets_manager(self, mod):
        # Reset cache
        mod._stripe_api_key = None
        mod._stripe_api_key_expires_at = 0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            'SecretString': json.dumps({'secret_key': 'sk_test_abc'})
        }
        with patch.object(mod, 'STRIPE_SECRET_NAME', 'stripe-secret'), \
             patch('boto3.client', return_value=mock_sm):
            key = mod._get_stripe_key()
            assert key == 'sk_test_abc'

    def test_returns_cached_key(self, mod):
        import time as time_mod
        mod._stripe_api_key = 'sk_cached'
        mod._stripe_api_key_expires_at = time_mod.time() + 300

        key = mod._get_stripe_key()
        assert key == 'sk_cached'

        # Clean up
        mod._stripe_api_key = None
        mod._stripe_api_key_expires_at = 0

    def test_no_secret_name_returns_none(self, mod):
        mod._stripe_api_key = None
        mod._stripe_api_key_expires_at = 0

        with patch.object(mod, 'STRIPE_SECRET_NAME', ''):
            assert mod._get_stripe_key() is None


# ---------------------------------------------------------------------------
# Configurable Downgrade Days Tests
# ---------------------------------------------------------------------------

class TestConfigurableDowngradeDays:

    def test_downgrade_after_days_is_configurable(self, mod):
        assert isinstance(mod.DOWNGRADE_AFTER_DAYS, int)
        assert mod.DOWNGRADE_AFTER_DAYS > 0


# ---------------------------------------------------------------------------
# Handler Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:

    def test_no_table_returns_500(self, mod):
        with patch.object(mod, 'customers_table', None):
            resp = mod.lambda_handler({}, None)
            assert resp['statusCode'] == 500

    def test_freezes_unfrozen_past_deadline(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': False,
            'frozen_at': '',
        }
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_freeze_account', return_value=True) as mock_freeze, \
             patch.object(mod, '_send_freeze_notification') as mock_email, \
             patch.object(mod, '_emit_metric'), \
             patch.object(mod, 'audit_table', mock_audit):
            mod.lambda_handler({}, None)

            mock_freeze.assert_called_once()
            mock_email.assert_called_once_with('user@test.com')

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'account_frozen'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item

    def test_freeze_failure_skips_notification(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': False,
            'frozen_at': '',
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_freeze_account', return_value=False) as mock_freeze, \
             patch.object(mod, '_send_freeze_notification') as mock_email, \
             patch.object(mod, '_emit_metric') as mock_metric:
            resp = mod.lambda_handler({}, None)

            mock_freeze.assert_called_once()
            mock_email.assert_not_called()
            body = json.loads(resp['body'])
            assert body['accounts_frozen'] == 0

    def test_downgrades_after_30_days_frozen(self, mod):
        frozen_at = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': True,
            'frozen_at': frozen_at,
        }
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_downgrade_account', return_value=True) as mock_downgrade, \
             patch.object(mod, '_send_downgrade_notification') as mock_email, \
             patch.object(mod, '_emit_metric'), \
             patch.object(mod, 'audit_table', mock_audit):
            mod.lambda_handler({}, None)

            mock_downgrade.assert_called_once()
            mock_email.assert_called_once_with('user@test.com')

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'account_downgraded'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item

    def test_does_not_downgrade_within_30_days(self, mod):
        frozen_at = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': True,
            'frozen_at': frozen_at,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_downgrade_account') as mock_downgrade, \
             patch.object(mod, '_emit_metric'):
            mod.lambda_handler({}, None)

            mock_downgrade.assert_not_called()

    def test_freeze_succeeds_when_audit_fails(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': False,
            'frozen_at': '',
        }
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_freeze_account', return_value=True) as mock_freeze, \
             patch.object(mod, '_send_freeze_notification'), \
             patch.object(mod, '_emit_metric'), \
             patch.object(mod, 'audit_table', mock_audit):
            resp = mod.lambda_handler({}, None)

            # Freeze should succeed despite audit failure
            mock_freeze.assert_called_once()
            body = json.loads(resp['body'])
            assert body['accounts_frozen'] == 1

    def test_downgrade_succeeds_when_audit_fails(self, mod):
        frozen_at = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        customer = {
            'auth0_subject': 'auth0|u1',
            'email': 'user@test.com',
            'frozen': True,
            'frozen_at': frozen_at,
        }
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[customer]), \
             patch.object(mod, '_downgrade_account', return_value=True) as mock_downgrade, \
             patch.object(mod, '_send_downgrade_notification'), \
             patch.object(mod, '_emit_metric'), \
             patch.object(mod, 'audit_table', mock_audit):
            resp = mod.lambda_handler({}, None)

            # Downgrade should succeed despite audit failure
            mock_downgrade.assert_called_once()
            body = json.loads(resp['body'])
            assert body['accounts_downgraded'] == 1

    def test_emits_metrics(self, mod):
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_customers_past_deadline', return_value=[]), \
             patch.object(mod, '_emit_metric') as mock_metric:
            mod.lambda_handler({}, None)

            calls = [c[0] for c in mock_metric.call_args_list]
            assert ('AccountsFrozen', 0) in calls
            assert ('AccountsDowngraded', 0) in calls
