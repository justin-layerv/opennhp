"""
Tests for Stripe Checkout & Portal Session Lambda.

Covers: JWT auth extraction, checkout session creation, portal session creation,
        Stripe customer creation, DynamoDB customer lookup, CORS.

Run with: pytest terraform/modules/billing/lambda/test_checkout_session.py -v
"""

import json

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _import_module():
    import sys
    for mod in [k for k in sys.modules if k.startswith('checkout_session')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import checkout_session as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import checkout_session
    return checkout_session


# ---------------------------------------------------------------------------
# Handler Routing Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:

    def test_options_returns_cors(self, mod):
        event = {
            'requestContext': {'http': {'method': 'OPTIONS'}},
            'rawPath': '/billing/checkout-session',
            'headers': {'origin': 'https://layerv.ai'},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in resp['headers']

    def test_missing_auth_returns_401(self, mod):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'rawPath': '/billing/checkout-session',
            'headers': {},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 401
        body = json.loads(resp['body'])
        assert body['error']['code'] == 'unauthorized'

    def test_unknown_path_returns_404(self, mod):
        event = {
            'requestContext': {
                'http': {'method': 'POST'},
                'authorizer': {'jwt': {'claims': {'sub': 'auth0|u1'}}},
            },
            'rawPath': '/billing/unknown',
            'headers': {},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 404

    def test_routes_to_checkout(self, mod):
        event = {
            'requestContext': {
                'http': {'method': 'POST'},
                'authorizer': {'jwt': {'claims': {'sub': 'auth0|u1'}}},
            },
            'rawPath': '/billing/checkout-session',
            'headers': {},
        }
        with patch.object(mod, 'handle_checkout_session', return_value={'statusCode': 200}) as mock_handler:
            mod.lambda_handler(event, None)
            mock_handler.assert_called_once()

    def test_routes_to_portal(self, mod):
        event = {
            'requestContext': {
                'http': {'method': 'POST'},
                'authorizer': {'jwt': {'claims': {'sub': 'auth0|u1'}}},
            },
            'rawPath': '/billing/portal-session',
            'headers': {},
        }
        with patch.object(mod, 'handle_portal_session', return_value={'statusCode': 200}) as mock_handler:
            mod.lambda_handler(event, None)
            mock_handler.assert_called_once()


# ---------------------------------------------------------------------------
# Checkout Session Tests
# ---------------------------------------------------------------------------

class TestHandleCheckoutSession:

    def test_returns_checkout_url(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_123'}
        with patch.object(mod, '_get_or_create_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api', return_value={'id': 'cs_1', 'url': 'https://checkout.stripe.com/pay/cs_1'}), \
             patch.object(mod, 'GROWTH_PRICE_ID', 'price_growth'):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/checkout-session',
                'headers': {},
            }
            resp = mod.handle_checkout_session(event, 'auth0|u1')
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert 'checkout_url' in body['data']

    def test_no_customer_returns_500(self, mod):
        with patch.object(mod, '_get_or_create_customer', return_value=None), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/checkout-session',
                'headers': {},
            }
            resp = mod.handle_checkout_session(event, 'auth0|u1')
            assert resp['statusCode'] == 500

    def test_no_price_ids_returns_500(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_123'}
        with patch.object(mod, '_get_or_create_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, 'GROWTH_PRICE_ID', ''), \
             patch.object(mod, 'BASE_FEE_PRICE_ID', ''):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/checkout-session',
                'headers': {},
            }
            resp = mod.handle_checkout_session(event, 'auth0|u1')
            assert resp['statusCode'] == 500
            body = json.loads(resp['body'])
            assert body['error']['code'] == 'no_price_configured'

    def test_stripe_api_failure_returns_500(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_123'}
        with patch.object(mod, '_get_or_create_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api', return_value=None), \
             patch.object(mod, 'GROWTH_PRICE_ID', 'price_growth'):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/checkout-session',
                'headers': {},
            }
            resp = mod.handle_checkout_session(event, 'auth0|u1')
            assert resp['statusCode'] == 500


# ---------------------------------------------------------------------------
# Portal Session Tests
# ---------------------------------------------------------------------------

class TestHandlePortalSession:

    def test_returns_portal_url(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_123'}
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api', return_value={'id': 'bps_1', 'url': 'https://billing.stripe.com/session/bps_1'}):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/portal-session',
                'headers': {},
            }
            resp = mod.handle_portal_session(event, 'auth0|u1')
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert 'portal_url' in body['data']

    def test_no_subscription_returns_400(self, mod):
        with patch.object(mod, '_get_customer', return_value={'auth0_subject': 'auth0|u1'}), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'):
            event = {
                'requestContext': {'http': {'method': 'POST'}},
                'rawPath': '/billing/portal-session',
                'headers': {},
            }
            resp = mod.handle_portal_session(event, 'auth0|u1')
            assert resp['statusCode'] == 400
            body = json.loads(resp['body'])
            assert body['error']['code'] == 'no_subscription'


# ---------------------------------------------------------------------------
# Customer Helper Tests
# ---------------------------------------------------------------------------

class TestGetCustomer:

    def test_returns_item(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            'Item': {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        }
        with patch.object(mod, 'customers_table', mock_table):
            result = mod._get_customer('auth0|u1')
            assert result['stripe_customer_id'] == 'cus_1'

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

    def test_returns_none_when_no_table(self, mod):
        with patch.object(mod, 'customers_table', None):
            assert mod._get_customer('auth0|u1') is None


class TestGetOrCreateCustomer:

    def test_returns_existing_customer(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        with patch.object(mod, '_get_customer', return_value=customer):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            assert result['stripe_customer_id'] == 'cus_1'

    def test_creates_new_stripe_customer(self, mod):
        existing = {'auth0_subject': 'auth0|u1', 'email': 'user@test.com'}
        mock_table = MagicMock()
        with patch.object(mod, '_get_customer', return_value=existing), \
             patch.object(mod, '_stripe_api', return_value={'id': 'cus_new'}), \
             patch.object(mod, 'customers_table', mock_table):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            assert result['stripe_customer_id'] == 'cus_new'
            mock_table.update_item.assert_called_once()
            # Verify conditional expression is used
            call_kwargs = mock_table.update_item.call_args[1]
            assert 'ConditionExpression' in call_kwargs

    def test_returns_none_on_stripe_failure(self, mod):
        with patch.object(mod, '_get_customer', return_value={}), \
             patch.object(mod, '_stripe_api', return_value=None):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            assert result is None

    def test_returns_customer_even_if_ddb_update_fails(self, mod):
        existing = {'auth0_subject': 'auth0|u1', 'email': 'user@test.com'}
        mock_table = MagicMock()
        cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
        mock_table.meta.client.exceptions.ConditionalCheckFailedException = cond_exc
        mock_table.update_item.side_effect = Exception("DDB error")
        with patch.object(mod, '_get_customer', return_value=existing), \
             patch.object(mod, '_stripe_api', return_value={'id': 'cus_new'}), \
             patch.object(mod, 'customers_table', mock_table):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            # Should still return the customer despite DDB failure
            assert result['stripe_customer_id'] == 'cus_new'

    def test_race_condition_returns_winner(self, mod):
        """When two requests race, the loser re-reads and returns the winner's Stripe ID."""
        existing_no_stripe = {'auth0_subject': 'auth0|u1', 'email': 'user@test.com'}
        winner_record = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_winner', 'email': 'user@test.com'}

        mock_table = MagicMock()
        # Simulate ConditionalCheckFailedException (another request won)
        cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
        mock_table.meta.client.exceptions.ConditionalCheckFailedException = cond_exc
        mock_table.update_item.side_effect = cond_exc("Condition not met")

        # First _get_customer returns no stripe ID, second returns the winner
        with patch.object(mod, '_get_customer', side_effect=[existing_no_stripe, winner_record]), \
             patch.object(mod, '_stripe_api', return_value={'id': 'cus_loser'}), \
             patch.object(mod, 'customers_table', mock_table):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            # Should return the winner's Stripe ID, not ours
            assert result['stripe_customer_id'] == 'cus_winner'

    def test_race_condition_fallback_on_reread_failure(self, mod):
        """If re-read after race also fails, return our own Stripe customer."""
        existing_no_stripe = {'auth0_subject': 'auth0|u1', 'email': 'user@test.com'}

        mock_table = MagicMock()
        cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
        mock_table.meta.client.exceptions.ConditionalCheckFailedException = cond_exc
        mock_table.update_item.side_effect = cond_exc("Condition not met")

        # First _get_customer returns no stripe ID, second also returns no stripe ID
        with patch.object(mod, '_get_customer', side_effect=[existing_no_stripe, None]), \
             patch.object(mod, '_stripe_api', return_value={'id': 'cus_ours'}), \
             patch.object(mod, 'customers_table', mock_table):
            result = mod._get_or_create_customer('auth0|u1', 'sk_test')
            # Fall through to return our ID
            assert result['stripe_customer_id'] == 'cus_ours'


# ---------------------------------------------------------------------------
# Stripe Key Tests
# ---------------------------------------------------------------------------

class TestGetStripeKey:

    def test_returns_cached_key(self, mod):
        import time
        with patch.object(mod, '_stripe_key', 'sk_cached'), \
             patch.object(mod, '_stripe_key_expires_at', time.time() + 300):
            assert mod._get_stripe_key() == 'sk_cached'

    def test_returns_none_on_error(self, mod):
        with patch.object(mod, '_stripe_key', None), \
             patch.object(mod, '_stripe_key_expires_at', 0), \
             patch('boto3.client') as mock_boto:
            mock_boto.return_value.get_secret_value.side_effect = Exception("SM error")
            result = mod._get_stripe_key()
            assert result is None


# ---------------------------------------------------------------------------
# CORS Tests
# ---------------------------------------------------------------------------

class TestCors:

    def test_allowed_origin_returned(self, mod):
        event = {'headers': {'origin': 'https://layerv.ai'}}
        assert mod.get_cors_origin(event) == 'https://layerv.ai'

    def test_unknown_origin_returns_default(self, mod):
        event = {'headers': {'origin': 'https://evil.com'}}
        origin = mod.get_cors_origin(event)
        assert origin != 'https://evil.com'
