"""
Tests for Invoices Lambda.

Covers: JWT auth extraction, invoice listing, Stripe API interaction,
        query parameter parsing, CORS.

Run with: pytest terraform/modules/billing/lambda/test_invoices.py -v
"""

import json

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _import_module():
    import sys
    for mod in [k for k in sys.modules if k.startswith('invoices')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import invoices as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import invoices
    return invoices


# ---------------------------------------------------------------------------
# Handler Routing Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:

    def test_options_returns_cors(self, mod):
        event = {
            'requestContext': {'http': {'method': 'OPTIONS'}},
            'headers': {'origin': 'https://layerv.ai'},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in resp['headers']

    def test_missing_auth_returns_401(self, mod):
        event = {
            'requestContext': {'http': {'method': 'GET'}},
            'headers': {},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 401
        body = json.loads(resp['body'])
        assert body['error']['code'] == 'unauthorized'

    def test_non_get_returns_405(self, mod):
        event = {
            'requestContext': {
                'http': {'method': 'POST'},
                'authorizer': {'jwt': {'claims': {'sub': 'auth0|u1'}}},
            },
            'headers': {},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 405


# ---------------------------------------------------------------------------
# Invoice Listing Tests
# ---------------------------------------------------------------------------

class TestHandleListInvoices:

    def test_no_customer_returns_empty_list(self, mod):
        with patch.object(mod, '_get_customer', return_value=None):
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': None,
            }
            resp = mod.handle_list_invoices(event, 'auth0|u1')
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert body['data']['invoices'] == []
            assert body['data']['has_more'] is False

    def test_no_stripe_id_returns_empty_list(self, mod):
        with patch.object(mod, '_get_customer', return_value={'auth0_subject': 'auth0|u1'}):
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': None,
            }
            resp = mod.handle_list_invoices(event, 'auth0|u1')
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert body['data']['invoices'] == []

    def test_returns_transformed_invoices(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        stripe_response = {
            'data': [{
                'id': 'in_1',
                'number': 'INV-001',
                'status': 'paid',
                'amount_due': 1000,
                'amount_paid': 1000,
                'currency': 'usd',
                'period_start': 1700000000,
                'period_end': 1702592000,
                'created': 1700000000,
                'hosted_invoice_url': 'https://invoice.stripe.com/i/in_1',
                'invoice_pdf': 'https://invoice.stripe.com/pdf/in_1',
            }],
            'has_more': False,
        }
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api_get', return_value=stripe_response):
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': None,
            }
            resp = mod.handle_list_invoices(event, 'auth0|u1')
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            invoices = body['data']['invoices']
            assert len(invoices) == 1
            assert invoices[0]['id'] == 'in_1'
            assert invoices[0]['amount_paid'] == 1000
            assert invoices[0]['invoice_pdf'] == 'https://invoice.stripe.com/pdf/in_1'

    def test_stripe_api_failure_returns_500(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api_get', return_value=None):
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': None,
            }
            resp = mod.handle_list_invoices(event, 'auth0|u1')
            assert resp['statusCode'] == 500

    def test_limit_from_query_params(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api_get', return_value={'data': [], 'has_more': False}) as mock_api:
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': {'limit': '25'},
            }
            mod.handle_list_invoices(event, 'auth0|u1')
            call_args = mock_api.call_args[0][0]
            assert 'limit=25' in call_args

    def test_limit_capped_at_max(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api_get', return_value={'data': [], 'has_more': False}) as mock_api:
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': {'limit': '500'},
            }
            mod.handle_list_invoices(event, 'auth0|u1')
            call_args = mock_api.call_args[0][0]
            assert 'limit=100' in call_args

    def test_invalid_limit_uses_default(self, mod):
        customer = {'auth0_subject': 'auth0|u1', 'stripe_customer_id': 'cus_1'}
        with patch.object(mod, '_get_customer', return_value=customer), \
             patch.object(mod, '_get_stripe_key', return_value='sk_test'), \
             patch.object(mod, '_stripe_api_get', return_value={'data': [], 'has_more': False}) as mock_api:
            event = {
                'requestContext': {'http': {'method': 'GET'}},
                'headers': {},
                'queryStringParameters': {'limit': 'abc'},
            }
            mod.handle_list_invoices(event, 'auth0|u1')
            call_args = mock_api.call_args[0][0]
            assert 'limit=10' in call_args


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

    def test_returns_none_when_no_table(self, mod):
        with patch.object(mod, 'customers_table', None):
            assert mod._get_customer('auth0|u1') is None

    def test_returns_none_on_error(self, mod):
        mock_table = MagicMock()
        mock_table.get_item.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._get_customer('auth0|u1') is None


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

    def test_response_has_correct_methods(self, mod):
        event = {'headers': {}}
        resp = mod.cors_response(event, 200, {'test': True})
        assert resp['headers']['Access-Control-Allow-Methods'] == 'GET, OPTIONS'
