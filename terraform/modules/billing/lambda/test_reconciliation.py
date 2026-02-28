"""
Tests for Billing Reconciliation Lambda.

Covers: usage comparison, discrepancy detection, auto-correction for <1%,
        CloudWatch metrics.

Run with: pytest terraform/modules/billing/lambda/test_reconciliation.py -v
"""

import json

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _import_module():
    import sys
    for mod in [k for k in sys.modules if k.startswith('reconciliation')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import reconciliation as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import reconciliation
    return reconciliation


# ---------------------------------------------------------------------------
# Handler Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:

    def test_no_table_returns_500(self, mod):
        with patch.object(mod, 'customers_table', None):
            resp = mod.lambda_handler({}, None)
            assert resp['statusCode'] == 500

    def test_no_growth_customers_returns_early(self, mod):
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[]), \
             patch.object(mod, '_emit_metric') as mock_metric:
            resp = mod.lambda_handler({}, None)
            assert resp['statusCode'] == 200
            mock_metric.assert_called_once_with('ReconciliationCustomersChecked', 0)

    def test_no_discrepancy(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 100,
            'current_period_start': 1700000000,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=100), \
             patch.object(mod, '_emit_metric') as mock_metric:
            resp = mod.lambda_handler({}, None)

            body = json.loads(resp['body'])
            assert body['discrepancies_found'] == 0

    def test_detects_discrepancy(self, mod):
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 100,
            'current_period_start': 1700000000,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=110), \
             patch.object(mod, '_emit_metric') as mock_metric, \
             patch.object(mod, '_auto_correct_usage') as mock_correct:
            resp = mod.lambda_handler({}, None)

            body = json.loads(resp['body'])
            assert body['discrepancies_found'] == 1


# ---------------------------------------------------------------------------
# Auto-Correction Tests
# ---------------------------------------------------------------------------

class TestAutoCorrection:

    def test_small_discrepancy_auto_corrected(self, mod):
        """<1% discrepancy should be auto-corrected."""
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 1000,
            'current_period_start': 1700000000,
        }
        # 1005 vs 1000 = 0.5% discrepancy
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=1005), \
             patch.object(mod, '_auto_correct_usage') as mock_correct, \
             patch.object(mod, '_emit_metric'):
            mod.lambda_handler({}, None)
            mock_correct.assert_called_once_with('auth0|u1', 1005)

    def test_large_discrepancy_not_auto_corrected(self, mod):
        """>=1% discrepancy should NOT be auto-corrected."""
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 100,
            'current_period_start': 1700000000,
        }
        # 110 vs 100 = 10% discrepancy
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=110), \
             patch.object(mod, '_auto_correct_usage') as mock_correct, \
             patch.object(mod, '_emit_metric'):
            mod.lambda_handler({}, None)
            mock_correct.assert_not_called()

    def test_auto_correct_updates_dynamodb(self, mod):
        mock_table = MagicMock()
        with patch.object(mod, 'customers_table', mock_table):
            mod._auto_correct_usage('auth0|u1', 42)
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['ExpressionAttributeValues'][':count'] == 42


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------

class TestReconciliationEdgeCases:

    def test_zero_usage_no_discrepancy(self, mod):
        """Zero reported and zero audit should not flag discrepancy."""
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 0,
            'current_period_start': 1700000000,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=0), \
             patch.object(mod, '_auto_correct_usage') as mock_correct, \
             patch.object(mod, '_emit_metric'):
            resp = mod.lambda_handler({}, None)
            body = json.loads(resp['body'])
            assert body['discrepancies_found'] == 0
            mock_correct.assert_not_called()

    def test_missing_period_start_skips_customer(self, mod):
        """Customer without current_period_start should be skipped."""
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 50,
            # No current_period_start
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries') as mock_count, \
             patch.object(mod, '_emit_metric'):
            resp = mod.lambda_handler({}, None)
            mock_count.assert_not_called()

    def test_string_usage_count_handled(self, mod):
        """DynamoDB may return numbers as Decimal; int() conversion should work."""
        from decimal import Decimal
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': Decimal('100'),
            'current_period_start': 1700000000,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=100), \
             patch.object(mod, '_emit_metric'):
            resp = mod.lambda_handler({}, None)
            body = json.loads(resp['body'])
            assert body['discrepancies_found'] == 0

    def test_audit_table_unavailable_skips_customer(self, mod):
        """If _count_audit_entries returns None, customer should be skipped."""
        customer = {
            'auth0_subject': 'auth0|u1',
            'current_period_usage': 50,
            'current_period_start': 1700000000,
        }
        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=[customer]), \
             patch.object(mod, '_count_audit_entries', return_value=None), \
             patch.object(mod, '_auto_correct_usage') as mock_correct, \
             patch.object(mod, '_emit_metric'):
            resp = mod.lambda_handler({}, None)
            body = json.loads(resp['body'])
            assert body['customers_checked'] == 0
            mock_correct.assert_not_called()

    def test_multiple_customers_mixed_results(self, mod):
        """Handler should process all customers independently."""
        customers = [
            {'auth0_subject': 'auth0|u1', 'current_period_usage': 100, 'current_period_start': 1700000000},
            {'auth0_subject': 'auth0|u2', 'current_period_usage': 200, 'current_period_start': 1700000000},
        ]

        def count_entries(auth0_sub, period_start):
            return 100 if auth0_sub == 'auth0|u1' else 250  # u2 has discrepancy

        with patch.object(mod, 'customers_table', MagicMock()), \
             patch.object(mod, '_get_growth_customers', return_value=customers), \
             patch.object(mod, '_count_audit_entries', side_effect=count_entries), \
             patch.object(mod, '_auto_correct_usage'), \
             patch.object(mod, '_emit_metric'):
            resp = mod.lambda_handler({}, None)
            body = json.loads(resp['body'])
            assert body['customers_checked'] == 2
            assert body['discrepancies_found'] == 1  # only u2
