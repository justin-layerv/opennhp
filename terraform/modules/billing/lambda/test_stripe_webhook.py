"""
Tests for Stripe Webhook Lambda.

Covers: signature verification, event routing, DynamoDB updates, SNS publishing.

Run with: pytest terraform/modules/billing/lambda/test_stripe_webhook.py -v
"""

import hashlib
import hmac as hmac_mod
import json
import time

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Module import with mocked AWS
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _import_module():
    """Import stripe_webhook with mocked AWS clients."""
    import sys
    for mod in [k for k in sys.modules if k.startswith('stripe_webhook')]:
        del sys.modules[mod]
    with patch('boto3.resource'), patch('boto3.client'):
        import importlib
        import stripe_webhook as _mod
        importlib.reload(_mod)


@pytest.fixture
def mod():
    import stripe_webhook
    return stripe_webhook


# ---------------------------------------------------------------------------
# Signature Verification Tests
# ---------------------------------------------------------------------------

class TestVerifyStripeSignature:
    """Tests for _verify_stripe_signature()."""

    def _make_sig(self, payload, secret, timestamp=None):
        ts = timestamp or str(int(time.time()))
        signed = f"{ts}.{payload}"
        sig = hmac_mod.new(
            secret.encode(), signed.encode(), hashlib.sha256
        ).hexdigest()
        return f"t={ts},v1={sig}"

    def test_valid_signature(self, mod):
        secret = "whsec_test123"
        payload = '{"type":"checkout.session.completed"}'
        sig_header = self._make_sig(payload, secret)
        assert mod._verify_stripe_signature(payload, sig_header, secret) is True

    def test_invalid_signature(self, mod):
        secret = "whsec_test123"
        payload = '{"type":"checkout.session.completed"}'
        sig_header = "t=12345,v1=invalidsig"
        assert mod._verify_stripe_signature(payload, sig_header, secret) is False

    def test_missing_timestamp(self, mod):
        assert mod._verify_stripe_signature("body", "v1=abc", "secret") is False

    def test_missing_v1(self, mod):
        assert mod._verify_stripe_signature("body", "t=12345", "secret") is False

    def test_empty_header(self, mod):
        assert mod._verify_stripe_signature("body", "", "secret") is False

    def test_expired_timestamp(self, mod):
        secret = "whsec_test123"
        payload = "body"
        old_ts = str(int(time.time()) - 600)  # 10 minutes ago
        sig_header = self._make_sig(payload, secret, timestamp=old_ts)
        assert mod._verify_stripe_signature(payload, sig_header, secret) is False

    def test_multiple_v1_signatures(self, mod):
        secret = "whsec_test123"
        payload = "body"
        ts = str(int(time.time()))
        signed = f"{ts}.{payload}"
        valid_sig = hmac_mod.new(
            secret.encode(), signed.encode(), hashlib.sha256
        ).hexdigest()
        sig_header = f"t={ts},v1=badsig1,v1={valid_sig}"
        assert mod._verify_stripe_signature(payload, sig_header, secret) is True

    def test_tampered_payload(self, mod):
        secret = "whsec_test123"
        original = '{"amount":100}'
        tampered = '{"amount":999}'
        sig_header = self._make_sig(original, secret)
        assert mod._verify_stripe_signature(tampered, sig_header, secret) is False


# ---------------------------------------------------------------------------
# Event Handler Tests
# ---------------------------------------------------------------------------

class TestHandleCheckoutCompleted:
    """Tests for _handle_checkout_completed()."""

    def test_updates_customer_tier(self, mod):
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|user1'), \
             patch.object(mod, '_get_stripe_key_for_api', return_value=None), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()

            session = {
                'customer': 'cus_123',
                'subscription': 'sub_456',
                'metadata': {},
            }
            mod._handle_checkout_completed(session)

            mock_table.update_item.assert_called_once()
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['Key'] == {'auth0_subject': 'auth0|user1'}
            assert ':tier' in call_kwargs['ExpressionAttributeValues']
            assert call_kwargs['ExpressionAttributeValues'][':tier'] == 'growth'

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'tier_upgraded'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item

    def test_uses_metadata_auth0_sub(self, mod):
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id') as mock_find, \
             patch.object(mod, '_get_stripe_key_for_api', return_value=None), \
             patch.object(mod, 'audit_table', MagicMock()):
            mock_table.update_item = MagicMock()

            session = {
                'customer': 'cus_123',
                'subscription': 'sub_456',
                'metadata': {'auth0_subject': 'auth0|direct'},
            }
            mod._handle_checkout_completed(session)

            mock_find.assert_not_called()
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['Key'] == {'auth0_subject': 'auth0|direct'}

    def test_missing_customer_id_returns_early(self, mod):
        with patch.object(mod, 'customers_table') as mock_table:
            mock_table.update_item = MagicMock()
            mod._handle_checkout_completed({'customer': '', 'subscription': ''})
            mock_table.update_item.assert_not_called()


class TestHandleSubscriptionDeleted:
    """Tests for _handle_subscription_deleted()."""

    def test_downgrades_to_free(self, mod):
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_subscription_deleted({'customer': 'cus_1'})

            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['ExpressionAttributeValues'][':tier'] == 'free'
            assert 'REMOVE stripe_subscription_id' in call_kwargs['UpdateExpression']

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'tier_downgraded'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item

    def test_customer_not_found_skips(self, mod):
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value=None):
            mock_table.update_item = MagicMock()
            mod._handle_subscription_deleted({'customer': 'cus_unknown'})
            mock_table.update_item.assert_not_called()


class TestHandlePaymentFailed:
    """Tests for _handle_payment_failed()."""

    def test_sets_grace_deadline(self, mod):
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_payment_failed({'customer': 'cus_1'})

            call_kwargs = mock_table.update_item.call_args[1]
            assert ':deadline' in call_kwargs['ExpressionAttributeValues']
            assert 'payment_grace_deadline' in call_kwargs['UpdateExpression']

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'grace_started'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item


class TestHandlePaymentSucceeded:
    """Tests for _handle_payment_succeeded()."""

    def test_clears_frozen_state(self, mod):
        mock_audit = MagicMock()
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_payment_succeeded({'customer': 'cus_1'})

            call_kwargs = mock_table.update_item.call_args[1]
            assert 'REMOVE payment_grace_deadline, frozen, frozen_reason' in call_kwargs['UpdateExpression']

            # Verify audit write
            mock_audit.put_item.assert_called_once()
            audit_item = mock_audit.put_item.call_args[1]['Item']
            assert audit_item['event_type'] == 'grace_cleared'
            assert 'timestamp' in audit_item
            assert 'ttl' in audit_item


# ---------------------------------------------------------------------------
# Customer Lookup Tests
# ---------------------------------------------------------------------------

class TestFindAuth0SubByStripeId:
    """Tests for _find_auth0_sub_by_stripe_id() using GSI query."""

    def test_found_via_gsi_query(self, mod):
        mock_table = MagicMock()
        mock_table.query.return_value = {
            'Items': [{'auth0_subject': 'auth0|u1'}],
        }
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._find_auth0_sub_by_stripe_id('cus_1') == 'auth0|u1'
            mock_table.query.assert_called_once()
            call_kwargs = mock_table.query.call_args[1]
            assert call_kwargs['IndexName'] == 'stripe-customer-id-index'
            assert call_kwargs['Limit'] == 1

    def test_not_found_returns_none(self, mod):
        mock_table = MagicMock()
        mock_table.query.return_value = {'Items': []}
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._find_auth0_sub_by_stripe_id('cus_missing') is None

    def test_returns_none_for_empty_id(self, mod):
        with patch.object(mod, 'customers_table', MagicMock()):
            assert mod._find_auth0_sub_by_stripe_id('') is None

    def test_returns_none_when_no_table(self, mod):
        with patch.object(mod, 'customers_table', None):
            assert mod._find_auth0_sub_by_stripe_id('cus_1') is None

    def test_query_error_returns_none(self, mod):
        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DDB error")
        with patch.object(mod, 'customers_table', mock_table):
            assert mod._find_auth0_sub_by_stripe_id('cus_1') is None


# ---------------------------------------------------------------------------
# Audit Write Resilience Tests
# ---------------------------------------------------------------------------

class TestAuditWriteResilience:
    """Verify billing operations succeed even when audit writes fail."""

    def test_checkout_succeeds_when_audit_fails(self, mod):
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, '_get_stripe_key_for_api', return_value=None), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            session = {
                'customer': 'cus_1',
                'subscription': 'sub_1',
                'metadata': {},
            }
            # Should not raise despite audit failure
            mod._handle_checkout_completed(session)
            mock_table.update_item.assert_called_once()

    def test_payment_failed_succeeds_when_audit_fails(self, mod):
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_payment_failed({'customer': 'cus_1'})
            mock_table.update_item.assert_called_once()

    def test_subscription_deleted_succeeds_when_audit_fails(self, mod):
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_subscription_deleted({'customer': 'cus_1'})
            mock_table.update_item.assert_called_once()

    def test_payment_succeeded_succeeds_when_audit_fails(self, mod):
        mock_audit = MagicMock()
        mock_audit.put_item.side_effect = Exception("DDB throttle")
        with patch.object(mod, 'customers_table') as mock_table, \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|u1'), \
             patch.object(mod, 'audit_table', mock_audit):
            mock_table.update_item = MagicMock()
            mod._handle_payment_succeeded({'customer': 'cus_1'})
            mock_table.update_item.assert_called_once()


# ---------------------------------------------------------------------------
# SNS Publishing Tests
# ---------------------------------------------------------------------------

class TestPublishCustomerUpdated:
    """Tests for _publish_customer_updated()."""

    def test_publishes_when_sns_configured(self, mod):
        mock_sns = MagicMock()
        with patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            mod._publish_customer_updated('checkout.session.completed', {'customer': 'cus_1'}, 'auth0|test1')
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            assert call_kwargs['Subject'] == 'customer.updated'
            msg = json.loads(call_kwargs['Message'])
            assert msg['auth0_subject'] == 'auth0|test1'

    def test_skips_when_no_sns(self, mod):
        with patch.object(mod, 'sns', None), \
             patch.object(mod, 'SNS_TOPIC_ARN', ''):
            # Should not raise
            mod._publish_customer_updated('checkout.session.completed', {'customer': 'cus_1'}, 'auth0|test1')


# ---------------------------------------------------------------------------
# Lambda Handler Integration Tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    """Tests for the main lambda_handler()."""

    def test_options_returns_cors(self, mod):
        event = {
            'requestContext': {'http': {'method': 'OPTIONS'}},
            'headers': {'origin': 'https://layerv.ai'},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in resp['headers']

    def test_non_post_rejected(self, mod):
        event = {
            'requestContext': {'http': {'method': 'GET'}},
            'headers': {},
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 405

    def test_missing_signature_rejected(self, mod):
        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {},
            'body': '{}',
        }
        resp = mod.lambda_handler(event, None)
        assert resp['statusCode'] == 400

    def test_valid_webhook_returns_200(self, mod):
        secret = "whsec_test"
        payload = json.dumps({'type': 'unknown.event', 'id': 'evt_1', 'data': {'object': {}}})
        ts = str(int(time.time()))
        signed = f"{ts}.{payload}"
        sig = hmac_mod.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()

        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'stripe-signature': f't={ts},v1={sig}'},
            'body': payload,
        }

        with patch.object(mod, '_get_webhook_secret', return_value=secret):
            resp = mod.lambda_handler(event, None)
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert body['received'] is True


# ---------------------------------------------------------------------------
# Idempotency Tests
# ---------------------------------------------------------------------------

class TestClaimEvent:
    """Tests for atomic event claiming (idempotency via _claim_event)."""

    def _make_dedup_mock(self, *, raise_conditional=False, raise_error=None):
        """Create a mock dedup table with configurable put_item behavior."""
        mock_dedup = MagicMock()
        # Set up ConditionalCheckFailedException as a real exception class
        cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
        mock_dedup.meta.client.exceptions.ConditionalCheckFailedException = cond_exc
        if raise_conditional:
            mock_dedup.put_item.side_effect = cond_exc("Already exists")
        elif raise_error:
            mock_dedup.put_item.side_effect = raise_error
        return mock_dedup

    def test_new_event_claims_successfully(self, mod):
        mock_dedup = self._make_dedup_mock()
        with patch.object(mod, 'dedup_table', mock_dedup):
            assert mod._claim_event('evt_new1', 'invoice.paid') is True
            mock_dedup.put_item.assert_called_once()
            item = mock_dedup.put_item.call_args[1]['Item']
            assert item['event_id'] == 'evt_new1'
            assert item['event_type'] == 'invoice.paid'
            assert 'ttl' in item
            assert mock_dedup.put_item.call_args[1]['ConditionExpression'] == 'attribute_not_exists(event_id)'

    def test_duplicate_event_returns_false(self, mod):
        mock_dedup = self._make_dedup_mock(raise_conditional=True)
        with patch.object(mod, 'dedup_table', mock_dedup):
            assert mod._claim_event('evt_dup1', 'invoice.paid') is False

    def test_no_dedup_table_returns_true(self, mod):
        with patch.object(mod, 'dedup_table', None):
            assert mod._claim_event('evt_any', 'invoice.paid') is True

    def test_empty_event_id_returns_true(self, mod):
        mock_dedup = self._make_dedup_mock()
        with patch.object(mod, 'dedup_table', mock_dedup):
            assert mod._claim_event('', 'invoice.paid') is True
            mock_dedup.put_item.assert_not_called()

    def test_ddb_error_fails_open(self, mod):
        mock_dedup = self._make_dedup_mock(raise_error=Exception("DDB error"))
        with patch.object(mod, 'dedup_table', mock_dedup):
            assert mod._claim_event('evt_err', 'invoice.paid') is True

    def test_duplicate_event_handler_returns_200_with_flag(self, mod):
        """Full handler path: duplicate event → 200 with duplicate flag."""
        secret = "whsec_test"
        payload = json.dumps({'type': 'invoice.paid', 'id': 'evt_dup1', 'data': {'object': {'customer': 'cus_1'}}})
        ts = str(int(time.time()))
        signed = f"{ts}.{payload}"
        sig = hmac_mod.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()

        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'stripe-signature': f't={ts},v1={sig}'},
            'body': payload,
        }

        mock_dedup = self._make_dedup_mock(raise_conditional=True)

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', mock_dedup):
            resp = mod.lambda_handler(event, None)
            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert body.get('duplicate') is True


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for webhook handler error responses."""

    def test_handler_error_returns_500(self, mod):
        """Handler errors should return 500 so Stripe retries."""
        secret = "whsec_test"
        payload = json.dumps({
            'type': 'checkout.session.completed',
            'id': 'evt_fail1',
            'data': {'object': {'customer': 'cus_1', 'subscription': 'sub_1', 'metadata': {}}},
        })
        ts = str(int(time.time()))
        signed = f"{ts}.{payload}"
        sig = hmac_mod.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()

        event = {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'stripe-signature': f't={ts},v1={sig}'},
            'body': payload,
        }

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', None), \
             patch.object(mod, '_handle_checkout_completed', side_effect=Exception("DB error")):
            resp = mod.lambda_handler(event, None)
            assert resp['statusCode'] == 500
            body = json.loads(resp['body'])
            assert body['error'] == 'handler_error'

    def test_stripe_api_get_http_error(self, mod):
        """Stripe API GET returns None on HTTP errors."""
        import urllib.error
        with patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError(
            'https://api.stripe.com/v1/test', 429, 'Too Many Requests',
            {}, None
        )):
            result = mod._stripe_api_get('/v1/test', 'sk_test_123')
            assert result is None

    def test_stripe_api_get_timeout(self, mod):
        """Stripe API GET returns None on timeout."""
        import socket
        with patch('urllib.request.urlopen', side_effect=socket.timeout("timed out")):
            result = mod._stripe_api_get('/v1/test', 'sk_test_123')
            assert result is None

    def test_stripe_api_get_connection_refused(self, mod):
        """Stripe API GET returns None on connection refused."""
        with patch('urllib.request.urlopen', side_effect=ConnectionError("Connection refused")):
            result = mod._stripe_api_get('/v1/test', 'sk_test_123')
            assert result is None

    def test_stripe_api_get_invalid_json(self, mod):
        """Stripe API GET returns None on malformed JSON response."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'not json'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch('urllib.request.urlopen', return_value=mock_resp):
            result = mod._stripe_api_get('/v1/test', 'sk_test_123')
            assert result is None

    def test_stripe_api_get_success(self, mod):
        """Stripe API GET returns parsed JSON on success."""
        expected = {'id': 'sub_123', 'status': 'active'}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(expected).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch('urllib.request.urlopen', return_value=mock_resp):
            result = mod._stripe_api_get('/v1/subscriptions/sub_123', 'sk_test_123')
            assert result == expected

    def test_stripe_api_get_uses_base_url(self, mod):
        """Stripe API GET uses STRIPE_API_BASE_URL from env."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.object(mod, 'STRIPE_API_BASE_URL', 'https://mock.stripe.test'), \
             patch('urllib.request.urlopen', return_value=mock_resp) as mock_open:
            mod._stripe_api_get('/v1/test', 'sk_test_123')
            req = mock_open.call_args[0][0]
            assert req.full_url.startswith('https://mock.stripe.test/')

    def test_stripe_api_get_unexpected_schema(self, mod):
        """Stripe API GET handles unexpected response schema gracefully."""
        # Response is valid JSON but missing expected fields
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({'unexpected': True}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch('urllib.request.urlopen', return_value=mock_resp):
            result = mod._stripe_api_get('/v1/subscriptions/sub_123', 'sk_test_123')
            # Should return the parsed dict without error — caller handles missing fields
            assert result == {'unexpected': True}


# ---------------------------------------------------------------------------
# Grace Period Configuration Tests
# ---------------------------------------------------------------------------

class TestGracePeriodConfig:
    """Tests for configurable grace period."""

    def test_grace_period_from_env(self, mod):
        """GRACE_PERIOD_DAYS should be readable from module."""
        assert isinstance(mod.GRACE_PERIOD_DAYS, int)
        assert mod.GRACE_PERIOD_DAYS > 0


# ---------------------------------------------------------------------------
# Customer Updated SNS Tests
# ---------------------------------------------------------------------------

class TestPublishCustomerUpdatedFix:
    """Tests for _publish_customer_updated customer ID extraction."""

    def test_uses_top_level_customer_field(self, mod):
        """Should use top-level 'customer' field, not metadata fallback."""
        mock_sns = MagicMock()
        with patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            mod._publish_customer_updated('invoice.paid', {
                'customer': 'cus_correct',
                'metadata': {'customer': 'cus_wrong'},
            }, 'auth0|paid_user')
            call_kwargs = mock_sns.publish.call_args[1]
            msg = json.loads(call_kwargs['Message'])
            assert msg['stripe_customer_id'] == 'cus_correct'
            assert msg['auth0_subject'] == 'auth0|paid_user'

    def test_empty_customer_still_publishes(self, mod):
        """Should still publish even if customer field is empty."""
        mock_sns = MagicMock()
        with patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'), \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value=None):
            mod._publish_customer_updated('checkout.session.completed', {})
            mock_sns.publish.assert_called_once()
            call_kwargs = mock_sns.publish.call_args[1]
            msg = json.loads(call_kwargs['Message'])
            assert msg['stripe_customer_id'] == ''
            assert msg['auth0_subject'] == ''


# ---------------------------------------------------------------------------
# CORS Tests
# ---------------------------------------------------------------------------

class TestCors:
    """Tests for CORS helpers."""

    def test_allowed_origin_returned(self, mod):
        event = {'headers': {'origin': 'https://layerv.ai'}}
        assert mod.get_cors_origin(event) == 'https://layerv.ai'

    def test_unknown_origin_returns_default(self, mod):
        event = {'headers': {'origin': 'https://evil.com'}}
        origin = mod.get_cors_origin(event)
        assert origin != 'https://evil.com'


# ---------------------------------------------------------------------------
# Integration Tests: Webhook → DynamoDB → SNS
# ---------------------------------------------------------------------------

class TestWebhookIntegration:
    """End-to-end tests verifying the full webhook processing chain:
    valid signature → handler processes event → DynamoDB updated → SNS published.
    """

    def _make_webhook_event(self, payload, secret):
        ts = str(int(time.time()))
        signed = f"{ts}.{payload}"
        sig = hmac_mod.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
        return {
            'requestContext': {'http': {'method': 'POST'}},
            'headers': {'stripe-signature': f't={ts},v1={sig}'},
            'body': payload,
        }

    def test_checkout_completed_full_chain(self, mod):
        """checkout.session.completed → DDB update (tier=growth) → SNS publish."""
        secret = "whsec_integration"
        payload = json.dumps({
            'type': 'checkout.session.completed',
            'id': 'evt_integ_checkout',
            'data': {'object': {
                'customer': 'cus_integ1',
                'subscription': 'sub_integ1',
                'metadata': {'auth0_subject': 'auth0|integ1'},
            }},
        })
        event = self._make_webhook_event(payload, secret)

        mock_table = MagicMock()
        mock_sns = MagicMock()

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', None), \
             patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_get_stripe_key_for_api', return_value=None), \
             patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            resp = mod.lambda_handler(event, None)

            # Verify 200 response
            assert resp['statusCode'] == 200

            # Verify DynamoDB was updated with growth tier
            mock_table.update_item.assert_called_once()
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['Key'] == {'auth0_subject': 'auth0|integ1'}
            assert call_kwargs['ExpressionAttributeValues'][':tier'] == 'growth'
            assert call_kwargs['ExpressionAttributeValues'][':cid'] == 'cus_integ1'

            # Verify SNS was published
            mock_sns.publish.assert_called_once()
            sns_kwargs = mock_sns.publish.call_args[1]
            msg = json.loads(sns_kwargs['Message'])
            assert msg['event_type'] == 'checkout.session.completed'
            assert msg['stripe_customer_id'] == 'cus_integ1'
            assert msg['auth0_subject'] == 'auth0|integ1'

    def test_payment_failed_full_chain(self, mod):
        """invoice.payment_failed → DDB update (grace deadline) → SNS publish."""
        secret = "whsec_integration"
        payload = json.dumps({
            'type': 'invoice.payment_failed',
            'id': 'evt_integ_fail',
            'data': {'object': {'customer': 'cus_integ2'}},
        })
        event = self._make_webhook_event(payload, secret)

        mock_table = MagicMock()
        mock_sns = MagicMock()

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', None), \
             patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|integ2'), \
             patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            resp = mod.lambda_handler(event, None)

            assert resp['statusCode'] == 200

            # Verify grace deadline was set
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['Key'] == {'auth0_subject': 'auth0|integ2'}
            assert ':deadline' in call_kwargs['ExpressionAttributeValues']

            # Verify SNS notification
            mock_sns.publish.assert_called_once()

    def test_payment_succeeded_full_chain(self, mod):
        """invoice.paid → DDB update (clear frozen) → SNS publish."""
        secret = "whsec_integration"
        payload = json.dumps({
            'type': 'invoice.paid',
            'id': 'evt_integ_paid',
            'data': {'object': {'customer': 'cus_integ3'}},
        })
        event = self._make_webhook_event(payload, secret)

        mock_table = MagicMock()
        mock_sns = MagicMock()

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', None), \
             patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|integ3'), \
             patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            resp = mod.lambda_handler(event, None)

            assert resp['statusCode'] == 200

            # Verify frozen state cleared
            call_kwargs = mock_table.update_item.call_args[1]
            assert 'REMOVE payment_grace_deadline, frozen, frozen_reason' in call_kwargs['UpdateExpression']

            # Verify SNS notification
            mock_sns.publish.assert_called_once()

    def test_subscription_deleted_full_chain(self, mod):
        """customer.subscription.deleted → DDB downgrade → SNS publish."""
        secret = "whsec_integration"
        payload = json.dumps({
            'type': 'customer.subscription.deleted',
            'id': 'evt_integ_unsub',
            'data': {'object': {'customer': 'cus_integ4'}},
        })
        event = self._make_webhook_event(payload, secret)

        mock_table = MagicMock()
        mock_sns = MagicMock()

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', None), \
             patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, '_find_auth0_sub_by_stripe_id', return_value='auth0|integ4'), \
             patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            resp = mod.lambda_handler(event, None)

            assert resp['statusCode'] == 200

            # Verify downgraded to free
            call_kwargs = mock_table.update_item.call_args[1]
            assert call_kwargs['ExpressionAttributeValues'][':tier'] == 'free'

            # Verify SNS notification
            mock_sns.publish.assert_called_once()

    def test_dedup_prevents_duplicate_processing(self, mod):
        """Duplicate event ID → 200 with duplicate flag, no DDB/SNS calls."""
        secret = "whsec_integration"
        payload = json.dumps({
            'type': 'checkout.session.completed',
            'id': 'evt_integ_dup',
            'data': {'object': {
                'customer': 'cus_dup',
                'subscription': 'sub_dup',
                'metadata': {'auth0_subject': 'auth0|dup'},
            }},
        })
        event = self._make_webhook_event(payload, secret)

        mock_table = MagicMock()
        mock_sns = MagicMock()
        mock_dedup = MagicMock()
        # Simulate atomic claim failure (event already claimed by another invocation)
        cond_exc = type('ConditionalCheckFailedException', (Exception,), {})
        mock_dedup.meta.client.exceptions.ConditionalCheckFailedException = cond_exc
        mock_dedup.put_item.side_effect = cond_exc("Already exists")

        with patch.object(mod, '_get_webhook_secret', return_value=secret), \
             patch.object(mod, 'dedup_table', mock_dedup), \
             patch.object(mod, 'customers_table', mock_table), \
             patch.object(mod, 'sns', mock_sns), \
             patch.object(mod, 'SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123:topic'):
            resp = mod.lambda_handler(event, None)

            assert resp['statusCode'] == 200
            body = json.loads(resp['body'])
            assert body.get('duplicate') is True

            # Verify NO DDB or SNS calls were made
            mock_table.update_item.assert_not_called()
            mock_sns.publish.assert_not_called()
