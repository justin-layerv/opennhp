"""
Tests for the canary deployment orchestrator Lambda function.

Run with: python3 -m unittest discover -s terraform/modules/canary-deployment/lambda -p "test_*.py" -v
No external dependencies required (uses stdlib unittest.mock to mock boto3).
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

# Set environment variables before importing the module
os.environ.update({
    'ENVIRONMENT': 'test',
    'ASG_NAME': 'test-asg',
    'NLB_ARN_SUFFIX': 'net/test-nlb/abc123',
    'TARGET_GROUP_ARN_SUFFIX': 'targetgroup/test-tg/def456',
    'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-2:123456789012:test-alerts',
    'SSM_IMAGE_TAG_PARAM': '/test/nhp/server/image-tag',
    'SSM_CANARY_STATE_PARAM': '/test/nhp/cell0/canary/state',
    'SSM_CANARY_EXECUTION_ARN_PARAM': '/test/nhp/cell0/canary/execution-arn',
    'MAX_CPU_PERCENT': '90',
    'CHECKPOINT_PERCENTAGES': '[20, 50, 100]',
    'CHECKPOINT_DELAY': '300',
    'INSTANCE_WARMUP': '180',
})

# Create separate mock clients for each boto3 service
_mock_clients = {}


def _make_boto3_client(service_name):
    """Return a unique MagicMock per service name."""
    if service_name not in _mock_clients:
        _mock_clients[service_name] = MagicMock(name=f'boto3.client({service_name!r})')
    return _mock_clients[service_name]


# Mock boto3 and botocore before importing the orchestrator module
mock_boto3 = MagicMock()
mock_boto3.client.side_effect = _make_boto3_client

mock_botocore = MagicMock()
sys.modules['boto3'] = mock_boto3
sys.modules['botocore'] = mock_botocore
sys.modules['botocore.exceptions'] = mock_botocore.exceptions


# Create a real ClientError class for testing
class MockClientError(Exception):
    def __init__(self, error_response, operation_name):
        self.response = error_response
        self.operation_name = operation_name
        super().__init__(f"{operation_name}: {error_response}")


mock_botocore.exceptions.ClientError = MockClientError

# Now import the module - boto3.client() calls will create separate mocks per service
import canary_orchestrator


class CanaryTestCase(unittest.TestCase):
    """Base test class that provides fresh mocks for each test."""

    def setUp(self):
        # Replace module-level clients with fresh MagicMocks for complete isolation
        self.mock_autoscaling = MagicMock(name='autoscaling')
        self.mock_cloudwatch = MagicMock(name='cloudwatch')
        self.mock_ssm = MagicMock(name='ssm')
        self.mock_sns = MagicMock(name='sns')
        canary_orchestrator.autoscaling = self.mock_autoscaling
        canary_orchestrator.cloudwatch = self.mock_cloudwatch
        canary_orchestrator.ssm = self.mock_ssm
        canary_orchestrator.sns = self.mock_sns


class TestHandler(CanaryTestCase):
    """Test the main handler action routing."""

    def test_missing_action_returns_error(self):
        result = canary_orchestrator.handler({}, None)
        self.assertIn('error', result)
        self.assertIn('Missing required field: action', result['error'])

    def test_unknown_action_returns_error(self):
        result = canary_orchestrator.handler({'action': 'nonexistent'}, None)
        self.assertIn('error', result)
        self.assertIn('Unknown action', result['error'])

    def test_action_routing(self):
        """Verify all expected actions are routable."""
        expected_actions = [
            'prepare', 'start_refresh', 'check_refresh_status',
            'check_health', 'rollback', 'alarm_triggered_rollback',
            'notify', 'complete',
        ]
        for action in expected_actions:
            result = canary_orchestrator.handler({'action': action}, None)
            if 'error' in result:
                self.assertNotIn('Unknown action', result['error'],
                                 f"Action '{action}' not routed correctly")

    def test_exception_in_handler_returns_error_dict(self):
        self.mock_autoscaling.describe_auto_scaling_groups.side_effect = \
            Exception("Simulated failure")
        result = canary_orchestrator.handler({'action': 'prepare'}, None)
        self.assertIn('error', result)
        self.assertEqual(result['error_type'], 'Exception')
        self.assertIn('Simulated failure', result['error'])


class TestPrepare(CanaryTestCase):
    """Test the prepare action handler."""

    def test_prepare_success(self):
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'AutoScalingGroupName': 'test-asg'}]
        }
        self.mock_ssm.get_parameter.side_effect = [
            {'Parameter': {'Value': 'idle'}},
            {'Parameter': {'Value': 'sha-abc123'}},
        ]

        result = canary_orchestrator.handle_prepare({}, None)
        self.assertEqual(result['asg_name'], 'test-asg')
        self.assertEqual(result['current_image_tag'], 'sha-abc123')
        self.assertIn('deployment_id', result)

        self.mock_ssm.put_parameter.assert_called_once()
        call_args = self.mock_ssm.put_parameter.call_args
        self.assertEqual(call_args[1]['Value'], 'deploying')

    def test_prepare_blocks_concurrent_deployment(self):
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'AutoScalingGroupName': 'test-asg'}]
        }
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'deploying'}
        }

        with self.assertRaises(RuntimeError) as ctx:
            canary_orchestrator.handle_prepare({}, None)
        self.assertIn('Concurrent deployment blocked', str(ctx.exception))

    def test_prepare_asg_not_found(self):
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': []
        }

        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_prepare({}, None)
        self.assertIn('ASG not found', str(ctx.exception))


class TestStartRefresh(CanaryTestCase):
    """Test the start_refresh action handler."""

    def test_start_refresh_success(self):
        self.mock_autoscaling.start_instance_refresh.return_value = {
            'InstanceRefreshId': 'refresh-123'
        }

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')
        self.assertEqual(result['status'], 'Pending')

        call_args = self.mock_autoscaling.start_instance_refresh.call_args[1]
        self.assertEqual(call_args['Strategy'], 'Rolling')
        self.assertEqual(call_args['Preferences']['CheckpointPercentages'], [20, 50, 100])
        self.assertEqual(call_args['Preferences']['CheckpointDelay'], 300)
        self.assertEqual(call_args['Preferences']['InstanceWarmup'], 180)
        self.assertEqual(call_args['Preferences']['MinHealthyPercentage'], 90)

    def test_start_refresh_missing_image_tag(self):
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_start_refresh({}, None)
        self.assertIn('image_tag', str(ctx.exception))


class TestCheckRefreshStatus(CanaryTestCase):
    """Test the check_refresh_status action handler."""

    def test_in_progress_not_at_checkpoint(self):
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{
                'Status': 'InProgress',
                'StatusReason': 'Replacing instances',
                'PercentageComplete': 10,
                'InstancesToUpdate': 2,
            }]
        }
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 3}]
        }

        result = canary_orchestrator.handle_check_refresh_status(
            {'instance_refresh_id': 'refresh-123'}, None
        )
        self.assertEqual(result['status'], 'InProgress')
        self.assertFalse(result['at_checkpoint'])
        self.assertEqual(result['percentage_complete'], 10)

    def test_at_checkpoint_detected(self):
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{
                'Status': 'InProgress',
                'StatusReason': 'Waiting for CheckpointDelay of 300',
                'PercentageComplete': 20,
                'InstancesToUpdate': 2,
            }]
        }
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 3}]
        }

        result = canary_orchestrator.handle_check_refresh_status(
            {'instance_refresh_id': 'refresh-123'}, None
        )
        self.assertEqual(result['status'], 'InProgress')
        self.assertTrue(result['at_checkpoint'])

    def test_successful_status(self):
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{
                'Status': 'Successful',
                'StatusReason': '',
                'PercentageComplete': 100,
                'InstancesToUpdate': 0,
            }]
        }
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 3}]
        }

        result = canary_orchestrator.handle_check_refresh_status(
            {'instance_refresh_id': 'refresh-123'}, None
        )
        self.assertEqual(result['status'], 'Successful')
        self.assertFalse(result['at_checkpoint'])

    def test_missing_refresh_id(self):
        with self.assertRaises(ValueError):
            canary_orchestrator.handle_check_refresh_status({}, None)

    def test_refresh_not_found(self):
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': []
        }
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_check_refresh_status(
                {'instance_refresh_id': 'nonexistent'}, None
            )
        self.assertIn('not found', str(ctx.exception))


class TestCheckHealth(CanaryTestCase):
    """Test the check_health action handler."""

    def test_healthy_deployment(self):
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [3.0]},
                {'Id': 'unhealthy_hosts', 'Values': [0.0]},
                {'Id': 'cpu_utilization', 'Values': [45.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertTrue(result['healthy'])
        self.assertEqual(result['details']['healthy_hosts'], 3.0)
        self.assertEqual(result['details']['unhealthy_hosts'], 0.0)
        self.assertEqual(result['details']['avg_cpu'], 45.0)

    def test_unhealthy_hosts_detected(self):
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [2.0]},
                {'Id': 'unhealthy_hosts', 'Values': [1.0]},
                {'Id': 'cpu_utilization', 'Values': [50.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])

    def test_high_cpu_detected(self):
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [3.0]},
                {'Id': 'unhealthy_hosts', 'Values': [0.0]},
                {'Id': 'cpu_utilization', 'Values': [95.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])

    def test_no_healthy_hosts(self):
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [0.0]},
                {'Id': 'unhealthy_hosts', 'Values': [0.0]},
                {'Id': 'cpu_utilization', 'Values': [10.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])

    def test_missing_metrics_with_healthy_hosts(self):
        """When only healthy hosts data exists, should be healthy."""
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [3.0]},
                {'Id': 'unhealthy_hosts', 'Values': []},
                {'Id': 'cpu_utilization', 'Values': []},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertTrue(result['healthy'])

    def test_no_metric_data_at_all(self):
        """When no metrics are available, should be unhealthy (no healthy hosts)."""
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': []},
                {'Id': 'unhealthy_hosts', 'Values': []},
                {'Id': 'cpu_utilization', 'Values': []},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])


class TestRollback(CanaryTestCase):
    """Test the rollback action handler."""

    def test_rollback_success(self):
        result = canary_orchestrator.handle_rollback({}, None)
        self.assertEqual(result['status'], 'rolling_back')
        self.mock_autoscaling.rollback_instance_refresh.assert_called_once()
        self.mock_ssm.put_parameter.assert_called_once()

    def test_rollback_no_active_refresh(self):
        self.mock_autoscaling.rollback_instance_refresh.side_effect = \
            MockClientError(
                {'Error': {'Code': 'ActiveInstanceRefreshNotFound', 'Message': 'No active refresh'}},
                'RollbackInstanceRefresh'
            )

        result = canary_orchestrator.handle_rollback({}, None)
        self.assertEqual(result['status'], 'no_active_refresh')
        self.mock_ssm.put_parameter.assert_not_called()


class TestAlarmTriggeredRollback(CanaryTestCase):
    """Test the alarm_triggered_rollback action handler."""

    def test_alarm_rollback_when_deploying(self):
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'deploying'}
        }

        result = canary_orchestrator.handle_alarm_triggered_rollback({}, None)
        self.assertTrue(result['action_taken'])
        self.mock_autoscaling.rollback_instance_refresh.assert_called_once()

    def test_alarm_rollback_skipped_when_idle(self):
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'idle'}
        }

        result = canary_orchestrator.handle_alarm_triggered_rollback({}, None)
        self.assertFalse(result['action_taken'])
        self.mock_autoscaling.rollback_instance_refresh.assert_not_called()

    def test_alarm_rollback_skipped_when_already_rolling_back(self):
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'rolling_back'}
        }

        result = canary_orchestrator.handle_alarm_triggered_rollback({}, None)
        self.assertFalse(result['action_taken'])
        self.mock_autoscaling.rollback_instance_refresh.assert_not_called()

    def test_alarm_rollback_no_active_refresh_resets_state(self):
        """When deploying but no active refresh exists, reset state to idle."""
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'deploying'}
        }
        self.mock_autoscaling.rollback_instance_refresh.side_effect = \
            MockClientError(
                {'Error': {'Code': 'ActiveInstanceRefreshNotFound', 'Message': 'No active refresh'}},
                'RollbackInstanceRefresh'
            )

        result = canary_orchestrator.handle_alarm_triggered_rollback({}, None)
        self.assertFalse(result['action_taken'])
        # Verify state reset to idle when no active refresh found
        self.mock_ssm.put_parameter.assert_called_once()
        put_args = self.mock_ssm.put_parameter.call_args[1]
        self.assertEqual(put_args['Value'], 'idle')


class TestNotify(CanaryTestCase):
    """Test the notify action handler."""

    def test_notify_publishes_to_sns(self):
        result = canary_orchestrator.handle_notify(
            {'status': 'success', 'message': 'Deployed', 'image_tag': 'sha-abc'},
            None
        )
        self.assertTrue(result['notified'])
        self.mock_sns.publish.assert_called_once()

        call_args = self.mock_sns.publish.call_args[1]
        self.assertIn('[test] Canary Deploy: success', call_args['Subject'])
        message_body = json.loads(call_args['Message'])
        self.assertEqual(message_body['environment'], 'test')
        self.assertEqual(message_body['status'], 'success')
        self.assertEqual(message_body['image_tag'], 'sha-abc')

    def test_notify_truncates_long_subject(self):
        long_status = 'x' * 200
        canary_orchestrator.handle_notify(
            {'status': long_status}, None
        )
        call_args = self.mock_sns.publish.call_args[1]
        self.assertLessEqual(len(call_args['Subject']), 100)


class TestComplete(CanaryTestCase):
    """Test the complete action handler."""

    def test_complete_resets_state(self):
        result = canary_orchestrator.handle_complete({}, None)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('timestamp', result)

        calls = self.mock_ssm.put_parameter.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]['Value'], 'idle')
        self.assertEqual(calls[1][1]['Value'], 'none')


class TestHelpers(CanaryTestCase):
    """Test helper functions."""

    def test_get_ssm_value_success(self):
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'test-value'}
        }
        result = canary_orchestrator.get_ssm_value('/test/param')
        self.assertEqual(result, 'test-value')

    def test_get_ssm_value_not_found(self):
        self.mock_ssm.get_parameter.side_effect = MockClientError(
            {'Error': {'Code': 'ParameterNotFound', 'Message': 'Not found'}},
            'GetParameter'
        )
        result = canary_orchestrator.get_ssm_value('/test/param')
        self.assertIsNone(result)

    def test_set_ssm_value(self):
        canary_orchestrator.set_ssm_value('/test/param', 'new-value')
        self.mock_ssm.put_parameter.assert_called_once_with(
            Name='/test/param',
            Value='new-value',
            Type='String',
            Overwrite=True,
        )


if __name__ == '__main__':
    unittest.main()
