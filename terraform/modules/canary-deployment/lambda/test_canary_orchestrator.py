"""
Tests for the canary deployment orchestrator Lambda function.

Run with: python3 -m unittest discover -s terraform/modules/canary-deployment/lambda -p "test_*.py" -v
No external dependencies required (uses stdlib unittest.mock to mock boto3).
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

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
    'INSTANCE_WARMUP': '60',
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

    def test_missing_action_raises(self):
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handler({}, None)
        self.assertIn('Missing required field: action', str(ctx.exception))

    def test_unknown_action_raises(self):
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handler({'action': 'nonexistent'}, None)
        self.assertIn('Unknown action', str(ctx.exception))

    def test_action_routing(self):
        """Verify all expected actions have handler functions."""
        expected_actions = [
            'prepare', 'start_refresh', 'check_refresh_status',
            'check_health', 'rollback', 'alarm_triggered_rollback',
            'notify', 'complete',
        ]
        for action in expected_actions:
            handler_fn = getattr(canary_orchestrator, f'handle_{action}', None)
            self.assertIsNotNone(handler_fn, f"No handler for action '{action}'")

    def test_exception_in_handler_re_raises(self):
        self.mock_autoscaling.describe_auto_scaling_groups.side_effect = \
            Exception("Simulated failure")
        with self.assertRaises(Exception) as ctx:
            canary_orchestrator.handler({'action': 'prepare'}, None)
        self.assertIn('Simulated failure', str(ctx.exception))


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
        self.assertTrue(call_args[1]['Value'].startswith('deploying:'))

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

    def test_prepare_fails_fast_on_inconsistent_nlb_wiring(self):
        """Regression fence for cr#2 round 12: handle_prepare must
        cross-check the NLB-mode env vars BEFORE the SFN starts
        replacing instances. A misconfig that bypasses the TF
        precondition (manual env edit, drift) should surface here, not
        at the first checkpoint health check after instances have
        already been replaced.
        """
        # NLB_HEALTH_CHECKS_DISABLED=True but suffixes populated → mismatch.
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_prepare({}, None)
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))
            # describe_auto_scaling_groups should NOT have been called —
            # the consistency check fires before the ASG validate.
            self.mock_autoscaling.describe_auto_scaling_groups.assert_not_called()


class TestStartRefresh(CanaryTestCase):
    """Test the start_refresh action handler."""

    def _setup_asg_mock(self):
        """Common ASG mock setup for start_refresh tests."""
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{
                'AutoScalingGroupName': 'test-asg',
                'LaunchTemplate': {
                    'LaunchTemplateId': 'lt-abc123',
                    'Version': '3',
                }
            }]
        }
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': []
        }
        self.mock_autoscaling.start_instance_refresh.return_value = {
            'InstanceRefreshId': 'refresh-123'
        }

    def test_start_refresh_success(self):
        self._setup_asg_mock()

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')
        self.assertEqual(result['status'], 'Pending')

        call_args = self.mock_autoscaling.start_instance_refresh.call_args[1]
        self.assertEqual(call_args['Strategy'], 'Rolling')
        self.assertEqual(call_args['Preferences']['CheckpointPercentages'], [20, 50, 100])
        self.assertEqual(call_args['Preferences']['CheckpointDelay'], 300)
        self.assertEqual(call_args['Preferences']['InstanceWarmup'], 60)
        self.assertEqual(call_args['Preferences']['MinHealthyPercentage'], 90)
        self.assertEqual(
            call_args['DesiredConfiguration']['LaunchTemplate']['LaunchTemplateId'],
            'lt-abc123'
        )
        self.assertEqual(
            call_args['DesiredConfiguration']['LaunchTemplate']['Version'],
            '3'
        )

    def test_start_refresh_missing_image_tag(self):
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_start_refresh({}, None)
        self.assertIn('image_tag', str(ctx.exception))

    def test_start_refresh_asg_not_found(self):
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': []
        }
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_start_refresh(
                {'image_tag': 'sha-abc123'}, None
            )
        self.assertIn('ASG not found', str(ctx.exception))

    def test_start_refresh_no_launch_template(self):
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{
                'AutoScalingGroupName': 'test-asg',
            }]
        }
        with self.assertRaises(ValueError) as ctx:
            canary_orchestrator.handle_start_refresh(
                {'image_tag': 'sha-abc123'}, None
            )
        self.assertIn('no launch template', str(ctx.exception))

    @patch('canary_orchestrator.time.sleep')
    def test_start_refresh_cancels_existing_inprogress(self, mock_sleep):
        self._setup_asg_mock()
        self.mock_autoscaling.describe_instance_refreshes.side_effect = [
            # Initial check: existing InProgress refresh
            {'InstanceRefreshes': [{'InstanceRefreshId': 'old-123', 'Status': 'InProgress'}]},
            # First poll after cancel: now Cancelled
            {'InstanceRefreshes': [{'InstanceRefreshId': 'old-123', 'Status': 'Cancelled'}]},
        ]

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')
        self.mock_autoscaling.cancel_instance_refresh.assert_called_once_with(
            AutoScalingGroupName='test-asg'
        )
        mock_sleep.assert_called_with(5)

    @patch('canary_orchestrator.time.sleep')
    def test_start_refresh_cancels_existing_pending(self, mock_sleep):
        self._setup_asg_mock()
        self.mock_autoscaling.describe_instance_refreshes.side_effect = [
            {'InstanceRefreshes': [{'InstanceRefreshId': 'old-456', 'Status': 'Pending'}]},
            {'InstanceRefreshes': [{'InstanceRefreshId': 'old-456', 'Status': 'Cancelled'}]},
        ]

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')
        self.mock_autoscaling.cancel_instance_refresh.assert_called_once()

    def test_start_refresh_rollback_in_progress_raises(self):
        self._setup_asg_mock()
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{'InstanceRefreshId': 'rb-789', 'Status': 'RollbackInProgress'}]
        }

        with self.assertRaises(RuntimeError) as ctx:
            canary_orchestrator.handle_start_refresh(
                {'image_tag': 'sha-abc123'}, None
            )
        self.assertIn('rolling back', str(ctx.exception))
        self.assertIn('rb-789', str(ctx.exception))
        self.mock_autoscaling.cancel_instance_refresh.assert_not_called()
        self.mock_autoscaling.start_instance_refresh.assert_not_called()

    def test_start_refresh_cancel_already_completed(self):
        self._setup_asg_mock()
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{'InstanceRefreshId': 'old-999', 'Status': 'InProgress'}]
        }
        # Make the exception a real class so the except clause catches it
        exc_class = type('ActiveInstanceRefreshNotFoundFault', (Exception,), {})
        self.mock_autoscaling.exceptions.ActiveInstanceRefreshNotFoundFault = exc_class
        self.mock_autoscaling.cancel_instance_refresh.side_effect = exc_class()

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')

    def test_start_refresh_describe_client_error_continues(self):
        self._setup_asg_mock()
        self.mock_autoscaling.describe_instance_refreshes.side_effect = MockClientError(
            {'Error': {'Code': 'InternalFailure', 'Message': 'oops'}},
            'DescribeInstanceRefreshes'
        )

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-abc123'}, None
        )
        # Should still proceed to start a new refresh
        self.assertEqual(result['instance_refresh_id'], 'refresh-123')
        self.mock_autoscaling.cancel_instance_refresh.assert_not_called()

    def test_start_refresh_fails_fast_on_inconsistent_nlb_wiring(self):
        """Regression fence: handle_start_refresh must cross-check the
        NLB-mode env vars BEFORE calling StartInstanceRefresh.

        Mirrors test_prepare_fails_fast_on_inconsistent_nlb_wiring for
        the start-refresh action — a same-axis env edit that slips
        between handle_prepare and the SFN's start-refresh task should
        surface here, not at the first checkpoint health check after
        instances have already been replaced.
        """
        self._setup_asg_mock()
        # NLB_HEALTH_CHECKS_DISABLED=True but suffixes populated → mismatch.
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_start_refresh(
                    {'image_tag': 'sha-abc123'}, None
                )
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))
            # start_instance_refresh and cancel_instance_refresh must NOT
            # have been called — the consistency check fires before any
            # mutation against the ASG.
            self.mock_autoscaling.start_instance_refresh.assert_not_called()
            self.mock_autoscaling.cancel_instance_refresh.assert_not_called()


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


class TestCheckHealthNLBDisabled(CanaryTestCase):
    """Test the check_health action handler in NLB-disabled (frps) mode.

    Frps has no NLB; canary-deployment is wired for it via
    `disable_nlb_health_checks = true` and the orchestrator skips the
    NLB metric queries, falling back to ASG-instance health
    (GroupInServiceInstances vs GroupTotalInstances). The
    `nlb_disabled` flag in `result['details']` lets a downstream
    state-machine assertion distinguish the two regimes.
    """

    def setUp(self):
        super().setUp()
        # Patch the module-level constants to simulate the Terraform
        # `disable_nlb_health_checks = true` path: empty NLB/TG suffixes
        # AND the explicit NLB_HEALTH_CHECKS_DISABLED toggle set to True.
        # The Lambda's defensive cross-check enforces these agree.
        self._nlb_patcher = patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', '')
        self._tg_patcher = patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', '')
        self._nlb_disabled_patcher = patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True)
        self._nlb_patcher.start()
        self._tg_patcher.start()
        self._nlb_disabled_patcher.start()
        # Default ASG describe response — handle_check_health on the
        # NLB-disabled path now reads DesiredCapacity to scale the
        # has_healthy threshold against MinHealthyPercentage. Individual
        # tests can override.
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 6}]
        }

    def tearDown(self):
        self._nlb_disabled_patcher.stop()
        self._tg_patcher.stop()
        self._nlb_patcher.stop()
        super().tearDown()

    def test_healthy_asg_path(self):
        """All ASG instances in service: healthy."""
        # Note: in NLB-disabled mode, the orchestrator queries
        # GroupInServiceInstances (Id='healthy_hosts') and
        # GroupTotalInstances (Id='unhealthy_hosts'), then computes
        # implicit_unhealthy = total - in_service.
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [6.0]},   # GroupInServiceInstances
                {'Id': 'unhealthy_hosts', 'Values': [6.0]}, # GroupTotalInstances
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertTrue(result['healthy'])
        self.assertTrue(result['details']['nlb_disabled'])
        self.assertEqual(result['details']['healthy_hosts'], 6.0)
        # implicit unhealthy = total (6) - in-service (6) = 0
        self.assertEqual(result['details']['unhealthy_hosts'], 0)
        self.assertEqual(result['details']['total_instances'], 6.0)

    def test_unhealthy_asg_path(self):
        """One ASG instance failing health check: unhealthy."""
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [5.0]},   # GroupInServiceInstances
                {'Id': 'unhealthy_hosts', 'Values': [6.0]}, # GroupTotalInstances
                {'Id': 'cpu_utilization', 'Values': [50.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        # implicit unhealthy = total (6) - in-service (5) = 1
        self.assertEqual(result['details']['unhealthy_hosts'], 1)

    def test_min_healthy_threshold_below_floor(self):
        """ASG path: healthy_hosts below MinHealthyPercentage threshold
        is unhealthy, even with no unhealthy hosts.

        Regression fence: pre-fix the threshold was `healthy_hosts > 0`,
        which let a 1-instance survival in a 6-instance fleet (PR 4
        target: 2/AZ × 3 AZ = 6) advance the canary into an
        ~83% blast radius. Post-fix the threshold scales with
        DesiredCapacity × MinHealthyPercentage (90%, matching what
        StartInstanceRefresh.Preferences enforces).
        """
        # Default mock has DesiredCapacity = 6 → ceil(6*0.9) = 6.
        # Only 1 in-service host out of 6 → fails threshold.
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [1.0]},     # only 1 in-service
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},   # 6 total → 5 implicit-unhealthy
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }
        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        self.assertEqual(result['details']['min_healthy_count'], 6)
        self.assertEqual(result['details']['asg_desired'], 6)

    def test_min_healthy_threshold_at_floor(self):
        """ASG path: healthy_hosts exactly at the threshold is healthy."""
        # 6-instance fleet, 6 in-service → exactly meets ceil(6*0.9)=6.
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [6.0]},
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }
        result = canary_orchestrator.handle_check_health({}, None)
        self.assertTrue(result['healthy'])
        self.assertEqual(result['details']['min_healthy_count'], 6)

    def test_metric_query_shape(self):
        """NLB-disabled mode passes ASG-namespace queries, not NLB."""
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [],
        }

        canary_orchestrator.handle_check_health({}, None)
        self.mock_cloudwatch.get_metric_data.assert_called_once()
        call_args = self.mock_cloudwatch.get_metric_data.call_args
        queries = call_args.kwargs['MetricDataQueries']
        # No NLB-namespace queries. Sanity-check by namespace.
        namespaces = {q['MetricStat']['Metric']['Namespace'] for q in queries}
        self.assertNotIn('AWS/NetworkELB', namespaces)
        self.assertIn('AWS/AutoScaling', namespaces)
        self.assertIn('AWS/EC2', namespaces)

    def test_partial_data_race_total_only(self):
        """GroupTotalInstances published, GroupInServiceInstances not yet
        — must NOT report every host unhealthy.

        Regression fence: pre-fix, this case set
        `unhealthy_hosts = total` (raw), so `no_unhealthy = False` and
        the canary rolled back spuriously on a fresh ASG where
        in-service metric hadn't published yet.
        """
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': []},        # GroupInServiceInstances missing
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},   # GroupTotalInstances present
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        # has_healthy=False (no in-service metric) → healthy=False, but
        # NOT because of the bogus implicit-unhealthy = total.
        # Surface that distinction via the details dict so a downstream
        # alarm can tell "no data yet" from "real instance failure".
        self.assertFalse(result['healthy'])
        self.assertIsNone(result['details']['unhealthy_hosts'])
        self.assertIsNone(result['details']['healthy_hosts'])
        # `total_instances` is still preserved for telemetry.
        self.assertEqual(result['details']['total_instances'], 6.0)

    def test_partial_data_race_in_service_only(self):
        """GroupInServiceInstances published, GroupTotalInstances not yet
        — handler must not crash subtracting None from a number, and
        the canary should ADVANCE on the partial signal.

        Posture rationale: `GroupInServiceInstances` is the load-bearing
        metric on the ASG path (it's how the lambda concludes "yes, N
        hosts are passing health checks"). `GroupTotalInstances` is
        only used to compute the implicit-unhealthy delta; without it,
        we don't know if there are any unhealthy hosts but we DO know
        the healthy hosts count. The existing health logic treats
        `unhealthy_hosts is None` as `no_unhealthy=True` (no evidence
        of unhealthy hosts), so the canary advances when the in-service
        count meets the MinHealthyPercentage threshold. The alternative
        — wait for both metrics — would penalize fresh ASGs whose
        Total publish-cycle lags InService by one period, stalling
        legitimate deploys behind a missing-metric race.

        The opposite race (Total present, InService missing) keeps
        `healthy=False` via `has_healthy=False`, biasing toward
        "rollback on no in-service evidence" — see
        `test_partial_data_race_total_only`.
        """
        # Override default DesiredCapacity (6) to match this scenario:
        # 3-instance fleet, 3 in-service → meets MinHealthyPercentage=90% threshold.
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 3}]
        }
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [3.0]},     # GroupInServiceInstances present
                {'Id': 'unhealthy_hosts', 'Values': []},      # GroupTotalInstances missing
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }

        # Should not raise. unhealthy_hosts stays None (no conversion possible).
        result = canary_orchestrator.handle_check_health({}, None)
        self.assertIsNone(result['details']['unhealthy_hosts'])
        # healthy_hosts (3) >= ceil(3 * 0.9) = 3 → has_healthy=True;
        # no_unhealthy=True (None) and CPU is fine → healthy=True.
        # The canary advances on the available signal rather than
        # rolling back on missing data.
        self.assertTrue(result['healthy'])
        self.assertEqual(result['details']['healthy_hosts'], 3.0)

    def test_no_metric_data_at_all(self):
        """Cold-start: neither GroupInServiceInstances nor
        GroupTotalInstances has published yet.

        The NLB-enabled path has the same test (test_no_metric_data_at_all
        in TestCheckHealth); this case pins the same behavior for the
        NLB-disabled path so a future refactor can't regress it. The
        canary should report `healthy=False` because `has_healthy=False`
        (no in-service hosts) — better to roll back on no-data than to
        advance on partial signal.
        """
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': []},
                {'Id': 'unhealthy_hosts', 'Values': []},
                {'Id': 'cpu_utilization', 'Values': []},
            ]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        self.assertIsNone(result['details']['healthy_hosts'])
        self.assertIsNone(result['details']['unhealthy_hosts'])

    def test_asg_describe_failure_fails_closed(self):
        """ASG describe failure on the NLB-disabled path returns
        `healthy=False` instead of falling back to the legacy
        `min_healthy_count = 1` floor.

        Regression fence for the cr-flagged silent fallback: a
        transient `DescribeAutoScalingGroups` throttle during the blast
        radius window of a bad deploy used to log a warning and let
        `min_healthy_count` fall back to 1 — the exact "any healthy"
        floor the percentage gate was added to replace. The fail-closed
        path now returns `healthy=False` so the SFN retries on the next
        poll and the alarm-driven rollback path engages on sustained
        failure.
        """
        # Healthy metrics — would advance under the old fallback path.
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [6.0]},
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }
        # ASG describe throttles.
        self.mock_autoscaling.describe_auto_scaling_groups.side_effect = (
            MockClientError(
                {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}},
                'DescribeAutoScalingGroups',
            )
        )

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        self.assertTrue(result['details']['asg_describe_failed'])
        self.assertIsNone(result['details']['asg_desired'])
        self.assertIsNone(result['details']['min_healthy_count'])

    def test_asg_describe_anomalous_shape_fails_closed(self):
        """describe_auto_scaling_groups returns an empty list on the
        NLB-disabled path → fail closed.

        Regression fence for cr round 22 #2: the legacy fallback to
        `min_healthy_count = 1` would silently drop the safety
        threshold on the path with no NLB safety net. AWS-side
        anomalies (empty AutoScalingGroups list, missing
        DesiredCapacity) should fail closed for the same reason the
        ClientError path does.
        """
        # Healthy metrics — would advance under the old fallback path.
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [6.0]},
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }
        # Anomalous shape: empty AutoScalingGroups list.
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': []
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        self.assertTrue(result['details']['asg_describe_anomalous_shape'])
        self.assertIsNone(result['details']['asg_desired'])
        self.assertIsNone(result['details']['min_healthy_count'])

    def test_asg_describe_missing_desired_capacity_fails_closed(self):
        """describe_auto_scaling_groups returns a member without
        DesiredCapacity on the NLB-disabled path → fail closed.

        Companion fence to test_asg_describe_anomalous_shape_fails_closed
        — covers the other "AWS-side anomaly" shape: the response has
        a group dict but no DesiredCapacity key. Same fail-closed
        posture: better to roll back than to silently advance on
        "any healthy".
        """
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [6.0]},
                {'Id': 'unhealthy_hosts', 'Values': [6.0]},
                {'Id': 'cpu_utilization', 'Values': [40.0]},
            ]
        }
        # Anomalous shape: group present but DesiredCapacity missing.
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'AutoScalingGroupName': 'test-asg'}]
        }

        result = canary_orchestrator.handle_check_health({}, None)
        self.assertFalse(result['healthy'])
        self.assertTrue(result['details']['asg_describe_anomalous_shape'])
        self.assertIsNone(result['details']['asg_desired'])
        self.assertIsNone(result['details']['min_healthy_count'])


class TestCheckHealthInconsistentNLBWiring(CanaryTestCase):
    """Defense-in-depth: the Lambda cross-checks the explicit
    `NLB_HEALTH_CHECKS_DISABLED` env var against whether the
    NLB/TG ARN suffixes are empty. The Terraform precondition
    (`terraform_data.component_invariants` in modules/canary-
    deployment/main.tf) normally enforces they agree at plan time;
    the runtime check is a backstop for manual env-var edits or
    drift.
    """

    def test_disabled_flag_set_but_suffixes_present_raises(self):
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_check_health({}, None)
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))

    def test_disabled_flag_unset_but_suffixes_empty_raises(self):
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', False), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', ''), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', ''):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_check_health({}, None)
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))

    def test_half_mix_disabled_with_one_suffix_present_raises(self):
        """Half-mix: disabled=true with NLB suffix populated but TG empty.

        The runtime uses AND-empty (BOTH suffixes must be empty under
        disabled=true) — matching the TF precondition. An OR-empty
        rule would ACCEPT this state because at-least-one-empty=True,
        which would leave a window where TF rejects what the Lambda
        accepts.
        """
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', ''):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_check_health({}, None)
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))

    def test_half_mix_enabled_with_one_suffix_empty_raises(self):
        """Half-mix: disabled=false with TG suffix populated but NLB empty.

        Same window as the disabled-side half-mix above, but on the
        NLB-enabled regime. The TF precondition's non-disabled branch
        already required BOTH non-empty (`!= "" && != ""`); the
        runtime now matches.
        """
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', False), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', ''), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            with self.assertRaises(RuntimeError) as ctx:
                canary_orchestrator.handle_check_health({}, None)
            self.assertIn('Inconsistent NLB-mode wiring', str(ctx.exception))


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

    def test_manual_rollback_skips_consistency_check(self):
        """handle_rollback DOES NOT call `_check_nlb_mode_consistency`.

        Recovery-path posture, parallel to
        test_alarm_rollback_skips_consistency_check. If NLB-mode wiring
        drifts mid-deploy, gating manual rollback on the same drift
        would leave the fleet stuck mid-replace. The other three
        handlers (`handle_prepare`, `handle_start_refresh`,
        `handle_check_health`) gate on the consistency check because
        they advance deploy state; this one only undoes it.

        Regression fence for cr round 22 #3.
        """
        # Inconsistent NLB-mode wiring: would block prepare / start /
        # check_health, but must NOT block manual rollback.
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            result = canary_orchestrator.handle_rollback({}, None)
        self.assertEqual(result['status'], 'rolling_back')
        self.mock_autoscaling.rollback_instance_refresh.assert_called_once()


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

    def test_alarm_rollback_skips_consistency_check(self):
        """handle_alarm_triggered_rollback DOES NOT call
        `_check_nlb_mode_consistency`.

        This is the recovery path. If NLB-mode wiring drifts mid-deploy,
        gating rollback on the same drift would leave the fleet stuck
        mid-replace. The other three handlers (`handle_prepare`,
        `handle_start_refresh`, `handle_check_health`) DO gate on the
        consistency check because they advance deploy state; this one
        only undoes it.

        Regression fence: test that an alarm-triggered rollback proceeds
        even when the NLB env vars are inconsistent (suffixes set but
        flag says disabled). A future refactor that adds the check here
        would fail this test.
        """
        self.mock_ssm.get_parameter.return_value = {
            'Parameter': {'Value': 'deploying'}
        }
        # Inconsistent NLB-mode wiring: would block prepare / start /
        # check_health, but must NOT block alarm rollback.
        with patch.object(canary_orchestrator, 'NLB_HEALTH_CHECKS_DISABLED', True), \
             patch.object(canary_orchestrator, 'NLB_ARN_SUFFIX', 'net/foo/abc'), \
             patch.object(canary_orchestrator, 'TARGET_GROUP_ARN_SUFFIX', 'targetgroup/foo/def'):
            result = canary_orchestrator.handle_alarm_triggered_rollback({}, None)
        self.assertTrue(result['action_taken'])
        self.mock_autoscaling.rollback_instance_refresh.assert_called_once()


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


class TestAsgNamePropagation(CanaryTestCase):
    """Test that handlers use the event-provided asg_name over the env var default."""

    CUSTOM_ASG = 'custom-ac-asg'

    def test_start_refresh_uses_event_asg_name(self):
        """handle_start_refresh targets the ASG from the event, not the env var."""
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{
                'AutoScalingGroupName': self.CUSTOM_ASG,
                'LaunchTemplate': {
                    'LaunchTemplateId': 'lt-ac123',
                    'Version': '2',
                }
            }]
        }
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': []
        }
        self.mock_autoscaling.start_instance_refresh.return_value = {
            'InstanceRefreshId': 'refresh-ac-001'
        }

        result = canary_orchestrator.handle_start_refresh(
            {'image_tag': 'sha-ac', 'asg_name': self.CUSTOM_ASG}, None
        )

        self.assertEqual(result['instance_refresh_id'], 'refresh-ac-001')
        # Verify the custom ASG was used in API calls
        self.mock_autoscaling.describe_auto_scaling_groups.assert_called_with(
            AutoScalingGroupNames=[self.CUSTOM_ASG]
        )
        call_args = self.mock_autoscaling.start_instance_refresh.call_args[1]
        self.assertEqual(call_args['AutoScalingGroupName'], self.CUSTOM_ASG)

    def test_check_refresh_status_uses_event_asg_name(self):
        """handle_check_refresh_status targets the ASG from the event."""
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{
                'InstanceRefreshId': 'refresh-ac-001',
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
            {'instance_refresh_id': 'refresh-ac-001', 'asg_name': self.CUSTOM_ASG}, None
        )

        self.assertEqual(result['status'], 'Successful')
        self.mock_autoscaling.describe_instance_refreshes.assert_called_with(
            AutoScalingGroupName=self.CUSTOM_ASG,
            InstanceRefreshIds=['refresh-ac-001'],
        )

    def test_check_health_uses_event_asg_name(self):
        """handle_check_health uses event asg_name for CPU metric dimension."""
        self.mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'healthy_hosts', 'Values': [3.0]},
                {'Id': 'unhealthy_hosts', 'Values': [0.0]},
                {'Id': 'cpu_utilization', 'Values': [10.0]},
            ]
        }

        canary_orchestrator.handle_check_health(
            {'asg_name': self.CUSTOM_ASG}, None
        )

        # Verify the CPU metric query uses the custom ASG name
        call_args = self.mock_cloudwatch.get_metric_data.call_args[1]
        cpu_query = [q for q in call_args['MetricDataQueries']
                     if q['Id'] == 'cpu_utilization'][0]
        asg_dim = [d for d in cpu_query['MetricStat']['Metric']['Dimensions']
                   if d['Name'] == 'AutoScalingGroupName'][0]
        self.assertEqual(asg_dim['Value'], self.CUSTOM_ASG)

    def test_rollback_uses_event_asg_name(self):
        """handle_rollback targets the ASG from the event."""
        canary_orchestrator.handle_rollback(
            {'asg_name': self.CUSTOM_ASG}, None
        )

        self.mock_autoscaling.rollback_instance_refresh.assert_called_with(
            AutoScalingGroupName=self.CUSTOM_ASG
        )

    def test_handlers_fall_back_to_env_var_when_no_event_asg(self):
        """Without asg_name in event, handlers use the ASG_NAME env var."""
        self.mock_autoscaling.describe_instance_refreshes.return_value = {
            'InstanceRefreshes': [{
                'InstanceRefreshId': 'refresh-001',
                'Status': 'Successful',
                'StatusReason': '',
                'PercentageComplete': 100,
                'InstancesToUpdate': 0,
            }]
        }
        self.mock_autoscaling.describe_auto_scaling_groups.return_value = {
            'AutoScalingGroups': [{'DesiredCapacity': 3}]
        }

        canary_orchestrator.handle_check_refresh_status(
            {'instance_refresh_id': 'refresh-001'}, None
        )

        # Should use the default ASG_NAME from env var ('test-asg')
        self.mock_autoscaling.describe_instance_refreshes.assert_called_with(
            AutoScalingGroupName='test-asg',
            InstanceRefreshIds=['refresh-001'],
        )


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
