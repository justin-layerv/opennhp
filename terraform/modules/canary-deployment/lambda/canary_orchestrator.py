"""
NHP Canary Deployment Orchestrator Lambda

This Lambda function handles canary deployment orchestration for NHP Server ASGs.
It is invoked by Step Functions with action-based routing to manage the lifecycle
of a rolling instance refresh with checkpoint-based health validation.

Actions:
- prepare: Validate ASG and set deployment state
- start_refresh: Begin ASG instance refresh with checkpoints
- check_refresh_status: Poll instance refresh progress
- check_health: Validate health via CloudWatch metrics
- rollback: Manually trigger rollback
- alarm_triggered_rollback: EventBridge entry point for alarm-driven rollback
- notify: Send deployment notifications via SNS
- complete: Finalize deployment and reset state
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'unknown')
ASG_NAME = os.environ.get('ASG_NAME', '')
NLB_ARN_SUFFIX = os.environ.get('NLB_ARN_SUFFIX', '')
TARGET_GROUP_ARN_SUFFIX = os.environ.get('TARGET_GROUP_ARN_SUFFIX', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SSM_IMAGE_TAG_PARAM = os.environ.get('SSM_IMAGE_TAG_PARAM', '')
SSM_CANARY_STATE_PARAM = os.environ.get('SSM_CANARY_STATE_PARAM', '')
SSM_CANARY_EXECUTION_ARN_PARAM = os.environ.get('SSM_CANARY_EXECUTION_ARN_PARAM', '')
MAX_CPU_PERCENT = float(os.environ.get('MAX_CPU_PERCENT', '80'))
CHECKPOINT_PERCENTAGES = json.loads(os.environ.get('CHECKPOINT_PERCENTAGES', '[20, 50, 100]'))
INSTANCE_WARMUP = int(os.environ.get('INSTANCE_WARMUP', '180'))
CHECKPOINT_DELAY = int(os.environ.get('CHECKPOINT_DELAY', '300'))

# Initialize clients
autoscaling = boto3.client('autoscaling')
cloudwatch = boto3.client('cloudwatch')
ssm = boto3.client('ssm')
sns = boto3.client('sns')


def handler(event, context):
    """
    Lambda handler with action-based routing.

    Event structure:
    {
        "action": "prepare|start_refresh|check_refresh_status|check_health|rollback|...",
        ...action-specific fields...
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")

    action = event.get('action')
    if not action:
        raise ValueError('Missing required field: action')

    actions = {
        'prepare': handle_prepare,
        'start_refresh': handle_start_refresh,
        'check_refresh_status': handle_check_refresh_status,
        'check_health': handle_check_health,
        'rollback': handle_rollback,
        'alarm_triggered_rollback': handle_alarm_triggered_rollback,
        'notify': handle_notify,
        'complete': handle_complete,
    }

    action_handler = actions.get(action)
    if not action_handler:
        raise ValueError(f'Unknown action: {action}')

    try:
        return action_handler(event, context)
    except Exception as e:
        logger.error(f"Error handling action '{action}': {str(e)}", exc_info=True)
        # Re-raise so Lambda returns a FunctionError response.
        # Step Functions Catch blocks only activate on task failures,
        # not on successful responses containing error dicts.
        raise


def handle_prepare(event, _context):
    """Validate ASG exists and set deployment state to prevent concurrent deploys."""
    logger.info(f"Preparing canary deployment for ASG: {ASG_NAME}")

    # Validate ASG exists
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[ASG_NAME]
    )
    groups = response.get('AutoScalingGroups', [])
    if not groups:
        raise ValueError(f"ASG not found: {ASG_NAME}")

    # Check current canary state to prevent concurrent deployments.
    # Note: This is a best-effort check (TOCTOU race between read and write).
    # The GitHub Actions concurrency group is the primary lock; this is defense-in-depth.
    # Manual Step Functions executions could theoretically race, but this is acceptable
    # since StartInstanceRefresh rejects concurrent refreshes on the same ASG.
    current_state = get_ssm_value(SSM_CANARY_STATE_PARAM)
    if current_state and current_state.startswith('deploying'):
        raise RuntimeError(
            f"Concurrent deployment blocked: canary state is '{current_state}'. "
            f"If a previous deployment is stuck, manually set {SSM_CANARY_STATE_PARAM} to 'idle'."
        )

    # Read current image tag
    current_image_tag = get_ssm_value(SSM_IMAGE_TAG_PARAM)

    # Set canary state to deploying with timestamp for stale lock detection.
    # Format: "deploying:<ISO timestamp>" — parsed by canary-deploy.yml validate step
    # to auto-reset stale locks from crashed deployments.
    deployment_id = str(uuid.uuid4())[:8]
    deploy_timestamp = datetime.now(timezone.utc).isoformat()
    set_ssm_value(SSM_CANARY_STATE_PARAM, f'deploying:{deploy_timestamp}')

    logger.info(f"Deployment {deployment_id} prepared: current_image_tag={current_image_tag}")

    return {
        'asg_name': ASG_NAME,
        'current_image_tag': current_image_tag,
        'deployment_id': deployment_id,
    }


def handle_start_refresh(event, _context):
    """Start an ASG instance refresh with checkpoint percentages."""
    image_tag = event.get('image_tag')
    if not image_tag:
        raise ValueError("Missing required field: image_tag")

    logger.info(f"Starting instance refresh for ASG {ASG_NAME} with image_tag={image_tag}")

    # Look up the ASG's current launch template to pass as DesiredConfiguration.
    # Without DesiredConfiguration, AWS rejects RollbackInstanceRefresh with
    # IrreversibleInstanceRefreshFault.
    asg_response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[ASG_NAME]
    )
    groups = asg_response.get('AutoScalingGroups', [])
    if not groups:
        raise ValueError(f"ASG not found: {ASG_NAME}")

    asg = groups[0]
    launch_template = asg.get('LaunchTemplate', {})
    if not launch_template:
        raise ValueError(f"ASG {ASG_NAME} has no launch template configured")

    desired_config = {
        'LaunchTemplate': {
            'LaunchTemplateId': launch_template['LaunchTemplateId'],
            'Version': launch_template['Version'],
        }
    }
    logger.info(f"DesiredConfiguration: {desired_config}")

    response = autoscaling.start_instance_refresh(
        AutoScalingGroupName=ASG_NAME,
        Strategy='Rolling',
        DesiredConfiguration=desired_config,
        Preferences={
            'MinHealthyPercentage': 90,
            'InstanceWarmup': INSTANCE_WARMUP,
            'CheckpointPercentages': CHECKPOINT_PERCENTAGES,
            'CheckpointDelay': CHECKPOINT_DELAY,
        },
    )

    instance_refresh_id = response['InstanceRefreshId']
    logger.info(f"Instance refresh started: {instance_refresh_id}")

    return {
        'instance_refresh_id': instance_refresh_id,
        'status': 'Pending',
    }


def handle_check_refresh_status(event, _context):
    """Check the current status of an instance refresh."""
    instance_refresh_id = event.get('instance_refresh_id')
    if not instance_refresh_id:
        raise ValueError("Missing required field: instance_refresh_id")

    logger.info(f"Checking instance refresh status: {instance_refresh_id}")

    response = autoscaling.describe_instance_refreshes(
        AutoScalingGroupName=ASG_NAME,
        InstanceRefreshIds=[instance_refresh_id],
    )

    refreshes = response.get('InstanceRefreshes', [])
    if not refreshes:
        raise ValueError(f"Instance refresh not found: {instance_refresh_id}")

    refresh = refreshes[0]
    status = refresh.get('Status', 'Unknown')
    status_reason = refresh.get('StatusReason', '')
    percentage_complete = refresh.get('PercentageComplete', 0)
    instances_to_update = refresh.get('InstancesToUpdate', 0)

    # Calculate instances updated from percentage and total
    desired = 0
    asg_response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[ASG_NAME]
    )
    groups = asg_response.get('AutoScalingGroups', [])
    if groups:
        desired = groups[0].get('DesiredCapacity', 0)

    instances_updated = int(desired * percentage_complete / 100) if desired > 0 else 0

    # Detect checkpoint: status is InProgress and reason mentions waiting
    at_checkpoint = (
        status == 'InProgress'
        and 'Waiting' in status_reason
    )

    logger.info(
        f"Refresh {instance_refresh_id}: status={status}, "
        f"progress={percentage_complete}%, at_checkpoint={at_checkpoint}"
    )

    return {
        'status': status,
        'status_reason': status_reason,
        'percentage_complete': percentage_complete,
        'at_checkpoint': at_checkpoint,
        'instances_to_update': instances_to_update,
        'instances_updated': instances_updated,
    }


def handle_check_health(_event, _context):
    """Check deployment health via CloudWatch metrics."""
    logger.info("Checking deployment health metrics")

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=5)

    metric_queries = [
        {
            'Id': 'healthy_hosts',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/NetworkELB',
                    'MetricName': 'HealthyHostCount',
                    'Dimensions': [
                        {'Name': 'TargetGroup', 'Value': TARGET_GROUP_ARN_SUFFIX},
                        {'Name': 'LoadBalancer', 'Value': NLB_ARN_SUFFIX},
                    ],
                },
                'Period': 300,
                'Stat': 'Average',
            },
        },
        {
            'Id': 'unhealthy_hosts',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/NetworkELB',
                    'MetricName': 'UnHealthyHostCount',
                    'Dimensions': [
                        {'Name': 'TargetGroup', 'Value': TARGET_GROUP_ARN_SUFFIX},
                        {'Name': 'LoadBalancer', 'Value': NLB_ARN_SUFFIX},
                    ],
                },
                'Period': 300,
                'Stat': 'Average',
            },
        },
        {
            'Id': 'cpu_utilization',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/EC2',
                    'MetricName': 'CPUUtilization',
                    'Dimensions': [
                        {'Name': 'AutoScalingGroupName', 'Value': ASG_NAME},
                    ],
                },
                'Period': 300,
                'Stat': 'Average',
            },
        },
    ]

    response = cloudwatch.get_metric_data(
        MetricDataQueries=metric_queries,
        StartTime=start_time,
        EndTime=now,
    )

    # Parse metric results
    healthy_hosts = None
    unhealthy_hosts = None
    avg_cpu = None

    for result in response.get('MetricDataResults', []):
        values = result.get('Values', [])
        if not values:
            continue
        if result['Id'] == 'healthy_hosts':
            healthy_hosts = values[0]
        elif result['Id'] == 'unhealthy_hosts':
            unhealthy_hosts = values[0]
        elif result['Id'] == 'cpu_utilization':
            avg_cpu = values[0]

    # Determine health
    # healthy = no unhealthy hosts (or no data) AND cpu below threshold (or no data) AND at least one healthy host
    no_unhealthy = unhealthy_hosts is None or unhealthy_hosts == 0
    cpu_ok = avg_cpu is None or avg_cpu < MAX_CPU_PERCENT
    has_healthy = healthy_hosts is not None and healthy_hosts > 0

    healthy = no_unhealthy and cpu_ok and has_healthy

    logger.info(
        f"Health check: healthy={healthy}, healthy_hosts={healthy_hosts}, "
        f"unhealthy_hosts={unhealthy_hosts}, avg_cpu={avg_cpu}, "
        f"max_cpu_threshold={MAX_CPU_PERCENT}"
    )

    return {
        'healthy': healthy,
        'details': {
            'healthy_hosts': healthy_hosts,
            'unhealthy_hosts': unhealthy_hosts,
            'avg_cpu': avg_cpu,
            'max_cpu_threshold': MAX_CPU_PERCENT,
        },
    }


def handle_rollback(_event, _context):
    """Manually trigger a rollback of the instance refresh."""
    logger.info(f"Rolling back instance refresh for ASG: {ASG_NAME}")

    try:
        autoscaling.rollback_instance_refresh(
            AutoScalingGroupName=ASG_NAME
        )
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ActiveInstanceRefreshNotFound':
            logger.warning("No active instance refresh to rollback")
            return {
                'status': 'no_active_refresh',
                'message': 'No active instance refresh found to rollback',
            }
        raise

    set_ssm_value(SSM_CANARY_STATE_PARAM, 'rolling_back')

    logger.info("Rollback initiated successfully")

    return {
        'status': 'rolling_back',
        'message': f'Rollback initiated for ASG {ASG_NAME}',
    }


def handle_alarm_triggered_rollback(_event, _context):
    """
    EventBridge entry point for alarm-driven rollback.
    Idempotent: only proceeds if canary state is 'deploying'.
    """
    logger.info("Alarm-triggered rollback received")

    current_state = get_ssm_value(SSM_CANARY_STATE_PARAM)
    if not current_state or not current_state.startswith('deploying'):
        logger.info(f"Skipping alarm rollback: canary state is '{current_state}', not 'deploying'")
        return {
            'action_taken': False,
            'message': f"No action: canary state is '{current_state}'",
        }

    try:
        autoscaling.rollback_instance_refresh(
            AutoScalingGroupName=ASG_NAME
        )
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ActiveInstanceRefreshNotFound':
            logger.warning("No active instance refresh to rollback (alarm may have fired late)")
            set_ssm_value(SSM_CANARY_STATE_PARAM, 'idle')
            return {
                'action_taken': False,
                'message': 'No active instance refresh found',
            }
        raise

    set_ssm_value(SSM_CANARY_STATE_PARAM, 'rolling_back')

    logger.info("Alarm-triggered rollback initiated")

    return {
        'action_taken': True,
        'message': f'Rollback initiated for ASG {ASG_NAME} due to alarm',
    }


def handle_notify(event, _context):
    """Send deployment notification via SNS."""
    status = event.get('status', 'unknown')
    message = event.get('message', '')
    stage = event.get('stage', '')
    details = event.get('details', {})
    image_tag = event.get('image_tag', '')

    notification = {
        'environment': ENVIRONMENT,
        'asg_name': ASG_NAME,
        'status': status,
        'image_tag': image_tag,
        'stage': stage,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'details': details,
        'message': message,
    }

    subject = f"[{ENVIRONMENT}] Canary Deploy: {status}"
    # SNS subject has a 100 character limit
    if len(subject) > 100:
        subject = subject[:97] + '...'

    logger.info(f"Sending notification: {subject}")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=json.dumps(notification, indent=2),
    )

    return {'notified': True}


def handle_complete(_event, _context):
    """Finalize deployment: reset canary state and clear execution ARN."""
    logger.info("Completing canary deployment")

    set_ssm_value(SSM_CANARY_STATE_PARAM, 'idle')
    set_ssm_value(SSM_CANARY_EXECUTION_ARN_PARAM, 'none')

    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"Deployment completed at {timestamp}")

    return {
        'status': 'completed',
        'timestamp': timestamp,
    }


# --- Helper functions ---

def get_ssm_value(param_name):
    """Get a value from SSM Parameter Store."""
    try:
        response = ssm.get_parameter(Name=param_name)
        return response['Parameter']['Value']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            logger.warning(f"SSM parameter not found: {param_name}")
            return None
        raise


def set_ssm_value(param_name, value):
    """Set a value in SSM Parameter Store."""
    ssm.put_parameter(
        Name=param_name,
        Value=value,
        Type='String',
        Overwrite=True,
    )
    logger.info(f"SSM parameter updated: {param_name}={value}")
