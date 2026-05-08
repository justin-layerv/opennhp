"""
NHP Canary Deployment Orchestrator Lambda

This Lambda function handles canary deployment orchestration for NHP ASGs (server and AC).
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
import time
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
# Explicit toggle for the NLB-less (frps) regime. Sourced from the
# Terraform-side `disable_nlb_health_checks` variable; mirrored here so
# the regime is unambiguous at runtime even if a future caller passes
# only one of NLB_ARN_SUFFIX/TARGET_GROUP_ARN_SUFFIX.
NLB_HEALTH_CHECKS_DISABLED = os.environ.get('NLB_HEALTH_CHECKS_DISABLED', 'false').lower() == 'true'
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SSM_IMAGE_TAG_PARAM = os.environ.get('SSM_IMAGE_TAG_PARAM', '')
SSM_CANARY_STATE_PARAM = os.environ.get('SSM_CANARY_STATE_PARAM', '')
SSM_CANARY_EXECUTION_ARN_PARAM = os.environ.get('SSM_CANARY_EXECUTION_ARN_PARAM', '')
MAX_CPU_PERCENT = float(os.environ.get('MAX_CPU_PERCENT', '80'))
CHECKPOINT_PERCENTAGES = json.loads(os.environ.get('CHECKPOINT_PERCENTAGES', '[20, 50, 100]'))
INSTANCE_WARMUP = int(os.environ.get('INSTANCE_WARMUP', '60'))

# StartInstanceRefresh.Preferences.MinHealthyPercentage AND the
# handle_check_health threshold floor share this percentage. The SFN
# enforces it during rolling replacement; the canary's own health gate
# uses it as the minimum tolerable in-service count on the NLB-disabled
# (frps) path. Sourced from a single Lambda env var (threaded from the
# Terraform `min_healthy_percentage` variable in lambda.tf) so the two
# call sites can't drift silently — changing the SFN-side preference
# without updating the health gate would let the canary advance on a
# fleet shape the refresh wouldn't itself produce.
MIN_HEALTHY_PERCENTAGE = int(os.environ.get('MIN_HEALTHY_PERCENTAGE', '90'))
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

    # Fail fast on regime-mismatch BEFORE the SFN starts replacing
    # instances. handle_check_health re-checks this for defense in depth
    # (the SFN may invoke health checks outside a deploy run), but
    # surfacing it at prepare-time prevents a misconfig from getting an
    # instance refresh kicked off.
    _check_nlb_mode_consistency()

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

    logger.info(f"Deployment {deployment_id} prepared: asg={ASG_NAME}, current_image_tag={current_image_tag}")

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

    # Defense in depth: a same-axis edit between handle_prepare and
    # the SFN's start-refresh task (e.g., manual env-var swap on the
    # Lambda) would otherwise slip through. Mirrors the call from
    # handle_prepare and handle_check_health.
    _check_nlb_mode_consistency()

    asg_name = event.get('asg_name', ASG_NAME)
    logger.info(f"Starting instance refresh for ASG {asg_name} with image_tag={image_tag}")

    # Look up the ASG's current launch template to pass as DesiredConfiguration.
    # Without DesiredConfiguration, AWS rejects RollbackInstanceRefresh with
    # IrreversibleInstanceRefreshFault.
    asg_response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )
    groups = asg_response.get('AutoScalingGroups', [])
    if not groups:
        raise ValueError(f"ASG not found: {asg_name}")

    asg = groups[0]
    launch_template = asg.get('LaunchTemplate', {})
    if not launch_template:
        raise ValueError(f"ASG {asg_name} has no launch template configured")

    # Use the ASG's *currently recorded* LT version, not the LT's
    # `latest_version`. The Terraform-managed ASG records `version =
    # aws_launch_template.frps.latest_version`, so this matches "latest as
    # of last terraform apply" — not "latest in EC2 right now". For the
    # blue/green path this is the desired behavior: the LT is shared and
    # the green binary differs via the `green_image_tag` SSM, not via a
    # new LT version. A CI-only flow that bumps the SSM key without a
    # `terraform apply` therefore refreshes the ASG to the same LT
    # version it was already on, picking up the new image tag through
    # user_data. Same shape as the existing server / ac canary wiring.
    desired_config = {
        'LaunchTemplate': {
            'LaunchTemplateId': launch_template['LaunchTemplateId'],
            'Version': launch_template['Version'],
        }
    }
    logger.info(f"DesiredConfiguration: {desired_config}")

    # Cancel any existing in-progress or pending refresh (e.g., from TF apply).
    # RollbackInProgress cannot be cancelled — fail early so the operator can
    # wait for the rollback to finish and retry.
    try:
        existing = autoscaling.describe_instance_refreshes(
            AutoScalingGroupName=asg_name
        )
    except ClientError as e:
        logger.warning(f"Error checking for existing refreshes: {e}")
        existing = {'InstanceRefreshes': []}

    existing_refreshes = existing.get('InstanceRefreshes', [])

    rolling_back = [r for r in existing_refreshes
                    if r['Status'] == 'RollbackInProgress']
    if rolling_back:
        rb_id = rolling_back[0]['InstanceRefreshId']
        raise RuntimeError(
            f"Refresh {rb_id} is rolling back — cannot start a new refresh. "
            "Wait for the rollback to complete and retry."
        )

    active = [r for r in existing_refreshes
              if r['Status'] in ('InProgress', 'Pending')]
    if active:
        existing_id = active[0]['InstanceRefreshId']
        logger.warning(f"Found existing refresh {existing_id} ({active[0]['Status']}), cancelling...")
        try:
            autoscaling.cancel_instance_refresh(AutoScalingGroupName=asg_name)
        except autoscaling.exceptions.ActiveInstanceRefreshNotFoundFault:
            logger.info("Refresh already completed/cancelled")
        else:
            # Wait for cancellation (up to 90s)
            status = "unknown"
            for _ in range(18):
                time.sleep(5)
                status_resp = autoscaling.describe_instance_refreshes(
                    AutoScalingGroupName=asg_name,
                    InstanceRefreshIds=[existing_id]
                )
                refreshes = status_resp.get('InstanceRefreshes', [])
                if not refreshes:
                    logger.info(f"Refresh {existing_id} no longer found")
                    break
                status = refreshes[0]['Status']
                if status in ('Cancelled', 'Failed', 'Successful'):
                    logger.info(f"Previous refresh {existing_id} is now {status}")
                    break
            else:
                logger.warning(f"Previous refresh {existing_id} still not cancelled after 90s (final status: {status})")

    response = autoscaling.start_instance_refresh(
        AutoScalingGroupName=asg_name,
        Strategy='Rolling',
        DesiredConfiguration=desired_config,
        Preferences={
            'MinHealthyPercentage': MIN_HEALTHY_PERCENTAGE,
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

    asg_name = event.get('asg_name', ASG_NAME)
    logger.info(f"Checking instance refresh status: {instance_refresh_id}")

    response = autoscaling.describe_instance_refreshes(
        AutoScalingGroupName=asg_name,
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
        AutoScalingGroupNames=[asg_name]
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


def _check_nlb_mode_consistency():
    """Defensive cross-check that the explicit NLB_HEALTH_CHECKS_DISABLED
    toggle agrees with whether NLB/TG suffixes are empty. The Terraform
    `terraform_data.component_invariants` precondition normally
    enforces this at plan time; this is a runtime backstop for manual
    env-var edits or drift.

    Raises immediately on mismatch so the regime fault surfaces BEFORE
    the canary state machine begins replacing instances. Called from
    `handle_prepare` (the first action in every deploy run) and from
    `handle_check_health` (defense in depth — the SFN may invoke health
    checks outside a deploy run, e.g., for alarm-triggered rollback).
    """
    # AND-empty matches the Terraform `terraform_data.component_invariants`
    # precondition exactly: under `disable_nlb_health_checks = true` BOTH
    # suffixes must be empty; under false BOTH must be non-empty. A
    # half-mix (one empty, one not) is rejected at both layers in either
    # regime — locking both layers to AND-empty closes the window where
    # a manual env-var edit could slip past one gate but not the other.
    suffixes_empty = not NLB_ARN_SUFFIX and not TARGET_GROUP_ARN_SUFFIX
    suffixes_present = bool(NLB_ARN_SUFFIX) and bool(TARGET_GROUP_ARN_SUFFIX)
    expected_state_ok = (
        (NLB_HEALTH_CHECKS_DISABLED and suffixes_empty)
        or (not NLB_HEALTH_CHECKS_DISABLED and suffixes_present)
    )
    if not expected_state_ok:
        raise RuntimeError(
            f"Inconsistent NLB-mode wiring: "
            f"NLB_HEALTH_CHECKS_DISABLED={NLB_HEALTH_CHECKS_DISABLED}, "
            f"NLB_ARN_SUFFIX={NLB_ARN_SUFFIX!r}, "
            f"TARGET_GROUP_ARN_SUFFIX={TARGET_GROUP_ARN_SUFFIX!r}. "
            f"Under disable_nlb_health_checks=true BOTH suffixes must be "
            f"empty; under false BOTH must be non-empty. A half-mix "
            f"(one empty, one not) is rejected. The canary-deployment "
            f"module's `component_invariants` precondition normally "
            f"enforces this at plan time; this is the runtime backstop."
        )


def handle_check_health(event, _context):
    """Check deployment health via CloudWatch metrics.

    Two regimes, selected by the `NLB_HEALTH_CHECKS_DISABLED` env var:
      - server / ac (false): NLB target-group health + CPU.
      - frps        (true):  ASG-instance health (GroupInServiceInstances /
                             GroupTotalInstances) + CPU. NLB metric queries
                             are skipped.
    """
    asg_name = event.get('asg_name', ASG_NAME)
    _check_nlb_mode_consistency()
    nlb_disabled = NLB_HEALTH_CHECKS_DISABLED
    logger.info(
        f"Checking deployment health metrics for ASG: {asg_name} "
        f"(nlb_disabled={nlb_disabled})"
    )

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=5)

    metric_queries = []

    if not nlb_disabled:
        metric_queries.extend([
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
        ])
    else:
        # NLB-less path (frps): use ASG-instance counts. The qurl-reverse-tunnel-server
        # ASG enables `GroupInServiceInstances` and `GroupTotalInstances`
        # (see modules/qurl-reverse-tunnel-server/main.tf::aws_autoscaling_group.frps
        # `enabled_metrics`). InService is the "healthy" signal; (Total -
        # InService) is the "unhealthy" signal.
        metric_queries.extend([
            {
                'Id': 'healthy_hosts',
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/AutoScaling',
                        'MetricName': 'GroupInServiceInstances',
                        'Dimensions': [
                            {'Name': 'AutoScalingGroupName', 'Value': asg_name},
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
                        # Pull `GroupTotalInstances` here and compute
                        # implicit-unhealthy = Total - InService client-
                        # side after both queries return (see the
                        # post-processing block below). Direct
                        # GroupUnHealthyInstanceCount also exists but
                        # lags `InService` by one period in our
                        # experience — `Total - InService` is identical
                        # to it within the same period and avoids a
                        # missing-metric race on fresh ASGs that haven't
                        # published the dedicated unhealthy series yet.
                        # A CloudWatch math expression (`m1 - m2`) would
                        # work too, but keeping the subtraction in
                        # Python lets the partial-data race handler
                        # (Total published, InService not yet) surface
                        # cleanly as `unhealthy_hosts = None` instead
                        # of a single math-result NaN we'd have to
                        # detect downstream.
                        'Namespace': 'AWS/AutoScaling',
                        'MetricName': 'GroupTotalInstances',
                        'Dimensions': [
                            {'Name': 'AutoScalingGroupName', 'Value': asg_name},
                        ],
                    },
                    'Period': 300,
                    'Stat': 'Average',
                },
            },
        ])

    metric_queries.append({
        'Id': 'cpu_utilization',
        'MetricStat': {
            'Metric': {
                'Namespace': 'AWS/EC2',
                'MetricName': 'CPUUtilization',
                'Dimensions': [
                    {'Name': 'AutoScalingGroupName', 'Value': asg_name},
                ],
            },
            'Period': 300,
            'Stat': 'Average',
        },
    })

    response = cloudwatch.get_metric_data(
        MetricDataQueries=metric_queries,
        StartTime=start_time,
        EndTime=now,
    )

    # Parse metric results
    healthy_hosts = None
    unhealthy_hosts = None
    avg_cpu = None
    total_instances = None

    for result in response.get('MetricDataResults', []):
        values = result.get('Values', [])
        if not values:
            continue
        if result['Id'] == 'healthy_hosts':
            healthy_hosts = values[0]
        elif result['Id'] == 'unhealthy_hosts':
            # NLB path: this is UnHealthyHostCount.
            # ASG path: this is GroupTotalInstances; convert to
            # implicit unhealthy = total - in-service.
            unhealthy_hosts = values[0]
        elif result['Id'] == 'cpu_utilization':
            avg_cpu = values[0]

    # On the ASG path, the "unhealthy_hosts" series is actually
    # `GroupTotalInstances`; subtract `GroupInServiceInstances` to get
    # the actual unhealthy count. The two are independent CloudWatch
    # streams and may publish on slightly different schedules — on a
    # fresh ASG that just started publishing, only `GroupTotalInstances`
    # may be present in the first metric window. Without the guard
    # below, `unhealthy_hosts` would stay equal to `total` and the
    # health computation would treat every instance as unhealthy
    # (false-positive rollback). Convert only when BOTH metrics are
    # present; otherwise leave `unhealthy_hosts = None` so the
    # `no_unhealthy = unhealthy_hosts is None` branch keeps the
    # rollback decision off the unhealthy axis (the `has_healthy`
    # check on `healthy_hosts > 0` is the load-bearing signal on the
    # ASG path anyway).
    if nlb_disabled:
        if unhealthy_hosts is not None and healthy_hosts is not None:
            total_instances = unhealthy_hosts
            unhealthy_hosts = max(0, total_instances - healthy_hosts)
        elif unhealthy_hosts is not None and healthy_hosts is None:
            # Total published but in-service hasn't yet — preserve the
            # raw total as `total_instances` for telemetry, but flatten
            # the implicit-unhealthy field to None so it's not read as
            # "every host unhealthy".
            total_instances = unhealthy_hosts
            unhealthy_hosts = None

    # Determine health.
    #
    # healthy_threshold: on the NLB path, "any healthy host" is fine
    # because NLB target-group health subsumes "is this instance dialable
    # at all". On the ASG path, `GroupInServiceInstances > 0` is much
    # weaker — a 6-instance frps fleet (PR 4: 2/AZ × 3 AZ) with 5
    # crashlooped instances would still report `has_healthy=True` and
    # let the canary advance into a near-fleet-wide blast. Resolve the
    # ASG path against the ASG's DesiredCapacity and require at least
    # MinHealthyPercentage (matching what StartInstanceRefresh enforces
    # during the rolling replacement).
    #
    # Fail-closed posture on the NLB-disabled path: if the
    # `describe_auto_scaling_groups` call fails (throttle, transient
    # IAM hiccup, etc.) we cannot compute the threshold safely. The
    # pre-fix behavior was to fall back to `min_healthy_count = 1` —
    # the exact "any healthy" floor this percentage gate was added to
    # replace, which would silently drop the safety guarantee during
    # the blast-radius window of a bad deploy. Instead, return
    # `healthy=False` immediately. The SFN's check_health step retries
    # on the next poll and a sustained describe failure trips the
    # ASG-unhealthy / CPU composite alarm via the alarm-driven
    # rollback path. The legacy "asg_desired = None ⇒ floor = 1"
    # path remains for the NLB (server/ac) regime, which has its own
    # NLB-target-group safety net.
    asg_desired = None
    if nlb_disabled:
        try:
            asg_resp = autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name]
            )
            asg_groups = asg_resp.get('AutoScalingGroups', [])
            if asg_groups:
                asg_desired = asg_groups[0].get('DesiredCapacity')
        except ClientError as e:
            logger.error(
                f"Could not fetch ASG DesiredCapacity for tighter has_healthy threshold: {e}. "
                "Failing closed — returning healthy=False so the canary does not advance "
                "on the legacy 'any healthy' floor that this percentage gate was added "
                "to replace."
            )
            return {
                'healthy': False,
                'details': {
                    'healthy_hosts': healthy_hosts,
                    'unhealthy_hosts': unhealthy_hosts,
                    'avg_cpu': avg_cpu,
                    'max_cpu_threshold': MAX_CPU_PERCENT,
                    'nlb_disabled': nlb_disabled,
                    'total_instances': total_instances,
                    'asg_desired': None,
                    'min_healthy_count': None,
                    'asg_describe_failed': True,
                },
            }
    if asg_desired and asg_desired > 0:
        # ceil(asg_desired * MIN_HEALTHY_PERCENTAGE / 100). Single
        # source of truth for the percentage — see the
        # MIN_HEALTHY_PERCENTAGE module-top constant.
        min_healthy_count = (asg_desired * MIN_HEALTHY_PERCENTAGE + 99) // 100
    elif nlb_disabled:
        # NLB-disabled regime AND describe_auto_scaling_groups returned
        # an unexpected shape — empty `AutoScalingGroups` list or a
        # member without `DesiredCapacity`. This is an AWS-side
        # anomaly (DesiredCapacity is always populated for an existing
        # ASG), but on the path with no NLB safety net we fail closed
        # for the same reason the ClientError branch above does:
        # falling back to the legacy "any healthy" floor would silently
        # drop the safety threshold during the blast radius window.
        # The SFN's check_health step retries on the next poll; a
        # sustained anomaly trips the ASG-unhealthy / CPU composite
        # alarm via the alarm-driven rollback path.
        logger.error(
            "NLB-disabled path: describe_auto_scaling_groups returned an "
            "unexpected shape (no DesiredCapacity). Failing closed — this "
            "branch is reached only on AWS-side anomalies."
        )
        return {
            'healthy': False,
            'details': {
                'healthy_hosts': healthy_hosts,
                'unhealthy_hosts': unhealthy_hosts,
                'avg_cpu': avg_cpu,
                'max_cpu_threshold': MAX_CPU_PERCENT,
                'nlb_disabled': nlb_disabled,
                'total_instances': total_instances,
                'asg_desired': None,
                'min_healthy_count': None,
                'asg_describe_anomalous_shape': True,
            },
        }
    else:
        # NLB regime (server / ac): we never queried the ASG. The
        # NLB target-group health acts as the safety net, so the
        # "any healthy" floor is correct.
        min_healthy_count = 1  # legacy behavior — "at least one healthy"

    no_unhealthy = unhealthy_hosts is None or unhealthy_hosts == 0
    cpu_ok = avg_cpu is None or avg_cpu < MAX_CPU_PERCENT
    has_healthy = healthy_hosts is not None and healthy_hosts >= min_healthy_count

    healthy = no_unhealthy and cpu_ok and has_healthy

    logger.info(
        f"Health check: healthy={healthy}, healthy_hosts={healthy_hosts}, "
        f"unhealthy_hosts={unhealthy_hosts}, avg_cpu={avg_cpu}, "
        f"max_cpu_threshold={MAX_CPU_PERCENT}, nlb_disabled={nlb_disabled}, "
        f"total_instances={total_instances}, asg_desired={asg_desired}, "
        f"min_healthy_count={min_healthy_count}"
    )

    # Step Functions consumer contract: the SFN ASL only branches on
    # `$.health.result.healthy` (the boolean) — every key under
    # `details` is for human / CloudWatch consumption only. New fields
    # added here (e.g., `total_instances`, `asg_desired`,
    # `min_healthy_count`, `asg_describe_failed`) are safe to add
    # without an ASL change. A future SFN edit that does branch on a
    # `details.*` key MUST also: (a) ensure the key is always present
    # (the fail-closed branch above intentionally returns the same
    # detail keys to keep the shape stable), and (b) update this
    # comment so the contract stays auditable.
    return {
        'healthy': healthy,
        'details': {
            'healthy_hosts': healthy_hosts,
            'unhealthy_hosts': unhealthy_hosts,
            'avg_cpu': avg_cpu,
            'max_cpu_threshold': MAX_CPU_PERCENT,
            'nlb_disabled': nlb_disabled,
            'total_instances': total_instances,
            'asg_desired': asg_desired,
            'min_healthy_count': min_healthy_count,
        },
    }


def handle_rollback(event, _context):
    """Manually trigger a rollback of the instance refresh.

    Deliberately does NOT call `_check_nlb_mode_consistency`. Like
    `handle_alarm_triggered_rollback`, this is a recovery path: if the
    NLB-mode wiring drifted while a deploy was in progress, blocking
    rollback on the same drift would leave the fleet stuck mid-replace.
    The advance-state handlers (`handle_prepare`, `handle_start_refresh`,
    `handle_check_health`) gate on the consistency check; the two
    rollback handlers do not — see test_manual_rollback_skips_consistency_check.
    """
    asg_name = event.get('asg_name', ASG_NAME)
    logger.info(f"Rolling back instance refresh for ASG: {asg_name}")

    try:
        autoscaling.rollback_instance_refresh(
            AutoScalingGroupName=asg_name
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
        'message': f'Rollback initiated for ASG {asg_name}',
    }


def handle_alarm_triggered_rollback(_event, _context):
    """
    EventBridge entry point for alarm-driven rollback.
    Idempotent: only proceeds if canary state is 'deploying'.
    Uses the Lambda's configured ASG_NAME (set via Terraform per-component).
    Each component's EventBridge rule only fires for its own composite alarm.

    Deliberately does NOT call `_check_nlb_mode_consistency`. This is a
    recovery path: if the NLB-mode wiring drifted while a deploy was
    in progress, blocking rollback on the same drift would leave the
    fleet stuck mid-replace. The other three handlers (`handle_prepare`,
    `handle_start_refresh`, `handle_check_health`) gate on the
    consistency check because they advance the deploy state; this one
    only undoes it. A future refactor that adds the check here breaks
    that recovery posture — see test_alarm_rollback_skips_consistency_check.
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
        'asg_name': event.get('asg_name', ASG_NAME),
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
