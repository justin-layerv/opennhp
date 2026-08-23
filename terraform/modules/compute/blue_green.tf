# =============================================================================
# Blue/Green Deployment Infrastructure
# =============================================================================
# This file contains resources for blue/green deployment of NHP Server.
# All resources are conditional on var.enable_blue_green.
#
# Architecture:
# - Blue ASG (existing in main.tf) and Green ASG (this file) share one launch template
# - Instant traffic switching via NLB listener modification
# - Warm standby (1 instance by default) for previous color
#
# Naming Convention:
# - Blue ASG: ${name_prefix}-server (existing)
# - Green ASG: ${name_prefix}-server-green
# - Target groups use -grn suffix for green (AWS 32 char limit)
# =============================================================================

# =============================================================================
# SSM Parameters for Blue/Green State
# =============================================================================

# Active color - "blue" or "green"
resource "aws_ssm_parameter" "active_color" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/active-color"
  description = "Currently active deployment color (blue or green)"
  type        = "String"
  value       = "blue" # Initial state - blue is active

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-active-color"
    Component = "compute"
    Cell      = var.cell_id
  })

  # CI/CD updates this value during traffic switch
  lifecycle {
    ignore_changes = [value]
  }
}

# Image tag for green ASG - updated by CI/CD
resource "aws_ssm_parameter" "green_image_tag" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/green-image-tag"
  description = "NHP Server Docker image tag for green ASG - updated by CI/CD"
  type        = "String"
  value       = var.image_tag # Initial value from Terraform

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-green-image-tag"
    Component = "compute"
    Cell      = var.cell_id
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

# Last switch timestamp - audit trail
resource "aws_ssm_parameter" "last_switch_timestamp" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/last-switch-timestamp"
  description = "Timestamp of last blue/green traffic switch (ISO 8601)"
  type        = "String"
  value       = "never" # Initial state

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-last-switch"
    Component = "compute"
    Cell      = var.cell_id
  })

  # CI/CD updates this value during traffic switch
  lifecycle {
    ignore_changes = [value]
  }
}

# Green ASG name - for CI/CD scripts
resource "aws_ssm_parameter" "green_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/green-asg-name"
  description = "NHP Server Green Auto Scaling Group name - used by CI/CD"
  type        = "String"
  value       = aws_autoscaling_group.server_green[0].name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-green-asg-name"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Blue ASG name - for symmetric naming with green-asg-name
# The original asg-name parameter in main.tf is kept for backward compatibility.
# This creates an explicit blue-asg-name parameter so CI/CD scripts can use
# consistent naming patterns (blue-asg-name / green-asg-name).
resource "aws_ssm_parameter" "blue_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/blue-asg-name"
  description = "NHP Server Blue Auto Scaling Group name - symmetric with green-asg-name"
  type        = "String"
  value       = aws_autoscaling_group.server.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-blue-asg-name"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# ECR repository name - for CI/CD to validate images
# Eliminates hardcoded fallback in workflow
resource "aws_ssm_parameter" "ecr_repo_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/ecr-repo-name"
  description = "ECR repository name for NHP Server images"
  type        = "String"
  # Extract repo name from full ECR URL: account.dkr.ecr.region.amazonaws.com/repo/name
  # The repo name is everything after the first "/" (e.g., "layerv/nhp-server")
  value = regex("^[^/]+/(.+)$", var.server_repo_url)[0]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-ecr-repo-name"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# SSM Parameters for Target Group and Listener ARNs
# CI/CD scripts read these to switch traffic
# =============================================================================

resource "aws_ssm_parameter" "blue_udp_tg_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/blue-udp-tg-arn"
  description = "Blue UDP target group ARN for traffic switching"
  type        = "String"
  value       = aws_lb_target_group.udp[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-blue-udp-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "green_udp_tg_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/green-udp-tg-arn"
  description = "Green UDP target group ARN for traffic switching"
  type        = "String"
  value       = aws_lb_target_group.udp_green[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-green-udp-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "udp_listener_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/server/udp-listener-arn"
  description = "NLB UDP listener ARN for traffic switching"
  type        = "String"
  value       = aws_lb_listener.udp[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-udp-listener"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "blue_internal_udp_tg_arn" {
  count = var.enable_blue_green && var.relay_enabled ? 1 : 0

  name        = "/${var.environment}/nhp/server/blue-internal-udp-tg-arn"
  description = "Blue internal relay UDP target group ARN for active-color traffic switching"
  type        = "String"
  value       = aws_lb_target_group.udp_internal[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-blue-internal-udp-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "green_internal_udp_tg_arn" {
  count = var.enable_blue_green && var.relay_enabled ? 1 : 0

  name        = "/${var.environment}/nhp/server/green-internal-udp-tg-arn"
  description = "Green internal relay UDP target group ARN for active-color traffic switching"
  type        = "String"
  value       = aws_lb_target_group.udp_internal_green[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-green-internal-udp-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "internal_udp_listener_arn" {
  count = var.enable_blue_green && var.relay_enabled ? 1 : 0

  name        = "/${var.environment}/nhp/server/internal-udp-listener-arn"
  description = "Internal relay UDP listener ARN for active-color traffic switching"
  type        = "String"
  value       = aws_lb_listener.udp_internal[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-internal-udp-listener"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# HTTPS target group and listener ARNs (conditional on QURL endpoint being enabled)
resource "aws_ssm_parameter" "blue_https_tg_arn" {
  count = var.enable_blue_green && var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = "/${var.environment}/nhp/server/blue-https-tg-arn"
  description = "Blue HTTPS target group ARN for traffic switching"
  type        = "String"
  value       = aws_lb_target_group.https[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-blue-https-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "green_https_tg_arn" {
  count = var.enable_blue_green && var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = "/${var.environment}/nhp/server/green-https-tg-arn"
  description = "Green HTTPS target group ARN for traffic switching"
  type        = "String"
  value       = aws_lb_target_group.https_green[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-green-https-tg"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "https_listener_arn" {
  count = var.enable_blue_green && var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = "/${var.environment}/nhp/server/https-listener-arn"
  description = "NLB HTTPS listener ARN for traffic switching"
  type        = "String"
  value       = aws_lb_listener.https[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-https-listener"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# Green Target Groups
# =============================================================================

# UDP Target Group for Green ASG
# Note: Using "-grn" suffix instead of "-green" due to AWS target group name
# limit of 32 characters. The name_prefix can be up to ~20 chars, leaving
# limited space for the suffix. Full name in tags for clarity.
resource "aws_lb_target_group" "udp_green" {
  count = var.enable_blue_green ? 1 : 0

  name        = replace("${var.name_prefix}-udp-grn", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Must match the blue public UDP target group: direct SDK knocks retain the
  # original client address at nhp-server after a blue/green switch.
  preserve_client_ip = true

  # HTTP health check on port 8888 (same as blue)
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-tg-udp-green"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
  })
}

# Internal UDP target group for the GREEN server ASG. The listener lives in
# main.tf and flips between this TG and aws_lb_target_group.udp_internal (blue).
resource "aws_lb_target_group" "udp_internal_green" {
  count = var.enable_blue_green && var.relay_enabled ? 1 : 0

  name        = replace("${var.name_prefix}-srv-int-grn", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Preserve the relay instance IP on the server-side packet so the server replies
  # directly to the relay. Must match the blue internal TG in main.tf.
  preserve_client_ip = true

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-tg-srv-int-udp-green"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
  })
}

# HTTPS Target Group for Green ASG (conditional on QURL endpoint)
resource "aws_lb_target_group" "https_green" {
  count = var.enable_blue_green && var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = replace("${var.name_prefix}-https-grn", "_", "-")
  port        = 8888
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Health check on port 8888 — must match the blue HTTPS target group at
  # main.tf::aws_lb_target_group.https. Both use /health/knock-ready (not
  # /health/live) to verify the server has connected AC peers before routing
  # knock traffic to it (H1 hardening). /health/live is still used by the
  # ASG/UDP target groups so healthy-but-waiting servers are not terminated.
  #
  # Bootstrap-deadlock note: this strict path can't deadlock the green ASG
  # because the green ASG also uses health_check_type = "EC2" (set in
  # aws_autoscaling_group.server_green below) and the server itself has an
  # HTTP forwarder fallback that routes knocks to a peer when the local AC
  # peer count is zero. Full chain documented at main.tf::server ASG; search
  # for "Bootstrap deadlock avoidance".
  #
  # Keep this in sync with main.tf::aws_lb_target_group.https.health_check.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/knock-ready"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    matcher             = "200"
  }

  deregistration_delay = 30

  # Mirror the blue HTTPS TG's connection_termination=true (see
  # main.tf::aws_lb_target_group.https for the rationale + 2026-05-22
  # incident reference + the disjoint-roles note re:
  # deregistration_delay). When the listener flips green→blue and the
  # green ASG shrinks, NLB must send RST on in-flight flows so CF
  # detects the dead peer and retries on the new color on its own
  # retry cadence (sub-second to single-digit seconds in practice,
  # bounded by CF's connection-error retry budget) rather than
  # sitting on its 60s OriginReadTimeout. Drift between
  # the two colors is fenced at plan time by
  # `check "https_target_group_blue_green_drift"` in main.tf — that
  # block now also asserts {connection_termination, deregistration_delay}
  # agreement; do not edit either color without the same edit here.
  connection_termination = true

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-tg-https-green"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# Green Auto Scaling Group
# Uses the same launch template as Blue - only SSM image tag differs
# =============================================================================

resource "aws_autoscaling_group" "server_green" {
  count = var.enable_blue_green ? 1 : 0

  name                = "${var.name_prefix}-server-green"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.green_standby_min_size
  max_size            = var.max_capacity
  desired_capacity    = var.green_standby_min_size

  # Uses same launch template as blue ASG
  launch_template {
    id      = aws_launch_template.server.id
    version = "$Latest"
  }

  health_check_type = "EC2"
  # Matches the server ASG grace period in main.tf. Docker is pre-baked
  # into the AMI so the ~120s apt-get install is no longer in the critical
  # path; 90s gives ~1.5x the observed worst-case boot-to-healthy time.
  health_check_grace_period = 90

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  # Keep GroupDesiredCapacity + GroupInServiceInstances: the green standby
  # capacity-deficit alarm below depends on both metric streams.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  # Attach to green target groups. The relay->server internal NLB uses per-color
  # TGs, so the green ASG attaches only to the green internal TG and never shares
  # the blue TG with the warm-standby path.
  target_group_arns = compact(concat(
    [aws_lb_target_group.udp_green[0].arn],
    var.enable_qurl_resolve_endpoint ? [aws_lb_target_group.https_green[0].arn] : [],
    var.relay_enabled ? [aws_lb_target_group.udp_internal_green[0].arn] : []
  ))

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-server-green"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "compute"
    propagate_at_launch = true
  }

  tag {
    key                 = "Cell"
    value               = var.cell_id
    propagate_at_launch = true
  }

  # Critical: Deploy color tag - user_data reads this to determine SSM parameter
  tag {
    key                 = "DeployColor"
    value               = "green"
    propagate_at_launch = true
  }

  # SSM parameter path for image tag - user_data reads this tag
  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.green_image_tag[0].name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # CI/CD manages capacity during blue/green switches
    # Suspension state, like desired/min capacity, is an operator-owned
    # deployment/incident control. Terraform must not resume a deliberately
    # frozen standby group during an unrelated infrastructure update. Keep this
    # list in lockstep with the blue ASG in main.tf.
    ignore_changes = [desired_capacity, min_size, max_size, suspended_processes]
  }
}

# =============================================================================
# Green Scaling Policies
# =============================================================================

resource "aws_autoscaling_policy" "cpu_green" {
  count = var.enable_blue_green ? 1 : 0

  name                   = "${var.name_prefix}-cpu-green"
  autoscaling_group_name = aws_autoscaling_group.server_green[0].name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Network scaling policy removed — see compute/main.tf for rationale.

# =============================================================================
# Green Termination Cleanup (conditional on enable_termination_cleanup)
# Mirrors the blue ASG termination cleanup but for green instances
# =============================================================================

# Lifecycle Hook - pauses termination to allow cleanup
resource "aws_autoscaling_lifecycle_hook" "termination_green" {
  count = var.enable_blue_green && var.enable_termination_cleanup ? 1 : 0

  name                   = "${var.name_prefix}-termination-hook-green"
  autoscaling_group_name = aws_autoscaling_group.server_green[0].name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE" # Allow termination even if Lambda fails
  heartbeat_timeout      = 300        # 5 minutes max for cleanup
}

# EventBridge Rule - captures lifecycle hook events for green ASG
resource "aws_cloudwatch_event_rule" "termination_green" {
  count = var.enable_blue_green && var.enable_termination_cleanup ? 1 : 0

  name        = "${var.name_prefix}-server-termination-green"
  description = "Captures NHP Server (green) termination lifecycle events"

  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-terminate Lifecycle Action"]
    detail = {
      AutoScalingGroupName = [aws_autoscaling_group.server_green[0].name]
    }
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-rule-green"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# EventBridge Target - reuses existing Lambda from main.tf
resource "aws_cloudwatch_event_target" "termination_green" {
  count = var.enable_blue_green && var.enable_termination_cleanup ? 1 : 0

  rule      = aws_cloudwatch_event_rule.termination_green[0].name
  target_id = "server-termination-cleanup-green"
  arn       = aws_lambda_function.termination_cleanup[0].arn
}

# Lambda Permission - allows EventBridge to invoke Lambda for green events
resource "aws_lambda_permission" "termination_green" {
  count = var.enable_blue_green && var.enable_termination_cleanup ? 1 : 0

  statement_id  = "AllowEventBridgeInvokeGreen"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.termination_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.termination_green[0].arn
}

# IAM Policy for Lambda - ASG lifecycle completion for green ASG
resource "aws_iam_role_policy" "termination_cleanup_asg_green" {
  count = var.enable_blue_green && var.enable_termination_cleanup ? 1 : 0

  name = "asg-lifecycle-green"
  role = aws_iam_role.termination_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CompleteLifecycleActionGreen"
        Effect   = "Allow"
        Action   = ["autoscaling:CompleteLifecycleAction"]
        Resource = aws_autoscaling_group.server_green[0].arn
      }
    ]
  })
}

# =============================================================================
# CloudWatch Alarms for Blue/Green Deployment Monitoring
# =============================================================================

# Alarm: Green ASG has sustained capacity deficit (fires when standby has issues)
#
# Green standby has no live traffic, so this uses the same 10-min window
# as the AC/frps standby alarms (2 x 300s): slower page, fewer false
# positives during instance refreshes and AMI rolls. The input stats are
# intentionally asymmetric: `desired` Minimum and `in_service` Maximum
# only declare a deficit when capacity stayed short across the period.
# Revisit after the first sandbox green refresh; lengthen the window only
# if this still pages on healthy refresh noise.
resource "aws_cloudwatch_metric_alarm" "green_asg_unhealthy" {
  # Gate on the STATIC enable_sns_alerts, not the computed
  # alerts_sns_topic_arn != null (module.monitoring's ARN), to avoid
  # "Invalid count argument" on a greenfield apply before the ARN is in
  # state. alarm_actions still uses the ARN — the variable contract
  # guarantees it's non-null when enable_sns_alerts=true (cf. #2664 / #2665).
  count = var.enable_blue_green && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-green-asg-unhealthy"
  alarm_description   = "Green ASG has sustained capacity deficit - may affect rollback capability"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  # Belt-and-suspenders for whole-expression no-data states; the FILLs
  # make normal partial input gaps explicit.
  treat_missing_data = "notBreaching"

  metric_query {
    id = "capacity_deficit"
    # FILL bias is intentional for one-sided gaps: missing desired is treated
    # as "nothing wanted"; missing in-service with desired present should read
    # as a full deficit. The rollout ledger verifies CloudWatch's fresh-series
    # and one-input-missing behavior after apply.
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    label       = "ASG desired capacity minus in-service instances"
    return_data = true
  }

  metric_query {
    id = "desired"
    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Minimum"
      dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.server_green[0].name
      }
    }
  }

  metric_query {
    id = "in_service"
    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Maximum"
      dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.server_green[0].name
      }
    }
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-green-asg-unhealthy-alarm"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Alarm: Green target group has no healthy targets (critical for rollback).
# Warm standby treats missing data as breaching; cold standby intentionally has
# no green targets until it is warmed, so missing datapoints do not page.
# This same warm/cold gate applies to the pre-existing public green TG alarm,
# not just the new internal relay green TG alarm below.
resource "aws_cloudwatch_metric_alarm" "green_tg_no_healthy_targets" {
  # Gate on the STATIC enable_sns_alerts, not the computed
  # alerts_sns_topic_arn != null, to avoid count-depends-on-computed
  # "Invalid count argument" on a greenfield apply (cf. #2664 / #2665).
  #
  # The public NLB and green UDP TG remain required; the internal relay NLB has
  # separate internal-path alarms.
  count = var.enable_blue_green && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-green-tg-no-healthy"
  alarm_description   = "Green target group has no healthy targets - rollback capability impaired"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = var.green_standby_min_size > 0 ? "breaching" : "notBreaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.udp_green[0].arn_suffix
    LoadBalancer = aws_lb.server[0].arn_suffix
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-green-tg-health-alarm"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Alarm: the GREEN internal relay target group has no healthy targets. The BLUE
# internal TG alarm lives next to aws_lb_target_group.udp_internal in main.tf;
# this sibling keeps green-side relay routing covered now that the internal relay
# path is per-color instead of a single both-color TG. Warm standby pages on
# missing HealthyHostCount because an unhealthy standby color is unsafe to flip
# to; cold standby suppresses missing-data pages until green is intentionally
# warmed.
resource "aws_cloudwatch_metric_alarm" "green_internal_tg_no_healthy_targets" {
  count = var.enable_blue_green && var.relay_enabled && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-srv-int-green-tg-no-healthy"
  alarm_description   = "Green internal relay target group has no healthy targets - green relay knocks would fail if green is or becomes active"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = var.green_standby_min_size > 0 ? "breaching" : "notBreaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.udp_internal_green[0].arn_suffix
    LoadBalancer = aws_lb.server_internal[0].arn_suffix
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-srv-int-green-tg-health-alarm"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Alarm: No recent deployment activity (stale deployment detection)
#
# The workflow pushes DeploymentCount=1 after each successful deployment.
# This alarm fires if no deployments occur within the evaluation period.
#
# NOTE: CloudWatch maximum period is 86400 seconds (1 day), so we use
# evaluation_periods to check over a configurable window.
# Set deployment_stale_threshold_days=0 to disable this alarm.
resource "aws_cloudwatch_metric_alarm" "deployment_stale" {
  # Gate on the STATIC enable_sns_alerts, not the computed
  # alerts_sns_topic_arn != null, to avoid count-depends-on-computed
  # "Invalid count argument" on a greenfield apply (cf. #2664 / #2665).
  # The threshold-days>0 disable switch is preserved.
  count = var.enable_blue_green && var.enable_sns_alerts && var.deployment_stale_threshold_days > 0 ? 1 : 0

  alarm_name          = "${var.name_prefix}-deployment-stale"
  alarm_description   = "No blue/green deployments in past ${var.deployment_stale_threshold_days} days - check if deployments are stalled"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = var.deployment_stale_threshold_days
  metric_name         = "DeploymentCount"
  namespace           = "NHP/BlueGreen"
  period              = 86400 # 1 day (CloudWatch max)
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "breaching" # No metric = no deployments = alert

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-deployment-stale-alarm"
    Component = "compute"
    Cell      = var.cell_id
  })
}
