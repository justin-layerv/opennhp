# =============================================================================
# Blue/Green Deployment Infrastructure for AC
# =============================================================================
# This file contains resources for blue/green deployment of NHP AC.
# All resources are conditional on var.enable_blue_green.
#
# Architecture:
# - Blue ASG (existing in main.tf) and Green ASG (this file) share one launch template
# - Instant traffic switching via NLB TCP listener modification
# - Warm standby (1 instance by default) for previous color
#
# Key Difference from Server:
# - AC uses a single NLB TCP listener on port 443 (TLS passthrough to Traefik)
# - Health check on port 8080 /ping (Traefik dashboard/ping entrypoint)
# - No termination cleanup needed (CloudMap deregistration via systemd ExecStop)
#
# Naming Convention:
# - Blue ASG: ${name_prefix}-ac (existing)
# - Green ASG: ${name_prefix}-ac-green
# - Target groups use -grn suffix for green (AWS 32 char limit)
# =============================================================================

# =============================================================================
# SSM Parameters for Blue/Green State
# =============================================================================

# Active color - "blue" or "green"
resource "aws_ssm_parameter" "active_color" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/active-color"
  description = "Currently active AC deployment color (blue or green)"
  type        = "String"
  value       = "blue" # Initial state - blue is active

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-active-color"
    Component = "ac"
  })

  # CI/CD updates this value during traffic switch
  lifecycle {
    ignore_changes = [value]
  }
}

# Image tag for green ASG - updated by CI/CD
resource "aws_ssm_parameter" "green_image_tag" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/green-image-tag"
  description = "NHP AC Docker image tag for green ASG - updated by CI/CD"
  type        = "String"
  value       = var.image_tag # Initial value from Terraform

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-green-image-tag"
    Component = "ac"
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

# Last switch timestamp - audit trail
resource "aws_ssm_parameter" "last_switch_timestamp" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/last-switch-timestamp"
  description = "Timestamp of last AC blue/green traffic switch (ISO 8601)"
  type        = "String"
  value       = "never" # Initial state

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-last-switch"
    Component = "ac"
  })

  # CI/CD updates this value during traffic switch
  lifecycle {
    ignore_changes = [value]
  }
}

# Green ASG name - for CI/CD scripts
resource "aws_ssm_parameter" "green_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/green-asg-name"
  description = "NHP AC Green Auto Scaling Group name - used by CI/CD"
  type        = "String"
  value       = aws_autoscaling_group.ac_green[0].name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-green-asg-name"
    Component = "ac"
  })
}

# Blue ASG name - for symmetric naming with green-asg-name
resource "aws_ssm_parameter" "blue_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/blue-asg-name"
  description = "NHP AC Blue Auto Scaling Group name - symmetric with green-asg-name"
  type        = "String"
  value       = aws_autoscaling_group.ac.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-blue-asg-name"
    Component = "ac"
  })
}

# ECR repository name - for CI/CD to validate images
resource "aws_ssm_parameter" "ecr_repo_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/ecr-repo-name"
  description = "ECR repository name for NHP AC images"
  type        = "String"
  # Extract repo name from full ECR URL: account.dkr.ecr.region.amazonaws.com/repo/name
  value = regex("^[^/]+/(.+)$", var.ac_repo_url)[0]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-ecr-repo-name"
    Component = "ac"
  })
}

# =============================================================================
# SSM Parameters for Target Group and Listener ARNs
# CI/CD scripts read these to switch traffic
# =============================================================================

resource "aws_ssm_parameter" "blue_tcp_tg_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/blue-tcp-tg-arn"
  description = "Blue TCP target group ARN for AC traffic switching"
  type        = "String"
  value       = aws_lb_target_group.ac_tcp.arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-blue-tcp-tg"
    Component = "ac"
  })
}

resource "aws_ssm_parameter" "green_tcp_tg_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/green-tcp-tg-arn"
  description = "Green TCP target group ARN for AC traffic switching"
  type        = "String"
  value       = aws_lb_target_group.ac_tcp_green[0].arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-green-tcp-tg"
    Component = "ac"
  })
}

resource "aws_ssm_parameter" "tcp_listener_arn" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/ac/tcp-listener-arn"
  description = "NLB TCP listener ARN for AC traffic switching"
  type        = "String"
  value       = aws_lb_listener.https.arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-tcp-listener"
    Component = "ac"
  })
}

# =============================================================================
# Green Target Group
# =============================================================================

# TCP Target Group for Green ASG (TLS passthrough to Traefik)
resource "aws_lb_target_group" "ac_tcp_green" {
  count = var.enable_blue_green ? 1 : 0

  name              = replace("${var.name_prefix}-ac-tcp-grn", "_", "-")
  port              = 443
  protocol          = "TCP"
  vpc_id            = var.vpc_id
  target_type       = "instance"
  proxy_protocol_v2 = true

  # HTTP health check on Traefik's ping endpoint (port 8080)
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8080"
    path                = "/ping"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-tg-ac-tcp-green"
    Component   = "ac"
    DeployColor = "green"
  })
}

# =============================================================================
# Green Auto Scaling Group
# Uses the same launch template as Blue - only SSM image tag differs
# =============================================================================

resource "aws_autoscaling_group" "ac_green" {
  count = var.enable_blue_green ? 1 : 0

  name                = "${var.name_prefix}-ac-green"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = var.green_standby_min_size
  max_size            = local.is_prod ? 6 : 3
  desired_capacity    = var.green_standby_min_size

  # Uses same launch template as blue ASG
  launch_template {
    id      = aws_launch_template.ac.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 180
    }
  }

  # Attach to green target group
  target_group_arns = [aws_lb_target_group.ac_tcp_green[0].arn]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-ac-green"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "ac"
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
    ignore_changes = [desired_capacity, min_size]
  }
}

# =============================================================================
# Green Scaling Policies
# =============================================================================

resource "aws_autoscaling_policy" "cpu_green" {
  count = var.enable_blue_green ? 1 : 0

  name                   = "${var.name_prefix}-ac-cpu-green"
  autoscaling_group_name = aws_autoscaling_group.ac_green[0].name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_autoscaling_policy" "network_green" {
  count = var.enable_blue_green ? 1 : 0

  name                   = "${var.name_prefix}-ac-network-green"
  autoscaling_group_name = aws_autoscaling_group.ac_green[0].name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageNetworkIn"
    }
    target_value = 10485760 # 10 MB/s
  }
}

# =============================================================================
# CloudWatch Alarms for Blue/Green Deployment Monitoring
# =============================================================================

# Alarm: Green ASG has unhealthy instances (fires when standby has issues)
resource "aws_cloudwatch_metric_alarm" "ac_green_asg_unhealthy" {
  count = var.enable_blue_green && var.alerts_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-green-asg-unhealthy"
  alarm_description   = "AC Green ASG has unhealthy instances - may affect rollback capability"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupUnHealthyInstanceCount"
  namespace           = "AWS/AutoScaling"
  period              = 300
  statistic           = "Average"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.ac_green[0].name
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-green-asg-unhealthy-alarm"
    Component = "ac"
  })
}

# Alarm: Green target group has no healthy targets (critical for rollback)
resource "aws_cloudwatch_metric_alarm" "ac_green_tg_no_healthy_targets" {
  count = var.enable_blue_green && var.alerts_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-green-tg-no-healthy"
  alarm_description   = "AC Green target group has no healthy targets - rollback capability impaired"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.ac_tcp_green[0].arn_suffix
    LoadBalancer = aws_lb.ac.arn_suffix
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-green-tg-health-alarm"
    Component = "ac"
  })
}
