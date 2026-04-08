# CloudWatch monitoring for AC instances
# Alarms for disk usage, SSM compliance, and EIP pool utilization
# Note: Uses data.aws_region.current from main.tf

# ==================== CloudWatch Alarms ====================

resource "aws_cloudwatch_metric_alarm" "disk_usage_high" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-disk-usage-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DiskUsagePercent"
  namespace           = "LayerV/NHP"
  period              = 900 # 15 minutes
  statistic           = "Maximum"
  threshold           = var.disk_usage_threshold_percent
  alarm_description   = "Disk usage exceeds ${var.disk_usage_threshold_percent}% on AC instances"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component = "AC"
  }

  # Send to SNS if configured
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-disk-usage-high"
  })
}

resource "aws_cloudwatch_metric_alarm" "registration_failure" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-registration-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RegistrationFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "AC registration failures exceeded 5 in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component = "AC"
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-registration-failure"
  })
}

resource "aws_cloudwatch_metric_alarm" "server_connection_failure" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-server-connection-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ServerConnectionFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "AC server connection failures exceeded 10 in 10 minutes (2 consecutive periods)"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component = "AC"
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-server-connection-failure"
  })
}

# ==================== Custom Domain Cert Sync Alarms ====================

resource "aws_cloudwatch_metric_alarm" "cert_sync_failures" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-cert-sync-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CertSyncFailures"
  namespace           = "LayerV/NHP"
  dimensions = {
    Component = "AC"
  }
  period             = 21600 # 6 hours (matches SSM association interval)
  statistic          = "Maximum"
  threshold          = 0
  alarm_description  = "Custom domain cert sync encountered failures on AC instances"
  treat_missing_data = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-cert-sync-failures"
  })
}

# Note: an earlier draft of this PR added two AC-to-server registration health
# alarms (`servers_healthy_low` and `registration_stale`). They were dropped
# during staff review because:
#
#   1. `ServersHealthy` is not published by any AC code path. The closest
#      candidate is the `connectedCount` calculated inside checkServerHealth(),
#      but it is only logged, not exposed as a CloudWatch metric. The alarm
#      would never have fired.
#
#   2. `RegistrationSuccess` is published with an additional `RegistrationType`
#      dimension via IncrCounterWithDims, so the metric in CloudWatch lives at
#      [Environment, Component, RegistrationType], not [Environment, Component].
#      A two-dimension alarm cannot match a three-dimension metric, so the
#      stale-registration alarm would also never have fired.
#
# Adding non-functional alarms is worse than no alarms at all because it
# creates false confidence in coverage. The follow-up work is tracked in a
# dedicated issue so the metric publishers and alarm dimensions can be
# designed together.

# ==================== EIP Pool Monitoring ====================
#
# Dimension schema note: the EIP alarms below use [Component, Environment]
# while the existing alarms above (disk_usage_high, registration_failure,
# server_connection_failure, cert_sync_failures) use [Component] only.
#
# This is intentional but inconsistent. The EIP metrics are published from
# user_data.sh.tpl with both Component AND Environment dimensions
# (search for `MetricName=EIPClaimSuccess` in user_data.sh.tpl), so the
# alarms must match that exact set or they would never fire. The existing
# Go-side metrics (RegistrationFailure, ServerConnectionFailure, etc.) use
# the older publishing convention and the alarms above match THEIR set.
#
# Unifying the schema would require either:
#   1. Adding Environment to the Go-side IncrCounter calls AND adding it
#      to the existing alarms in the same change (so the alarms keep
#      matching), OR
#   2. Removing Environment from the EIP user_data publishes AND from the
#      EIP alarms (loses per-environment isolation when multiple envs
#      share an account)
#
# Both are out of scope for this PR. Tracked in issue #946 alongside the
# RegistrationSuccess dimension-mismatch follow-up.

# Alarm: EIP pool utilization exceeds threshold (default 80%)
# Fires when pool usage is high, warning before exhaustion blocks instance launches.
# Metric is pushed by each instance at boot (user_data) AFTER it has already
# claimed its EIP, so by the time an alert fires the instance that triggered
# it is past the danger window. The signal is for capacity planning, not for
# rescuing the launching instance.
resource "aws_cloudwatch_metric_alarm" "eip_pool_utilization_high" {
  count = var.enable_egress_eips && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-eip-pool-utilization-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EIPPoolUtilizationPercent"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Maximum"
  threshold           = var.eip_pool_utilization_threshold_percent
  # Note: local.eip_count is defined in eip.tf (accounts for blue/green 2x multiplier).
  alarm_description  = "AC EIP pool utilization exceeds ${var.eip_pool_utilization_threshold_percent}%. Pool exhaustion will prevent new instances from launching. Total EIPs allocated: ${local.eip_count}."
  treat_missing_data = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-eip-pool-utilization-high"
  })
}

# Alarm: EIP claim failure
# Any single failure means the pool is exhausted or there is an AWS API issue.
# This is a critical alarm - the instance will terminate after a 2-minute cooldown.
#
# treat_missing_data = "notBreaching" is correct for a failure counter:
# the metric is only published when an instance attempts a claim, so periods
# with no instance launches genuinely have no failures and should not alarm.
# Switching to "missing" or "breaching" here would page on every quiet hour.
resource "aws_cloudwatch_metric_alarm" "eip_claim_failure" {
  count = var.enable_egress_eips && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-eip-claim-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EIPClaimFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "AC instance failed to claim an EIP from the pool. The instance will terminate. This indicates the EIP pool is exhausted - increase ac_max_capacity or check for leaked EIP associations."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-eip-claim-failure"
  })
}

# ==================== CloudWatch Dashboard ====================

locals {
  # All EIP dashboard widgets. The list is always defined but only included
  # in the dashboard when var.enable_egress_eips is true (see
  # eip_dashboard_widgets below). The two-step definition is required because
  # Terraform's `cond ? a : b` requires both branches to produce the same
  # tuple type/length, and this list is a heterogeneous tuple of 4 widget
  # objects — a for-expression with an `if` clause is the standard workaround.
  # Dashboard layout: the existing dashboard ends at y=9 with a height-2
  # text widget (rows 9 and 10), so the EIP widgets at y=11 are visually
  # contiguous with the previous row — no gap, no overlap. Each EIP row
  # is height=6, so the second row starts at y=17. If you re-order the
  # dashboard, recompute these to match the new previous-widget end.
  eip_widget_definitions = [
    {
      type   = "metric"
      x      = 0
      y      = 11 # immediately below the existing y=9, height=2 text widget
      width  = 12
      height = 6
      properties = {
        title  = "EIP Pool Utilization"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPPoolUtilizationPercent", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Utilization %" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            max   = 100
            label = "Percent"
          }
        }
        annotations = {
          horizontal = [
            {
              label = "Warning Threshold"
              value = var.eip_pool_utilization_threshold_percent
              color = "#ff7f0e"
            },
            {
              label = "Pool Exhausted"
              value = 100
              color = "#d62728"
            }
          ]
        }
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 11
      width  = 12
      height = 6
      properties = {
        title  = "EIP Pool Capacity"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPPoolTotal", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Total Allocated" }],
          ["LayerV/NHP", "EIPPoolAvailable", "Component", "AC", "Environment", var.environment, { "stat" : "Minimum", "label" : "Available" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            label = "Count"
          }
        }
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 17
      width  = 12
      height = 6
      properties = {
        title  = "EIP Claim Results"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPClaimSuccess", "Component", "AC", "Environment", var.environment, { "stat" : "Sum", "label" : "Success" }],
          ["LayerV/NHP", "EIPClaimFailure", "Component", "AC", "Environment", var.environment, { "stat" : "Sum", "label" : "Failure" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 17
      width  = 12
      height = 6
      properties = {
        title  = "EIP Claim Duration"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPClaimDuration", "Component", "AC", "Environment", var.environment, { "stat" : "Average", "label" : "Average" }],
          ["LayerV/NHP", "EIPClaimDuration", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Max" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            label = "Seconds"
          }
        }
      }
    }
  ]

  # Conditionally include the widgets via a for-comprehension. When
  # var.enable_egress_eips is false the comprehension yields [] and the
  # dashboard's concat() call no-ops the EIP section.
  eip_dashboard_widgets = [for w in local.eip_widget_definitions : w if var.enable_egress_eips]
}

resource "aws_cloudwatch_dashboard" "ac_monitoring" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  dashboard_name = "${var.name_prefix}-ac-monitoring"

  dashboard_body = jsonencode({
    widgets = concat([
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "AC Disk Usage by Instance"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "DiskUsagePercent", "Component", "AC", { "stat" : "Maximum" }]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 900
          annotations = {
            horizontal = [
              {
                label = "Warning Threshold"
                value = var.disk_usage_threshold_percent
                color = "#ff7f0e"
              }
            ]
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "SSM Association Compliance"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/SSM", "AssociationCompliantCount", "AssociationId", aws_ssm_association.bootstrap_instance[0].association_id],
            ["AWS/SSM", "AssociationNonCompliantCount", "AssociationId", aws_ssm_association.bootstrap_instance[0].association_id]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 3600
        }
      },
      {
        type   = "alarm"
        x      = 0
        y      = 6
        width  = 24
        height = 3
        properties = {
          title = "Active Alarms"
          alarms = concat([
            aws_cloudwatch_metric_alarm.disk_usage_high[0].arn,
            aws_cloudwatch_metric_alarm.registration_failure[0].arn,
            aws_cloudwatch_metric_alarm.server_connection_failure[0].arn,
            ],
            var.enable_egress_eips ? [
              aws_cloudwatch_metric_alarm.eip_pool_utilization_high[0].arn,
              aws_cloudwatch_metric_alarm.eip_claim_failure[0].arn,
            ] : []
          )
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 9
        width  = 24
        height = 2
        properties = {
          markdown = <<-EOT
            ## NHP AC Instance Monitoring

            **Environment:** ${var.environment} | **Instance Tag:** ${var.ac_instance_tag} | **Disk Threshold:** ${var.disk_usage_threshold_percent}%

            Disk metrics are collected every 30 minutes via SSM State Manager. Log rotation runs daily at 3 AM UTC.
          EOT
        }
      }
      ],
      # EIP Pool widgets - only included when egress EIPs are enabled.
      # Uses a local to avoid Terraform tuple length mismatch in conditional expressions.
      local.eip_dashboard_widgets
    )
  })
}
