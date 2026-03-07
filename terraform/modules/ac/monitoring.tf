# CloudWatch monitoring for AC instances
# Alarms for disk usage and SSM compliance
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
  namespace           = "NHP/CustomDomainCerts"
  period              = 21600 # 6 hours (matches SSM association interval)
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Custom domain cert sync encountered failures on AC instances"
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-cert-sync-failures"
  })
}

# ==================== CloudWatch Dashboard ====================

resource "aws_cloudwatch_dashboard" "ac_monitoring" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  dashboard_name = "${var.name_prefix}-ac-monitoring"

  dashboard_body = jsonencode({
    widgets = [
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
          alarms = [
            aws_cloudwatch_metric_alarm.disk_usage_high[0].arn,
            aws_cloudwatch_metric_alarm.registration_failure[0].arn,
            aws_cloudwatch_metric_alarm.server_connection_failure[0].arn,
          ]
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
    ]
  })
}
