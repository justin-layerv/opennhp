# =====================================================================
# CloudTrail custom metric filters + alarms — issue #1140 residuals
# =====================================================================
#
# These are detection-useful filters that are deliberately outside the
# Security Hub CIS exact-pattern set in cloudtrail_metric_filters.tf.
# Keep them separate so tuning a finding-specific signal cannot break
# the CIS CloudWatch controls.

locals {
  cloudtrail_sensitive_kms_key_match = join(" || ", [
    for arn in var.cloudtrail_sensitive_kms_key_arns : "($.resources[*].ARN = \"${arn}\")"
  ])

  # key => {
  #   metric_name : CloudWatch metric the filter publishes / alarm reads
  #   severity    : "page" (rare, high-signal) | "ticket" (likely triage)
  #   pattern     : CloudTrail log filter pattern
  #   description : operator-facing alarm description
  # }
  cloudtrail_base_custom_detection_filters = {
    unauthorized_api_calls = {
      metric_name = "UnauthorizedAPICallCount"
      severity    = "ticket"
      description = "CloudTrail recorded unauthorized API calls. Investigate sustained rates or calls from unexpected principals; single events can occur during IAM propagation or denied policy probes."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }

    update_assume_role_policy = {
      metric_name = "UpdateAssumeRolePolicyCount"
      severity    = "page"
      description = "An IAM role trust policy was modified via UpdateAssumeRolePolicy. This is a high-signal persistence/escalation path unless tied to a known terraform apply."
      pattern     = "{ ($.eventSource = iam.amazonaws.com) && ($.eventName = UpdateAssumeRolePolicy) }"
    }
  }

  cloudtrail_sensitive_kms_decrypt_filter = length(var.cloudtrail_sensitive_kms_key_arns) > 0 ? {
    sensitive_kms_decrypt = {
      metric_name = "SensitiveKMSDecryptCount"
      severity    = "ticket"
      description = "A direct KMS Decrypt call targeted an NHP sensitive CMK (secrets/logs by default). Service-mediated decrypts are excluded; investigate unexpected caller roles."
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && ($.eventName = Decrypt) && ($.userIdentity.invokedBy NOT EXISTS) && (${local.cloudtrail_sensitive_kms_key_match}) }"
    }
  } : {}

  cloudtrail_custom_detection_filters = merge(
    local.cloudtrail_base_custom_detection_filters,
    local.cloudtrail_sensitive_kms_decrypt_filter,
  )

  cloudtrail_custom_detection_filters_gated = local.cloudtrail_alarms_enabled ? local.cloudtrail_custom_detection_filters : {}
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_custom_detection" {
  for_each = local.cloudtrail_custom_detection_filters_gated

  name           = "${var.name_prefix}-custom-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = local.cloudtrail_metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_custom_detection" {
  for_each = local.cloudtrail_custom_detection_filters_gated

  alarm_name          = "${var.name_prefix}-custom-${each.key}"
  alarm_description   = "#1140 custom CloudTrail detection: ${each.value.description} See docs/SECURITY.md (CloudTrail custom detections)."
  namespace           = local.cloudtrail_metric_namespace
  metric_name         = each.value.metric_name
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 1
  period              = 300
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.cloudtrail_alarm_sns_actions
  ok_actions    = each.value.severity == "page" ? local.cloudtrail_alarm_sns_actions : []

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-custom-${each.key}"
    Component = "security"
    Severity  = each.value.severity
    Detection = each.key
    Issue     = "1140"
  })

  lifecycle {
    precondition {
      condition     = local.alerts_topic_valid
      error_message = "alerts_sns_topic_arn must be set to a non-empty ARN when enable_cloudtrail is true: #1140 custom CloudTrail detections must notify a subscribed SNS topic."
    }
  }
}
