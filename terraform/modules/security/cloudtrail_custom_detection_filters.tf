# =====================================================================
# CloudTrail custom metric filters + alarms — issue #1140 residuals
# =====================================================================
#
# These are detection-useful filters that are deliberately outside the
# Security Hub CIS exact-pattern set in cloudtrail_metric_filters.tf.
# Keep them separate so tuning a finding-specific signal cannot break
# the CIS CloudWatch controls.

locals {
  # key => {
  #   metric_name : CloudWatch metric the filter publishes / alarm reads
  #   severity    : "page" (rare, high-signal) | "ticket" (likely triage)
  #   threshold   : Sum threshold within the 5-minute alarm window
  #   pattern     : CloudTrail log filter pattern
  #   description : operator-facing alarm description
  # }
  cloudtrail_base_custom_detection_filters = {
    unauthorized_api_calls = {
      metric_name = "UnauthorizedAPICallCount"
      severity    = "ticket"
      threshold   = 10
      description = "CloudTrail recorded at least 10 unauthorized API calls in 5 minutes. Investigate sustained rates or calls from unexpected principals; single events can occur during IAM propagation or denied policy probes."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }

    update_assume_role_policy = {
      metric_name = "UpdateAssumeRolePolicyCount"
      severity    = "ticket"
      threshold   = 1
      description = "An IAM role trust policy was modified via UpdateAssumeRolePolicy. This is a high-signal persistence/escalation path unless tied to a known terraform apply."
      pattern     = "{ ($.eventSource = iam.amazonaws.com) && ($.eventName = UpdateAssumeRolePolicy) }"
    }
  }

  # Keep sensitive-key decrypt filters key-specific so the high-signal secrets
  # CMK can alarm on a single direct decrypt while noisier keys, such as the
  # CloudWatch Logs CMK, can start with a higher ticket threshold.
  cloudtrail_sensitive_kms_decrypt_filters = {
    for key, detection in var.cloudtrail_sensitive_kms_direct_decrypt_detections :
    key => {
      metric_name = detection.metric_name
      severity    = "ticket"
      threshold   = detection.threshold
      description = detection.description
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && ($.eventName = Decrypt) && ($.userIdentity.invokedBy NOT EXISTS) && ($.resources[*].ARN = \"${detection.arn}\") }"
    }
  }

  cloudtrail_custom_detection_filters = merge(
    local.cloudtrail_base_custom_detection_filters,
    local.cloudtrail_sensitive_kms_decrypt_filters,
  )

  cloudtrail_base_custom_detection_keys           = toset(keys(local.cloudtrail_base_custom_detection_filters))
  cloudtrail_sensitive_kms_decrypt_detection_keys = toset(keys(local.cloudtrail_sensitive_kms_decrypt_filters))
  cloudtrail_cis_metric_names                     = toset([for detection in values(local.cloudtrail_filters) : detection.metric_name])
  cloudtrail_custom_metric_names                  = [for detection in values(local.cloudtrail_custom_detection_filters) : detection.metric_name]

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
  threshold           = each.value.threshold
  evaluation_periods  = 1
  period              = 300
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"

  # Severity is a tag today, not a separate SNS route. Ticket alarms still
  # notify the shared alerts topic on ALARM; only OK notifications are omitted
  # so routine ticket-class events self-clear quietly. Today's custom
  # detections are all ticket-class; keep the page branch to mirror the CIS
  # alarm shape for future rare, high-signal custom detections.
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
    # Same apply-time contract as the CIS CloudTrail alarms in the sibling
    # file: when CloudTrail filters exist, they must notify the shared alerts
    # topic. The root module wires module.monitoring.sns_topic_arn for prod.
    precondition {
      condition     = local.alerts_topic_valid
      error_message = "alerts_sns_topic_arn must be set to a non-empty ARN when enable_cloudtrail is true: #1140 custom CloudTrail detections must notify a subscribed SNS topic."
    }
    precondition {
      condition     = !contains(local.cloudtrail_cis_metric_names, each.value.metric_name)
      error_message = "#1140 custom CloudTrail metric names must not collide with CIS CloudTrail metric names in the shared LayerV/Security namespace."
    }
    precondition {
      condition     = length([for metric_name in local.cloudtrail_custom_metric_names : metric_name if metric_name == each.value.metric_name]) == 1
      error_message = "#1140 custom CloudTrail metric names must be unique within the shared LayerV/Security namespace."
    }
    precondition {
      condition     = length(setintersection(local.cloudtrail_base_custom_detection_keys, local.cloudtrail_sensitive_kms_decrypt_detection_keys)) == 0
      error_message = "Sensitive KMS direct-Decrypt detection keys must not collide with base #1140 custom CloudTrail detection keys."
    }
  }
}
