# qurl-api CloudWatch log metric filters and alarms.

# qURL v2 resource-key provisioning is on the critical create path: if KMS key
# creation regresses, qurl-service logs this structured error and POST /v1/qurls
# returns 500. Alarm on the exact inner resource-key failure rather than all
# createQurl 5xxs so the signal stays tied to the incident class from #3026.
resource "aws_cloudwatch_log_metric_filter" "qurl_api_resource_key_provisioning_failed" {
  name           = "${local.service_name}-resource-key-provisioning-failed"
  log_group_name = aws_cloudwatch_log_group.qurl.name

  # Cross-repo contract accepted: qurl-service owns this slog message in
  # internal/service/resource_key.go::provisionResourceKeyForNewResource, and
  # this alarm owns the matching filter. A rename there must update this filter
  # in the same release; otherwise the alarm stays healthy while going dark.
  #
  # qurl-service cmd/qurl-api uses slog.NewJSONHandler, so the application
  # message is the top-level JSON `msg` field. The companion top-level
  # `create qurl failed` line is broader and intentionally not matched here.
  pattern = "{ $.msg = \"resource-key provisioning failed\" }"

  metric_transformation {
    name          = "ResourceKeyProvisioningFailedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "qurl_api_resource_key_provisioning_failures" {
  alarm_name          = "${local.service_name}-resource-key-provisioning-failures"
  alarm_description   = "qurl-api logged a resource-key provisioning failure while creating a qURL. This usually means per-resource KMS key provisioning is broken; check qurl-api logs around `resource-key provisioning failed` and `create qurl failed` before re-enabling or continuing qURL v2 resource-key rollout."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "ResourceKeyProvisioningFailedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  # A single match pages intentionally. The emit site is past request
  # validation and feature gating, immediately after resourceKeyProv.CreateKey
  # returns an error; the create fails closed with HTTP 500. #3026 asks for
  # rate > 0 detection for this incident class, so one occurrence should alert.
  #
  # Root qurl-service modules wire this local to module.monitoring.sns_topic_arn
  # for sandbox/prod; check-observability-parity.py fences that root routing.
  alarm_actions = local.qurl_service_alarm_actions
  # No OK notification: for this event detector, OK means no matching log line
  # arrived this period, not that KMS provisioning has recovered.
  ok_actions = []

  tags = merge(var.tags, {
    Name      = "${local.service_name}-resource-key-provisioning-failures"
    Component = "qurl-service"
    Cell      = var.cell_id
    Severity  = "page"
  })
}

# Private cells remain dark at the public edge, but their intra-cell callers
# still need an actionable readiness signal before catalog activation. The
# internal primary ALB is the traffic boundary, so HealthyHostCount is stronger
# evidence than "ECS desired task exists": it proves the task passed the same
# readiness probe real NHP/qRTS callers traverse.
resource "aws_cloudwatch_metric_alarm" "qurl_api_no_healthy_targets" {
  count = var.target_health_alarm_enabled ? 1 : 0

  alarm_name          = "${local.service_name}-no-healthy-targets"
  alarm_description   = "qurl-service primary ALB has no healthy targets. Keep this cell disabled; inspect the exact ECS task, repo@sha256 image/source revision, secret resolution, and /health/ready logs before activation."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = aws_lb.qurl.arn_suffix
    TargetGroup  = aws_lb_target_group.qurl.arn_suffix
  }

  alarm_actions             = local.qurl_service_alarm_actions
  ok_actions                = local.qurl_service_alarm_actions
  insufficient_data_actions = []

  tags = merge(var.tags, {
    Name      = "${local.service_name}-no-healthy-targets"
    Component = "qurl-service"
    Cell      = var.cell_id
    Severity  = "page"
  })
}
