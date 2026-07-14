# =====================================================================
# qURL sandbox CI live-environment lock failure alarm
# =====================================================================
#
# qurl-service and NHP CI publish two SandboxLiveEnvLockFailure samples whenever
# the shared sandbox qURL ECS lock cannot be acquired, read, released, or safely
# reconciled: a dimensionless alarm sample first, then a Reason/Action diagnostic
# sample. Both attempts are independent so failure of either AWS call cannot
# suppress the other attempt.
#
# A standard alarm with no dimensions selects the exact dimensionless stream.
# Keep it that way: alarming on the diagnostic streams through Metrics Insights
# makes a first-ever Reason/Action pair depend on metric discovery before its
# one-shot datapoint leaves the evaluation window. The observability-parity lint
# and its mutation tests fence this paired-producer contract.

resource "aws_cloudwatch_metric_alarm" "qurl_ci_sandbox_live_env_lock_failure" {
  # Gate on the environment, not deploy_qurl_service: CI publishers can fail
  # the shared lock even while the sandbox service itself is not deployed.
  count = var.environment == "sandbox" ? 1 : 0

  alarm_name          = "${local.name_prefix}-qurl-service-ci-live-env-lock-failure"
  alarm_description   = "Any qurl-service or NHP CI failure involving the shared sandbox qURL live-environment lock. Reads the dimensionless alarm stream; use the paired Reason/Action sample for diagnosis. Inspect the lock and owning workflow before release. Runbook: https://github.com/layervai/nhp/blob/main/docs/runbooks/qurl-sandbox-live-env-lock-alarm.md"
  actions_enabled     = true
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "SandboxLiveEnvLockFailure"
  namespace           = "LayerV/QURLServiceCI"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  # The shared monitoring topic is the repository's actionable on-call path.
  # In sandbox, alerts-infra owns the sandbox-alerts-sandbox Chatbot
  # subscription to layerv-nhp-sandbox-cell0-alerts. OK is deliberately
  # informational: each isolated event produces an ALARM -> OK pair, but OK
  # does not prove a retained SSM lock is safe to delete. The rollout ledger
  # requires on-call acceptance of that volume; the runbook keeps
  # reconciliation explicitly manual.
  alarm_actions             = [module.monitoring.sns_topic_arn]
  ok_actions                = [module.monitoring.sns_topic_arn]
  insufficient_data_actions = []

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-qurl-service-ci-live-env-lock-failure"
    Component = "qurl-service"
    Severity  = "page"
  })
}
