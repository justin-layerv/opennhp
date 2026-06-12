# =====================================================================
# CloudTrail CIS metric filters + alarms — detection coverage (#1140)
# =====================================================================
#
# Closes the CloudTrail half of the #1140 detection-coverage gap: the
# CloudTrail trail (this module's `aws_cloudtrail.main`) already streams
# management events to the `aws_cloudwatch_log_group.cloudtrail` log
# group, but nothing turned those events into metrics or alarms. A
# real attacker touching IAM, security groups, the trail itself, or the
# root account produced log lines no one was paged on.
#
# Each filter below is one of the auto-evaluated CloudWatch.x controls
# in the CIS AWS Foundations Benchmark **v1.4.0** standard this account
# subscribes to (`aws_securityhub_standards_subscription.cis`, prod-only).
# Implementing them flips those Security Hub controls FAIL -> PASS — the
# acceptance check for this file is "the listed CloudWatch.N controls
# report PASSED", not merely "the resources exist".
#
# **Filter patterns are load-bearing and frozen.** Security Hub matches
# the filter pattern against the exact CIS-prescribed term set; per the
# AWS remediation docs, "this control fails if the exact metric filters
# prescribed by CIS are not used. Additional fields or terms cannot be
# added." So the `pattern` strings here are the canonical CIS patterns
# verbatim — do NOT add noise-reduction terms (e.g. a sourceIPAddress
# exclusion on unauthorized-API): a "helpful" edit silently drops the
# control back to FAILED. Tune noise via `severity`/routing, not the
# pattern. Patterns sourced from the AWS Security Hub CloudWatch control
# remediation pages (CloudWatch.1/4/5/6/7/8/9/10/11/12/13/14).
#
# **Scope decisions (documented for review):**
#   * Prod-only today. Gated on `var.enable_cloudtrail`, which is the
#     same gate as the log group these filters read. Sandbox sets
#     `enable_cloudtrail = false` (no trail, no log group), so the
#     for_each is empty there and nothing is created. If sandbox ever
#     enables CloudTrail, these extend automatically with no edit.
#   * Manual-only CIS controls are intentionally omitted. CloudWatch.2
#     (unauthorized API calls) and CloudWatch.3 (console sign-in without
#     MFA) are auto-graded only in CIS v1.2.0; under v1.4.0 they are
#     manual checks, so a metric filter does not move a control. They
#     are detection-useful but out of scope for the "flip every graded
#     v1.4.0 monitoring control" goal — track separately if their
#     real-time signal is wanted. (CloudWatch.3, console sign-in without
#     MFA, IS now tracked separately — see console_login_mfa_alarm.tf,
#     #1138.)
#   * Finding-specific filters from #1140 live in
#     cloudtrail_custom_detection_filters.tf, not in this CIS file. Keep
#     the CIS set exact so Security Hub continues to auto-grade it, and
#     add non-CIS defense-in-depth filters separately.
#
# **Routing.** Alarms fan out to `var.alerts_sns_topic_arn` — the shared
# monitoring `alerts` topic, which already subscribes both email and
# Slack (via Chatbot). One target reaches both audiences, matching every
# other alarm in this stack. A Security Hub CloudWatch.x control only
# PASSes when the alarm action points at an SNS topic that has at least
# one subscriber, so this wiring is part of the control, not cosmetic.
#
# **Overlap with the tamper-alert EventBridge rule (intentional).** The
# separate `enable_cloudtrail_tamper_alerts` EventBridge rule in main.tf
# also pages on trail tamper (Stop/Delete/Update/PutEventSelectors) to
# the same `alerts` topic. So a real trail-tamper event fires TWO
# notifications: this CloudWatch.5 (`cloudtrail_config_changes`) alarm
# AND that rule. Keep both — they are different mechanisms: the
# EventBridge rule also covers the SCP-locked / cross-region trails this
# module doesn't own, and CloudWatch.5 is *required* for the CIS control
# to PASS. Do NOT "dedup" by dropping either side; on-call should expect
# the paired page for a trail-tamper.
#
# **Severity / noise.** `Severity` is a tag (the repo has no
# severity-based SNS routing), so all of these land on the same topic.
# The change-detection controls (IAM/SG/NACL/VPC/route/gateway/config/
# S3-policy) fire on routine `terraform apply` traffic from the CI role
# and are tagged `ticket`, not `page`: their value here is CIS posture
# (FAIL->PASS) + forensic trail, not real-time paging. The genuinely
# rare, high-signal ones (root usage, CloudTrail tampering, CMK
# disable/delete) are tagged `page`. To take the bulk of the apply-time
# noise out on day one, `ok_actions` is wired only for `page` alarms
# (see the alarm resource). Separating the `ticket` stream onto its own
# lower-urgency destination so it can't desensitize operators to the
# `page` stream is tracked as a near-term follow-up (#2353) — the fix is
# routing/subscription, never weakening the (frozen) filter patterns.

locals {
  # Single gate: filters AND alarms exist exactly when the CloudTrail
  # log group exists. `var.enable_cloudtrail` drives both, so there is
  # no separate alarm-side gate to factor out.
  cloudtrail_alarms_enabled = var.enable_cloudtrail

  # All metrics share one namespace, consistent with the repo's
  # LayerV/<Service> convention (cf. LayerV/QurlService). Security Hub
  # does not require a specific namespace — only that the filter's
  # metric_transformation and the alarm reference the same
  # (namespace, metric_name) pair, which the shared for_each guarantees.
  cloudtrail_metric_namespace = "LayerV/Security"

  # key => {
  #   metric_name : CloudWatch metric the filter publishes / alarm reads
  #   control     : Security Hub control ID + CIS v1.4.0 requirement #
  #   severity    : "page" (rare, high-signal) | "ticket" (CIS posture)
  #   pattern     : CANONICAL CIS filter pattern — frozen, do not edit
  #   description : operator-facing alarm description
  # }
  #
  # The patterns embed bare CloudTrail eventName identifiers (no quotes)
  # except where the CIS pattern itself quotes a value ("Root",
  # "AwsServiceEvent", "Failed authentication"); those quotes are
  # escaped for HCL. `$.` is a JSON-path selector, not a Terraform
  # interpolation (`${`), so it passes through literally.
  cloudtrail_filters = {
    root_account_usage = {
      metric_name = "RootAccountUsageCount"
      control     = "CloudWatch.1 / CIS v1.4.0 4.3"
      severity    = "page"
      description = "Root account credentials were used. Root should never be used for routine work; investigate immediately."
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }

    iam_policy_changes = {
      metric_name = "IAMPolicyChangeCount"
      control     = "CloudWatch.4 / CIS v1.4.0 4.4"
      severity    = "ticket"
      description = "An IAM policy was created, deleted, attached, detached, or modified. Expected during terraform apply from CI; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }

    cloudtrail_config_changes = {
      metric_name = "CloudTrailConfigChangeCount"
      control     = "CloudWatch.5 / CIS v1.4.0 4.5"
      severity    = "page"
      description = "CloudTrail logging was created, updated, deleted, started, or stopped. This is detection-tampering — investigate immediately unless tied to a known trail change."
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }

    console_auth_failures = {
      metric_name = "ConsoleAuthFailureCount"
      control     = "CloudWatch.6 / CIS v1.4.0 4.6"
      severity    = "ticket"
      description = "Failed AWS Management Console sign-in(s). A sustained rate suggests credential-stuffing or password-guessing against the account."
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }

    cmk_disable_or_delete = {
      metric_name = "CMKDisableOrDeleteCount"
      control     = "CloudWatch.7 / CIS v1.4.0 4.7"
      severity    = "page"
      description = "A customer-managed KMS key was disabled or scheduled for deletion. This stack is KMS-central (logs, CloudTrail, secrets) — a wrongful delete is destructive and hard to reverse."
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }

    s3_bucket_policy_changes = {
      metric_name = "S3BucketPolicyChangeCount"
      control     = "CloudWatch.8 / CIS v1.4.0 4.8"
      severity    = "ticket"
      description = "An S3 bucket ACL, policy, CORS, lifecycle, or replication setting was changed. Expected during terraform apply; investigate changes to log/CloudTrail buckets made outside a known apply."
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }

    aws_config_changes = {
      metric_name = "AWSConfigChangeCount"
      control     = "CloudWatch.9 / CIS v1.4.0 4.9"
      severity    = "ticket"
      description = "An AWS Config recorder or delivery channel was changed/stopped. Put* events fire on routine config apply; Stop/Delete events are detection-tampering — investigate those."
      pattern     = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }

    security_group_changes = {
      metric_name = "SecurityGroupChangeCount"
      control     = "CloudWatch.10 / CIS v1.4.0 4.10"
      severity    = "ticket"
      description = "A security group ingress/egress rule or group was changed. Expected during terraform apply from CI; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }

    network_acl_changes = {
      metric_name = "NetworkAclChangeCount"
      control     = "CloudWatch.11 / CIS v1.4.0 4.11"
      severity    = "ticket"
      description = "A network ACL or NACL entry was created, deleted, or replaced. Expected during terraform apply; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }

    network_gateway_changes = {
      metric_name = "NetworkGatewayChangeCount"
      control     = "CloudWatch.12 / CIS v1.4.0 4.12"
      severity    = "ticket"
      description = "An internet or customer gateway was created, deleted, attached, or detached. Expected during terraform apply; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }

    route_table_changes = {
      metric_name = "RouteTableChangeCount"
      control     = "CloudWatch.13 / CIS v1.4.0 4.13"
      severity    = "ticket"
      description = "A route or route table was created, replaced, deleted, or disassociated. Expected during terraform apply; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
    }

    vpc_changes = {
      metric_name = "VpcChangeCount"
      control     = "CloudWatch.14 / CIS v1.4.0 4.14"
      severity    = "ticket"
      description = "A VPC or VPC peering connection was changed. Expected during terraform apply; investigate changes made outside a known apply."
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    }
  }

  # The filter set, gated. Empty map when CloudTrail is disabled so the
  # filter and alarm resources both create zero instances. Shared by
  # both for_each blocks below so the gate lives in exactly one place.
  cloudtrail_filters_gated = local.cloudtrail_alarms_enabled ? local.cloudtrail_filters : {}

  # The alerts topic is required (non-null AND non-empty) wherever these
  # alarms exist — a CIS CloudWatch.x control only PASSes when its alarm
  # notifies a subscribed topic. Validated once here, enforced by the
  # alarm precondition below. trimspace guards an empty/whitespace ARN
  # that would otherwise pass a bare != null check and fail at apply.
  alerts_topic_valid = var.alerts_sns_topic_arn != null ? trimspace(var.alerts_sns_topic_arn) != "" : false

  # SNS action list, guarded by alerts_topic_valid. The guard keeps the
  # list from becoming `[null]`/`[""]` (an invalid SNS action that fails
  # at apply) so the precondition's friendly message surfaces first.
  cloudtrail_alarm_sns_actions = local.alerts_topic_valid ? [var.alerts_sns_topic_arn] : []
}

# ── Metric filters ──
#
# One filter per CIS monitoring control, on the CloudTrail CloudWatch
# Logs group. `value = "1"` increments the metric per matching event.
# No `default_value`: CIS detections are "any-occurrence", so we want
# missing data (no matching events in the period) to read as no samples,
# which the alarm's `treat_missing_data = "notBreaching"` arm handles.
resource "aws_cloudwatch_log_metric_filter" "cloudtrail" {
  for_each = local.cloudtrail_filters_gated

  name           = "${var.name_prefix}-cis-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = local.cloudtrail_metric_namespace
    value     = "1"
  }
}

# ── Alarms ──
#
# Canonical CIS alarm shape: fire when >= 1 matching event lands in a
# 5-minute window. `period = 300`, `evaluation_periods = 1` gives fast
# detection (CIS reference templates often use a daily rollup; 5 min is
# a deliberate, Security-Hub-neutral improvement — Security Hub grades
# the filter pattern + alarm existence + SNS subscription, not the
# period/threshold). `treat_missing_data = "notBreaching"` keeps the
# alarm quiet when no matching events occur.
resource "aws_cloudwatch_metric_alarm" "cloudtrail" {
  for_each = local.cloudtrail_filters_gated

  alarm_name          = "${var.name_prefix}-cis-${each.key}"
  alarm_description   = "${each.value.control}: ${each.value.description} See docs/SECURITY.md (CloudTrail CIS alarms)."
  namespace           = local.cloudtrail_metric_namespace
  metric_name         = each.value.metric_name
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 1
  period              = 300
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.cloudtrail_alarm_sns_actions

  # ok_actions only for `page`-severity alarms. A "resolved" notification
  # is useful for the rare high-signal events (root usage, trail
  # tampering, CMK delete) but is pure noise for the `ticket`
  # change-detection set, which trips ALARM->OK on every routine
  # terraform apply. CIS grades only alarm_actions, so omitting
  # ok_actions here does not affect the control (the alarm still
  # self-clears in the console via treat_missing_data = notBreaching).
  ok_actions = each.value.severity == "page" ? local.cloudtrail_alarm_sns_actions : []

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cis-${each.key}"
    Component = "security"
    Severity  = each.value.severity
    Control   = each.value.control
  })

  # A CIS CloudWatch.x control only PASSes when the alarm action points
  # at an SNS topic with a subscriber. Without a topic the alarm exists
  # but the control stays FAILED. Fail loud instead — at plan time when
  # the ARN is known then (the standard wiring passes the already-created
  # monitoring topic), otherwise at apply.
  lifecycle {
    precondition {
      condition     = local.alerts_topic_valid
      error_message = "alerts_sns_topic_arn must be set to a non-empty ARN when enable_cloudtrail is true: CIS CloudWatch.x controls require each metric-filter alarm to notify a subscribed SNS topic."
    }
  }
}
