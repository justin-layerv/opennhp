# Security Module
# WAFv2 Web ACL for DDoS protection and common vulnerability protection
#
# Note: WAF can be attached to CloudFront, ALB, or API Gateway.
# For NLB-based services, deploy CloudFront in front first.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  is_prod = var.environment == "prod"
}

# WAFv2 Web ACL - can be used with CloudFront (CLOUDFRONT scope) or regional resources (REGIONAL scope)
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.name_prefix}-waf"
  description = "WAF Web ACL for LayerV NHP"
  scope       = var.waf_scope

  default_action {
    allow {}
  }

  # Rule 1: Rate limiting - prevent DDoS
  rule {
    name     = "RateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_requests
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: AWS Managed Rules - IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Block requests from anonymous proxies (production only)
  dynamic "rule" {
    for_each = local.is_prod ? [1] : []
    content {
      name     = "AWSManagedRulesAnonymousIpList"
      priority = 5

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAnonymousIpList"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-anonymous-ip"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, { Component = "security" })
}

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf" {
  count             = var.enable_waf_logging ? 1 : 0
  name              = "aws-waf-logs-${var.name_prefix}"
  retention_in_days = local.is_prod ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, { Component = "security" })
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_waf_logging ? 1 : 0
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }
  }
}

# ==================== GuardDuty ====================
# Threat detection service for AWS accounts

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  finding_publishing_frequency = local.is_prod ? "FIFTEEN_MINUTES" : "SIX_HOURS"

  tags = merge(var.tags, { Component = "security" })
}

# GuardDuty features (replaces deprecated datasources block)
resource "aws_guardduty_detector_feature" "s3_data_events" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "rds_login_events" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.main[0].id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  # GuardDuty returns all three agent-management configurations even when only
  # EC2 management is enabled. Declare the disabled defaults too; otherwise the
  # AWS provider plans their removal on every apply and needlessly rewrites the
  # unified Runtime Monitoring feature. The resulting EC2 coverage gap makes
  # the fail-closed relay functional-boundary check reject a replacement.
  # Keep this provider/API order: the additional_configuration block is ordered
  # and a different order causes perpetual drift in affected provider versions.
  # Track provider ordering semantics:
  # https://github.com/hashicorp/terraform-provider-aws/issues/36400
  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "DISABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "DISABLED"
  }

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# ==================== GuardDuty Alerting ====================
# EventBridge rule to send GuardDuty findings to SNS for email/Slack notifications
#
# IMPORTANT: GuardDuty uses a SEPARATE SNS topic for email alerts to prevent
# CloudWatch alarm emails from being sent to the same recipients. The main
# alerts_sns_topic_arn (with Chatbot) is only used for Slack notifications.

locals {
  enable_guardduty_alerts       = var.enable_guardduty && var.enable_guardduty_alerts
  enable_guardduty_email_alerts = local.enable_guardduty_alerts && length(var.guardduty_alert_emails) > 0

  # Shared security-alerting gate + CloudWatch-alarm destination for the MFA
  # features in console_login_mfa_alarm.tf and iam_mfa_audit.tf (#1138), defined
  # here next to the GuardDuty-alerting locals as the single source of truth for
  # those two features. (The stale-finding watchdog intentionally keeps its own
  # destination local — its self-failure alarm wants the email topic as a
  # fallback, whereas these alarms follow the module convention of routing only
  # to the Chatbot/Slack topic, so they are deliberately not unified.)
  #
  # enable_guardduty_email_alerts is defined above as
  # (enable_guardduty_alerts && emails>0), so it implies enable_guardduty_alerts
  # — there is no email-only path, and this gate is exactly enable_guardduty_alerts.
  # Named for intent so both features gate on one local. Built ONLY from var.*
  # booleans, so it is safe in count/for_each (an SNS ARN value is unknown at
  # plan on the apply that creates the topic — the #2327 bug class).
  security_alerting_enabled = local.enable_guardduty_alerts

  # Destination for the security CloudWatch alarms: the Chatbot/Slack topic, per
  # the module convention that alarms route to alerts_sns_topic_arn while the
  # dedicated GuardDuty email topic is reserved for findings. The
  # alerts_sns_topic_arn validation guarantees this is non-null whenever the gate
  # is on, so the alarms are never actionless. ARN VALUE — used only in
  # alarm_actions, NEVER in count; compact() drops the empty leg defensively.
  security_alert_destination_arns = compact([
    local.enable_guardduty_alerts ? var.alerts_sns_topic_arn : ""
  ])

  # Single source of truth for the triage-runbook link embedded in every
  # GuardDuty alert body (email + Slack EventBridge targets below, and the
  # stale-finding watchdog Lambda via its TRIAGE_RUNBOOK_URL env var). Built
  # from the repo-wide runbook base URL (var.runbook_base_url) so docs moves are
  # a one-variable edit; the base is required to be literal-safe (#2334).
  guardduty_triage_runbook_url = "${var.runbook_base_url}/guardduty-finding-triage.md"
}

# Dedicated SNS topic for GuardDuty email alerts
# This ensures CloudWatch alarms (which use alerts_sns_topic_arn) don't trigger emails
# Note: No KMS encryption, consistent with main alerts SNS topic in monitoring module
resource "aws_sns_topic" "guardduty_email" {
  count = local.enable_guardduty_email_alerts ? 1 : 0
  name  = "${var.name_prefix}-guardduty-email"

  tags = merge(var.tags, { Component = "security" })
}

# SNS Topic Policy - allows EventBridge to publish GuardDuty findings
resource "aws_sns_topic_policy" "guardduty_email" {
  count  = local.enable_guardduty_email_alerts ? 1 : 0
  arn    = aws_sns_topic.guardduty_email[0].arn
  policy = data.aws_iam_policy_document.guardduty_email_policy[0].json
}

data "aws_iam_policy_document" "guardduty_email_policy" {
  count = local.enable_guardduty_email_alerts ? 1 : 0

  # Allow EventBridge to publish
  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.guardduty_email[0].arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = local.enable_guardduty_alerts ? 1 : 0
  name        = "${var.name_prefix}-guardduty-findings"
  description = "Capture GuardDuty findings for alerting"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      # Threshold is integer-enforced (variables.tf floor() validation)
      # for parity with the stale-finding watchdog Lambda's SDK contract.
      severity = [{
        numeric = [">=", var.guardduty_alert_severity_threshold]
      }]
    }
  })

  tags = merge(var.tags, { Component = "security" })
}

# EventBridge target for Email - plain text format
# Uses dedicated GuardDuty email topic (NOT the main alerts topic)
resource "aws_cloudwatch_event_target" "guardduty_email" {
  count     = local.enable_guardduty_email_alerts ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "guardduty-to-email"
  arn       = aws_sns_topic.guardduty_email[0].arn

  # Plain text format optimized for email readability
  # Template must be a quoted string for non-JSON output
  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.region"
      account     = "$.account"
      time        = "$.time"
      findingId   = "$.detail.id"
    }
    input_template = join("", [
      "\"GuardDuty Security Finding - Severity <severity>\\n\\n",
      "Type: <type>\\n",
      "Title: <title>\\n\\n",
      "Description:\\n",
      "<description>\\n\\n",
      "AWS Details:\\n",
      "- Region: <region>\\n",
      "- Account: <account>\\n",
      "- Time: <time>\\n",
      "- Finding ID: <findingId>\\n\\n",
      "View in Console:\\n",
      "https://<region>.console.aws.amazon.com/guardduty/home?region=<region>#/findings?search=id%3D<findingId>\\n\\n",
      "Triage Runbook:\\n${local.guardduty_triage_runbook_url}\"",
    ])
  }
}

# EventBridge target for Slack - AWS Chatbot formatted JSON
resource "aws_cloudwatch_event_target" "guardduty_slack" {
  count     = local.enable_guardduty_alerts && var.enable_slack_target ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "guardduty-to-slack"
  arn       = var.alerts_sns_topic_arn

  # AWS Chatbot-optimized JSON format
  # Note: Can't use jsonencode() because we need literal <placeholder> strings
  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      region      = "$.region"
      account     = "$.account"
      time        = "$.time"
      findingId   = "$.detail.id"
    }
    input_template = join("", [
      "{",
      "\"version\":\"1.0\",",
      "\"source\":\"custom\",",
      "\"content\":{",
      "\"textType\":\"client-markdown\",",
      "\"title\":\":rotating_light: GuardDuty Finding - Severity <severity>\",",
      "\"description\":\"*<type>*\\n<title>\\n\\n<description>\",",
      "\"nextSteps\":[",
      "\"Account: `<account>` | Region: `<region>` | Time: `<time>`\",",
      "\"<https://<region>.console.aws.amazon.com/guardduty/home?region=<region>#/findings?search=id%3D<findingId>|View in GuardDuty Console>\",",
      "\"<${local.guardduty_triage_runbook_url}|Triage runbook>\"",
      "]",
      "}",
      "}",
    ])
  }
}

# Email subscriptions for GuardDuty alerts
# Subscribed to the dedicated GuardDuty email topic (NOT the main alerts topic)
resource "aws_sns_topic_subscription" "guardduty_email" {
  for_each = local.enable_guardduty_email_alerts ? toset(var.guardduty_alert_emails) : toset([])

  topic_arn = aws_sns_topic.guardduty_email[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# ==================== Security Hub ====================
# Centralized security findings and compliance checks

resource "aws_securityhub_account" "main" {
  count                     = var.enable_security_hub ? 1 : 0
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.id}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Enable CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub && local.is_prod ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.id}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# Send GuardDuty findings to Security Hub
resource "aws_securityhub_product_subscription" "guardduty" {
  count       = var.enable_security_hub && var.enable_guardduty ? 1 : 0
  product_arn = "arn:aws:securityhub:${data.aws_region.current.id}::product/aws/guardduty"

  depends_on = [aws_securityhub_account.main]
}

# ==================== AWS Config ====================
# Configuration compliance and drift detection

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported  = length(var.config_resource_types) == 0
    resource_types = length(var.config_resource_types) > 0 ? var.config_resource_types : null
  }

  recording_mode {
    recording_frequency = var.config_recording_frequency
  }
}

resource "aws_iam_role" "config" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-config"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_aws_config ? 1 : 0
  name  = "config-s3-delivery"
  role  = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      Resource = "${aws_s3_bucket.config[0].arn}/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl" = "bucket-owner-full-control"
        }
      }
    }]
  })
}

# S3 bucket for Config delivery
resource "aws_s3_bucket" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = "${var.name_prefix}-config-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ==================== AWS Config Rules ====================

# EBS volumes should be encrypted
resource "aws_config_config_rule" "ebs_encrypted" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-ebs-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# S3 buckets should have server-side encryption
resource "aws_config_config_rule" "s3_encrypted" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-s3-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# IAM users should have MFA enabled
resource "aws_config_config_rule" "iam_mfa" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-iam-mfa"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root account should have MFA enabled
resource "aws_config_config_rule" "root_mfa" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-root-mfa"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Security groups should not allow unrestricted SSH
resource "aws_config_config_rule" "restricted_ssh" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# VPC flow logs should be enabled
resource "aws_config_config_rule" "vpc_flow_logs" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-vpc-flow-logs"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CloudTrail should be enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ==================== IAM Permission Boundaries ====================
# Permission boundaries restrict the maximum permissions for IAM entities
# These should be attached to all IAM roles to enforce least privilege

resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.name_prefix}-permission-boundary"
  description = "Permission boundary for all IAM roles in the NHP infrastructure"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEC2AndECSActions"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "ecs:*",
          "ecr:*",
          "elasticfilesystem:*",
          "autoscaling:*",
          "elasticloadbalancing:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "AllowLoggingAndMonitoring"
        Effect = "Allow"
        Action = [
          "logs:*",
          "cloudwatch:*",
          "sns:*",
          "events:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsAndSSM"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:GetRandomPassword",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssmmessages:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowServiceDiscovery"
        Effect = "Allow"
        Action = [
          "servicediscovery:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowRoute53ACMERead"
        Effect = "Allow"
        Action = [
          "route53:GetChange",
          "route53:ListResourceRecordSets",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      },
      {
        # This boundary grant is intentionally ACME-DNS-only. It narrows any
        # attached role's existing Route53 grants to ACME TXT changes, but it
        # remains zone-wildcard as a permission-boundary ceiling. Do not attach
        # the boundary to roles that need ACM validation CNAMEs, aliases, or
        # Terraform-style DNS writes; those roles need a different boundary.
        Sid    = "AllowRoute53ACMERecordChanges"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets"
        ]
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          # Route53 populates these multi-valued keys for every
          # ChangeResourceRecordSets batch; ForAllValues validates every
          # record in the request. ForAllValues is vacuously true if AWS
          # omits a key, so Null=false keeps the wildcard zone ARN fail-closed.
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["_acme-challenge.*"]
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
            "route53:ChangeResourceRecordSetsActions"               = "false"
            "route53:ChangeResourceRecordSetsRecordTypes"           = "false"
          }
          "ForAllValues:StringEquals" = {
            "route53:ChangeResourceRecordSetsActions"     = ["CREATE", "UPSERT", "DELETE"]
            "route53:ChangeResourceRecordSetsRecordTypes" = ["TXT"]
          }
        }
      },
      {
        Sid    = "AllowKMSForEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        # aws:ResourceAccount (not kms:CallerAccount) is the load-bearing key:
        # it resolves to the account that owns the key being acted on, so the
        # boundary actually caps KMS use to same-account keys. kms:CallerAccount
        # resolves to the principal's own account — always this account in an
        # identity policy — a tautology that advertises a cross-account bound it
        # never enforces. See #1125 / PR #1520 and the KMS wildcard-decrypt
        # guard in .github/scripts/check-terraform-policy-conditions.py.
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:CreatePolicy",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenySensitiveServices"
        Effect = "Deny"
        Action = [
          "organizations:*",
          "account:*",
          "iam:DeactivateMFADevice",
          "iam:DeleteAccessKey",
          "iam:DeleteUser",
          "iam:UpdateLoginProfile"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, { Component = "security" })
}

# ==================== CloudTrail ====================
# API call audit logging for security and compliance

resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = "${var.name_prefix}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "archive-and-delete"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = local.is_prod ? 365 : 180
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-trail"
          }
        }
      }
      ],
      # Break-glass delete guard (#1143): deny log-object deletion to every
      # principal except the configured break-glass roles. CloudTrail PutObject
      # (above) is unaffected, and S3 lifecycle expiration is unaffected because
      # lifecycle actions are performed by the S3 service and are not evaluated
      # against the bucket policy at all. Scoped to object deletion only —
      # s3:PutBucketPolicy is intentionally left out so this Terraform keeps
      # managing the policy; the residual "strip the guard, then delete" path is
      # closed by S3 Object Lock (the stronger follow-up). Attached only when an
      # allowlist is set, so the default never risks locking out the account.
      length(var.cloudtrail_bucket_delete_guard_role_arns) > 0 ? [
        {
          Sid       = "DenyLogDeletionExceptBreakGlass"
          Effect    = "Deny"
          Principal = "*"
          Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
          Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/*"
          Condition = {
            ArnNotLike = {
              "aws:PrincipalArn" = var.cloudtrail_bucket_delete_guard_role_arns
            }
          }
        }
    ] : [])
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudtrail ? 1 : 0
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = local.is_prod ? 365 : 90
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_iam_role" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_iam_role_policy" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0
  name  = "cloudtrail-logs"
  role  = aws_iam_role.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail[0].arn
  kms_key_id                    = var.logs_kms_key_arn

  # Log data events for S3 and Lambda (optional, can increase costs)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(var.tags, { Component = "security" })

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  # Ignore kms_key_id changes when SCP blocks CloudTrail updates
  lifecycle {
    ignore_changes = [kms_key_id]
  }
}

# ==================== CloudTrail Tamper Detection ====================
# Page on-call when anyone disables, deletes, or reconfigures a CloudTrail
# trail — the "attacker disables logging" kill-chain step from #1143.
#
# Intentionally NOT gated on enable_cloudtrail: it must protect trails this
# module does not own. The independence is from *this module's* trail
# specifically — the "AWS API Call via CloudTrail" events reach the us-east-2
# default event bus while *some* us-east-2 trail is logging management events
# (this module's trail, the org trail, or the SCP-locked sandbox trails).
# The call that disables the last such trail is itself captured and pages
# (best-effort — EventBridge delivery is at-least-once and the event must be
# emitted while a trail is still logging in us-east-2; not a hard guarantee).
#
# Region scope: control-plane CloudTrail calls (StopLogging/DeleteTrail/...)
# are emitted in the trail's home region. This rule runs in the module's region
# (us-east-2), which is the home region of every trail in the #1143 target
# state. The trails homed elsewhere (sandbox-audit us-west-2, layerv-prod-trail
# us-east-1) are NOT covered — acceptable because those are being deleted.
# Revisit if a surviving trail is ever homed outside us-east-2.
locals {
  # "effective" = the var folded together with the other preconditions
  # (Slack/Chatbot target enabled + a real alerts topic), not just the var.
  cloudtrail_tamper_effective = var.enable_cloudtrail_tamper_alerts && var.enable_slack_target && var.alerts_sns_topic_arn != null && var.alerts_sns_topic_arn != ""
}

resource "aws_cloudwatch_event_rule" "cloudtrail_tamper" {
  count       = local.cloudtrail_tamper_effective ? 1 : 0
  name        = "${var.name_prefix}-cloudtrail-tamper"
  description = "Alert when CloudTrail logging is disabled, deleted, or reconfigured (#1143)"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      # PutEventSelectors is included alongside the three eventNames named in
      # #1143 because narrowing a trail's selectors is an equivalent way to
      # blind it without StopLogging/DeleteTrail.
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
      ]
    }
  })

  tags = merge(var.tags, { Component = "security" })
}

# Slack/Chatbot target on the main alerts topic — the on-call "page" path in
# this infra (the alerts topic already permits events.amazonaws.com:Publish).
resource "aws_cloudwatch_event_target" "cloudtrail_tamper_slack" {
  count     = local.cloudtrail_tamper_effective ? 1 : 0
  rule      = aws_cloudwatch_event_rule.cloudtrail_tamper[0].name
  target_id = "cloudtrail-tamper-to-slack"
  arn       = var.alerts_sns_topic_arn

  # AWS Chatbot-optimized JSON format (literal <placeholder> tokens, so no
  # jsonencode()). An unmatched input path renders as an empty string, which
  # two fields rely on:
  #   - errorCode is blank when the call succeeded — that blank is the
  #     high-signal case (logging actually stopped), not an error. A populated
  #     code (e.g. AccessDenied, expected where an SCP blocks the call) means a
  #     blocked attempt still worth investigating.
  #   - The trail name lives under requestParameters.name for StopLogging/
  #     DeleteTrail/UpdateTrail but under requestParameters.trailName for
  #     PutEventSelectors. Input transformers can't coalesce two paths into one
  #     variable, so both are emitted adjacently (<trailName><trailNameSel>) —
  #     exactly one is populated per event, so the concatenation is the name.
  input_transformer {
    input_paths = {
      eventName    = "$.detail.eventName"
      trailName    = "$.detail.requestParameters.name"
      trailNameSel = "$.detail.requestParameters.trailName"
      userArn      = "$.detail.userIdentity.arn"
      sourceIp     = "$.detail.sourceIPAddress"
      region       = "$.region"
      account      = "$.account"
      time         = "$.time"
      errorCode    = "$.detail.errorCode"
    }
    input_template = join("", [
      "{",
      "\"version\":\"1.0\",",
      "\"source\":\"custom\",",
      "\"content\":{",
      "\"textType\":\"client-markdown\",",
      "\"title\":\":rotating_light: CloudTrail tampering: <eventName>\",",
      "\"description\":\"*<eventName>* on trail `<trailName><trailNameSel>` by `<userArn>`\\nError code (blank = the call succeeded): `<errorCode>`\",",
      "\"nextSteps\":[",
      "\"Account: `<account>` | Region: `<region>` | Source IP: `<sourceIp>` | Time: `<time>`\",",
      "\"If unplanned, treat as active intrusion: rotate credentials for the caller and re-enable logging.\"",
      "]",
      "}",
      "}",
    ])
  }
}
