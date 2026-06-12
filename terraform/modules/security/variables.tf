variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "waf_scope" {
  description = "WAF scope - CLOUDFRONT for CloudFront, REGIONAL for ALB/API Gateway"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.waf_scope)
    error_message = "WAF scope must be CLOUDFRONT or REGIONAL."
  }
}

variable "rate_limit_requests" {
  description = "Number of requests allowed per 5-minute period per IP"
  type        = number
  default     = 2000
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch"
  type        = bool
  default     = true
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for centralized security findings"
  type        = bool
  default     = true
}

variable "enable_aws_config" {
  description = "Enable AWS Config for configuration compliance monitoring"
  type        = bool
  default     = true
}

variable "config_recording_frequency" {
  description = "AWS Config recording frequency: CONTINUOUS (every change) or DAILY (once per 24h). DAILY reduces costs ~90%."
  type        = string
  default     = "DAILY"

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.config_recording_frequency)
    error_message = "config_recording_frequency must be CONTINUOUS or DAILY."
  }
}

variable "config_resource_types" {
  description = "Specific AWS resource types to record. When set, only these types are recorded instead of all supported types. Reduces Config costs by excluding high-churn resources."
  type        = list(string)
  default = [
    # Required by Config rules: ENCRYPTED_VOLUMES
    "AWS::EC2::Volume",
    # Required by Config rules: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
    "AWS::S3::Bucket",
    # Required by Config rules: INCOMING_SSH_DISABLED
    "AWS::EC2::SecurityGroup",
    # Required by Config rules: VPC_FLOW_LOGS_ENABLED
    "AWS::EC2::VPC",
    # Required by Config rules: IAM_USER_MFA_ENABLED, ROOT_ACCOUNT_MFA_ENABLED
    "AWS::IAM::User",
    # SecurityHub FSBP: instance metadata, IMDSv2
    "AWS::EC2::Instance",
    # SecurityHub FSBP: encryption, public access
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    # SecurityHub FSBP: public access checks
    "AWS::Lambda::Function",
    # SecurityHub FSBP: key rotation
    "AWS::KMS::Key",
    # SecurityHub FSBP: certificate expiration
    "AWS::ACM::Certificate",
    # SecurityHub FSBP: load balancer security
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    # SecurityHub FSBP: cluster/service configuration
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    # SecurityHub FSBP: ASG health checks
    "AWS::AutoScaling::AutoScalingGroup",
    # SecurityHub FSBP: topic encryption
    "AWS::SNS::Topic",
    # SecurityHub CIS: CloudTrail configuration
    "AWS::CloudTrail::Trail",
  ]
}

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API audit logging"
  type        = bool
  default     = true
}

variable "cloudtrail_sensitive_kms_key_arns" {
  description = "Sensitive KMS key ARNs whose direct Decrypt API calls should emit a CloudTrail metric-filter alarm (#1140). Keep this scoped to keys where direct decrypts are unusual; service-mediated decrypts are filtered out by the pattern."
  type        = list(string)
  default     = []
}

variable "enable_cloudtrail_tamper_alerts" {
  description = "Page on-call (via the Slack alerts topic) when a CloudTrail trail is disabled, deleted, or reconfigured (#1143). Deliberately independent of enable_cloudtrail: the alert watches API-call events on the default event bus, so it protects trails this module does not own (e.g. the SCP-locked sandbox trails). Requires enable_slack_target and a non-empty alerts_sns_topic_arn."
  type        = bool
  default     = true
}

variable "cloudtrail_bucket_delete_guard_role_arns" {
  description = "Break-glass IAM role ARNs exempt from the CloudTrail log-delete guard (#1143). When non-empty, a bucket-policy Deny blocks s3:DeleteObject/DeleteObjectVersion for every other principal; empty (default) attaches no Deny (no lockout). Caller gotchas: (1) use the role-ARN form arn:aws:iam::ACCT:role/NAME (ArnLike wildcards ok, e.g. .../role/break-glass-*) — an STS assumed-role session ARN will NOT match aws:PrincipalArn and fails silently; (2) the account root is matched like any principal, so list arn:aws:iam::ACCT:root to keep it as an escape hatch; (3) include the deploy/destroy role if the versioned bucket must ever be emptied (cleanup needs DeleteObjectVersion, which the Deny blocks); (4) only applies when enable_cloudtrail=true (otherwise a silent no-op). See docs/SECURITY.md § CloudTrail Log Integrity for design rationale (PutBucketPolicy residual, Object Lock follow-up)."
  type        = list(string)
  default     = []
}

# GuardDuty alerting configuration
variable "enable_guardduty_alerts" {
  description = "Enable GuardDuty finding alerts (Slack via main topic, email via dedicated topic)"
  type        = bool
  default     = false
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for Slack notifications via Chatbot (GuardDuty Slack + CloudWatch alarms). Email alerts use a separate dedicated topic."
  type        = string
  default     = null

  validation {
    # When GuardDuty alerting is on, this topic is the destination for the
    # security CloudWatch alarms and the MFA audit Lambda's Slack channel. A
    # null here would create actionless alarms and emit Resource=null in the
    # audit Lambda's role policy (MalformedPolicyDocument at apply). Require it
    # explicitly so the misconfig fails loudly at plan instead of silently.
    # (Skipped automatically while the ARN is unknown at plan; re-checked at
    # apply once module.monitoring.sns_topic_arn resolves.)
    condition     = !(var.enable_guardduty && var.enable_guardduty_alerts) || var.alerts_sns_topic_arn != null
    error_message = "alerts_sns_topic_arn must be non-null when enable_guardduty and enable_guardduty_alerts are true — the security alarms and MFA audit Lambda need a destination."
  }
}

variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty finding alerts"
  type        = list(string)
  default     = []
}

variable "guardduty_alert_severity_threshold" {
  description = "Minimum severity for GuardDuty alerts (1-8 integer; AWS bands: HIGH 7.0+, MEDIUM 4.0-6.9, LOW 1.0-3.9). Integer-only because the stale-finding watchdog Lambda (#1137) calls GuardDuty ListFindings, which rejects float for severity.Gte. Shared with the EventBridge initial-alert rule; raising silences both."
  type        = number
  default     = 4

  validation {
    condition     = var.guardduty_alert_severity_threshold >= 1 && var.guardduty_alert_severity_threshold <= 8
    error_message = "GuardDuty severity threshold must be between 1 and 8."
  }

  validation {
    condition     = floor(var.guardduty_alert_severity_threshold) == var.guardduty_alert_severity_threshold
    error_message = "GuardDuty severity threshold must be an integer; fractional values would silently truncate in the watchdog Lambda, causing it to re-alert on findings that never tripped the initial EventBridge alert."
  }
}

variable "enable_slack_target" {
  description = "Enable separate Slack-optimized EventBridge target (requires AWS Chatbot integration)"
  type        = bool
  default     = true
}

# GuardDuty stale-finding watchdog (#1137)
variable "enable_stale_finding_watchdog" {
  description = "Enable weekly watchdog Lambda that re-alerts on non-archived GuardDuty findings (#1137). Requires enable_guardduty."
  type        = bool
  default     = true
}

variable "stale_finding_age_days" {
  description = "Days a non-archived finding must be un-touched before the watchdog re-alerts. Shorter = louder, longer = quieter. 7 matches the ops SLO for HIGH severity triage. GuardDuty's finding retention is 90 days, so values above ~90 are rarely meaningful; the 365-day upper bound is a sanity check, not a policy."
  type        = number
  default     = 7

  validation {
    condition     = var.stale_finding_age_days >= 1 && var.stale_finding_age_days <= 365
    error_message = "stale_finding_age_days must be between 1 and 365."
  }
}

variable "stale_finding_watchdog_schedule" {
  description = "EventBridge schedule expression for the stale-finding watchdog. Default is weekly on Monday at 13:00 UTC (timezone-fixed — US/Eastern drifts between 08:00 and 09:00 with DST). Weekly is enough given the 7-day staleness threshold, and avoids alert-fatigue from daily re-pings on the same unarchived finding."
  type        = string
  default     = "cron(0 13 ? * MON *)"

  validation {
    condition     = can(regex("^(cron|rate)\\(", var.stale_finding_watchdog_schedule))
    error_message = "stale_finding_watchdog_schedule must start with cron(...) or rate(...). See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"
  }
}

# MFA detection + enforcement (#1138)
variable "enable_console_login_mfa_alarm" {
  description = "Create the CloudTrail metric filter + alarm that fires on a ConsoleLogin completed without MFA (#1138). Requires enable_cloudtrail (the filter reads the CloudTrail CloudWatch log group). The alarm only attaches if an SNS destination is available (alerts_sns_topic_arn or the GuardDuty email topic)."
  type        = bool
  default     = true
}

variable "console_login_mfa_filter_pattern" {
  description = "CloudWatch Logs metric-filter pattern for MFA-less ConsoleLogin events. Default is the CIS-3.2 pattern (#1138) plus a Success guard: MFAUsed!=Yes also matches FAILED password attempts (which carry no MFA field), so without the responseElements.ConsoleLogin=Success leg a single fat-fingered login would page; the issue is about *successful* MFA-less logins, so the Success guard targets that and cuts failed-attempt noise. AWS IAM Identity Center (SSO) logs ConsoleLogin with MFAUsed=No because MFA happens at the IdP — none exists in this account today, but if one is added, tighten this (e.g. add `($.userIdentity.type = \"IAMUser\")`)."
  type        = string
  default     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin = \"Success\") }"
}

variable "enable_require_mfa_policy" {
  description = "Create the require_mfa managed IAM policy (#1138). The policy denies all actions for a session that did not present MFA, except self-service MFA enrollment. NOTE: this only ships the policy artifact — it is NOT attached here, because the human IAM users/roles that log into this account are managed outside this Terraform. Attach it to those principals manually; its ARN is exported as require_mfa_policy_arn."
  type        = bool
  default     = true
}

variable "enable_account_password_policy" {
  description = "Manage the account-wide IAM password policy (#1138 Step 3). An account password policy is a SINGLETON and CANNOT require MFA (that is the require_mfa policy's job) — this hardens password length/complexity/rotation/reuse only. DEFAULT false: applying it OVERWRITES any externally-managed account password policy and tightening rotation/reuse can force existing IAM users to reset their password at next sign-in, so enabling it is a deliberate, separately-reviewed apply (capture the current policy first — see the prod rollout ledger). Flip to true once that's been coordinated."
  type        = bool
  default     = false
}

variable "password_minimum_length" {
  description = "Minimum length for the account IAM password policy. 14 aligns with CIS AWS Foundations 1.8."
  type        = number
  default     = 14

  validation {
    condition     = var.password_minimum_length >= 8 && var.password_minimum_length <= 128
    error_message = "password_minimum_length must be between 8 and 128 (AWS account password policy bounds)."
  }
}

variable "password_max_age_days" {
  description = "Maximum age in days before an IAM console password must be rotated. 90 aligns with CIS AWS Foundations 1.11."
  type        = number
  default     = 90

  validation {
    condition     = var.password_max_age_days >= 1 && var.password_max_age_days <= 1095
    error_message = "password_max_age_days must be between 1 and 1095 (AWS account password policy bounds)."
  }
}

variable "enable_iam_mfa_audit" {
  description = "Enable the weekly Lambda that lists IAM users and alerts on any without an MFA device (#1138). Complements AWS Config's IAM_USER_MFA_ENABLED rule by actively paging rather than only recording. Only deploys when an SNS destination is available (alerts_sns_topic_arn or the GuardDuty email topic)."
  type        = bool
  default     = true
}

variable "iam_mfa_audit_schedule" {
  description = "EventBridge schedule expression for the IAM MFA audit Lambda (#1138). Default is weekly on Monday at 13:30 UTC — offset from the GuardDuty stale-finding watchdog (13:00) so the two don't contend, and timezone-fixed to avoid DST drift."
  type        = string
  default     = "cron(30 13 ? * MON *)"

  validation {
    condition     = can(regex("^(cron|rate)\\(", var.iam_mfa_audit_schedule))
    error_message = "iam_mfa_audit_schedule must start with cron(...) or rate(...). See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html"
  }
}

variable "runbook_base_url" {
  # Concatenated unescaped into the EventBridge input templates and a Slack
  # `<url|text>` link, so it must be literal-safe (no double-quote, `<`, `>`,
  # `|`, backslash, whitespace) and free of a trailing `/`. That invariant is
  # validated once at the caller's root qurl_alerts_runbook_base_url; this module
  # is internal to this repo and trusts that validated value rather than
  # repeating the regex (which would have to be hand-kept in sync). If this
  # module is ever reused outside this repo, validate at the new root.
  description = "Base URL for runbook links embedded in GuardDuty alert bodies. Threaded from (and validated at) the root qurl_alerts_runbook_base_url."
  type        = string
  default     = "https://github.com/layervai/nhp/blob/main/docs/runbooks"
}
