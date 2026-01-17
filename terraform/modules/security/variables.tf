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

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API audit logging"
  type        = bool
  default     = true
}

# GuardDuty alerting configuration
variable "enable_guardduty_alerts" {
  description = "Enable GuardDuty finding alerts via SNS (email + Slack)"
  type        = bool
  default     = false
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for security alerts (GuardDuty findings will be sent here)"
  type        = string
  default     = null
}

variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty finding alerts"
  type        = list(string)
  default     = []
}

variable "guardduty_alert_severity_threshold" {
  description = "Minimum severity for GuardDuty alerts (1-8, where 7+ is High, 4-6.9 is Medium)"
  type        = number
  default     = 4 # Medium and above

  validation {
    condition     = var.guardduty_alert_severity_threshold >= 1 && var.guardduty_alert_severity_threshold <= 8
    error_message = "GuardDuty severity threshold must be between 1 and 8."
  }
}

variable "enable_slack_target" {
  description = "Enable separate Slack-optimized EventBridge target (requires AWS Chatbot integration)"
  type        = bool
  default     = true
}
