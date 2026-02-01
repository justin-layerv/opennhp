# ==============================================================================
# ACME Certificate Manager Variables
# ==============================================================================

variable "name_prefix" {
  description = "Prefix for resource names (e.g., 'layerv-nhp-sandbox')"
  type        = string
}

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

# ------------------------------------------------------------------------------
# Domain Configuration
# ------------------------------------------------------------------------------

variable "domains" {
  description = "List of domains for the certificate. First domain is the main/CN, rest are SANs. Include wildcards as needed (e.g., ['nhp.layerv.xyz', '*.nhp.layerv.xyz'])"
  type        = list(string)

  validation {
    condition     = length(var.domains) > 0
    error_message = "At least one domain must be specified."
  }
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for DNS-01 challenge"
  type        = string
}

variable "acme_email" {
  description = "Email address for ACME account registration and expiry notifications"
  type        = string
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false). Staging is for testing to avoid rate limits."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# KMS Configuration
# ------------------------------------------------------------------------------

variable "kms_key_arn" {
  description = "KMS CMK ARN for encrypting certificate secrets. If not provided, a new key will be created."
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption. Should be a key with CloudWatch Logs service permissions."
  type        = string
  default     = null

  validation {
    condition     = var.logs_kms_key_arn == null || can(regex("^arn:aws:kms:", var.logs_kms_key_arn))
    error_message = "logs_kms_key_arn must be a valid KMS key ARN."
  }
}

variable "create_kms_key" {
  description = "Create a dedicated KMS key for certificate encryption"
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Renewal Configuration
# ------------------------------------------------------------------------------

variable "renewal_days_before_expiry" {
  description = "Number of days before certificate expiry to trigger renewal. Let's Encrypt certs are valid for 90 days."
  type        = number
  default     = 30

  validation {
    condition     = var.renewal_days_before_expiry >= 7 && var.renewal_days_before_expiry <= 60
    error_message = "Renewal days must be between 7 and 60."
  }
}

variable "renewal_schedule" {
  description = "CloudWatch Events schedule expression for renewal checks (e.g., 'rate(1 day)' or 'cron(0 4 * * ? *)')"
  type        = string
  default     = "rate(1 day)"
}

# ------------------------------------------------------------------------------
# Alerting Configuration
# ------------------------------------------------------------------------------

variable "alert_emails" {
  description = "Email addresses to receive certificate alerts"
  type        = list(string)
  default     = []
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for certificate alerts (stored in Secrets Manager)"
  type        = string
  default     = null
  sensitive   = true
}

variable "existing_sns_topic_arn" {
  description = "Existing SNS topic ARN for alerts. If not provided, a new topic will be created."
  type        = string
  default     = null
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds. ACME operations can take time due to DNS propagation (60s+ per domain)."
  type        = number
  default     = 600

  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 60 and 900 seconds."
  }
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory >= 128 && var.lambda_memory <= 1024
    error_message = "Lambda memory must be between 128 and 1024 MB."
  }
}

variable "lambda_log_retention_days" {
  description = "CloudWatch Logs retention period for Lambda logs"
  type        = number
  default     = 30
}

# ------------------------------------------------------------------------------
# Networking (Optional - for VPC Lambda)
# ------------------------------------------------------------------------------

variable "vpc_id" {
  description = "VPC ID if Lambda should run in VPC (for private Route 53 zones)"
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs for Lambda VPC configuration"
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Security group IDs for Lambda VPC configuration"
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------------------
# Tags
# ------------------------------------------------------------------------------

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
