# ==============================================================================
# Custom Domain Certificate Manager Variables
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
# ACME Configuration
# ------------------------------------------------------------------------------

variable "acme_base_domain" {
  description = "Base domain for ACME delegation zone (e.g., layerv.xyz for sandbox, layerv.ai for prod)"
  type        = string
}

variable "parent_zone_id" {
  description = "Route53 hosted zone ID of the parent domain (e.g., the layerv.xyz zone) for NS delegation of the acme sub-zone"
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
  description = "KMS CMK ARN for encrypting certificate secrets. If null, uses default AWS-managed key."
  type        = string
  default     = null
}

variable "has_kms_key" {
  description = "Static boolean: set true when kms_key_arn is provided (avoids count-depends-on-computed)"
  type        = bool
  default     = false
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

# ------------------------------------------------------------------------------
# DynamoDB Configuration
# ------------------------------------------------------------------------------

variable "qurl_domains_table_name" {
  description = "DynamoDB table name for QURL domains (for status updates)"
  type        = string
}

variable "qurl_domains_table_arn" {
  description = "DynamoDB table ARN for QURL domains (for IAM policy)"
  type        = string
}

# ------------------------------------------------------------------------------
# SSM Configuration
# ------------------------------------------------------------------------------

variable "ac_instance_tag" {
  description = "Tag name:value to target AC instances for SSM SendCommand (e.g., 'layerv-nhp-sandbox-ac')"
  type        = string
}

# ------------------------------------------------------------------------------
# Alerting Configuration
# ------------------------------------------------------------------------------

variable "existing_sns_topic_arn" {
  description = "Existing SNS topic ARN for alerts. If not provided, a new topic will be created."
  type        = string
  default     = null
}

variable "use_existing_sns_topic" {
  description = "Static boolean: set true when existing_sns_topic_arn is provided (avoids count-depends-on-computed)"
  type        = bool
  default     = false
}

variable "cleanup_topic_arn" {
  description = "SNS topic ARN that the lambda subscribes to for domain.cleanup events (nhp#1990 / qurl-service#148). Owned at the env level to avoid a module cycle (qurl-service consumes this ARN via module.nhp). Empty disables the subscription and leaves the lambda EventBridge-only."
  type        = string
  default     = ""

  validation {
    condition     = var.cleanup_topic_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$", var.cleanup_topic_arn))
    error_message = "cleanup_topic_arn must be a valid SNS topic ARN or empty."
  }
}

variable "alert_emails" {
  description = "Email addresses to receive certificate alerts"
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------------------
# SSM Parameter Store Configuration
# ------------------------------------------------------------------------------

variable "ssm_cert_prefix" {
  description = "SSM Parameter Store path prefix for custom domain certificate params"
  type        = string
  default     = "/nhp/certs"
}

# ------------------------------------------------------------------------------
# Tags
# ------------------------------------------------------------------------------

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
