# Billing Module Variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for all resources"
  type        = map(string)
  default     = {}
}

# ==============================================================================
# Encryption
# ==============================================================================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
}

variable "sqs_kms_key_arn" {
  description = "KMS key ARN for SQS encryption. If null, uses AWS managed key."
  type        = string
  default     = null
}

variable "dynamodb_kms_key_arn" {
  description = "KMS CMK ARN for DynamoDB encryption. If null, uses AWS managed key."
  type        = string
  default     = null
}

# ==============================================================================
# Auth0 / JWT
# ==============================================================================

variable "auth0_domain" {
  description = "Auth0 domain for JWT authorizer (e.g., auth.layerv.ai)"
  type        = string
}

variable "auth0_audience" {
  description = "Auth0 API audience for JWT validation"
  type        = string

  validation {
    condition     = var.auth0_audience != null && var.auth0_audience != ""
    error_message = "auth0_audience must be set to the Auth0 API identifier."
  }
}

# ==============================================================================
# Stripe Secrets
# ==============================================================================

variable "stripe_secret_name" {
  description = "Secrets Manager secret name for Stripe API key (contains secret_key)"
  type        = string
}

variable "stripe_webhook_secret_name" {
  description = "Secrets Manager secret name for Stripe webhook signing secret"
  type        = string
}

variable "stripe_api_base_url" {
  description = "Base URL for Stripe API. Override for testing."
  type        = string
  default     = "https://api.stripe.com"
}

# ==============================================================================
# DynamoDB
# ==============================================================================

variable "customers_table_name" {
  description = "DynamoDB customers table name"
  type        = string
}

variable "customers_table_arn" {
  description = "DynamoDB customers table ARN"
  type        = string
}

variable "billing_audit_table_name" {
  description = "DynamoDB billing audit table name. If empty, audit writes are skipped."
  type        = string
  default     = ""
}

variable "billing_audit_table_arn" {
  description = "DynamoDB billing audit table ARN. Required when billing_audit_table_name is set."
  type        = string
  default     = ""

  validation {
    condition     = var.billing_audit_table_name == "" || var.billing_audit_table_arn != ""
    error_message = "billing_audit_table_arn is required when billing_audit_table_name is set."
  }
}

# ==============================================================================
# Stripe Price IDs
# ==============================================================================

variable "growth_price_id" {
  description = "Stripe Price ID for the Growth plan metered usage component. Empty until Stripe products are created — checkout Lambda validates at runtime."
  type        = string
  default     = ""
}

variable "base_fee_price_id" {
  description = "Stripe Price ID for the Growth plan base fee (flat monthly). Empty until Stripe products are created; if empty at runtime, no base fee line item is added to checkout."
  type        = string
  default     = ""
}

# ==============================================================================
# URLs
# ==============================================================================

variable "success_url" {
  description = "URL to redirect to after successful Stripe Checkout"
  type        = string
}

variable "cancel_url" {
  description = "URL to redirect to when user cancels Stripe Checkout"
  type        = string
}

# ==============================================================================
# CORS
# ==============================================================================

variable "allowed_origins" {
  description = "List of allowed CORS origins"
  type        = list(string)

  validation {
    condition     = length(var.allowed_origins) > 0
    error_message = "allowed_origins must contain at least one origin."
  }
}

# ==============================================================================
# Email (SES)
# ==============================================================================

variable "from_email" {
  description = "SES verified sender email address for grace period notifications"
  type        = string
}

variable "ses_region" {
  description = "AWS region for SES (may differ from deployment region)"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d$", var.ses_region))
    error_message = "ses_region must be a valid AWS region (e.g., us-east-1)"
  }
}

# ==============================================================================
# Monitoring
# ==============================================================================

variable "metrics_namespace" {
  description = "CloudWatch metrics namespace for billing business metrics"
  type        = string
  default     = "LayerV/Billing"
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms. If null, alarms are not created."
  type        = string
  default     = null
}

# ==============================================================================
# Grace Period Configuration
# ==============================================================================

variable "grace_period_days" {
  description = "Days after payment failure before account is frozen"
  type        = number
  default     = 7

  validation {
    condition     = var.grace_period_days >= 1 && var.grace_period_days <= 30
    error_message = "grace_period_days must be between 1 and 30"
  }
}

variable "downgrade_after_days" {
  description = "Days after account freeze before downgrade to free tier"
  type        = number
  default     = 30

  validation {
    condition     = var.downgrade_after_days >= 7 && var.downgrade_after_days <= 90
    error_message = "downgrade_after_days must be between 7 and 90"
  }
}

# ==============================================================================
# Throttling
# ==============================================================================

variable "api_throttle_burst_limit" {
  description = "API Gateway default throttle burst limit"
  type        = number
  default     = 50
}

variable "api_throttle_rate_limit" {
  description = "API Gateway default throttle rate limit"
  type        = number
  default     = 25
}
