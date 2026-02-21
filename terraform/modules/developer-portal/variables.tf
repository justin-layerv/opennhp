# Developer Portal Module Variables

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

variable "dynamodb_kms_key_arn" {
  description = "KMS key ARN for DynamoDB encryption. If null, uses AWS managed key."
  type        = string
  default     = null
}

# ==============================================================================
# Secrets Manager
# ==============================================================================

variable "playground_m2m_secret_name" {
  description = "Secrets Manager secret name for playground M2M credentials (client_id, client_secret, audience)"
  type        = string
}

variable "auth0_mgmt_secret_name" {
  description = "Secrets Manager secret name for Auth0 management API credentials"
  type        = string
}

# ==============================================================================
# QURL API
# ==============================================================================

variable "qurl_api_url" {
  description = "QURL API base URL (e.g., https://api.layerv.xyz)"
  type        = string
}

variable "auth0_domain" {
  description = "Auth0 domain for credential provisioner (e.g., auth.layerv.ai)"
  type        = string
}

variable "qurl_api_audience" {
  description = "Auth0 API audience for QURL API"
  type        = string

  validation {
    condition     = var.qurl_api_audience != null && var.qurl_api_audience != ""
    error_message = "qurl_api_audience must be set to the Auth0 API identifier (e.g., https://api.layerv.ai). Empty audience prevents credential provisioning."
  }
}

# ==============================================================================
# Email
# ==============================================================================

variable "from_email" {
  description = "SES verified sender email address"
  type        = string
}

variable "notify_email" {
  description = "Email address for admin notifications"
  type        = string
}

# ==============================================================================
# URLs
# ==============================================================================

variable "site_url" {
  description = "Website URL (e.g., https://staging.layerv.ai)"
  type        = string
}

variable "verify_url" {
  description = "Email verification URL - the keys page (e.g., https://staging.layerv.ai/qurl/keys)"
  type        = string
}

# ==============================================================================
# CORS
# ==============================================================================

variable "allowed_origins" {
  description = "List of allowed CORS origins"
  type        = list(string)
}

# ==============================================================================
# Custom Domain (optional)
# ==============================================================================

variable "custom_domain" {
  description = "Custom domain for API Gateway (e.g., dev-api.layerv.xyz). If null, uses default API Gateway URL."
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for custom domain. Required when custom_domain is set."
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for custom domain. Required when custom_domain is set."
  type        = string
  default     = null
}

# ==============================================================================
# Monitoring
# ==============================================================================

variable "sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms. If null, alarms are not created."
  type        = string
  default     = null
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

# ==============================================================================
# Rate Limiting (Lambda-level)
# ==============================================================================

variable "playground_ip_rate_limit" {
  description = "Max playground requests per IP per rate window"
  type        = number
  default     = 20
}

variable "playground_global_rate_limit" {
  description = "Max playground requests globally per rate window"
  type        = number
  default     = 500
}

variable "playground_rate_window" {
  description = "Playground rate limit window in seconds"
  type        = number
  default     = 3600
}

variable "registration_rate_limit_ip" {
  description = "Max registration attempts per IP per rate window"
  type        = number
  default     = 5
}

variable "registration_rate_window" {
  description = "Registration rate limit window in seconds"
  type        = number
  default     = 86400
}

variable "verify_rate_limit_ip" {
  description = "Max verification attempts per IP per rate window"
  type        = number
  default     = 10
}

variable "verify_rate_window" {
  description = "Verification rate limit window in seconds"
  type        = number
  default     = 3600
}

# ==============================================================================
# SES
# ==============================================================================

variable "ses_region" {
  description = "AWS region for SES (may differ from deployment region if SES identity is verified elsewhere)"
  type        = string
  default     = "us-east-1"
}
