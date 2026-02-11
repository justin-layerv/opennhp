# Status Page Module Variables

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
# Domain & DNS
# ==============================================================================

variable "status_domain" {
  description = "Domain for the status page (e.g., status.layerv.xyz). If null, only CloudFront domain is used."
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for the status domain. Required when status_domain is set."
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the status domain (must be in us-east-1 for CloudFront). If null, CloudFront default certificate is used (no custom domain)."
  type        = string
  default     = null
}

# ==============================================================================
# SSM & Monitoring
# ==============================================================================

variable "ssm_prefix" {
  description = "SSM parameter path prefix (e.g., /sandbox/nhp)"
  type        = string
}

variable "alarm_name_prefix" {
  description = "CloudWatch alarm name prefix for filtering relevant alarms"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for deployment event notifications"
  type        = string
}

# ==============================================================================
# Target Group ARNs (for health checks)
# ==============================================================================

variable "server_nlb_tg_arns" {
  description = "Server NLB target group ARNs to check health (blue, optionally green)"
  type        = list(string)
  default     = []
}

variable "ac_nlb_tg_arns" {
  description = "AC NLB target group ARNs to check health (blue, optionally green)"
  type        = list(string)
  default     = []
}

# ==============================================================================
# Encryption
# ==============================================================================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
}
