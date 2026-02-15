# License Events Module Variables
# SNS/SQS configuration for license change notifications

# ==================== Environment ====================

variable "name_prefix" {
  description = "Prefix for resource names (e.g., nhp-sandbox)"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell-1)"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ==================== Access Control ====================

variable "console_service_role_arn" {
  description = "IAM role ARN for console service (allowed to publish to SNS topic)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]+:role/.+$", var.console_service_role_arn))
    error_message = "console_service_role_arn must be a valid IAM role ARN."
  }
}

# ==================== Encryption ====================

variable "kms_key_arn" {
  description = "KMS key ARN for encryption (uses AWS managed key if not provided)"
  type        = string
  default     = null
}

# ==================== Monitoring ====================

variable "enable_dlq_alarm" {
  description = "Enable CloudWatch alarm for dead letter queue messages"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms (optional)"
  type        = string
  default     = null
}
