# NHP Keypair Module Variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "KMS key ARN for SSM SecureString encryption. If null, AWS managed key is used."
  type        = string
  default     = null
}
