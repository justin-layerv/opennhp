# Traefik Plugins Deploy Module - Variables
#
# Infrastructure for out-of-band Traefik plugin deployment to AC instances
# via SSM documents (deploy + rollback) with a dedicated GitHub Actions role.

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "Environment must be 'sandbox' or 'prod'."
  }
}

variable "name_prefix" {
  description = "Resource naming prefix (e.g., layerv-nhp-sandbox)"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "aws_account_id" {
  description = "AWS account ID (for S3 bucket naming and IAM ARNs)"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

variable "aws_region" {
  description = "AWS region for IAM policy resource ARNs"
  type        = string
}

variable "github_oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider (from ecr module)"
  type        = string
}

variable "github_org" {
  description = "GitHub organization name"
  type        = string
  default     = "layervai"
}

variable "github_repo" {
  description = "GitHub repository name for traefik-plugins"
  type        = string
  default     = "traefik-plugins"
}

variable "ac_instance_tag_names" {
  description = "List of Name tag values for AC instances (for SSM SendCommand targeting)"
  type        = list(string)
}

variable "terraform_state_bucket" {
  description = "S3 bucket name for Terraform state access"
  type        = string
  default     = ""
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "terraform-state-lock"
}

variable "boot_time_plugins_bucket_arn" {
  description = "ARN of the boot-time plugins S3 bucket (layerv-nhp-{env}-plugins, from plugins module)"
  type        = string
}

variable "boot_time_plugins_kms_key_arn" {
  description = "ARN of the KMS key used to encrypt the boot-time plugins S3 bucket. Required for S3 PutObject when bucket uses KMS encryption."
  type        = string
  default     = null
}
