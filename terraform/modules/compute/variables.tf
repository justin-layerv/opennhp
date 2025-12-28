variable "environment" {
  description = "Environment name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode"
  type        = bool
}

variable "min_capacity" {
  description = "Minimum ASG capacity"
  type        = number
}

variable "max_capacity" {
  description = "Maximum ASG capacity"
  type        = number
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for NLB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ASG"
  type        = list(string)
}

variable "server_repo_url" {
  description = "ECR repository URL for NHP server"
  type        = string
}

variable "server_repo_arn" {
  description = "ECR repository ARN for NHP server"
  type        = string
}

variable "etcd_endpoint" {
  description = "etcd endpoint"
  type        = string
  default     = null
}

variable "etcd_secret_arn" {
  description = "etcd secret ARN"
  type        = string
  default     = null
}

variable "etcd_tls_secret_arn" {
  description = "etcd TLS certificates secret ARN"
  type        = string
  default     = null
}

variable "namespace_id" {
  description = "Service Discovery namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Service Discovery namespace name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  type        = string
  default     = null
}

# ============================================================================
# NHP Server Configuration Options
# These options control the server's authentication and resource management
# ============================================================================

variable "dev_mode" {
  description = "Enable development mode for the NHP server"
  type        = bool
  default     = false
}

variable "resource_mode" {
  description = "Resource management mode: 'local' (config file) or 'api' (external auth service)"
  type        = string
  default     = "local"
  validation {
    condition     = contains(["local", "api"], var.resource_mode)
    error_message = "resource_mode must be either 'local' or 'api'"
  }
}

variable "auth_url" {
  description = "URL of the external authentication service (required when resource_mode is 'api')"
  type        = string
  default     = null
}

variable "auth_signing_key" {
  description = "Signing key for authentication tokens (required when resource_mode is 'api')"
  type        = string
  default     = null
  sensitive   = true
}

variable "auth_aes_key" {
  description = "AES encryption key for authentication (required when resource_mode is 'api')"
  type        = string
  default     = null
  sensitive   = true
}

# ============================================================================
# Deployment Configuration
# ============================================================================

variable "image_tag" {
  description = "Docker image tag to deploy (defaults to 'latest', set to commit SHA for immutable deployments)"
  type        = string
  default     = "latest"
}

# ============================================================================
# Plugin Configuration
# NHP Server plugins (passcode, oidc, etc.) are deployed via S3.
# The plugins module manages the S3 bucket and config rendering.
# ============================================================================

variable "plugin_bucket_name" {
  description = "Name of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_bucket_arn" {
  description = "ARN of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_download_policy_arn" {
  description = "ARN of the IAM policy for downloading plugins (from plugins module)"
  type        = string
  default     = null
}

variable "server_plugins" {
  description = <<-EOT
    Map of NHP Server plugins with their S3 keys (from plugins module output).
    Example:
    server_plugins = {
      passcode = {
        version    = "v1.0.0"
        binary_key = "nhp-server/passcode/v1.0.0/main.so"
        config_key = "configs/nhp-server/passcode/config.toml"
      }
    }
  EOT
  type = map(object({
    version    = string
    binary_key = string
    config_key = string
  }))
  default = {}
}
