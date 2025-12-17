# Variables for LayerV NHP infrastructure
# Consistent with layerv/traefik-plugins terraform patterns

# ==================== Environment ====================

variable "environment" {
  description = "Environment name (staging, prod)"
  type        = string

  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "Environment must be 'staging' or 'prod'."
  }
}

# ==================== AWS Configuration ====================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., us-east-2)."
  }
}

variable "aws_account_id" {
  description = "AWS account ID (used for validation)"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

# ==================== Multi-Account Configuration ====================

variable "is_primary_account" {
  description = "Whether this is the primary account that owns ECR repositories (staging = true, prod = false)"
  type        = bool
  default     = true
}

variable "primary_account_id" {
  description = "AWS account ID of the primary account (staging). Required if is_primary_account = false"
  type        = string
  default     = ""

  validation {
    condition     = var.primary_account_id == "" || can(regex("^[0-9]{12}$", var.primary_account_id))
    error_message = "Primary account ID must be exactly 12 digits or empty."
  }
}

# ==================== NHP Configuration ====================

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.domain_name))
    error_message = "Domain name must be a valid hostname."
  }
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode with etcd"
  type        = bool
  default     = true
}

variable "min_capacity" {
  description = "Minimum ASG capacity"
  type        = number
  default     = 3

  validation {
    condition     = var.min_capacity >= 1 && var.min_capacity <= 100
    error_message = "Min capacity must be between 1 and 100."
  }
}

variable "max_capacity" {
  description = "Maximum ASG capacity"
  type        = number
  default     = 10

  validation {
    condition     = var.max_capacity >= 1 && var.max_capacity <= 100
    error_message = "Max capacity must be between 1 and 100."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.100.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

# ==================== GitHub Configuration ====================

variable "github_org" {
  description = "GitHub organization name"
  type        = string
  default     = "layervai"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "nhp"
}

# ==================== Common Tags ====================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
