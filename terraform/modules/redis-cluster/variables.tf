# Redis Cluster Module Variables
# ElastiCache Serverless Redis configuration

# ==================== Environment ====================

variable "name_prefix" {
  description = "Prefix for resource names"
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

# ==================== Networking ====================

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for security group rules"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for Redis cluster"
  type        = list(string)
}

# ==================== Capacity ====================

variable "max_data_storage_gb" {
  description = "Maximum data storage in GB for ElastiCache Serverless"
  type        = number
  default     = 1

  validation {
    condition     = var.max_data_storage_gb >= 1 && var.max_data_storage_gb <= 5000
    error_message = "max_data_storage_gb must be between 1 and 5000 GB."
  }
}

variable "max_ecpu_per_second" {
  description = "Maximum ElastiCache Processing Units per second"
  type        = number
  default     = 1000

  validation {
    condition     = var.max_ecpu_per_second >= 1000 && var.max_ecpu_per_second <= 15000000
    error_message = "max_ecpu_per_second must be between 1000 and 15000000."
  }
}

# ==================== Backup ====================

variable "snapshot_retention_days" {
  description = "Number of days to retain automatic snapshots (0 to disable). Recommended: 7 for production workloads."
  type        = number
  default     = 7

  validation {
    condition     = var.snapshot_retention_days >= 0 && var.snapshot_retention_days <= 35
    error_message = "snapshot_retention_days must be between 0 and 35."
  }
}

# ==================== Encryption ====================

variable "kms_key_arn" {
  description = "KMS key ARN for encryption at rest (uses AWS managed key if not provided)"
  type        = string
  default     = null
}
