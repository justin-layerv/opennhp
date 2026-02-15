# RDS Aurora PostgreSQL Serverless v2 Module Variables

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for security group rules"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for RDS"
  type        = list(string)
}

variable "database_name" {
  description = "Name of the default database to create"
  type        = string
  default     = "portal"
}

variable "master_username" {
  description = "Master username for the database"
  type        = string
  default     = "portal"
}

variable "min_capacity" {
  description = "Minimum Aurora Serverless v2 capacity (ACUs). 0.5 is the minimum."
  type        = number
  default     = 0.5
}

variable "max_capacity" {
  description = "Maximum Aurora Serverless v2 capacity (ACUs). 128 is the maximum."
  type        = number
  default     = 4

  validation {
    condition     = var.max_capacity >= 0.5 && var.max_capacity <= 128
    error_message = "Max capacity must be between 0.5 and 128 ACUs."
  }
}

variable "backup_retention_period" {
  description = "Days to retain automated backups"
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot when destroying"
  type        = bool
  default     = false
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for encrypting secrets"
  type        = string
}

variable "storage_kms_key_arn" {
  description = "KMS key ARN for encrypting RDS storage (optional, uses AWS managed key if not specified)"
  type        = string
  default     = null
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights"
  type        = bool
  default     = true
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention period in days (7 for free tier, 731 max)"
  type        = number
  default     = 7
}

variable "allowed_security_group_ids" {
  description = "Additional security group IDs allowed to connect to RDS"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
