# Console Application Module Variables
# Deploys the LayerV Console (Gin-Vue-Admin portal management)

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
  description = "VPC CIDR block"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for ALB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "console_image" {
  description = "Docker image for console server"
  type        = string
}

variable "console_port" {
  description = "Port the console server listens on"
  type        = number
  default     = 8888
}

# Database configuration
variable "rds_endpoint" {
  description = "RDS cluster endpoint"
  type        = string
}

variable "rds_port" {
  description = "RDS port"
  type        = number
  default     = 5432
}

variable "rds_database_name" {
  description = "RDS database name"
  type        = string
}

variable "rds_secret_arn" {
  description = "Secrets Manager ARN for RDS credentials"
  type        = string
}

variable "rds_security_group_id" {
  description = "RDS security group ID (for access)"
  type        = string
}

# Access Controllers configuration
variable "ac_configs" {
  description = "List of AC configurations for portal sites"
  type = list(object({
    id       = string
    ip       = string
    port     = number
    protocol = string
  }))
  default = []
}

# Domain configuration
variable "domain_name" {
  description = "Domain name for console (e.g., console.layerv.xyz)"
  type        = string
  default     = null
}

variable "hosted_zone" {
  description = "Route 53 hosted zone name"
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS (if not provided, uses HTTP only)"
  type        = string
  default     = null
}

variable "cookie_domain" {
  description = "Cookie domain for portal sites"
  type        = string
  default     = ".layerv.ai"
}

# ECS configuration
variable "cpu" {
  description = "CPU units for ECS task (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Memory for ECS task in MB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 1
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
