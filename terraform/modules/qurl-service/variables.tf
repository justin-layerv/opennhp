# QURL Service Module Variables
# ECS Fargate deployment for the QURL API service

# ==================== Environment ====================

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

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
  description = "VPC CIDR block"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for ALB"
  type        = list(string)
}

# ==================== Container ====================

variable "ecr_repo_url" {
  description = "ECR repository URL for qurl-api image"
  type        = string
}

variable "image_tag_ssm_param" {
  description = "SSM parameter name containing the image tag (e.g., /nhp-sandbox/qurl-api-image-tag)"
  type        = string
}

variable "container_cpu" {
  description = "CPU units for container (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "container_memory" {
  description = "Memory in MB for container"
  type        = number
  default     = 512
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 1
}

variable "autoscaling_min_capacity" {
  description = "Minimum number of ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 2
}

variable "autoscaling_max_capacity" {
  description = "Maximum number of ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 10
}

# ==================== DynamoDB ====================

variable "dynamodb_table_arns" {
  description = "List of DynamoDB table ARNs for IAM permissions"
  type        = list(string)
}

variable "dynamodb_table_prefix" {
  description = "Prefix for DynamoDB table names (passed to container)"
  type        = string
  default     = ""
}

# ==================== Auth0 ====================

variable "auth0_domain" {
  description = "Auth0 domain for JWT validation"
  type        = string
}

variable "auth0_audience" {
  description = "Auth0 audience for JWT validation"
  type        = string
  default     = "https://api.layerv.ai"
}

# ==================== Secrets ====================

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager"
  type        = string
  default     = null
}

variable "jwt_secret_arn" {
  description = "Secrets Manager ARN for JWT signing secret"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.jwt_secret_arn))
    error_message = "jwt_secret_arn must be a valid Secrets Manager ARN (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME)."
  }
}

variable "internal_service_token_arn" {
  description = "Secrets Manager ARN for internal service token"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.internal_service_token_arn))
    error_message = "internal_service_token_arn must be a valid Secrets Manager ARN (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME)."
  }
}

# ==================== KMS ====================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "alb_access_logs_bucket" {
  description = "S3 bucket name for ALB access logs. If not provided, access logging is disabled."
  type        = string
  default     = null
}

# ==================== QURL Defaults ====================

variable "cookie_domain" {
  description = "Cookie domain for NHP tokens (e.g., .qurl.site)"
  type        = string
  default     = ".qurl.site"
}

variable "default_token_expire" {
  description = "Default JWT token expiration in seconds"
  type        = number
  default     = 3600
}

variable "default_open_time" {
  description = "Default firewall open time in seconds"
  type        = number
  default     = 300
}

# ==================== AC Fleet ====================

variable "default_ac_id" {
  description = "Default AC identifier for new resources"
  type        = string
}

variable "default_ac_host" {
  description = "Default AC hostname for new resources"
  type        = string
}

variable "default_ac_port" {
  description = "Default AC port for new resources"
  type        = number
  default     = 443
}

# ==================== Domain ====================

variable "domain_name" {
  description = "Domain name for the QURL API (e.g., api.qurl.link)"
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for the domain"
  type        = string
  default     = null
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS (must be in same region)"
  type        = string
  default     = null
}
