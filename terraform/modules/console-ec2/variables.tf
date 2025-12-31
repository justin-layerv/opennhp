# Console EC2 Module Variables
# Deploys the LayerV Console API on EC2 with nginx + Docker

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
  description = "Public subnet IDs for NLB and EC2"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (for RDS access)"
  type        = list(string)
}

# ============================================================================
# Console Application Configuration
# ============================================================================

variable "console_image" {
  description = "Docker image for console server (ECR URL with tag)"
  type        = string
}

variable "console_port" {
  description = "Port the console server listens on"
  type        = number
  default     = 8888
}

variable "cookie_domain" {
  description = "Cookie domain for portal sites"
  type        = string
  default     = ".layerv.ai"
}

# ============================================================================
# Database Configuration
# ============================================================================

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
  description = "RDS security group ID (for access rules)"
  type        = string
}

# ============================================================================
# Access Controllers Configuration
# ============================================================================

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

# ============================================================================
# NHP Protection Configuration
# ============================================================================

variable "internal_only" {
  description = "Make Console internal-only (behind AC/NHP protection). When true, uses internal NLB, private subnets, HTTP-only mode."
  type        = bool
  default     = false
}

variable "ac_security_group_id" {
  description = "Security group ID of AC instances (required when internal_only=true)"
  type        = string
  default     = null
}

variable "seed_console_resource" {
  description = "Seed the Console as a portal site in RDS for NHP protection"
  type        = bool
  default     = false
}

variable "console_app_id" {
  description = "App ID for Console resource in NHP (e.g., 'console')"
  type        = string
  default     = "console"
}

variable "ac_nlb_dns" {
  description = "AC NLB DNS name for resource routing (required when seed_console_resource=true)"
  type        = string
  default     = null
}

variable "ac_domain" {
  description = "AC domain suffix (e.g., '.nhp.layerv.xyz')"
  type        = string
  default     = ".nhp.layerv.xyz"
}

variable "nhp_server_endpoint" {
  description = "NHP Server HTTP endpoint for /plugins/* routing (e.g., server.nhp.sandbox.internal:8888)"
  type        = string
  default     = null
}

# ============================================================================
# Database Auto-Initialization Configuration
# ============================================================================

variable "auto_init" {
  description = "Enable automatic database initialization on first deployment. Creates admin user and seeds initial data."
  type        = bool
  default     = true
}

variable "admin_password" {
  description = "Admin user password for Console. If not provided, a random password will be generated and logged."
  type        = string
  sensitive   = true
  default     = null
}

# ============================================================================
# Domain and TLS Configuration
# ============================================================================

variable "domain_name" {
  description = "Domain name for console API (e.g., console.nhp.layerv.xyz)"
  type        = string
}

variable "acme_email" {
  description = "Email for Let's Encrypt certificate registration"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for the domain"
  type        = string
  default     = null
}

# ============================================================================
# EC2 Configuration
# ============================================================================

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
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
# ECR Configuration
# ============================================================================

variable "ecr_repo_arn" {
  description = "ECR repository ARN for console image (for IAM permissions)"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
