# Demo Gateway Module Variables
# nginx + certbot for qurl.link routing to NHP Server HTTP plugins

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the Demo Gateway (e.g., qurl.link)"
  type        = string
}

variable "acme_email" {
  description = "Email for Let's Encrypt certificate registration"
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

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# Upstream Configuration
# ============================================================================

variable "nhp_server_endpoint" {
  description = "NHP Server endpoint for plugin HTTP requests (Cloud Map DNS or NLB DNS)"
  type        = string
}

variable "nhp_server_port" {
  description = "NHP Server HTTP port for plugin requests"
  type        = number
  default     = 8888
}

# ============================================================================
# Route 53 Configuration for ACME DNS-01 Challenge
# ============================================================================

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN in management account for cross-account Route 53 access (ACME DNS-01 challenges)"
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for the domain (for DNS-01 challenge and NLB record)"
  type        = string
  default     = null
}

# ============================================================================
# EC2 Configuration
# ============================================================================

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
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

# ============================================================================
# Fallback Landing Page
# ============================================================================

variable "fallback_url" {
  description = "URL to redirect to when accessing root path (e.g., https://layerv.ai/demo)"
  type        = string
  default     = "https://layerv.ai/demo"
}
