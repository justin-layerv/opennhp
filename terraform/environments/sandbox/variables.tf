# Variables for sandbox environment
# Values are set in terraform.tfvars

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "aws_account_id" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "hosted_zone" {
  type    = string
  default = null
}

variable "multi_tenant" {
  type = bool
}

variable "min_capacity" {
  type = number
}

variable "max_capacity" {
  type = number
}

variable "vpc_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "is_primary_account" {
  type    = bool
  default = true
}

variable "primary_account_id" {
  type    = string
  default = ""
}

variable "github_org" {
  type    = string
  default = "layervai"
}

variable "github_repo" {
  type    = string
  default = "nhp"
}

variable "deploy_ac" {
  type    = bool
  default = true
}

variable "acme_email" {
  type    = string
  default = ""
}

variable "terraform_state_bucket" {
  type    = string
  default = ""
}

variable "terraform_lock_table" {
  type    = string
  default = "terraform-state-lock"
}

# AC configuration
variable "ac_auth_service_id" {
  type    = string
  default = "layerv"
}

variable "ac_resource_ids" {
  type    = list(string)
  default = ["default"]
}

# Security services
variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail. Set to false if SCP blocks cloudtrail operations."
  type        = bool
  default     = true
}

# GitHub OIDC
variable "create_oidc_provider" {
  description = "Create GitHub OIDC provider. Set to false if org manages centrally or SCP blocks creation."
  type        = bool
  default     = true
}

# Server configuration
variable "dev_mode" {
  type    = bool
  default = false
}

variable "resource_mode" {
  type    = string
  default = "local"
}

variable "auth_url" {
  type    = string
  default = null
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

# Monitoring
variable "enable_slack_notifications" {
  type    = bool
  default = false
}

variable "slack_workspace_id" {
  type    = string
  default = ""
}

variable "slack_channel_id" {
  type    = string
  default = ""
}

# RDS configuration
variable "deploy_rds" {
  type    = bool
  default = false
}

variable "rds_database_name" {
  type    = string
  default = "portal"
}

variable "rds_min_capacity" {
  type    = number
  default = 0.5
}

variable "rds_max_capacity" {
  type    = number
  default = 4
}

variable "rds_deletion_protection" {
  type    = bool
  default = false # Allow deletion in sandbox
}

# Production domains
variable "production_domains" {
  type    = list(string)
  default = []
}

variable "production_zone_ids" {
  type    = list(string)
  default = []
}

# Deployment configuration
variable "image_tag" {
  description = "Docker image tag for NHP server and AC"
  type        = string
  default     = "latest"
}

# NHP Server plugins - statically compiled into server binary
variable "server_plugins" {
  description = "List of NHP Server plugins to enable (plugins are compiled into the server)"
  type        = list(string)
  default     = []
}

# Traefik plugins
variable "traefik_plugins" {
  description = "Map of Traefik plugins to deploy"
  type = map(object({
    version = string
    config  = optional(map(string), {})
  }))
  default = {}
}

# Plugin repos - repos that can assume the GitHub Actions role
variable "plugin_repos" {
  description = "Additional GitHub repos that can assume the GitHub Actions role"
  type        = list(string)
  default     = []
}

# Demo Gateway configuration
variable "deploy_demo_gateway" {
  description = "Deploy the Demo Gateway for qurl.link routing"
  type        = bool
  default     = false
}

variable "demo_gateway_domain" {
  description = "Domain name for Demo Gateway (e.g., qurl.link)"
  type        = string
  default     = null
}

variable "demo_gateway_hosted_zone_id" {
  description = "Route 53 hosted zone ID for Demo Gateway domain"
  type        = string
  default     = null
}

variable "demo_gateway_fallback_url" {
  description = "URL to redirect to when no appId is provided"
  type        = string
  default     = "https://layerv.ai/demo"
}

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN for cross-account Route 53 access"
  type        = string
  default     = null
}

# Console EC2 configuration
variable "deploy_console_ec2" {
  description = "Deploy Console on EC2"
  type        = bool
  default     = false
}

variable "console_ec2_domain" {
  description = "Domain name for Console EC2 (e.g., console.nhp.layerv.xyz)"
  type        = string
  default     = null
}

variable "console_cookie_domain" {
  description = "Cookie domain for Console (e.g., .layerv.xyz)"
  type        = string
  default     = null
}

variable "console_internal_only" {
  description = "Make Console internal-only (NHP-protected via AC)"
  type        = bool
  default     = false
}

variable "console_protected_hostname" {
  description = "NHP-protected Console hostname (e.g., 'console2.apps.layerv.xyz'). Where users redirect after auth_code knock."
  type        = string
  default     = null
}

variable "console_ac_license_key_hash" {
  description = "Bcrypt hash of Console AC license key for DynamoDB validation. Generate with: ./terraform/scripts/generate-console-ac-license.sh"
  type        = string
  sensitive   = true
  default     = ""
}

# TLS certificate configuration
variable "additional_tls_domains" {
  description = "Additional domains for TLS certificates in same account"
  type        = list(string)
  default     = []
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false)"
  type        = bool
  default     = null
}
