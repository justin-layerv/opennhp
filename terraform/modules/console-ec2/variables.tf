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

variable "console_image_repo" {
  description = "ECR repository URL for console server (without tag). Tag is read from SSM at boot."
  type        = string
}

variable "console_image_tag_ssm_param" {
  description = "SSM parameter name containing the Console image tag. Read at boot for dynamic updates."
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
    host     = string
    port     = number
    protocol = string
  }))
  default = []
}

# ============================================================================
# NHP Server Assignment Configuration
# ============================================================================

variable "nhp_server_assignment_enabled" {
  description = <<-EOT
    Enable NHP server assignment for ACs. When enabled, Console automatically
    assigns NHP servers to ACs using DynamoDB for storage and CloudMap for
    server discovery. Servers are selected from different availability zones
    for high availability.
    Required (must be explicitly set). Recommended: true
  EOT
  type        = bool
  # No default - must be explicitly configured
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables and CloudMap namespace. Required. Recommended: match deployment region."
  type        = string
  # No default - must be explicitly configured
}

variable "nhp_dynamodb_ac_assignments_table" {
  description = "DynamoDB table name for AC server assignments"
  type        = string
  default     = null # Uses environment-specific name from dynamodb module
}

variable "nhp_dynamodb_server_ac_index_table" {
  description = "DynamoDB table name for server-to-AC index"
  type        = string
  default     = null # Uses environment-specific name from dynamodb module
}

variable "nhp_dynamodb_licenses_table" {
  description = "DynamoDB table name for license validation. Used to seed Console AC license. Recommended: '{env}-nhp-licenses'"
  type        = string
  default     = null # Optional - only needed if using license validation
}

variable "nhp_dynamodb_resources_table" {
  description = "DynamoDB table name for resource definitions. Required for cloud mode. Recommended: '{env}-nhp-resources'"
  type        = string
  default     = null # Optional - only needed in cloud mode
}

variable "nhp_cloudmap_namespace" {
  description = "CloudMap namespace for NHP server discovery (e.g., 'nhp.sandbox.internal')"
  type        = string
  # No default - must be passed from environment (module.data.namespace_name)
}

variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers. Required. Recommended: 'server'"
  type        = string
  # No default - must be explicitly configured
}

variable "nhp_assignment_servers_per_ac" {
  description = "Number of servers to assign per AC for redundancy. Required. Recommended: 3 (one per AZ)."
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_assignment_servers_per_ac >= 1
    error_message = "nhp_assignment_servers_per_ac must be at least 1."
  }
}

variable "nhp_assignment_require_distinct_azs" {
  description = "Require assigned servers to be in different AZs for HA. Required. Recommended: true for production."
  type        = bool
  # No default - must be explicitly configured
}

variable "nhp_health_monitor_check_interval" {
  description = "Interval in seconds between NHP health monitor checks. Required. Recommended: 60 (check every minute)."
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_health_monitor_check_interval >= 1
    error_message = "nhp_health_monitor_check_interval must be at least 1 second."
  }
}

variable "nhp_health_monitor_operation_timeout" {
  description = "Timeout in seconds for each health monitor operation. Required. Recommended: 30 seconds."
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_health_monitor_operation_timeout >= 1
    error_message = "nhp_health_monitor_operation_timeout must be at least 1 second."
  }
}

variable "nhp_console_ac_enabled" {
  description = "Enable Console's embedded AC self-registration in DynamoDB. Required. Recommended: true for Console EC2 deployments."
  type        = bool
  # No default - must be explicitly configured
}

variable "nhp_console_ac_customer_id" {
  description = "Customer ID (ULID format) for Console's embedded AC registration. LayerV system uses nil ULID."
  type        = string
  default     = "00000000000000000000000000" # Nil ULID for LayerV system customer
}

variable "nhp_console_ac_license_key_hash" {
  description = "Bcrypt hash of the Console AC license key. REQUIRED - AC registration will fail without it. Generate with: terraform/scripts/generate-console-ac-license.sh"
  type        = string
  sensitive   = true
  default     = null
}

variable "nhp_console_ac_license_key_sha256" {
  description = "SHA256 hash of the Console AC license key. REQUIRED for DynamoDB license lookup. Generate with: terraform/scripts/generate-console-ac-license.sh"
  type        = string
  sensitive   = true
  default     = null
}

variable "nhp_console_ac_license_secret_arn" {
  description = "ARN of Secrets Manager secret containing Console AC license key. Console AC reads this at boot."
  type        = string
  default     = null
}

variable "nhp_dynamodb_licenses_customer_index" {
  description = "GSI name for querying licenses by customer_id. Recommended: 'customer_id-index'"
  type        = string
  default     = null
}

variable "nhp_dynamodb_licenses_auth0_subject_index" {
  description = "GSI name for querying licenses by auth0_subject. Required for QURL quota lookup. Recommended: 'auth0_subject-index'"
  type        = string
  default     = null
}

# ============================================================================
# Internal Service Authentication
# ============================================================================

variable "internal_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the internal service token. Used for Auth0 Actions to call Console API."
  type        = string
  default     = null
}

variable "provisioning_resource_id" {
  description = "Resource ID for auto-provisioned licenses. Recommended: 'qurl-auto-provisioned'"
  type        = string
  default     = null
}

variable "provisioning_default_tier" {
  description = "Default license tier for new customers. Must be: free, pro, enterprise, or system. Recommended: 'free'"
  type        = string
  default     = null

  validation {
    condition     = var.provisioning_default_tier == null ? true : contains(["free", "pro", "enterprise", "system"], var.provisioning_default_tier)
    error_message = "provisioning_default_tier must be one of: free, pro, enterprise, system"
  }
}

variable "provisioning_default_max_acs" {
  description = "Default MaxACs limit for new customers. 0 = unlimited. Recommended: 1 (for free tier)"
  type        = number
  default     = null

  validation {
    condition     = var.provisioning_default_max_acs == null ? true : var.provisioning_default_max_acs >= 0
    error_message = "provisioning_default_max_acs must be non-negative"
  }
}

variable "log_level" {
  description = "NHP AC log level: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

# ============================================================================
# NHP Protection Configuration (Network-Level Hiding)
# NHP protection is always enabled on Console EC2. This configures iptables
# DROP by default, with port 443 only accessible after NHP knock adds the
# user's IP to ipset.
# ============================================================================

variable "internal_only" {
  description = "Make Console internal-only (behind AC/NHP protection). When true, uses internal NLB, private subnets, HTTP-only mode."
  type        = bool
  default     = false
}

variable "nhp_server_secret_arn" {
  description = "ARN of NHP Server secret in Secrets Manager (for public key). Required for Console login flow."
  type        = string
  default     = null
}

variable "nhp_ac_repo_url" {
  description = "ECR URL for nhp-ac image (to extract nhp-acd binary). Required for Console login flow."
  type        = string
  default     = null
}

variable "nhp_ac_ecr_repo_arn" {
  description = "ECR repository ARN for nhp-ac image (for IAM permissions). Required for Console login flow."
  type        = string
  default     = null
}

variable "ac_image_tag_ssm_param" {
  description = "SSM parameter name containing the AC image tag. Read at boot for dynamic updates (same pattern as console_image_tag_ssm_param)."
  type        = string
}

variable "protected_hosted_zone_id" {
  description = "Route 53 hosted zone ID for the protected domain (e.g., apps.layerv.xyz zone). Required for NHP protection."
  type        = string
  default     = null
}

variable "nhp_server_cloudmap_dns" {
  description = "NHP Server Cloud Map internal DNS (e.g., server.nhp.sandbox.internal). Used for AC registration in cloud mode. Console uses this instead of public NLB since it's in the same VPC as NHP Servers."
  type        = string
  default     = null
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

variable "protected_hostname" {
  description = "NHP-protected Console hostname (e.g., 'console2.apps.layerv.xyz'). This is where users are redirected after auth_code knock."
  type        = string
  default     = null
}

variable "nhp_server_endpoint" {
  description = "NHP Server HTTP endpoint for /plugins/* routing (e.g., server.nhp.sandbox.internal:8888)"
  type        = string
  default     = null
}

variable "etcd_endpoint" {
  description = "etcd endpoint for on-prem deployments using etcd storage backend (e.g., https://etcd.internal:2379). Required when storage.backend=etcd."
  type        = string
  default     = null
}

variable "etcd_tls_secret_arn" {
  description = "Secrets Manager ARN containing etcd TLS certificates (caCert, clientCert, clientKey). Required when etcd_endpoint is set."
  type        = string
  default     = null
}

# ============================================================================
# Database Auto-Initialization Configuration
# ============================================================================

variable "admin_password" {
  description = "Admin user password for Console. Passed via GVA_ADMIN_PASSWORD for initial setup."
  type        = string
  sensitive   = true
  default     = null
}

variable "auth_signing_key" {
  description = "JWT signing key for Console authentication. Must match Console's jwt.signing-key in config.yaml."
  type        = string
  sensitive   = true
  default     = null
}

variable "ac_id" {
  description = "AC identifier for knock routing. Must match the ac_id configured in the AC module."
  type        = string
  default     = "layerv-ac-tf"
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
