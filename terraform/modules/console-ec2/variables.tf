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
# NHP Server Assignment Configuration
# ============================================================================

variable "nhp_server_assignment_enabled" {
  description = <<-EOT
    Enable NHP server assignment for ACs. When enabled, Console automatically
    assigns NHP servers to ACs using DynamoDB for storage and CloudMap for
    server discovery. Servers are selected from different availability zones
    for high availability.
  EOT
  type        = bool
  default     = true
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables and CloudMap namespace"
  type        = string
  default     = "us-east-2"
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
  description = "DynamoDB table name for license validation. Used to seed Console AC license."
  type        = string
  default     = null
}

variable "nhp_cloudmap_namespace" {
  description = "CloudMap namespace for NHP server discovery"
  type        = string
  default     = "nhp.internal"
}

variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers"
  type        = string
  default     = "nhp-servers"
}

variable "nhp_assignment_servers_per_ac" {
  description = "Number of servers to assign per AC for redundancy (typically 3 for multi-AZ)"
  type        = number
  default     = 3
}

variable "nhp_health_monitor_check_interval" {
  description = "Interval in seconds between NHP health monitor checks. The monitor queries Cloud Map for unhealthy servers and reassigns affected ACs. Must be >= 1."
  type        = number
  default     = 60 # Matches Console's DefaultNHPConfig()

  validation {
    condition     = var.nhp_health_monitor_check_interval >= 1
    error_message = "nhp_health_monitor_check_interval must be at least 1 second."
  }
}

variable "nhp_health_monitor_operation_timeout" {
  description = "Timeout in seconds for each health monitor operation (e.g., reassigning ACs from an unhealthy server). Must be >= 1."
  type        = number
  default     = 30 # Matches Console's DefaultNHPConfig()

  validation {
    condition     = var.nhp_health_monitor_operation_timeout >= 1
    error_message = "nhp_health_monitor_operation_timeout must be at least 1 second."
  }
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
