# AC Module Variables
# Access Controller with embedded Traefik for TLS termination

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the AC (e.g., nhp.layerv.xyz)"
  type        = string
}

variable "hosted_zone" {
  description = "Route 53 hosted zone name (e.g., layerv.xyz)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID (bypasses zone lookup for cross-account zones)"
  type        = string
  default     = null
}

variable "skip_dns_records" {
  description = "Skip creating DNS records (for cross-account zones where records are created by the caller with the correct provider)"
  type        = bool
  default     = false
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
  description = "Public subnet IDs for NLB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "ac_repo_url" {
  description = "ECR repository URL for AC image"
  type        = string
}

variable "ac_repo_arn" {
  description = "ECR repository ARN for AC image"
  type        = string
}

variable "namespace_id" {
  description = "Cloud Map namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Cloud Map namespace name"
  type        = string
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

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  type        = string
  default     = null
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  type        = string
  default     = null
}

variable "enable_cloudfront" {
  description = "Enable CloudFront + WAF in front of NLB for DDoS protection"
  type        = bool
  default     = false
}

# ============================================================================
# NHP AC Configuration Options
# These options control the AC daemon's behavior
# ============================================================================

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
# Cloud Mode Registration
# AC registers with NHP servers using credentials for DynamoDB license validation
# ============================================================================

variable "customer_id" {
  description = "Customer ID (ULID format) for license record. Used for querying, not lookup."
  type        = string
}

variable "license_key" {
  description = "License key for server registration. AC sends this to server for validation. Required."
  type        = string
  sensitive   = true
}

variable "license_key_hash" {
  description = "Bcrypt hash of license key for DynamoDB seeding. Generate with: htpasswd -bnBC 10 '' 'your-key' | tr -d ':\\n'"
  type        = string
  sensitive   = true
}

variable "license_key_sha256" {
  description = "SHA256 hash of license key for DynamoDB lookup. Generate with: echo -n 'your-key' | sha256sum | cut -d' ' -f1"
  type        = string
  sensitive   = true
}

variable "server_endpoint" {
  description = "NHP server endpoint for registration (e.g., 'server.nhp.sandbox.internal' for internal, or NLB DNS for external). Required."
  type        = string
}

variable "nhp_dynamodb_licenses_table" {
  description = "DynamoDB table name for license validation. If set, module will seed AC license."
  type        = string
  default     = null
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables"
  type        = string
  default     = null
}

variable "auth_service_id" {
  description = "Authentication service ID for the AC"
  type        = string
  default     = "layerv"
}

variable "ac_id" {
  description = "AC identifier used for knock routing. All ACs in the same group should share this ID so resources can reference them."
  type        = string
  default     = "layerv-ac-tf"
}

variable "resource_ids" {
  description = "List of resource IDs that this AC protects"
  type        = list(string)
  default     = ["default"]
}

variable "server_secret_arn" {
  description = "ARN of the NHP Server's secret containing public key. Required for cloud registration."
  type        = string
}

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN in management account for cross-account Route 53 access (ACME DNS challenges for production domains)"
  type        = string
  default     = null
}

variable "production_domains" {
  description = "List of production domains for ACME certificate generation"
  type        = list(string)
  default     = []
}

variable "production_zone_ids" {
  description = "Route 53 hosted zone IDs for production domains (for same-account ACME challenges)"
  type        = list(string)
  default     = []
}

variable "additional_tls_domains" {
  description = "Additional domains for TLS certificates in same account (uses standard ACME DNS challenge)"
  type        = list(string)
  default     = []
}

# ============================================================================
# Centralized Certificate Management
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs
# without hitting Let's Encrypt rate limits.
# ============================================================================

variable "centralized_cert_enabled" {
  description = "Enable centralized certificate management. When true, ACs fetch TLS cert from Secrets Manager instead of using per-instance ACME."
  type        = bool
  default     = false
}

variable "centralized_cert_secret_arn" {
  description = "ARN of Secrets Manager secret containing TLS certificate (from acme-cert module). Required when centralized_cert_enabled=true."
  type        = string
  default     = null
}

variable "centralized_cert_domains" {
  description = "List of domains covered by the centralized certificate. Used to configure Traefik TLS. Required when centralized_cert_enabled=true."
  type        = list(string)
  default     = []
}

variable "acme_lambda_function_name" {
  description = "Name of the ACME certificate Lambda function (for error messages). Only used when centralized_cert_enabled=true."
  type        = string
  default     = ""
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false). Staging certs are not trusted by browsers."
  type        = bool
  default     = null # null means auto-detect based on environment (prod=true, else=false)
}

# ============================================================================
# SSM and Monitoring Configuration
# These control automated maintenance and observability for AC instances
# ============================================================================

variable "enable_ssm_maintenance" {
  description = "Enable SSM-based maintenance (log rotation, disk monitoring)"
  type        = bool
  default     = true
}

variable "ac_instance_tag" {
  description = "Tag value used to identify AC instances (Name tag)"
  type        = string
  default     = "nhp_ac"
}

variable "log_rotation_schedule" {
  description = "Cron expression for log rotation (UTC)"
  type        = string
  default     = "cron(0 3 * * ? *)" # Daily at 3 AM UTC
}

variable "journal_max_size_mb" {
  description = "Maximum size for systemd journal in MB"
  type        = number
  default     = 100
}

variable "log_retention_days" {
  description = "Days to retain rotated log files"
  type        = number
  default     = 7
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for AC monitoring"
  type        = bool
  default     = true
}

variable "disk_usage_threshold_percent" {
  description = "Disk usage percentage threshold for alarms"
  type        = number
  default     = 85
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications (optional)"
  type        = string
  default     = ""
}

# ============================================================================
# Deployment Configuration
# ============================================================================

variable "image_tag" {
  description = "Docker image tag to deploy (defaults to 'latest', set to commit SHA for immutable deployments)"
  type        = string
  default     = "latest"
}

# ============================================================================
# Plugin Configuration
# Traefik plugins are deployed via the unified plugins S3 bucket.
# ============================================================================

variable "plugin_bucket_name" {
  description = "Name of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_bucket_arn" {
  description = "ARN of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_download_policy_arn" {
  description = "ARN of the IAM policy for downloading plugins (from plugins module)"
  type        = string
  default     = null
}

variable "traefik_plugins_deploy_bucket_arn" {
  description = "ARN of the S3 bucket used by traefik-plugins CI/CD for plugin deployment"
  type        = string
  default     = null
}

variable "traefik_plugins" {
  description = <<-EOT
    Map of Traefik plugins with their S3 keys (from plugins module output).
    Example:
    traefik_plugins = {
      nhp-token-validator = {
        version    = "v1.0.0"
        plugin_key = "traefik/nhp-token-validator/v1.0.0/"
        config_key = null
      }
    }
  EOT
  type = map(object({
    version    = string
    plugin_key = string
    config_key = optional(string)
  }))
  default = {}
}

# ============================================================================
# Console Backend Configuration (for NHP-protected Console)
# When Console is in internal_only mode, AC routes traffic to Console
# ============================================================================

variable "console_backend_url" {
  description = "Console internal endpoint URL for AC to proxy to (e.g., http://nlb-dns:8888). Must be set together with console_domain."
  type        = string
  default     = null
}

variable "console_domain" {
  description = "Console domain that AC should route to Console backend (e.g., console.nhp.layerv.xyz). Must be set together with console_backend_url."
  type        = string
  default     = null
}

# ============================================================================
# QURL Router Plugin Configuration
# Routes requests from *.qurl.site subdomains to their target backends
# ============================================================================

variable "qurl_router_config" {
  description = <<-EOT
    QURL Router plugin configuration. When enabled, Traefik routes requests
    from *.qurl.site subdomains by looking up target URLs from the QURL Service.

    Example:
    qurl_router_config = {
      enabled         = true
      api_url         = "http://qurl-api.internal:8080"
      base_domain     = "qurl.site"
      cache_ttl       = 60
      negative_cache_ttl = 30
      api_timeout     = 5
      proxy_timeout   = 30
    }
  EOT
  type = object({
    enabled            = bool
    api_url            = string # QURL Service internal URL
    base_domain        = string # Base domain for QURL resources (e.g., qurl.site)
    cache_ttl          = optional(number, 60)
    negative_cache_ttl = optional(number, 30)
    max_cache_size     = optional(number, 1000)
    api_timeout        = optional(number, 5)
    proxy_timeout      = optional(number, 30)
    cache_shards       = optional(number, 16)
  })
  default = null

  validation {
    condition     = var.qurl_router_config == null || can(var.qurl_router_config.enabled)
    error_message = "qurl_router_config must include 'enabled' field when set."
  }
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token for Traefik QURL router"
  type        = string
  default     = null
}

# ============================================================================
# Blue/Green Deployment Configuration
# ============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure for AC"
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Min instance count for green ASG (1=warm standby, 0=cold)"
  type        = number
  default     = 1

  validation {
    condition     = var.green_standby_min_size >= 0 && var.green_standby_min_size <= 10
    error_message = "green_standby_min_size must be between 0 and 10."
  }
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for deployment alarms"
  type        = string
  default     = null
}
