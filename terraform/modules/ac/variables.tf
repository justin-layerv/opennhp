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

variable "etcd_endpoint" {
  description = "etcd endpoint for configuration"
  type        = string
  default     = null
}

variable "etcd_secret_arn" {
  description = "etcd credentials secret ARN"
  type        = string
  default     = null
}

variable "etcd_tls_secret_arn" {
  description = "etcd TLS certificates secret ARN"
  type        = string
  default     = null
}

variable "etcd_security_group_id" {
  description = "etcd security group ID (for Lambda VPC access)"
  type        = string
  default     = null
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

variable "auth_service_id" {
  description = "Authentication service ID for the AC"
  type        = string
  default     = "layerv"
}

variable "resource_ids" {
  description = "List of resource IDs that this AC protects"
  type        = list(string)
  default     = ["default"]
}

variable "server_nlb_dns" {
  description = "NLB DNS name for NHP server (fallback for server discovery)"
  type        = string
  default     = ""
}

variable "server_secret_arn" {
  description = "ARN of the NHP Server's secret containing public key"
  type        = string
  default     = ""
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
  description = "Console internal endpoint URL for AC to proxy to (e.g., http://nlb-dns:8888)"
  type        = string
  default     = null
}

variable "console_domain" {
  description = "Console domain that AC should route to Console backend (e.g., console.nhp.layerv.xyz)"
  type        = string
  default     = null
}
