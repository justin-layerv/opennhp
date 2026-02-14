variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell0, cell1)"
  type        = string
  default     = "cell0"
}

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode"
  type        = bool
}

variable "min_capacity" {
  description = "Minimum ASG capacity"
  type        = number
}

variable "max_capacity" {
  description = "Maximum ASG capacity"
  type        = number
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
  description = "Private subnet IDs for ASG"
  type        = list(string)
}

variable "server_repo_url" {
  description = "ECR repository URL for NHP server"
  type        = string
}

variable "server_repo_arn" {
  description = "ECR repository ARN for NHP server"
  type        = string
}

variable "etcd_endpoint" {
  description = "etcd endpoint"
  type        = string
  default     = null
}

variable "etcd_secret_arn" {
  description = "etcd secret ARN"
  type        = string
  default     = null
}

variable "etcd_tls_secret_arn" {
  description = "etcd TLS certificates secret ARN"
  type        = string
  default     = null
}

variable "namespace_id" {
  description = "Service Discovery namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Service Discovery namespace name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
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
# NHP Server Configuration Options
# These options control the server's authentication and resource management
# ============================================================================

variable "log_level" {
  description = "NHP server log level: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

variable "dev_mode" {
  description = "Enable development mode for the NHP server"
  type        = bool
  default     = false
}

variable "resource_mode" {
  description = "Resource management mode: 'local' (config file) or 'api' (external auth service)"
  type        = string
  default     = "local"
  validation {
    condition     = contains(["local", "api"], var.resource_mode)
    error_message = "resource_mode must be either 'local' or 'api'"
  }
}

variable "auth_url" {
  description = "URL of the external authentication service (required when resource_mode is 'api')"
  type        = string
  default     = null
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
# NHP Server plugins (passcode, oidc, etc.) are baked into the Docker image.
# This ensures Go version compatibility between server and plugins.
# See docker/Dockerfile.server for plugin build configuration.
# ============================================================================

variable "server_plugins" {
  description = <<-EOT
    List of NHP Server plugin names that are baked into the Docker image.
    These are used for etcd seeding (AuthServiceId configuration).
    The actual plugin binaries are built into the Docker image at build time.
    Example: ["passcode", "oidc"]
  EOT
  type        = list(string)
  default     = []
}

variable "auth_service_id" {
  description = "Auth Service Provider ID for resource.toml (maps aspId to plugin paths)"
  type        = string
  default     = ""
}

# ============================================================================
# Phase 4: Pluggable Storage Backend
# These settings control which storage backend is used for AC assignments,
# licenses, and resources. DynamoDB is the default for cloud deployments.
# etcd is available as a feature flag for on-prem deployments.
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md for full architecture.
# ============================================================================

variable "storage_backend" {
  description = <<-EOT
    Storage backend for AC assignments, licenses, and resources.
    - "dynamodb" (default): Use AWS DynamoDB for cloud deployments
    - "etcd": Use etcd for on-prem deployments (feature flag)
    When set to "dynamodb", attach_storage_policies must be true.
    When set to "etcd", etcd_endpoint and etcd_tls_secret_arn should be configured.
  EOT
  type        = string
  default     = "dynamodb"
  validation {
    condition     = contains(["dynamodb", "etcd"], var.storage_backend)
    error_message = "storage_backend must be either 'dynamodb' or 'etcd'"
  }
}

variable "dynamodb_region" {
  description = "AWS region for DynamoDB tables (defaults to current region)"
  type        = string
  default     = null
}

variable "dynamodb_licenses_table" {
  description = "DynamoDB table name for licenses"
  type        = string
  default     = null
}

variable "dynamodb_ac_assignments_table" {
  description = "DynamoDB table name for AC assignments"
  type        = string
  default     = null
}

variable "dynamodb_resources_table" {
  description = "DynamoDB table name for resources"
  type        = string
  default     = null
}

variable "attach_storage_policies" {
  description = "Whether to attach storage backend policies (DynamoDB + keypair). Must be true when storage_backend is 'dynamodb'. This boolean is required because Terraform cannot evaluate count based on module outputs at plan time."
  type        = bool
  default     = false
}

variable "dynamodb_read_policy_arn" {
  description = "IAM policy ARN for DynamoDB read access (from dynamodb module). Required when attach_storage_policies is true and storage_backend is 'dynamodb'."
  type        = string
  default     = null
}

variable "keypair_policy_arn" {
  description = "IAM policy ARN for SSM keypair access (from nhp-keypair module). Required when attach_storage_policies is true."
  type        = string
  default     = null
}

# =============================================================================
# Cloud Map Configuration for Server Health Discovery
# Used to filter stale AC assignments pointing to terminated servers.
# =============================================================================

variable "cloudmap_enabled" {
  description = "Enable Cloud Map health filtering for AC assignments"
  type        = bool
  default     = false
}

variable "cloudmap_namespace_name" {
  description = "Cloud Map namespace name (e.g., 'nhp.sandbox.internal')"
  type        = string
  default     = null
}

variable "cloudmap_service_name" {
  description = "Cloud Map service name within the namespace (e.g., 'server')"
  type        = string
  default     = null
}

# =============================================================================
# ASG Lifecycle Hook for Termination Cleanup
# =============================================================================

variable "enable_termination_cleanup" {
  description = "Enable ASG lifecycle hook for immediate DynamoDB cleanup on server termination. When enabled, a Lambda function cleans up AC assignments before the server terminates."
  type        = bool
  default     = false
}

variable "dynamodb_server_ac_index_table" {
  description = "DynamoDB table name for server-ac-index (inverted index). Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "dynamodb_ac_assignments_arn" {
  description = "DynamoDB table ARN for AC assignments. Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "dynamodb_server_ac_index_arn" {
  description = "DynamoDB table ARN for server-ac-index. Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms. Used for Lambda error alerts."
  type        = string
  default     = null
}

variable "enable_sns_alerts" {
  description = "Static boolean: set true when alerts_sns_topic_arn is provided (avoids count-depends-on-computed)"
  type        = bool
  default     = false
}

# =============================================================================
# QURL Plugin Configuration
# These settings configure the QURL token resolution plugin for qurl.link flow.
# All settings are passed as environment variables to the NHP Server container.
# =============================================================================

variable "qurl_config" {
  description = <<-EOT
    QURL plugin configuration. When enabled, the NHP Server will handle
    token resolution for the qurl.link → qurl.site authentication flow.
    All values are passed as environment variables to the Docker container.
  EOT
  type = object({
    enabled                 = bool
    api_url                 = string # QURL API base URL (e.g., https://api.qurl.internal)
    allowed_redirect_domain = string # Domain suffix for redirect validation (e.g., qurl.site)
    api_timeout             = number # API request timeout in seconds
    max_idle_conns          = number # Maximum idle HTTP connections
    max_idle_conns_per_host = number # Maximum idle connections per host
    idle_conn_timeout       = number # Idle connection timeout in seconds
  })
  default = null

  # Note: Use ternary instead of || because Terraform evaluates both sides
  # of || even when the first condition is true (no short-circuit evaluation)
  validation {
    condition = var.qurl_config == null ? true : (
      var.qurl_config.api_timeout > 0 &&
      var.qurl_config.max_idle_conns > 0 &&
      var.qurl_config.max_idle_conns_per_host > 0 &&
      var.qurl_config.idle_conn_timeout > 0 &&
      length(var.qurl_config.allowed_redirect_domain) > 0 &&
      length(var.qurl_config.api_url) > 0
    )
    error_message = "qurl_config: all timeout/connection values must be positive, and api_url/allowed_redirect_domain must be non-empty."
  }
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token for API authentication"
  type        = string
  default     = null
}

variable "enable_qurl_resolve_endpoint" {
  description = "Enable the QURL resolve endpoint (TLS listener on port 443). When true, adds infrastructure for resolve.qurl.link to route directly to the NHP Server plugin endpoint."
  type        = bool
  default     = false
}

variable "qurl_resolve_certificate_arn" {
  description = "ACM certificate ARN for the QURL resolve endpoint (resolve.qurl.link). Required when enable_qurl_resolve_endpoint is true."
  type        = string
  default     = null
}

# =============================================================================
# Blue/Green Deployment Configuration
# =============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure. Creates a second ASG (green) and SSM parameters for traffic switching."
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Minimum instance count for green ASG in standby mode. 1 = warm standby (instant switch), 0 = cold standby (requires scale-up before switch)."
  type        = number
  default     = 1

  validation {
    condition     = var.green_standby_min_size >= 0 && var.green_standby_min_size <= 10
    error_message = "green_standby_min_size must be between 0 and 10."
  }
}

variable "deployment_stale_threshold_days" {
  description = "Number of days without deployments before the stale deployment alarm fires. Set to 0 to disable the alarm."
  type        = number
  default     = 7

  validation {
    condition     = var.deployment_stale_threshold_days >= 0 && var.deployment_stale_threshold_days <= 30
    error_message = "deployment_stale_threshold_days must be between 0 and 30."
  }
}
