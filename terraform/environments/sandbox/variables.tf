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

variable "enable_termination_cleanup" {
  description = "Enable ASG lifecycle hook for immediate DynamoDB cleanup on server termination"
  type        = bool
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

# QURL plugin configuration
variable "qurl_config" {
  description = "QURL plugin configuration for token resolution (qurl.link → qurl.site flow)"
  type = object({
    enabled                 = bool
    api_url                 = string
    allowed_redirect_domain = string
    api_timeout             = number
    max_idle_conns          = number
    max_idle_conns_per_host = number
    idle_conn_timeout       = number
  })
  default = null
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token"
  type        = string
  default     = null
}

# QURL Link redirect page (CloudFront + S3)
variable "deploy_qurl_link" {
  description = "Deploy the QURL link redirect page"
  type        = bool
  default     = false
}

variable "qurl_link_frontend_domain" {
  description = "Domain for the QURL link redirect page (e.g., link.nhp.layerv.xyz)"
  type        = string
  default     = null
}

variable "qurl_link_hosted_zone_id" {
  description = "Route53 hosted zone ID for the QURL link domain"
  type        = string
  default     = null
}

variable "qurl_link_external_dns" {
  description = "When true, Route53 records for qurl_link are managed externally (e.g., via AWS CLI in layerv-mgmt)"
  type        = bool
  default     = false
}

variable "qurl_link_enable_access_logs" {
  description = "Enable CloudFront access logging for QURL link redirect page"
  type        = bool
  default     = false
}

# QURL Service deployment
variable "deploy_qurl_service" {
  description = "Deploy the QURL API service on ECS Fargate"
  type        = bool
}

variable "qurl_jwt_secret_arn" {
  description = "Secrets Manager ARN for QURL JWT signing secret"
  type        = string
  default     = null
}

variable "qurl_internal_service_token_arn" {
  description = "Secrets Manager ARN for QURL internal service token"
  type        = string
  default     = null
}

variable "qurl_link_domain" {
  description = "Domain for QURL access links (e.g., qurl.link)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_link_domain))
    error_message = "qurl_link_domain must be a valid domain name (e.g., qurl.link)"
  }
}

variable "qurl_site_domain" {
  description = "Domain for QURL protected resources (e.g., qurl.site)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_site_domain))
    error_message = "qurl_site_domain must be a valid domain name (e.g., qurl.site)"
  }
}

variable "qurl_audit_retention_days" {
  description = "Number of days to retain QURL audit logs in DynamoDB"
  type        = number

  validation {
    condition     = var.qurl_audit_retention_days > 0 && var.qurl_audit_retention_days <= 3650
    error_message = "qurl_audit_retention_days must be between 1 and 3650 days (10 years max)"
  }
}

variable "qurl_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for QURL API"
  type        = string
}

variable "qurl_additional_allowed_hosts" {
  description = "Additional allowed hostnames for DNS rebinding protection. ALB DNS and localhost are always included."
  type        = list(string)
  default     = []
}

# QURL Rate Limiting
variable "qurl_owner_rate_limit" {
  description = "Rate limit for authenticated owner routes (requests per minute)"
  type        = number

  validation {
    condition     = var.qurl_owner_rate_limit > 0 && var.qurl_owner_rate_limit <= 10000
    error_message = "qurl_owner_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_owner_rate_burst" {
  description = "Burst allowance for authenticated owner routes"
  type        = number

  validation {
    condition     = var.qurl_owner_rate_burst > 0 && var.qurl_owner_rate_burst <= 1000
    error_message = "qurl_owner_rate_burst must be between 1 and 1000"
  }
}

variable "qurl_ip_rate_limit" {
  description = "Rate limit for IP-based internal routes (requests per minute)"
  type        = number

  validation {
    condition     = var.qurl_ip_rate_limit > 0 && var.qurl_ip_rate_limit <= 10000
    error_message = "qurl_ip_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_ip_rate_burst" {
  description = "Burst allowance for IP-based internal routes"
  type        = number

  validation {
    condition     = var.qurl_ip_rate_burst > 0 && var.qurl_ip_rate_burst <= 1000
    error_message = "qurl_ip_rate_burst must be between 1 and 1000"
  }
}

# QURL Router plugin configuration
variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik"
  type        = bool
  default     = false
}

variable "qurl_router_cache_ttl" {
  description = "Cache TTL in seconds for successful lookups"
  type        = number
  default     = 60

  validation {
    condition     = var.qurl_router_cache_ttl >= 0 && var.qurl_router_cache_ttl <= 86400
    error_message = "qurl_router_cache_ttl must be between 0 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_router_negative_cache_ttl" {
  description = "Cache TTL in seconds for failed lookups"
  type        = number
  default     = 30

  validation {
    condition     = var.qurl_router_negative_cache_ttl >= 0 && var.qurl_router_negative_cache_ttl <= 3600
    error_message = "qurl_router_negative_cache_ttl must be between 0 and 3600 seconds (1 hour max)"
  }
}

variable "qurl_router_max_cache_size" {
  description = "Maximum cache entries"
  type        = number
  default     = 1000

  validation {
    condition     = var.qurl_router_max_cache_size > 0 && var.qurl_router_max_cache_size <= 100000
    error_message = "qurl_router_max_cache_size must be between 1 and 100000 entries"
  }
}

variable "qurl_router_api_timeout" {
  description = "Timeout in seconds for QURL API calls"
  type        = number
  default     = 5

  validation {
    condition     = var.qurl_router_api_timeout > 0 && var.qurl_router_api_timeout <= 300
    error_message = "qurl_router_api_timeout must be between 1 and 300 seconds"
  }
}

variable "qurl_router_proxy_timeout" {
  description = "Timeout in seconds for proxying to backends"
  type        = number
  default     = 30

  validation {
    condition     = var.qurl_router_proxy_timeout > 0 && var.qurl_router_proxy_timeout <= 600
    error_message = "qurl_router_proxy_timeout must be between 1 and 600 seconds"
  }
}

variable "qurl_router_cache_shards" {
  description = "Number of cache shards"
  type        = number
  default     = 16

  validation {
    condition     = var.qurl_router_cache_shards > 0 && var.qurl_router_cache_shards <= 256
    error_message = "qurl_router_cache_shards must be between 1 and 256"
  }
}

# QURL Idempotency Cache
variable "qurl_idempotency_cache_ttl_seconds" {
  description = "TTL for idempotency cache entries in seconds"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cache_ttl_seconds > 0 && var.qurl_idempotency_cache_ttl_seconds <= 86400
    error_message = "qurl_idempotency_cache_ttl_seconds must be between 1 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cache_max_size > 0 && var.qurl_idempotency_cache_max_size <= 1000000
    error_message = "qurl_idempotency_cache_max_size must be between 1 and 1000000 entries"
  }
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs in seconds"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cleanup_interval_seconds > 0 && var.qurl_idempotency_cleanup_interval_seconds <= 3600
    error_message = "qurl_idempotency_cleanup_interval_seconds must be between 1 and 3600 seconds"
  }
}

# QURL Health Check
variable "qurl_health_check_timeout_seconds" {
  description = "Timeout for QURL health check operations in seconds"
  type        = number

  validation {
    condition     = var.qurl_health_check_timeout_seconds > 0 && var.qurl_health_check_timeout_seconds <= 300
    error_message = "qurl_health_check_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_health_startup_timeout_seconds" {
  description = "Timeout for QURL startup health checks in seconds"
  type        = number

  validation {
    condition     = var.qurl_health_startup_timeout_seconds > 0 && var.qurl_health_startup_timeout_seconds <= 600
    error_message = "qurl_health_startup_timeout_seconds must be between 1 and 600 seconds"
  }
}

# QURL License Cache
variable "qurl_license_cache_ttl_seconds" {
  description = "TTL for license cache entries in seconds"
  type        = number

  validation {
    condition     = var.qurl_license_cache_ttl_seconds > 0 && var.qurl_license_cache_ttl_seconds <= 86400
    error_message = "qurl_license_cache_ttl_seconds must be between 1 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_license_cache_max_size" {
  description = "Maximum number of license cache entries"
  type        = number

  validation {
    condition     = var.qurl_license_cache_max_size > 0 && var.qurl_license_cache_max_size <= 100000
    error_message = "qurl_license_cache_max_size must be between 1 and 100000 entries"
  }
}

# QURL Resource Config
# TTL Relationship:
# - qurl_default_expires_in_seconds: How long a QURL is valid (user-facing)
# - qurl_resource_ttl_buffer_seconds: Additional time before DynamoDB cleanup
# - qurl_session_ttl_seconds: How long session records persist

variable "qurl_default_expires_in_seconds" {
  description = "Default QURL lifetime in seconds (60s min, 30 days max)"
  type        = number
  default     = 86400 # 24 hours

  validation {
    condition     = var.qurl_default_expires_in_seconds >= 60 && var.qurl_default_expires_in_seconds <= 2592000
    error_message = "qurl_default_expires_in_seconds must be between 60 (1 minute) and 2592000 (30 days)."
  }
}

variable "qurl_resource_ttl_buffer_seconds" {
  description = "Buffer after expiration for DynamoDB cleanup in seconds (1 hour min, 30 days max)"
  type        = number
  default     = 604800 # 7 days

  validation {
    condition     = var.qurl_resource_ttl_buffer_seconds >= 3600 && var.qurl_resource_ttl_buffer_seconds <= 2592000
    error_message = "qurl_resource_ttl_buffer_seconds must be between 3600 (1 hour) and 2592000 (30 days)."
  }
}

variable "qurl_session_ttl_seconds" {
  description = "Session TTL in seconds (60s min, 30 days max)"
  type        = number
  default     = 86400 # 24 hours

  validation {
    condition     = var.qurl_session_ttl_seconds >= 60 && var.qurl_session_ttl_seconds <= 2592000
    error_message = "qurl_session_ttl_seconds must be between 60 (1 minute) and 2592000 (30 days)."
  }
}

variable "qurl_default_list_limit" {
  description = "Default items per page for list endpoints (1-100)"
  type        = number
  default     = 20

  validation {
    condition     = var.qurl_default_list_limit >= 1 && var.qurl_default_list_limit <= 100
    error_message = "qurl_default_list_limit must be between 1 and 100."
  }
}

# QURL API Domain Configuration
variable "qurl_service_domain" {
  description = "Custom domain for QURL API (e.g., api.layerv.xyz). When set, creates ACM certificate."
  type        = string
  default     = null
}

variable "qurl_hosted_zone_id" {
  description = "Route53 hosted zone ID for qurl_service_domain DNS records"
  type        = string
  default     = null
}

# QURL Auth0 Configuration
variable "qurl_auth0_domain" {
  description = "Auth0 domain for JWKS validation (custom domain, e.g., auth.layerv.ai)"
  type        = string
}

variable "qurl_auth0_audience" {
  description = "Auth0 API audience/identifier (e.g., https://api.layerv.xyz)"
  type        = string

  validation {
    condition     = can(regex("^https://", var.qurl_auth0_audience))
    error_message = "qurl_auth0_audience must be an HTTPS URL"
  }
}

# QURL Auth0 JWKS
variable "qurl_auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number

  validation {
    condition     = var.qurl_auth0_jwks_cache_ttl_seconds > 0 && var.qurl_auth0_jwks_cache_ttl_seconds <= 86400
    error_message = "qurl_auth0_jwks_cache_ttl_seconds must be between 1 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS in seconds"
  type        = number

  validation {
    condition     = var.qurl_auth0_jwks_fetch_timeout_seconds > 0 && var.qurl_auth0_jwks_fetch_timeout_seconds <= 60
    error_message = "qurl_auth0_jwks_fetch_timeout_seconds must be between 1 and 60 seconds"
  }
}

# QURL AC Fleet defaults
variable "qurl_default_ac_id" {
  description = "Default AC identifier for new QURL resources"
  type        = string
}

variable "qurl_default_ac_port" {
  description = "Default AC port for new QURL resources"
  type        = number
  default     = 443

  validation {
    condition     = var.qurl_default_ac_port > 0 && var.qurl_default_ac_port <= 65535
    error_message = "qurl_default_ac_port must be a valid port number (1-65535)"
  }
}

# QURL Webhooks
variable "qurl_webhooks_enabled" {
  description = "Enable webhook delivery for QURL service"
  type        = bool
  default     = false
}

variable "qurl_webhooks_worker_count" {
  description = "Number of concurrent webhook delivery workers"
  type        = number

  validation {
    condition     = var.qurl_webhooks_worker_count > 0 && var.qurl_webhooks_worker_count <= 100
    error_message = "qurl_webhooks_worker_count must be between 1 and 100"
  }
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number

  validation {
    condition     = var.qurl_webhooks_max_webhooks_per_owner > 0 && var.qurl_webhooks_max_webhooks_per_owner <= 100
    error_message = "qurl_webhooks_max_webhooks_per_owner must be between 1 and 100"
  }
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_delivery_timeout_seconds > 0 && var.qurl_webhooks_delivery_timeout_seconds <= 300
    error_message = "qurl_webhooks_delivery_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number

  validation {
    condition     = var.qurl_webhooks_max_retries >= 0 && var.qurl_webhooks_max_retries <= 10
    error_message = "qurl_webhooks_max_retries must be between 0 and 10"
  }
}

variable "qurl_webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number

  validation {
    condition     = var.qurl_webhooks_event_channel_size > 0 && var.qurl_webhooks_event_channel_size <= 10000
    error_message = "qurl_webhooks_event_channel_size must be between 1 and 10000"
  }
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_retry_worker_interval_seconds > 0 && var.qurl_webhooks_retry_worker_interval_seconds <= 3600
    error_message = "qurl_webhooks_retry_worker_interval_seconds must be between 1 and 3600 seconds"
  }
}

variable "qurl_webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_drain_timeout_seconds > 0 && var.qurl_webhooks_drain_timeout_seconds <= 300
    error_message = "qurl_webhooks_drain_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_webhooks_response_body_limit" {
  description = "Maximum response body size to store from webhook endpoints in bytes"
  type        = number

  validation {
    condition     = var.qurl_webhooks_response_body_limit > 0 && var.qurl_webhooks_response_body_limit <= 1048576
    error_message = "qurl_webhooks_response_body_limit must be between 1 and 1048576 bytes (1MB max)"
  }
}

variable "qurl_webhooks_api_version" {
  description = "API version string for webhook payloads"
  type        = string
}

# QURL Observability (OpenTelemetry)
variable "qurl_otel_enabled" {
  description = "Enable OpenTelemetry instrumentation for QURL service"
  type        = bool
  default     = false
}

variable "qurl_otel_service_name" {
  description = "Service name for OpenTelemetry"
  type        = string
}

variable "qurl_otel_service_version" {
  description = "Service version for OpenTelemetry"
  type        = string
}

variable "qurl_otel_environment" {
  description = "Environment name for OpenTelemetry"
  type        = string
}

variable "qurl_otel_exporter_endpoint" {
  description = "OTLP exporter endpoint (e.g., http://localhost:4317)"
  type        = string
}

variable "qurl_otel_exporter_protocol" {
  description = "OTLP exporter protocol (grpc or http/protobuf)"
  type        = string
}

variable "qurl_otel_exporter_insecure" {
  description = "Use insecure connection to OTLP endpoint (for localhost sidecar)"
  type        = bool
}

variable "qurl_otel_trace_sample_rate" {
  description = "Trace sampling rate (0.0 to 1.0)"
  type        = number

  validation {
    condition     = var.qurl_otel_trace_sample_rate >= 0 && var.qurl_otel_trace_sample_rate <= 1
    error_message = "qurl_otel_trace_sample_rate must be between 0.0 and 1.0"
  }
}

variable "qurl_otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number

  validation {
    condition     = var.qurl_otel_metrics_interval > 0 && var.qurl_otel_metrics_interval <= 3600
    error_message = "qurl_otel_metrics_interval must be between 1 and 3600 seconds"
  }
}

variable "qurl_otel_metrics_enabled" {
  description = "Enable OpenTelemetry metrics"
  type        = bool
}

variable "qurl_otel_tracing_enabled" {
  description = "Enable OpenTelemetry tracing"
  type        = bool
}

variable "qurl_otel_log_correlation" {
  description = "Enable trace ID correlation in logs"
  type        = bool
}

# QURL Container Sizing
variable "qurl_container_cpu" {
  description = "CPU units for QURL container (256, 512, 1024, 2048, 4096, 8192, 16384)"
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.qurl_container_cpu)
    error_message = "qurl_container_cpu must be a valid Fargate CPU value."
  }
}

variable "qurl_container_memory" {
  description = "Memory in MB for QURL container. When grafana_cloud_enabled=true, effective memory is container_memory + 256."
  type        = number
  default     = 512

  validation {
    condition     = var.qurl_container_memory >= 512 && var.qurl_container_memory <= 122880
    error_message = "qurl_container_memory must be between 512 and 122880 MB."
  }
}

# QURL Grafana Cloud (ADOT Sidecar)
variable "qurl_grafana_cloud_enabled" {
  description = "Enable Grafana Cloud OTLP export via ADOT sidecar for QURL service"
  type        = bool
  default     = false
}

variable "qurl_grafana_secret_arn" {
  description = "ARN of Secrets Manager secret containing Grafana Cloud OTLP credentials"
  type        = string
  default     = null
}

variable "qurl_adot_collector_image" {
  description = "ADOT Collector container image for QURL service"
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

# Grafana Cloud Dashboards
variable "grafana_dashboards_enabled" {
  description = "Enable Grafana Cloud dashboard provisioning"
  type        = bool
  default     = false
}

variable "grafana_url" {
  description = "Grafana Cloud stack URL (e.g., https://layervai.grafana.net)"
  type        = string
  default     = ""
}

variable "grafana_auth" {
  description = "Grafana Cloud API key or service account token with Editor role"
  type        = string
  default     = ""
  sensitive   = true
}

variable "grafana_prometheus_datasource_uid" {
  description = "UID of the Prometheus/Mimir datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-prom"
}

variable "grafana_tempo_datasource_uid" {
  description = "UID of the Tempo datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-traces"
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

# Traefik plugins deploy bucket (for traefik-plugins CI/CD SSM-based deployment)
variable "traefik_plugins_deploy_bucket_arn" {
  description = "ARN of the S3 bucket used by traefik-plugins CI/CD for SSM-based plugin deployment"
  type        = string
  default     = null
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

variable "console_ac_license_key_sha256" {
  description = "SHA256 hash of Console AC license key for DynamoDB lookup. Generate with: ./terraform/scripts/generate-console-ac-license.sh"
  type        = string
  sensitive   = true
  default     = null
}

# Console license lookup GSI names
variable "nhp_dynamodb_licenses_customer_index" {
  description = "GSI name for querying licenses by customer_id. Recommended: 'customer_id-index'"
  type        = string
  default     = null
}

variable "nhp_dynamodb_licenses_auth0_subject_index" {
  description = "GSI name for querying licenses by auth0_subject. Recommended: 'auth0_subject-index'"
  type        = string
  default     = null
}

# NHP Server Assignment Configuration
# All fields are required - no defaults (explicit configuration philosophy)
variable "nhp_server_assignment_enabled" {
  description = "Enable NHP server assignment for ACs. Required. Recommended: true"
  type        = bool
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables and CloudMap. Required. Recommended: match deployment region"
  type        = string
}

variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers. Required. Recommended: 'server'"
  type        = string
}

variable "nhp_assignment_servers_per_ac" {
  description = "Number of NHP servers to assign per AC. Required. Recommended: 3"
  type        = number
}

variable "nhp_assignment_require_distinct_azs" {
  description = "Require assigned servers to be in different AZs. Required. Recommended: true"
  type        = bool
}

variable "nhp_health_monitor_check_interval" {
  description = "Interval in seconds between health checks. Required. Recommended: 60"
  type        = number
}

variable "nhp_health_monitor_operation_timeout" {
  description = "Timeout in seconds for health check operations. Required. Recommended: 30"
  type        = number
}

variable "nhp_console_ac_enabled" {
  description = "Enable Console's embedded AC self-registration. Required. Recommended: true"
  type        = bool
}

# Console internal service auth and customer provisioning
variable "internal_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret for internal service token"
  type        = string
  default     = null
}

variable "provisioning_resource_id" {
  description = "Resource ID for auto-provisioned licenses. Recommended: 'qurl-auto-provisioned'"
  type        = string
  default     = null
}

variable "provisioning_default_tier" {
  description = "Default license tier for new customers. Recommended: 'free'"
  type        = string
  default     = null
}

variable "provisioning_default_max_acs" {
  description = "Default MaxACs for new customers. Recommended: 1"
  type        = number
  default     = null
}

# Standalone AC license credentials (for cloud mode registration)
variable "ac_customer_id" {
  description = "Customer ID for standalone AC license (ULID format)"
  type        = string
  default     = null
}

variable "ac_license_key" {
  description = "License key for standalone AC registration (plaintext, passed via TF_VAR_ac_license_key)"
  type        = string
  sensitive   = true
  default     = null
}

variable "ac_license_key_hash" {
  description = "Bcrypt hash of standalone AC license key for validation"
  type        = string
  sensitive   = true
  default     = null
}

variable "ac_license_key_sha256" {
  description = "SHA256 hash of standalone AC license key for DynamoDB lookup"
  type        = string
  sensitive   = true
  default     = null
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

# Security alerting
variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty security finding alerts"
  type        = list(string)
  default     = []
}

# ==============================================================================
# Auth0 Configuration
# ==============================================================================

variable "auth0_domain" {
  description = "Auth0 tenant domain for Management API (e.g., dev-xxx.us.auth0.com). Required when using Auth0 module."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+\\.(us|eu|au|jp)\\.auth0\\.com$", var.auth0_domain))
    error_message = "auth0_domain must be a valid Auth0 tenant domain (e.g., dev-xxx.us.auth0.com)"
  }
}

variable "auth0_tf_client_id" {
  description = "Auth0 M2M client ID for Terraform (Management API access). Required - pass via TF_VAR_auth0_tf_client_id"
  type        = string
  sensitive   = true
}

variable "auth0_tf_client_secret" {
  description = "Auth0 M2M client secret for Terraform (Management API access). Required - pass via TF_VAR_auth0_tf_client_secret"
  type        = string
  sensitive   = true
}

# ==============================================================================
# Auth0 Secret Rotation Configuration
# ==============================================================================

variable "auth0_enable_rotation" {
  description = "Enable automatic rotation for Auth0 M2M credentials"
  type        = bool
  default     = false
}

variable "auth0_rotation_days" {
  description = "Rotate Auth0 M2M credentials every N days"
  type        = number
  default     = 30
}

variable "auth0_management_secret_arn" {
  description = "Secrets Manager ARN containing Auth0 Management API credentials for rotation Lambda. Required when auth0_enable_rotation is true."
  type        = string
  default     = null
}

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs
# without hitting Let's Encrypt rate limits.
#
# NOTE: This is an interim solution. For production at scale, consider migrating
# to HashiCorp Vault PKI for short-lived certificates and better revocation.

variable "centralized_cert_enabled" {
  description = "Enable centralized certificate management for AC fleet"
  type        = bool
  default     = false
}

variable "centralized_cert_domains" {
  description = "Domains for centralized TLS certificate (e.g., ['nhp.layerv.xyz', '*.nhp.layerv.xyz'])"
  type        = list(string)
  default     = []
}

# ==============================================================================
# Blue/Green Deployment Configuration
# ==============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure for NHP Server"
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Min instances for green ASG in standby (1=warm, 0=cold)"
  type        = number
  default     = 1
}

variable "deployment_stale_threshold_days" {
  description = "Days without deployments before stale alarm fires (0=disable)"
  type        = number
  default     = 7
}
