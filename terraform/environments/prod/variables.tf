# Variables for production environment
# Values are set in terraform.tfvars

# SAFEGUARD: Requires explicit confirmation to deploy to production
variable "confirm_prod_deployment" {
  description = "Must be set to 'yes-deploy-to-production' to apply changes"
  type        = string
  default     = ""

  validation {
    condition     = var.confirm_prod_deployment == "yes-deploy-to-production"
    error_message = "PRODUCTION DEPLOYMENT BLOCKED: Set confirm_prod_deployment=\"yes-deploy-to-production\" to proceed."
  }
}

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

# Deployment configuration
variable "image_tag" {
  description = "Docker image tag for NHP server and AC"
  type        = string
  default     = "latest"
}

# ==============================================================================
# QURL Service Configuration
# ==============================================================================

# QURL Service deployment
variable "deploy_qurl_service" {
  description = "Deploy the QURL API service on ECS Fargate"
  type        = bool
  default     = false
}

variable "qurl_service_domain" {
  description = "Custom domain for QURL API (e.g., api.layerv.ai). When set, creates ACM certificate."
  type        = string
  default     = null
}

variable "qurl_hosted_zone_id" {
  description = "Route53 hosted zone ID for qurl_service_domain DNS records"
  type        = string
  default     = null
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

variable "qurl_additional_allowed_hosts" {
  description = "Additional allowed hostnames for DNS rebinding protection"
  type        = list(string)
  default     = []
}

# QURL plugin configuration
variable "qurl_config" {
  description = "QURL plugin configuration for token resolution"
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

# QURL Router plugin
variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik"
  type        = bool
  default     = false
}

variable "qurl_router_cache_ttl" {
  description = "Cache TTL in seconds for successful lookups"
  type        = number
  default     = 60
}

variable "qurl_router_negative_cache_ttl" {
  description = "Cache TTL in seconds for failed lookups"
  type        = number
  default     = 30
}

variable "qurl_router_max_cache_size" {
  description = "Maximum cache entries"
  type        = number
  default     = 1000
}

variable "qurl_router_api_timeout" {
  description = "Timeout in seconds for QURL API calls"
  type        = number
  default     = 5
}

variable "qurl_router_proxy_timeout" {
  description = "Timeout in seconds for proxying to backends"
  type        = number
  default     = 30
}

variable "qurl_router_cache_shards" {
  description = "Number of cache shards"
  type        = number
  default     = 16
}

# QURL Idempotency Cache
variable "qurl_idempotency_cache_ttl_seconds" {
  description = "TTL for idempotency cache entries in seconds"
  type        = number
  default     = 300
}

variable "qurl_idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number
  default     = 1000
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs"
  type        = number
  default     = 60
}

# QURL Health Check
variable "qurl_health_check_timeout_seconds" {
  description = "Timeout for QURL health check operations"
  type        = number
  default     = 10
}

variable "qurl_health_startup_timeout_seconds" {
  description = "Timeout for QURL startup health checks"
  type        = number
  default     = 30
}

# QURL License Cache
variable "qurl_license_cache_ttl_seconds" {
  description = "TTL for license cache entries in seconds"
  type        = number
  default     = 300
}

variable "qurl_license_cache_max_size" {
  description = "Maximum number of license cache entries"
  type        = number
  default     = 1000
}

# QURL Resource Config
variable "qurl_default_expires_in_seconds" {
  description = "Default QURL lifetime in seconds"
  type        = number
  default     = 86400
}

variable "qurl_resource_ttl_buffer_seconds" {
  description = "Buffer after expiration for DynamoDB cleanup"
  type        = number
  default     = 604800
}

variable "qurl_session_ttl_seconds" {
  description = "Session TTL in seconds"
  type        = number
  default     = 86400
}

variable "qurl_default_list_limit" {
  description = "Default items per page for list endpoints"
  type        = number
  default     = 20
}

# QURL Auth0 JWKS
variable "qurl_auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number
  default     = 3600
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS"
  type        = number
  default     = 10
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
  default     = 4
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number
  default     = 10
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery"
  type        = number
  default     = 30
}

variable "qurl_webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number
  default     = 5
}

variable "qurl_webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number
  default     = 1000
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs"
  type        = number
  default     = 30
}

variable "qurl_webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown"
  type        = number
  default     = 30
}

variable "qurl_webhooks_response_body_limit" {
  description = "Maximum response body size from webhook endpoints"
  type        = number
  default     = 8192
}

variable "qurl_webhooks_api_version" {
  description = "API version string for webhook payloads"
  type        = string
  default     = "2024-01-01"
}

# QURL Observability (OpenTelemetry)
variable "qurl_otel_enabled" {
  description = "Enable OpenTelemetry instrumentation"
  type        = bool
  default     = false
}

variable "qurl_otel_service_name" {
  description = "Service name for OpenTelemetry"
  type        = string
  default     = "qurl-api"
}

variable "qurl_otel_service_version" {
  description = "Service version for OpenTelemetry"
  type        = string
  default     = "prod"
}

variable "qurl_otel_environment" {
  description = "Environment name for OpenTelemetry"
  type        = string
  default     = "prod"
}

variable "qurl_otel_exporter_endpoint" {
  description = "OTLP exporter endpoint"
  type        = string
  default     = "http://localhost:4317"
}

variable "qurl_otel_exporter_protocol" {
  description = "OTLP exporter protocol"
  type        = string
  default     = "grpc"
}

variable "qurl_otel_exporter_insecure" {
  description = "Use insecure connection to OTLP endpoint"
  type        = bool
  default     = true
}

variable "qurl_otel_trace_sample_rate" {
  description = "Trace sampling rate (0.0 to 1.0)"
  type        = number
  default     = 0.1
}

variable "qurl_otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number
  default     = 60
}

variable "qurl_otel_metrics_enabled" {
  description = "Enable OpenTelemetry metrics"
  type        = bool
  default     = true
}

variable "qurl_otel_tracing_enabled" {
  description = "Enable OpenTelemetry tracing"
  type        = bool
  default     = true
}

variable "qurl_otel_log_correlation" {
  description = "Enable trace ID correlation in logs"
  type        = bool
  default     = true
}

# QURL Container Sizing
variable "qurl_container_cpu" {
  description = "CPU units for QURL container"
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.qurl_container_cpu)
    error_message = "qurl_container_cpu must be a valid Fargate CPU value."
  }
}

variable "qurl_container_memory" {
  description = "Memory in MB for QURL container"
  type        = number
  default     = 1024

  validation {
    condition     = var.qurl_container_memory >= 512 && var.qurl_container_memory <= 122880
    error_message = "qurl_container_memory must be between 512 and 122880 MB."
  }
}

# QURL Grafana Cloud (ADOT Sidecar)
variable "qurl_grafana_cloud_enabled" {
  description = "Enable Grafana Cloud OTLP export via ADOT sidecar"
  type        = bool
  default     = false
}

variable "qurl_grafana_secret_arn" {
  description = "ARN of Secrets Manager secret containing Grafana Cloud credentials"
  type        = string
  default     = null
}

variable "qurl_adot_collector_image" {
  description = "ADOT Collector container image"
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
  description = "Grafana Cloud stack URL"
  type        = string
  default     = ""
}

variable "grafana_auth" {
  description = "Grafana Cloud API key or service account token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "grafana_prometheus_datasource_uid" {
  description = "UID of the Prometheus datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-prom"
}

variable "grafana_tempo_datasource_uid" {
  description = "UID of the Tempo datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-traces"
}
