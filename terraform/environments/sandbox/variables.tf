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

# QURL Router plugin configuration
variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik"
  type        = bool
  default     = false
}

variable "qurl_router_base_domain" {
  description = "Base domain for QURL resources (e.g., qurl.site)"
  type        = string
  default     = "qurl.site"
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
}

variable "qurl_idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs in seconds"
  type        = number
}

# QURL Health Check
variable "qurl_health_check_timeout_seconds" {
  description = "Timeout for QURL health check operations in seconds"
  type        = number
}

variable "qurl_health_startup_timeout_seconds" {
  description = "Timeout for QURL startup health checks in seconds"
  type        = number
}

# QURL License Cache
variable "qurl_license_cache_ttl_seconds" {
  description = "TTL for license cache entries in seconds"
  type        = number
}

variable "qurl_license_cache_max_size" {
  description = "Maximum number of license cache entries"
  type        = number
}

# QURL Auth0 JWKS
variable "qurl_auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS in seconds"
  type        = number
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
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery in seconds"
  type        = number
}

variable "qurl_webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number
}

variable "qurl_webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs in seconds"
  type        = number
}

variable "qurl_webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown in seconds"
  type        = number
}

variable "qurl_webhooks_response_body_limit" {
  description = "Maximum response body size to store from webhook endpoints in bytes"
  type        = number
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
}

variable "qurl_otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number
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
