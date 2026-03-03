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
  description = "AWS account ID for the production environment"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID"
  }
}

variable "domain_name" {
  type = string
}

variable "hosted_zone" {
  type    = string
  default = null
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID (bypasses zone lookup for cross-account zones)"
  type        = string
  default     = null
}

variable "lambda_layer_bucket" {
  description = "S3 bucket containing Lambda layer artifacts"
  type        = string
  default     = null
}

variable "qurl_alb_access_logs_bucket" {
  description = "S3 bucket for QURL ALB access logs"
  type        = string
  default     = null
}

variable "multi_tenant" {
  type = bool
}

variable "deploy_etcd" {
  description = "Deploy etcd infrastructure. Set to false for cloud deployments using DynamoDB backend."
  type        = bool
  default     = null
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

# AC capacity
variable "ac_min_capacity" {
  description = "Minimum number of AC instances"
  type        = number
  default     = null
}

variable "ac_max_capacity" {
  description = "Maximum number of AC instances"
  type        = number
  default     = null
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

variable "config_recording_frequency" {
  description = "AWS Config recording frequency: CONTINUOUS or DAILY"
  type        = string
  default     = "DAILY"
}

variable "config_resource_types" {
  description = "Specific AWS resource types to record. Empty list uses module defaults."
  type        = list(string)
  default     = []
}

# GitHub OIDC
variable "create_oidc_provider" {
  description = "Create GitHub OIDC provider. Set to false if org manages centrally or SCP blocks creation."
  type        = bool
  default     = true
}

# Server configuration
variable "log_level" {
  description = "NHP log level for all components: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2 # Info for production

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

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

# Deployment configuration
variable "image_tag" {
  description = "Docker image tag for NHP server and AC"
  type        = string
  default     = "latest"
}

variable "server_plugins" {
  description = "List of NHP Server plugins to enable"
  type        = list(string)
  default     = []
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
  default = true
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

variable "additional_tls_domains" {
  type    = list(string)
  default = []
}

variable "use_production_acme" {
  type    = bool
  default = null
}

variable "enable_termination_cleanup" {
  type    = bool
  default = true
}

variable "enable_secret_reconciliation" {
  description = "Enable scheduled cleanup of orphaned per-instance AC secrets"
  type        = bool
  default     = true
}

# ==============================================================================
# QURL Service Configuration
# ==============================================================================

variable "deploy_qurl_service" {
  type    = bool
  default = false
}

variable "qurl_service_domain" {
  type    = string
  default = null
}

variable "qurl_hosted_zone_id" {
  type    = string
  default = null
}

variable "qurl_jwt_secret_arn" {
  type    = string
  default = null
}

variable "qurl_internal_service_token_arn" {
  type    = string
  default = null
}

variable "qurl_additional_allowed_hosts" {
  type    = list(string)
  default = []
}

variable "qurl_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for QURL API"
  type        = string
  default     = ""
}

variable "qurl_audit_retention_days" {
  type    = number
  default = 365
}

variable "qurl_link_domain" {
  description = "Domain for QURL access links (e.g., qurl.link)"
  type        = string
  default     = "qurl.link"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_link_domain))
    error_message = "qurl_link_domain must be a valid domain name (e.g., qurl.link)"
  }
}

variable "qurl_site_domain" {
  description = "Domain for QURL protected resources (e.g., qurl.site)"
  type        = string
  default     = "qurl.site"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_site_domain))
    error_message = "qurl_site_domain must be a valid domain name (e.g., qurl.site)"
  }
}

variable "qurl_site_hosted_zone_id" {
  description = "Route53 hosted zone ID for the qurl.site domain wildcard record"
  type        = string
  default     = null

  validation {
    condition     = var.qurl_site_hosted_zone_id == null || can(regex("^Z[A-Z0-9]+$", var.qurl_site_hosted_zone_id))
    error_message = "qurl_site_hosted_zone_id must be a valid Route53 zone ID (starts with Z)"
  }
}

variable "qurl_ip_rate_limit" {
  description = "Rate limit for IP-based internal routes (requests per minute)"
  type        = number
  default     = 300

  validation {
    condition     = var.qurl_ip_rate_limit > 0 && var.qurl_ip_rate_limit <= 10000
    error_message = "qurl_ip_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_ip_rate_burst" {
  description = "Burst allowance for IP-based internal routes"
  type        = number
  default     = 100

  validation {
    condition     = var.qurl_ip_rate_burst > 0 && var.qurl_ip_rate_burst <= 1000
    error_message = "qurl_ip_rate_burst must be between 1 and 1000"
  }
}

variable "qurl_config" {
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

variable "qurl_cookie_domain" {
  description = "Cookie domain for NHP tokens (e.g., .qurl.site)"
  type        = string
  default     = ".qurl.site"
}

variable "qurl_service_token_secret_arn" {
  type    = string
  default = null
}

variable "deploy_qurl_link" {
  type    = bool
  default = false
}

variable "qurl_link_frontend_domain" {
  type    = string
  default = null
}

variable "qurl_link_hosted_zone_id" {
  type    = string
  default = null
}

variable "qurl_link_external_dns" {
  type    = bool
  default = false
}

variable "qurl_link_enable_access_logs" {
  type    = bool
  default = false
}

variable "enable_resolve_cloudfront" {
  type    = bool
  default = false
}

variable "qurl_router_enabled" {
  type    = bool
  default = false
}

variable "qurl_router_cache_ttl" {
  type    = number
  default = 60
}

variable "qurl_router_negative_cache_ttl" {
  type    = number
  default = 30
}

variable "qurl_router_max_cache_size" {
  type    = number
  default = 1000
}

variable "qurl_router_api_timeout" {
  type    = number
  default = 5
}

variable "qurl_router_proxy_timeout" {
  type    = number
  default = 30
}

variable "qurl_router_cache_shards" {
  type    = number
  default = 16
}

variable "qurl_idempotency_cache_ttl_seconds" {
  type    = number
  default = 300
}

variable "qurl_idempotency_cache_max_size" {
  type    = number
  default = 1000
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  type    = number
  default = 60
}

variable "qurl_health_check_timeout_seconds" {
  type    = number
  default = 10
}

variable "qurl_health_startup_timeout_seconds" {
  type    = number
  default = 30
}

variable "qurl_license_cache_ttl_seconds" {
  type    = number
  default = 300
}

variable "qurl_license_cache_max_size" {
  type    = number
  default = 1000
}

variable "qurl_default_expires_in_seconds" {
  type    = number
  default = 86400
}

variable "qurl_resource_ttl_buffer_seconds" {
  type    = number
  default = 604800
}

variable "qurl_session_ttl_seconds" {
  type    = number
  default = 86400
}

variable "qurl_default_list_limit" {
  type    = number
  default = 20
}

variable "qurl_auth0_domain" {
  type    = string
  default = "auth.layerv.ai"
}

variable "qurl_auth0_audience" {
  description = "Auth0 API audience/identifier for JWT validation"
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_auth0_audience == "" || can(regex("^https://", var.qurl_auth0_audience))
    error_message = "qurl_auth0_audience must be an HTTPS URL"
  }
}

variable "qurl_auth0_jwks_cache_ttl_seconds" {
  type    = number
  default = 3600
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  type    = number
  default = 10
}

variable "qurl_default_ac_id" {
  type    = string
  default = ""
}

variable "qurl_default_ac_port" {
  type    = number
  default = 443
}

variable "qurl_webhooks_enabled" {
  type    = bool
  default = false
}

variable "qurl_webhooks_worker_count" {
  type    = number
  default = 4
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  type    = number
  default = 10
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  type    = number
  default = 30
}

variable "qurl_webhooks_max_retries" {
  type    = number
  default = 5
}

variable "qurl_webhooks_event_channel_size" {
  type    = number
  default = 1000
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  type    = number
  default = 30
}

variable "qurl_webhooks_drain_timeout_seconds" {
  type    = number
  default = 30
}

variable "qurl_webhooks_response_body_limit" {
  type    = number
  default = 8192
}

variable "qurl_webhooks_api_version" {
  type    = string
  default = "2024-01-01"
}

variable "qurl_geoip_enabled" {
  description = "Enable GeoIP lookups for geo-restriction policies"
  type        = bool
  default     = false
}

variable "qurl_geoip_db_path" {
  description = "Filesystem path for the GeoIP .mmdb database inside the container"
  type        = string
  default     = "/app/data/GeoLite2-Country.mmdb"
}

variable "qurl_geoip_s3_uri" {
  description = "S3 URI of the GeoLite2-Country .mmdb database"
  type        = string
  default     = ""
}

variable "qurl_otel_enabled" {
  type    = bool
  default = false
}

variable "qurl_otel_service_name" {
  type    = string
  default = "qurl-api"
}

variable "qurl_otel_service_version" {
  type    = string
  default = "prod"
}

variable "qurl_otel_environment" {
  type    = string
  default = "prod"
}

variable "qurl_otel_exporter_endpoint" {
  type    = string
  default = "http://localhost:4317"
}

variable "qurl_otel_exporter_protocol" {
  type    = string
  default = "grpc"
}

variable "qurl_otel_exporter_insecure" {
  type    = bool
  default = true
}

variable "qurl_otel_trace_sample_rate" {
  type    = number
  default = 0.1
}

variable "qurl_otel_metrics_interval" {
  type    = number
  default = 60
}

variable "qurl_otel_metrics_enabled" {
  type    = bool
  default = true
}

variable "qurl_otel_tracing_enabled" {
  type    = bool
  default = true
}

variable "qurl_otel_log_correlation" {
  type    = bool
  default = true
}

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

variable "qurl_grafana_cloud_enabled" {
  type    = bool
  default = false
}

variable "qurl_grafana_secret_arn" {
  type    = string
  default = null
}

variable "qurl_adot_collector_image" {
  type    = string
  default = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

variable "grafana_dashboards_enabled" {
  type    = bool
  default = false
}

variable "grafana_url" {
  type    = string
  default = ""
}

variable "grafana_auth" {
  type      = string
  default   = ""
  sensitive = true
}

variable "grafana_nhp_dashboard_url" {
  type    = string
  default = ""
}

variable "grafana_cloudwatch_enabled" {
  type    = bool
  default = false
}

variable "grafana_cloud_aws_account_id" {
  type    = string
  default = ""
}

variable "grafana_cloud_external_id" {
  type    = string
  default = ""
}

variable "grafana_create_dashboards" {
  type    = bool
  default = true
}

variable "grafana_prometheus_datasource_uid" {
  type    = string
  default = "grafanacloud-prom"
}

variable "grafana_tempo_datasource_uid" {
  type    = string
  default = "grafanacloud-traces"
}

variable "traefik_plugins" {
  type = map(object({
    version = string
    config  = optional(map(string), {})
  }))
  default = {}
}

variable "traefik_plugins_deploy_bucket_arn" {
  type    = string
  default = null
}

variable "plugin_repos" {
  type    = list(string)
  default = []
}

variable "cross_account_route53_role_arn" {
  type    = string
  default = null
}

variable "deploy_console_ec2" {
  type    = bool
  default = false
}

variable "console_ec2_domain" {
  type    = string
  default = null
}

variable "console_cookie_domain" {
  type    = string
  default = null
}

variable "console_internal_only" {
  type    = bool
  default = false
}

variable "console_protected_hostname" {
  type    = string
  default = null
}

variable "console_ac_license_key_hash" {
  type      = string
  sensitive = true
  default   = ""
}

variable "console_ac_license_key_sha256" {
  type      = string
  sensitive = true
  default   = null
}

variable "nhp_dynamodb_licenses_customer_index" {
  type    = string
  default = null
}

variable "nhp_dynamodb_licenses_auth0_subject_index" {
  type    = string
  default = null
}

variable "internal_service_token_secret_arn" {
  type    = string
  default = null
}

variable "provisioning_resource_id" {
  type    = string
  default = null
}

variable "provisioning_default_tier" {
  type    = string
  default = null
}

variable "provisioning_default_max_acs" {
  type    = number
  default = null
}

# NHP Server Assignment Configuration (required, no defaults)
variable "nhp_server_assignment_enabled" {
  type = bool
}

variable "nhp_region" {
  type = string
}

variable "nhp_cloudmap_service_name" {
  type = string
}

variable "nhp_assignment_servers_per_ac" {
  type = number
}

variable "nhp_assignment_require_distinct_azs" {
  type = bool
}

variable "nhp_health_monitor_check_interval" {
  type = number
}

variable "nhp_health_monitor_operation_timeout" {
  type = number
}

variable "nhp_console_ac_enabled" {
  type = bool
}

variable "ac_customer_id" {
  type    = string
  default = null
}

variable "ac_license_key" {
  type      = string
  sensitive = true
  default   = null
}

variable "ac_license_key_hash" {
  type      = string
  sensitive = true
  default   = null
}

variable "ac_license_key_sha256" {
  type      = string
  sensitive = true
  default   = null
}

variable "guardduty_alert_emails" {
  type    = list(string)
  default = []
}

variable "alert_emails" {
  description = "Email addresses for CloudWatch alarm SNS notifications"
  type        = list(string)
  default     = []
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch Logs"
  type        = bool
  default     = true
}

variable "qurl_desired_count" {
  description = "Desired number of QURL ECS tasks"
  type        = number
  default     = 1
}

variable "qurl_autoscaling_min_capacity" {
  description = "Minimum number of QURL ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

variable "qurl_autoscaling_max_capacity" {
  description = "Maximum number of QURL ECS tasks for auto-scaling"
  type        = number
  default     = 4
}

variable "deploy_redis" {
  description = "Deploy ElastiCache Serverless Redis for distributed QURL rate limiting"
  type        = bool
  default     = false
}

# ==============================================================================
# Auth0 Configuration
# ==============================================================================

variable "auth0_domain" {
  description = "Auth0 tenant domain for Management API (e.g., dev-xxx.us.auth0.com)"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+(\\.(us|eu|au|jp))?\\.auth0\\.com$", var.auth0_domain))
    error_message = "auth0_domain must be a valid Auth0 tenant domain (e.g., layerv.auth0.com or dev-xxx.us.auth0.com)"
  }
}

variable "auth0_tf_client_id" {
  description = "Auth0 M2M client ID for Terraform provider. Set via TF_VAR_auth0_tf_client_id."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.auth0_tf_client_id) > 0
    error_message = "auth0_tf_client_id must be set. Pass via TF_VAR_auth0_tf_client_id environment variable or sensitive.auto.tfvars."
  }
}

variable "auth0_tf_client_secret" {
  description = "Auth0 M2M client secret for Terraform provider. Set via TF_VAR_auth0_tf_client_secret."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.auth0_tf_client_secret) > 0
    error_message = "auth0_tf_client_secret must be set. Pass via TF_VAR_auth0_tf_client_secret environment variable or sensitive.auto.tfvars."
  }
}

variable "auth0_enable_rotation" {
  type    = bool
  default = false
}

variable "auth0_rotation_days" {
  type    = number
  default = 30
}

variable "auth0_management_secret_arn" {
  type    = string
  default = null
}

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================

variable "centralized_cert_enabled" {
  type    = bool
  default = false
}

variable "centralized_cert_domains" {
  type    = list(string)
  default = []
}

# ==============================================================================
# Blue/Green Deployment Configuration
# ==============================================================================

variable "enable_blue_green" {
  type    = bool
  default = false
}

variable "green_standby_min_size" {
  type    = number
  default = 1
}

variable "deployment_stale_threshold_days" {
  type    = number
  default = 7
}

variable "enable_ac_blue_green" {
  type    = bool
  default = false
}

variable "ac_green_standby_min_size" {
  type    = number
  default = 1
}

# ==============================================================================
# Canary Deployment Configuration
# ==============================================================================

variable "enable_canary_deployment" {
  description = "Enable Step Functions-based canary deployment for progressive production rollouts"
  type        = bool
  default     = false
}

variable "canary_checkpoint_percentages" {
  description = "Instance refresh checkpoint percentages for canary stages"
  type        = list(number)
  default     = [20, 50, 100]
}

variable "canary_checkpoint_delay_seconds" {
  description = "Seconds to observe at each canary checkpoint before auto-resuming"
  type        = number
  default     = 300
}

variable "canary_instance_warmup_seconds" {
  description = "Instance warmup time in seconds for canary refresh"
  type        = number
  default     = 180
}

# ==============================================================================
# Status Page Configuration
# ==============================================================================

variable "deploy_status_page" {
  description = "Deploy the status page (Lambda + API Gateway + S3 + CloudFront)"
  type        = bool
  default     = false
}

variable "status_page_domain" {
  description = "Custom domain for the status page"
  type        = string
  default     = null
}

variable "status_page_hosted_zone_id" {
  description = "Route53 hosted zone ID for the status page domain"
  type        = string
  default     = null
}

# ==============================================================================
# Cost Analytics
# ==============================================================================

variable "deploy_cost_analytics" {
  description = "Deploy AWS cost analytics (Data Export + Athena + Grafana dashboard)"
  type        = bool
  default     = false
}

variable "cross_account_cost_analytics_role_arn" {
  description = "IAM role ARN in mgmt account for cost analytics resources"
  type        = string
  default     = null
}

variable "grafana_athena_config" {
  description = "Direct Athena config for cost dashboard when cost_analytics module is not deployed. Allows environments to share a single cost_analytics backend."
  type = object({
    assume_role_arn = string
    workgroup       = string
    database        = string
    region          = optional(string, "us-east-1")
  })
  default = null
}

# Developer Portal
variable "deploy_developer_portal" {
  description = "Deploy developer portal infrastructure (playground proxy + credential provisioner)"
  type        = bool
  default     = false
}

variable "developer_portal_m2m_secret_name" {
  description = "Secrets Manager secret name for playground M2M credentials"
  type        = string
  default     = null
}

variable "developer_portal_auth0_mgmt_secret_name" {
  description = "Secrets Manager secret name for Auth0 management API credentials"
  type        = string
  default     = null
}

variable "developer_portal_auth0_domain" {
  description = "Auth0 domain for developer portal"
  type        = string
  default     = null
}

variable "developer_portal_allowed_origins" {
  description = "CORS allowed origins for developer portal API"
  type        = list(string)
  default     = []
}

variable "dashboard_allowed_origins" {
  description = "Default CORS origins shared by all dashboard APIs (developer portal, billing)"
  type        = list(string)
  default     = []
}

variable "deploy_billing" {
  description = "Deploy billing infrastructure (Stripe integration, usage reporting, payment grace)"
  type        = bool
  default     = false
}

variable "developer_portal_custom_domain" {
  description = "Custom domain for developer portal API"
  type        = string
  default     = null
}

variable "developer_portal_hosted_zone_id" {
  description = "Route53 hosted zone ID for developer portal custom domain"
  type        = string
  default     = null
}

variable "developer_portal_ci_bypass_secret_name" {
  description = "Secrets Manager secret name for CI bypass key"
  type        = string
  default     = null
}

# ==============================================================================
# Auth0 SPA Dashboard Configuration
# ==============================================================================

variable "enable_auth0_spa_dashboard" {
  description = "Enable Auth0 SPA client for dashboard login"
  type        = bool
  default     = false
}

variable "auth0_spa_callback_urls" {
  description = "Auth0 SPA callback URLs for dashboard"
  type        = list(string)
  default     = []
}

variable "auth0_spa_logout_urls" {
  description = "Auth0 SPA logout URLs for dashboard"
  type        = list(string)
  default     = []
}

variable "auth0_spa_web_origins" {
  description = "Auth0 SPA web origins for dashboard CORS"
  type        = list(string)
  default     = []
}

variable "auth0_custom_domain" {
  description = "Auth0 custom domain for SPA login (e.g., auth.layerv.ai). If null, falls back to auth0_domain."
  type        = string
  default     = null
}

# ==============================================================================
# Auth0 Social Connection Configuration
# ==============================================================================
# OAuth credentials for social login providers (Google, GitHub).
# Pass via environment variables: TF_VAR_google_oauth_client_id, etc.
# Store in GitHub Secrets for CI/CD.

variable "google_oauth_client_id" {
  description = "Google OAuth2 client ID for social login. If null, Google connection is not created."
  type        = string
  default     = null
  sensitive   = true
}

variable "google_oauth_client_secret" {
  description = "Google OAuth2 client secret for social login."
  type        = string
  default     = null
  sensitive   = true
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth client ID for social login. If null, GitHub connection is not created."
  type        = string
  default     = null
  sensitive   = true
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth client secret for social login."
  type        = string
  default     = null
  sensitive   = true
}
