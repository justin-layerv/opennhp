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

variable "server_ami_id" {
  description = "Docker-optimized AMI ID for NHP Server. If null, compute module reads from /prod/nhp/server/ami-id SSM parameter."
  type        = string
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

variable "enable_replication" {
  description = "Enable ECR cross-account replication (receive images from primary account)"
  type        = bool
  default     = false
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

variable "enable_egress_eips" {
  description = "Allocate Elastic IPs for AC instances for stable egress IPs (2x when blue/green enabled). Customers whitelist these on their origin firewalls."
  type        = bool
  default     = false
}

# AC configuration
variable "ac_auth_service_id" {
  type    = string
  default = "agent"
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

variable "nhp_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for NHP HTTP server"
  type        = string
  default     = ""
}

variable "nhp_knock_headertype_verify_require" {
  description = "Wrapper passthrough for the root nhp_knock_headertype_verify_require — see ../../variables.tf and ../../modules/compute/variables.tf for gate semantics and burn-in criteria."
  type        = bool
  default     = false
}

variable "nhp_knock_global_rate_limit_pps" {
  description = "Wrapper passthrough for the root nhp_knock_global_rate_limit_pps (#1159). Aggregate UDP knock pps cap."
  type        = number
  default     = 5000
}

variable "nhp_knock_global_rate_limit_burst" {
  description = "Wrapper passthrough for the root nhp_knock_global_rate_limit_burst (#1159). Burst allowance for the aggregate cap."
  type        = number
  default     = 10000
}

variable "nhp_udp_recv_buffer_bytes" {
  description = "Wrapper passthrough for the root nhp_udp_recv_buffer_bytes (#1159). Target SO_RCVBUF for the NHP knock listen socket."
  type        = number
  default     = 8388608
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
  default = true
}

variable "slack_workspace_id" {
  type    = string
  default = "T09UP622L90"
}

variable "slack_channel_id" {
  type    = string
  default = "C09UP62A8F4"
}

variable "chatbot_owned_externally" {
  description = "Prod's #all-layerv Chatbot config is owned by website CDK's LayerV-Monitoring stack (us-east-1, ProdSlackChannel), which subscribes our layerv-nhp-prod-cell0-alerts SNS topic. Default true keeps NHP from re-colliding on the (workspace, channel) pair. See website repo CLAUDE.md *Cross-repo handoff*."
  type        = bool
  default     = true
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

variable "qurl_internal_service_domain" {
  description = "Hostname for the QURL API internal ALB (e.g., internal-api.qurl.layerv.ai). See canonical doc + RFC1035 validation on the root variable of the same name."
  type        = string
  default     = null
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

# ==================== qurl-router HRW (traefik-plugins #134) ====================

variable "enable_instance_hrw" {
  description = "Enable router-side HRW dispatch in qurl-router. Default false; PR 4 flips to true after sandbox validation. See terraform/variables.tf for the full description."
  type        = bool
  default     = false
}

variable "instance_discovery_ttl_seconds" {
  description = "TTL in seconds for the qurl-router instance-IP allowlist. Range validation lives at the root (terraform/variables.tf) and on the AC module's qurl_router_config — duplicating it here would be a future inconsistency vector."
  type        = number
  default     = 20
}

variable "enable_qurl_site_authz" {
  description = "Enable the qurl-router L7 per-session authz gate on *.qurl.site. See terraform/variables.tf for the full description (activation cadence, producer dependency, trust-boundary requirements)."
  type        = bool
  default     = false
}

variable "qurl_tunnel_active_registrations_enabled" {
  description = "Enable qurl-service to publish authoritative active reverse-tunnel target sets (`upstream_addrs`) from qurl-reverse-tunnel-server registration heartbeats. Default false keeps prod on the legacy per-AZ upstream_addr path until sandbox burn-in completes."
  type        = bool
  default     = false
}

# ==================== qurl-reverse-tunnel-server deploy + sizing (per-AZ + canary) ====================
# PR 3 only declares the NEW per-AZ / blue/green / canary variables here.
# The existing tfvars values for `deploy_frps` / `frps_*` are already
# latent no-ops in env tfvars (the env main.tf never forwarded them);
# PR 3 leaves that pre-existing gap untouched to avoid changing deploy
# state. PR 4 wires the legacy passthrough at the same time as the
# value flip.

variable "qurl_reverse_tunnel_server_min_size_per_az" {
  description = "Per-AZ ASG min size for qurl-reverse-tunnel-server. Default null keeps the legacy frps_min_size as the source of truth. See terraform/variables.tf for the full description and resolution rule."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_max_size_per_az" {
  description = "Per-AZ ASG max size for qurl-reverse-tunnel-server. Default null keeps the legacy frps_max_size as the source of truth. See terraform/variables.tf for the full description."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_desired_capacity_per_az" {
  description = "Per-AZ ASG desired capacity for qurl-reverse-tunnel-server. Default null keeps the legacy frps_desired_capacity. PR 4 will set this to 2 in prod tfvars to flip 1/AZ → 2/AZ."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_cloud_map_routing_policy" {
  description = "Cloud Map routing policy for qurl-reverse-tunnel-server per-AZ services. PR 4 flips to MULTIVALUE for router-side HRW dispatch."
  type        = string
  default     = "WEIGHTED"
}

variable "enable_qurl_reverse_tunnel_server_blue_green" {
  description = "Enable blue/green for qurl-reverse-tunnel-server. Sandbox-targeted; mutually exclusive with enable_qurl_reverse_tunnel_server_canary."
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_green_standby_capacity_per_az" {
  description = "Per-AZ desired capacity for the qurl-reverse-tunnel-server green ASG when in standby. Default null = auto-track min_size_per_az when set, else 1. Set explicitly for cold standby (0) or custom values. Ignored when enable_qurl_reverse_tunnel_server_blue_green=false. See terraform/variables.tf for the full description."
  type        = number
  default     = null
}

variable "enable_qurl_reverse_tunnel_server_canary" {
  description = "Enable canary deployment for qurl-reverse-tunnel-server via the canary-deployment module. Prod-targeted; mutually exclusive with enable_qurl_reverse_tunnel_server_blue_green."
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_tunnel_auth_mode" {
  description = <<-EOT
    Env-root pass-through for the root module's `qurl_reverse_tunnel_server_tunnel_auth_mode`
    variable. Prod keeps the default "" while deploy_frps is false, but declaring
    and forwarding the value here means the future prod FRPS flip can opt into
    "tunnel-auth" without discovering a silent env-wrapper gap at plan time.
    See `terraform/variables.tf::qurl_reverse_tunnel_server_tunnel_auth_mode`
    for the full rollout contract.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_reverse_tunnel_server_tunnel_auth_mode == "" || var.qurl_reverse_tunnel_server_tunnel_auth_mode == "tunnel-auth"
    error_message = "qurl_reverse_tunnel_server_tunnel_auth_mode must be \"\" (module-compat placeholder) or \"tunnel-auth\"."
  }
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

variable "qurl_customer_cache_ttl_seconds" {
  type    = number
  default = 300
}

variable "qurl_customer_cache_max_size" {
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
  default = 3600 # 1 hour — reduced from 24h to limit post-revocation access window
}

variable "deploy_custom_domain_cert" {
  description = "Deploy the custom domain certificate manager Lambda for QURL custom domains"
  type        = bool
  default     = false
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

variable "qurl_custom_domain_enabled" {
  description = "Enable custom domain management endpoints in QURL service"
  type        = bool
  default     = false
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

variable "qurl_geoip_s3_kms_key_arn" {
  description = "KMS key ARN used to encrypt the GeoIP S3 bucket"
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

variable "qurl_container_port" {
  description = "TCP port qurl-service tasks listen on. Threaded into BOTH module.qurl_service (container_port) AND module.bootstrap_alb (target_port) at the nhp module level so the two cannot drift (modules/bootstrap-alb/variables.tf::target_port explicitly calls out this footgun). Default 8080 — operators rarely override; only meaningful when the qurl-service container exposes a non-default port."
  type        = number
  default     = 8080
  nullable    = false

  validation {
    condition     = var.qurl_container_port > 0 && var.qurl_container_port < 65536
    error_message = "qurl_container_port must be a valid TCP port (1–65535)."
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
  default = null
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

variable "nhp_cloudmap_service_name" {
  type = string
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
  default     = true
}

variable "deploy_vpc_endpoints" {
  description = "Deploy additional VPC endpoints for QURL service AWS dependencies (DynamoDB gateway, SQS interface)"
  type        = bool
  default     = false
}

# ==============================================================================
# Website Email-Capture API DNS
# ==============================================================================

variable "deploy_website_api_dns" {
  type    = bool
  default = false
}

variable "website_api_domain" {
  type    = string
  default = null
}

variable "website_api_cfn_stack_name" {
  type    = string
  default = null
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

# Required for local dev (no default — must be set explicitly).
# In CI these are still passed but the provider nulls them when api_token is set.
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

# Optional — CI-only. When set, the provider uses this token and ignores client_id/client_secret.
variable "auth0_api_token" {
  description = "Pre-fetched Auth0 Management API token. When set, the Auth0 provider uses this instead of client_id/client_secret (saves 1 M2M token per plan/apply). Set via TF_VAR_auth0_api_token in CI."
  type        = string
  sensitive   = true
  default     = ""
}

variable "auth0_manage_tenant_resources" {
  description = "Whether this environment manages shared Auth0 tenant resources (roles, branding, attack protection, email, social connections). Only one environment should set this to true per shared tenant."
  type        = bool
  default     = true
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

variable "status_page_nhp_auth_enabled" {
  description = "Protect the status page with NHP authentication (dogfooding)"
  type        = bool
  default     = false
}

variable "status_page_nhp_auth_qurl_url" {
  description = "QURL link URL for status page authentication. Required when status_page_nhp_auth_enabled is true."
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

variable "billing_stripe_secret_name" {
  description = "Secrets Manager secret name for Stripe API key"
  type        = string
  default     = null
}

variable "billing_stripe_webhook_secret_name" {
  description = "Secrets Manager secret name for Stripe webhook signing secret"
  type        = string
  default     = null
}

variable "billing_stripe_api_base_url" {
  description = "Base URL for Stripe API"
  type        = string
  default     = "https://api.stripe.com"
}

variable "billing_growth_price_id" {
  description = "Stripe Price ID for the Growth plan metered usage component"
  type        = string
  default     = ""
}

variable "billing_base_fee_price_id" {
  description = "Stripe Price ID for the Growth plan base fee"
  type        = string
  default     = ""
}

variable "billing_success_url" {
  description = "URL to redirect to after successful Stripe Checkout"
  type        = string
  default     = null
}

variable "billing_cancel_url" {
  description = "URL to redirect to when user cancels Stripe Checkout"
  type        = string
  default     = null
}

variable "billing_allowed_origins" {
  description = "List of allowed CORS origins for billing API"
  type        = list(string)
  default     = []
}

variable "billing_from_email" {
  description = "SES verified sender email for grace period notifications"
  type        = string
  default     = null
}

variable "billing_ses_region" {
  description = "AWS region for SES"
  type        = string
  default     = "us-east-1"
}

variable "billing_grace_period_days" {
  description = "Days after payment failure before account is frozen"
  type        = number
  default     = 7
}

variable "billing_downgrade_after_days" {
  description = "Days after account freeze before downgrade to free tier"
  type        = number
  default     = 30
}

variable "billing_api_throttle_burst_limit" {
  description = "API Gateway throttle burst limit for billing API"
  type        = number
  default     = 10
}

variable "billing_api_throttle_rate_limit" {
  description = "API Gateway throttle rate limit for billing API"
  type        = number
  default     = 5
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

variable "developer_portal_connector_base_url" {
  description = "Base URL of the qURL S3 connector for /playground/upload."
  type        = string
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

# ==================== QURL Integrations DNS ====================
# See root terraform/variables.tf + main.tf for full rationale.

variable "deploy_qurl_integrations_dns" {
  description = "Create the cross-account A records for qurl-integrations-infra prod EC2 instances."
  type        = bool
  default     = false
}

variable "qurl_s3_connector_domain" {
  description = "FQDN for the qurl-s3-connector upload endpoint."
  type        = string
  default     = null
}

variable "qurl_s3_connector_eip" {
  description = "IPv4 EIP attached to the qurl-s3-connector EC2 instance."
  type        = string
  default     = null
}

variable "qurl_fileviewer_domain" {
  description = "FQDN for the fileviewer endpoint."
  type        = string
  default     = null
}

variable "qurl_fileviewer_eip" {
  description = "IPv4 EIP attached to the fileviewer EC2 instance."
  type        = string
  default     = null
}
