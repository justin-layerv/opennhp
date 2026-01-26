# Sandbox environment configuration
# Consistent with layerv/traefik-plugins terraform patterns

environment    = "sandbox"
aws_region     = "us-east-2"
aws_account_id = "767397897469"
domain_name    = "nhp.layerv.xyz"
hosted_zone    = "layerv.xyz"
multi_tenant   = true
min_capacity   = 1
max_capacity   = 10
vpc_cidr       = "10.100.0.0/16"

# Multi-account config: sandbox owns ECR repositories
is_primary_account = true
# secondary_account_ids = ["PROD_ACCOUNT_ID"]  # TODO: Add prod account ID when created

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.xyz"
ac_auth_service_id = "layerv"
ac_resource_ids    = ["demo", "mini-app-demo", "console"]

# Terraform state bucket for GitHub Actions permissions
terraform_state_bucket = "layerv-terraform-state-767397897469"
terraform_lock_table   = "terraform-state-lock"

# ==============================================================================
# Organization-Managed Resources
# ==============================================================================
# Some resources are managed centrally by the organization or blocked by SCPs.
# These settings ensure terraform works with pre-existing resources.

# OIDC Provider: Already exists in account, SCP blocks iam:CreateOpenIDConnectProvider
# Set to false to reference existing provider via data source
create_oidc_provider = false

# CloudTrail: SCP blocks cloudtrail:CreateTrail and cloudtrail:DeleteTrail
# The existing trail was created before SCP was applied and continues to work
enable_cloudtrail = false

# NHP Server configuration
# Set to true for sandbox to enable debug features
dev_mode      = true
resource_mode = "api"

# Termination cleanup: Lambda cleans stale DynamoDB assignments on server termination
enable_termination_cleanup = true
# auth_url is set dynamically in main.tf to Console EC2 internal NLB endpoint
# auth_signing_key and auth_aes_key are passed via GitHub Secrets (TF_VAR_auth_signing_key, TF_VAR_auth_aes_key)
# IMPORTANT: auth_signing_key must match Console's jwt.signing-key in config.yaml

# Slack notifications via AWS Chatbot
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C0A9S0VCAU9" # #alerts-sandbox

# GuardDuty security alerts (email + Slack via same SNS topic)
guardduty_alert_emails = [
  "justin@layerv.ai",
  "benc@layerv.ai",
  "joe@layerv.ai"
]

# RDS configuration for console database
deploy_rds              = true
rds_database_name       = "portal"
rds_min_capacity        = 0.5
rds_max_capacity        = 4
rds_deletion_protection = false # Allow deletion in sandbox

# NHP Server plugins - statically compiled into server binary
# This list specifies which AuthSvcIds are valid for authentication
# Plugins are compiled in at build time - no S3 download needed
server_plugins = ["passcode"]
# Add "oktaoidc" when OIDC authentication is needed

# Traefik plugins - sandbox uses "latest" for automatic updates
# When traefik-plugins repo deploys, it updates the "latest" version in S3
# AC instances will pick up the latest plugins on next boot/refresh
traefik_plugins = {
  hqdatamiddleware = {
    version = "latest"
    config  = {}
  }
}

# Traefik-plugins CI/CD uses a separate S3 bucket for SSM-based deployment
# This bucket is managed outside terraform (by traefik-plugins repo)
# The ARN is needed for AC instances to download plugin tarballs via SSM
traefik_plugins_deploy_bucket_arn = "arn:aws:s3:::traefik-plugins-deploy-767397897469"

# Repos that can assume the GitHub Actions IAM role
# NHP server plugins are now compiled in - only Traefik plugins use S3
plugin_repos = ["traefik-plugins", "console"]

# Production domains - disabled in sandbox
# qurl.site/qurl.link zones are in layerv-mgmt, requiring cross-account Route 53 access
# which conflicts with nhp.layerv.xyz in layerv account. Enable in prod environment only.
# production_domains = ["qurl.site", "qurl.link"]
# cross_account_route53_role_arn = "arn:aws:iam::165115313779:role/nhp-ac-route53-access"

# Additional domains for TLS certificates (same account, layerv.xyz zone)
# apps.layerv.xyz is needed for console2.apps.layerv.xyz (NHP-protected Console)
additional_tls_domains = ["apps.layerv.xyz"]

# Use production Let's Encrypt for valid browser-trusted certificates
# (Staging certs are not trusted by browsers)
use_production_acme = true

# ==============================================================================
# Demo Gateway Configuration
# Routes qurl.link/{appId} to NHP Server passcode plugin for demo flow
# ==============================================================================
# Set to true to deploy Demo Gateway (nginx + certbot for TLS)
# Requires cross_account_route53_role_arn for qurl.link ACME challenges
deploy_demo_gateway = false
# demo_gateway_domain = "qurl.link"
# demo_gateway_hosted_zone_id = "Z..." # qurl.link zone ID in layerv-mgmt

# ==============================================================================
# Console EC2 Configuration
# Console API for portal site management (alternative to Fargate - more cost effective)
# ==============================================================================
# Set to true to deploy Console on EC2 instead of ECS Fargate
deploy_console_ec2    = true
console_ec2_domain    = "console.nhp.layerv.xyz"
console_cookie_domain = ".layerv.xyz"
# Set to true to make Console internal-only (NHP-protected via AC)
# When enabled: Console runs on private subnets, accessed via AC NLB after NHP auth
# Traffic flow: Internet → AC NLB → Traefik → nhp-acd → Console internal NLB
console_internal_only = true
# Two-domain architecture for NHP Console:
# - Login domain: console.nhp.layerv.xyz (Traefik bypass, unprotected)
# - Protected domain: console2.apps.layerv.xyz (NHP-protected, where users land after auth)
console_protected_hostname = "console2.apps.layerv.xyz"
# Console AC license credentials for DynamoDB validation
# Generated with: ./terraform/scripts/generate-console-ac-license.sh sandbox
console_ac_license_key_hash   = "$2b$10$CtI9zvLpcpzt0JNscTwUIOSXL67YvC4sh1dkJsh0/Y6nytM41sWGm"
console_ac_license_key_sha256 = "f011ddf4f224db6f583da60bb998ec8ac225659c539aac176ca0d6935e28708c"

# Console license lookup GSI names
nhp_dynamodb_licenses_customer_index      = "customer_id-index"
nhp_dynamodb_licenses_auth0_subject_index = "auth0_subject-index"

# NHP Server Assignment Configuration
# All fields are required - no defaults (explicit configuration philosophy)
nhp_server_assignment_enabled        = true
nhp_region                           = "us-east-2"
nhp_cloudmap_service_name            = "server"
nhp_assignment_servers_per_ac        = 3
nhp_assignment_require_distinct_azs  = true
nhp_health_monitor_check_interval    = 60
nhp_health_monitor_operation_timeout = 30
nhp_console_ac_enabled               = true

# Console customer provisioning (for Auth0 Post User Registration)
# internal_service_token_secret_arn must be created in Secrets Manager first
# provisioning_resource_id   = "qurl-auto-provisioned"
# provisioning_default_tier  = "free"
# provisioning_default_max_acs = 1

# Standalone AC license credentials for DynamoDB validation
# Generated with: ./terraform/scripts/generate-ac-license.sh sandbox
# Note: ac_license_key comes from GitHub Secret (AC_LICENSE_KEY)
ac_customer_id        = "00000000000000000000000000"
ac_license_key_hash   = "$2b$10$DBTFv1FKlHIGC3PCcatuQuAnhxZzH8EgfZMCzOYEQZH4dAtAYFwve"
ac_license_key_sha256 = "a762d8af6c774acf2d0560575658062f306cd2e872409ac52cf0baf0749f4e7e"

# NHP network-level protection is always enabled on Console EC2.
# Console runs its own nhp-acd with iptables DROP by default.
# Port 443 is only accessible after NHP knock adds the user's IP to ipset.

# ==============================================================================
# QURL Service Configuration
# ECS Fargate deployment for QURL API (Auth0 JWT protected, no NHP needed)
# ==============================================================================
# QURL API service is deployed by default
deploy_qurl_service = true

# Domain configuration (set these when deploying)
# qurl_service_domain = "api.qurl.link"
# qurl_hosted_zone_id = "Z..."  # qurl.link zone ID in layerv-mgmt
# qurl_certificate_arn = "arn:aws:acm:us-east-2:767397897469:certificate/..."

# Auth0 configuration for JWT validation
qurl_auth0_domain   = "auth.layerv.ai"
qurl_auth0_audience = "https://api.layerv.xyz"

# Auth0 Terraform provider configuration
# IMPORTANT: auth0_domain must be the TENANT domain (not custom domain auth.layerv.ai)
# The custom domain is used for qurl_auth0_domain (JWKS validation in QURL service)
# but the Management API requires the actual tenant domain.
auth0_domain = "dev-q1kiedn8knbutena.us.auth0.com"
# auth0_tf_client_id and auth0_tf_client_secret are REQUIRED
# Pass via: TF_VAR_auth0_tf_client_id and TF_VAR_auth0_tf_client_secret
# In CI: Set from GitHub Secrets (AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

# Secrets Manager ARNs
qurl_jwt_secret_arn             = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-jwt-secret-i8a8OZ"
qurl_internal_service_token_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-internal-service-token-XgjoDM"

# AC Fleet defaults (for QURL resources)
# qurl_default_ac_id = "ac-sandbox-01"
# qurl_default_ac_host = "ac.nhp.layerv.xyz"

# Domain configuration for QURL links and sites
qurl_link_domain = "qurl.link"
qurl_site_domain = "qurl.site"

# Rate limiting (requests per minute)
qurl_owner_rate_limit = 200 # authenticated owner routes
qurl_owner_rate_burst = 50
qurl_ip_rate_limit    = 300 # internal API routes
qurl_ip_rate_burst    = 100

# Audit log retention
qurl_audit_retention_days = 90

# CORS - empty string means allow all origins (development mode only)
# In production, set to comma-separated list: "https://console.layerv.ai,https://app.layerv.ai"
qurl_cors_allowed_origins = ""

# Additional allowed hosts for DNS rebinding protection
# ALB DNS name, localhost, and 127.0.0.1 are always included automatically.
# Add custom domains here (e.g., ["api.qurl.link", "api-sandbox.qurl.link"])
qurl_additional_allowed_hosts = []

# Container sizing
# Note: When grafana_cloud_enabled=true, ADOT sidecar requires min 512 CPU and adds 256MB memory.
# Effective values: CPU=max(container_cpu, 512), Memory=container_memory+256
# For 512 CPU, effective memory must be 1024-4096, so container_memory >= 768
qurl_container_cpu    = 256 # 0.25 vCPU (effective: 512 with ADOT)
qurl_container_memory = 768 # 768 MB (effective: 1024 with ADOT sidecar)
# qurl_desired_count  = 1

# Idempotency cache configuration
qurl_idempotency_cache_ttl_seconds        = 300 # 5 minutes
qurl_idempotency_cache_max_size           = 1000
qurl_idempotency_cleanup_interval_seconds = 60 # 1 minute

# Health check configuration
qurl_health_check_timeout_seconds   = 10
qurl_health_startup_timeout_seconds = 30

# License cache configuration
qurl_license_cache_ttl_seconds = 300 # 5 minutes
qurl_license_cache_max_size    = 1000

# Auth0 JWKS cache configuration
qurl_auth0_jwks_cache_ttl_seconds     = 3600 # 1 hour
qurl_auth0_jwks_fetch_timeout_seconds = 10

# Webhooks configuration (disabled by default)
qurl_webhooks_enabled                       = false
qurl_webhooks_worker_count                  = 4
qurl_webhooks_max_webhooks_per_owner        = 10
qurl_webhooks_delivery_timeout_seconds      = 30
qurl_webhooks_max_retries                   = 5
qurl_webhooks_event_channel_size            = 1000
qurl_webhooks_retry_worker_interval_seconds = 30
qurl_webhooks_drain_timeout_seconds         = 30
qurl_webhooks_response_body_limit           = 8192 # 8KB
qurl_webhooks_api_version                   = "2024-01-01"

# Observability configuration - enabled with Grafana Cloud export
qurl_otel_enabled           = true
qurl_otel_service_name      = "qurl-api"
qurl_otel_service_version   = "dev"
qurl_otel_environment       = "sandbox"
qurl_otel_exporter_endpoint = "http://localhost:4317" # ADOT sidecar
qurl_otel_exporter_protocol = "grpc"
qurl_otel_exporter_insecure = true
qurl_otel_trace_sample_rate = 1.0
qurl_otel_metrics_interval  = 60
qurl_otel_metrics_enabled   = true
qurl_otel_tracing_enabled   = true
qurl_otel_log_correlation   = true

# Grafana Cloud ADOT Sidecar - exports telemetry to layervai.grafana.net
qurl_grafana_cloud_enabled = true
qurl_grafana_secret_arn    = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/grafana-cloud-otlp-mQLsCm"

# Grafana Cloud Dashboards - provisions dashboards via Terraform
# Pass token via: TF_VAR_grafana_auth=glsa_xxx terraform apply
grafana_dashboards_enabled        = true
grafana_url                       = "https://layervai.grafana.net"
grafana_prometheus_datasource_uid = "grafanacloud-prom"
grafana_tempo_datasource_uid      = "grafanacloud-traces"

# ==============================================================================
# QURL Router Plugin Configuration
# Traefik plugin that routes *.qurl.site requests to target backends
# Requires QURL Service to be deployed (deploy_qurl_service = true)
# ==============================================================================
# Enable QURL Router when QURL Service is deployed and internal_service_token is configured
qurl_router_enabled = false # Set to true after configuring qurl_internal_service_token_arn

# Cache settings (defaults are reasonable for most use cases)
# qurl_router_cache_ttl          = 60   # seconds for successful lookups
# qurl_router_negative_cache_ttl = 30   # seconds for 404s
# qurl_router_max_cache_size     = 1000 # max cache entries
# qurl_router_api_timeout        = 5    # seconds for QURL API calls
# qurl_router_proxy_timeout      = 30   # seconds for proxying to backend

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
