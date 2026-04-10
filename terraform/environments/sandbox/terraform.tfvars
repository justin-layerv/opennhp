# Sandbox environment configuration
# Consistent with layerv/traefik-plugins terraform patterns

environment    = "sandbox"
aws_region     = "us-east-2"
aws_account_id = "767397897469"
domain_name    = "nhp.layerv.xyz"
hosted_zone    = "layerv.xyz"
multi_tenant   = true
deploy_etcd    = false # Cloud deployment uses DynamoDB, not etcd
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.100.0.0/16"

# Multi-account config: sandbox owns ECR repositories
is_primary_account    = true
secondary_account_ids = ["235500187906"] # Prod account - enables cross-account ECR pull
enable_replication    = true             # Replicate images to prod so prod has no runtime dependency on sandbox

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.xyz"
ac_auth_service_id = "layerv"
ac_min_capacity    = 3
ac_resource_ids    = ["qurl"]
enable_egress_eips = true

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

# AWS Config: DAILY recording of specific resource types (was CONTINUOUS/ALL = ~$460/mo)
config_recording_frequency = "DAILY"

# NHP Server configuration
# Set to true for sandbox to enable debug features
log_level     = 4 # Debug for sandbox (0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace)
dev_mode      = true
resource_mode = "api"

# CORS allowed origins for NHP HTTP server (browser-facing plugin endpoints)
# Wildcard patterns (https://*.domain) match any single-level subdomain.
# Needed because AC Traefik serves pages on dynamic {resId}.nhp.layerv.xyz subdomains.
nhp_cors_allowed_origins = "https://*.nhp.layerv.xyz,https://*.apps.layerv.xyz,https://*.qurl.site.layerv.xyz,https://qurl.link.layerv.xyz,https://staging.layerv.ai"

# Termination cleanup: Lambda cleans stale DynamoDB assignments on server termination
enable_termination_cleanup = true

# Secret reconciliation: Lambda cleans orphaned per-instance AC secrets daily
enable_secret_reconciliation = true
# auth_url, auth_signing_key, and auth_aes_key are passed via GitHub Secrets (TF_VAR_*)

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

# NHP Server plugins - statically compiled into server binary
# This list specifies which AuthSvcIds are valid for authentication
# Plugins are compiled in at build time - no S3 download needed
server_plugins = ["passcode", "qurl"]
# Add "oktaoidc" when OIDC authentication is needed

# Traefik plugins - sandbox uses "latest" for automatic updates
# When traefik-plugins repo deploys, it updates the "latest" version in S3
# AC instances will pick up the latest plugins on next boot/refresh
#
# Key naming convention:
# - Short names (e.g., "hqdatamiddleware"): For plugins that don't require
#   Traefik's moduleName-based path resolution
# - Full module paths (e.g., "github.com/traefik/qurl-router"): For Traefik
#   local plugins that require the key to match the moduleName in traefik.toml
#   (plugins-local/src/{key}/ must exist)
traefik_plugins = {
  hqdatamiddleware = {
    version = "latest"
    config  = {}
  }
  "github.com/traefik/qurl-router" = {
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
plugin_repos = ["traefik-plugins"]

# QURL domains for sandbox (subdomains of layerv.xyz, same-account DNS)
# Production owns qurl.site and qurl.link directly
production_domains = ["qurl.site.layerv.xyz", "qurl.link.layerv.xyz"]

# Additional domains for TLS certificates (same account, layerv.xyz zone)
# apps.layerv.xyz is needed for console2.apps.layerv.xyz (NHP-protected Console)
additional_tls_domains = ["apps.layerv.xyz"]

# Use production Let's Encrypt for valid browser-trusted certificates
# (Staging certs are not trusted by browsers)
use_production_acme = true

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs
# without hitting Let's Encrypt rate limits.
#
# NOTE: This is an interim solution. For production at scale, consider migrating
# to HashiCorp Vault PKI for short-lived certificates and better revocation.
#
# To enable:
# 1. Set centralized_cert_enabled = true
# 2. Set centralized_cert_domains to the domains for the certificate
# 3. Run: terraform apply (creates the acme-cert module)
# 4. Invoke Lambda to generate cert: aws lambda invoke --function-name layerv-nhp-sandbox-acme-cert-manager --payload '{"type":"force_renew"}' /dev/stdout
# 5. Refresh AC instances to pick up the new cert

centralized_cert_enabled = true
centralized_cert_domains = ["nhp.layerv.xyz", "*.nhp.layerv.xyz", "apps.layerv.xyz", "*.apps.layerv.xyz", "qurl.site.layerv.xyz", "*.qurl.site.layerv.xyz", "qurl.link.layerv.xyz", "*.qurl.link.layerv.xyz"]

# Custom domain certificate manager — provisions Let's Encrypt certs for
# customer custom domains registered via the QURL API.
deploy_custom_domain_cert = true

# CloudMap configuration — enables server health filtering for knock forwarding
nhp_cloudmap_service_name = "server"
cloudmap_enabled          = true

# Standalone AC license credentials for DynamoDB validation
# Generated with: ./terraform/scripts/generate-ac-license.sh sandbox
# Note: ac_license_key comes from GitHub Secret (AC_LICENSE_KEY)
ac_customer_id        = "00000000000000000000000000"
ac_license_key_hash   = "$2b$10$DBTFv1FKlHIGC3PCcatuQuAnhxZzH8EgfZMCzOYEQZH4dAtAYFwve"
ac_license_key_sha256 = "a762d8af6c774acf2d0560575658062f306cd2e872409ac52cf0baf0749f4e7e"

# ==============================================================================
# QURL Service Configuration
# ECS Fargate deployment for QURL API (Auth0 JWT protected, no NHP needed)
# ==============================================================================
# QURL API service is deployed by default
deploy_qurl_service = true

# Domain configuration for QURL API
# Certificate is created automatically via Terraform when domain is set
qurl_service_domain = "api.layerv.xyz"
qurl_hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone

# Auth0 configuration for JWT validation
qurl_auth0_domain   = "auth.layerv.ai"
qurl_auth0_audience = "https://api.layerv.xyz"

# Auth0 Terraform provider configuration
# IMPORTANT: auth0_domain must be the TENANT domain (not custom domain auth.layerv.ai)
# The custom domain is used for qurl_auth0_domain (JWKS validation in QURL service)
# but the Management API requires the actual tenant domain.
# Both sandbox and prod share a single Auth0 tenant with the auth.layerv.ai custom
# domain. They are distinguished by separate API audiences.
# Prod now owns shared Auth0 tenant resources (roles, branding, attack protection, email, social connections)
auth0_manage_tenant_resources = false
auth0_domain                  = "layerv.us.auth0.com"
# auth0_tf_client_id and auth0_tf_client_secret are REQUIRED
# Pass via: TF_VAR_auth0_tf_client_id and TF_VAR_auth0_tf_client_secret
# In CI: Set from GitHub Secrets (AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

# Secrets Manager ARNs
qurl_jwt_secret_arn             = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-jwt-secret-i8a8OZ"
qurl_internal_service_token_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-internal-service-token-XgjoDM"

# Custom domain management (enables GET/POST/DELETE /v1/domains endpoints)
# ACME suffix and NLB target are derived from hosted_zone and AC module automatically
qurl_custom_domain_enabled = true

# GeoIP database for geo-restriction policies (geo_allowlist/geo_denylist)
qurl_geoip_enabled        = true
qurl_geoip_s3_uri         = "s3://layerv-nhp-sandbox-plugins/geoip/GeoLite2-Country.mmdb"
qurl_geoip_s3_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/c5250da7-1d0f-40a7-9ee5-64699fe15e10"

# AC Fleet defaults (for QURL resources)
qurl_default_ac_id   = "layerv-ac-tf"
qurl_default_ac_port = 443

# Domain configuration for QURL links and sites
qurl_cookie_domain       = ".qurl.site.layerv.xyz"
qurl_link_domain         = "qurl.link.layerv.xyz"
qurl_site_domain         = "qurl.site.layerv.xyz"
qurl_site_hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)

# Rate limiting (requests per minute)
qurl_ip_rate_limit = 300 # internal API routes
qurl_ip_rate_burst = 100

# Audit log retention
qurl_audit_retention_days = 90

# CORS allowed origins (required)
# For sandbox, allow console, qurl, and website domains.
# Note: staging.layerv.ai appears here (QURL API) AND in dashboard_allowed_origins
# (billing/developer-portal APIs) because they are separate CORS configurations
# on different services — QURL API (ECS) vs billing API (API Gateway).
qurl_cors_allowed_origins = "https://qurl.link.layerv.xyz,https://*.qurl.site.layerv.xyz,https://staging.layerv.ai,http://localhost:3000"

# Additional allowed hosts for DNS rebinding protection
# ALB DNS name, localhost, and 127.0.0.1 are always included automatically.
# Add custom domains here if needed
qurl_additional_allowed_hosts = []

# Container sizing
# Note: When grafana_cloud_enabled=true, ADOT sidecar requires min 512 CPU and adds 256MB memory.
# Effective values: CPU=max(container_cpu, 512), Memory=container_memory+256
# For 512 CPU, effective memory must be 1024-4096, so container_memory >= 768
qurl_container_cpu            = 256 # 0.25 vCPU (effective: 512 with ADOT)
qurl_container_memory         = 768 # 768 MB (effective: 1024 with ADOT sidecar)
qurl_desired_count            = 3
qurl_autoscaling_min_capacity = 3

# Idempotency cache configuration
qurl_idempotency_cache_ttl_seconds        = 300 # 5 minutes
qurl_idempotency_cache_max_size           = 1000
qurl_idempotency_cleanup_interval_seconds = 60 # 1 minute

# Health check configuration
qurl_health_check_timeout_seconds   = 10
qurl_health_startup_timeout_seconds = 30

# Auth0 JWKS cache configuration
qurl_auth0_jwks_cache_ttl_seconds     = 3600 # 1 hour
qurl_auth0_jwks_fetch_timeout_seconds = 10

# Webhooks configuration
qurl_webhooks_enabled                       = true
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

# CloudWatch datasource (Grafana Cloud assumes IAM role to read CloudWatch)
grafana_cloudwatch_enabled   = true
grafana_cloud_aws_account_id = "008923505280"
grafana_cloud_external_id    = null

# Don't create dashboards from sandbox (prod owns them)
grafana_create_dashboards = false

# QURL Redis rate limiting
# ElastiCache Serverless Redis for distributed rate limiting across ECS tasks.
deploy_redis = true

# Cost analytics: sandbox deploys the shared backend (S3, Glue, Athena) in mgmt account
deploy_cost_analytics = true

# ==============================================================================
# QURL Plugin Configuration (NHP Server)
# Enables qurl.link.layerv.xyz → qurl.site.layerv.xyz authentication flow in NHP Server
# ==============================================================================
# QURL plugin handles token resolution: SPA redirects to /plugins/qurl
# which validates tokens via QURL API and performs NHP knock
qurl_config = {
  enabled                 = true
  api_url                 = "https://api.layerv.xyz"
  allowed_redirect_domain = "qurl.site.layerv.xyz"
  api_timeout             = 10
  max_idle_conns          = 10
  max_idle_conns_per_host = 5
  idle_conn_timeout       = 30
}

# Uses same secret as QURL service for internal API auth
qurl_service_token_secret_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-internal-service-token-XgjoDM"

# ==============================================================================
# QURL Link Redirect Page
# Hosts the redirect page that extracts tokens and sends users to NHP Server
# ==============================================================================
deploy_qurl_link          = true
qurl_link_frontend_domain = "qurl.link.layerv.xyz"
qurl_link_hosted_zone_id  = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)
qurl_link_external_dns    = false

# CloudFront for resolve.qurl.link - ISP compatibility (AT&T WiFi blocks NLB IPs)
enable_resolve_cloudfront = true

# ==============================================================================
# QURL Router Plugin Configuration
# Traefik plugin that routes *.qurl.site.layerv.xyz requests to target backends
# Requires QURL Service to be deployed (deploy_qurl_service = true)
# ==============================================================================
# Enable QURL Router when QURL Service is deployed and internal_service_token is configured
qurl_router_enabled = true

# Cache settings (defaults are reasonable for most use cases)
# qurl_router_cache_ttl          = 60   # seconds for successful lookups
# qurl_router_negative_cache_ttl = 30   # seconds for 404s
# qurl_router_max_cache_size     = 1000 # max cache entries
# qurl_router_api_timeout        = 5    # seconds for QURL API calls
# qurl_router_proxy_timeout      = 30   # seconds for proxying to backend

# ==============================================================================
# Blue/Green Deployment Configuration
# Enables instant traffic switching and sub-second rollback for NHP Server
# ==============================================================================
enable_blue_green      = true
green_standby_min_size = 1 # Warm standby - 1 instance ready for instant switch

# AC Blue/Green Deployment
enable_ac_blue_green      = true
ac_green_standby_min_size = 1 # Warm standby - 1 instance ready for instant switch

# ==============================================================================
# Status Page Configuration
# Deployment visibility dashboard at status.layerv.xyz
# ==============================================================================
deploy_status_page         = true
status_page_domain         = "status.layerv.xyz"
status_page_hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone

# NHP Authentication (dogfooding) - protect status page with QURL
# To enable: 1) Create a QURL via API with target_url=https://status.layerv.xyz
#            2) Set the QURL link URL below and enable auth
# status_page_nhp_auth_enabled  = true
# status_page_nhp_auth_qurl_url = "https://qurl.link.layerv.xyz/#at_REPLACE_WITH_TOKEN"

# ==============================================================================
# Billing Configuration
# Stripe billing integration for usage-based pricing
# ==============================================================================
deploy_billing = true

# Stripe secrets (must be created in Secrets Manager before first apply)
billing_stripe_secret_name         = "layerv-nhp-sandbox/billing/stripe-api-key"
billing_stripe_webhook_secret_name = "layerv-nhp-sandbox/billing/stripe-webhook-secret"

# Stripe Price IDs
billing_growth_price_id = "price_1T6LJIHjvKwZFxwsbwOw913O"
# billing_base_fee_price_id = "price_xxx"  # optional flat monthly fee, not yet created

# Checkout redirect URLs
billing_success_url = "https://staging.layerv.ai/qurl/dashboard/billing?success=true"
billing_cancel_url  = "https://staging.layerv.ai/qurl/dashboard/billing?cancelled=true"

# SES sender for payment grace notifications
billing_from_email = "billing@layerv.ai"
billing_ses_region = "us-east-1"

# ==============================================================================
# Shared Dashboard CORS Origins
# Used by billing and developer portal APIs (per-module vars override if set)
# ==============================================================================
dashboard_allowed_origins = ["https://staging.layerv.ai", "http://localhost:3000"]

# ==============================================================================
# Developer Portal Configuration
# Playground proxy and credential provisioner for developer experience
# ==============================================================================
deploy_developer_portal                 = true
developer_portal_m2m_secret_name        = "layerv-nhp-sandbox-auth0-backend-credentials"
developer_portal_auth0_mgmt_secret_name = "layerv-nhp-sandbox/developer-portal/auth0-mgmt"
developer_portal_auth0_domain           = "auth.layerv.ai"
developer_portal_custom_domain          = "devapi.layerv.xyz"
developer_portal_hosted_zone_id         = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone
developer_portal_ci_bypass_secret_name  = "layerv-nhp-sandbox/developer-portal/ci-bypass-key"

# ==============================================================================
# Auth0 SPA Dashboard Configuration
# Website dashboard login for developers to manage API keys, usage, and billing
# ==============================================================================
enable_auth0_spa_dashboard = true
# Single Auth0 tenant shared across environments — custom domain is the same for sandbox and prod.
auth0_custom_domain = "auth.layerv.ai"

# Callback URLs: Auth0 redirects here after login
# Include staging site + localhost for development
auth0_spa_callback_urls = [
  "https://staging.layerv.ai/qurl/dashboard/callback/",
  "https://staging.layerv.ai/api/auth/callback/",
  "http://localhost:3000/qurl/dashboard/callback/",
  "http://localhost:3000/api/auth/callback/",
]

# Logout URLs: Auth0 redirects here after logout
auth0_spa_logout_urls = [
  "https://staging.layerv.ai",
  "https://staging.layerv.ai/qurl/dashboard/",
  "http://localhost:3000",
  "http://localhost:3000/qurl/dashboard/",
]

# Web origins: allowed for CORS and silent authentication
auth0_spa_web_origins = [
  "https://staging.layerv.ai",
  "http://localhost:3000",
]

# Social connections (Google + GitHub) for developer login
# OAuth credentials are passed via TF_VAR_* environment variables
# Store in GitHub Secrets: GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET,
#                          GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET

# ==============================================================================
# E2E Testing
# Echo server Lambda for QURL E2E integration tests
# ==============================================================================
deploy_e2e_echo_server = true

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
