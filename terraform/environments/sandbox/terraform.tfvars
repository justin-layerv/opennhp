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
# qurl_auth0_domain = "layerv.us.auth0.com"
# qurl_auth0_audience = "https://api.layerv.ai"

# Secrets Manager ARNs (create secrets before enabling QURL service)
# qurl_jwt_secret_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-jwt-secret"
# qurl_internal_service_token_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-internal-service-token"

# AC Fleet defaults (for QURL resources)
# qurl_default_ac_id = "ac-sandbox-01"
# qurl_default_ac_host = "ac.nhp.layerv.xyz"

# Container sizing (defaults are good for dev/sandbox)
# qurl_container_cpu    = 256   # 0.25 vCPU
# qurl_container_memory = 512   # 512 MB
# qurl_desired_count    = 1

# ==============================================================================
# QURL Router Plugin Configuration
# Traefik plugin that routes *.qurl.site requests to target backends
# Requires QURL Service to be deployed (deploy_qurl_service = true)
# ==============================================================================
# Enable QURL Router when QURL Service is deployed and internal_service_token is configured
qurl_router_enabled     = false # Set to true after configuring qurl_internal_service_token_arn
qurl_router_base_domain = "qurl.site"

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
