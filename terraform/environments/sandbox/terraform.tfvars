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
# auth_url is set dynamically in main.tf to Console EC2 internal NLB endpoint
# auth_signing_key and auth_aes_key are passed via GitHub Secrets (TF_VAR_auth_signing_key, TF_VAR_auth_aes_key)
# IMPORTANT: auth_signing_key must match Console's jwt.signing-key in config.yaml

# Slack notifications via AWS Chatbot
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C09UP62A8F4" # #all-layerv

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

# Enable true network-level NHP protection for Console
# When enabled, Console EC2 runs its own nhp-acd with iptables DROP by default.
# Port 443 is only accessible after NHP knock adds the user's IP to ipset.
enable_console_nhp_protection = true

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
