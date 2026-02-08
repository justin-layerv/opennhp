# Production environment configuration
# Consistent with layerv/traefik-plugins terraform patterns
#
# WARNING: Deployment blocked by default. See README.md for instructions.

environment    = "prod"
aws_region     = "us-east-2"
aws_account_id = "235500187906"
domain_name    = "nhp.layerv.ai"
hosted_zone    = "layerv.ai"            # Hosted in layerv-mgmt account - requires cross-account DNS access
hosted_zone_id = "Z0748438C8EK6UAW94ST" # Bypass lookup - zone is in layerv-mgmt account
multi_tenant   = true
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.200.0.0/16" # Different CIDR from sandbox

# Multi-account config: prod pulls images from sandbox account's ECR
is_primary_account = false
primary_account_id = "767397897469" # Sandbox (layerv) account ID

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.ai"
ac_auth_service_id = "layerv"
ac_resource_ids    = ["default"]

# Terraform state bucket for GitHub Actions permissions
terraform_state_bucket = "layerv-terraform-state-235500187906"
terraform_lock_table   = "terraform-state-lock"

# Lambda layer bucket (cryptography layer for key generation)
lambda_layer_bucket = "layerv-terraform-state-235500187906"

# ALB access logs bucket (required for production QURL service)
qurl_alb_access_logs_bucket = "layerv-nhp-prod-alb-logs"

# ==============================================================================
# Organization-Managed Resources
# ==============================================================================
create_oidc_provider = true

# CloudTrail - enable in prod for security auditing
enable_cloudtrail = true

# NHP Server configuration - NEVER enable dev_mode in production
dev_mode      = false
resource_mode = "api"

# Termination cleanup
enable_termination_cleanup = true

# Slack notifications via AWS Chatbot
# TEMPORARY: Disabled until Slack workspace is authorized for prod account (235500187906)
enable_slack_notifications = false
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C09UP62A8F4" # #all-layerv

# GuardDuty security alerts
guardduty_alert_emails = [
  "justin@layerv.ai",
  "benc@layerv.ai",
  "joe@layerv.ai"
]

# NHP Server plugins
server_plugins = ["passcode", "qurl"]

# NHP Server Assignment Configuration (all required, no defaults)
nhp_server_assignment_enabled        = true
nhp_region                           = "us-east-2"
nhp_cloudmap_service_name            = "server"
nhp_assignment_servers_per_ac        = 3
nhp_assignment_require_distinct_azs  = true
nhp_health_monitor_check_interval    = 60
nhp_health_monitor_operation_timeout = 30
nhp_console_ac_enabled               = true

# Production domains
production_domains = ["qurl.site", "qurl.link"]

# Use production Let's Encrypt
use_production_acme = true

# Centralized TLS certificate management
# ACs fetch TLS certificates from Secrets Manager instead of individual ACME requests
centralized_cert_enabled = true
centralized_cert_domains = ["nhp.layerv.ai", "*.nhp.layerv.ai", "qurl.site", "*.qurl.site", "qurl.link", "*.qurl.link"]

# Cross-account Route53 access for DNS records in layerv-mgmt account
# Required for ACME cert DNS-01 challenges, QURL Link, and QURL Service DNS
cross_account_route53_role_arn = "arn:aws:iam::165115313779:role/nhp-ac-route53-access"

# QURL domains
qurl_link_domain   = "qurl.link"
qurl_site_domain   = "qurl.site"
qurl_cookie_domain = ".qurl.site"

# QURL Service (ECS Fargate API)
deploy_qurl_service             = true
qurl_service_domain             = "api.layerv.ai"
qurl_hosted_zone_id             = "Z0748438C8EK6UAW94ST" # layerv.ai zone (in layerv-mgmt account)
qurl_jwt_secret_arn             = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/qurl-jwt-secret-NRk5sw"
qurl_internal_service_token_arn = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/qurl-internal-service-token-ETbWzv"

# QURL Link (CloudFront redirect page)
deploy_qurl_link          = true
qurl_link_frontend_domain = "qurl.link"
qurl_link_hosted_zone_id  = "Z0693053DKJ8S3XN9WPG" # qurl.link zone (in layerv-mgmt account)
qurl_link_external_dns    = false                  # DNS via route53_mgmt cross-account provider

# QURL Router plugin (Traefik - routes *.qurl.site to target backends)
# Requires QURL Service to be deployed (deploy_qurl_service = true)
qurl_router_enabled = true

# CORS
qurl_cors_allowed_origins = "https://console.nhp.layerv.ai,https://qurl.link,https://*.qurl.site"

# Audit log retention (production: longer retention)
qurl_audit_retention_days = 365

# Auth0 Terraform provider configuration
# IMPORTANT: auth0_domain must be the TENANT domain (not custom domain)
auth0_domain = "layerv.us.auth0.com"

# Auth0 configuration for JWT validation (custom domain)
qurl_auth0_domain   = "auth.layerv.ai"
qurl_auth0_audience = "https://api.layerv.ai"

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
