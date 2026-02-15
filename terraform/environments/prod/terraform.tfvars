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
deploy_etcd    = false # Cloud deployment uses DynamoDB, not etcd
# Minimal for initial deployment. Production-ready values: min=3, max=10
min_capacity = 1
max_capacity = 3
vpc_cidr     = "10.200.0.0/16" # Different CIDR from sandbox

# Multi-account config: prod pulls images from sandbox account's ECR
is_primary_account = false
primary_account_id = "767397897469" # Sandbox (layerv) account ID

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.ai"
ac_auth_service_id = "layerv"
ac_resource_ids    = ["qurl"] # Phase 2: QURL is the only service deployed initially
ac_min_capacity    = 1        # Minimal for initial deployment. Production-ready: 2
ac_max_capacity    = 3        # Production-ready: 6

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

# AWS Config: DAILY recording of specific resource types (was CONTINUOUS/ALL = ~$176/mo projected)
config_recording_frequency = "DAILY"

# NHP Server configuration - NEVER enable dev_mode in production
log_level     = 2 # Info for production (0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace)
dev_mode      = false
resource_mode = "api"

# Termination cleanup
enable_termination_cleanup = true

# Secret reconciliation: Lambda cleans orphaned per-instance AC secrets daily
enable_secret_reconciliation = true

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

# CloudWatch alarm email notifications (B8 - interim until Slack is authorized)
# Each email must confirm the SNS subscription via email link
alert_emails = [
  "justin@layerv.ai",
  "benc@layerv.ai",
  "joe@layerv.ai"
]

# WAF logging (B5 - security audit trail, cannot be backfilled)
enable_waf_logging = true

# NHP Server plugins
server_plugins = ["passcode", "qurl"]

# NHP Server Assignment Configuration (all required, no defaults)
nhp_server_assignment_enabled        = true
nhp_region                           = "us-east-2"
nhp_cloudmap_service_name            = "server"
nhp_assignment_servers_per_ac        = 1     # Minimal for initial deployment. Production-ready: 3
nhp_assignment_require_distinct_azs  = false # Production-ready: true (requires servers_per_ac >= 3)
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
qurl_link_domain         = "qurl.link"
qurl_site_domain         = "qurl.site"
qurl_site_hosted_zone_id = "Z09870522JYXPU8N4YJHY" # qurl.site hosted zone
qurl_cookie_domain       = ".qurl.site"

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

# Auth0 M2M credential rotation (Phase 2: enable after auth0 management secret is created)
auth0_enable_rotation = false

# Console license lookup GSIs (required for license validation even without Console EC2)
nhp_dynamodb_licenses_customer_index      = "customer_id-index"
nhp_dynamodb_licenses_auth0_subject_index = "auth0_subject-index"

# QURL ECS Fargate capacity (right-sized for initial sporadic traffic)
# With ADOT sidecar: CPU = max(256,512) = 512, memory = ceil((1024+256)/1024)*1024 = 2048
qurl_container_cpu            = 256  # 0.25 vCPU — ADOT bumps task CPU to 512
qurl_container_memory         = 1024 # 1024 MB — module rounds up task memory to 2048 for Fargate validity
qurl_desired_count            = 1    # Single task for initial low traffic
qurl_autoscaling_min_capacity = 1    # Minimum tasks (scale to zero not supported)
qurl_autoscaling_max_capacity = 4    # Allow burst scaling if traffic spikes

# QURL AC Fleet defaults
qurl_default_ac_id   = "layerv-ac-tf"
qurl_default_ac_port = 443

# QURL plugin configuration (NHP Server)
# Enables qurl.link → qurl.site authentication flow in NHP Server
qurl_config = {
  enabled                 = true
  api_url                 = "https://api.layerv.ai"
  allowed_redirect_domain = "qurl.site"
  api_timeout             = 10
  max_idle_conns          = 10
  max_idle_conns_per_host = 5
  idle_conn_timeout       = 30
}

# QURL internal service token (same secret used by QURL service for internal API auth)
qurl_service_token_secret_arn = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/qurl-internal-service-token-ETbWzv"

# ==============================================================================
# Observability (Phase 2)
# ==============================================================================

# QURL OpenTelemetry (enabled with Grafana Cloud ADOT sidecar)
qurl_otel_enabled           = true
qurl_otel_service_name      = "qurl-api"
qurl_otel_service_version   = "prod"
qurl_otel_environment       = "prod"
qurl_otel_exporter_endpoint = "http://localhost:4317" # ADOT sidecar
qurl_otel_exporter_protocol = "grpc"
qurl_otel_exporter_insecure = true
qurl_otel_trace_sample_rate = 0.1 # 10% sampling in prod (vs 100% in sandbox)
qurl_otel_metrics_interval  = 60
qurl_otel_metrics_enabled   = true
qurl_otel_tracing_enabled   = true
qurl_otel_log_correlation   = true

# Grafana Cloud ADOT Sidecar - exports telemetry to layervai.grafana.net
qurl_grafana_cloud_enabled = true
qurl_grafana_secret_arn    = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/grafana-cloud-otlp-8P5nBG"

# Grafana Cloud Dashboards (PROD_GRAFANA_AUTH GitHub secret already set)
# Token is passed via TF_VAR_grafana_auth in CI
grafana_dashboards_enabled        = true
grafana_url                       = "https://layervai.grafana.net"
grafana_prometheus_datasource_uid = "grafanacloud-prom"
grafana_tempo_datasource_uid      = "grafanacloud-traces"

# Grafana CloudWatch datasource (Grafana Cloud assumes IAM role to read CloudWatch)
grafana_cloudwatch_enabled   = true
grafana_cloud_aws_account_id = "008923505280" # Grafana Cloud stack account (same as sandbox)
grafana_cloud_external_id    = ""             # Not required - same Grafana Cloud stack

# ==============================================================================
# Status Page (B1)
# ==============================================================================
deploy_status_page         = true
status_page_domain         = "status.layerv.ai"
status_page_hosted_zone_id = "Z0748438C8EK6UAW94ST" # layerv.ai zone

# Canary deployment
enable_canary_deployment = true

# QURL Redis rate limiting (B15)
# ElastiCache Serverless Redis for distributed rate limiting across ECS tasks.
# Cost: ~$0/month idle (serverless scales to zero when unused, pay per ECPU + storage)
deploy_redis = true

# Cost analytics (CUR 2.0 → Athena → Grafana)
# Shared mgmt resources (S3, Glue, Athena) are managed by sandbox environment only.
# Both environments query the same consolidated billing data.
deploy_cost_analytics                 = false
cross_account_cost_analytics_role_arn = "arn:aws:iam::165115313779:role/nhp-cost-analytics-access"

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
