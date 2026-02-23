# Production Environment
# Sources the root module with production-specific configuration

locals {
  name_prefix = "layerv-nhp-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = "NHP"
    Application = "nhp"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "layervai/nhp"
  })
}

module "nhp" {
  source = "../.."

  providers = {
    aws              = aws
    aws.us_east_1    = aws.us_east_1
    aws.route53_mgmt = aws.route53_mgmt
    aws.billing_mgmt = aws.billing_mgmt
  }

  environment                 = var.environment
  aws_region                  = var.aws_region
  aws_account_id              = var.aws_account_id
  domain_name                 = var.domain_name
  hosted_zone                 = var.hosted_zone
  hosted_zone_id              = var.hosted_zone_id
  lambda_layer_bucket         = var.lambda_layer_bucket
  qurl_alb_access_logs_bucket = var.qurl_alb_access_logs_bucket
  multi_tenant                = var.multi_tenant
  deploy_etcd                 = var.deploy_etcd
  min_capacity                = var.min_capacity
  max_capacity                = var.max_capacity
  vpc_cidr                    = var.vpc_cidr
  tags                        = var.tags
  is_primary_account          = var.is_primary_account
  primary_account_id          = var.primary_account_id
  github_org                  = var.github_org
  github_repo                 = var.github_repo
  deploy_ac                   = var.deploy_ac
  acme_email                  = var.acme_email
  terraform_state_bucket      = var.terraform_state_bucket
  terraform_lock_table        = var.terraform_lock_table

  # AC configuration
  ac_auth_service_id = var.ac_auth_service_id
  ac_resource_ids    = var.ac_resource_ids
  ac_min_capacity    = var.ac_min_capacity
  ac_max_capacity    = var.ac_max_capacity

  # Security services
  enable_cloudtrail          = var.enable_cloudtrail
  enable_waf_logging         = var.enable_waf_logging
  config_recording_frequency = var.config_recording_frequency
  config_resource_types      = var.config_resource_types

  # GitHub OIDC
  create_oidc_provider = var.create_oidc_provider

  # Server configuration
  log_level        = var.log_level
  dev_mode         = var.dev_mode
  resource_mode    = var.resource_mode
  auth_url         = var.auth_url
  auth_signing_key = var.auth_signing_key
  auth_aes_key     = var.auth_aes_key

  # Monitoring
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id

  # RDS
  deploy_rds              = var.deploy_rds
  rds_database_name       = var.rds_database_name
  rds_min_capacity        = var.rds_min_capacity
  rds_max_capacity        = var.rds_max_capacity
  rds_deletion_protection = var.rds_deletion_protection

  # Production domains
  production_domains     = var.production_domains
  production_zone_ids    = var.production_zone_ids
  additional_tls_domains = var.additional_tls_domains
  use_production_acme    = var.use_production_acme

  # Deployment configuration
  image_tag      = var.image_tag
  server_plugins = var.server_plugins

  # QURL Service
  deploy_qurl_service             = var.deploy_qurl_service
  qurl_service_domain             = var.qurl_service_domain
  qurl_hosted_zone_id             = var.qurl_hosted_zone_id
  qurl_jwt_secret_arn             = var.qurl_jwt_secret_arn
  qurl_internal_service_token_arn = var.qurl_internal_service_token_arn
  qurl_additional_allowed_hosts   = var.qurl_additional_allowed_hosts
  qurl_cors_allowed_origins       = var.qurl_cors_allowed_origins
  qurl_audit_retention_days       = var.qurl_audit_retention_days
  qurl_link_domain                = var.qurl_link_domain
  qurl_site_domain                = var.qurl_site_domain
  qurl_site_hosted_zone_id        = var.qurl_site_hosted_zone_id
  qurl_owner_rate_limit           = var.qurl_owner_rate_limit
  qurl_owner_rate_burst           = var.qurl_owner_rate_burst
  qurl_ip_rate_limit              = var.qurl_ip_rate_limit
  qurl_ip_rate_burst              = var.qurl_ip_rate_burst

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_cookie_domain            = var.qurl_cookie_domain
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

  # QURL Link redirect page
  deploy_qurl_link             = var.deploy_qurl_link
  qurl_link_frontend_domain    = var.qurl_link_frontend_domain
  qurl_link_hosted_zone_id     = var.qurl_link_hosted_zone_id
  qurl_link_external_dns       = var.qurl_link_external_dns
  qurl_link_enable_access_logs = var.qurl_link_enable_access_logs
  enable_resolve_cloudfront    = var.enable_resolve_cloudfront

  # QURL Router plugin
  qurl_router_enabled            = var.qurl_router_enabled
  qurl_router_cache_ttl          = var.qurl_router_cache_ttl
  qurl_router_negative_cache_ttl = var.qurl_router_negative_cache_ttl
  qurl_router_max_cache_size     = var.qurl_router_max_cache_size
  qurl_router_api_timeout        = var.qurl_router_api_timeout
  qurl_router_proxy_timeout      = var.qurl_router_proxy_timeout
  qurl_router_cache_shards       = var.qurl_router_cache_shards

  # QURL Idempotency Cache
  qurl_idempotency_cache_ttl_seconds        = var.qurl_idempotency_cache_ttl_seconds
  qurl_idempotency_cache_max_size           = var.qurl_idempotency_cache_max_size
  qurl_idempotency_cleanup_interval_seconds = var.qurl_idempotency_cleanup_interval_seconds

  # QURL Health Check
  qurl_health_check_timeout_seconds   = var.qurl_health_check_timeout_seconds
  qurl_health_startup_timeout_seconds = var.qurl_health_startup_timeout_seconds

  # QURL License Cache
  qurl_license_cache_ttl_seconds = var.qurl_license_cache_ttl_seconds
  qurl_license_cache_max_size    = var.qurl_license_cache_max_size

  # QURL Resource Config
  qurl_default_expires_in_seconds  = var.qurl_default_expires_in_seconds
  qurl_resource_ttl_buffer_seconds = var.qurl_resource_ttl_buffer_seconds
  qurl_session_ttl_seconds         = var.qurl_session_ttl_seconds
  qurl_default_list_limit          = var.qurl_default_list_limit

  # QURL Auth0 Configuration
  qurl_auth0_domain                     = var.qurl_auth0_domain
  qurl_auth0_audience                   = var.qurl_auth0_audience
  qurl_auth0_jwks_cache_ttl_seconds     = var.qurl_auth0_jwks_cache_ttl_seconds
  qurl_auth0_jwks_fetch_timeout_seconds = var.qurl_auth0_jwks_fetch_timeout_seconds

  # QURL AC Fleet defaults
  qurl_default_ac_id   = var.qurl_default_ac_id
  qurl_default_ac_port = var.qurl_default_ac_port

  # QURL Webhooks
  qurl_webhooks_enabled                       = var.qurl_webhooks_enabled
  qurl_webhooks_worker_count                  = var.qurl_webhooks_worker_count
  qurl_webhooks_max_webhooks_per_owner        = var.qurl_webhooks_max_webhooks_per_owner
  qurl_webhooks_delivery_timeout_seconds      = var.qurl_webhooks_delivery_timeout_seconds
  qurl_webhooks_max_retries                   = var.qurl_webhooks_max_retries
  qurl_webhooks_event_channel_size            = var.qurl_webhooks_event_channel_size
  qurl_webhooks_retry_worker_interval_seconds = var.qurl_webhooks_retry_worker_interval_seconds
  qurl_webhooks_drain_timeout_seconds         = var.qurl_webhooks_drain_timeout_seconds
  qurl_webhooks_response_body_limit           = var.qurl_webhooks_response_body_limit
  qurl_webhooks_api_version                   = var.qurl_webhooks_api_version

  # QURL Observability
  qurl_otel_enabled           = var.qurl_otel_enabled
  qurl_otel_service_name      = var.qurl_otel_service_name
  qurl_otel_service_version   = var.qurl_otel_service_version
  qurl_otel_environment       = var.qurl_otel_environment
  qurl_otel_exporter_endpoint = var.qurl_otel_exporter_endpoint
  qurl_otel_exporter_protocol = var.qurl_otel_exporter_protocol
  qurl_otel_exporter_insecure = var.qurl_otel_exporter_insecure
  qurl_otel_trace_sample_rate = var.qurl_otel_trace_sample_rate
  qurl_otel_metrics_interval  = var.qurl_otel_metrics_interval
  qurl_otel_metrics_enabled   = var.qurl_otel_metrics_enabled
  qurl_otel_tracing_enabled   = var.qurl_otel_tracing_enabled
  qurl_otel_log_correlation   = var.qurl_otel_log_correlation

  # QURL Container Sizing
  qurl_container_cpu    = var.qurl_container_cpu
  qurl_container_memory = var.qurl_container_memory

  # QURL Grafana Cloud
  qurl_grafana_cloud_enabled = var.qurl_grafana_cloud_enabled
  qurl_grafana_secret_arn    = var.qurl_grafana_secret_arn
  qurl_adot_collector_image  = var.qurl_adot_collector_image

  # Grafana Cloud Dashboards
  grafana_dashboards_enabled        = var.grafana_dashboards_enabled
  grafana_url                       = var.grafana_url
  grafana_auth                      = var.grafana_auth
  grafana_prometheus_datasource_uid = var.grafana_prometheus_datasource_uid
  grafana_tempo_datasource_uid      = var.grafana_tempo_datasource_uid
  grafana_nhp_dashboard_url         = var.grafana_nhp_dashboard_url
  grafana_cloudwatch_enabled        = var.grafana_cloudwatch_enabled
  grafana_cloud_aws_account_id      = var.grafana_cloud_aws_account_id
  grafana_cloud_external_id         = var.grafana_cloud_external_id
  grafana_create_dashboards         = var.grafana_create_dashboards

  # Traefik plugins
  traefik_plugins                   = var.traefik_plugins
  traefik_plugins_deploy_bucket_arn = var.traefik_plugins_deploy_bucket_arn
  plugin_repos                      = var.plugin_repos

  # Demo Gateway
  deploy_demo_gateway            = var.deploy_demo_gateway
  demo_gateway_domain            = var.demo_gateway_domain
  demo_gateway_hosted_zone_id    = var.demo_gateway_hosted_zone_id
  demo_gateway_fallback_url      = var.demo_gateway_fallback_url
  cross_account_route53_role_arn = var.cross_account_route53_role_arn

  # Console EC2
  deploy_console_ec2            = var.deploy_console_ec2
  console_ec2_domain            = var.console_ec2_domain
  console_cookie_domain         = var.console_cookie_domain
  console_internal_only         = var.console_internal_only
  console_protected_hostname    = var.console_protected_hostname
  console_ac_license_key_hash   = var.console_ac_license_key_hash
  console_ac_license_key_sha256 = var.console_ac_license_key_sha256

  # Console license lookup and provisioning
  nhp_dynamodb_licenses_customer_index      = var.nhp_dynamodb_licenses_customer_index
  nhp_dynamodb_licenses_auth0_subject_index = var.nhp_dynamodb_licenses_auth0_subject_index
  internal_service_token_secret_arn         = var.internal_service_token_secret_arn
  provisioning_resource_id                  = var.provisioning_resource_id
  provisioning_default_tier                 = var.provisioning_default_tier
  provisioning_default_max_acs              = var.provisioning_default_max_acs

  # NHP Server Assignment
  nhp_server_assignment_enabled        = var.nhp_server_assignment_enabled
  nhp_region                           = var.nhp_region
  nhp_cloudmap_service_name            = var.nhp_cloudmap_service_name
  nhp_assignment_servers_per_ac        = var.nhp_assignment_servers_per_ac
  nhp_assignment_require_distinct_azs  = var.nhp_assignment_require_distinct_azs
  nhp_health_monitor_check_interval    = var.nhp_health_monitor_check_interval
  nhp_health_monitor_operation_timeout = var.nhp_health_monitor_operation_timeout
  nhp_console_ac_enabled               = var.nhp_console_ac_enabled

  # Standalone AC license credentials
  ac_customer_id        = var.ac_customer_id
  ac_license_key        = var.ac_license_key
  ac_license_key_hash   = var.ac_license_key_hash
  ac_license_key_sha256 = var.ac_license_key_sha256

  # Security alerting
  guardduty_alert_emails = var.guardduty_alert_emails
  alert_emails           = var.alert_emails

  # Centralized certificate management
  centralized_cert_enabled    = var.centralized_cert_enabled
  centralized_cert_secret_arn = var.centralized_cert_enabled ? module.acme_cert[0].certificate_secret_arn : null
  centralized_cert_domains    = var.centralized_cert_enabled ? var.centralized_cert_domains : []
  acme_lambda_function_name   = var.centralized_cert_enabled ? "${local.name_prefix}-acme-cert-manager" : ""

  # Termination cleanup
  enable_termination_cleanup = var.enable_termination_cleanup

  # Secret reconciliation (cleanup orphaned per-instance secrets)
  enable_secret_reconciliation = var.enable_secret_reconciliation

  # Blue/Green deployment
  enable_blue_green               = var.enable_blue_green
  green_standby_min_size          = var.green_standby_min_size
  deployment_stale_threshold_days = var.deployment_stale_threshold_days
  enable_ac_blue_green            = var.enable_ac_blue_green
  ac_green_standby_min_size       = var.ac_green_standby_min_size

  # Canary deployment
  enable_canary_deployment        = var.enable_canary_deployment
  canary_checkpoint_percentages   = var.canary_checkpoint_percentages
  canary_checkpoint_delay_seconds = var.canary_checkpoint_delay_seconds
  canary_instance_warmup_seconds  = var.canary_instance_warmup_seconds

  # Status page (B1)
  deploy_status_page         = var.deploy_status_page
  status_page_domain         = var.status_page_domain
  status_page_hosted_zone_id = var.status_page_hosted_zone_id

  # Developer Portal
  deploy_developer_portal                 = var.deploy_developer_portal
  developer_portal_m2m_secret_name        = var.developer_portal_m2m_secret_name
  developer_portal_auth0_mgmt_secret_name = var.developer_portal_auth0_mgmt_secret_name
  developer_portal_auth0_domain           = var.developer_portal_auth0_domain
  developer_portal_qurl_api_audience      = var.developer_portal_qurl_api_audience
  developer_portal_from_email             = var.developer_portal_from_email
  developer_portal_ses_region             = var.developer_portal_ses_region
  developer_portal_notify_email           = var.developer_portal_notify_email
  developer_portal_site_url               = var.developer_portal_site_url
  developer_portal_verify_url             = var.developer_portal_verify_url
  developer_portal_allowed_origins        = var.developer_portal_allowed_origins
  developer_portal_custom_domain          = var.developer_portal_custom_domain
  developer_portal_hosted_zone_id         = var.developer_portal_hosted_zone_id
  developer_portal_ci_bypass_secret_name  = var.developer_portal_ci_bypass_secret_name

  # QURL ECS capacity
  qurl_desired_count            = var.qurl_desired_count
  qurl_autoscaling_min_capacity = var.qurl_autoscaling_min_capacity
  qurl_autoscaling_max_capacity = var.qurl_autoscaling_max_capacity

  # Redis (distributed rate limiting)
  deploy_redis = var.deploy_redis

  # Cost analytics
  deploy_cost_analytics                 = var.deploy_cost_analytics
  cross_account_cost_analytics_role_arn = var.cross_account_cost_analytics_role_arn
  grafana_athena_config                 = var.grafana_athena_config
}

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================

module "acme_cert" {
  count  = var.centralized_cert_enabled ? 1 : 0
  source = "../../modules/acme-cert"

  name_prefix         = local.name_prefix
  environment         = var.environment
  domains             = var.centralized_cert_domains
  hosted_zone_id      = var.qurl_hosted_zone_id
  acme_email          = var.acme_email
  use_production_acme = var.use_production_acme
  kms_key_arn         = module.nhp.secrets_kms_key_arn
  has_kms_key         = true # Static boolean - avoids count-depends-on-computed
  logs_kms_key_arn    = module.nhp.logs_kms_key_arn

  domain_zone_mappings = {
    "layerv.ai" = { zone_id = "Z0748438C8EK6UAW94ST", cross_account = true }
    "qurl.site" = { zone_id = "Z06942509AYXSB91X7CD", cross_account = true }
    "qurl.link" = { zone_id = "Z0693053DKJ8S3XN9WPG", cross_account = true }
  }
  cross_account_role_arn = var.cross_account_route53_role_arn

  renewal_days_before_expiry = 30
  renewal_schedule           = "rate(1 day)"

  alert_emails           = var.guardduty_alert_emails
  existing_sns_topic_arn = module.nhp.sns_topic_arn
  use_existing_sns_topic = true # Static boolean - avoids count-depends-on-computed

  tags = local.common_tags
}

# ==============================================================================
# Auth0 Identity Management
# ==============================================================================

module "auth0" {
  source = "../../modules/auth0"

  environment  = var.environment
  name_prefix  = local.name_prefix
  api_audience = var.qurl_auth0_audience
  tags         = local.common_tags

  enable_rotation             = var.auth0_enable_rotation
  rotation_days               = var.auth0_rotation_days
  auth0_domain                = var.auth0_enable_rotation ? var.auth0_domain : null
  auth0_management_secret_arn = var.auth0_management_secret_arn

  # Developer portal management M2M app (only create when portal is enabled)
  dev_portal_mgmt_secret_name = var.deploy_developer_portal ? var.developer_portal_auth0_mgmt_secret_name : null
  auth0_tenant_domain         = var.auth0_domain
}

# ==============================================================================
# Outputs
# ==============================================================================

output "vpc_id" {
  description = "VPC ID for the production environment"
  value       = module.nhp.vpc_id
}

output "nlb_dns_name" {
  description = "NHP Server NLB DNS name"
  value       = module.nhp.nlb_dns_name
}

output "server_repo_url" {
  description = "ECR repository URL for NHP Server images"
  value       = module.nhp.server_repo_url
}

output "ac_repo_url" {
  description = "ECR repository URL for AC images"
  value       = module.nhp.ac_repo_url
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions CI/CD"
  value       = module.nhp.github_actions_role_arn
}

output "etcd_endpoint" {
  description = "etcd cluster endpoint for NHP server config"
  value       = module.nhp.etcd_endpoint
}

output "cloudmap_service_dns" {
  description = "Cloud Map DNS name for NHP server discovery"
  value       = module.nhp.cloudmap_service_dns
}

output "ac_nlb_dns" {
  description = "AC NLB DNS name"
  value       = module.nhp.ac_nlb_dns
}

output "ac_fqdn" {
  description = "AC fully qualified domain name"
  value       = module.nhp.ac_fqdn
}

output "dns_fqdn" {
  description = "Primary DNS FQDN for the environment"
  value       = module.nhp.dns_fqdn
}

output "asg_name" {
  description = "NHP Server Auto Scaling Group name"
  value       = module.nhp.asg_name
}

output "ac_asg_name" {
  description = "AC Auto Scaling Group name"
  value       = module.nhp.ac_asg_name
}

output "plugin_bucket_name" {
  description = "S3 bucket name for Traefik plugins"
  value       = module.nhp.plugin_bucket_name
}

output "plugin_bucket_arn" {
  description = "S3 bucket ARN for Traefik plugins"
  value       = module.nhp.plugin_bucket_arn
}

output "rds_endpoint" {
  description = "RDS Aurora Serverless endpoint"
  value       = module.nhp.rds_endpoint
}

output "rds_secret_arn" {
  description = "Secrets Manager ARN for RDS credentials"
  value       = module.nhp.rds_secret_arn
}

output "rds_database_name" {
  description = "RDS database name"
  value       = module.nhp.rds_database_name
}

output "console_ec2_nlb_dns" {
  description = "Console EC2 NLB DNS name"
  value       = module.nhp.console_ec2_nlb_dns
}

output "console_ec2_api_endpoint" {
  description = "Console EC2 API endpoint URL"
  value       = module.nhp.console_ec2_api_endpoint
}

output "console_ec2_asg_name" {
  description = "Console EC2 Auto Scaling Group name"
  value       = module.nhp.console_ec2_asg_name
}

output "console_ec2_public_url" {
  description = "Console public URL"
  value       = module.nhp.console_ec2_public_url
}

output "demo_gateway_nlb_dns" {
  description = "Demo gateway NLB DNS name"
  value       = module.nhp.demo_gateway_nlb_dns
}

output "demo_gateway_fqdn" {
  description = "Demo gateway FQDN"
  value       = module.nhp.demo_gateway_fqdn
}

output "demo_gateway_asg_name" {
  description = "Demo gateway Auto Scaling Group name"
  value       = module.nhp.demo_gateway_asg_name
}

output "console_repo_url" {
  description = "ECR repository URL for Console images"
  value       = module.nhp.console_repo_url
}

output "auth0_api_identifier" {
  description = "Auth0 API identifier (audience)"
  value       = module.auth0.api_identifier
}

output "auth0_backend_service_client_id" {
  description = "Auth0 backend service M2M client ID"
  value       = module.auth0.backend_service_client_id
}

output "auth0_backend_credentials_secret_arn" {
  description = "Secrets Manager ARN for Auth0 backend credentials"
  value       = module.auth0.backend_credentials_secret_arn
}

output "auth0_rotation_lambda_arn" {
  description = "Auth0 credential rotation Lambda ARN"
  value       = module.auth0.rotation_lambda_arn
}

output "auth0_rotation_enabled" {
  description = "Whether Auth0 credential rotation is enabled"
  value       = module.auth0.rotation_enabled
}
