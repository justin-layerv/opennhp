# Production Environment
# Sources the root module with production-specific configuration

module "nhp" {
  source = "../.."

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment            = var.environment
  aws_region             = var.aws_region
  aws_account_id         = var.aws_account_id
  domain_name            = var.domain_name
  hosted_zone            = var.hosted_zone
  multi_tenant           = var.multi_tenant
  min_capacity           = var.min_capacity
  max_capacity           = var.max_capacity
  vpc_cidr               = var.vpc_cidr
  tags                   = var.tags
  is_primary_account     = var.is_primary_account
  primary_account_id     = var.primary_account_id
  github_org             = var.github_org
  github_repo            = var.github_repo
  deploy_ac              = var.deploy_ac
  acme_email             = var.acme_email
  terraform_state_bucket = var.terraform_state_bucket
  terraform_lock_table   = var.terraform_lock_table

  # Deployment configuration
  image_tag = var.image_tag

  # QURL Service
  deploy_qurl_service             = var.deploy_qurl_service
  qurl_service_domain             = var.qurl_service_domain
  qurl_hosted_zone_id             = var.qurl_hosted_zone_id
  qurl_jwt_secret_arn             = var.qurl_jwt_secret_arn
  qurl_internal_service_token_arn = var.qurl_internal_service_token_arn
  qurl_additional_allowed_hosts   = var.qurl_additional_allowed_hosts

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

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

  # QURL Auth0 JWKS
  qurl_auth0_jwks_cache_ttl_seconds     = var.qurl_auth0_jwks_cache_ttl_seconds
  qurl_auth0_jwks_fetch_timeout_seconds = var.qurl_auth0_jwks_fetch_timeout_seconds

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

  # QURL Observability (OpenTelemetry)
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

  # QURL Grafana Cloud (ADOT Sidecar)
  qurl_grafana_cloud_enabled = var.qurl_grafana_cloud_enabled
  qurl_grafana_secret_arn    = var.qurl_grafana_secret_arn
  qurl_adot_collector_image  = var.qurl_adot_collector_image

  # Grafana Cloud Dashboards
  grafana_dashboards_enabled        = var.grafana_dashboards_enabled
  grafana_url                       = var.grafana_url
  grafana_auth                      = var.grafana_auth
  grafana_prometheus_datasource_uid = var.grafana_prometheus_datasource_uid
  grafana_tempo_datasource_uid      = var.grafana_tempo_datasource_uid
}

# Re-export outputs
output "vpc_id" {
  value = module.nhp.vpc_id
}

output "nlb_dns_name" {
  value = module.nhp.nlb_dns_name
}

output "server_repo_url" {
  value = module.nhp.server_repo_url
}

output "ac_repo_url" {
  value = module.nhp.ac_repo_url
}

output "github_actions_role_arn" {
  value = module.nhp.github_actions_role_arn
}

output "etcd_endpoint" {
  value = module.nhp.etcd_endpoint
}

output "cloudmap_service_dns" {
  value = module.nhp.cloudmap_service_dns
}

output "ac_nlb_dns" {
  value = module.nhp.ac_nlb_dns
}

output "ac_fqdn" {
  value = module.nhp.ac_fqdn
}

output "dns_fqdn" {
  value = module.nhp.dns_fqdn
}

# ASG outputs for CI/CD
output "asg_name" {
  value = module.nhp.asg_name
}

output "ac_asg_name" {
  value = module.nhp.ac_asg_name
}
