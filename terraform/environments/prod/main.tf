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

  environment                     = var.environment
  cell_id                         = var.cell_id
  connector_authority_cell_config = local.connector_authority_cell_config
  aws_region                      = var.aws_region
  aws_account_id                  = var.aws_account_id
  domain_name                     = var.domain_name
  hosted_zone                     = var.hosted_zone
  hosted_zone_id                  = var.hosted_zone_id
  lambda_layer_bucket             = var.lambda_layer_bucket
  qurl_alb_access_logs_bucket     = var.qurl_alb_access_logs_bucket
  multi_tenant                    = var.multi_tenant
  deploy_etcd                     = var.deploy_etcd
  server_ami_id                   = var.server_ami_id
  ac_ami_id                       = var.ac_ami_id
  min_capacity                    = var.min_capacity
  max_capacity                    = var.max_capacity
  vpc_cidr                        = var.vpc_cidr
  tags                            = var.tags
  is_primary_account              = var.is_primary_account
  primary_account_id              = var.primary_account_id
  enable_replication              = var.enable_replication
  github_org                      = var.github_org
  github_repo                     = var.github_repo
  deploy_ac                       = var.deploy_ac
  acme_email                      = var.acme_email
  terraform_state_bucket          = var.terraform_state_bucket
  terraform_lock_table            = var.terraform_lock_table

  # AC configuration
  ac_auth_service_id              = var.ac_auth_service_id
  ac_resource_ids                 = var.ac_resource_ids
  ac_min_capacity                 = var.ac_min_capacity
  ac_max_capacity                 = var.ac_max_capacity
  ac_filter_mode                  = var.ac_filter_mode
  enable_l3_flush_on_expiry       = var.enable_l3_flush_on_expiry
  l3_flush_dry_run                = var.l3_flush_dry_run
  l3_flush_real_mode_acknowledged = var.l3_flush_real_mode_acknowledged
  l3_flush_conntrack_backend      = var.l3_flush_conntrack_backend
  l3_flush_conntrack_pool_size    = var.l3_flush_conntrack_pool_size
  enable_egress_eips              = var.enable_egress_eips

  # Security services
  enable_cloudtrail          = var.enable_cloudtrail
  enable_waf_logging         = var.enable_waf_logging
  config_recording_frequency = var.config_recording_frequency
  config_resource_types      = var.config_resource_types

  # GitHub OIDC
  create_oidc_provider = var.create_oidc_provider

  # Server configuration
  log_level                               = var.log_level
  dev_mode                                = var.dev_mode
  resource_mode                           = var.resource_mode
  auth_url                                = var.auth_url
  auth_signing_key                        = var.auth_signing_key
  auth_aes_key                            = var.auth_aes_key
  nhp_cors_allowed_origins                = var.nhp_cors_allowed_origins
  nhp_knock_headertype_verify_require     = var.nhp_knock_headertype_verify_require
  nhp_internal_auth_require               = var.nhp_internal_auth_require
  nhp_revocation_retry_enabled            = var.nhp_revocation_retry_enabled
  nhp_revocation_retry_interval_seconds   = var.nhp_revocation_retry_interval_seconds
  nhp_revocation_retry_age_out_seconds    = var.nhp_revocation_retry_age_out_seconds
  nhp_overload_cookie_time_window_seconds = var.nhp_overload_cookie_time_window_seconds

  # Knock-port DoS hardening (#1159)
  nhp_knock_global_rate_limit_pps   = var.nhp_knock_global_rate_limit_pps
  nhp_knock_global_rate_limit_burst = var.nhp_knock_global_rate_limit_burst
  nhp_udp_recv_buffer_bytes         = var.nhp_udp_recv_buffer_bytes
  public_nhp_udp_ingress_cidrs      = var.public_nhp_udp_ingress_cidrs

  # Monitoring
  enable_slack_notifications                  = var.enable_slack_notifications
  slack_workspace_id                          = var.slack_workspace_id
  slack_channel_id                            = var.slack_channel_id
  chatbot_owned_externally                    = var.chatbot_owned_externally
  qurl_browser_rejected_alarm_actions_enabled = var.qurl_browser_rejected_alarm_actions_enabled

  # Production domains
  production_domains     = var.production_domains
  production_zone_ids    = var.production_zone_ids
  additional_tls_domains = var.additional_tls_domains
  use_production_acme    = var.use_production_acme

  # Deployment configuration
  image_tag      = var.image_tag
  server_plugins = var.server_plugins

  # QURL Service
  deploy_qurl_service                  = var.deploy_qurl_service
  deploy_qurl_bootstrap_chain          = var.deploy_qurl_bootstrap_chain
  enable_qurl_agent_bootstrap          = var.enable_qurl_agent_bootstrap
  qurl_scanner_lambda_enabled          = var.qurl_scanner_lambda_enabled
  qurl_scanner_sqs_emit_enabled        = var.qurl_scanner_sqs_emit_enabled
  qurl_scanner_tombstone_write_enabled = var.qurl_scanner_tombstone_write_enabled
  qurl_scanner_active_recheck_enabled  = var.qurl_scanner_active_recheck_enabled
  qurl_service_domain                  = var.qurl_service_domain
  qurl_hosted_zone_id                  = var.qurl_hosted_zone_id
  qurl_jwt_secret_arn                  = var.qurl_jwt_secret_arn
  qurl_internal_service_token_arn      = var.qurl_internal_service_token_arn
  qurl_internal_service_domain         = var.qurl_internal_service_domain
  qurl_additional_allowed_hosts        = var.qurl_additional_allowed_hosts
  qurl_cors_allowed_origins            = var.qurl_cors_allowed_origins
  qurl_audit_retention_days            = var.qurl_audit_retention_days
  qurl_link_domain                     = var.qurl_link_domain
  qurl_site_domain                     = var.qurl_site_domain
  qurl_site_hosted_zone_id             = var.qurl_site_hosted_zone_id
  qurl_ip_rate_limit                   = var.qurl_ip_rate_limit
  qurl_ip_rate_burst                   = var.qurl_ip_rate_burst

  # Website email-capture API DNS (cross-account A-alias for web-api.layerv.ai)
  deploy_website_api_dns     = var.deploy_website_api_dns
  website_api_domain         = var.website_api_domain
  website_api_cfn_stack_name = var.website_api_cfn_stack_name

  # qurl-integrations-infra cross-account DNS — see main.tf for context.
  deploy_qurl_integrations_dns = var.deploy_qurl_integrations_dns
  qurl_s3_connector_domain     = var.qurl_s3_connector_domain
  qurl_s3_connector_eip        = var.qurl_s3_connector_eip
  qurl_fileviewer_domain       = var.qurl_fileviewer_domain
  qurl_fileviewer_eip          = var.qurl_fileviewer_eip

  # QURL Custom Domains
  qurl_custom_domain_enabled                 = var.qurl_custom_domain_enabled
  qurl_custom_domain_cleanup_topic_arn       = var.deploy_custom_domain_cert ? aws_sns_topic.custom_domain_cleanup[0].arn : ""
  qurl_custom_domain_cleanup_publish_enabled = var.deploy_custom_domain_cert
  deploy_custom_domain_cert                  = var.deploy_custom_domain_cert

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_cookie_domain            = var.qurl_cookie_domain
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

  # Agent registration + email OTP (T1). Flags + email_from + relay + alarm
  # thresholds flow env→root; the root creates the SES infra + pepper secret when
  # agent_otp_enabled. Prod: registration + OTP ON (values in terraform.tfvars).
  agent_registration_enabled                             = var.agent_registration_enabled
  agent_otp_enabled                                      = var.agent_otp_enabled
  agent_otp_registration_enabled                         = var.agent_otp_registration_enabled
  agent_otp_email_from                                   = var.agent_otp_email_from
  agent_registration_relay_base_url                      = var.agent_registration_relay_base_url
  agent_otp_send_failed_threshold_per_minute             = var.agent_otp_send_failed_threshold_per_minute
  agent_otp_bounce_threshold_per_minute                  = var.agent_otp_bounce_threshold_per_minute
  agent_otp_rate_limited_threshold_per_minute            = var.agent_otp_rate_limited_threshold_per_minute
  agent_register_attempts_exceeded_threshold_per_minute  = var.agent_register_attempts_exceeded_threshold_per_minute
  agent_register_credential_invalid_threshold_per_minute = var.agent_register_credential_invalid_threshold_per_minute
  agent_register_rate_limited_threshold_per_minute       = var.agent_register_rate_limited_threshold_per_minute
  relay_otp_reject_rate_limited_threshold_per_minute     = var.relay_otp_reject_rate_limited_threshold_per_minute

  # qURL v2 (keyed identity) — all default off; prod stays dark (not set in tfvars).
  qurl_v2_issuer_key_enabled                   = var.qurl_v2_issuer_key_enabled
  qurl_v2_resource_keys_enabled                = var.qurl_v2_resource_keys_enabled
  qurl_v2_resource_key_software_default        = var.qurl_v2_resource_key_software_default
  qurl_v2_resource_key_reaper_enabled          = var.qurl_v2_resource_key_reaper_enabled
  qurl_v2_resource_key_reaper_interval_seconds = var.qurl_v2_resource_key_reaper_interval_seconds
  qurl_v2_issuance_enabled                     = var.qurl_v2_issuance_enabled
  qurl_v2_admission_enabled                    = var.qurl_v2_admission_enabled
  qurl_v2_issuer_kid                           = var.qurl_v2_issuer_kid
  qurl_v2_relay_url                            = var.qurl_v2_relay_url
  qurl_v2_relay_allowlist                      = var.qurl_v2_relay_allowlist

  # QURL Link redirect page
  deploy_qurl_link                = var.deploy_qurl_link
  qurl_link_frontend_domain       = var.qurl_link_frontend_domain
  qurl_link_hosted_zone_id        = var.qurl_link_hosted_zone_id
  qurl_link_external_dns          = var.qurl_link_external_dns
  qurl_link_enable_access_logs    = var.qurl_link_enable_access_logs
  qurl_link_js_agent_enabled      = var.qurl_link_js_agent_enabled
  enable_resolve_cloudfront       = var.enable_resolve_cloudfront
  resolve_waf_ip_reputation_block = var.resolve_waf_ip_reputation_block
  enable_resolve_waf_logging      = var.enable_resolve_waf_logging
  enable_resolve_access_logs      = var.enable_resolve_access_logs

  # QURL Router plugin
  qurl_router_enabled            = var.qurl_router_enabled
  qurl_router_cache_ttl          = var.qurl_router_cache_ttl
  qurl_router_negative_cache_ttl = var.qurl_router_negative_cache_ttl
  qurl_router_max_cache_size     = var.qurl_router_max_cache_size
  qurl_router_api_timeout        = var.qurl_router_api_timeout
  qurl_router_proxy_timeout      = var.qurl_router_proxy_timeout
  qurl_router_cache_shards       = var.qurl_router_cache_shards
  enable_instance_hrw            = var.enable_instance_hrw
  instance_discovery_ttl_seconds = var.instance_discovery_ttl_seconds
  enable_qurl_site_authz         = var.enable_qurl_site_authz
  require_connector_routing_id   = var.require_connector_routing_id

  # qurl-reverse-tunnel-server (FRPS-behind-AC) — prod env-root close-out.
  # Mirrors the sandbox wiring (#2035): #1745 had threaded only the NEW
  # per-AZ/blue-green/canary/MULTIVALUE vars, leaving `deploy_frps`,
  # `connect_layerv_host`, `qurl_connector_auth_enabled`, `frps_image_tag`,
  # the frps ports/suffixes, and the legacy sizing triple undeclared at
  # the prod env-root — so prod tfvars values silently no-op'd as "Value
  # for undeclared variable" warnings (the bug-class #2035 fixed for
  # sandbox). Declaring + threading them here is what makes the prod
  # `deploy_frps = true` / `connect_layerv_host` flip take effect.
  qurl_connector_auth_enabled = var.qurl_connector_auth_enabled
  deploy_frps                 = var.deploy_frps
  connect_layerv_host         = var.connect_layerv_host
  frps_image_tag              = var.frps_image_tag
  frps_bind_port              = var.frps_bind_port
  frps_vhost_http_port        = var.frps_vhost_http_port
  frps_az_suffixes            = var.frps_az_suffixes
  frps_min_size               = var.frps_min_size
  frps_max_size               = var.frps_max_size
  frps_desired_capacity       = var.frps_desired_capacity

  qurl_reverse_tunnel_server_min_size_per_az               = var.qurl_reverse_tunnel_server_min_size_per_az
  qurl_reverse_tunnel_server_max_size_per_az               = var.qurl_reverse_tunnel_server_max_size_per_az
  qurl_reverse_tunnel_server_desired_capacity_per_az       = var.qurl_reverse_tunnel_server_desired_capacity_per_az
  qurl_reverse_tunnel_server_cloud_map_routing_policy      = var.qurl_reverse_tunnel_server_cloud_map_routing_policy
  enable_qurl_reverse_tunnel_server_blue_green             = var.enable_qurl_reverse_tunnel_server_blue_green
  qurl_reverse_tunnel_server_green_standby_capacity_per_az = var.qurl_reverse_tunnel_server_green_standby_capacity_per_az
  enable_qurl_reverse_tunnel_server_canary                 = var.enable_qurl_reverse_tunnel_server_canary
  qurl_reverse_tunnel_server_tunnel_auth_mode              = var.qurl_reverse_tunnel_server_tunnel_auth_mode
  qurl_reverse_tunnel_server_min_client_version            = var.qurl_reverse_tunnel_server_min_client_version

  # owner_missing reverse-tunnel reject alarm threshold. Threaded to prod
  # (unlike the sandbox-only knock-token / bootstrap-outcome thresholds)
  # because this alarm is PAGE severity on a customer-visible prod outage
  # whose remediation — a connector force-restart — itself emits a short
  # owner_missing burst, so the runbook's Tuning step (raise the threshold
  # to ride out a planned restart window) has to work in prod, not only
  # sandbox. Same declare-and-thread as the #2035 env-root close-out above;
  # default 5.
  owner_missing_reject_threshold = var.owner_missing_reject_threshold

  # bootstrap-alb (agent-bootstrap knock-flow ingress) — prod env-root
  # close-out, mirror of sandbox #2054. Declared + threaded so prod tfvars
  # flips reach module.nhp. Prod runs the module's cross-account Path 1
  # (operator pre-provisioned cert via bootstrap_alb_existing_certificate_arn,
  # provision_certificate=false, manage_dns_alias=false).
  deploy_bootstrap_alb                        = var.deploy_bootstrap_alb
  bootstrap_alb_dns_name                      = var.bootstrap_alb_dns_name
  bootstrap_alb_route53_zone_id               = var.bootstrap_alb_route53_zone_id
  bootstrap_alb_manage_dns_alias              = var.bootstrap_alb_manage_dns_alias
  bootstrap_alb_provision_certificate         = var.bootstrap_alb_provision_certificate
  bootstrap_alb_existing_certificate_arn      = var.bootstrap_alb_existing_certificate_arn
  bootstrap_alb_waf_count_only_rule_groups    = var.bootstrap_alb_waf_count_only_rule_groups
  bootstrap_alb_cross_account_subscriber_arns = var.bootstrap_alb_cross_account_subscriber_arns
  bootstrap_alb_alarm_email_subscriptions     = var.bootstrap_alb_alarm_email_subscriptions
  bootstrap_alb_elb_5xx_threshold_per_minute  = var.bootstrap_alb_elb_5xx_threshold_per_minute

  # NHP-Relay (#2208) — dark in prod (deploy_relay defaults false; sandbox-only
  # until the relay is validated end-to-end and a prod-enable PR flips it).
  deploy_relay                             = var.deploy_relay
  relay_vpc_cidr                           = var.relay_vpc_cidr
  relay_additional_trusted_public_keys_b64 = var.relay_additional_trusted_public_keys_b64
  relay_dns_name                           = var.relay_dns_name
  relay_route53_zone_id                    = var.relay_route53_zone_id
  relay_provision_certificate              = var.relay_provision_certificate
  relay_manage_dns_alias                   = var.relay_manage_dns_alias
  relay_existing_certificate_arn           = var.relay_existing_certificate_arn

  relay_waf_rate_limit_per_source_ip = var.relay_waf_rate_limit_per_source_ip
  relay_scale_requests_per_target    = var.relay_scale_requests_per_target

  # QURL Idempotency Cache
  qurl_idempotency_cache_ttl_seconds        = var.qurl_idempotency_cache_ttl_seconds
  qurl_idempotency_cache_max_size           = var.qurl_idempotency_cache_max_size
  qurl_idempotency_cleanup_interval_seconds = var.qurl_idempotency_cleanup_interval_seconds

  # QURL Health Check
  qurl_health_check_timeout_seconds   = var.qurl_health_check_timeout_seconds
  qurl_health_startup_timeout_seconds = var.qurl_health_startup_timeout_seconds

  # Customer Cache
  qurl_customer_cache_ttl_seconds = var.qurl_customer_cache_ttl_seconds
  qurl_customer_cache_max_size    = var.qurl_customer_cache_max_size

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

  # QURL GeoIP
  qurl_geoip_enabled        = var.qurl_geoip_enabled
  qurl_geoip_db_path        = var.qurl_geoip_db_path
  qurl_geoip_s3_uri         = var.qurl_geoip_s3_uri
  qurl_geoip_s3_kms_key_arn = var.qurl_geoip_s3_kms_key_arn

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
  qurl_container_port   = var.qurl_container_port

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
  grafana_cloudwatch_enabled        = var.grafana_cloudwatch_enabled
  grafana_cloud_aws_account_id      = var.grafana_cloud_aws_account_id
  grafana_cloud_external_id         = var.grafana_cloud_external_id
  grafana_create_dashboards         = var.grafana_create_dashboards

  # Traefik plugins
  traefik_plugins                   = var.traefik_plugins
  traefik_plugins_deploy_bucket_arn = var.traefik_plugins_deploy_bucket_arn
  plugin_repos                      = var.plugin_repos

  cross_account_route53_role_arn = var.cross_account_route53_role_arn

  # CloudMap
  nhp_cloudmap_service_name = var.nhp_cloudmap_service_name

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
  deploy_status_page                     = var.deploy_status_page
  status_page_domain                     = var.status_page_domain
  status_page_hosted_zone_id             = var.status_page_hosted_zone_id
  status_page_additional_service_urls    = var.status_page_additional_service_urls
  status_page_display_only_component_ids = var.status_page_display_only_component_ids
  status_page_nhp_auth_enabled           = var.status_page_nhp_auth_enabled
  status_page_nhp_auth_qurl_url          = var.status_page_nhp_auth_qurl_url

  # Developer Portal
  deploy_developer_portal                 = var.deploy_developer_portal
  developer_portal_m2m_secret_name        = var.developer_portal_m2m_secret_name
  developer_portal_auth0_mgmt_secret_name = var.developer_portal_auth0_mgmt_secret_name
  developer_portal_auth0_domain           = var.developer_portal_auth0_domain
  developer_portal_allowed_origins        = var.developer_portal_allowed_origins
  dashboard_allowed_origins               = var.dashboard_allowed_origins
  developer_portal_custom_domain          = var.developer_portal_custom_domain
  developer_portal_hosted_zone_id         = var.developer_portal_hosted_zone_id
  developer_portal_ci_bypass_secret_name  = var.developer_portal_ci_bypass_secret_name
  developer_portal_connector_base_url     = var.developer_portal_connector_base_url

  # Billing
  deploy_billing                     = var.deploy_billing
  billing_stripe_secret_name         = var.billing_stripe_secret_name
  billing_stripe_webhook_secret_name = var.billing_stripe_webhook_secret_name
  billing_stripe_api_base_url        = var.billing_stripe_api_base_url
  billing_growth_price_id            = var.billing_growth_price_id
  billing_base_fee_price_id          = var.billing_base_fee_price_id
  billing_success_url                = var.billing_success_url
  billing_cancel_url                 = var.billing_cancel_url
  billing_allowed_origins            = var.billing_allowed_origins
  billing_from_email                 = var.billing_from_email
  billing_ses_region                 = var.billing_ses_region
  billing_grace_period_days          = var.billing_grace_period_days
  billing_downgrade_after_days       = var.billing_downgrade_after_days
  billing_api_throttle_burst_limit   = var.billing_api_throttle_burst_limit
  billing_api_throttle_rate_limit    = var.billing_api_throttle_rate_limit

  # QURL ECS capacity
  qurl_desired_count            = var.qurl_desired_count
  qurl_autoscaling_min_capacity = var.qurl_autoscaling_min_capacity
  qurl_autoscaling_max_capacity = var.qurl_autoscaling_max_capacity

  # Redis (distributed rate limiting)
  deploy_redis = var.deploy_redis

  # VPC endpoints for QURL service AWS dependencies
  deploy_vpc_endpoints = var.deploy_vpc_endpoints

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
# Custom Domain Certificate Manager
# ==============================================================================
# Lambda that provisions Let's Encrypt certificates for custom domains registered
# via the QURL API. Polls DynamoDB for domains in "provisioning_tls" status every
# 15 minutes, provisions certs via ACME DNS-01 challenge, stores key/chain in SSM
# Parameter Store, and triggers AC cert sync via SSM SendCommand.

# Inbound topic that qurl-service publishes domain.cleanup events to.
# Owned at the env level to break the module cycle: module.custom_domain_cert
# consumes module.nhp's DDB ARN, and module.nhp (via module.qurl_service)
# consumes the cleanup topic ARN — if the topic lived inside the cert module
# the modules would depend on each other circularly. See nhp#1990.
resource "aws_sns_topic" "custom_domain_cleanup" {
  count = var.deploy_custom_domain_cert ? 1 : 0
  name  = "${local.name_prefix}-custom-domain-cleanup"
  # AWS-managed `alias/aws/sns` rather than the per-env secrets CMK: SNS
  # itself calls kms:Decrypt at Lambda-delivery time as `sns.amazonaws.com`,
  # and the secrets CMK's key policy only authorizes `secretsmanager`. The
  # managed key allows in-account IAM principals via SNS service usage and
  # carries no per-key cost — see also bootstrap-alb/observability.tf:22.
  kms_master_key_id = "alias/aws/sns"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-custom-domain-cleanup"
  })
}

# Catches the systemic-failure case the reconciliation safety net (#1992)
# can't surface as a separate signal: a sustained cert-lambda outage or a
# malformed-publisher regression that produces an event-per-deletion error
# storm. Threshold of 5 in 15min is loose enough that a single transient
# DDB throttle (handled by TransientCleanupError + SNS retry) doesn't page,
# but a real outage does. Tracked in #1990's cleanup discussion.
resource "aws_cloudwatch_metric_alarm" "custom_domain_cleanup_delivery_failures" {
  count = var.deploy_custom_domain_cert ? 1 : 0

  alarm_name          = "${local.name_prefix}-custom-domain-cleanup-delivery-failures"
  alarm_description   = "Sustained SNS→Lambda delivery failures on the custom-domain cleanup topic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfNotificationsFailed"
  namespace           = "AWS/SNS"
  period              = 900
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    TopicName = aws_sns_topic.custom_domain_cleanup[0].name
  }

  alarm_actions = [module.nhp.sns_topic_arn]
  ok_actions    = [module.nhp.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-custom-domain-cleanup-delivery-failures"
  })
}

module "custom_domain_cert" {
  count  = var.deploy_custom_domain_cert ? 1 : 0
  source = "../../modules/custom-domain-cert"

  providers = {
    aws            = aws
    aws.parent_dns = aws.route53_mgmt # Parent zone (layerv.ai) is in mgmt account
  }

  name_prefix         = local.name_prefix
  environment         = var.environment
  cell_id             = var.cell_id
  acme_base_domain    = var.hosted_zone         # layerv.ai for prod
  parent_zone_id      = var.qurl_hosted_zone_id # layerv.ai zone — NS delegation for acme sub-zone
  acme_email          = var.acme_email
  use_production_acme = var.use_production_acme

  # DynamoDB — Lambda queries status-index GSI for provisioning_tls domains
  qurl_domains_table_name = module.nhp.dynamodb_qurl_domains_table_name
  qurl_domains_table_arn  = module.nhp.dynamodb_qurl_domains_table_arn

  # SSM SendCommand targeting — must match AC instance Name tag
  ac_instance_tag = "${local.name_prefix}-ac"

  # Encryption
  kms_key_arn      = module.nhp.secrets_kms_key_arn
  has_kms_key      = true
  logs_kms_key_arn = module.nhp.logs_kms_key_arn

  # Alerting — reuse existing SNS topic
  existing_sns_topic_arn = module.nhp.sns_topic_arn
  use_existing_sns_topic = true
  alert_emails           = var.guardduty_alert_emails

  # Cleanup events (Option A from qurl-service#148)
  cleanup_topic_arn            = aws_sns_topic.custom_domain_cleanup[0].arn
  cleanup_subscription_enabled = var.deploy_custom_domain_cert

  tags = local.common_tags
}

# Note: the smoke-test discovery params + smoke-role IAM policy for the
# cleanup consumer (#2000) are defined at root (terraform/main.tf), driven
# by `deploy_custom_domain_cert` and `qurl_custom_domain_cleanup_topic_arn`
# threaded from the module "nhp" inputs above.

# ==============================================================================
# Auth0 Identity Management
# ==============================================================================

module "auth0" {
  source = "../../modules/auth0"

  environment             = var.environment
  name_prefix             = local.name_prefix
  api_audience            = var.qurl_auth0_audience
  tags                    = local.common_tags
  manage_tenant_resources = var.auth0_manage_tenant_resources

  enable_rotation             = var.auth0_enable_rotation
  rotation_days               = var.auth0_rotation_days
  auth0_domain                = var.auth0_enable_rotation ? var.auth0_domain : null
  auth0_management_secret_arn = var.auth0_management_secret_arn

  # Rotation monitoring — alarms sent to the shared SNS topic
  # Gate SNS alarms with rotation: these alarms do not exist when rotation is off.
  alarm_sns_topic_arn = module.nhp.sns_topic_arn
  enable_sns_alerts   = var.auth0_enable_rotation

  # Developer portal management M2M app (only create when portal is enabled)
  dev_portal_mgmt_secret_name = var.deploy_developer_portal ? var.developer_portal_auth0_mgmt_secret_name : null
  auth0_tenant_domain         = var.auth0_domain

  # SPA dashboard client for developer login
  enable_spa_dashboard = var.enable_auth0_spa_dashboard
  auth0_custom_domain  = var.auth0_custom_domain

  # Auth0 client IDs (#3284). The Auth0 provider is retired, so the AWS-side
  # resources here take the client IDs as inputs. These are PUBLIC identifiers
  # (the dashboard one is already a plaintext SSM parameter shipped to browsers
  # as NEXT_PUBLIC_AUTH0_CLIENT_ID), not secrets. Client SECRETS are written
  # straight into Secrets Manager by an operator and never enter Terraform.
  backend_service_client_id = var.auth0_backend_service_client_id
  smoke_test_client_id      = var.auth0_smoke_test_client_id
  spa_dashboard_client_id   = var.auth0_spa_dashboard_client_id

  # Dedicated smoke test M2M client (system tier)
  enable_smoke_test_client = true

  # Email (SES) — layerv.ai domain needs SES verification for prod
  email_ses_region = "us-east-1"
}

# ==============================================================================
# Smoke Test Customer Record (system tier)
# ==============================================================================
# Ensure the smoke test M2M client has "system" tier in the qurl_customers
# table. Uses update-item (upsert) instead of aws_dynamodb_table_item because
# the item is auto-provisioned by qurl-service on first API call, and
# aws_dynamodb_table_item uses conditional PutItem which fails if the item
# already exists (and doesn't support import).
resource "terraform_data" "smoke_test_customer_tier" {
  count = module.auth0.smoke_test_client_id != null ? 1 : 0

  input = {
    table_name = module.nhp.dynamodb_qurl_customers_table_name
    subject    = "${module.auth0.smoke_test_client_id}@clients"
    region     = var.aws_region
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      aws dynamodb update-item \
        --table-name '${self.input.table_name}' \
        --key '{"auth0_subject": {"S": "${self.input.subject}"}}' \
        --update-expression 'SET tier = :t REMOVE email' \
        --expression-attribute-values '{":t": {"S": "system"}}' \
        --region '${self.input.region}'
    EOT
  }
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

output "connector_authority_cell_caller_role_name" {
  description = "Exact NHP server role name for this production cell's future least-privilege Connector Authority calls."
  value       = module.nhp.connector_authority_cell_caller_role_name
}

output "connector_authority_cell_caller_role_arn" {
  description = "Exact NHP server role ARN for this production cell's future least-privilege Connector Authority calls."
  value       = module.nhp.connector_authority_cell_caller_role_arn
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

output "github_actions_terraform_plan_pr_role_arn" {
  description = "Sandbox-only read-only IAM role ARN for terraform-plan-pr.yml; prod returns null by design."
  value       = module.nhp.github_actions_terraform_plan_pr_role_arn
}

output "github_actions_packer_role_arn" {
  description = "Dedicated IAM role ARN for the build-and-push.yml::packer-build Server and AC AMI builds. Store in GitHub Actions secret AWS_PACKER_PROD_ROLE_ARN."
  value       = module.nhp.github_actions_packer_role_arn
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

output "auth0_api_identifier" {
  description = "Auth0 API identifier (audience)"
  value       = module.auth0.api_identifier
}

output "auth0_backend_service_client_id" {
  description = "Website playground M2M client ID (legacy name: 'backend') — NOT for CI/smoke tests"
  value       = module.auth0.backend_service_client_id
}

output "auth0_backend_credentials_secret_arn" {
  description = "Secrets Manager ARN for website playground proxy credentials — NOT for CI/smoke tests"
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

# SPA Dashboard outputs
output "auth0_spa_dashboard_client_id" {
  description = "Auth0 SPA dashboard client ID (NEXT_PUBLIC_AUTH0_CLIENT_ID)"
  value       = module.auth0.spa_dashboard_client_id
}

output "auth0_spa_dashboard_enabled" {
  description = "Whether the SPA dashboard Auth0 client is enabled"
  value       = module.auth0.spa_dashboard_enabled
}

output "auth0_spa_domain" {
  description = "Auth0 domain for SPA frontend configuration (NEXT_PUBLIC_AUTH0_DOMAIN)"
  value       = module.auth0.auth0_domain
}

output "auth0_spa_api_audience" {
  description = "Auth0 API audience for SPA frontend configuration (NEXT_PUBLIC_AUTH0_AUDIENCE)"
  value       = module.auth0.api_audience
}

output "auth0_spa_client_id_ssm_arn" {
  description = "ARN of SSM parameter containing SPA client ID (for IAM policies)"
  value       = module.auth0.spa_client_id_ssm_arn
}

output "auth0_spa_domain_ssm_arn" {
  description = "ARN of SSM parameter containing Auth0 domain (for IAM policies)"
  value       = module.auth0.spa_auth0_domain_ssm_arn
}

output "auth0_spa_api_audience_ssm_arn" {
  description = "ARN of SSM parameter containing API audience (for IAM policies)"
  value       = module.auth0.spa_api_audience_ssm_arn
}

# Smoke test outputs
output "auth0_smoke_test_client_id" {
  description = "Auth0 smoke test M2M client ID"
  value       = module.auth0.smoke_test_client_id
}

output "auth0_smoke_test_credentials_secret_arn" {
  description = "Secrets Manager ARN for smoke test Auth0 credentials"
  value       = module.auth0.smoke_test_credentials_secret_arn
}
