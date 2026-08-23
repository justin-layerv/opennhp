# Sandbox Environment
# Sources the root module with sandbox-specific configuration

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
  server_ami_id                   = var.server_ami_id
  ac_ami_id                       = var.ac_ami_id
  domain_name                     = var.domain_name
  hosted_zone                     = var.hosted_zone
  multi_tenant                    = var.multi_tenant
  deploy_etcd                     = var.deploy_etcd
  min_capacity                    = var.min_capacity
  max_capacity                    = var.max_capacity
  vpc_cidr                        = var.vpc_cidr
  tags                            = var.tags
  is_primary_account              = var.is_primary_account
  primary_account_id              = var.primary_account_id
  secondary_account_ids           = var.secondary_account_ids
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
  ac_filter_mode                  = var.ac_filter_mode
  enable_l3_flush_on_expiry       = var.enable_l3_flush_on_expiry
  l3_flush_dry_run                = var.l3_flush_dry_run
  l3_flush_real_mode_acknowledged = var.l3_flush_real_mode_acknowledged
  l3_flush_conntrack_backend      = var.l3_flush_conntrack_backend
  l3_flush_conntrack_pool_size    = var.l3_flush_conntrack_pool_size
  enable_egress_eips              = var.enable_egress_eips

  # Security services
  enable_cloudtrail          = var.enable_cloudtrail
  config_recording_frequency = var.config_recording_frequency
  config_resource_types      = var.config_resource_types

  # GitHub OIDC - set to false if org manages centrally or SCP blocks creation
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

  # QURL domains (sandbox uses layerv.xyz subdomains)
  production_domains     = var.production_domains
  production_zone_ids    = var.production_zone_ids
  additional_tls_domains = var.additional_tls_domains
  use_production_acme    = var.use_production_acme

  # Deployment configuration
  image_tag = var.image_tag

  # NHP Server plugins
  server_plugins = var.server_plugins

  # QURL Service
  deploy_qurl_service                  = var.deploy_qurl_service
  control_identity_environment_id      = var.control_identity_environment_id
  control_identity_home_region         = var.control_identity_home_region
  control_identity_kms_key_arn         = var.control_identity_kms_key_arn
  deploy_qurl_bootstrap_chain          = var.deploy_qurl_bootstrap_chain
  enable_qurl_agent_bootstrap          = var.enable_qurl_agent_bootstrap
  retire_http_agent_lifecycle          = var.retire_http_agent_lifecycle
  qurl_scanner_lambda_enabled          = var.qurl_scanner_lambda_enabled
  qurl_scanner_sqs_emit_enabled        = var.qurl_scanner_sqs_emit_enabled
  qurl_scanner_tombstone_write_enabled = var.qurl_scanner_tombstone_write_enabled
  qurl_scanner_active_recheck_enabled  = var.qurl_scanner_active_recheck_enabled
  qurl_connector_auth_enabled          = var.qurl_connector_auth_enabled
  qurl_service_domain                  = var.qurl_service_domain
  qurl_hosted_zone_id                  = var.qurl_hosted_zone_id
  qurl_jwt_secret_arn                  = var.qurl_jwt_secret_arn
  qurl_internal_service_token_arn      = var.qurl_internal_service_token_arn
  qurl_internal_service_domain         = var.qurl_internal_service_domain
  qurl_additional_allowed_hosts        = var.qurl_additional_allowed_hosts
  qurl_cors_allowed_origins            = var.qurl_cors_allowed_origins
  qurl_audit_retention_days            = var.qurl_audit_retention_days
  qurl_cookie_domain                   = var.qurl_cookie_domain
  qurl_link_domain                     = var.qurl_link_domain
  qurl_site_domain                     = var.qurl_site_domain
  qurl_site_hosted_zone_id             = var.qurl_site_hosted_zone_id
  qurl_ip_rate_limit                   = var.qurl_ip_rate_limit
  qurl_ip_rate_burst                   = var.qurl_ip_rate_burst

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

  # Agent registration + email OTP (T1). Sandbox: DARK (all flags false / empty in
  # terraform.tfvars). Thresholds still flow through so a future sandbox enable is
  # a focused tfvars flip. With the flags off the root creates nothing.
  agent_registration_enabled                             = var.agent_registration_enabled
  agent_otp_enabled                                      = var.agent_otp_enabled
  agent_otp_registration_enabled                         = var.agent_otp_registration_enabled
  agent_otp_ci_send_gate_enabled                         = var.agent_otp_ci_send_gate_enabled
  agent_otp_email_from                                   = var.agent_otp_email_from
  agent_otp_ci_mailbox_enabled                           = var.agent_otp_ci_mailbox_enabled
  agent_registration_relay_base_url                      = var.agent_registration_relay_base_url
  agent_otp_send_failed_threshold_per_minute             = var.agent_otp_send_failed_threshold_per_minute
  agent_otp_bounce_threshold_per_minute                  = var.agent_otp_bounce_threshold_per_minute
  agent_otp_rate_limited_threshold_per_minute            = var.agent_otp_rate_limited_threshold_per_minute
  agent_register_attempts_exceeded_threshold_per_minute  = var.agent_register_attempts_exceeded_threshold_per_minute
  agent_register_credential_invalid_threshold_per_minute = var.agent_register_credential_invalid_threshold_per_minute
  agent_register_rate_limited_threshold_per_minute       = var.agent_register_rate_limited_threshold_per_minute
  relay_otp_reject_rate_limited_threshold_per_minute     = var.relay_otp_reject_rate_limited_threshold_per_minute

  # qURL v2 (keyed identity) — all default off; flip in tfvars to enable.
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

  # QURL Router plugin (Traefik)
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

  # qurl-reverse-tunnel-server (FRPS-behind-AC). The legacy FRPS
  # passthroughs below (`deploy_frps`, `connect_layerv_host`,
  # `frps_image_tag`, `frps_bind_port`, `frps_vhost_http_port`,
  # `frps_az_suffixes`, and the `frps_min_size`/`max_size`/`desired_capacity`
  # triple) were previously set in env tfvars (or could be) but NOT
  # declared at the env root, which surfaced as "Value for undeclared
  # variable" warnings at plan time and made the values silently no-op
  # at apply — leaving #1977's FRPS-behind-AC topology unapplied.
  # Threading them here closes that gap (deferral comment from #1745's
  # `qurl-frps 2/AZ` work explicitly handed this off as "PR 4").
  # `frps_bind_port` and `frps_vhost_http_port` aren't set in current
  # tfvars but are wired through so any future env-level override
  # doesn't fall into the same trap.
  deploy_frps           = var.deploy_frps
  connect_layerv_host   = var.connect_layerv_host
  frps_image_tag        = var.frps_image_tag
  frps_bind_port        = var.frps_bind_port
  frps_vhost_http_port  = var.frps_vhost_http_port
  frps_az_suffixes      = var.frps_az_suffixes
  frps_min_size         = var.frps_min_size
  frps_max_size         = var.frps_max_size
  frps_desired_capacity = var.frps_desired_capacity

  # Bootstrap ALB (`bootstrap.layerv.{xyz,ai}`). See variables.tf §Bootstrap ALB
  # for rationale; per-env runbook in modules/bootstrap-alb/README.md.
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

  # NHP-Relay (#2208)
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

  # qurl-service bootstrap-outcome 401/429 spike alarms (#2102, root-
  # level `terraform/qurl_service_outcomes.tf`). Threshold defaults
  # 3/min mirror the existing `alb_target_5xx` shape; env-tunable to
  # quiet the alarm during a known operator probe / load test.
  bootstrap_unauthorized_threshold_per_minute = var.bootstrap_unauthorized_threshold_per_minute
  bootstrap_rate_limited_threshold_per_minute = var.bootstrap_rate_limited_threshold_per_minute

  # qurl-reverse-tunnel-server knock-token reject-rate alarm threshold
  # (#2102). Same default + tuning shape as the bootstrap-outcome
  # thresholds above; env-tunable for known maintenance windows.
  knock_token_reject_threshold_per_minute = var.knock_token_reject_threshold_per_minute

  # qurl-reverse-tunnel-server owner_missing reverse-tunnel reject alarm
  # threshold. Same env-wrapper forward as the knock-token threshold above
  # (root default 5); without this pass-through, the Tuning step in the
  # runbook ("raise via env tfvars during a planned force-restart window")
  # would silently no-op on the root default — the #2131 env-root gap.
  owner_missing_reject_threshold = var.owner_missing_reject_threshold

  # qurl-reverse-tunnel-server per-AZ Cloud Map fanout (#1745):
  # blue/green, canary, and MULTIVALUE-flip variables.
  qurl_reverse_tunnel_server_min_size_per_az               = var.qurl_reverse_tunnel_server_min_size_per_az
  qurl_reverse_tunnel_server_max_size_per_az               = var.qurl_reverse_tunnel_server_max_size_per_az
  qurl_reverse_tunnel_server_desired_capacity_per_az       = var.qurl_reverse_tunnel_server_desired_capacity_per_az
  qurl_reverse_tunnel_server_cloud_map_routing_policy      = var.qurl_reverse_tunnel_server_cloud_map_routing_policy
  enable_qurl_reverse_tunnel_server_blue_green             = var.enable_qurl_reverse_tunnel_server_blue_green
  qurl_reverse_tunnel_server_green_standby_capacity_per_az = var.qurl_reverse_tunnel_server_green_standby_capacity_per_az
  enable_qurl_reverse_tunnel_server_canary                 = var.enable_qurl_reverse_tunnel_server_canary

  # Knock-token-as-identity auth mode for qurl-reverse-tunnel-server.
  # Sandbox flips to "tunnel-auth" via terraform.tfvars. This pass-through is
  # the piece that was missing in #2131: the var was declared at the root and
  # set in sandbox tfvars, but the env wrapper didn't forward it, so Terraform
  # silently kept FRPS on the root default regardless of tfvars.
  qurl_reverse_tunnel_server_tunnel_auth_mode   = var.qurl_reverse_tunnel_server_tunnel_auth_mode
  qurl_reverse_tunnel_server_min_client_version = var.qurl_reverse_tunnel_server_min_client_version

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

  # QURL Custom Domains
  qurl_custom_domain_enabled                 = var.qurl_custom_domain_enabled
  qurl_custom_domain_cleanup_topic_arn       = var.deploy_custom_domain_cert ? aws_sns_topic.custom_domain_cleanup[0].arn : ""
  qurl_custom_domain_cleanup_publish_enabled = var.deploy_custom_domain_cert
  deploy_custom_domain_cert                  = var.deploy_custom_domain_cert

  # QURL GeoIP
  qurl_geoip_enabled        = var.qurl_geoip_enabled
  qurl_geoip_db_path        = var.qurl_geoip_db_path
  qurl_geoip_s3_uri         = var.qurl_geoip_s3_uri
  qurl_geoip_s3_kms_key_arn = var.qurl_geoip_s3_kms_key_arn

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
  qurl_container_cpu            = var.qurl_container_cpu
  qurl_container_memory         = var.qurl_container_memory
  qurl_container_port           = var.qurl_container_port
  qurl_desired_count            = var.qurl_desired_count
  qurl_autoscaling_min_capacity = var.qurl_autoscaling_min_capacity

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
  grafana_cloudwatch_enabled        = var.grafana_cloudwatch_enabled
  grafana_cloud_aws_account_id      = var.grafana_cloud_aws_account_id
  grafana_cloud_external_id         = var.grafana_cloud_external_id
  grafana_create_dashboards         = var.grafana_create_dashboards

  # Cost analytics
  deploy_cost_analytics                 = var.deploy_cost_analytics
  cross_account_cost_analytics_role_arn = var.cross_account_cost_analytics_role_arn
  grafana_athena_config                 = var.grafana_athena_config

  # Traefik plugins
  traefik_plugins = var.traefik_plugins

  # Traefik plugins deploy bucket (for traefik-plugins CI/CD SSM-based deployment)
  traefik_plugins_deploy_bucket_arn = var.traefik_plugins_deploy_bucket_arn

  # Plugin repos - repos that can assume the GitHub Actions role
  plugin_repos = var.plugin_repos

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

  # Centralized certificate management
  centralized_cert_enabled    = var.centralized_cert_enabled
  centralized_cert_secret_arn = var.centralized_cert_enabled ? module.acme_cert[0].certificate_secret_arn : null
  centralized_cert_domains    = var.centralized_cert_enabled ? var.centralized_cert_domains : []
  # Use computed name to avoid cycle: nhp depends on acme_cert output, acme_cert depends on nhp's logs_kms_key_arn
  # WARNING: This name must match the pattern in modules/acme-cert/main.tf local.function_name
  acme_lambda_function_name = var.centralized_cert_enabled ? "${local.name_prefix}-acme-cert-manager" : ""

  # Termination cleanup
  enable_termination_cleanup = var.enable_termination_cleanup

  # Secret reconciliation (cleanup orphaned per-instance secrets)
  enable_secret_reconciliation = var.enable_secret_reconciliation

  # Blue/Green deployment configuration (Server)
  enable_blue_green               = var.enable_blue_green
  green_standby_min_size          = var.green_standby_min_size
  deployment_stale_threshold_days = var.deployment_stale_threshold_days

  # Blue/Green deployment configuration (AC)
  enable_ac_blue_green      = var.enable_ac_blue_green
  ac_green_standby_min_size = var.ac_green_standby_min_size

  # Canary deployment
  enable_canary_deployment        = var.enable_canary_deployment
  canary_checkpoint_percentages   = var.canary_checkpoint_percentages
  canary_checkpoint_delay_seconds = var.canary_checkpoint_delay_seconds
  canary_instance_warmup_seconds  = var.canary_instance_warmup_seconds

  # Status page
  deploy_status_page                     = var.deploy_status_page
  status_page_domain                     = var.status_page_domain
  status_page_hosted_zone_id             = var.status_page_hosted_zone_id
  status_page_additional_service_urls    = var.status_page_additional_service_urls
  status_page_display_only_component_ids = var.status_page_display_only_component_ids
  status_page_nhp_auth_enabled           = var.status_page_nhp_auth_enabled
  status_page_nhp_auth_qurl_url          = var.status_page_nhp_auth_qurl_url

  # Redis (distributed rate limiting)
  deploy_redis = var.deploy_redis

  # VPC endpoints for QURL service AWS dependencies
  deploy_vpc_endpoints = var.deploy_vpc_endpoints

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
  dashboard_allowed_origins          = var.dashboard_allowed_origins
  billing_from_email                 = var.billing_from_email
  billing_ses_region                 = var.billing_ses_region
  billing_grace_period_days          = var.billing_grace_period_days
  billing_downgrade_after_days       = var.billing_downgrade_after_days
  billing_api_throttle_burst_limit   = var.billing_api_throttle_burst_limit
  billing_api_throttle_rate_limit    = var.billing_api_throttle_rate_limit

  # Developer Portal
  deploy_developer_portal                 = var.deploy_developer_portal
  developer_portal_m2m_secret_name        = var.developer_portal_m2m_secret_name
  developer_portal_auth0_mgmt_secret_name = var.developer_portal_auth0_mgmt_secret_name
  developer_portal_auth0_domain           = var.developer_portal_auth0_domain
  developer_portal_allowed_origins        = var.developer_portal_allowed_origins
  developer_portal_custom_domain          = var.developer_portal_custom_domain
  developer_portal_hosted_zone_id         = var.developer_portal_hosted_zone_id
  developer_portal_ci_bypass_secret_name  = var.developer_portal_ci_bypass_secret_name
  developer_portal_connector_base_url     = var.developer_portal_connector_base_url
}

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================
# Manages TLS certificates for AC fleet using Let's Encrypt.
# Certificates are stored in Secrets Manager and fetched by ACs on boot.
# This scales to thousands of ACs without hitting Let's Encrypt rate limits.
#
# NOTE: This is an interim solution. For production at scale, consider
# migrating to HashiCorp Vault PKI for:
# - Short-lived certificates (hours vs 90 days)
# - Internal CA (no external dependencies)
# - Better revocation support

module "acme_cert" {
  count  = var.centralized_cert_enabled ? 1 : 0
  source = "../../modules/acme-cert"

  name_prefix         = local.name_prefix
  environment         = var.environment
  domains             = var.centralized_cert_domains
  hosted_zone_id      = var.qurl_hosted_zone_id # layerv.xyz zone (default for domains not in domain_zone_mappings)
  acme_email          = var.acme_email
  use_production_acme = var.use_production_acme
  kms_key_arn         = module.nhp.secrets_kms_key_arn
  logs_kms_key_arn    = module.nhp.logs_kms_key_arn

  # All sandbox domains are in the layerv.xyz zone (same account, no cross-account needed)
  domain_zone_mappings   = {}
  cross_account_role_arn = null

  # Renewal configuration
  renewal_days_before_expiry = 30
  renewal_schedule           = "rate(1 day)"

  # Alerting
  alert_emails           = var.guardduty_alert_emails
  existing_sns_topic_arn = module.nhp.sns_topic_arn

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
# Owned at env level to break the module cycle (see prod equivalent / nhp#1990).
resource "aws_sns_topic" "custom_domain_cleanup" {
  count = var.deploy_custom_domain_cert ? 1 : 0
  name  = "${local.name_prefix}-custom-domain-cleanup"
  # AWS-managed key — see prod equivalent for rationale (cert lambda
  # subscription needs sns.amazonaws.com → kms:Decrypt at delivery).
  kms_master_key_id = "alias/aws/sns"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-custom-domain-cleanup"
  })
}

# Mirrors the prod alarm — see prod equivalent for rationale.
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
    aws.parent_dns = aws # Same account in sandbox
  }

  name_prefix         = local.name_prefix
  environment         = var.environment
  cell_id             = var.cell_id
  acme_base_domain    = var.hosted_zone         # layerv.xyz for sandbox
  parent_zone_id      = var.qurl_hosted_zone_id # layerv.xyz zone — NS delegation for acme sub-zone
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
# threaded from the module "nhp" inputs above. No env-level resources needed.

# ==============================================================================
# Auth0 Identity Management
# ==============================================================================
# Manages Auth0 resources for QURL API authentication.

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

module "auth0" {
  source = "../../modules/auth0"

  environment             = var.environment
  name_prefix             = local.name_prefix
  api_audience            = var.qurl_auth0_audience
  tags                    = local.common_tags
  manage_tenant_resources = var.auth0_manage_tenant_resources
  # secrets_kms_key_arn - uses AWS managed key (null default)

  # Secret rotation configuration
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
  slack_oauth_client_id     = var.auth0_slack_oauth_client_id

  # Dedicated smoke test M2M client (system tier)
  enable_smoke_test_client = true

  # Slack OAuth regular_web client for qurl-bot-slack workspace-install flow.
  # Callback URL is derived from `local.slack_bot_domain` (qurl_bot_dns.tf:36) +
  # the qurl-bot-slack handler's fixed `/oauth/qurl/callback` path. Single source
  # of truth for the bot's hostname; changes to the DNS local propagate here
  # without an extra tfvars edit.
  enable_slack_oauth_client = var.enable_auth0_slack_oauth_client

  # Email (SES)
  email_ses_region = "us-east-2"
}

# The module.auth0[0] -> module.auth0 state migration `moved` blocks that lived
# here were deleted with #3284. Their targets were `auth0_*` resources, which
# Terraform no longer manages (see modules/auth0/removed.tf); a `moved` block
# pointing at a resource absent from configuration is not valid. The migration
# itself completed long ago — sandbox state records the non-indexed addresses.

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

# Remove the old aws_dynamodb_table_item from state without destroying
# the DynamoDB item. The resource was replaced by terraform_data above.
removed {
  from = aws_dynamodb_table_item.smoke_test_customer

  lifecycle {
    destroy = false
  }
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

output "github_actions_terraform_plan_pr_role_arn" {
  description = "Read-only IAM role ARN for .github/workflows/terraform-plan-pr.yml. Store in GitHub Actions repo secret AWS_TERRAFORM_PLAN_PR_ROLE_ARN."
  value       = module.nhp.github_actions_terraform_plan_pr_role_arn
}

output "github_actions_packer_role_arn" {
  description = "ARN to put in GitHub Actions secret AWS_PACKER_SANDBOX_ROLE_ARN for Server and AC AMI builds (see terraform/modules/ecr/packer.tf)."
  value       = module.nhp.github_actions_packer_role_arn
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

output "plugin_bucket_name" {
  value = module.nhp.plugin_bucket_name
}

output "plugin_bucket_arn" {
  value = module.nhp.plugin_bucket_arn
}

# Auth0 outputs
output "auth0_api_identifier" {
  description = "Auth0 API identifier (audience) for JWT validation"
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
  description = "ARN of the Auth0 secret rotation Lambda (null if rotation disabled)"
  value       = module.auth0.rotation_lambda_arn
}

output "auth0_rotation_enabled" {
  description = "Whether Auth0 secret rotation is enabled"
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

# Billing outputs
output "billing_api_url" {
  description = "Billing API Gateway invoke URL"
  value       = module.nhp.billing_api_url
}

output "billing_usage_events_queue_url" {
  description = "SQS queue URL for billing usage events"
  value       = module.nhp.billing_usage_events_queue_url
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
