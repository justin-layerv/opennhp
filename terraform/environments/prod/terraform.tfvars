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
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.200.0.0/16" # Different CIDR from sandbox

# Multi-account config: images replicated from sandbox ECR to local prod registry
is_primary_account = false
primary_account_id = "767397897469" # Sandbox (layerv) account ID
enable_replication = true           # Receive replicated images from sandbox ECR

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.ai"
ac_auth_service_id = "agent"
# Two AC-protected resources, each a distinct identity per NHP spec
# (CSA "Stealth Mode SDP" Appendix 2, NHP-KNK Message Fields):
#   - "qurl"               — viewer-side qurl-link / SPA resolve flow
#                            (gates the qurl.site landing endpoint)
#   - "qurl-tunnel-server" — agent-side reverse-tunnel control channel
#                            (gates the tunnel-server FRP control port
#                            behind the AC's ipset). Mirrors the resId
#                            emitted by `local.tunnel_server_res_id` in
#                            resources.tf, which the agent knocks against.
# DO NOT add `frps-*` aliases here — those were a pre-spec naming where
# the resId conflated implementation (FRPS) and placement (env/region)
# with resource identity. Hard-cutover rename in PR shipping this file.
ac_resource_ids    = ["qurl", "qurl-tunnel-server"]
ac_min_capacity    = 3
ac_max_capacity    = 10
enable_egress_eips = true

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

# CORS allowed origins for NHP HTTP server (browser-facing plugin endpoints)
# Wildcard patterns (https://*.domain) match any single-level subdomain.
# Needed because AC Traefik serves pages on dynamic {resId}.nhp.layerv.ai subdomains.
nhp_cors_allowed_origins = "https://*.nhp.layerv.ai,https://*.qurl.site,https://qurl.link,https://layerv.ai,https://www.layerv.ai"

# Termination cleanup
enable_termination_cleanup = true

# Secret reconciliation: Lambda cleans orphaned per-instance AC secrets daily
enable_secret_reconciliation = true

# Slack notifications via AWS Chatbot.
#
# slack_workspace_id and slack_channel_id are documentation-only while
# chatbot_owned_externally = true — local.enable_slack short-circuits and
# nothing here actually wires them to a Chatbot config. They mirror the
# (workspace, channel) pair that website CDK's LayerV-Monitoring stack owns;
# keep these values in sync with that stack if either side rotates so a
# future re-takeover doesn't land on stale identifiers.
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C09UP62A8F4" # #all-layerv

# The (T09UP622L90, C09UP62A8F4) Chatbot config is owned by website CDK's
# LayerV-Monitoring stack (ProdSlackChannel, us-east-1), which subscribes our
# us-east-2 alerts topic. NHP terraform skips creating its own Chatbot config
# here so the account-wide (workspace, channel) uniqueness constraint stays
# satisfied. See website repo CLAUDE.md *Cross-repo handoff*.
#
# OPERATOR NOTE: the first prod apply after this lands will plan a destroy
# on `module.monitoring.aws_chatbot_slack_channel_configuration.alerts[0]`
# and the dedicated IAM role/policy. Do NOT apply that destroy until the
# website CDK's `LayerV-Monitoring` stack is deployed and subscribed —
# follow the website repo runbook (steps 0–4) which runs `terraform state rm`
# on the chatbot config before any prod apply touches it.
chatbot_owned_externally = true

# GuardDuty security alerts
guardduty_alert_emails = [
  "justin@layerv.ai",
  "benc@layerv.ai",
  "joe@layerv.ai"
]

# CloudWatch alarm email notifications (complementary to Slack)
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

# AC license key hashes (plaintext key passed via TF_VAR_ac_license_key from PROD_AC_LICENSE_KEY secret)
# Generated by: terraform/scripts/generate-ac-license.sh prod
# Stored in Secrets Manager: layerv-nhp-prod/ac-license-key
ac_customer_id        = "00000000000000000000000000" # Nil ULID for LayerV system customer (required for DynamoDB GSI)
ac_license_key_hash   = "$2b$10$DOiwRhVzk94ZSllcY0Arye1hON734.qydu1ou2d/RSTklnvEVcRcO"
ac_license_key_sha256 = "cd7f8df5284861a9ebfbe485085843b3631b8dbe325f272622473bfb4991bdfe"

# CloudMap — enables server health filtering for knock forwarding
nhp_cloudmap_service_name = "server"
cloudmap_enabled          = true

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
# Cross-account Route53 zones (layerv-mgmt account: 165115313779)
# layerv.ai  = Z0748438C8EK6UAW94ST
# qurl.site  = Z06942509AYXSB91X7CD
# qurl.link  = Z0693053DKJ8S3XN9WPG
qurl_link_domain         = "qurl.link"
qurl_site_domain         = "qurl.site"
qurl_site_hosted_zone_id = "Z06942509AYXSB91X7CD" # qurl.site zone (in layerv-mgmt account)
qurl_cookie_domain       = ".qurl.site"

# QURL Service (ECS Fargate API)
deploy_qurl_service             = true
qurl_service_domain             = "api.layerv.ai"
qurl_hosted_zone_id             = "Z0748438C8EK6UAW94ST" # layerv.ai zone (in layerv-mgmt account)
qurl_jwt_secret_arn             = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/qurl-jwt-secret-NRk5sw"
qurl_internal_service_token_arn = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/qurl-internal-service-token-ETbWzv"

# Internal ALB hostname (qurl-service #335 network isolation).
# Workload-account private hosted zone; external resolvers NXDOMAIN.
# Cert validation CNAME on the public layerv.ai mgmt zone above.
qurl_internal_service_domain = "internal-api.qurl.layerv.ai"

# Stage-2 of the rollout — sandbox MUST flip to true and verify before
# prod follows. Keep false at PR1 merge time; flip only after PR2/PR3
# have moved consumers to the internal hostname.
qurl_enforce_internal_alb_only = false

# Website email-capture API DNS — A-alias for the APIGW custom domain that the
# website CDK provisions in layerv-prod us-east-1. Replaces the old broken wiring
# where the site's tracker hit api.layerv.ai (now QURL). See layervai/website#188.
# The A-alias target is read from the CDK stack's CloudFormation outputs
# (ApiCustomDomainRegionalDomainName + ApiCustomDomainRegionalHostedZoneId).
deploy_website_api_dns     = true
website_api_domain         = "web-api.layerv.ai"
website_api_cfn_stack_name = "LayerV-production-Api"

# QURL Custom Domains (enables /v1/domains endpoints)
qurl_custom_domain_enabled = true

# QURL Link (CloudFront redirect page)
deploy_qurl_link          = true
qurl_link_frontend_domain = "qurl.link"
qurl_link_hosted_zone_id  = "Z0693053DKJ8S3XN9WPG" # qurl.link zone (in layerv-mgmt account)
qurl_link_external_dns    = false                  # DNS via route53_mgmt cross-account provider

# CloudFront for resolve.qurl.link - ISP compatibility (AT&T WiFi blocks NLB IPs)
enable_resolve_cloudfront = true

# Traefik plugins (downloaded from S3 at boot time)
# Plugin source files are uploaded by traefik-plugins repo CI to s3://layerv-nhp-prod-plugins/
# Key names must match moduleName in traefik.toml for Traefik local plugin resolution
traefik_plugins = {
  "github.com/traefik/qurl-router" = {
    version = "latest"
    config  = {}
  }
}

# QURL Router plugin (Traefik - routes *.qurl.site to target backends)
# Requires QURL Service to be deployed (deploy_qurl_service = true)
qurl_router_enabled = true

# L7 per-session authz gate on *.qurl.site. Activates at the NEXT
# AC instance refresh after apply (not at terraform apply itself —
# the AC ASG has no instance_refresh{} block on purpose). The prod
# canary state machine is what drives the refresh.
# See `var.enable_qurl_site_authz` for the full description.
enable_qurl_site_authz = true

# CORS
# Note: website origins appear here (QURL API) AND in dashboard_allowed_origins
# (billing/developer-portal APIs) because they are separate CORS configurations.
qurl_cors_allowed_origins = "https://qurl.link,https://*.qurl.site,https://layerv.ai,https://www.layerv.ai"

# Dashboard CORS origins (shared by developer portal, billing API)
dashboard_allowed_origins = ["https://layerv.ai", "https://www.layerv.ai"]

# Billing — When enabling deploy_billing in prod, set these values:
# billing_stripe_secret_name         = "layerv-nhp-prod-stripe-credentials"
# billing_stripe_webhook_secret_name = "layerv-nhp-prod-stripe-webhook-secret"
# billing_growth_price_id            = "price_xxx"  # from Stripe dashboard
# billing_base_fee_price_id          = "price_xxx"  # from Stripe dashboard
# billing_success_url                = "https://layerv.ai/qurl/dashboard/billing?success=true"
# billing_cancel_url                 = "https://layerv.ai/qurl/dashboard/billing?cancelled=true"
# billing_allowed_origins            = ["https://layerv.ai", "https://www.layerv.ai"]
# billing_from_email                 = "billing@layerv.ai"

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

# Audit log retention (production: longer retention)
qurl_audit_retention_days = 365

# Auth0 Terraform provider configuration
# IMPORTANT: auth0_domain must be the TENANT domain (not custom domain)
auth0_domain = "layerv.us.auth0.com"

# Auth0 configuration for JWT validation (custom domain)
qurl_auth0_domain   = "auth.layerv.ai"
qurl_auth0_audience = "https://api.layerv.ai"

# Prod owns shared Auth0 tenant resources (roles, branding, attack protection, email, social connections)
auth0_manage_tenant_resources = true

# Auth0 M2M credential rotation (Phase 2: enable after auth0 management secret is created)
auth0_enable_rotation = false

# QURL ECS Fargate capacity (right-sized for initial sporadic traffic)
# With ADOT sidecar: CPU = max(256,512) = 512, memory = ceil((1024+256)/1024)*1024 = 2048
qurl_container_cpu            = 256  # 0.25 vCPU — ADOT bumps task CPU to 512
qurl_container_memory         = 1024 # 1024 MB — module rounds up task memory to 2048 for Fargate validity
qurl_desired_count            = 3
qurl_autoscaling_min_capacity = 3
qurl_autoscaling_max_capacity = 10

# GeoIP database for geo-restriction policies (geo_allowlist/geo_denylist)
qurl_geoip_enabled        = true
qurl_geoip_s3_uri         = "s3://layerv-nhp-prod-plugins/geoip/GeoLite2-Country.mmdb"
qurl_geoip_s3_kms_key_arn = "arn:aws:kms:us-east-2:235500187906:key/1a8cbf38-72ea-48a3-9a93-cb9762c83f50"

# QURL AC Fleet defaults
qurl_default_ac_id   = "layerv-ac-tf"
qurl_default_ac_port = 443

# ==============================================================================
# FRPS-behind-AC / reverse-tunnel activation (prod)
# ==============================================================================
# Activates the qurl-reverse-tunnel-server data path in prod, mirroring the
# sandbox topology that has soaked green (the layerv-nhp-sandbox-frps ASG runs
# 3/3 healthy and connect.layerv.xyz resolves per-AZ). The three documented
# flip-to-prod prereqs are met:
#   1. Sandbox burn-in green — frps ASG healthy, connect.layerv.xyz live.
#   2. qurl-reverse-tunnel-server #98 merged + sandbox in tunnel-auth mode.
#   3. cross-account Route53 (aws.route53_mgmt) + the connect_cross_account
#      record are in main, and prod cross_account_route53_role_arn is set —
#      so connect.layerv.ai publishes into the layerv-mgmt layerv.ai zone.
#
# Fleet shape mirrors the sandbox-soaked config: a plain per-AZ ASG (one
# instance per AZ via frps_az_suffixes), NOT canary/blue-green/per_az — those
# stay at their prod defaults (off/null).
#
# frps_image_tag is intentionally NOT set here. The running image is owned by
# rts CI (qurl-reverse-tunnel-server's promote-production.yml writes
# /prod/nhp/reverse-tunnel-server/image-tag + instance-refresh; user_data reads
# it from SSM at boot). The tfvars var only fed terraform/main.tf's
# `deploy_frps ⇒ non-bootstrap frps_image_tag` precondition, so we resolve it at
# deploy time as TF_VAR_frps_image_tag from the sandbox-validated SSM tag in
# promote-to-prod.yml (mirroring qurl_image_tag) rather than baking a SHA here.
deploy_frps           = true
frps_az_suffixes      = ["a", "b", "c"]
frps_min_size         = 3
frps_max_size         = 3
frps_desired_capacity = 3

# qurl-service tunnel auth + active-registration reads. This is a consistent
# set enforced at plan time by terraform_data.qurl_tunnel_active_registration_preconditions:
# qurl_tunnel_active_registrations_enabled requires qurl_tunnel_auth_enabled +
# deploy_frps + qurl_router_enabled + enable_instance_hrw + MULTIVALUE — all
# satisfied here (qurl_router_enabled/enable_qurl_site_authz already true above).
qurl_tunnel_auth_enabled                            = true
qurl_tunnel_active_registrations_enabled            = true
enable_instance_hrw                                 = true
qurl_reverse_tunnel_server_cloud_map_routing_policy = "MULTIVALUE"

# Knock-token-as-identity auth on qurl-reverse-tunnel-server (sandbox parity).
qurl_reverse_tunnel_server_tunnel_auth_mode = "tunnel-auth"

# Customer-facing FRPS control-channel DNS. A non-empty value un-gates the AC
# NLB:7000 listener/TG/ASG-attachment + Traefik frps-control entrypoint and
# publishes connect.layerv.ai → AC NLB via connect_cross_account (cross-account
# into the layerv-mgmt layerv.ai zone). This is the customer-traffic gate.
#
# Pre-merge gate: eyeball the CI prod plan for exactly (1) connect_cross_account
# A-record Create into the mgmt zone, the AC NLB:7000 listener + TG + ASG
# attachment Creates, and NO `aws_autoscaling_group.frps` *replace* (the
# static-name + create_before_destroy invariant in terraform/CLAUDE.md).
# Post-apply on-call checks: `nc -zv connect.layerv.ai 7000` from outside the
# VPC; `layerv-nhp-prod-frps` ASG 3/3 healthy; registration heartbeats reaching
# qurl-service (see docs/runbooks/qurl-internal-v1-triage.md if dials fail).
connect_layerv_host = "connect.layerv.ai"

# ==============================================================================
# Agent-bootstrap knock flow + bootstrap-alb (prod)
# ==============================================================================
# Enables the qurl-service agent-bootstrap chain and the bootstrap-alb ingress
# that fronts bootstrap.layerv.ai. Consistent set enforced at plan time:
# enable_qurl_agent_bootstrap requires deploy_qurl_bootstrap_chain, which
# requires deploy_qurl_service (true above).
#
# bootstrap-alb runs the module's cross-account Path 1 (parent zone layerv.ai
# in layerv-mgmt) — operator runbook: terraform/modules/bootstrap-alb/README.md
# "Step 0 — cross-account cert + DNS". The ACM cert was operator-pre-provisioned
# (Step 0) and is attached via bootstrap_alb_existing_certificate_arn with
# provision_certificate=false + manage_dns_alias=false (the plan-time XOR cert
# gate accepts exactly this combination).
#
# REQUIRED POST-APPLY MANUAL STEP (Path 1, manage_dns_alias=false): write the
# bootstrap.layerv.ai A-alias → bootstrap-alb DNS name into the layerv-mgmt
# layerv.ai zone AFTER this apply (the alias targets the ALB DNS that only
# exists post-apply), and verify with `dig +short bootstrap.layerv.ai`
# returning the ALB DNS BEFORE the qurl-service rollout starts taking traffic.
# Until the alias resolves, bootstrap.layerv.ai is NXDOMAIN and ALL customer
# agent-bootstrap traffic is blocked. A clean re-apply re-requires both Step 0
# (cert) and this A-alias — they are operator-owned, not in TF.
deploy_qurl_bootstrap_chain = true
enable_qurl_agent_bootstrap = true

deploy_bootstrap_alb                       = true
bootstrap_alb_dns_name                     = "bootstrap.layerv.ai"
bootstrap_alb_provision_certificate        = false                                                                                 # Path 1: cert pre-provisioned cross-account
bootstrap_alb_manage_dns_alias             = false                                                                                 # Path 1: A-alias written out-of-band post-apply
bootstrap_alb_existing_certificate_arn     = "arn:aws:acm:us-east-2:235500187906:certificate/baf58cbf-b14d-454e-a13a-988a81594eb3" # bootstrap.layerv.ai, ISSUED (Step 0)
bootstrap_alb_elb_5xx_threshold_per_minute = 1

# WAF go-live watch period (count-only). Unlike sandbox's dark launch, this PR
# flips enable_qurl_agent_bootstrap=true simultaneously, so real customer agents
# can hit bootstrap.layerv.ai on day 1. Per var.bootstrap_alb_waf_count_only_rule_groups's
# guidance, bring both managed groups up count-only for the first 2–4 weeks —
# AnonymousIpList false-positives on customer VPN egress; CommonRuleSet (CRS)
# body-inspection false-positives on PEM-wrapped public keys. Flip to enforce
# after the watch period — tracked in #2238 (also covers populating
# bootstrap_alb_cross_account_subscriber_arns post-activation).
bootstrap_alb_waf_count_only_rule_groups = ["AWSManagedRulesAnonymousIpList", "AWSManagedRulesCommonRuleSet"]

# Interim alarm routing for go-live. Unlike sandbox's dark launch (where the
# bootstrap-alb alarms had nowhere to go ON PURPOSE), this PR activates real
# traffic with elb_5xx_threshold_per_minute=1 — so a 5xx alarm must reach a
# human on day 1 rather than publishing to a subscriber-less SNS topic. Until
# the durable alerts-infra cross-account ARN is wired
# (bootstrap_alb_cross_account_subscriber_arns, tracked in #2238), subscribe
# the same on-call addresses prod already uses (alert_emails above).
# NOTE: SNS email subscriptions are PENDING until each recipient clicks the
# confirmation link — these must be confirmed before the apply window or the
# alarm still goes unheard. Remove once #2238 wires the cross-account path.
bootstrap_alb_alarm_email_subscriptions = ["justin@layerv.ai", "benc@layerv.ai", "joe@layerv.ai"]

# QURL plugin configuration (NHP Server)
# Enables qurl.link → qurl.site authentication flow in NHP Server
# api_url points at the internal-ALB hostname (workload-account PHZ
# alias). NHP server is in private subnets and resolves the PHZ via the
# VPC Route 53 Resolver. The plugin only calls /internal/v1/*, which is
# exactly the surface served by the internal ALB. See qurl-service #335
# for the network-isolation rationale.
qurl_config = {
  enabled = true
  # TODO(#1605): qurl_config.api_url is free-form here but is required to
  # match the workload-account PHZ alias built from the soon-to-be-introduced
  # var.qurl_internal_service_domain. Once #1605 lands, this field is
  # derived in TF rather than hand-written, eliminating the configuration-
  # drift class that tests/smoke/08_qurl_api_url_internal_test.go fences.
  api_url                 = "https://internal-api.qurl.layerv.ai"
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
grafana_cloud_external_id    = null           # Not required - same Grafana Cloud stack
grafana_create_dashboards    = true

# ==============================================================================
# Status Page (B1)
# ==============================================================================
deploy_status_page         = true
status_page_domain         = "status.layerv.ai"
status_page_hosted_zone_id = "Z0748438C8EK6UAW94ST" # layerv.ai zone

# NHP Authentication (dogfooding) - protect status page with QURL
# To enable: 1) Create a QURL via API with target_url=https://status.layerv.ai
#            2) Set the QURL link URL below and enable auth
# status_page_nhp_auth_enabled  = true
# status_page_nhp_auth_qurl_url = "https://qurl.link/#at_REPLACE_WITH_TOKEN"

# Canary deployment
enable_canary_deployment = true

# QURL Redis rate limiting (B15)
# ElastiCache Serverless Redis for distributed rate limiting across ECS tasks.
# Cost: ~$0/month idle (serverless scales to zero when unused, pay per ECPU + storage)
deploy_redis = true

# Cost analytics (CUR 2.0 → Athena → Grafana)
# Cost analytics: disabled in prod because sandbox owns the shared backend
# (S3 bucket, Glue crawler, Athena workgroup) in the mgmt account. Enabling
# here would create duplicate resources. Both environments query the same
# consolidated CUR 2.0 billing data via the cross-account role below.
deploy_cost_analytics                 = false
cross_account_cost_analytics_role_arn = "arn:aws:iam::165115313779:role/nhp-cost-analytics-access"

# (qurl-reverse-tunnel-server per-AZ sizing + frps_az_suffixes now live in the
#  "FRPS-behind-AC / reverse-tunnel activation" block above, alongside the
#  deploy_frps flip — the env-root passthroughs this PR adds make them effective.)

# Athena config for Grafana cost dashboard — points to sandbox-deployed resources in mgmt account.
# These values come from sandbox's cost_analytics module outputs (terraform/modules/cost-analytics/outputs.tf).
# If sandbox's cost_analytics config changes (name_prefix, region, etc.), update these values to match.
grafana_athena_config = {
  assume_role_arn = "arn:aws:iam::165115313779:role/layerv-nhp-mgmt-grafana-athena"
  workgroup       = "layerv-nhp-mgmt-cost-analytics"
  database        = "layerv_nhp_mgmt_cost"
  region          = "us-east-1"
}

# ==============================================================================
# Billing Configuration
# Stripe billing — not yet enabled in production
#
# When enabling, use SSM parameters for Stripe price IDs instead of tfvars
# so prices can be updated without code changes:
#   billing_growth_price_id   → /${environment}/nhp/billing/growth-price-id
#   billing_base_fee_price_id → /${environment}/nhp/billing/base-fee-price-id
# ==============================================================================
deploy_billing = false

# ==============================================================================
# Developer Portal Configuration
# ==============================================================================
deploy_developer_portal                 = true
developer_portal_m2m_secret_name        = "layerv-nhp-prod-auth0-backend-credentials"
developer_portal_auth0_mgmt_secret_name = "layerv-nhp-prod/developer-portal/auth0-mgmt"
developer_portal_auth0_domain           = "auth.layerv.ai"
developer_portal_allowed_origins        = ["https://layerv.ai", "https://www.layerv.ai"]
developer_portal_custom_domain          = "devapi.layerv.ai"
developer_portal_hosted_zone_id         = "Z0748438C8EK6UAW94ST" # layerv.ai zone (in layerv-mgmt account)

# /playground/upload connector URL — prod S3 connector (the only one
# deployed today, also used by sandbox per layervai/nhp#2066).
developer_portal_connector_base_url = "https://getqurllink.layerv.ai"

# ==============================================================================
# Auth0 SPA Dashboard Configuration
# Website dashboard login for developers to manage API keys, usage, and billing
# ==============================================================================
enable_auth0_spa_dashboard = true
# Single Auth0 tenant shared across environments — custom domain is the same for sandbox and prod.
auth0_custom_domain = "auth.layerv.ai"

# Callback URLs: Auth0 redirects here after login
auth0_spa_callback_urls = [
  "https://layerv.ai/qurl/dashboard/callback/",
  "https://layerv.ai/api/auth/callback/",
]

# Logout URLs: Auth0 redirects here after logout
auth0_spa_logout_urls = [
  "https://layerv.ai",
  "https://layerv.ai/qurl/dashboard/",
]

# Web origins: allowed for CORS and silent authentication
auth0_spa_web_origins = [
  "https://layerv.ai",
]

# Social connections (Google + GitHub) for developer login
# OAuth credentials are passed via TF_VAR_* environment variables
# Store in GitHub Secrets: GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET,
#                          GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET

# Custom domain certificate manager — provisions Let's Encrypt certs for
# customer custom domains registered via the QURL API.
deploy_custom_domain_cert = true

# qurl-integrations-infra cross-account DNS. See main.tf QURL
# Integrations DNS section for rationale.
#
# EIPs sourced 2026-04-23 from the integrations-prod account via
# `aws ec2 describe-addresses`. EIPs are stable across instance
# replacement; if ever intentionally reallocated, update here and
# re-apply in coordination with a qurl-integrations-infra PR (see
# the subdomain-takeover note in main.tf and issue #247).
deploy_qurl_integrations_dns = true
qurl_s3_connector_domain     = "getqurllink.layerv.ai"
qurl_s3_connector_eip        = "3.132.101.16"
qurl_fileviewer_domain       = "fileviewer.layerv.ai"
qurl_fileviewer_eip          = "3.13.11.40"

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
