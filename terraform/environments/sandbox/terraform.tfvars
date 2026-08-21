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
ac_auth_service_id = "agent"
ac_min_capacity    = 3
ac_filter_mode     = 1
# L3 flush-on-expiry sandbox rollout levers. Sandbox remains on
# FilterMode=EBPFXDP, so enabled L3 flush uses BpfFlusher; the conntrack backend
# knob is only load-bearing under FilterMode=IPTABLES.
enable_l3_flush_on_expiry    = true
l3_flush_dry_run             = false
l3_flush_conntrack_backend   = "exec"
l3_flush_conntrack_pool_size = 0
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

# qURL v2 immediate-revocation proof engine (#2793). ACK support is now in the
# AC/server protocol; keep this enabled so NHP_REV retries until every targeted
# AC slot ACKs or ages out to RevocationAgedOut.
nhp_revocation_retry_enabled          = true
nhp_revocation_retry_interval_seconds = 5
nhp_revocation_retry_age_out_seconds  = 60

# Termination cleanup: Lambda cleans stale DynamoDB assignments on server termination
enable_termination_cleanup = true

# Secret reconciliation: Lambda cleans orphaned per-instance AC secrets daily
enable_secret_reconciliation = true
# auth_url, auth_signing_key, and auth_aes_key are passed via GitHub Secrets (TF_VAR_*)

# Slack notifications via AWS Chatbot.
#
# slack_workspace_id and slack_channel_id are documentation-only while
# chatbot_owned_externally = true — local.enable_slack short-circuits and
# nothing here actually wires them to a Chatbot config. They mirror the
# (workspace, channel) pair alerts-infra owns; keep in sync with the
# alerts-infra-side `sandbox-alerts-sandbox` module if either side rotates.
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C0A9S0VCAU9" # #alerts-sandbox

# The (T09UP622L90, C0A9S0VCAU9) Chatbot config is owned by alerts-infra's
# `sandbox-alerts-sandbox` module (the org-wide AWS Chatbot home, per
# alerts-infra CLAUDE.md), which subscribes our `module.monitoring.sns_topic_arn`
# alongside `bootstrap-alb-sandbox-alerts`. NHP terraform skips creating its
# own Chatbot config here so the account-wide (workspace, channel) uniqueness
# constraint stays satisfied.
#
# OPERATOR NOTE: the sandbox apply after this lands will plan a destroy on
# `module.monitoring.aws_chatbot_slack_channel_configuration.alerts[0]` and
# the dedicated IAM role/policy. Sequence: this NHP PR merges + applies first
# (destroying the in-module config), then alerts-infra PR #22 merges +
# applies (creating the replacement). Between the two applies, sandbox
# alarms queue in the SNS topic but don't reach Slack — short, expected,
# acceptable; no Slack delivery during the gap. Operator should post a
# heads-up in `#alerts-sandbox` before kicking off the first apply so
# whoever's on-call knows the channel is briefly silent.
chatbot_owned_externally = true

# GuardDuty security alerts (email + Slack via same SNS topic).
# security@layerv.ai is the canonical, non-personal destination (see #2334);
# the individual addresses are kept as redundant delivery. Each new address must
# confirm its SNS subscription via the email link before it receives findings.
guardduty_alert_emails = [
  "security@layerv.ai",
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
# Keys must match the moduleName in plugins-local/src/{key}/ for Traefik's
# local plugin resolution. Today only qurl-router lives here; the older
# hqdatamiddleware shipped to S3 but was never wired into any router's
# middleware chain (refresh-bypass investigation, see qurl-service #514 and
# traefik-plugins #146 for the supersession story). Removed in the same PR
# as the plugin source deletion per the AC Plugin Source-of-Truth Invariant
# in CLAUDE.md.
traefik_plugins = {
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

# Wave 5 — sandbox-only opt-in to the qurl-service ↔ nhp-server agent
# bootstrap chain. When true, the qurl-service ECS task def gains four
# TF-injected env vars (NHP_SERVER_PUBLIC_KEY_B64, NHP_SERVER_HOST,
# NHP_SERVER_PORT, QURL_AGENT_BOOTSTRAP_ENABLED) alongside the existing
# NHP_SERVER_INTERNAL_URL — no runtime SSM fetch, no new IAM grants.
# `enable_qurl_agent_bootstrap` is the per-env activation flip:
# flipped to true here to begin Wave 5 activation in sandbox. Prod
# tfvars deliberately omits both until sandbox burn-in lands.
deploy_qurl_bootstrap_chain = true
enable_qurl_agent_bootstrap = true
retire_http_agent_lifecycle = true

# qurl-scanner Lambda — sandbox second-apply of the two-apply rollout
# documented in the prod-rollout ledger entry for #2326. First apply
# (gated on `deploy_qurl_service = true` above) created the
# `layerv/qurl-scanner-lambda` ECR repo + the
# `/layerv-nhp-sandbox/qurl-scanner-lambda-image-tag` SSM param; qurl-service
# CI has published its first image and the SSM param carries a real SHA.
# This flag-on apply creates the Lambda function itself + the EventBridge
# 1-minute cron + the `qurl-scanner-invocation-gap` alarm. Lambda boots in
# log-only mode (no `EMIT_MODE` env var, no `--allow-prod-emit`) — it scans
# the time-bucket-index GSI and slog-logs what it would have emitted, with
# no SQS / no downstream webhook fan-out yet. SQS activation is a separate
# downstream PR gated on qurl-service SQS queue infra + consumer dedupe.
# Rollback: flip to `false` and re-apply (destroys Lambda + cron + alarm;
# leaves ECR repo + SSM param). Prod tfvars deliberately omits this until
# the HARD PROD preconditions in the #2326 ledger entry are met.
qurl_scanner_lambda_enabled = true

# Activation flag — flips scanner Lambda emit mode (log-only → sqs)
# AND the qurl-api consumer goroutine (dormant → draining) on the
# resource-lifecycle queue. See
# `modules/qurl-service/variables.tf::qurl_scanner_sqs_emit_enabled`
# for the full rationale (ordering / rollback de-atomization risk /
# operator gates).
#
# Gate met 2026-06-12: qurl-service main is pinned at 7791fcc
# (`fix(ci): publish scanner lambda image without attestations (#914)`),
# the SSM-tracked `/layerv-nhp-sandbox/qurl-api-image-tag` carries that
# SHA, and the qurl-api ECS deployment under
# `layerv-nhp-sandbox-cell0-qurl-api` completed cleanly with zero failed
# tasks at 2026-06-12T00:53Z. Operator-verified healthy → flipping the
# data-path on.
#
# On merge, build-and-push.yml auto-applies the `terraform/**` change
# on push to main, which:
#   1. Updates the scanner Lambda env to `QURL_SCANNER_EMIT_MODE=sqs` +
#      `QURL_SCANNER_SQS_QUEUE_URL=<resource_lifecycle_queue.url>` —
#      next 1-min EventBridge tick emits to SQS.
#   2. Rolls the qurl-api ECS task def to add
#      `WEBHOOK_EVENTS_CONSUMER_ENABLED=true` +
#      `WEBHOOK_EVENTS_SQS_QUEUE_URL=<same URL>` — consumer goroutine
#      wakes and starts draining.
#
# Ordering note: the Lambda env update and the ECS task-def revision
# are independent resources in the Terraform graph, but in wall-clock
# the Lambda env applies near-instantly while the ECS rolling deploy
# takes minutes — so producer effectively flips ahead of consumer. A
# short window where the scanner emits to SQS before the consumer is
# draining is harmless: the main `resource_lifecycle` queue retains
# `message_retention_seconds = 345600` (4 days), well past the
# minutes-scale ECS roll. Per `modules/qurl-service/resource_lifecycle_queue.tf`
# the 4-day bound is "long enough for an ops incident to investigate,
# short enough that any logical-bug leak evaporates" — the matching DLQ
# carries 14d for forensic triage past the long weekend.
#
# Rollback: flip back to `false` and re-apply. Lambda goes log-only,
# main queue retains buffered messages until 4d retention reaps them
# (14d for the DLQ if the consumer fails 3× redeliveries first).
qurl_scanner_sqs_emit_enabled = true

# Destructive scanner tombstone-write phase — flips the scanner Lambda
# env to `QURL_SCANNER_ENABLE_TOMBSTONE_WRITE=true` so the per-minute
# scan, after emitting `resource.closed`, also writes the qurl-service
# DDB tombstone (`resource_tombstoned_at` / `tombstone_ttl`). That
# tombstone is what makes a re-mint to a closed transit resource return
# 410 Gone instead of silently re-opening it. See
# `modules/qurl-service/variables.tf::qurl_scanner_tombstone_write_enabled`
# and issue #2490 for the full chain.
#
# Requires `qurl_scanner_sqs_emit_enabled = true` (above) — enforced by
# the module precondition in `modules/qurl-service/main.tf`: tombstoning
# without the SQS consumer draining `resource.closed` would flip
# resources to 410-Gone before the connector/bot cleanup ran.
#
# Gate met 2026-06-14: #2489 activated the SQS data path on 2026-06-12,
# and the ~2-day burn-in is clean (sandbox, us-east-2):
#   * scanner Lambda `Errors` = 0 across 2026-06-12 → 2026-06-14
#   * scanner Lambda `Invocations` ≈ 1440/day (steady 1-per-minute tick)
#   * `*-qurl-resource-lifecycle` queue `NumberOfMessagesSent` ==
#     `NumberOfMessagesDeleted` each day (consumer fully draining)
#   * main queue + `*-qurl-resource-lifecycle-dlq` both at depth 0
# No DLQ accumulation, no errored ticks → the emit/consumer path the
# tombstone write rides on is healthy. (`tombstone_errors` can't exist
# yet — this flag is what first turns tombstone writes on.)
#
# On merge, build-and-push.yml auto-applies the `terraform/**` change on
# push to main. This flag's only effect is the scanner Lambda env-var
# add — no IAM, no new resources (the DDB grants landed with the
# Lambda). The next 1-minute EventBridge tick begins writing tombstones
# for resources it closes.
#
# Rollback is NOT fully reversible. Flipping back to `false` and
# re-applying removes the env var so the scanner stops writing NEW
# tombstones, but resources already tombstoned during the active window
# stay tombstoned (the write is a durable DDB mutation with its own
# `tombstone_ttl`; it is not un-done by removing the env var). Treat
# re-mint-returns-410 as the expected, intended steady state once this
# is on.
#
# Prod tfvars deliberately omits this var (defaults false) — prod
# activation rides a separate follow-up after the sandbox e2e 410
# verification, the #2326 HARD PROD preconditions, and #2491 (SNS alarm
# wiring) all clear.
qurl_scanner_tombstone_write_enabled = true

# Hourly active-resource recheck scheduler. Stays false until the
# per-minute tombstone-write phase above has burned in and qurl-service
# #919 hard gates confirm the broad status-index sweep fits the cell.
qurl_scanner_active_recheck_enabled = false

# Domain configuration for QURL API
# Certificate is created automatically via Terraform when domain is set
qurl_service_domain = "api.layerv.xyz"
qurl_hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone

# Internal ALB hostname (qurl-service #335 network isolation).
# Served on a workload-account private hosted zone; external resolvers
# return NXDOMAIN. Cert validation CNAME publishes on the public mgmt
# zone (qurl_hosted_zone_id above) but no public A record exists.
qurl_internal_service_domain = "internal-api.qurl.layerv.xyz"

# Stage-2 of the rollout: when true, removes the in-VPC bypass on the
# qurl-service ECS-task SG. Apply with false first (creates internal
# ALB, leaves bypass), verify the new path, then flip to true and
# re-apply to close the bypass. Plan: PR1's sub-step 1B.
qurl_enforce_internal_alb_only = false

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

# Connector-auth feature gate (qurl-service PR #277). Flipping this to true
# wires CONNECTOR_AUTH_ENABLED=true into the qurl-service ECS task, which:
#   - mounts POST /internal/v1/tunnel/auth (consumed by qurl-reverse-tunnel-server's httpPlugin)
#   - allows POST /v1/qurls and POST /v1/resources to accept type=tunnel
# Pre-req for the qurl-reverse-tunnel-server deploy (deploy_frps=true) to actually serve
# tunnels — without it, FRPS clients would 404 on Login/NewProxy.
qurl_connector_auth_enabled = true

# Active-registration reads are authoritative in sandbox: qurl-reverse-tunnel-
# server publishes per-instance targets, and qurl-router consumes them through
# discovery/HRW so qurl.site reaches the FRPS instance the sidecar registered on.
qurl_connector_active_registrations_enabled = true

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

# FRPS-behind-AC customer-facing DNS (SLACK_QURL_ROLLOUT.md §6, 2026-05-18).
# Public DNS name written into the DDB seed row's `resource_fqdn` field;
# the bridge materializes that as `ResourceInfo.Hostname` and that's the
# agent's dial target. A-record alias to the AC NLB created in
# `terraform/main.tf::aws_route53_record.connect`. Sandbox uses the
# in-account `layerv.xyz` zone (no cross-account provider alias).
connect_layerv_host = "connect.layerv.xyz"

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
# qurl-reverse-tunnel-server (per-AZ tunnel routing)
# ==============================================================================
# Multi-AZ ASG sizing for the per-AZ qurl-reverse-tunnel-server fleet (#1499).
# qurl-service hashes OwnerID to one of frps_az_suffixes and emits the matching
# DNS name as `frps_addr` in API responses, so frpc and qurl-router converge on
# the same instance. The ASG runs at desired = 3 (one instance per AZ); each
# instance reads its AZ from IMDS at boot and registers with the matching
# Cloud Map service. Module defaults remain 1/1/1 so the module can still
# be consumed in isolation; the override here is what flips on multi-AZ.
#
# Sandbox is the first env to flip `deploy_frps = true`. The structural
# risks (single-ASG distribution skew, intra-fleet AZ-empty NXDOMAIN) and
# the alarm-coverage gaps that motivate the per-AZ refactor + #1542
# detection alarm are documented in the long-form comment in
# `modules/qurl-reverse-tunnel-server/main.tf` above `aws_autoscaling_group.frps`. The
# cross-repo gating list (qurl-service, traefik-plugins, frpc, etc.) lives
# in the PR description for #1544 — it's release-time coordination, not
# an invariant worth duplicating here.
#
# ===== Apply-gate (FRPS-behind-AC, nhp #1977 / SLACK_QURL_ROLLOUT.md §6) =====
#
# `connect_layerv_host = "connect.layerv.xyz"` above wires the FRPS-
# behind-AC topology on sandbox (AC NLB:7000 + Traefik TCP forwarder +
# AC kernel ipset gate). Do NOT `terraform apply` this env while
# `connect_layerv_host` is set to a non-empty value until the
# following are all true:
#
#   1. qurl-reverse-tunnel-server #98 (knock-token validation at
#      FRP-Login via nhp-server `/token/validate`) is MERGED.
#   2. qurl-reverse-tunnel-server #98 is DEPLOYED to sandbox FRPS
#      with `LAYERV_REQUIRE_KNOCK=true` flipped on. Without #98 +
#      require-knock the system runs with the ipset source-IP pre-
#      filter as the only fence — the inverse of the security posture
#      (the per-client X25519 key-authenticated knock + knock-token
#      validation chain is the PRIMARY access control; ipset is
#      coarse and exists because the AC is in the data plane FOR NOW,
#      per nhp #2019).
#
# Post-apply live regression fence: from outside the VPC,
# `nc -zv connect.layerv.xyz 7000` MUST hang/timeout pre-knock and
# succeed within ~1s post-knock. CloudWatch: AC INPUT-chain DROP
# counter for dport=7000 spikes pre-knock, drops to zero post-knock.
#
# To OPT OUT of the FRPS-behind-AC topology for sandbox (e.g. revert
# during incident triage), set `connect_layerv_host = ""` above. All
# `count`-gated new resources (Route 53 records, AC NLB:7000 listener
# + TG + ASG attachment + SG ingress, Traefik entrypoint + dynamic
# router) collapse to zero in lockstep — sandbox returns to the
# pre-PR topology with no manual cleanup needed.
deploy_frps = true
# Pinned at the env level (matches the module default in
# `terraform/variables.tf`) so a future default change can't silently
# flip sandbox onto a different suffix set — the OwnerID-hash ↔
# frps-${suffix}.${namespace} mapping must stay stable across
# qurl-service, frpc, and traefik-plugins.
frps_az_suffixes      = ["a", "b", "c"]
frps_min_size         = 3
frps_max_size         = 3
frps_desired_capacity = 3

# Active registrations publish per-instance private FRP vhost origins
# (http://<instance-private-ip>:8080). qurl-router accepts those only via
# discovery, so sandbox turns on instance discovery before the qurl-service
# active-read flag is flipped.
qurl_reverse_tunnel_server_cloud_map_routing_policy = "MULTIVALUE"
enable_instance_hrw                                 = true

# Current qURL Connectors register FRP with the API-issued c-* routing
# identity. Keep the router on the same identity so r_* qURL hosts reach the
# admitted proxy instead of being forwarded to FRP under the legacy r_* host.
require_connector_routing_id = true

# Opt sandbox into knock-token-as-identity auth on qurl-reverse-tunnel-server.
# See `terraform/variables.tf::qurl_reverse_tunnel_server_tunnel_auth_mode`
# for the mode semantics, cross-repo prereqs, and per-mode env shape.
qurl_reverse_tunnel_server_tunnel_auth_mode = "tunnel-auth"

# ==============================================================================
# QURL Plugin Configuration (NHP Server)
# Enables qurl.link.layerv.xyz → qurl.site.layerv.xyz authentication flow in NHP Server
# ==============================================================================
# QURL plugin handles qurl.link relay bootstrap and steady-state re-knock
# authorization. In sandbox, browsers reach it through the JS agent + relay;
# qurl-service is called only from NHP over the internal API.
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
  api_url                 = "https://internal-api.qurl.layerv.xyz"
  allowed_redirect_domain = "qurl.site.layerv.xyz"
  api_timeout             = 10
  max_idle_conns          = 10
  max_idle_conns_per_host = 5
  idle_conn_timeout       = 30
}

# ==================== qURL v2 (keyed identity) — sandbox ====================
# FULLY ENABLED (all flags on). The enable was staged across two applies —
# admission + resource_keys first, then issuance — because qurl-api's fast ECS
# deploy would otherwise mint v2 before the ~20-min server blue/green loaded the
# issuer into its trust store (a dead-link window). Full rollout + prod sequence +
# rollback: docs/runbooks/prod-rollout-ledger/2026-07-01-qurl-v2-issuer-infra.md
#
# resource_keys=true depends on the exhaustive CMK-deny in #2990, risk-accepted for
# sandbox. Preconditions (terraform_data.qurl_v2_flag_invariants) enforce the shape:
# issuance ⇒ issuer_key + resource_keys + admission + relay_url;
# admission ⇒ issuer_key + kid; issuer_key ⇒ relay_allowlist.
# Rollback: set issuance=false (createQurl reverts to v1); the rest can stay on.
qurl_v2_issuer_key_enabled    = true
qurl_v2_resource_keys_enabled = true
# Software custody is the DEFAULT for unentitled owners (cost decision
# 2026-07-09: per-resource CMKs at ~$1/mo each were the dominant KMS spend —
# software custody mints zero CMKs). Ships ON: the software path goes live at
# the first deploy of the custody-aware qurl-service image. Hardware (KMS) is
# per-customer opt-in via CustomerInfo.HardwareKeyStorage. Prod flips together
# with qv2 prod enablement (resource keys are off there; the flag-invariant
# precondition rejects ramp-on without them).
qurl_v2_resource_key_software_default = true
# Periodic reaper: keeps the per-resource CMK population converged with live
# resources (one-time backlog sweep executed 2026-07-09; the reaper prevents
# regrowth from test churn until the software-custody ramp flips).
qurl_v2_resource_key_reaper_enabled = true
qurl_v2_issuance_enabled            = true
qurl_v2_admission_enabled           = true
qurl_v2_issuer_kid                  = "qurl-issuer-sandbox-2026-07"
qurl_v2_relay_url                   = "https://relay.qurl.link.layerv.xyz"
qurl_v2_relay_allowlist             = "relay.qurl.link.layerv.xyz"

# Uses same secret as QURL service for internal API auth
qurl_service_token_secret_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox/qurl-internal-service-token-XgjoDM"

# ==============================================================================
# Agent registration + email OTP (T1) — SANDBOX: ON (PATH A + PATH B)
# ==============================================================================
# Both enrollment paths are ON in sandbox: PATH A (agent_registration_enabled) and
# PATH B (agent_otp_enabled + agent_otp_registration_enabled). Enabled after prod
# launch burn-in (this block previously held sandbox dark under a "prod leads,
# sandbox validates" posture).
#
# ⚠️  MERGE ≈ SANDBOX GO-LIVE — there is no separate flip step. build-and-push runs
# `terraform apply` to sandbox on main-push, so the first apply after this merges
# (INCLUDING one triggered by an unrelated image bump) activates BOTH paths at once:
# NHP agent registration AND OTP email via SES from the notify.layerv.xyz sender to
# real recipients. The two usual OTP gates are already handled for sandbox:
#   1. PEPPER — auto-seeded on apply by terraform_data.agent_otp_pepper_seed
#      (get-random-password 48 chars → put-secret-value; the value never enters TF
#      state). No manual seed needed; an operator MAY hand-populate instead (ledger
#      step c), but it is optional.
#   2. SES — the sandbox account already has SES production access
#      (ProductionAccessEnabled + SendingEnabled + HEALTHY in us-east-2, confirmed
#      2026-07-11), so OTP reaches any recipient. The notify.layerv.xyz identity +
#      DKIM + MAIL FROM are created by TF in the layerv.xyz zone (hosted_zone above,
#      same-account) and verify a few minutes after apply.
# Remaining human step: an operator watching -agent-otp-send-failed-spike /
# -agent-otp-bounce on first real traffic. TF preconditions (main.tf) check only
# flag COHERENCE, not SES/DNS — but both gates above are already satisfied.
#
# The flip injects QURL_AGENT_REGISTRATION_ENABLED / QURL_AGENT_OTP_ENABLED /
# QURL_AGENT_OTP_EMAIL_FROM / QURL_NHP_RELAY_BASE_URL + QURL_AGENT_OTP_PEPPER on the
# qurl-service task def, renders AGENT_OTP_REGISTRATION_ENABLED into nhp-server
# user_data (~20-min fleet blue/green), and CREATES the SES identity + DKIM/MAIL
# FROM DNS + config set + the pepper secret + the task-role SES grant.
#
# Values: agent_otp_email_from → SES domain identity notify.layerv.xyz (sender
# domain = part after @). agent_registration_relay_base_url → the LIVE sandbox relay
# (deploy_relay = true below → relay.qurl.link.layerv.xyz), so unlike prod's dark
# relay, registration points clients at a reachable relay.
agent_registration_enabled        = true
agent_otp_enabled                 = true
agent_otp_registration_enabled    = true
agent_otp_email_from              = "noreply@notify.layerv.xyz"
agent_registration_relay_base_url = "https://relay.qurl.link.layerv.xyz"

# Lets qurl-service's per-PR live-email gate send a real message through real
# SES as noreply@notify.layerv.xyz (recipient is always the AWS mailbox
# simulator, so nothing reaches a real inbox). Sandbox only — the fence in
# agent_otp_ses.tf fails the plan if this is ever set in prod.
agent_otp_ci_send_gate_enabled = true

# Receive mailbox for qurl-go's OTP gate: SES accepts mail for
# otp-gate@ci-otp.notify.layerv.xyz (a dedicated subdomain with its own MX --
# notify.layerv.xyz itself is untouched), stores it to S3, and notifies SQS so
# CI can read the emailed code. The mailbox role admits only qurl-go's
# pull_request subject and exact refs/heads/main subject. Sandbox only; the fence in
# agent_otp_ci_mailbox.tf fails the plan if this is ever set in prod.
#
# OWNERSHIP NOTE: enabling this makes THIS ROOT the owner of the sandbox
# account's SES active receipt rule set, which is a per-region singleton. It
# was empty when this landed. If any other inbound-mail configuration is ever
# added to this account and region, the two applies will fight over that one
# active set, each re-asserting its own on every run. Route new inbound mail
# through additional rules in THIS set rather than a second set.
agent_otp_ci_mailbox_enabled = true

# ==============================================================================
# QURL Link Redirect Page
# Hosts the redirect page that extracts tokens and sends users to NHP Server
# ==============================================================================
deploy_qurl_link          = true
qurl_link_frontend_domain = "qurl.link.layerv.xyz"
qurl_link_hosted_zone_id  = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)
qurl_link_external_dns    = false
# #2208/#2680 sandbox cutover: serve the browser NHP agent bundle from the same
# qurl.link origin, render relay bootstrap config into the verifier, and disable
# the public resolve endpoint so browser ingress is relay-only.
qurl_link_js_agent_enabled = true

# Legacy resolve CloudFront toggle. Inert while qurl_link_js_agent_enabled=true
# because the root module disables resolve ingress for the JS-agent flow.
enable_resolve_cloudfront = true

# Resolve WAF: run the Amazon IP-reputation rule in COUNT (observe, don't block).
# See prod tfvars / docs/runbooks/prod-rollout-ledger/README.md for rationale; flip
# to true to restore blocking.
resolve_waf_ip_reputation_block = false

# Keep resolve WAF logging on (explicit, mirroring prod) so the count-mode
# IP-reputation rule stays observable.
enable_resolve_waf_logging = true

# CloudFront access logging (v2 -> S3) for the resolve distribution (#1799),
# mirroring prod. Sandbox applies first, so it validates the delivery wiring +
# the new CI IAM grant before prod. Delivered fields omit cs-uri-query, so the
# ?token= credential is never logged. Set false to disable.
enable_resolve_access_logs = true

# ==============================================================================
# QURL Router Plugin Configuration
# Traefik plugin that routes *.qurl.site.layerv.xyz requests to target backends
# Requires QURL Service to be deployed (deploy_qurl_service = true)
# ==============================================================================
# Enable QURL Router when QURL Service is deployed and internal_service_token is configured
qurl_router_enabled = true

# L7 per-session authz gate on *.qurl.site. Activates at the NEXT
# AC instance refresh after apply (not at terraform apply itself —
# the AC ASG has no instance_refresh{} block on purpose). The
# blue/green deploy workflow is what drives the refresh in sandbox.
# See `var.enable_qurl_site_authz` for the full description.
enable_qurl_site_authz = true

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
# Public status page at status.layerv.xyz
# ==============================================================================
deploy_status_page         = true
status_page_domain         = "status.layerv.xyz"
status_page_hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone

# Extra public components on the status page (component id => health URL).
# qURL API + qURL link checks are wired automatically from their domains.
status_page_additional_service_urls = {
  website = "https://staging.layerv.ai/"
}
status_page_display_only_component_ids = ["website"]

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

# /playground/upload connector URL. Currently points at the SAME
# connector as prod because no separate sandbox connector is deployed
# (tracked in layervai/nhp#2066). Setting it explicitly here rather
# than via a module default so a future sandbox connector stand-up is
# a one-line tfvars change, not a code change.
developer_portal_connector_base_url = "https://getqurllink.layerv.ai"

# ==============================================================================
# Auth0 SPA Dashboard Configuration
# Website dashboard login for developers to manage API keys, usage, and billing
# ==============================================================================
enable_auth0_spa_dashboard = true
# Single Auth0 tenant shared across environments — custom domain is the same for sandbox and prod.
auth0_custom_domain = "auth.layerv.ai"

# Callback URLs: Auth0 redirects here after login
# Include staging site + localhost for development

# Logout URLs: Auth0 redirects here after logout

# Web origins: allowed for CORS and silent authentication

# ==============================================================================
# Auth0 Slack OAuth Configuration
# qurl-bot-slack workspace-install handshake (per SLACK_QURL_ROLLOUT.md Wave 1).
# Callback URL is derived in `main.tf` from `local.slack_bot_domain`
# (`qurl_bot_dns.tf:36`) + the fixed `/oauth/qurl/callback` path — single
# source of truth, no callback override at the env level.
# ==============================================================================
enable_auth0_slack_oauth_client = true

# ==============================================================================
# Auth0 client IDs (#3284)
# ==============================================================================
# Tenant configuration lives in the Auth0 dashboard; Terraform no longer manages
# it (see modules/auth0/removed.tf). These IDs are inputs to the AWS resources
# that publish/reference them. Public identifiers, not secrets — client secrets
# are put straight into Secrets Manager by an operator.
#
# Read them from the Auth0 dashboard (Applications > <app> > Settings) or:
#   GET https://layerv.us.auth0.com/api/v2/clients?fields=client_id,name
auth0_backend_service_client_id = "vLkOiUhRTtO87D4DReZ7J1030kJsdYbC" # Website Playground (sandbox)
auth0_smoke_test_client_id      = "5hUGQ5Y6JsoUdzNDvtjAhuJK5aRVhABB" # Smoke Test (sandbox)
auth0_spa_dashboard_client_id   = "fhtppYPLcNmItML0QmxGdOihFKU1UgiA" # QURL Dashboard (sandbox)
auth0_slack_oauth_client_id     = "DOnL3bpEHhXEi49YBeDdiXoE22ArZGzw" # qurl-bot-slack (sandbox)

# ==============================================================================
# E2E Testing
# Echo server Lambda for QURL E2E integration tests
# ==============================================================================
deploy_e2e_echo_server = true

# ==============================================================================
# Bootstrap ALB — tunnel-client sidecar cold-start path
# ==============================================================================
# Public HTTPS surface at `bootstrap.layerv.xyz` that the qurl-reverse-tunnel-
# client sidecar calls on first boot to exchange its bootstrap code for the
# per-agent QURL API key + frps_addr. Sandbox provisions + validates the ACM
# cert in-account (the `layerv.xyz` parent zone lives here in `767397897469`),
# so both `provision_certificate` and `manage_dns_alias` are true. Prod
# (`bootstrap.layerv.ai`) is cross-account and tracked separately
# (SLACK_QURL_ROLLOUT.md §5b — needs Justin's `layerv-mgmt` consent).
#
# First apply is CI-clean. `aws_route53_record.cert_validation`'s
# `for_each` keys on the static `var.dns_name` (plan-time known),
# so the cold-start fence that used to require an operator-laptop
# targeted apply is gone. The module-level README's DEPRECATED
# §Step 0a preserves the historical recovery context only.
#
# `bootstrap_alb_cross_account_subscriber_arns` is deliberately omitted (empty
# default) for this first flip. Per the var description: populating it now
# would page alerts-infra during the dark-launch window between this PR and
# the paired data-plane (qurl-service /v1/agent/bootstrap) PR — every 503
# probe would route. Wire alerts-infra in a separate follow-up after the
# data plane is healthy.
deploy_bootstrap_alb                = false
bootstrap_alb_dns_name              = "bootstrap.layerv.xyz"
bootstrap_alb_route53_zone_id       = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)
bootstrap_alb_provision_certificate = true
bootstrap_alb_manage_dns_alias      = true
# `bootstrap_alb_existing_certificate_arn` deliberately left at its
# default ("") — Path 2 (same-account, module-managed cert) requires
# it empty (see root `check "bootstrap_alb_required_variables"` XOR
# in `terraform/main.tf`). Adding an ARN here during a future cert
# rotation would fail plan (XOR check prints a warning + the
# listener-side precondition in `modules/bootstrap-alb/alb.tf`
# rejects the both-set combo) — go through the module's rotation
# path instead.

# Tighten ELB-side 5xx alarm threshold after the data plane is wired
# (nhp PR #2082 closed the empty-TG outage; qurl-service PRs #683 +
# #697 routed bootstrap.layerv.xyz through the validator end-to-end).
# The module-side default of 10/min is dark-launch-friendly (tolerates
# the noise from every probe getting 503 on an empty target group);
# the variable's own description in `modules/bootstrap-alb/variables.tf`
# explicitly calls out that env tfvars SHOULD override to 1 once the
# data plane is live, since any ALB-side 5xx is then the outage signal.
# Closes #2084.
bootstrap_alb_elb_5xx_threshold_per_minute = 1

# Count-only AWSManagedRulesAmazonIpReputationList: its IP-reputation sub-rules
# categorically false-positive on cloud / hosting / datacenter source IPs —
# both the live-sandbox connector smoke run from GitHub-hosted (Azure) runners
# (layervai/qurl-connector#347) and real cloud-deployed connector sidecars —
# 403'ing them at the ALB with no qurl-service log entry. This mirrors the
# qurl_resolve edge WAF, which already counts this exact rule for the same
# public-edge false-positive (see aws_wafv2_web_acl.qurl_resolve in
# terraform/main.tf). The load-bearing defenses still enforce: the per-API-key
# bootstrap rate limit (10/hr, in qurl-service) and the per-source-IP WAF
# rate-limit rule. HostingProviderIPList (the AnonymousIpList cloud sub-rule) is
# separately count-only'd via the bootstrap-alb module's rule_action_override
# (nhp #2604).
#
# AnonymousIpList + CommonRuleSet stay at full enforce here; their separate
# count-only watch-period flip (customer-VPN-egress / PEM-body CRS
# false-positives) remains tracked at nhp #1982.
bootstrap_alb_waf_count_only_rule_groups = ["AWSManagedRulesAmazonIpReputationList"]

# ── NHP-Relay (#2208 Phase-2 #5) — sandbox dark launch ──
# Autoscaling internet-facing relay fleet (one instance per AZ) fronting
# relay.qurl.link.layerv.xyz, forwarding browser knocks to the cells' internal
# server endpoints. One-per-AZ in sandbox is deliberate (validates the multi-instance
# fleet + per the one-per-AZ directive), accepting the dark-launch cost of N
# inert instances until #6. Ships DARK: until 5c (#2627) registers the relay
# pubkey in the server's relay.toml AND sets DisableRelayPeerValidation=true,
# every POST /relay/{id} is rejected at the server's Noise layer (504) — the
# surface is internet-reachable but cannot pivot into the private network. relay.qurl.link.layerv.xyz
# is a subdomain of the layerv.xyz zone (same account → Path 2: the module
# provisions the regional ACM cert + writes the A-alias). The CI deploy leg
# (SSM image-tag update + ASG refresh) and the rightmost-XFF relay-code fix are
# tracked follow-ups (both #6 blockers). `relay_existing_certificate_arn` stays
# empty (Path 2 requires it).
deploy_relay                = true
relay_vpc_cidr              = "10.101.0.0/16"
relay_dns_name              = "relay.qurl.link.layerv.xyz"
relay_route53_zone_id       = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)
relay_provision_certificate = true
relay_manage_dns_alias      = true

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}

# Identity plane: read accounts and credentials from Control, not this cell.
#
# The Connector Authority is global -- it validates enrollment credentials for
# every cell -- so it reads only the Control namespace. While this cell kept its
# own accounts and API keys, a perfectly valid customer key was invisible to the
# Authority and every native enrollment answered credential_invalid.
#
# The identity rows (1141 API keys, 15 customers, 993 agent keys) were copied to
# Control and each one verified field-by-field BEFORE this was set. Order
# matters: setting it first would point every existing customer at an empty
# namespace.
control_identity_environment_id = "sandbox"
control_identity_home_region    = "us-east-2"
# The Control tables are encrypted with the Connector Authority key, which is
# NOT this cell's DynamoDB key. Without decrypt on it the service boots fine and
# then every API-key lookup returns AccessDeniedException as a 500.
control_identity_kms_key_arn = "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee"
