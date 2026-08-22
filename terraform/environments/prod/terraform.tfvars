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
ac_resource_ids = ["qurl", "qurl-tunnel-server"]
ac_min_capacity = 3
ac_max_capacity = 10
# eBPF/XDP datapath (E5 flip). 1 = FilterMode_EBPFXDP, 0 = iptables.
#
# Applying this only updates the AC launch template — the datapath does not
# change until the AC ASG is rolled, so the apply alone is a no-op at runtime
# and the rollout MUST refresh the fleet. Two consequences that are easy to miss:
#   * the Tier 1 AC eBPF object smoke stops being dormant and becomes a hard
#     deploy-time check once any active AC reports FilterMode=EBPFXDP, so it
#     must be invoked with allow_ssm_probes=true or it skips by policy and
#     proves nothing;
#   * v6 DENY telemetry changes shape (0-address DENYs, action tokens without
#     the `6` suffix) — intended and v4-parity-justified, but it lands in
#     CloudWatch only at this flip.
# Rollback is symmetric: set 0 and roll the ASG again.
ac_filter_mode = 1
# L3 flush-on-expiry rollout levers (docs/runbooks/l3-flush-*.md). Off by
# default via the module; the prod flip is the higher-stakes one, so drive it
# from here — uncomment, enable with dry-run first, soak, then set
# l3_flush_dry_run = false to acknowledge real-flush.
# enable_l3_flush_on_expiry = false
# l3_flush_dry_run          = true
enable_egress_eips = true

# Terraform state bucket for GitHub Actions permissions
terraform_state_bucket = "layerv-terraform-state-235500187906"
terraform_lock_table   = "terraform-state-lock"

# Keep the assigned-cell registration handoff dark until production Control's
# runtime and alias outputs are applied and verified. Activation requires a
# reviewed source-lock removal plus this tfvars flip, followed by a production
# server canary/ASG rollout.
connector_authority_cell_from_control_enabled = false

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

# GuardDuty security alerts.
# security@layerv.ai is the canonical, non-personal destination (resilient to
# any one person being OOO — see #2334). The individual addresses are kept as
# redundant delivery; Slack (via Chatbot) remains the primary real-time channel.
# Each new address must confirm its SNS subscription via the email link before
# it receives findings (prod rollout ledger entry for #2334).
guardduty_alert_emails = [
  "security@layerv.ai",
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

# Strict internal HMAC auth (#1311). Prod permit-mode burn-in was verified on
# 2026-05-31 before enabling: qurl-service headless resolve emitted
# InternalAuthSuccess (Sum=1 at 14:28 CDT), and InternalAuthFailPermit stayed at
# zero/no datapoints across the 14-day burn-in and fresh-smoke windows.
nhp_internal_auth_require = true

# ── Two-apply activation ──
# APPLY 1 (this file as committed): relay live, v2 issuer key + resource keys +
# server-side admission on, eBPF launch template updated. No qv2 link is minted
# and qurl.link keeps its current legacy flow, so nothing customer-facing
# depends on a fleet that has not rolled yet.
#
#   -> roll the server fleet (protocol 1.1) and the AC ASG (eBPF), confirm the
#      relay target group is healthy
#
# APPLY 2: flip qurl_v2_issuance_enabled and qurl_link_js_agent_enabled to true
# together. That is the customer-visible cutover.
#
# This split is not caution about the flag values; it is the promote pipeline's
# job order. terraform-apply runs before deploy-server, so anything Terraform
# publishes for browsers goes live before the fleet that serves it.

# ── qURL v2 keyed identity ──
# The four gates flip together by contract, enforced at plan time by
# terraform_data.qurl_v2_flag_invariants:
#   issuance  -> requires admission (else minted links have no issuer in the
#                NHP-server trust store and every knock denies)
#   issuance  -> requires issuer_key + resource_keys
#   admission -> requires issuer_key AND a non-empty issuer_kid (an empty kid
#                renders the trust store as "{}" and denies every qv2 admission)
#   issuance  -> requires a non-empty relay_url, embedded in signed claims
#
# The kid is environment-scoped on purpose. It is the trust-store key the NHP
# server looks the issuer up by, so reusing the sandbox kid in prod would have
# prod claims resolve against a key prod does not hold — ErrUnknownKID on every
# admission. Rotating it later means re-minting: links already signed under the
# old kid stop admitting once it leaves the trust store.
qurl_v2_issuer_key_enabled            = true
qurl_v2_resource_keys_enabled         = true
qurl_v2_resource_key_software_default = true
# ── APPLY 2 ── issuance flips with the js-agent, for a reason that is easy to
# miss: minting is useless without a portal that can open the link. Both
# qurl_browser_relay_base_url (threaded to qurl-service) and the portal's
# server_public_key_b64 are gated on qurl_link_js_agent_enabled, so with the
# js-agent off a minted #qv2. link reaches a qv1-only portal and fails closed.
# Issuance-on + js-agent-off would mint links nothing can open.
qurl_v2_issuance_enabled = false
# Admission stays ON in apply 1 on purpose. The plan only enforces
# issuance -> admission, never the reverse ("admission on, issuance off is
# harmless"), so the server fleet can be ready to admit qv2 before the first
# qv2 link exists. That ordering is the safe direction.
qurl_v2_admission_enabled = true
qurl_v2_issuer_kid        = "qurl-issuer-prod-2026-08"

# relay_url is stamped into every signed claim and must be ON the allowlist, so
# these two move together and both must match relay_dns_name below. A mismatch
# mints links whose relay the issuer's own allowlist rejects.
qurl_v2_relay_url       = "https://relay.layerv.ai"
qurl_v2_relay_allowlist = "relay.layerv.ai"

# ── qurl-scanner — deliberately still OFF, and it cannot join this apply ──
# The scanner is a two-apply rollout per environment and prod has not had its
# first apply: /layerv-nhp-prod/qurl-scanner-lambda-image-tag does not exist.
# Terraform creates that parameter seeded "latest" with ignore_changes=[value]
# and reads its CURRENT value through a plan-time data source, so enabling the
# gate in the same apply that first creates it fails plan on ParameterNotFound —
# and even if it resolved, "latest" is not a tag present in the prod repository.
#
# Sequence after this release lands:
#   1. this apply creates the parameter (gate off) and the repo policy
#   2. write the replicated image SHA to it — c13be39 is already present in the
#      prod layerv/qurl-scanner-lambda repository (pushed 2026-08-05)
#   3. a follow-up apply sets qurl_scanner_lambda_enabled = true, then
#      sqs_emit, then tombstone_write, each after its own burn-in
# qurl_scanner_lambda_enabled          = true
# qurl_scanner_sqs_emit_enabled        = true
# qurl_scanner_tombstone_write_enabled = true

# qURL v2 immediate-revocation proof engine (#2793). ACK support is now in the
# AC/server protocol; keep this enabled so NHP_REV retries until every targeted
# AC slot ACKs or ages out to RevocationAgedOut.
nhp_revocation_retry_enabled          = true
nhp_revocation_retry_interval_seconds = 5
nhp_revocation_retry_age_out_seconds  = 60

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
# ── APPLY 2 ── flip to true only AFTER the fleet is rolled. See the
# "Two-apply activation" note beside qurl_v2_issuance_enabled above.
#
# Terraform is what publishes the browser bundle (module.qurl_link reads
# frontend/nhp-agent.min.js and its .sri), and promote-to-prod runs
# terraform-apply BEFORE deploy-server. Leaving this true would therefore put a
# protocol-1.1 bundle on qurl.link while the fleet is still 1.0 and the relay
# has no healthy targets — a ~20-minute browser outage across the blue/green
# roll, and exactly the inversion PR #3693's ledger warns against ("Fleet
# marginally first so a freshly-fetched 1.1 bundle always finds a 1.1
# receiver"). No Terraform ordering can fix that: the fleet roll happens in a
# later workflow job, outside the graph.
#
# When flipped it swaps the qurl.link CSP and cache policy — HTML and
# /nhp-agent.min.js move to Cache-Control: no-cache and the rendered script
# integrity must match the served bundle.
qurl_link_js_agent_enabled = false

# CloudFront for resolve.qurl.link - ISP compatibility (AT&T WiFi blocks NLB IPs)
enable_resolve_cloudfront = true

# Resolve WAF: run the Amazon IP-reputation rule in COUNT (observe, don't block).
# Conscious prod posture, not a side effect of the module default: the endpoint
# is token-gated and RateLimit/CommonRuleSet/KnownBadInputs stay enforcing, while
# the IP-reputation list false-positives legitimate datacenter-origin traffic
# (CI smoke, VPN, proxies, link-unfurlers). WAF logging captures what it would
# block; flip to true to restore blocking. See docs/runbooks/prod-rollout-ledger/README.md.
resolve_waf_ip_reputation_block = false

# Keep resolve WAF logging on (explicit, matching the posture decision above) so
# the count-mode IP-reputation rule stays observable. The logging_filter scopes
# it to IP-reputation-matched + BLOCKed requests; set false only under log-cost pressure.
enable_resolve_waf_logging = true

# CloudFront access logging (v2 -> S3) for the resolve distribution (#1799), so
# per-request x-edge-detailed-result-type is on hand for origin-error RCA. The
# delivered fields omit cs-uri-query, so the ?token= credential is never logged.
# 90-day-expiry bucket; bounded cost at resolve traffic. Set false to disable.
enable_resolve_access_logs = true

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

# qurl-service Connector sharing. Active tunnel registrations are authoritative;
# terraform_data.qurl_tunnel_registration_preconditions therefore requires
# deploy_qurl_service + deploy_frps + qurl_router_enabled + enable_instance_hrw +
# MULTIVALUE whenever this is true. All are satisfied here
# (qurl_router_enabled/enable_qurl_site_authz are already true above).
qurl_connector_auth_enabled                         = true
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
# in layerv-mgmt). The ACM cert is operator-pre-provisioned (module README
# "Step 0 — cross-account cert + DNS") and attached via
# bootstrap_alb_existing_certificate_arn with provision_certificate=false (the
# plan-time XOR cert gate accepts exactly this combination).
#
# DNS is automated: manage_dns_alias=false keeps the module's OWN (same-account)
# alias off, and the bootstrap.layerv.ai A-alias is instead written
# cross-account by terraform via aws_route53_record.bootstrap_alb_cross_account
# in terraform/main.tf (mirrors connect_cross_account). So there is NO manual
# post-apply A-alias step — the only operator pre-step remaining is the ACM
# cert (Step 0). A clean re-apply re-requires only the cert.
deploy_qurl_bootstrap_chain = true
enable_qurl_agent_bootstrap = true

deploy_bootstrap_alb                       = true
bootstrap_alb_dns_name                     = "bootstrap.layerv.ai"
bootstrap_alb_provision_certificate        = false                                                                                 # Path 1: cert pre-provisioned cross-account
bootstrap_alb_manage_dns_alias             = false                                                                                 # Path 1: A-alias written cross-account by aws_route53_record.bootstrap_alb_cross_account (see block above)
bootstrap_alb_existing_certificate_arn     = "arn:aws:acm:us-east-2:235500187906:certificate/baf58cbf-b14d-454e-a13a-988a81594eb3" # bootstrap.layerv.ai, ISSUED (Step 0)
bootstrap_alb_elb_5xx_threshold_per_minute = 1

# ── NHP-Relay (#2208) — LIVE ──
# The relay carries the browser qURL path (qurl.link js-agent) and is the
# endpoint advertised to registering agents, so it goes live with this release.
#
# DNS is Terraform-managed through the cross-account layerv-mgmt provider, not
# pre-provisioned out of band. `relay.layerv.ai` lives in the layerv.ai zone
# (Z0748438C8EK6UAW94ST, layerv-mgmt 165115313779), which the default provider
# cannot write — the same constraint every other prod DNS writer here already
# handles. The relay root previously had no cross-account path at all, which is
# why deploy_relay=true could not apply in prod before this release; the
# `*_mgmt` twins in relay_control_plane.tf close that gap and engage
# automatically because cross_account_route53_role_arn is set above.
#
# This differs deliberately from the bootstrap ALB's "Path 1" above, which
# leaves its cert and A-alias operator-managed. Path 1 was a concession, not a
# goal; the relay is the customer data path and its DNS stays in Terraform.
#
# relay_vpc_cidr MUST be set explicitly. Its default is 10.101.0.0/16 — the
# SANDBOX relay block — and the relay DMZ is VPC-peered to the main VPC, so
# inheriting a default here would bake a sandbox-shaped address plan into prod
# and make any future prod<->sandbox or inter-region peering unroutable.
# 10.201.0.0/16 keeps prod inside its own 10.2xx block: 10.200 main (live),
# 10.201 relay (this), 10.202 Control. Audited against live prod on 2026-08-07 —
# the only VPCs in the account are 10.200.0.0/16 and the 172.31.0.0/16 default.
deploy_relay                = true
relay_vpc_cidr              = "10.201.0.0/16"
relay_dns_name              = "relay.layerv.ai"
relay_route53_zone_id       = "Z0748438C8EK6UAW94ST" # layerv.ai zone (in layerv-mgmt account — written via aws.route53_mgmt)
relay_provision_certificate = true
relay_manage_dns_alias      = true

# WAF go-live watch period (count-only). Unlike sandbox's dark launch, this PR
# flips enable_qurl_agent_bootstrap=true simultaneously, so real customer agents
# can hit bootstrap.layerv.ai on day 1. Per var.bootstrap_alb_waf_count_only_rule_groups's
# guidance, bring both managed groups up count-only for the first 2–4 weeks —
# AnonymousIpList false-positives on customer VPN egress; CommonRuleSet (CRS)
# body-inspection false-positives on PEM-wrapped public keys. Flip to enforce
# after the watch period — tracked in #2238 (also covers populating
# bootstrap_alb_cross_account_subscriber_arns post-activation).
#
# AWSManagedRulesAmazonIpReputationList is count-only for a DIFFERENT, durable
# reason — NOT the watch period: its IP-reputation sub-rules categorically
# false-positive on cloud / hosting / datacenter source IPs, which is where
# connector sidecars run (AWS Nitro / GCP Confidential Space). Enforcing it 403s
# legitimate cloud-deployed agents at the ALB with no qurl-service log entry.
# This mirrors the qurl_resolve edge WAF (aws_wafv2_web_acl.qurl_resolve,
# terraform/main.tf), which counts the same rule for the same reason. The
# #2238 flip-to-enforce applies to AnonymousIpList + CRS only — leave
# AmazonIpReputationList count-only.
bootstrap_alb_waf_count_only_rule_groups = ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList", "AWSManagedRulesCommonRuleSet"]

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
# Agent registration + email OTP (T1) — PROD: registration + OTP ON AT LAUNCH
# ==============================================================================
# PATH A (agent_registration_enabled) and PATH B (agent_otp_enabled +
# agent_otp_registration_enabled) are both committed ON in prod for the launch.
# ⚠️ This is a live-launch merge, NOT a dark launch — read the warning below.
#
# ┌──────────────────────────────────────────────────────────────────────────┐
# │ ⚠️  MERGE = PROD LAUNCH.  READ BEFORE MERGING THIS PR.                      │
# └──────────────────────────────────────────────────────────────────────────┘
# These three flags are committed `true` by an EXPLICIT decision — this is NOT a
# dark launch, and they are deliberately NOT defaulted `false`. The FIRST prod
# `terraform apply` after this PR merges — INCLUDING an apply triggered by an
# UNRELATED change (e.g. a routine image bump) — activates BOTH enrollment paths
# in one shot: NHP agent registration AND OTP email sending via SES to the
# `notify.layerv.ai` sender domain (real emails to real users). There is no
# second "flip" step; merging + the next apply IS the go-live.
#
# Therefore MERGE THIS PR ONLY inside the launch window, and ONLY after ALL of
# the following are confirmed (this human gate is the real safety net):
#   1. SES PRODUCTION ACCESS granted for the sender domain (out of the SES
#      sandbox) — otherwise every OTP send fails closed.
#   2. DKIM + MAIL-FROM DNS records VERIFIED for notify.layerv.ai (SES shows the
#      domain Verified, DKIM Successful, MAIL FROM MX resolving).
#   3. The OTP pepper secret (${name_prefix}-agent-otp-pepper) SEEDED (≥32 chars).
#   4. relay.layerv.ai REACHABLE if/when deploy_relay flips (prod keeps it false
#      today; the register flow advertises this URL to clients regardless).
#   5. An OPERATOR STANDING BY to watch the launch-blocking alarms on first real
#      traffic: -agent-otp-send-failed-spike and -agent-otp-bounce (both page at
#      the first failure — a misconfigured sender surfaces here first).
#
# Terraform preconditions (main.tf) only check flag COHERENCE (registration ⇒
# bootstrap chain + relay URL; OTP ⇒ registration + email_from + both PATH B
# flags). They CANNOT verify SES production access or DNS propagation — so a plan/
# apply will happily succeed against an unverified sender. Do not rely on TF to
# catch a premature launch; rely on the checklist above. Full staged procedure:
# docs/runbooks/prod-rollout-ledger/2026-07-08-agent-registration-ses.md.
#
# The flip injects QURL_AGENT_REGISTRATION_ENABLED / QURL_AGENT_OTP_ENABLED /
# QURL_AGENT_OTP_EMAIL_FROM / QURL_NHP_RELAY_BASE_URL + QURL_AGENT_OTP_PEPPER on
# the qurl-service task def, renders AGENT_OTP_REGISTRATION_ENABLED into nhp-server
# user_data (a ~20-min fleet blue/green roll), and CREATES the SES identity +
# DKIM/MAIL-FROM DNS + config set + the pepper secret (agent_otp_ses.tf).
agent_registration_enabled     = true
agent_otp_enabled              = true
agent_otp_registration_enabled = true

# From address for OTP emails. The SES sender domain is derived from the part
# after `@` (here: notify.layerv.ai), and DKIM + MAIL FROM records land in the
# layerv.ai zone (hosted_zone_id = Z0748438C8EK6UAW94ST, cross-account layerv-mgmt).
# This IS the intended launch value (committed by the keep-true decision). SES
# production access + DKIM/MAIL-FROM verification for THIS domain are pre-merge
# checklist items in the ⚠️ warning above — a live apply mails from here for real.
agent_otp_email_from = "noreply@notify.layerv.ai"

# Relay base URL the agent-register flow points clients at (QURL_NHP_RELAY_BASE_URL).
# NOTE: prod keeps deploy_relay=false (the relay is dark until its dedicated
# prod-enable PR), so this is the PUBLIC relay origin the register flow advertises,
# not a module reference. This IS the intended launch value (committed by the
# keep-true decision); relay.layerv.ai reachability is a pre-merge checklist item
# in the ⚠️ warning above. (If registration must not go live until the relay is up,
# coordinate this flip with deploy_relay in the same rollout window.)
agent_registration_relay_base_url = "https://relay.layerv.ai"

# Agent-registration + OTP alarm thresholds (qurl_service_outcomes.tf). Defaults
# are sensible for launch; set explicitly here so prod values are auditable and
# the send_failed / relay-shed pages are pinned at first-event.
agent_otp_send_failed_threshold_per_minute             = 0 # LAUNCH-BLOCKING: page on the first SES send failure
agent_otp_bounce_threshold_per_minute                  = 0 # LAUNCH-BLOCKING: page on the first SES bounce/complaint/reject
agent_otp_rate_limited_threshold_per_minute            = 5
agent_register_attempts_exceeded_threshold_per_minute  = 3
agent_register_credential_invalid_threshold_per_minute = 10
agent_register_rate_limited_threshold_per_minute       = 5
# OTP-shed alarm (OTPRejectRateLimited) is gated on agent_otp_enabled OR
# deploy_relay, so with OTP on it IS created in prod even though the relay is dark
# (deploy_relay=false) — the metric is emitted on the direct-UDP OTP path
# regardless of the relay. Threshold pinned to 0 here (matching the default) so the
# launch value is explicit/auditable: the first OTP-cap reject pages, whether it
# comes via the direct path today or the relay once it goes live.
relay_otp_reject_rate_limited_threshold_per_minute = 0

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

# Extra public components on the status page (component id => health URL).
# qURL API + qURL link checks are wired automatically from their domains.
status_page_additional_service_urls = {
  website = "https://layerv.ai/"
}
status_page_display_only_component_ids = ["website"]

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

# Logout URLs: Auth0 redirects here after logout

# Web origins: allowed for CORS and silent authentication

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
auth0_backend_service_client_id = "V1n2pT1oSzcOVqBghwBUM1e7afp2AaPH" # Website Playground (prod)
auth0_smoke_test_client_id      = "2jgXb70UztKbn7Sbekk993cvUt8XtfDv" # Smoke Test (prod)
auth0_spa_dashboard_client_id   = "EhwI8cJwqviPsDFxKnBMVn6xWgR769IW" # qURL Dashboard (prod)

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
