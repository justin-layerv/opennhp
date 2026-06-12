# QURL Service Module
# ECS Fargate deployment for the QURL API service
#
# Architecture:
# Internet → ALB (HTTPS 443) → ECS Fargate (port 8080)
#
# The QURL API handles:
# - Public API: QURL management (Auth0 JWT protected)
# - Internal API: Token resolution for NHP plugin, target lookup for Traefik

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Subnet lookups for the ALB — used below to compute QURL_TRUSTED_PROXY_CIDRS
# from each subnet's cidr_block. This is the authoritative source for the
# "what addresses does the ALB actually originate from" question, and keeps
# the env var correct through any VPC resize or subnet remap without a
# separate Terraform variable to keep in sync. See local.alb_subnet_cidrs
# for how this is consumed.
data "aws_subnet" "alb" {
  for_each = toset(var.public_subnet_ids)
  id       = each.value
}

# Per-AZ FRPS env-var triple must be set as an all-or-nothing group. The
# `container_env` ternary in `local.container_env` already gates emission
# on `frps_port != 0 && frps_domain != "" && frps_az_suffixes != ""`, but
# a partial-config typo (e.g., a follow-up PR that only sets two of the
# three) would silently fall back to qurl-service's pre-FRPS behavior
# instead of failing closed. Plan-time fence so partial wiring is
# rejected at PR review.
resource "terraform_data" "frps_env_var_triple" {
  lifecycle {
    precondition {
      # XOR of "all set" vs "all unset". `frps_port != 0` reads as "set"
      # because the variable's "unset" sentinel is 0 (paired with empty-
      # string sentinels for the other two). The booleans below collapse
      # to true only when the trio agrees.
      condition = (
        var.frps_port == 0 && var.frps_domain == "" && var.frps_az_suffixes == ""
        ) || (
        var.frps_port != 0 && var.frps_domain != "" && var.frps_az_suffixes != ""
      )
      error_message = "qurl-service FRPS env vars (frps_az_suffixes, frps_domain, frps_port) must be set together or all unset. Partial wiring silently falls back to no `upstream_addr` in API responses."
    }
  }
}

resource "terraform_data" "nhp_resource_catalog_inputs" {
  lifecycle {
    precondition {
      condition = (
        (
          var.nhp_resources_table_name == ""
          && var.nhp_resources_table_arn == ""
          && var.nhp_resources_customer_id_prefix == ""
        )
        || (
          var.nhp_resources_table_name != ""
          && var.nhp_resources_table_arn != ""
          && var.nhp_resources_customer_id_prefix != ""
        )
      )
      error_message = "nhp_resources_table_name, nhp_resources_table_arn, and nhp_resources_customer_id_prefix must be provided together so qurl-service can publish dynamic q_ catalog shard rows with scoped IAM."
    }
    precondition {
      condition = (
        (
          var.nhp_server_internal_url == ""
          && var.nhp_resources_table_name == ""
        )
        || (
          var.nhp_server_internal_url != ""
          && var.nhp_resources_table_name != ""
        )
      )
      error_message = "nhp_server_internal_url and nhp_resources_table_name must be provided together; qurl-service requires the dynamic catalog table and internal knock origin as one atomic NHP integration surface."
    }
    precondition {
      condition = (
        var.nhp_resources_customer_id_prefix == ""
        || var.nhp_resources_customer_id_prefix != "00000000000000000000000000"
      )
      error_message = "nhp_resources_customer_id_prefix must not be the NHP system customer_id partition; qurl-service may only write its reserved dynamic q_ shard namespace."
    }
  }
}

# Module-reuse hardening for the QURL agent → nhp-server bootstrap chain.
# The validation/precondition split:
#   - Variable-level `validation` blocks (in variables.tf) handle
#     empty-vs-malformed checks per-variable in isolation
#     (base64-decodable 32-byte pubkey, bare FQDN host, numeric port).
#   - This `terraform_data` precondition handles the cross-variable
#     invariant that variable validation can't express — "non-empty
#     when the gate is on" requires referencing both
#     `var.deploy_qurl_bootstrap_chain` and the value-bearing var.
# Today the only caller (`terraform/main.tf`) always threads both
# producer outputs (module.compute.server_public_key_b64,
# module.compute.nlb_dns_name) when the gate is on, so this precondition
# is defense in depth — but a future caller that flips
# `deploy_qurl_bootstrap_chain = true` without wiring the values would
# otherwise inject empty env vars and surface the failure only at agent
# runtime. Fail at plan time instead.
#
# Caveat: `module.compute.server_public_key_b64` is "known after apply"
# on a greenfield env (it resolves through a
# `data.aws_secretsmanager_secret_version` that depends on
# `aws_lambda_invocation.keygen`). The condition then evaluates at apply
# time rather than plan time — a fail-loud apply error is still strictly
# better than a runtime agent failure, which is the point of the fence.
# Sandbox + prod both have the secret populated already, so the
# plan-time signal works there today.
resource "terraform_data" "qurl_bootstrap_chain_inputs" {
  count = var.deploy_qurl_bootstrap_chain ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.nhp_server_public_key_b64 != ""
      error_message = "deploy_qurl_bootstrap_chain=true but nhp_server_public_key_b64 is empty. The agent would receive NHP_SERVER_PUBLIC_KEY_B64=\"\" and fail its handshake at runtime. Thread `module.compute.server_public_key_b64` from the root (NOT `module.nhp_keypair.registration_public_key` — that is the AC↔server registration key, a different role; wiring it here passes the variable shape check but silently 100%-fails every agent knock at runtime)."
    }
    precondition {
      condition     = var.nhp_server_host != ""
      error_message = "deploy_qurl_bootstrap_chain=true but nhp_server_host is empty. The agent would receive NHP_SERVER_HOST=\"\" and have no responder to reach. Thread `module.compute.nlb_dns_name` from the root."
    }
  }
}

# SSM parameter for image tag - created with default, updated by CI
# The CI pipeline updates this parameter after pushing a new image to ECR.
# Using lifecycle ignore_changes so CI updates don't cause drift.
resource "aws_ssm_parameter" "image_tag" {
  name        = var.image_tag_ssm_param
  type        = "String"
  value       = "latest"
  description = "Current Docker image tag for QURL service (managed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-image-tag"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# SSM parameters for ECS cluster/service names - consumed by CI for deployments.
# This avoids hardcoding infrastructure names in the CI workflow.
#
# Note: These use inline path construction (/${var.name_prefix}/...) rather than
# variables like image_tag_ssm_param because CI only needs to know name_prefix
# to construct the path. The image_tag param uses a variable because its path
# pattern is more complex and was established before this convention.
resource "aws_ssm_parameter" "ecs_cluster" {
  name        = "/${var.name_prefix}/qurl-ecs-cluster"
  type        = "String"
  value       = aws_ecs_cluster.qurl.name
  description = "ECS cluster name for QURL service (consumed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-cluster"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "ecs_service" {
  name        = "/${var.name_prefix}/qurl-ecs-service"
  type        = "String"
  value       = aws_ecs_service.qurl.name
  description = "ECS service name for QURL service (consumed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-service"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# SSM parameter for default AC ID - resolved by ECS at task launch time via
# valueFrom in the container definition. This ensures the value is always
# current, even when task definitions are cloned by CI.
resource "aws_ssm_parameter" "default_ac_id" {
  name        = "/${var.name_prefix}/qurl-default-ac-id"
  type        = "String"
  value       = var.default_ac_id
  description = "Default AC ID for QURL service (resolved by ECS at task launch)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-default-ac-id"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== Locals ====================

locals {
  is_prod      = var.environment == "prod"
  service_name = "${var.name_prefix}-${var.cell_id}-qurl-api"
  # Shorter name for resources with 32-char limit (ALB/NLB names)
  short_name = "${var.name_prefix}-${var.cell_id}-qurl"
  # DNS-safe form used as the base for AWS resources subject to the 32-char
  # name ceiling (ALB, TG). Computed once so name + length-precondition +
  # error message can't drift across the resources that share the limit.
  short_name_dash    = replace(local.short_name, "_", "-")
  internal_alb_name  = "${local.short_name_dash}-i"
  internal_name_fits = length(local.internal_alb_name) <= 32

  # Task-level CPU/memory with ADOT sidecar overhead.
  # Fargate requires specific CPU/memory combinations (memory in 1024 MB increments
  # for CPU values 256-4096). Round up to avoid invalid combinations like 512 CPU / 1280 MB.
  # See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  task_cpu    = var.grafana_cloud_enabled ? max(var.container_cpu, 512) : var.container_cpu
  task_memory = ceil((var.grafana_cloud_enabled ? var.container_memory + 256 : var.container_memory) / 1024) * 1024

  # Compute allowed hosts: ALB DNS + domain + localhost for health checks + any additional hosts.
  # When the internal ALB is enabled, its DNS name and the operator-supplied
  # internal_domain_name are also accepted so HostValidation doesn't 400 the
  # internal callers. aws_lb.{qurl,qurl_internal}.dns_name are referenced
  # later; terraform handles the dependency.
  computed_allowed_hosts = join(",", compact(concat(
    [aws_lb.qurl.dns_name, "localhost", "127.0.0.1"],
    var.domain_name != null ? [var.domain_name] : [],
    var.internal_alb_enabled ? [aws_lb.qurl_internal[0].dns_name] : [],
    var.internal_alb_enabled && var.internal_domain_name != null ? [var.internal_domain_name] : [],
    var.additional_allowed_hosts
  )))

  # Compute API base URL for Location headers and absolute URLs
  # Priority: explicit > domain with cert > ALB DNS
  computed_api_base_url = coalesce(
    var.api_base_url,
    var.domain_name != null && var.certificate_arn != null ? "https://${var.domain_name}" : null,
    "http://${aws_lb.qurl.dns_name}"
  )

  # Trusted-proxy CIDRs for Gin's SetTrustedProxies, derived from the ALB's
  # own subnets (aws_lb.qurl.subnets = var.public_subnet_ids). This is the
  # *exact* set of origin IPs the ALB can present to the container, so it's
  # both necessary and sufficient — tighter than the VPC CIDR (which would
  # also trust peers/workers) and auto-correct through any subnet resize.
  # Consumed by qurl-service via the QURL_TRUSTED_PROXY_CIDRS env var below.
  # See qurl-service PR #323 (fix #296): this variable MUST be set on the
  # task definition before that PR can deploy to prod — prod hard-fails
  # startup if it's empty. Sorted so Terraform doesn't show a spurious
  # diff when AWS reorders subnet API responses.
  #
  # IPv4 only: aws_subnet.cidr_block returns the v4 CIDR. If the ALB ever
  # becomes dual-stack or IPv6-only (aws_lb.qurl currently has no
  # ip_address_type so it defaults to ipv4), extend this with
  # `s.ipv6_cidr_block` filtered to non-empty — otherwise c.ClientIP()
  # silently falls back to the TCP source for v6 connections with no
  # operator signal.
  #
  # Internal ALB asymmetry: this list is derived from public_subnet_ids
  # only (aws_lb.qurl.subnets). The internal ALB (aws_lb.qurl_internal)
  # lives in private_subnet_ids and its ENI source IPs are NOT in this
  # list. Consequence: requests routed via the internal ALB fall back to
  # the TCP source for c.ClientIP(), so XFF is NOT trusted on
  # internal-ALB traffic. This is intentional — /internal/v1/* is the
  # only consumer of the internal ALB and its trust model uses the
  # request-body src_ip as authoritative (see PR #1588 trust-model
  # table). If a future internal endpoint needs trustworthy XFF, extend
  # alb_subnet_cidrs with private_subnet_ids when var.internal_alb_enabled.
  alb_subnet_cidrs = sort([for s in data.aws_subnet.alb : s.cidr_block])

  # DynamoDB tables owned by this module are folded into the same task-role
  # policy as the shared qurl tables passed in from module.dynamodb.
  qurl_service_owned_dynamodb_table_arns = [
    aws_dynamodb_table.qurl_external_identities.arn,
  ]
  qurl_service_dynamodb_table_arns = concat(
    var.dynamodb_table_arns,
    local.qurl_service_owned_dynamodb_table_arns,
  )

  # Container environment variables
  container_env = concat([
    { name = "QURL_ENV", value = local.is_prod ? "production" : "development" },
    { name = "AWS_REGION", value = data.aws_region.current.id },
    { name = "SERVER_HOST", value = "0.0.0.0" },
    { name = "SERVER_PORT", value = tostring(var.container_port) },
    { name = "API_BASE_URL", value = local.computed_api_base_url },
    { name = "DYNAMODB_TABLE_PREFIX", value = var.dynamodb_table_prefix },
    # Hardcoded "true" — every cell running this module must have the
    # periodic DynamoDB schema reconciler on; no per-env opt-out.
    # Defense-in-depth layer against GSI drift (incident class #877).
    # Kill switch on misfire is a manual ECS task-def override + force
    # deploy (see docs/runbooks/verify-qurl-schema-prevention.md §3.1);
    # terraform-apply is too slow for incident rollback.
    { name = "QURL_SCHEMA_RECONCILER_ENABLED", value = "true" },
    { name = "AUTH0_DOMAIN", value = var.auth0_domain },
    { name = "AUTH0_AUDIENCE", value = var.auth0_audience },
    { name = "AUTH0_JWKS_CACHE_TTL", value = tostring(var.auth0_jwks_cache_ttl_seconds) },
    { name = "AUTH0_JWKS_FETCH_TIMEOUT", value = tostring(var.auth0_jwks_fetch_timeout_seconds) },
    { name = "QURL_COOKIE_DOMAIN", value = var.cookie_domain },
    { name = "QURL_LINK_DOMAIN", value = var.qurl_link_domain },
    { name = "QURL_SITE_DOMAIN", value = var.qurl_site_domain },
    { name = "QURL_DEFAULT_TOKEN_EXPIRE", value = tostring(var.default_token_expire) },
    { name = "QURL_DEFAULT_OPEN_TIME", value = tostring(var.default_open_time) },
    { name = "QURL_AC_PORT", value = tostring(var.default_ac_port) },
    { name = "IP_RATE_LIMIT", value = tostring(var.ip_rate_limit) },
    { name = "IP_RATE_BURST", value = tostring(var.ip_rate_burst) },
    { name = "AUDIT_RETENTION_DAYS", value = tostring(var.audit_retention_days) },
    { name = "CORS_ALLOWED_ORIGINS", value = var.cors_allowed_origins },
    { name = "ALLOWED_HOSTS", value = local.computed_allowed_hosts },
    # Tells qurl-service which upstream IPs are allowed to set X-Forwarded-*
    # headers. Without this set, the service treats XFF as untrusted
    # caller-supplied data and falls back to the TCP source for c.ClientIP()
    # — which is wrong when the ALB is terminating the connection. Prod
    # (qurl-service cfg.IsProduction()) hard-fails startup on an empty
    # value, so this env var is a deploy-order prerequisite for
    # qurl-service PR #323. Derived from the ALB's own subnets so it
    # stays correct through VPC/subnet changes.
    { name = "QURL_TRUSTED_PROXY_CIDRS", value = join(",", local.alb_subnet_cidrs) },
    # Tunnel-auth feature gate (qurl-service PR #277). Default false keeps
    # the new code paths inert in prod until the POST /v1/resources type=tunnel
    # creation endpoint (#405) and the per-AZ FRPS assignment (#396) deploy
    # together. Flipped to true per-env via tfvars once those land.
    { name = "TUNNEL_AUTH_ENABLED", value = var.tunnel_auth_enabled ? "true" : "false" },
    # Active-registration read gate (qurl-service #732). Registration writes
    # can dark-launch while this remains false; flipping true makes
    # `upstream_addrs` authoritative for tunnel routing.
    { name = "QURL_TUNNEL_ACTIVE_REGISTRATIONS_ENABLED", value = var.tunnel_active_registrations_enabled ? "true" : "false" },
    # Idempotency cache configuration
    { name = "IDEMPOTENCY_CACHE_TTL", value = tostring(var.idempotency_cache_ttl_seconds) },
    { name = "IDEMPOTENCY_CACHE_MAX_SIZE", value = tostring(var.idempotency_cache_max_size) },
    { name = "IDEMPOTENCY_CLEANUP_INTERVAL", value = tostring(var.idempotency_cleanup_interval_seconds) },
    # Health check configuration
    { name = "HEALTH_CHECK_TIMEOUT", value = tostring(var.health_check_timeout_seconds) },
    { name = "HEALTH_STARTUP_TIMEOUT", value = tostring(var.health_startup_timeout_seconds) },
    # Customer cache configuration (tier lookups for quota/rate-limiting)
    { name = "CUSTOMER_CACHE_TTL", value = tostring(var.customer_cache_ttl_seconds) },
    { name = "CUSTOMER_CACHE_MAX_SIZE", value = tostring(var.customer_cache_max_size) },
    # QURL resource configuration
    { name = "QURL_DEFAULT_EXPIRES_IN", value = tostring(var.qurl_default_expires_in_seconds) },
    { name = "QURL_RESOURCE_TTL_BUFFER", value = tostring(var.qurl_resource_ttl_buffer_seconds) },
    { name = "QURL_SESSION_TTL", value = tostring(var.qurl_session_ttl_seconds) },
    { name = "QURL_DEFAULT_LIST_LIMIT", value = tostring(var.qurl_default_list_limit) },
    ],
    # Redis configuration (for distributed rate limiting)
    var.redis_enabled ? concat([
      { name = "REDIS_ENABLED", value = "true" },
      { name = "REDIS_ENDPOINT", value = var.redis_endpoint },
      { name = "REDIS_TLS_ENABLED", value = "true" },
      ],
      var.redis_pool_size > 0 ? [{ name = "REDIS_POOL_SIZE", value = tostring(var.redis_pool_size) }] : [],
      var.redis_min_idle_conns > 0 ? [{ name = "REDIS_MIN_IDLE_CONNS", value = tostring(var.redis_min_idle_conns) }] : [],
    ) : [],
    # Usage events (billing metered usage reporting via SQS)
    var.usage_events_enabled ? [
      { name = "USAGE_EVENTS_ENABLED", value = "true" },
      { name = "USAGE_SQS_QUEUE_URL", value = var.usage_events_queue_url },
    ] : [],
    # Webhook-events SQS consumer (qurl-service PR #874 drainer goroutine).
    # Activated by `qurl_scanner_sqs_emit_enabled` — see
    # `modules/qurl-service/variables.tf::qurl_scanner_sqs_emit_enabled`
    # for the canonical rationale (producer/consumer ordering, rollback
    # de-atomization risk, when to flip).
    #
    # Conditional ANDs both flags so the `[0]` lookup against
    # `aws_sqs_queue.resource_lifecycle_queue` (count-gated on
    # `qurl_scanner_lambda_enabled`) is structurally unreachable in the
    # operator-misconfig case (`emit=true, lambda=false`). Terraform
    # evaluates the ternary lazily, so the `[0]` reference is simply
    # never reached when the AND'd condition is false — no `Invalid
    # index`. The lifecycle precondition below is then the
    # friendly-error layer: it prints the copy-pasteable misconfig
    # message so the operator sees what's wrong, instead of a silent
    # plan-passes-with-empty-env-vars no-op.
    (var.qurl_scanner_sqs_emit_enabled && var.qurl_scanner_lambda_enabled) ? [
      { name = "WEBHOOK_EVENTS_CONSUMER_ENABLED", value = "true" },
      { name = "WEBHOOK_EVENTS_SQS_QUEUE_URL", value = aws_sqs_queue.resource_lifecycle_queue[0].url },
    ] : [],
    # Idempotency table (for distributed idempotency)
    var.idempotency_table_name != "" ? [
      { name = "IDEMPOTENCY_TABLE_NAME", value = var.idempotency_table_name },
    ] : [],
    # API key idempotency table (dedicated for POST /v1/api-keys mint)
    var.apikey_idempotency_table_name != "" ? [
      { name = "APIKEY_IDEMPOTENCY_TABLE_NAME", value = var.apikey_idempotency_table_name },
    ] : [],
    # Webhooks configuration
    var.webhooks_enabled ? [
      { name = "WEBHOOKS_ENABLED", value = "true" },
      { name = "WEBHOOKS_WORKER_COUNT", value = tostring(var.webhooks_worker_count) },
      { name = "WEBHOOKS_MAX_PER_OWNER", value = tostring(var.webhooks_max_webhooks_per_owner) },
      { name = "WEBHOOKS_DELIVERY_TIMEOUT", value = tostring(var.webhooks_delivery_timeout_seconds) },
      { name = "WEBHOOKS_MAX_RETRIES", value = tostring(var.webhooks_max_retries) },
      { name = "WEBHOOKS_EVENT_CHANNEL_SIZE", value = tostring(var.webhooks_event_channel_size) },
      { name = "WEBHOOKS_RETRY_WORKER_INTERVAL", value = tostring(var.webhooks_retry_worker_interval_seconds) },
      { name = "WEBHOOKS_DRAIN_TIMEOUT", value = tostring(var.webhooks_drain_timeout_seconds) },
      { name = "WEBHOOKS_RESPONSE_BODY_LIMIT", value = tostring(var.webhooks_response_body_limit) },
      { name = "WEBHOOKS_API_VERSION", value = var.webhooks_api_version },
    ] : [],
    # Custom domain management
    var.custom_domain_enabled ? concat([
      { name = "CUSTOM_DOMAIN_ENABLED", value = "true" },
      { name = "CUSTOM_DOMAIN_ACME_SUFFIX", value = var.custom_domain_acme_suffix },
      { name = "CUSTOM_DOMAIN_NLB_TARGET", value = var.custom_domain_nlb_target },
      ],
      var.custom_domain_cleanup_topic_arn != "" ? [
        { name = "CUSTOM_DOMAIN_CLEANUP_TOPIC_ARN", value = var.custom_domain_cleanup_topic_arn },
      ] : [],
    ) : [],
    # NHP dynamic resource catalog. qurl-service #827 requires this table
    # and NHP_SERVER_INTERNAL_URL as one atomic integration surface; the
    # module precondition above rejects table-only or URL-only wiring.
    var.nhp_resources_table_name != "" ? [
      { name = "NHP_RESOURCES_TABLE_NAME", value = var.nhp_resources_table_name },
    ] : [],
    # NHP integration (headless resolve via POST /v1/resolve)
    var.nhp_server_internal_url != "" ? [
      { name = "NHP_SERVER_INTERNAL_URL", value = var.nhp_server_internal_url },
      { name = "NHP_KNOCK_TIMEOUT", value = tostring(var.nhp_knock_timeout_seconds) },
    ] : [],
    # QURL agent → nhp-server bootstrap chain (Wave 5 dark-launch). Threaded
    # directly from module.compute at the root
    # (server_public_key_b64 for the server-identity pubkey, nlb_dns_name
    # for the host) so the agent's view of the responder can never drift
    # from what nhp-server actually publishes. Same wiring shape as
    # NHP_SERVER_INTERNAL_URL above — TF-injected env vars on the task
    # def, no second config-fetch mechanism (no ssm:GetParameter at
    # runtime), no IAM surface for these statics. The values change only
    # on TF apply (NLB DNS rotation, server-secret keypair rotation,
    # constant port). Gate is var.deploy_qurl_bootstrap_chain;
    # the chain is activated via a separate
    # var.enable_qurl_agent_bootstrap tfvars flip per environment —
    # matches the established dark-launch pattern in this tree
    # (deploy_frps, deploy_qurl_service, deploy_bootstrap_alb).
    var.deploy_qurl_bootstrap_chain ? [
      { name = "NHP_SERVER_PUBLIC_KEY_B64", value = var.nhp_server_public_key_b64 },
      { name = "NHP_SERVER_HOST", value = var.nhp_server_host },
      { name = "NHP_SERVER_PORT", value = var.nhp_server_port },
      { name = "QURL_AGENT_BOOTSTRAP_ENABLED", value = var.enable_qurl_agent_bootstrap ? "true" : "false" },
    ] : [],
    # FRPS integration (#1499). qurl-service hashes OwnerID to a
    # suffix and emits `frps-${suffix}.${domain}:${port}` as `upstream_addr`
    # in CreateResource / GetResourceTarget responses. All three vars
    # must be set together — gated on `frps_port != 0` because Terraform
    # comparisons of empty string in `concat([...], cond ? [...] : [])`
    # are easy to typo, and a numeric `!= 0` reads unambiguously. The
    # root module wires this only when `deploy_frps = true`.
    var.frps_port != 0 && var.frps_domain != "" && var.frps_az_suffixes != "" ? [
      { name = "QURL_FRPS_AZ_SUFFIXES", value = var.frps_az_suffixes },
      { name = "QURL_FRPS_DOMAIN", value = var.frps_domain },
      { name = "QURL_FRPS_PORT", value = tostring(var.frps_port) },
    ] : [],
    # GeoIP configuration (for geo-restriction policies)
    var.geoip_enabled ? concat([
      { name = "GEOIP_ENABLED", value = "true" },
      { name = "GEOIP_DB_PATH", value = var.geoip_db_path },
      ],
      var.geoip_s3_uri != "" ? [
        { name = "GEOIP_S3_URI", value = var.geoip_s3_uri },
      ] : [],
    ) : [],
    # Stripe billing integration (for checkout, portal, invoices)
    var.stripe_secret_arn != "" ? [
      { name = "STRIPE_SECRET_ARN", value = var.stripe_secret_arn },
      { name = "GROWTH_PRICE_ID", value = var.stripe_growth_price_id },
      { name = "STRIPE_CHECKOUT_SUCCESS_URL", value = var.stripe_checkout_success_url },
      { name = "STRIPE_CHECKOUT_CANCEL_URL", value = var.stripe_checkout_cancel_url },
    ] : [],
    # OpenTelemetry configuration
    # When Grafana Cloud is enabled, OTEL exports to the local ADOT sidecar
    # The sidecar then forwards to Grafana Cloud OTLP endpoint
    var.otel_enabled ? [
      { name = "OTEL_ENABLED", value = "true" },
      { name = "OTEL_SERVICE_NAME", value = var.otel_service_name },
      { name = "OTEL_SERVICE_VERSION", value = var.otel_service_version },
      { name = "OTEL_ENVIRONMENT", value = var.otel_environment },
      # When Grafana Cloud is enabled, send to local ADOT sidecar; otherwise use configured endpoint
      # gRPC endpoint must be host:port without scheme - http:// causes "too many colons" error
      { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = var.grafana_cloud_enabled ? "localhost:4317" : var.otel_exporter_endpoint },
      { name = "OTEL_EXPORTER_OTLP_PROTOCOL", value = var.grafana_cloud_enabled ? "grpc" : var.otel_exporter_protocol },
      { name = "OTEL_EXPORTER_OTLP_INSECURE", value = var.grafana_cloud_enabled ? "true" : (var.otel_exporter_insecure ? "true" : "false") },
      { name = "OTEL_TRACE_SAMPLE_RATE", value = tostring(var.otel_trace_sample_rate) },
      { name = "OTEL_METRICS_INTERVAL", value = tostring(var.otel_metrics_interval) },
      { name = "OTEL_METRICS_ENABLED", value = var.otel_metrics_enabled ? "true" : "false" },
      { name = "OTEL_TRACING_ENABLED", value = var.otel_tracing_enabled ? "true" : "false" },
      { name = "OTEL_LOG_CORRELATION", value = var.otel_log_correlation ? "true" : "false" },
    ] : [],
  )

  # Secrets and SSM parameters resolved by ECS at task launch time.
  # Despite the field name, ECS "secrets" supports both Secrets Manager ARNs
  # and SSM Parameter Store ARNs — it's the mechanism for dynamic value resolution.
  container_secrets = [
    { name = "QURL_JWT_SECRET", valueFrom = var.jwt_secret_arn },
    { name = "QURL_INTERNAL_SERVICE_TOKEN", valueFrom = var.internal_service_token_arn },
    { name = "QURL_AC_ID", valueFrom = aws_ssm_parameter.default_ac_id.arn },
    # Shared HMAC secret — signer side of the /nhp/internal/knock contract with nhp-server.
    { name = "NHP_INTERNAL_AUTH_SECRET", valueFrom = var.nhp_internal_auth_secret_arn },
  ]
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "qurl" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/qurl-api"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  # Prevent accidental deletion of production logs via Terraform
  skip_destroy = local.is_prod

  tags = merge(var.tags, {
    Name      = "${local.service_name}-logs"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== ECS Cluster ====================

resource "aws_ecs_cluster" "qurl" {
  name = local.service_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== IAM Roles ====================

# Task execution role (used by ECS agent to pull images, write logs)
resource "aws_iam_role" "execution" {
  name = "${local.service_name}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_basic" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Policy to read secrets from Secrets Manager and SSM parameters for valueFrom
resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = concat(
          [
            var.jwt_secret_arn,
            var.internal_service_token_arn,
            var.nhp_internal_auth_secret_arn,
          ],
          # Add Grafana Cloud secret when ADOT sidecar is enabled
          var.grafana_cloud_enabled && var.grafana_secret_arn != null ? [var.grafana_secret_arn] : []
        )
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameters"]
        Resource = [aws_ssm_parameter.default_ac_id.arn]
      }
      ], var.secrets_kms_key_arn != null ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# Task role (used by the container application)
resource "aws_iam_role" "task" {
  name = "${local.service_name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# Policy for DynamoDB access
resource "aws_iam_role_policy" "task_dynamodb" {
  name = "dynamodb-access"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBAccess"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchGetItem",
            "dynamodb:BatchWriteItem",
            # DescribeTable is required by the periodic schema reconciler
            # in qurl-service (internal/health/dynamodb_schema.go) which
            # calls DescribeTable every 60s on each table in the registry
            # to detect GSI drift. Without this permission the reconciler
            # fails with AccessDenied, /health/ready flips to 503, and
            # the ALB de-registers every task. Added to close the
            # 2026-03-24 incident class (nhp PR #877) at runtime as the
            # belt-and-suspenders to the workflow gate in promote-to-prod.
            "dynamodb:DescribeTable",
          ]
          Resource = concat(
            local.qurl_service_dynamodb_table_arns,
            [for arn in local.qurl_service_dynamodb_table_arns : "${arn}/index/*"],
            # Idempotency table (if configured)
            var.idempotency_table_arn != "" ? [var.idempotency_table_arn] : [],
            # API key idempotency table (if configured)
            var.apikey_idempotency_table_arn != "" ? [var.apikey_idempotency_table_arn] : []
          )
        },
      ],
      var.nhp_resources_table_arn != "" ? [{
        Sid    = "NHPResourceCatalogWrite"
        Effect = "Allow"
        # qurl-service treats nhp_resources as a write-only catalog client:
        # full PutItem on mint/update and DeleteItem on revoke. It is not in
        # qurl-service's schema-reconciler registry, so DescribeTable remains
        # intentionally scoped to qurl-service-owned DynamoDB tables above.
        Action = [
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
        ]
        Resource = [var.nhp_resources_table_arn]
        Condition = {
          # Safe with PutItem/DeleteItem because each request has exactly one
          # table leading key; the ForAllValues absent-key caveat is not
          # reachable for these item APIs.
          "ForAllValues:StringLike" = {
            # Matches terraform/resources.tf
            # local.nhp_qurl_dynamic_customer_id_prefix,
            # endpoints/server/resource_lookup.go
            # nhpQURLDynamicCustomerIDPrefix, and qurl-service's
            # NHPQurlDynamicCustomerIDPrefix. Dynamic qURL rows live under
            # "<prefix>-00" through "<prefix>-ff"; the two-character pattern
            # keeps the policy compact while preventing writes to Terraform-owned
            # static qurl-tunnel-server or agent rows in the system partition.
            # IAM StringLike cannot express hex-only; writer/reader helpers and
            # the shared vector tests enforce the [0-9a-f]{2} shard suffix.
            "dynamodb:LeadingKeys" = ["${var.nhp_resources_customer_id_prefix}-??"]
          }
        }
      }] : [],
      # KMS decrypt for DynamoDB (tables are encrypted with KMS)
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSDecryptDynamoDB"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
      }] : [],
    )
  })
}

# Policy for GeoIP database download from S3 (conditional)
resource "aws_iam_role_policy" "task_geoip_s3" {
  count = var.geoip_s3_uri != "" ? 1 : 0
  name  = "geoip-s3-access"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid      = "GeoIPDatabaseDownload"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = [replace(var.geoip_s3_uri, "s3://", "arn:aws:s3:::")]
      }],
      var.geoip_s3_kms_key_arn != "" ? [{
        Sid      = "GeoIPKMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.geoip_s3_kms_key_arn]
      }] : [],
    )
  })
}

# Policy to read Stripe secret from Secrets Manager (conditional)
resource "aws_iam_role_policy" "task_stripe_secret" {
  count = var.stripe_secret_arn != "" ? 1 : 0
  name  = "stripe-secret-access"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Sid      = "StripeSecretRead"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.stripe_secret_arn]
      }],
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSDecryptStripeSecret"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

resource "aws_iam_role_policy" "task_usage_events" {
  count = var.usage_events_queue_arn != "" ? 1 : 0
  name  = "usage-events-sqs-send"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Sid      = "SQSSendUsageEvents"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [var.usage_events_queue_arn]
      }],
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSEncryptSQS"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# Resource-lifecycle queue consumer policy: grants the qurl-api task role
# `Receive`/`Delete`/`GetQueueAttributes` on the resource-lifecycle SQS
# queue (defined in resource_lifecycle_queue.tf) and `kms:Decrypt` on the
# same `secrets` CMK the queue is encrypted with. Powers the qurl-api
# webhook-event drainer goroutine (qurl-service PR #874) once the
# activation PR sets `WEBHOOK_EVENTS_CONSUMER_ENABLED=true` +
# `WEBHOOK_EVENTS_SQS_QUEUE_URL=<this queue's URL>` on the ECS task. The
# drainer stays dormant when those env vars are absent, so this grant
# pre-positions the IAM without changing runtime behavior. (Same-account,
# cross-service — qurl-api task role + scanner Lambda role + queue all
# live in the qurl-service module in the same workload account; no
# assume-role hop here.)
#
# Gated identically to the queue itself: `qurl_scanner_lambda_enabled`.
# In an env without the producer Lambda, the queue doesn't exist and
# this grant has no target.
resource "aws_iam_role_policy" "task_resource_lifecycle_queue_consumer" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0
  name  = "resource-lifecycle-sqs-consume"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SQSConsumeResourceLifecycle"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
        ]
        Resource = [aws_sqs_queue.resource_lifecycle_queue[0].arn]
      },
      {
        Sid      = "KMSDecryptResourceLifecycleSQS"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
      },
    ]
  })
}

# Publish to the custom-domain cleanup topic on domain deletion. The Go side
# (cmd/qurl-api/main.go) gates the publisher on CUSTOM_DOMAIN_CLEANUP_TOPIC_ARN,
# so when the topic ARN is empty this resource is also absent — no idle role
# grants. The topic is encrypted with the AWS-managed `alias/aws/sns` key,
# which authorises in-account IAM principals to GenerateDataKey via SNS
# service usage from its own key policy — no explicit kms:* grant is needed
# here. (kms:Decrypt would be a consumer-side grant and is intentionally
# omitted; the publisher never decrypts.) The resource is scoped to the
# specific topic ARN, which is created in this same account — there is no
# cross-account confused-deputy surface here (the publisher principal is
# the ECS task role itself, not a service principal acting on its behalf).
resource "aws_iam_role_policy" "task_custom_domain_cleanup" {
  count = var.custom_domain_cleanup_publish_enabled ? 1 : 0
  name  = "custom-domain-cleanup-sns-publish"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SNSPublishCustomDomainCleanup"
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = [var.custom_domain_cleanup_topic_arn]
    }]
  })
}

# ==================== Security Groups ====================

resource "aws_security_group" "alb" {
  name_prefix = "${local.service_name}-alb-"
  vpc_id      = var.vpc_id
  description = "Security group for QURL API ALB"

  # HTTPS from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # HTTP redirect (optional)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect"
  }

  # Outbound to ECS tasks - restrict to VPC only (least privilege)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Outbound to VPC only"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-alb-sg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "ecs" {
  name_prefix = "${local.service_name}-ecs-"
  vpc_id      = var.vpc_id
  description = "Security group for QURL API ECS tasks"

  lifecycle {
    create_before_destroy = true

    # Without the internal ALB live, flipping enforce_internal_alb_only
    # to true removes the cidr_blocks rule and leaves ECS reachable only
    # from the public-ALB SG — internal callers (NHP server, AC Traefik)
    # lose their path entirely. Reject the combination at plan time.
    # The flip is reversible: setting enforce_internal_alb_only back to
    # false and re-applying restores the legacy bypass via in-place
    # AuthorizeSecurityGroupIngress.
    precondition {
      condition     = !var.enforce_internal_alb_only || var.internal_alb_enabled
      error_message = "enforce_internal_alb_only = true requires internal_alb_enabled = true. Stand up the internal ALB first (set qurl_internal_service_domain), verify, then flip enforce_internal_alb_only on a second apply. ROLLBACK: to disable the internal ALB entirely, you must flip BOTH qurl_enforce_internal_alb_only=false AND qurl_internal_service_domain=null in the same apply — flipping just the domain to null while enforce stays true trips this same precondition."
    }
  }

  # HTTP from public ALB (internet-facing)
  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "HTTP from public ALB"
  }

  # Legacy in-VPC bypass — kept while enforce_internal_alb_only = false so
  # operators can run sub-step 1A of the qurl-service-#335 rollout
  # non-disruptively (introduce internal ALB, verify, then flip
  # enforce_internal_alb_only to true to close the bypass on a second
  # apply). When this rule is gone, ECS tasks are reachable only from
  # the two ALB SGs (public + internal). The flip is in-place
  # (RevokeSecurityGroupIngress); no SG replacement.
  dynamic "ingress" {
    for_each = var.enforce_internal_alb_only ? [] : [1]
    content {
      from_port   = var.container_port
      to_port     = var.container_port
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
      description = "HTTP from VPC (legacy bypass - to be removed via enforce_internal_alb_only=true)"
    }
  }

  # Internal ALB ingress — kept inline alongside the public-ALB ingress
  # so all rules on this SG live in one block. AWS provider docs warn
  # that mixing inline ingress on aws_security_group with standalone
  # aws_security_group_rule resources targeting the same SG can cause
  # silent oscillation across applies; keeping everything inline
  # avoids that class entirely.
  dynamic "ingress" {
    for_each = var.internal_alb_enabled ? [1] : []
    content {
      from_port       = var.container_port
      to_port         = var.container_port
      protocol        = "tcp"
      security_groups = [aws_security_group.alb_internal[0].id]
      description     = "HTTP from internal ALB"
    }
  }

  # Bootstrap-ALB ingress (paired with modules/bootstrap-alb). The
  # bootstrap-ALB module deliberately widens its OWN egress to vpc_cidr
  # because cross-account SG references are brittle on the egress side
  # (see modules/bootstrap-alb/security_groups.tf header) — so this
  # SG-scoped ingress on the task SG is the load-bearing access control
  # between the bootstrap-ALB ENIs and qurl-service tasks ONCE the
  # legacy VPC-CIDR bypass closes. With enforce_internal_alb_only=false
  # (the current posture in both envs), the legacy bypass at the
  # `dynamic "ingress"` block above already admits any VPC-IP including
  # the bootstrap-ALB ENIs, so this rule is structurally redundant in
  # today's posture but forward-compat for the eventual flip to
  # enforce_internal_alb_only=true (qurl-service #335 second-stage).
  # Kept inline alongside the other ALB ingresses for the same reason
  # called out above. Null var → ingress elides.
  #
  # Pairing invariant: this ingress and the bootstrap-ALB load_balancer
  # block on aws_ecs_service.qurl (below) MUST be set together (both
  # var-driven gates must agree). The constraint is enforced by the
  # `precondition` on aws_ecs_service.qurl.lifecycle. If a future
  # refactor splits this SG resource out of this module (e.g., into a
  # shared modules/qurl-shared-sg/), MOVE OR DUPLICATE the precondition
  # so this side of the pair is also fenced — otherwise the invariant
  # quietly degrades.
  dynamic "ingress" {
    for_each = var.bootstrap_alb_security_group_id != null ? [1] : []
    content {
      from_port       = var.container_port
      to_port         = var.container_port
      protocol        = "tcp"
      security_groups = [var.bootstrap_alb_security_group_id]
      description     = "HTTP from bootstrap ALB"
    }
  }

  # All outbound (DynamoDB, Secrets Manager, Redis, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-sg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# Internal ALB security group. Lives in private subnets, accepts only
# in-VPC traffic on 443. Distinct from aws_security_group.alb so the
# public-vs-internal trust boundary is structural, not just commentary.
resource "aws_security_group" "alb_internal" {
  count       = var.internal_alb_enabled ? 1 : 0
  name_prefix = "${local.service_name}-alb-internal-"
  vpc_id      = var.vpc_id
  description = "Security group for QURL API internal ALB (VPC-only)"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS from VPC"
  }

  # Egress scoped to vpc_cidr because the only legitimate next hop is
  # the qurl-service ECS task ENIs, which live in this VPC. If the
  # service ever grows a cross-VPC peering / TGW path (e.g. backend in
  # a peered VPC), extend this with the additional reachable CIDRs —
  # otherwise the failure shows up as the ALB silently 504-ing health
  # checks with no SG-level signal.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Outbound to VPC only"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-alb-internal-sg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Allow ECS tasks to connect to Redis (if enabled)
resource "aws_security_group_rule" "ecs_to_redis" {
  count = var.redis_enabled ? 1 : 0

  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = var.redis_security_group_id
  description              = "Redis from QURL ECS tasks (ElastiCache Serverless port 6379)"
}

# ==================== ECS Task Definition ====================

resource "aws_ecs_task_definition" "qurl" {
  family                   = local.service_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = local.task_cpu
  memory                   = local.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  # Note: Initial deployment uses "latest" tag from SSM parameter default value.
  # CI pipeline updates the SSM parameter and deploys new task definitions independently.
  # Terraform ignores task_definition changes after initial creation (lifecycle.ignore_changes).
  container_definitions = jsonencode(concat(
    # QURL API container (always present)
    [{
      name  = "qurl-api"
      image = "${var.ecr_repo_url}:${aws_ssm_parameter.image_tag.value}"

      portMappings = [{
        containerPort = var.container_port
        protocol      = "tcp"
      }]

      environment = local.container_env
      secrets     = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qurl.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # ECS container health check - uses liveness probe (fast, no dependency checks)
      # /health/live only verifies the service is running, not that dependencies are healthy
      # Note: Container uses Alpine with wget, not curl
      healthCheck = {
        command     = ["CMD-SHELL", "wget --quiet --tries=1 --spider http://localhost:${var.container_port}/health/live || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      # Increase file descriptor limits to prevent resource exhaustion under load
      ulimits = [{
        name      = "nofile"
        softLimit = 65536
        hardLimit = 65536
      }]
    }],
    # ADOT Collector sidecar (only when Grafana Cloud is enabled)
    # Receives OTLP from QURL container and exports to Grafana Cloud
    # Config is inline below; keep files/otel-collector-config.yaml in sync for reference
    var.grafana_cloud_enabled ? [{
      name      = "adot-collector"
      image     = var.adot_collector_image
      essential = false # Allow main container to continue if sidecar fails

      portMappings = [
        { containerPort = 4317, protocol = "tcp" }, # OTLP gRPC
        { containerPort = 4318, protocol = "tcp" }, # OTLP HTTP
      ]

      secrets = [
        { name = "GRAFANA_OTLP_ENDPOINT", valueFrom = "${var.grafana_secret_arn}:endpoint::" },
        { name = "GRAFANA_OTLP_AUTH", valueFrom = "${var.grafana_secret_arn}:auth::" },
      ]

      # Use inline config via AOT_CONFIG_CONTENT environment variable
      # This avoids needing to mount the config file from S3
      command = ["--config=env:AOT_CONFIG_CONTENT"]

      # ADOT collector config embedded as environment variable
      # See files/otel-collector-config.yaml for the source config
      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        {
          name = "AOT_CONFIG_CONTENT"
          value = yamlencode({
            extensions = {
              health_check = {
                endpoint = "0.0.0.0:13133"
              }
            }
            receivers = {
              otlp = {
                protocols = {
                  grpc = { endpoint = "0.0.0.0:4317" }
                  http = { endpoint = "0.0.0.0:4318" }
                }
              }
            }
            processors = {
              # Prevent OOM by limiting memory usage - critical for sidecar containers
              memory_limiter = {
                check_interval  = "1s"
                limit_mib       = 200
                spike_limit_mib = 50
              }
              batch = {
                timeout         = "10s"
                send_batch_size = 1024
              }
              resourcedetection = {
                detectors = ["env", "ecs"]
                timeout   = "5s"
                override  = false
              }
              attributes = {
                actions = [
                  {
                    key    = "deployment.environment"
                    value  = var.environment
                    action = "upsert"
                  },
                  {
                    key    = "cell.id"
                    value  = var.cell_id
                    action = "upsert"
                  }
                ]
              }
            }
            exporters = {
              otlphttp = {
                endpoint = "$${GRAFANA_OTLP_ENDPOINT}"
                headers = {
                  Authorization = "Basic $${GRAFANA_OTLP_AUTH}"
                }
              }
            }
            service = {
              extensions = ["health_check"]
              pipelines = {
                traces = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
                metrics = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
                logs = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
              }
            }
          })
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qurl.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "adot"
        }
      }

      healthCheck = {
        command     = ["CMD", "/healthcheck"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }] : []
  ))

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  # Validate Fargate CPU/memory combinations at plan time
  # See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  # Note: When grafana_cloud_enabled=true, CPU is set to max(container_cpu, 512) and memory is increased by 256MB
  lifecycle {
    precondition {
      condition = (
        # When ADOT sidecar is enabled, effective CPU is max(container_cpu, 512) and memory += 256
        var.grafana_cloud_enabled ? (
          # Effective CPU: max(container_cpu, 512)
          # Effective memory: container_memory + 256
          (max(var.container_cpu, 512) == 512 && (var.container_memory + 256) >= 1024 && (var.container_memory + 256) <= 4096) ||
          (max(var.container_cpu, 512) == 1024 && (var.container_memory + 256) >= 2048 && (var.container_memory + 256) <= 8192) ||
          (max(var.container_cpu, 512) == 2048 && (var.container_memory + 256) >= 4096 && (var.container_memory + 256) <= 16384) ||
          (max(var.container_cpu, 512) == 4096 && (var.container_memory + 256) >= 8192 && (var.container_memory + 256) <= 30720) ||
          (max(var.container_cpu, 512) == 8192 && (var.container_memory + 256) >= 16384 && (var.container_memory + 256) <= 61440) ||
          (max(var.container_cpu, 512) == 16384 && (var.container_memory + 256) >= 32768 && (var.container_memory + 256) <= 122880)
          ) : (
          # Original validation when ADOT is disabled
          (var.container_cpu == 256 && var.container_memory >= 512 && var.container_memory <= 2048) ||
          (var.container_cpu == 512 && var.container_memory >= 1024 && var.container_memory <= 4096) ||
          (var.container_cpu == 1024 && var.container_memory >= 2048 && var.container_memory <= 8192) ||
          (var.container_cpu == 2048 && var.container_memory >= 4096 && var.container_memory <= 16384) ||
          (var.container_cpu == 4096 && var.container_memory >= 8192 && var.container_memory <= 30720) ||
          (var.container_cpu == 8192 && var.container_memory >= 16384 && var.container_memory <= 61440) ||
          (var.container_cpu == 16384 && var.container_memory >= 32768 && var.container_memory <= 122880)
        )
      )
      error_message = "Invalid Fargate CPU/memory combination. See AWS docs for valid combinations. When grafana_cloud_enabled=true, effective CPU is max(container_cpu, 512) and memory is increased by 256MB."
    }

    precondition {
      condition     = var.environment != "prod" || (var.cors_allowed_origins != "" && var.cors_allowed_origins != "*")
      error_message = "Production requires explicit CORS origins, not empty or wildcard."
    }

    precondition {
      condition     = var.environment != "prod" || startswith(local.computed_api_base_url, "https://")
      error_message = "Production requires HTTPS: API_BASE_URL must use https:// in prod environment. Either provide certificate_arn or set api_base_url to an https:// URL."
    }

    # Fails at plan time if QURL_TRUSTED_PROXY_CIDRS would be empty —
    # qurl-service prod hard-fails startup on that condition, so catching
    # it here gives operators a pre-apply error instead of a mid-rollout
    # container crash. Relies on local.alb_subnet_cidrs being derived
    # from var.public_subnet_ids, so a misconfigured module call surfaces
    # here before it reaches the running service.
    precondition {
      condition     = length(local.alb_subnet_cidrs) > 0
      error_message = "QURL_TRUSTED_PROXY_CIDRS would be empty: var.public_subnet_ids must resolve to at least one subnet with a cidr_block (qurl-service hard-fails startup in prod on an empty trust list)."
    }

    # Activation-flag coherence: `local.container_env` above conditionally
    # references `aws_sqs_queue.resource_lifecycle_queue[0].url` when
    # `qurl_scanner_sqs_emit_enabled = true`. The queue resource has
    # `count = qurl_scanner_lambda_enabled ? 1 : 0` (see
    # resource_lifecycle_queue.tf), so flipping emit-enabled with
    # Lambda-disabled would fail plan with a bare `Invalid index` on
    # the `[0]` lookup. Catch it here with a copy-pasteable error
    # instead. This task def resource has NO count gate (always
    # planned), so the precondition always evaluates — unlike the
    # scanner Lambda which is count-gated on `qurl_scanner_lambda_enabled`
    # and would skip its own preconditions when disabled. cr #2471 r1.
    precondition {
      condition     = !var.qurl_scanner_sqs_emit_enabled || var.qurl_scanner_lambda_enabled
      error_message = "qurl_scanner_sqs_emit_enabled=true requires qurl_scanner_lambda_enabled=true. Without the Lambda the resource_lifecycle_queue doesn't exist, so the qurl-api task def's WEBHOOK_EVENTS_SQS_QUEUE_URL env var (and the scanner Lambda's QURL_SCANNER_SQS_QUEUE_URL) reference `aws_sqs_queue.resource_lifecycle_queue[0].url` against count=0 → `Invalid index`. Set qurl_scanner_lambda_enabled = true (or leave qurl_scanner_sqs_emit_enabled = false until the Lambda is enabled)."
    }
    precondition {
      condition     = !var.qurl_scanner_tombstone_write_enabled || var.qurl_scanner_sqs_emit_enabled
      error_message = "qurl_scanner_tombstone_write_enabled=true requires qurl_scanner_sqs_emit_enabled=true. Tombstone writes are destructive and qurl-scanner rejects tombstone-write runs without the SQS consumer path; flip SQS emit/consumer first, then enable tombstone writes in a later apply."
    }
    precondition {
      condition     = !var.qurl_scanner_active_recheck_enabled || var.qurl_scanner_tombstone_write_enabled
      error_message = "qurl_scanner_active_recheck_enabled=true requires qurl_scanner_tombstone_write_enabled=true. Burn in SQS emit/consumer and per-minute tombstone writes first, then enable the broad active-resource recheck scheduler in a later apply."
    }
  }
}

# ==================== Application Load Balancer ====================

resource "aws_lb" "qurl" {
  name               = replace(local.short_name, "_", "-")
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  # The set of subnets here is also the source for QURL_TRUSTED_PROXY_CIDRS
  # (see data.aws_subnet.alb + local.alb_subnet_cidrs). If you change this
  # binding — e.g. move the ALB to a different subnet set — also re-point
  # data.aws_subnet.alb, or the trust list will silently drift from the
  # actual ALB origin IPs and reopen a narrow XFF-spoofing class.
  subnets = var.public_subnet_ids

  # Access logging for production audit compliance
  dynamic "access_logs" {
    for_each = var.alb_access_logs_bucket != null ? [1] : []
    content {
      bucket  = var.alb_access_logs_bucket
      prefix  = var.alb_access_logs_prefix
      enabled = true
    }
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.alb_access_logs_bucket != null
      error_message = "ALB access logs bucket is required for production environments for audit compliance."
    }
  }
}

resource "aws_lb_target_group" "qurl" {
  name        = replace("${var.name_prefix}-${var.cell_id}-qurl", "_", "-")
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # Match compute/AC modules (30s). AWS default is 300s which delays
  # post-deploy smoke tests — old tasks serve stale responses during draining.
  deregistration_delay = 30

  # ALB health check - uses readiness probe (deep dependency checks)
  # /health/ready verifies all critical dependencies are healthy before routing traffic
  # Returns 200 for healthy/degraded, 503 for unhealthy (critical dependency failure)
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health/ready"
    matcher             = "200"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-tg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# HTTPS Listener (requires certificate)
# Note: count uses domain_name (not certificate_arn) because certificate_arn may be
# computed at apply time (e.g., from aws_acm_certificate_validation), which would
# cause "Invalid count argument" errors during terraform plan.
#
# Listener-rule priority slots:
#   - priority = 1: reserved for `aws_lb_listener_rule.public_internal_block`
#     (the /internal/* lockdown). Must remain first-evaluated; no
#     business rule should claim slot 1.
#   - priority >= 2: business rules.
# AWS rejects priority collisions on the CreateRule API call (i.e.,
# at apply time, not plan time), so the slot is exclusive without
# runtime checks — adding a rule at priority 1 here would pass plan
# and fail apply.
resource "aws_lb_listener" "https" {
  count = var.domain_name != null ? 1 : 0

  load_balancer_arn = aws_lb.qurl.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qurl.arn
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-https"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# Public ALB /internal/* lockdown (qurl-service #335 PR4).
#
# Returns 404 (not 403) for any /internal* path on the public ALB —
# 404 avoids leaking that the path exists ("path not found" looks the
# same as a typo'd public path), so an external scanner can't enumerate
# the internal surface from this signal alone.
#
# Gate: both `domain_name` (the HTTPS listener exists) AND
# `internal_alb_enabled` (consumers have an in-VPC alternative). On
# greenfield envs without the internal ALB the rule is absent and the
# public path keeps serving — locking it down without an alternative
# would break the QURL plugin / AC qurl-router / FRP auth path.
#
# Priority 1 makes this the first-evaluated rule (lower number =
# higher precedence in AWS ALB). It is NOT a blanket deny — only
# the path_patterns below 404; everything else still falls through
# to the default forward action on the listener. The structural
# guarantee priority 1 buys is that no other rule can ever preempt
# this match: AWS rejects priority collisions on the CreateRule
# API call (i.e., at apply time, not plan time), so the slot is
# exclusive. Future business rules pick priority >= 2, and a
# narrower-pattern shadow at higher precedence is impossible. The
# Priority 1 (first-evaluated) was chosen over priority 100 + a
# describe-rules probe: the latter would require runtime verification
# that no rule with priority < 100 has an overlapping pattern, which
# is a soft guarantee. AWS-side priority-collision rejection is a
# hard structural fence.
#
# Attached to the HTTPS listener only. The HTTP listener (port 80) is
# redirect-only when `domain_name != null`, so HTTP probes go through
# the 301 → HTTPS chain and hit the lockdown after redirect. A
# parallel rule on the HTTP listener would never be reached.
#
# Path patterns cover four bypass classes:
#   - `/internal` (bare): AWS ALB's `*` matches 0+ characters, so
#     `/internal/*` matches `/internal/` (trailing slash, zero chars
#     after). What it does NOT match is `/internal` with no trailing
#     slash — that requires the literal `/`. The bare entry fences
#     the `https://api/internal` prefix-fishing class. Note: paths
#     like `/internalfoo` (no separator) ALSO fall through — they're
#     a different namespace and gin's 404 at the backend catches them.
#   - `/internal/*` (canonical): the production path for /internal/v1/*.
#   - `/Internal` + `/Internal/*` (capitalized): AWS ALB
#     path_pattern is case-sensitive; the rule covers the two most
#     likely typos (Title case bare + canonical), mirroring the
#     lowercase pair. Fully-uppercase / mixed-case variants are NOT
#     covered and rely on gin's case sensitivity at the backend.
#   - `/*../internal/*` (literal-`..`-substring): AWS ALB performs
#     RFC 3986 § 5.2.4 dot-segment removal on the request path BEFORE
#     matching `path_pattern` conditions, so an actual traversal-shaped
#     attack like `/v1/qurls/../internal/v1/resolve` is normalized to
#     `/v1/internal/v1/resolve` and matches NONE of the entries above —
#     but it also can't reach the internal handler (same normalized
#     path arrives at the backend). The canonical traversal class is
#     therefore structurally fenced by `/internal/*` after ALB
#     normalization, not by this glob. The empirical verification is
#     pinned by the `normalizes_to_canonical` subtest in
#     `tests/smoke/09_public_alb_internal_lockdown_test.go` (see PR
#     #1893 for the curl `--path-as-is` evidence).
#
#     What this slot DOES fence is the literal-`..`-substring class:
#     paths like `/foo/bar../internal/baz` where `bar..` is a single
#     non-traversal segment (RFC 3986 only collapses segments that
#     are exactly `.` or `..`). The slot is thinly utilized — this
#     synthetic shape has no production analogue — and a future review
#     may swap it for `/INTERNAL` + `/INTERNAL/*` to close the
#     uppercase case-variant gap at the ALB rather than at gin
#     (tracked in #1897).
#
#     The `/*../internal/*` glob depends on AWS ALB's `*` matching
#     ANY character including `/` (per AWS docs: "0 or more of any
#     character"). If AWS ever path-segment-bounded `*`,
#     `/*../internal/*` would no longer match
#     `/foo/bar../internal/baz`, narrowing the fence silently. The
#     `primary` smoke subtest fences slash-spanning `*` semantics
#     via the canonical pattern; the `bare_prefix_trailing_slash`
#     subtest fences the orthogonal zero-char `*` axis.
#
#     False-positive surface is empty today (no public path uses
#     literal `..`); if a future public path ever needs literal `..`
#     segments (e.g., a generated archive viewer), this pattern will
#     need to be split or the path will need to be namespaced under
#     a different prefix to dodge the glob. Tracked in #1641.
#
# Trust-model boundary: this listener rule fences the network layer
# only (public-internet reachability of /internal/*). The auth layer
# (X-Service-Token check at qurl-service handlers) is the second
# line — if it ever bypasses, only the in-VPC bound remains. Tier 2
# fence on that check is tracked in qurl-service#439.
#
# Slot budget: AWS ALB caps a single path_pattern condition at 5
# values, and all 5 are used by the bypass-class taxonomy below.
# Adding a 6th class (e.g., `/INTERNAL*` for fully-uppercase) cannot
# extend this list — it requires a SECOND `aws_lb_listener_rule` at
# priority 2 with the additional patterns (a second condition block
# on this rule would AND-narrow the match to zero). Don't waste a
# plan cycle finding this out empirically.
#
# Body-shape leak: the fixed-response body `{"error":"not found"}`
# is itself a fingerprint distinguishing a lockdown match from a
# real backend 404 (gin emits `text/plain "404 page not found"` as
# its default). An attacker probing the surface can use this
# differential to enumerate which paths the lockdown covers — a
# small leak counter to the original "404 not 403 to avoid existence
# leaks" rationale. Accepted tradeoff: the JSON body is a strong
# triage signal in CloudWatch / runner logs (the smoke fence
# discriminates on it), and an attacker probing has to compare
# against the public-path baseline regardless. If this leak ever
# matters, change the body to mimic gin's plain text and keep the
# triage signal in a header instead.
#
# ── Lockdown body: single source of truth (#1645, Path B) ───────────────────
# This is the CANONICAL explanation; the message_body and SSM-parameter
# comments below carry only their site-local facts and refer back here.
#
# local.public_internal_lockdown_body is the one place the body is authored. It
# feeds BOTH the rule's fixed_response.message_body AND
# aws_ssm_parameter.public_internal_lockdown_body, so an apply can never leave
# the served body and the smoke fence's expected body out of sync. The fence
# reads the SSM parameter — NOT a DescribeRules read of the rule it probes — so
# an out-of-band edit to the live rule moves the wire response but not the
# parameter, and the fence flips red (acceptance criterion #5); a self-sourced
# expected value never could.
#
# Trust model (cf. the cellIDPattern note elsewhere in this file): the
# guarantee rests on Terraform re-pinning the parameter every apply. An
# out-of-band `aws ssm put-parameter` could move the expected value to match a
# tampered rule and mask a body edit until the next apply re-pins it. Note this
# is a small REDUCTION in tamper-resistance vs. the prior Go-literal expected
# value, not a wash: before #1645 the expected body lived in version control, so
# masking a body edit meant tampering the live rule AND landing a reviewed code
# change; now both the rule and the expected value are movable with the same AWS
# write creds, no PR. Acceptable because this is a post-deploy smoke fence (not a
# runtime control) and the next apply reverts the mask — but state it plainly.
locals {
  public_internal_lockdown_body = jsonencode({ error = "not found" })
}

resource "aws_lb_listener_rule" "public_internal_block" {
  count = var.domain_name != null && var.internal_alb_enabled ? 1 : 0

  # `one(...)` is defensive: this resource's gate is strictly tighter
  # than `aws_lb_listener.https`'s (`var.domain_name != null` plus the
  # internal-ALB predicate), so [0] is safe today. `one()` keeps that
  # invariant explicit and fails plan with a clearer message if a
  # future gate change inverts it.
  listener_arn = one(aws_lb_listener.https[*].arn)
  priority     = 1

  action {
    type = "fixed-response"
    # message_body comes from local.public_internal_lockdown_body (the single
    # source of truth — see the local's comment above); the body shape is no
    # longer duplicated as a Go literal, so changing it needs no Go edit.
    # content_type and status_code, however, ARE still mirrored as Go literals
    # (publicALBLockdownExpectedCT / publicALBLockdownExpectedStatus): status
    # deliberately — an independent 404 invariant the fence must not source from
    # the rule it probes — and content_type pending the #1642 text/plain switch.
    # Change either of those two → update the matching Go literal in the SAME PR.
    fixed_response {
      content_type = "application/json"
      message_body = local.public_internal_lockdown_body
      status_code  = "404"
    }
  }

  condition {
    # Slot budget: see resource header comment above. Order below is
    # by likelihood-of-bypass: bare and canonical lowercase patterns
    # first, then case + traversal defense-in-depth. The case +
    # traversal combination (`/*../Internal/*`) is intentionally
    # omitted — gin's case sensitivity at the backend is the second
    # line on case bypass already.
    path_pattern {
      values = [
        "/internal",
        "/internal/*",
        "/Internal",
        "/Internal/*",
        # NOT in this list (would need a 6th slot — see resource
        # header for slot-budget guidance): `/INTERNAL` and
        # `/INTERNAL/*` (fully-uppercase). Backstopped by gin's
        # case sensitivity at qurl-service today, fenced by
        # tests/smoke/09_*.go::TestPublicALB_GinCaseBackstop
        # at runtime. If qurl-service ever migrates to a
        # case-folding router, that test surfaces the regression
        # and a second `aws_lb_listener_rule` (priority 2) becomes
        # necessary to add the uppercase variants.
        "/*../internal/*",
      ]
    }
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-internal-lockdown"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# Smoke-fence source of truth for the lockdown body (#1645, Path B — see
# local.public_internal_lockdown_body's comment above for WHY this exists and
# how it makes the fence catch out-of-band edits). Read at startup by
# tests/smoke/setup_test.go via
# aws_helpers.go::resolvePublicALBLockdownExpectedBody; no runtime consumer
# other than smoke. Site-local facts:
#   - Gated on the EXACT condition as the rule above, so it exists iff the rule
#     does; value sources the shared local, so it can't drift from the rule.
#   - No new IAM: the smoke runner role already has ssm:Get*
#     (terraform/modules/ecr/main.tf "SSMRead").
#   - Env-scoped (/${var.environment}/nhp/...) to match the smoke suite's other
#     reads (/{env}/nhp/deploy/*, .../server/*), NOT this module's
#     /${var.name_prefix}/qurl-* params — smoke is uniformly bare-{env} scoped
#     and must not have to know name_prefix. One qurl-service instance per env
#     today makes this unambiguous; cell-scoping is deferred to #1448 with the rest.
#   - No lifecycle.ignore_changes: Terraform-owned end to end (no CI/CD writer),
#     so every apply re-pins it to the local.
resource "aws_ssm_parameter" "public_internal_lockdown_body" {
  count = var.domain_name != null && var.internal_alb_enabled ? 1 : 0

  name        = "/${var.environment}/nhp/qurl/internal-lockdown-body"
  description = "qurl-service public-ALB /internal/* lockdown fixed-response body; smoke-fence expected-value source (#1645)"
  type        = "String"
  value       = local.public_internal_lockdown_body

  tags = merge(var.tags, {
    Name      = "${local.service_name}-internal-lockdown-body"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# HTTP Listener (redirect to HTTPS when domain configured, otherwise forward)
# WARNING: When domain_name is null, traffic is served over unencrypted HTTP.
# This should only be used during initial setup before certificate provisioning.
# For production, always provide a domain_name (which implies certificate).
resource "aws_lb_listener" "http" {
  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.domain_name != null
      error_message = "Production requires HTTPS: domain_name must be provided for prod environment."
    }
  }

  load_balancer_arn = aws_lb.qurl.arn
  port              = 80
  protocol          = "HTTP"

  # When domain is configured, redirect HTTP to HTTPS
  # When no domain, forward directly to target group (HTTP only mode)
  dynamic "default_action" {
    for_each = var.domain_name != null ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.domain_name == null ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.qurl.arn
    }
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-http"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== Internal ALB ====================
# Second ALB, internal=true, in private subnets. Forwards to its own
# target group (`aws_lb_target_group.qurl_internal`) — AWS rejects
# associating one TG with more than one LB (`TargetGroupAssociationLimit`),
# so the public and internal ALBs each own a TG and ECS registers tasks
# in both via paired `load_balancer` blocks below. Future readers: do
# not consolidate the TGs.

resource "aws_lb" "qurl_internal" {
  count = var.internal_alb_enabled ? 1 : 0
  # `-i` (not `-int`) keeps the name within AWS's 32-char ALB-name limit:
  # local.short_name is 29 chars in sandbox; `-int` would push to 33 and
  # only fail at apply time, not validate. local.internal_alb_name is the
  # single-source-of-truth value used here, by aws_lb_target_group.qurl_internal,
  # and by both name-length preconditions.
  name               = local.internal_alb_name
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_internal[0].id]
  subnets            = var.private_subnet_ids

  # Set explicitly here as a security default for the internal ALB. The
  # public ALB at aws_lb.qurl does NOT set this and inherits the AWS
  # default of false. The two ALBs are intentionally not symmetric on
  # this attr while layervai/nhp#1589 (harden the public ALB to match)
  # is pending; this is stricter, not laxer.
  drop_invalid_header_fields = true

  # Internal ALB intentionally has no access_logs configured. In-VPC
  # traffic is logged via VPC Flow Logs and ECS-side request logs.
  # See layervai/nhp#1592 for turning ALB-level logs on if audit policy
  # demands them.

  tags = merge(var.tags, {
    Name      = "${local.service_name}-internal-alb"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = !var.internal_alb_enabled || var.internal_domain_name != null
      error_message = "internal_alb_enabled = true requires internal_domain_name to be set."
    }
    precondition {
      condition     = !var.internal_alb_enabled || var.internal_certificate_arn != null
      error_message = "internal_alb_enabled = true requires internal_certificate_arn to be set."
    }
    # Catch the 32-char overflow at plan time — terraform validate doesn't
    # see this, so a future name_prefix that grows would otherwise fail
    # mid-apply with an opaque AWS API error.
    precondition {
      condition     = !var.internal_alb_enabled || local.internal_name_fits
      error_message = "Internal ALB name '${local.internal_alb_name}' exceeds AWS 32-char limit. Shorten name_prefix or cell_id."
    }
  }
}

resource "aws_lb_target_group" "qurl_internal" {
  count = var.internal_alb_enabled ? 1 : 0

  # Shares local.internal_alb_name with aws_lb.qurl_internal — AWS allows
  # an LB and TG to share a name (different resource types, distinct ARNs).
  name        = local.internal_alb_name
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health/ready"
    matcher             = "200"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-internal-tg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = !var.internal_alb_enabled || local.internal_name_fits
      error_message = "Internal TG name '${local.internal_alb_name}' exceeds AWS 32-char limit. Shorten name_prefix or cell_id."
    }
  }
}

# Internal-only is enforced by reachability (NXDOMAIN externally +
# internal=true), not by path filtering at this listener — the internal
# ALB serves every path the TG serves. PR4 adds the symmetric 404 rule
# on the *public* ALB for /internal/* paths.
resource "aws_lb_listener" "qurl_internal_https" {
  count = var.internal_alb_enabled ? 1 : 0

  load_balancer_arn = aws_lb.qurl_internal[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.internal_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qurl_internal[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-internal-https"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== ECS Service ====================

resource "aws_ecs_service" "qurl" {
  name            = local.service_name
  cluster         = aws_ecs_cluster.qurl.id
  task_definition = aws_ecs_task_definition.qurl.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.qurl.arn
    container_name   = "qurl-api"
    container_port   = var.container_port
  }

  # Register the same task IPs in the internal-ALB target group. Adding
  # this block is in-place on AWS provider 4+ (terraform-provider-aws
  # #23600 + #23786, merged 2022-03), so no Fargate service replacement.
  dynamic "load_balancer" {
    for_each = var.internal_alb_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.qurl_internal[0].arn
      container_name   = "qurl-api"
      container_port   = var.container_port
    }
  }

  # Register the same task IPs in the bootstrap-ALB target group (paired
  # with modules/bootstrap-alb — see its target_group_arn output's
  # description). Same in-place-add property as the internal block above.
  # Null var → block elides, pre-Wave-5 posture unchanged.
  #
  # Cross-module ordering: the bootstrap-ALB's listener lives inside the
  # bootstrap-alb module. Referencing var.bootstrap_alb_target_group_arn
  # creates an implicit cross-module dep on the TG, but NOT on the listener
  # (listener depends on TG, not the reverse), so on a fresh first-apply
  # where bootstrap-alb is created in the same run, ECS CreateService can
  # race the listener attach and fail with InvalidParameterException —
  # ECS does NOT retry RegisterTargets across that error. The env-root
  # closes this gap with `module.qurl_service.depends_on = [
  # module.bootstrap_alb]` so the whole module waits for the bootstrap-ALB
  # apply (listener included) to settle. On incremental applies
  # (bootstrap-alb already present in state, this attachment added later)
  # there is no race regardless.
  dynamic "load_balancer" {
    for_each = var.bootstrap_alb_target_group_arn != null ? [1] : []
    content {
      target_group_arn = var.bootstrap_alb_target_group_arn
      container_name   = "qurl-api"
      container_port   = var.container_port
    }
  }

  # Prevent premature unhealthy marking during slow container startups
  health_check_grace_period_seconds = 60

  # Allow external deployment tools (CI) to update the service
  deployment_controller {
    type = "ECS"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Ignore changes to desired_count (managed by auto-scaling) and task_definition (managed by CI)
  lifecycle {
    ignore_changes = [desired_count, task_definition]

    # bootstrap_alb_target_group_arn and bootstrap_alb_security_group_id
    # must be set together (both null OR both non-null). Enforced here
    # rather than as a cross-var validation block on the variables because
    # symmetric var.A.validation ↔ var.B.validation references form a
    # terraform plan-time cycle. The two referenced failure modes are the
    # ones that would silently break the bootstrap data plane.
    precondition {
      condition     = (var.bootstrap_alb_target_group_arn == null) == (var.bootstrap_alb_security_group_id == null)
      error_message = "bootstrap_alb_target_group_arn and bootstrap_alb_security_group_id must be set together (both null OR both non-null). Setting only the TG leaves the task SG without bootstrap-ALB ingress (registration succeeds, health checks 100% fail); setting only the SG omits the ECS load_balancer block, leaving the bootstrap-ALB TG with no registered targets (ingress allowed, but the ECS service never registers tasks)."
    }
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  # Listener-before-service ordering: ECS rejects RegisterTargets on a TG
  # not yet attached to a listener. The qurl_internal_https reference is
  # safe when internal_alb_enabled = false (count=0 → empty dep set).
  depends_on = [aws_lb_listener.http, aws_lb_listener.qurl_internal_https]
}

# ==================== Route53 Record ====================

resource "aws_route53_record" "qurl" {
  count = var.domain_name != null && var.hosted_zone_id != null ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.qurl.dns_name
    zone_id                = aws_lb.qurl.zone_id
    evaluate_target_health = true
  }
}

# ==================== Auto Scaling ====================

resource "aws_appautoscaling_target" "qurl" {
  count = local.is_prod ? 1 : 0

  max_capacity       = var.autoscaling_max_capacity
  min_capacity       = var.autoscaling_min_capacity
  resource_id        = "service/${aws_ecs_cluster.qurl.name}/${aws_ecs_service.qurl.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  count = local.is_prod ? 1 : 0

  name               = "${local.service_name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.qurl[0].resource_id
  scalable_dimension = aws_appautoscaling_target.qurl[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.qurl[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
