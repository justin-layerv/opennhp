# LayerV NHP Infrastructure
# Consistent with layerv/traefik-plugins terraform patterns
#
# Multi-account architecture:
# - Sandbox (layerv): Primary account, owns ECR repositories
# - Production (layerv-prod): Secondary account, pulls from sandbox ECR cross-account

terraform {
  required_version = "~> 1.14" # Pessimistic constraint - allows 1.14.x patches only

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.27"
      configuration_aliases = [aws.us_east_1, aws.route53_mgmt, aws.billing_mgmt]
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    grafana = {
      source  = "grafana/grafana"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}

# Grafana provider for dashboards module
# Configured with URL and auth from variables. Only used when grafana_dashboards_enabled=true.
provider "grafana" {
  url                = coalesce(var.grafana_url, "https://grafana.placeholder.local")
  auth               = var.grafana_auth
  retries            = 3
  retry_status_codes = ["429", "500", "502", "503"]
  retry_wait         = 10
}


# Validate standalone AC license credentials when deploy_ac is enabled
check "ac_license_credentials" {
  assert {
    condition = (
      var.deploy_ac == false || (
        var.ac_customer_id != null &&
        var.ac_license_key != null &&
        var.ac_license_key_hash != null &&
        var.ac_license_key_sha256 != null
      )
    )
    error_message = <<-EOT
      When deploy_ac = true, standalone AC license credentials are required:
        - ac_customer_id (ULID format)
        - ac_license_key (plaintext)
        - ac_license_key_hash (bcrypt hash)
        - ac_license_key_sha256 (SHA256 hash)

      Generate with: ./terraform/scripts/generate-ac-license.sh <environment>
    EOT
  }
}

# Note: Provider configurations are defined in environments/*/backend.tf
# This module expects to receive aws and aws.us_east_1 providers from the caller

# ==================== Data Sources ====================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ==================== Account Validation ====================

# Validate we're in the expected account (matches traefik-plugins pattern)
resource "null_resource" "account_validation" {
  count = data.aws_caller_identity.current.account_id != var.aws_account_id ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERROR: Running in account ${data.aws_caller_identity.current.account_id} but expected ${var.aws_account_id}' && exit 1"
  }
}

# Validate qurl_router requires qurl_service_domain.
# qurl_service_domain remains required even after qurl-service #335 introduced
# the internal-ALB path: it's the public ALB cert hostname AND the fallback
# api_url for greenfield envs that haven't set qurl_internal_service_domain
# (see the qurl_router_config.api_url ternary in the ac module wiring below).
# The internal-ALB path uses qurl_internal_service_domain with its own ACM cert.
# There is no symmetric check for qurl_internal_service_domain: its absence
# falls through to the public domain by design (greenfield safety).
resource "null_resource" "qurl_router_domain_validation" {
  count = var.qurl_router_enabled && var.qurl_service_domain == null ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERROR: qurl_router_enabled=true requires qurl_service_domain to be set (needed for HTTPS API calls)' && exit 1"
  }
}

# `enable_qurl_site_authz=true` is only meaningful when the qurl-router
# middleware is actually rendered into Traefik's dynamic config. That
# render is gated on `deploy_qurl_service && qurl_router_enabled` at
# the module-input assembly (see `qurl_router_config` in this file), so
# flipping the authz flag without those preconditions makes the flag
# silently a no-op — an operator-confusion trap. Fail at plan time
# instead.
resource "terraform_data" "qurl_site_authz_preconditions" {
  count = var.enable_qurl_site_authz ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.qurl_router_enabled
      error_message = "enable_qurl_site_authz=true requires qurl_router_enabled=true. Without the qurl-router middleware, the *.qurl.site branch isn't routed through this plugin and the L7 gate has no execution path."
    }
    precondition {
      condition     = var.deploy_qurl_service
      error_message = "enable_qurl_site_authz=true requires deploy_qurl_service=true. The L7 gate calls qurl-service's /internal/v1/resource/:id/authorize endpoint; without the service deployed, every request fails closed (silentDrop)."
    }
  }
}

# qurl-service's active-registration read gate makes `upstream_addrs`
# authoritative for tunnel resources. A half flip is worse than a no-op:
# without reporter writes it fails tunnels closed, and without router
# discovery the per-instance private endpoints are rejected by the AC
# allowlist. Keep the rollout contract encoded at plan time.
resource "terraform_data" "qurl_tunnel_active_registration_preconditions" {
  count = var.qurl_tunnel_active_registrations_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.qurl_tunnel_auth_enabled
      error_message = "qurl_tunnel_active_registrations_enabled=true requires qurl_tunnel_auth_enabled=true so qurl-service mounts the tunnel auth and registration endpoints."
    }
    precondition {
      condition     = var.deploy_frps
      error_message = "qurl_tunnel_active_registrations_enabled=true requires deploy_frps=true so qurl-reverse-tunnel-server can publish active target rows."
    }
    precondition {
      condition     = var.qurl_router_enabled
      error_message = "qurl_tunnel_active_registrations_enabled=true requires qurl_router_enabled=true so qurl-router consumes upstream_addrs."
    }
    precondition {
      condition     = var.enable_instance_hrw
      error_message = "qurl_tunnel_active_registrations_enabled=true requires enable_instance_hrw=true because active registrations publish per-instance private endpoints validated through router discovery."
    }
    precondition {
      condition     = var.qurl_reverse_tunnel_server_cloud_map_routing_policy == "MULTIVALUE"
      error_message = "qurl_tunnel_active_registrations_enabled=true requires qurl_reverse_tunnel_server_cloud_map_routing_policy=\"MULTIVALUE\" so router discovery sees every active instance IP."
    }
  }
}

# `deploy_qurl_bootstrap_chain=true` injects the bootstrap-chain env
# vars onto the qurl-service ECS task def. Without `deploy_qurl_service`
# the task def doesn't exist, so the gate silently does nothing — the
# same operator-confusion trap as the qurl_site_authz preconditions
# above. Fail at plan time.
resource "terraform_data" "qurl_bootstrap_chain_preconditions" {
  count = var.deploy_qurl_bootstrap_chain ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.deploy_qurl_service
      error_message = "deploy_qurl_bootstrap_chain=true requires deploy_qurl_service=true. The chain's env vars are injected onto the qurl-service ECS task def; without the service deployed, the gate has no execution path and silently does nothing."
    }
  }
}

# Inverse precondition: flipping the activation bool without the
# structural gate silently leaves the chain inert. The variable
# description says "only consulted when deploy_qurl_bootstrap_chain
# = true", but nothing enforces that — an operator who sets just
# `enable_qurl_agent_bootstrap = true` (forgetting the structural
# gate) gets a zero-diff plan with no signal that the activation
# is moot. This `count` ties to the activation flag specifically,
# so the precondition only exists when someone affirmatively flips
# the activation bool — the all-defaults-false posture doesn't
# trip it.
resource "terraform_data" "qurl_bootstrap_activation_preconditions" {
  count = var.enable_qurl_agent_bootstrap ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.deploy_qurl_bootstrap_chain
      error_message = "enable_qurl_agent_bootstrap=true requires deploy_qurl_bootstrap_chain=true. The activation flag drives the QURL_AGENT_BOOTSTRAP_ENABLED env var on the qurl-service task def; when the structural gate is off the whole 4-tuple is omitted from `container_env`, so flipping the activation alone leaves the chain inert."
    }
  }
}

# ==================== Locals ====================

locals {
  name_prefix = "layerv-nhp-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = "NHP"
    Application = "nhp"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "layervai/nhp"
    Service     = "shared"
  })

  # CloudFront ↔ NHP server keep-alive contract values. The
  # `terraform_data.http_keepalive_contract` resource carries
  # `lifecycle.precondition` blocks that hard-fail plan/apply if these
  # locals violate the relationship (`http_idle_timeout_ms` must clear
  # `cf_origin_keepalive_seconds + cf_keepalive_buffer_seconds`;
  # `http_write_timeout_ms` must stay below `cf_origin_read_timeout`).
  # The compute module's `var.http_timeouts_ms` validation enforces the
  # in-object relationships (idle > read, idle > write) independently.
  # See the precondition for the bug-class rationale.
  cf_origin_keepalive_seconds = 30
  cf_origin_read_timeout      = 60
  # cf_keepalive_buffer_seconds is the MINIMUM slack required between the
  # server's IdleTimeout and CF's origin_keepalive_timeout. The actual
  # gap (http_idle_timeout_ms - cf_origin_keepalive_seconds*1000) is
  # 6000ms today; this local is the floor enforced by the precondition,
  # not the realized gap. A future operator who tunes this to match the
  # realized 6 would tighten the precondition (36000 >= (30+6)*1000
  # passes by exact equality, losing the 1s slack) — to track the
  # realized gap, bump http_idle_timeout_ms in lockstep. Lifted into a
  # local so the precondition's condition AND error message stay in
  # sync if the floor is ever tuned.
  cf_keepalive_buffer_seconds = 5
  # http_idle_timeout_ms = 36000 (not exactly cf_keepalive + buffer = 35000)
  # so the precondition has 1s of real slack above the floor, instead of
  # passing by exact equality.
  http_idle_timeout_ms  = 36000
  http_read_timeout_ms  = 30000
  http_write_timeout_ms = 30000
}

# ==================== Modules ====================

# KMS Module - Customer-Managed Keys for encryption
module "kms" {
  source = "./modules/kms"

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = local.common_tags
}

# Plugins Module - Unified S3 bucket for NHP Server and Traefik plugins
module "plugins" {
  source = "./modules/plugins"

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # Plugin configurations
  server_plugins  = var.server_plugins
  traefik_plugins = var.traefik_plugins

  # GitHub repos that can upload plugins
  github_org   = var.github_org
  plugin_repos = var.plugin_repos

  # KMS encryption (consistent with other S3 buckets)
  kms_key_arn = module.kms.logs_key_arn
}

# Traefik Plugins Deploy Module - IAM role, S3 bucket, SSM documents for out-of-band
# plugin deployment to AC instances from the traefik-plugins repo.
module "traefik_plugins_deploy" {
  source = "./modules/traefik-plugins-deploy"

  environment              = var.environment
  name_prefix              = local.name_prefix
  tags                     = local.common_tags
  aws_account_id           = data.aws_caller_identity.current.account_id
  aws_region               = var.aws_region
  github_oidc_provider_arn = module.ecr.github_oidc_provider_arn
  github_org               = var.github_org
  github_repo              = var.traefik_plugins_github_repo
  # Both blue (-ac) and green (-ac-green) ASG instances need SSM access for plugin deploys.
  ac_instance_tag_names         = compact(["nhp_ac", "${local.name_prefix}-ac", "${local.name_prefix}-ac-green"])
  terraform_state_bucket        = var.terraform_state_bucket
  terraform_lock_table          = var.terraform_lock_table
  boot_time_plugins_bucket_arn  = module.plugins.bucket_arn
  boot_time_plugins_kms_key_arn = module.kms.logs_key_arn

  # Explicit dependency: module.ecr manages the GitHub Actions IAM role and its
  # policies (including iam:CreateRole and s3:CreateBucket for traefik-plugins-*).
  # Without this, Terraform may create this module's resources before the IAM
  # policy updates are applied, causing AccessDenied errors.
  depends_on = [module.ecr]
}

# ECR Module - Creates ECR in primary account, references cross-account in secondary
module "ecr" {
  source = "./modules/ecr"

  environment            = var.environment
  name_prefix            = local.name_prefix
  tags                   = local.common_tags
  is_primary_account     = var.is_primary_account
  primary_account_id     = var.primary_account_id
  secondary_account_ids  = var.secondary_account_ids
  enable_replication     = var.enable_replication
  github_org             = var.github_org
  github_repo            = var.github_repo
  terraform_state_bucket = var.terraform_state_bucket
  terraform_lock_table   = var.terraform_lock_table

  # OIDC Provider - set to false if org manages centrally or SCP blocks creation
  create_oidc_provider = var.create_oidc_provider

  # Plugin bucket (from plugins module)
  # Allows plugin repos to upload binaries to S3
  enable_plugin_bucket_policy = true
  plugin_bucket_arn           = module.plugins.bucket_arn
  traefik_plugins_github_repo = var.traefik_plugins_github_repo

  # NHP Server plugin repos (for IAM trust policy)
  plugin_repos = var.plugin_repos

  # QURL Service ECR repository
  deploy_qurl_ecr  = var.deploy_qurl_service
  qurl_github_repo = var.qurl_github_repo

  # qurl-reverse-tunnel-server source repo (for ECR publish workflow OIDC trust)
  qurl_reverse_tunnel_server_github_repo = var.qurl_reverse_tunnel_server_github_repo

  website_api_cfn_stack_name = var.website_api_cfn_stack_name
}

# Networking Module - VPC, Subnets, Security Groups
module "networking" {
  source = "./modules/networking"

  environment      = var.environment
  vpc_cidr         = var.vpc_cidr
  name_prefix      = local.name_prefix
  logs_kms_key_arn = module.kms.logs_key_arn
  tags             = local.common_tags

  # NHP protection requires NACL to allow port 443 from internet
  # so NLB can route to private subnets (iptables enforces access)
  allow_private_ingress_443 = true

  # QURL service VPC endpoints (DynamoDB gateway, SQS interface)
  deploy_vpc_endpoints = var.deploy_vpc_endpoints
}

# Data Module - etcd, EFS, Secrets, Service Discovery
module "data" {
  source = "./modules/data"

  environment         = var.environment
  multi_tenant        = var.multi_tenant
  deploy_etcd         = var.deploy_etcd
  lambda_layer_bucket = coalesce(var.lambda_layer_bucket, var.terraform_state_bucket)
  vpc_id              = module.networking.vpc_id
  private_subnet_ids  = module.networking.private_subnet_ids
  vpc_cidr            = var.vpc_cidr
  name_prefix         = local.name_prefix
  tags                = local.common_tags

  # KMS encryption keys
  efs_kms_key_arn     = module.kms.efs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn
  logs_kms_key_arn    = module.kms.logs_key_arn

  # S3 bucket for Lambda layer storage
  terraform_state_bucket = var.terraform_state_bucket
}

# ============================================================================
# Pluggable Storage Backend Infrastructure
# These modules support the per-AC server assignment architecture.
# DynamoDB is the default for cloud; etcd is available as a feature flag.
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md for full design.
# ============================================================================

# DynamoDB Module - Per-AC assignment storage (replaces etcd for cloud)
module "dynamodb" {
  source = "./modules/dynamodb"

  environment = var.environment
  cell_id     = var.cell_id
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # KMS encryption
  kms_key_arn = module.kms.secrets_key_arn

  # QURL Service tables
  deploy_qurl_tables = var.deploy_qurl_service
}

# NHP Keypair Module - Registration keypair for AC initial connection
module "nhp_keypair" {
  source = "./modules/nhp-keypair"

  environment = var.environment
  cell_id     = var.cell_id
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # KMS encryption for SSM SecureString
  kms_key_arn = module.kms.secrets_key_arn
}

# HMAC secret for /nhp/internal/knock; signed by qurl-service, verified by
# nhp-server. 32-byte floor enforced on both sides.
resource "aws_secretsmanager_secret" "nhp_internal_auth" {
  name                    = "${local.name_prefix}-nhp-internal-auth"
  description             = "HMAC secret for /nhp/internal/knock — shared by nhp-server and qurl-service"
  recovery_window_in_days = var.environment == "prod" ? 30 : 0
  kms_key_id              = module.kms.secrets_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-nhp-internal-auth"
    Component = "nhp-internal-auth"
  })
}

# 48 bytes > the 32-byte floor both sides enforce. The value never appears in
# Terraform state — it is written directly via the AWS CLI.
#
# NOTE: --exclude-punctuation is load-bearing. Both consumers write this
# value raw into env files (ECS task def + nhp-server secrets.env) without
# escaping. The [A-Za-z0-9] alphabet produced here is the only shape that's
# safe through those env-file transports. If a future change widens the
# alphabet for higher entropy, the env-file write paths must base64-encode
# the value (mirror the NHP_COOKIE_KEYS treatment in user_data.sh.tpl).
#
# Recovery: if the local-exec fails mid-apply the secret exists but is
# unpopulated and both services will refuse to start. Re-run with
# `terraform apply -replace=terraform_data.nhp_internal_auth_seed`.
resource "terraform_data" "nhp_internal_auth_seed" {
  triggers_replace = [aws_secretsmanager_secret.nhp_internal_auth.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    # --region is explicit so a local apply from a laptop with a
    # different AWS_REGION doesn't silently target the wrong region.
    # The -z guard is belt-and-suspenders against get-random-password
    # ever returning empty — the check block downstream catches this,
    # but failing here is the cheaper signal.
    command = <<-EOT
      set -euo pipefail
      SECRET_VALUE=$(aws secretsmanager get-random-password \
        --region "${data.aws_region.current.name}" \
        --password-length 48 \
        --exclude-punctuation \
        --query RandomPassword --output text)
      if [ -z "$SECRET_VALUE" ]; then
        echo "ERROR: get-random-password returned empty" >&2
        exit 1
      fi
      aws secretsmanager put-secret-value \
        --region "${data.aws_region.current.name}" \
        --secret-id "${aws_secretsmanager_secret.nhp_internal_auth.id}" \
        --secret-string "$SECRET_VALUE" > /dev/null
    EOT
  }
}

# Early diagnostic: confirm the secret has a populated version. If the seed's
# local-exec failed on first apply, this fires a warning at every subsequent
# plan/apply until `terraform apply -replace=terraform_data.nhp_internal_auth_seed`
# reseeds. check blocks are advisory (warn, not fail), so they don't break
# subsequent applies that don't depend on a populated value — but they do
# surface the failure so operators aren't relying on a mid-rollout container
# crash to discover it.
check "nhp_internal_auth_secret_populated" {
  data "aws_secretsmanager_secret_version" "nhp_internal_auth" {
    secret_id  = aws_secretsmanager_secret.nhp_internal_auth.id
    depends_on = [terraform_data.nhp_internal_auth_seed]
  }

  assert {
    condition     = length(data.aws_secretsmanager_secret_version.nhp_internal_auth.secret_string) >= 32
    error_message = "NHP internal auth secret is shorter than the 32-byte floor both sides enforce. Re-run: terraform apply -replace=terraform_data.nhp_internal_auth_seed"
  }
}

# Compute Module - ASG, NLB, Launch Template
module "compute" {
  source = "./modules/compute"

  environment         = var.environment
  cell_id             = var.cell_id
  server_ami_id       = var.server_ami_id
  domain_name         = var.domain_name
  multi_tenant        = var.multi_tenant
  min_capacity        = var.min_capacity
  max_capacity        = var.max_capacity
  vpc_id              = module.networking.vpc_id
  vpc_cidr            = var.vpc_cidr
  public_subnet_ids   = module.networking.public_subnet_ids
  private_subnet_ids  = module.networking.private_subnet_ids
  server_repo_url     = module.ecr.server_repo_url
  server_repo_arn     = module.ecr.server_repo_arn
  etcd_endpoint       = module.data.etcd_endpoint
  etcd_secret_arn     = module.data.etcd_secret_arn
  etcd_tls_secret_arn = module.data.etcd_ca_cert_arn
  namespace_id        = module.data.namespace_id
  namespace_name      = module.data.namespace_name
  name_prefix         = local.name_prefix
  tags                = merge(local.common_tags, { Service = "nhp-server" })

  # KMS encryption keys
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  logs_kms_key_arn    = module.kms.logs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # Server configuration options
  log_level        = var.log_level
  dev_mode         = var.dev_mode
  resource_mode    = var.resource_mode
  auth_url         = var.auth_url != null ? var.auth_url : ""
  auth_signing_key = var.auth_signing_key != null ? var.auth_signing_key : ""
  auth_aes_key     = var.auth_aes_key != null ? var.auth_aes_key : ""

  # Deployment configuration
  image_tag = var.image_tag

  # Plugin configuration (plugins baked into Docker image, just need names for etcd seeding)
  server_plugins  = var.server_plugins
  auth_service_id = var.ac_auth_service_id

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

  # Shared HMAC secret; seed ordering enforced via depends_on below.
  nhp_internal_auth_secret_arn = aws_secretsmanager_secret.nhp_internal_auth.arn

  # QURL resolve endpoint - TLS listener for resolve.qurl.link
  # Routes HTTPS traffic directly to NHP Server plugin endpoint
  # Note: enable_qurl_resolve_endpoint uses a static boolean to avoid "count depends on
  # resource attributes" errors. The certificate_arn is only used at apply time.
  enable_qurl_resolve_endpoint = var.deploy_qurl_link
  qurl_resolve_certificate_arn = var.deploy_qurl_link ? aws_acm_certificate_validation.qurl_resolve[0].certificate_arn : null

  # HTTP server timeouts — CF↔server keep-alive contract (see top-of-file
  # locals + `terraform_data.http_keepalive_contract`'s preconditions). The
  # same numbers are baked in at the binary level via
  # endpoints/server/constants.go as a safety net for deployments that don't
  # set http.toml.
  http_timeouts_ms = {
    idle  = local.http_idle_timeout_ms
    read  = local.http_read_timeout_ms
    write = local.http_write_timeout_ms
  }

  # S3 plugin bucket — also hosts the server bootstrap script
  # (scripts/server-init.sh) so the launch template's user_data stays
  # within EC2's 16KB limit. Same bucket the AC module uses; separate
  # path prefix. plugin_download_policy_arn includes both s3:GetObject
  # and kms:Decrypt on the bucket's CMK (which is module.kms.logs_key_arn,
  # NOT secrets_key_arn — separate CMK).
  plugin_bucket_name         = module.plugins.bucket_name
  plugin_download_policy_arn = module.plugins.download_policy_arn

  # Pluggable storage backend - DynamoDB (cloud default) with etcd feature flag for on-prem
  # Note: attach_storage_policies is required because Terraform cannot evaluate count based on module outputs
  attach_storage_policies  = true
  dynamodb_read_policy_arn = module.dynamodb.read_policy_arn
  keypair_policy_arn       = module.nhp_keypair.server_keypair_policy_arn

  # Storage backend configuration
  # - "dynamodb" (default): Uses AWS DynamoDB for cloud deployments
  # - "etcd": Uses etcd for on-prem deployments (feature flag)
  storage_backend               = "dynamodb"
  dynamodb_licenses_table       = module.dynamodb.licenses_table_name
  dynamodb_ac_assignments_table = module.dynamodb.ac_assignments_table_name
  dynamodb_resources_table      = module.dynamodb.resources_table_name
  dynamodb_agent_keys_table     = module.dynamodb.qurl_agent_keys_table_name

  # Cloud Map configuration for server health discovery
  # Filters stale AC assignments pointing to terminated servers
  cloudmap_enabled        = true
  cloudmap_namespace_name = module.data.namespace_name
  cloudmap_service_name   = var.nhp_cloudmap_service_name

  # ASG Lifecycle Hook for immediate DynamoDB cleanup on server termination
  # When enabled, a Lambda cleans up assignments before the server terminates
  enable_termination_cleanup     = var.enable_termination_cleanup
  dynamodb_server_ac_index_table = module.dynamodb.server_ac_index_table_name
  dynamodb_ac_assignments_arn    = module.dynamodb.ac_assignments_table_arn
  dynamodb_server_ac_index_arn   = module.dynamodb.server_ac_index_table_arn

  # SNS topic for Lambda error alarms (from monitoring module)
  # Note: The SNS topic is created before compute resources, avoiding circular dependency
  alerts_sns_topic_arn = module.monitoring.sns_topic_arn
  enable_sns_alerts    = true # Static boolean - monitoring module always creates SNS topic

  # CORS allowed origins for NHP HTTP server
  cors_allowed_origins = var.nhp_cors_allowed_origins

  # CloudFront trusted proxy CIDRs (for correct client IP extraction from X-Forwarded-For)
  cloudfront_cidrs_ssm_parameter = var.deploy_qurl_link && var.enable_resolve_cloudfront ? aws_ssm_parameter.cloudfront_cidrs[0].name : null

  knock_headertype_verify_require = var.nhp_knock_headertype_verify_require

  # Knock-port DoS hardening (#1159)
  knock_global_rate_limit_pps   = var.nhp_knock_global_rate_limit_pps
  knock_global_rate_limit_burst = var.nhp_knock_global_rate_limit_burst
  udp_recv_buffer_bytes         = var.nhp_udp_recv_buffer_bytes

  # Blue/Green deployment configuration
  enable_blue_green               = var.enable_blue_green
  green_standby_min_size          = var.green_standby_min_size
  deployment_stale_threshold_days = var.deployment_stale_threshold_days

  # Ensure the secret is populated before launch templates are created.
  # Without this, instances may come up reading an unseeded (empty) secret
  # and fail-closed at NHP_INTERNAL_AUTH_SECRET constructor time.
  depends_on = [terraform_data.nhp_internal_auth_seed]
}

# Monitoring Module - CloudWatch Dashboard, Alarms, Slack Notifications
module "monitoring" {
  source = "./modules/monitoring"

  environment                         = var.environment
  cell_id                             = var.cell_id
  nlb_arn_suffix                      = module.compute.nlb_arn_suffix
  target_group_arn_suffix             = module.compute.target_group_arn_suffix
  https_target_group_arn_suffix       = module.compute.https_target_group_arn_suffix
  https_green_target_group_arn_suffix = module.compute.https_green_target_group_arn_suffix
  asg_name                            = module.compute.asg_name
  server_stderr_log_group_name        = module.compute.log_group_stderr_name
  name_prefix                         = local.name_prefix
  tags                                = local.common_tags

  # Slack integration
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id
  chatbot_owned_externally   = var.chatbot_owned_externally

  # Email alert subscriptions (B8 - interim until Slack is authorized for prod)
  alert_emails = var.alert_emails

  # DynamoDB monitoring
  dynamodb_table_names = module.dynamodb.all_table_names
}

# Deploy-mode marker: lets out-of-band tooling (smoke tests, runbooks)
# discover whether this environment uses blue/green or canary deploys
# without re-deriving the toggle. Read by tests/smoke (#1330).
#
# Owned entirely by Terraform — never written by CI. No
# `lifecycle.ignore_changes` so a `terraform apply` always converges
# the value if the underlying toggles ever flip.
#
# The lifecycle.preconditions fence the truth table for the three
# independent toggles smoke depends on. The SSM value is derived from
# `enable_canary_deployment` only, but smoke's AC-side assertions
# (e.g., the EIP pool formula at terraform/modules/ac/eip.tf:33)
# branch on `enable_ac_blue_green`. Mixed configurations would let
# the SSM say "canary" while the AC infra is actually blue/green
# (or vice versa) — those silently mis-fence smoke. We require:
#
#   enable_canary_deployment XOR enable_blue_green     (server)
#   enable_blue_green        ==  enable_ac_blue_green  (server <-> AC symmetry)
#
# Together these collapse the eight-cell truth table to two valid
# states: {blue_green=true, ac_blue_green=true, canary=false} or
# {blue_green=false, ac_blue_green=false, canary=true}. A future
# split where AC and server run different regimes would need the
# SSM key shape revisited — see #1448 for the multi-cell parallel.
resource "aws_ssm_parameter" "deploy_mode" {
  name        = "/${var.environment}/nhp/deploy/mode"
  description = "Deployment model in effect: blue_green or canary"
  type        = "String"
  value       = var.enable_canary_deployment ? "canary" : "blue_green"

  # No Cell tag: this key is env-scoped, not cell-scoped. When #1448
  # ships multi-cell, it'll need a per-cell SSM tree and that tree
  # carries the Cell tag — not this env-level marker.
  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ssm-deploy-mode"
    Component = "deploy"
  })

  lifecycle {
    precondition {
      condition     = var.enable_canary_deployment != var.enable_blue_green
      error_message = "Exactly one of enable_canary_deployment / enable_blue_green must be true; got canary=${var.enable_canary_deployment} blue_green=${var.enable_blue_green}. New envs: pick one in tfvars (see tests/smoke/CLAUDE.md \"Deploy-mode tier mapping\")."
    }
    # Symmetry fence (not redundancy): smoke's AC-side assertions
    # (e.g., the EIP pool formula) read the deploy-mode SSM, which
    # only encodes a single regime. A half-flip would let smoke
    # mis-fence silently; this precondition rejects it at plan time.
    precondition {
      condition     = var.enable_blue_green == var.enable_ac_blue_green
      error_message = "enable_blue_green (${var.enable_blue_green}) and enable_ac_blue_green (${var.enable_ac_blue_green}) must agree — the deploy-mode SSM only encodes a single regime, and smoke's AC EIP formula reads it. Set them to the same value."
    }
    # Canary requires deploy_ac because module.canary_deployment_ac
    # is gated on `enable_canary_deployment && deploy_ac`. Without
    # it, the AC canary state SSM keys smoke's TestCanary_StateIdle
    # depends on don't exist. A future server-only canary env would
    # need the canary smoke tests + this assertion revisited.
    precondition {
      condition     = !var.enable_canary_deployment || var.deploy_ac
      error_message = "enable_canary_deployment=true requires deploy_ac=true; got deploy_ac=${var.deploy_ac}. Server-only canary envs need the canary smoke tests revisited (see tests/smoke/04_canary_state_test.go)."
    }
    # Same dependency on the blue/green side: requireActiveACASG
    # reads /{env}/nhp/ac/{color}-asg-name, which only exists when
    # the AC module is deployed. Symmetric with the canary fence
    # above; both paths fail at plan time rather than test time.
    precondition {
      condition     = !var.enable_blue_green || var.deploy_ac
      error_message = "enable_blue_green=true requires deploy_ac=true; got deploy_ac=${var.deploy_ac}. Server-only blue/green envs need the AC smoke tests revisited (see tests/smoke/05_ac_eip_pool_test.go)."
    }
  }
}

# Cell ID marker: smoke discovers the active cell from this SSM key
# rather than hardcoding "cell0" (#1448). Today every env defaults to
# cell0; this still gets a single env-level SSM key (no multi-cell
# fan-out) — when multi-cell ships, this needs to become a list or a
# per-cell SSM tree. Shape validation lives upstream in
# terraform/variables.tf::cell_id.
resource "aws_ssm_parameter" "cell_id" {
  name        = "/${var.environment}/nhp/deploy/cell-id"
  description = "Active cell ID (today: single-cell, see #1448 for multi-cell)"
  type        = "String"
  value       = var.cell_id

  # No Cell tag: env-scoped marker, see deploy_mode rationale above.
  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ssm-cell-id"
    Component = "deploy"
  })
}

# Canary Deployment Module - Step Functions-orchestrated progressive rollout
module "canary_deployment" {
  source = "./modules/canary-deployment"
  count  = var.enable_canary_deployment ? 1 : 0

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  component   = "server"
  tags        = merge(local.common_tags, { Service = "nhp-server" })

  asg_name                = module.compute.asg_name
  asg_arn                 = module.compute.asg_arn
  launch_template_arn     = module.compute.launch_template_arn
  ebs_kms_key_arn         = module.kms.ebs_key_arn
  nlb_arn_suffix          = module.compute.nlb_arn_suffix
  target_group_arn_suffix = module.compute.target_group_arn_suffix
  alerts_sns_topic_arn    = module.monitoring.sns_topic_arn
  logs_kms_key_arn        = module.kms.logs_key_arn
  ssm_image_tag_parameter = module.compute.ssm_image_tag_parameter

  checkpoint_percentages   = var.canary_checkpoint_percentages
  checkpoint_delay_seconds = var.canary_checkpoint_delay_seconds
  instance_warmup_seconds  = var.canary_instance_warmup_seconds
}

# NOTE: this re-instantiates ./modules/canary-deployment, which means
# its `data "archive_file" "orchestrator"` resolves to the same
# `${path.module}/lambda/canary_orchestrator.zip` as the server-side
# `module.canary_deployment` above. The writes are idempotent today
# because both produce **byte-identical content** (same `source_file`,
# same packaging) — NOT because terraform serializes them. Terraform's
# default `-parallelism=10` evaluates independent data sources
# concurrently; the safety here comes from content-equality. If
# `canary_deployment_ac` ever needs AC-specific orchestrator code, the
# two writes diverge AND race, AND it also needs its own upload/
# download pair in the workflow — the structural-symmetry test won't
# catch either omission. See #1380.
module "canary_deployment_ac" {
  source = "./modules/canary-deployment"
  count  = var.enable_canary_deployment && var.deploy_ac ? 1 : 0

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  component   = "ac"
  tags        = merge(local.common_tags, { Service = "nhp-ac" })

  asg_name                = module.ac[0].asg_name
  asg_arn                 = module.ac[0].asg_arn
  launch_template_arn     = module.ac[0].launch_template_arn
  ebs_kms_key_arn         = module.kms.ebs_key_arn
  nlb_arn_suffix          = module.ac[0].nlb_arn_suffix
  target_group_arn_suffix = module.ac[0].target_group_arn_suffix
  alerts_sns_topic_arn    = module.monitoring.sns_topic_arn
  logs_kms_key_arn        = module.kms.logs_key_arn
  ssm_image_tag_parameter = module.ac[0].ssm_image_tag_parameter

  checkpoint_percentages   = var.canary_checkpoint_percentages
  checkpoint_delay_seconds = var.canary_checkpoint_delay_seconds
  instance_warmup_seconds  = var.canary_instance_warmup_seconds
}

# qurl-reverse-tunnel-server canary deployment (prod-targeted). Independent of the
# `enable_canary_deployment` (server) flag because qurl-reverse-tunnel-server lives on
# its own ASG and release cadence; sandbox runs blue/green for frps
# while prod runs canary, but the symmetric server/AC path is unaware
# of either. Wired only when `enable_qurl_reverse_tunnel_server_canary = true` AND
# `deploy_frps = true`.
#
# See the NOTE on `module.canary_deployment_ac` re: shared `archive_file`
# output_path for the orchestrator Lambda — the same content-equality
# guarantee applies to this third instantiation. The
# `disable_nlb_health_checks = true` path added in this PR keeps the
# Lambda source byte-identical across server / ac / frps consumers
# (single `canary_orchestrator.py`, NLB-vs-ASG branch chosen at runtime
# from env vars), so the #1380 divergence-and-race risk class is
# preserved.
module "canary_deployment_qurl_reverse_tunnel_server" {
  source = "./modules/canary-deployment"
  count  = var.enable_qurl_reverse_tunnel_server_canary && var.deploy_frps ? 1 : 0

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  component   = "frps"
  tags        = merge(local.common_tags, { Service = "qurl-reverse-tunnel-server" })

  asg_name            = module.qurl_reverse_tunnel_server[0].asg_name
  asg_arn             = module.qurl_reverse_tunnel_server[0].asg_arn
  launch_template_arn = module.qurl_reverse_tunnel_server[0].launch_template_arn
  ebs_kms_key_arn     = module.kms.ebs_key_arn

  # qurl-reverse-tunnel-server has no NLB. Pass empty suffixes; the canary-deployment
  # module's `disable_nlb_health_checks = true` switch makes the
  # state machine skip NLB-keyed alarms and the orchestrator
  # Lambda skip NLB metric queries. Cloud Map empty-AZ alarm
  # (#1542 in modules/qurl-reverse-tunnel-server/monitoring_empty_az.tf) covers the
  # routing-layer fault class.
  nlb_arn_suffix            = ""
  target_group_arn_suffix   = ""
  disable_nlb_health_checks = true
  alerts_sns_topic_arn      = module.monitoring.sns_topic_arn
  logs_kms_key_arn          = module.kms.logs_key_arn
  ssm_image_tag_parameter   = module.qurl_reverse_tunnel_server[0].ssm_image_tag_parameter

  checkpoint_percentages   = var.canary_checkpoint_percentages
  checkpoint_delay_seconds = var.canary_checkpoint_delay_seconds
  instance_warmup_seconds  = var.canary_instance_warmup_seconds
}

# Status Page Module - Deployment visibility dashboard
# ACM certificate must be in us-east-1 for CloudFront
resource "aws_acm_certificate" "status_page" {
  count             = var.deploy_status_page && var.status_page_domain != null ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = var.status_page_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-status-page-cert"
  })
}

resource "aws_route53_record" "status_page_cert_validation" {
  for_each = var.deploy_status_page && var.status_page_domain != null && var.status_page_hosted_zone_id != null ? {
    for dvo in aws_acm_certificate.status_page[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  provider = aws.route53_mgmt

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.status_page_hosted_zone_id
}

resource "aws_acm_certificate_validation" "status_page" {
  count                   = var.deploy_status_page && var.status_page_domain != null ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.status_page[0].arn
  validation_record_fqdns = var.status_page_hosted_zone_id != null ? [for record in aws_route53_record.status_page_cert_validation : record.fqdn] : null
}

module "status_page" {
  source = "./modules/status-page"
  count  = var.deploy_status_page ? 1 : 0

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # Domain (optional - uses CloudFront default domain if not set)
  # DNS record created in root module (not module) for cross-account Route53 support
  status_domain       = var.status_page_domain
  hosted_zone_id      = null
  acm_certificate_arn = var.status_page_domain != null ? aws_acm_certificate_validation.status_page[0].certificate_arn : null

  # Target group ARNs for health checks
  server_nlb_tg_arns = compact([
    module.compute.udp_target_group_blue_arn,
    module.compute.udp_target_group_green_arn,
  ])
  ac_nlb_tg_arns = var.deploy_ac ? compact([
    module.ac[0].tcp_target_group_blue_arn,
    module.ac[0].tcp_target_group_green_arn,
  ]) : []

  # Monitoring
  alarm_name_prefix = "${local.name_prefix}-${var.cell_id}"
  sns_topic_arn     = module.monitoring.sns_topic_arn
  logs_kms_key_arn  = module.kms.logs_key_arn
  ssm_prefix        = "/${var.environment}/nhp"

  # Metrics & ASG
  server_nlb_arn_suffix = module.compute.nlb_arn_suffix
  ac_nlb_arn_suffix     = var.deploy_ac ? module.ac[0].nlb_arn_suffix : ""
  server_asg_name       = module.compute.asg_name
  ac_asg_name           = var.deploy_ac ? module.ac[0].asg_name : ""
  grafana_dashboard_url = var.grafana_dashboards_enabled && var.grafana_cloudwatch_enabled && var.grafana_create_dashboards ? module.grafana_dashboards[0].nhp_infrastructure_dashboard_url : var.grafana_nhp_dashboard_url

  # Deployment model
  deployment_model       = var.enable_canary_deployment ? "canary" : "blue_green"
  canary_state_ssm_param = var.enable_canary_deployment ? module.canary_deployment[0].ssm_canary_state_parameter : ""

  # Dependent services
  dependent_service_urls = var.qurl_service_domain != null ? {
    qurl_api = "https://${var.qurl_service_domain}/health/ready"
  } : {}

  # NHP Authentication (dogfooding)
  enable_nhp_auth   = var.status_page_nhp_auth_enabled
  nhp_auth_qurl_url = var.status_page_nhp_auth_qurl_url
}

# Status page DNS record for cross-account zones
# Uses route53_mgmt provider (same pattern as AC and QURL API DNS records)
resource "aws_route53_record" "status_page_dns" {
  count    = var.deploy_status_page && var.status_page_domain != null && var.status_page_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.status_page_hosted_zone_id
  name    = var.status_page_domain
  type    = "A"

  alias {
    name                   = module.status_page[0].cloudfront_domain_name
    zone_id                = module.status_page[0].cloudfront_hosted_zone_id
    evaluate_target_health = false
  }
}

# DNS Module - Route 53 records
module "dns" {
  source = "./modules/dns"
  count  = var.hosted_zone != null || var.hosted_zone_id != null ? 1 : 0

  environment      = var.environment
  domain_name      = var.domain_name
  hosted_zone_name = var.hosted_zone
  hosted_zone_id   = var.hosted_zone_id
  nlb_dns_name     = module.compute.nlb_dns_name
  nlb_zone_id      = module.compute.nlb_zone_id
  name_prefix      = local.name_prefix
  tags             = local.common_tags

  # Skip main record when AC is deployed (AC manages the domain for HTTPS)
  skip_main_record = var.deploy_ac
}

# Security Module - WAF for DDoS protection
# Note: WAF WebACL is created but association depends on resource type
# For NLB: Deploy CloudFront in front and associate WAF with CloudFront
# For ALB: Associate directly with the ALB
module "security" {
  source = "./modules/security"

  environment                = var.environment
  name_prefix                = local.name_prefix
  rate_limit_requests        = var.environment == "prod" ? 5000 : 2000
  logs_kms_key_arn           = module.kms.logs_key_arn
  enable_cloudtrail          = var.enable_cloudtrail
  enable_waf_logging         = var.enable_waf_logging
  config_recording_frequency = var.config_recording_frequency
  config_resource_types      = var.config_resource_types
  tags                       = local.common_tags

  # GuardDuty alerting - sends findings to SNS for email/Slack notifications
  enable_guardduty_alerts = length(var.guardduty_alert_emails) > 0
  alerts_sns_topic_arn    = module.monitoring.sns_topic_arn
  guardduty_alert_emails  = var.guardduty_alert_emails
}

# AC Module - Access Controller with embedded Traefik for TLS termination
# Note: Traefik plugins are managed separately by the traefik-plugins project
module "ac" {
  source = "./modules/ac"
  count  = var.deploy_ac ? 1 : 0

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment        = var.environment
  domain_name        = var.domain_name
  hosted_zone        = var.hosted_zone
  hosted_zone_id     = var.hosted_zone_id
  skip_dns_records   = var.cross_account_route53_role_arn != null # Cross-account zones: DNS records created in root module
  acme_email         = var.acme_email
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  ac_repo_url        = module.ecr.ac_repo_url
  ac_repo_arn        = module.ecr.ac_repo_arn
  namespace_id       = module.data.namespace_id
  namespace_name     = module.data.namespace_name
  name_prefix        = local.name_prefix
  tags               = merge(local.common_tags, { Service = "nhp-ac" })

  # KMS encryption keys
  logs_kms_key_arn    = module.kms.logs_key_arn
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # CloudFront + WAF (optional)
  enable_cloudfront = var.enable_cloudfront

  # AC configuration options
  log_level         = var.log_level
  auth_service_id   = var.ac_auth_service_id
  resource_ids      = var.ac_resource_ids
  server_endpoint   = module.compute.nlb_dns_name # External ACs use public NLB
  server_secret_arn = module.compute.server_secret_arn

  # License credentials for cloud mode registration
  # Default to empty strings to prevent null interpolation errors in user_data template
  customer_id        = var.ac_customer_id != null ? var.ac_customer_id : ""
  license_key        = var.ac_license_key != null ? var.ac_license_key : ""
  license_key_hash   = var.ac_license_key_hash != null ? var.ac_license_key_hash : ""
  license_key_sha256 = var.ac_license_key_sha256 != null ? var.ac_license_key_sha256 : ""

  # DynamoDB for license seeding (optional)
  nhp_dynamodb_licenses_table = module.dynamodb.licenses_table_name
  nhp_region                  = var.aws_region

  # Production domains (ACME for qurl.site, qurl.link, etc.)
  cross_account_route53_role_arn = var.cross_account_route53_role_arn
  production_domains             = var.production_domains
  production_zone_ids            = var.production_zone_ids
  additional_tls_domains         = var.additional_tls_domains
  use_production_acme            = var.use_production_acme

  # Deployment configuration
  image_tag = var.image_tag

  # Plugin configuration (from plugins module)
  plugin_bucket_name         = module.plugins.bucket_name
  plugin_bucket_arn          = module.plugins.bucket_arn
  plugin_download_policy_arn = module.plugins.download_policy_arn
  traefik_plugins            = module.plugins.traefik_plugins

  # Traefik-plugins CI/CD bucket (for SSM-based plugin deployment)
  traefik_plugins_deploy_bucket_arn = var.traefik_plugins_deploy_bucket_arn

  # QURL Router Plugin configuration (routes *.qurl.site to target backends).
  # api_url prefers the workload-account internal-ALB hostname when
  # qurl_internal_service_domain is set; that path's TLS uses the dedicated
  # internal-ALB ACM cert from qurl-service #335 PR1. Falls back to the
  # public domain on greenfield envs that haven't stood up the internal
  # ALB yet — that branch keeps the historical constraint that the public
  # ALB cert is the one that matches qurl_service_domain. Either branch is
  # cert-valid; the choice is reachability + isolation, not TLS.
  qurl_router_config = var.deploy_qurl_service && var.qurl_router_enabled ? {
    enabled = true
    # Routed through local.qurl_consumer_api_url so the AC qurl-router
    # consumer and the FRP auth-plugin consumer share one host-selection
    # rule (predicate + URL prefix). Local is the single edit point if
    # the gating evolves or a third internal consumer appears.
    api_url            = local.qurl_consumer_api_url
    base_domain        = var.qurl_site_domain
    cache_ttl          = var.qurl_router_cache_ttl
    negative_cache_ttl = var.qurl_router_negative_cache_ttl
    max_cache_size     = var.qurl_router_max_cache_size
    api_timeout        = var.qurl_router_api_timeout
    proxy_timeout      = var.qurl_router_proxy_timeout
    cache_shards       = var.qurl_router_cache_shards
    # Router-side HRW dispatch (traefik-plugins active-target routing).
    # Sandbox enables this before qurl-service active reads because active
    # registrations publish per-instance private endpoints that the AC must
    # validate through discovery. The module-level qurl_router_config
    # object's optional defaults (in modules/ac/variables.tf) backstop these
    # for module-direct consumers that don't pass the fields.
    enable_instance_hrw            = var.enable_instance_hrw
    instance_discovery_ttl_seconds = var.instance_discovery_ttl_seconds
    enable_qurl_site_authz         = var.enable_qurl_site_authz
    # qurl-reverse-tunnel-server boundary allowlist. Public FRP control
    # ingress is per-AZ: connect.layerv.* exposes one NHP-protected TCP
    # listener port per suffix, and the qurl-tunnel-server-{suffix}
    # resource rows return the matching host:port in the knock ack. Keep
    # this allowlist sourced from the same var.frps_az_suffixes root input
    # so qurl-router validation and qurl-service upstream_addr emission
    # move in lockstep.
    #
    # The inner check here is just `var.deploy_frps`; the
    # `qurl_router_enabled` gate is the outer ternary on this whole
    # `qurl_router_config` object (`var.deploy_qurl_service &&
    # var.qurl_router_enabled ? {...} : null`), so the effective
    # composition is `deploy_qurl_service && qurl_router_enabled &&
    # deploy_frps`. Keeping the inner branch narrow keeps the diff
    # local to the field that actually depends on `deploy_frps`.
    frp_server_urls = var.deploy_frps ? [
      for s in var.frps_az_suffixes :
      "http://frps-${s}.${module.data.namespace_name}:${var.frps_vhost_http_port}"
    ] : []
  } : null
  qurl_service_token_secret_arn = var.deploy_qurl_service && var.qurl_router_enabled ? var.qurl_internal_service_token_arn : null

  # Centralized certificate management (for scalable AC deployments)
  centralized_cert_enabled    = var.centralized_cert_enabled
  centralized_cert_secret_arn = var.centralized_cert_secret_arn
  centralized_cert_domains    = var.centralized_cert_domains
  acme_lambda_function_name   = var.acme_lambda_function_name

  # ASG capacity overrides
  ac_min_capacity = var.ac_min_capacity
  ac_max_capacity = var.ac_max_capacity

  # Egress EIPs for stable public IPs (customer origin firewall whitelisting)
  enable_egress_eips = var.enable_egress_eips

  # Blue/Green deployment configuration
  enable_blue_green      = var.enable_ac_blue_green
  green_standby_min_size = var.ac_green_standby_min_size
  alerts_sns_topic_arn   = module.monitoring.sns_topic_arn

  # Secret reconciliation (cleanup orphaned per-instance secrets)
  enable_secret_reconciliation = var.enable_secret_reconciliation

  # qurl-reverse-tunnel-server integration. qurl-router gets its tunnel
  # HTTP backend from the QURL API's per-resource `upstream_addr`, not from
  # the legacy singular AC fallback. Setting `frp_server_host = ""`
  # disables the legacy `/.well-known/layerv-frp` Traefik control-channel
  # router; the legacy singular `frpServerUrl` plugin field has been
  # removed from the plugin's Config struct, so the empty value rendered
  # into dynamic.toml is silently ignored.
  #
  # `frp_control_port` / `frp_vhost_http_port` are still threaded for
  # module-API stability. The public FRP control path is supplied by
  # `frp_control_upstream_host` below.
  frp_server_host     = ""
  frp_control_port    = var.frps_bind_port
  frp_vhost_http_port = var.frps_vhost_http_port

  # FRPS-behind-AC (SLACK_QURL_ROLLOUT.md §6, 2026-05-18). The AC
  # exposes the primary listener on frps_bind_port for legacy clients and
  # additional per-AZ listeners on frps_bind_port+index. Each listener is
  # still NHP-gated at the AC kernel; the only difference is which private
  # FRPS Cloud Map host Traefik forwards to after the knock opens the
  # specific public port.
  #
  # Ordering contract: `local.tunnel_server_az_suffixes` is sorted in
  # resources.tf, so the lexicographically-smallest suffix is the primary
  # AZ that keeps `frps_bind_port`; later suffixes get `+index` ports.
  # Adding a suffix after the current set is safe. Removing/replacing the
  # lexicographically-smallest suffix shifts every remaining suffix's public
  # port and requires a coordinated rollout.
  #
  # Predicate mirrors `local.tunnel_server_resources_enabled` so the
  # upstream-host and the DDB seed row converge on the same enable
  # condition. The `&& var.deploy_qurl_service`
  # conjunct is redundant in practice — `terraform_data.frps_preconditions`
  # enforces `deploy_frps ⇒ deploy_qurl_service` at plan time — but
  # keeping it inline keeps the predicate self-describing for readers
  # who haven't followed the precondition chain.
  frp_control_upstream_host = (
    var.deploy_frps && var.deploy_qurl_service
    ? local.tunnel_server_primary_host
    : ""
  )
  frp_control_additional_upstreams = (
    var.deploy_frps && var.deploy_qurl_service
    ? {
      for idx, suffix in local.tunnel_server_az_suffixes :
      suffix => {
        listen_port   = local.tunnel_server_az_control_port[suffix]
        upstream_host = "frps-${suffix}.${module.data.namespace_name}"
        upstream_port = var.frps_bind_port
      }
      if idx > 0
    }
    : {}
  )

  # Order the AC launch-template render after the internal-ALB stack is
  # reachable. The module's qurl_router_config.api_url points at
  # internal-api.qurl.layerv.{xyz,ai} when qurl_internal_service_domain is
  # set; the cert-validation + alias resources below are count-gated on the
  # same condition (local.qurl_internal_alb_enabled), so when the variable
  # is unset both depend_on entries collapse to empty resource sets and
  # this is a no-op. When set, AC ASG instances refresh only after TLS+DNS
  # are live, eliminating a first-apply window where Traefik would render
  # an api_url that NXDOMAINs.
  #
  # Granularity: module-wide depends_on rather than per-resource. Terraform
  # doesn't expose per-output depends_on, and gating only the launch
  # template would require restructuring module.ac to expose internal
  # resources. Module-wide serializes a few unrelated AC resources behind
  # cert validation on first apply (minutes, not hours); accepted as the
  # cost of the simpler boundary.
  depends_on = [
    aws_acm_certificate_validation.qurl_internal,
    aws_route53_record.qurl_internal_alias,
  ]
}

# Data source for hosted zone
# Skip lookup when hosted_zone_id is provided directly (cross-account zones)
data "aws_route53_zone" "main" {
  count = var.hosted_zone_id == null && var.hosted_zone != null ? 1 : 0
  name  = var.hosted_zone
}

locals {
  main_zone_id = var.hosted_zone_id != null ? var.hosted_zone_id : try(data.aws_route53_zone.main[0].zone_id, null)

  # Canonical VPC-internal nhp-server origin used by both qurl-service
  # headless resolve and qurl-reverse-tunnel-server knock-token validation.
  # The namespace suffix comes from modules/data/main.tf's private DNS
  # namespace (`nhp.${var.environment}.internal`); keep both consumers on
  # this local so validation and future topology changes move in lockstep.
  # The deploy_ac gate is about token issuance, not DNS existence: compute
  # registers `server.<namespace>` regardless, but without AC there are no
  # AC-issued knock tokens for either consumer to validate.
  nhp_server_internal_url = var.deploy_ac ? "http://server.${module.data.namespace_name}:8888" : ""
}

# Validate the shared nhp-server origin at the root level, not inside the
# FRPS-only preconditions: qurl-service consumes this same local whenever AC
# is deployed, even in topologies where `deploy_frps = false`.
# The current local renders only "" or the VPC-internal HTTP origin; the
# HTTPS branch is defensive for future edits that point the shared local at a
# direct-module/nonstandard topology. That branch is intentionally
# origin-shape-only escape-hatch validation; runtime URL parsing remains
# responsible for host/port semantics if it ever becomes load-bearing.
# Mirror the regex/error text in the two
# module-level `nhp_server_internal_url` validations below.
resource "terraform_data" "nhp_server_internal_url_preconditions" {
  lifecycle {
    precondition {
      condition = (
        local.nhp_server_internal_url == ""
        # HTTPS is currently unreachable from the root local and is retained
        # only to mirror direct-module validation for drift-lint parity.
        || can(regex("^https://[^[:space:]/?#]+$", local.nhp_server_internal_url))
        || can(regex("^http://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+internal:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", local.nhp_server_internal_url))
      )
      error_message = "local.nhp_server_internal_url must be empty, an HTTPS origin URL or an HTTP private hosted-zone origin ending in .internal with an explicit valid TCP port (1-65535); either form must have no path, query, fragment, or trailing slash (for example http://server.nhp.sandbox.internal:8888)."
    }
  }
}

# AC DNS records for cross-account zones
# When skip_dns_records is true in the AC module (cross-account scenario),
# the root module creates records using the route53_mgmt provider
resource "aws_route53_record" "ac_domain" {
  count    = var.deploy_ac && var.cross_account_route53_role_arn != null && local.main_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.main_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "ac_wildcard" {
  count    = var.deploy_ac && var.cross_account_route53_role_arn != null && local.main_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.main_zone_id
  name    = "*.${var.domain_name}"
  type    = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

# FRPS-behind-AC public DNS (SLACK_QURL_ROLLOUT.md §6, 2026-05-18).
# Customer frpc dials `var.connect_layerv_host` (e.g. `connect.layerv.xyz` /
# `connect.layerv.ai`) on `var.frps_bind_port`; that DNS resolves to the AC
# NLB. Per-env zone:
#   - sandbox: `layerv.xyz` in-account; uses the same `local.main_zone_id`
#     as `ac_domain` above. `var.cross_account_route53_role_arn` is null
#     in sandbox, so the count condition collapses to the in-account
#     branch (below).
#   - prod: `layerv.ai` in `layerv-mgmt`; same cross-account pattern as
#     `ac_domain`. `var.cross_account_route53_role_arn` non-null +
#     `local.main_zone_id` resolved from mgmt → the cross-account branch
#     (this resource) fires.
#
# Two count-gated resources because Terraform doesn't let a single
# `aws_route53_record` swap providers conditionally — the `provider =`
# attribute is module-graph-static. Same shape pattern as `ac_domain` +
# `ac_wildcard` (cross-account) vs the in-account records the AC module
# creates internally when `skip_dns_records = false`.
# `evaluate_target_health = true` on both records below trades "TCP
# connect timeout against an unhealthy AC NLB" for "DNS NXDOMAIN
# against `connect.layerv.{ai,xyz}` when the AC NLB has no healthy
# targets across ANY of its TGs." Route 53 considers an NLB alias
# healthy if any TG on the NLB has at least one healthy target —
# so a FRPS-specific TG break (e.g. `ac_frps_control` unhealthy
# while `ac_tcp` HTTPS:443 stays healthy) will NOT cause NXDOMAIN.
# The FRPS-only-broken case is caught by the boot guard
# (`user_data.sh.tpl`'s `nc -z 127.0.0.1:7000` post-Traefik bind
# check, which exits user_data non-zero) and by the post-deploy
# smoke check in #2007 — not by DNS-level failover.
#
# The trade is deliberate and consistent with the existing
# `ac_domain` / `ac_wildcard` pattern: a fully-degraded AC fleet
# should fail-closed at DNS so customer frpc backs off instead of
# burning retries against a black-hole NLB.
resource "aws_route53_record" "connect_cross_account" {
  # `var.deploy_ac` is AND-ed in even though the `frps_preconditions`
  # block enforces `deploy_frps ⇒ deploy_ac` — the alias below
  # indexes `module.ac[0]`, so a future PR that loosens the precondition
  # would otherwise produce a silent `module.ac[0]` out-of-bounds.
  # Defense in depth on the local count gate.
  count    = var.deploy_ac && var.deploy_frps && var.connect_layerv_host != "" && var.cross_account_route53_role_arn != null && local.main_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.main_zone_id
  name    = var.connect_layerv_host
  type    = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "connect" {
  # Same `var.deploy_ac` defense as the cross-account branch above.
  count = var.deploy_ac && var.deploy_frps && var.connect_layerv_host != "" && var.cross_account_route53_role_arn == null && local.main_zone_id != null ? 1 : 0

  zone_id = local.main_zone_id
  name    = var.connect_layerv_host
  type    = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

# Wildcard DNS for QURL site domains (e.g., *.qurl.site.layerv.xyz)
# Routes all resource-specific subdomains (r_xxx.qurl.site) to the AC NLB,
# where Traefik's QURL Router plugin handles routing to protected backends.
#
# Unlike ac_wildcard above, this doesn't check cross_account_route53_role_arn
# because qurl_site_hosted_zone_id is explicitly provided per environment
# (sandbox: layerv.xyz zone, prod: dedicated qurl.site zone).
resource "aws_route53_record" "qurl_site_wildcard" {
  count    = var.deploy_ac && var.qurl_site_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_site_hosted_zone_id
  name            = "*.${var.qurl_site_domain}"
  type            = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

# ==================== QURL FRP Server ====================
# FRP tunnel server for proxying traffic to customer backends via qurl-reverse-tunnel-client.
# Runs in private subnets, reachable only from AC security group.

# Cross-variable invariant for the qurl-reverse-tunnel-server ASG sizing knobs. Unconditional
# (no `count = deploy_frps ? 1 : 0`) so a typo like `frps_min_size = 3,
# frps_max_size = 1` in tfvars fails plan even while `deploy_frps = false` —
# matching the rationale on the per-variable `>= 1` validations. The module's
# own ASG-resource precondition (`min_size <= desired_capacity <= max_size`)
# stays in place as a second line of defense for module-direct consumers.
resource "terraform_data" "frps_asg_sizing" {
  lifecycle {
    precondition {
      condition     = var.frps_min_size <= var.frps_desired_capacity && var.frps_desired_capacity <= var.frps_max_size
      error_message = "qurl-reverse-tunnel-server ASG sizing must satisfy frps_min_size <= frps_desired_capacity <= frps_max_size (root-level guard so a typo fails plan even when deploy_frps = false)."
    }
  }
}

# Validate that everything the FRP auth plugin needs is wired before the
# module is instantiated. Without these, `qurl-reverse-tunnel-server` would boot with the
# built-in tunnel-auth plugin disabled and any client could register
# arbitrary proxies — an open relay on a publicly-reachable path.
resource "terraform_data" "frps_preconditions" {
  count = var.deploy_frps ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.deploy_ac
      error_message = "deploy_frps requires deploy_ac = true (the AC Traefik is the only way into the FRP control channel)."
    }
    precondition {
      condition     = var.deploy_qurl_service
      error_message = "deploy_frps requires deploy_qurl_service = true — the FRP auth plugin validates tunnel tokens against the QURL API."
    }
    precondition {
      # Treat both `null` and the empty string as "not set" — the downstream
      # module pass-through folds them together into "", and an empty ARN
      # would silently skip the Secrets Manager IAM policy + token-fetch
      # branch, undoing the whole point of this precondition.
      condition     = var.qurl_internal_service_token_arn != null && var.qurl_internal_service_token_arn != ""
      error_message = "deploy_frps requires qurl_internal_service_token_arn to be set to a non-empty value — without it, the FRP auth plugin has no token to present and tunnel auth is effectively disabled."
    }
    precondition {
      # Same null-vs-empty concern as the token above.
      condition     = var.qurl_service_domain != null && var.qurl_service_domain != ""
      error_message = "deploy_frps requires qurl_service_domain to be set to a non-empty value — the FRP auth plugin needs a URL to validate tunnel tokens against."
    }
    precondition {
      # FRPS-behind-AC requires the customer-facing public DNS name for
      # the AC ingress. Without it, the DDB seed row's `resource_fqdn`
      # is empty, the bridge materializes `ResourceInfo.Hostname = ""`,
      # and the agent has no dial target. Set per env: `connect.layerv.xyz`
      # (sandbox), `connect.layerv.ai` (prod). The NLB:${var.frps_bind_port}
      # listener + Route 53 record + AC Traefik TCP entrypoint that this
      # name fronts are all created from this same variable downstream —
      # a missing value at plan time is the earliest signal that the
      # topology won't function.
      condition     = var.connect_layerv_host != ""
      error_message = "deploy_frps requires connect_layerv_host to be set to a non-empty value — the DDB seed row's `resource_fqdn` needs a customer-facing public DNS name for the AC ingress (e.g. `connect.layerv.xyz` for sandbox, `connect.layerv.ai` for prod). See SLACK_QURL_ROLLOUT.md §6 (FRPS-behind-AC redesign 2026-05-18)."
    }
    precondition {
      # Hard-fence on the two DDB-interpolated AC IDs. Quote-injection
      # / shape regex is enforced by the per-variable `validation {}`
      # blocks in `terraform/variables.tf` (apply refuses on bad shape).
      # This precondition is the empty-string failover: an empty value
      # would pass the regex (which permits "") and silently write a
      # malformed DDB row (`ac_id = ""` → every knock returns
      # `ErrACConnectionNotFound`; `auth_service_id = ""` → bridge
      # FilterExpression matches no rows for any aspId). Today's prod
      # envs always set both in tfvars; this fence catches a future
      # greenfield env that forgets one.
      condition     = var.ac_auth_service_id != "" && var.qurl_default_ac_id != ""
      error_message = "deploy_frps requires both ac_auth_service_id and qurl_default_ac_id to be non-empty — the DDB seed row would otherwise be written with `auth_service_id = \"\"` (bridge FilterExpression matches no rows) or `ac_id = \"\"` (every knock returns ErrACConnectionNotFound). Today's prod envs always set both in tfvars; this fence catches a future greenfield env that forgets one."
    }
    precondition {
      # Hard fence on the `connect.layerv.*` Route 53 record actually
      # landing. The two `aws_route53_record.connect{,_cross_account}`
      # resources split on `cross_account_route53_role_arn != null` vs
      # `== null` (mutually exclusive count gates) AND require
      # `local.main_zone_id != null`. If `cross_account_route53_role_arn`
      # is set but the cross-account zone data lookup hasn't populated
      # `main_zone_id` yet (e.g. nhp #2002's cross-account provider
      # alias hasn't landed, or `hosted_zone_id`/`hosted_zone` is
      # missing), BOTH branches collapse to count=0 and `terraform apply`
      # succeeds with zero `connect.layerv.{ai,xyz}` A records. The
      # failure surfaces at customer dial time: DNS lookup fails, frpc
      # hangs, no log line in the AC fleet because no SYN ever arrives.
      # Catch it at plan instead.
      #
      # Condition reads "either we'd opt out (no connect host set) OR
      # we have a resolvable zone for the record." `local.main_zone_id`
      # ternary is identical to the count gate on the two record
      # resources, so this precondition fires under the same conditions
      # the records would silently no-op under.
      condition     = var.connect_layerv_host == "" || local.main_zone_id != null
      error_message = "deploy_frps with connect_layerv_host=${var.connect_layerv_host} requires local.main_zone_id to resolve (via var.hosted_zone_id or the var.hosted_zone data lookup); both aws_route53_record.connect and aws_route53_record.connect_cross_account would otherwise collapse to count=0 and apply would ship without a public DNS record for the FRPS-behind-AC ingress. Set `hosted_zone_id` directly (cross-account path) or `hosted_zone` (in-account lookup) in tfvars."
    }
    precondition {
      # Defensive even though this block also enforces deploy_frps => deploy_ac:
      # keep the reason close to the tunnel-auth mode check. AC issues the
      # knock tokens this mode validates; nhp-server's DNS origin exists
      # without AC.
      condition     = var.qurl_reverse_tunnel_server_tunnel_auth_mode != "tunnel-auth" || var.deploy_ac
      error_message = "qurl_reverse_tunnel_server_tunnel_auth_mode=\"tunnel-auth\" requires deploy_ac=true because AC issues the knock tokens qurl-reverse-tunnel-server validates against the VPC-internal nhp-server origin (server.<namespace>:8888)."
    }
    precondition {
      condition     = var.qurl_reverse_tunnel_server_tunnel_auth_mode == "tunnel-auth"
      error_message = "deploy_frps=true requires qurl_reverse_tunnel_server_tunnel_auth_mode=\"tunnel-auth\". Current qurl-reverse-tunnel-server images no longer support the legacy unset mode."
    }
    precondition {
      # Reject the bootstrap placeholder at plan time when `deploy_frps` is
      # on. The placeholder exists so a Terraform-only operator can't
      # accidentally install a moving `latest`; once CI has overwritten the
      # SSM image-tag parameter, `lifecycle { ignore_changes = [value] }` on
      # that parameter means this variable only drives the *initial* apply.
      # If CI fails between the terraform apply and the tag overwrite, the
      # ASG would roll an instance that tries to `docker pull
      # layerv/qurl-reverse-tunnel-server:v0.0.0-bootstrap` and crash-loop — catch it louder
      # at plan time instead. The regex rejects near-misses too
      # (`v0.0.0-bootstrap-foo`, `v0.0.0-bootstrap2`, etc.) so a typo'd
      # tfvars value can't slip past an exact-match check.
      condition     = !can(regex("^v0\\.0\\.0-bootstrap", var.frps_image_tag))
      error_message = "deploy_frps requires frps_image_tag to be overridden from the bootstrap placeholder. Set it to the real tag CI is publishing."
    }
    precondition {
      # ASG sizing must produce an integer multiple of length(frps_az_suffixes)
      # so each AZ gets the same number of instances at steady state.
      # Resolution rule: per-AZ vars win when set, else legacy triple.
      # When per-AZ form is used the math is automatic: per_az * len * AZs.
      # When legacy form is used we still demand `desired % len == 0` so a
      # historical `desired = 3` with 3 AZ suffixes works, AND a future
      # `desired = 6` with 3 AZ suffixes (= 2/AZ) also works — both flow
      # through the same fence.
      condition = (
        var.qurl_reverse_tunnel_server_desired_capacity_per_az != null
        ? true
        : var.frps_desired_capacity % length(var.frps_az_suffixes) == 0
      )
      error_message = "deploy_frps requires `frps_desired_capacity` to be an integer multiple of length(frps_az_suffixes), or `qurl_reverse_tunnel_server_desired_capacity_per_az` to be set instead. Got frps_desired_capacity=${var.frps_desired_capacity}, length(frps_az_suffixes)=${length(var.frps_az_suffixes)}. Mismatch would distribute instances unevenly across the per-AZ Cloud Map services."
    }
    precondition {
      # min == max == desired (in the resolved form) keeps the ASG at a
      # fixed size that matches the per-AZ Cloud Map fanout; allowing
      # min < desired means a scale-up event would land an instance in
      # some AZ as a duplicate. ASG-per-AZ is the structurally correct
      # fence, tracked under #1499; until that lands this equality keeps
      # the runtime drift bounded.
      #
      # Two forms checked: per-AZ form (when set) requires ALL THREE
      # per-AZ vars to be non-null AND equal — a half-set form (e.g.,
      # only `desired_capacity_per_az = 2` while `min_size_per_az`
      # stays null) would silently let `effective_min_size` fall back
      # to the legacy `var.min_size` (default 1; tfvars-set 3) and
      # produce a fleet where `min < desired`, defeating the fixed-
      # size guarantee. Legacy form requires the explicit triple to be
      # equal. Mixing forms is rejected explicitly.
      condition = (
        var.qurl_reverse_tunnel_server_desired_capacity_per_az != null
        ? (
          var.qurl_reverse_tunnel_server_min_size_per_az != null
          && var.qurl_reverse_tunnel_server_max_size_per_az != null
          && var.qurl_reverse_tunnel_server_min_size_per_az == var.qurl_reverse_tunnel_server_desired_capacity_per_az
          && var.qurl_reverse_tunnel_server_max_size_per_az == var.qurl_reverse_tunnel_server_desired_capacity_per_az
        )
        : (
          var.qurl_reverse_tunnel_server_min_size_per_az == null
          && var.qurl_reverse_tunnel_server_max_size_per_az == null
          && var.frps_min_size == var.frps_max_size
          && var.frps_max_size == var.frps_desired_capacity
        )
      )
      error_message = "deploy_frps requires fixed-size fleet sizing in exactly one form: per-AZ form requires ALL THREE of qurl_reverse_tunnel_server_{min_size,max_size,desired_capacity}_per_az to be set AND equal; legacy form requires qurl_reverse_tunnel_server_*_per_az to be null AND frps_min_size == frps_max_size == frps_desired_capacity. Half-mixes (e.g., only desired_capacity_per_az set) silently fall back to legacy `min_size` for the unset half, breaking the fixed-size guarantee. Pick one form fully."
    }
    precondition {
      # qurl-reverse-tunnel-server blue/green and canary are mutually exclusive; both own
      # the ASG `desired_capacity` field. Sandbox flips blue/green;
      # prod flips canary. A double-flip would sit in a state where
      # CI can't tell which control plane is authoritative.
      condition     = !(var.enable_qurl_reverse_tunnel_server_blue_green && var.enable_qurl_reverse_tunnel_server_canary)
      error_message = "enable_qurl_reverse_tunnel_server_blue_green and enable_qurl_reverse_tunnel_server_canary are mutually exclusive — both own the ASG desired_capacity field. Pick one."
    }
    precondition {
      # MULTIVALUE routing required once steady-state goes above 1/AZ
      # (router-side HRW needs the full A-record set). The module also
      # checks this; the duplicate root-level fence makes the error
      # surface in `terraform plan` against tfvars instead of inside
      # the module's count-gated graph.
      condition = (
        var.qurl_reverse_tunnel_server_cloud_map_routing_policy == "MULTIVALUE"
        || (
          var.qurl_reverse_tunnel_server_desired_capacity_per_az != null
          ? var.qurl_reverse_tunnel_server_desired_capacity_per_az <= 1
          : var.frps_desired_capacity <= length(var.frps_az_suffixes)
        )
      )
      error_message = "qurl_reverse_tunnel_server_cloud_map_routing_policy = \"WEIGHTED\" only supports up to 1 instance per AZ. Flip to \"MULTIVALUE\" before raising desired_capacity above length(frps_az_suffixes) — see traefik-plugins #134 for the router-side HRW that needs the full A-record set."
    }
    precondition {
      # HRW only makes sense with MULTIVALUE routing — WEIGHTED returns
      # a single A record per query, so HRW would always pick that one
      # IP and the dispatch decision wouldn't actually steer traffic.
      condition     = !var.enable_instance_hrw || var.qurl_reverse_tunnel_server_cloud_map_routing_policy == "MULTIVALUE"
      error_message = "enable_instance_hrw = true requires qurl_reverse_tunnel_server_cloud_map_routing_policy = \"MULTIVALUE\" — HRW needs the full healthy-IP set to make a non-trivial dispatch decision. With WEIGHTED routing, DNS only returns one A record per query."
    }
  }
}

module "qurl_reverse_tunnel_server" {
  source = "./modules/qurl-reverse-tunnel-server"
  # `deploy_ac` is already enforced by `terraform_data.frps_preconditions`
  # above, so the module count only needs to key off `deploy_frps`.
  count = var.deploy_frps ? 1 : 0

  # Mirror module.ac's depends_on (terraform/main.tf:953-956): the FRP
  # launch template renders local.qurl_consumer_api_url, which can
  # interpolate the internal-ALB hostname; on first apply the cert+DNS
  # must be live before any FRP instance reads its env. This dependency
  # became load-bearing with the FRP ASG instance_refresh added in #2181
  # (closing #1629): launch-template changes now roll the fleet, so the
  # template must not render internal-origin env before the origin exists.
  # No-op when qurl_internal_service_domain is null (count-gated resources
  # collapse to empty).
  depends_on = [
    terraform_data.frps_preconditions,
    aws_acm_certificate_validation.qurl_internal,
    aws_route53_record.qurl_internal_alias,
  ]

  environment        = var.environment
  name_prefix        = local.name_prefix
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  namespace_id       = module.data.namespace_id
  namespace_name     = module.data.namespace_name
  tags               = merge(local.common_tags, { Service = "qurl-reverse-tunnel-server" })

  # Security: only AC instances can reach the FRP server
  ac_security_group_id = module.ac[0].security_group_id

  # QURL API for FRP auth plugin (built-in tunnel auth in nhp-frps binary).
  # Routed through local.qurl_consumer_api_url, shared with the AC
  # qurl-router consumer above — single edit point for the host-
  # selection rule. Outer guard is just `deploy_qurl_service` because
  # `frps_preconditions` (line 1071) already enforces
  # `qurl_service_domain != null && != ""` whenever `deploy_frps = true`,
  # and the qurl-reverse-tunnel-server module's `^https://[^[:space:]]+$` validation
  # backstops the structural shape on the URL itself.
  qurl_api_internal_url          = var.deploy_qurl_service ? local.qurl_consumer_api_url : ""
  qurl_api_token_secret_arn      = var.deploy_qurl_service && var.qurl_internal_service_token_arn != null && var.qurl_internal_service_token_arn != "" ? var.qurl_internal_service_token_arn : ""
  secrets_kms_key_arn            = module.kms.secrets_key_arn
  nhp_server_internal_url        = local.nhp_server_internal_url
  nhp_internal_auth_secret_arn   = aws_secretsmanager_secret.nhp_internal_auth.arn
  connect_layerv_host            = var.connect_layerv_host
  tunnel_server_az_control_ports = local.tunnel_server_az_control_port
  # Per-environment opt-in to qurl-reverse-tunnel-server tunnel-auth mode:
  # knock-token validation, /internal/v1/tunnel/auth-by-owner, and active
  # target registration. Default "" keeps environments that have not
  # deployed FRPS unchanged; any environment with deploy_frps=true is
  # plan-gated into "tunnel-auth".
  # See module variable doc for the full env-shape contract.
  qurl_tunnel_auth_mode = var.qurl_reverse_tunnel_server_tunnel_auth_mode

  # Instance configuration
  instance_type = var.frps_instance_type

  # ASG sizing — two parallel forms supported:
  #   - Legacy explicit triple (frps_min_size/max_size/desired_capacity).
  #     Default 1/1/1; existing tfvars set 3/3/3 to express 1-per-AZ on
  #     a 3-AZ deploy. Continues working unchanged when per-AZ vars are
  #     null.
  #   - Per-AZ form (qurl_reverse_tunnel_server_*_per_az). When set,
  #     overrides the legacy triple and computes effective sizes as
  #     `per_az * length(suffixes)`. PR 4 will set
  #     qurl_reverse_tunnel_server_desired_capacity_per_az = 2 in prod
  #     tfvars to flip to 2/AZ steady-state.
  # Resolution happens inside the module (see local.effective_* in
  # modules/qurl-reverse-tunnel-server/main.tf).
  min_size                = var.frps_min_size
  max_size                = var.frps_max_size
  desired_capacity        = var.frps_desired_capacity
  min_size_per_az         = var.qurl_reverse_tunnel_server_min_size_per_az
  max_size_per_az         = var.qurl_reverse_tunnel_server_max_size_per_az
  desired_capacity_per_az = var.qurl_reverse_tunnel_server_desired_capacity_per_az

  # Cloud Map per-AZ routing policy. Default WEIGHTED is back-compat;
  # PR 4 flips to MULTIVALUE to support router-side HRW (traefik-plugins
  # #134) and the 2/AZ steady-state distribution.
  cloud_map_routing_policy = var.qurl_reverse_tunnel_server_cloud_map_routing_policy

  # Blue/green deployment (sandbox-targeted). Default false; mutually
  # exclusive with the canary form below — enforced by precondition in
  # `terraform_data.frps_preconditions` above.
  enable_blue_green             = var.enable_qurl_reverse_tunnel_server_blue_green
  green_standby_capacity_per_az = var.qurl_reverse_tunnel_server_green_standby_capacity_per_az

  # Per-AZ Cloud Map suffixes — must agree with the qurl-service env vars
  # below (QURL_FRPS_AZ_SUFFIXES) and with the upstream `frpc` consumption
  # side (i.e. the FRP client embedded in qurl-reverse-tunnel-client). See
  # the qurl-reverse-tunnel-server module header for the cross-repo contract.
  frps_az_suffixes = var.frps_az_suffixes

  # Port configuration (shared with AC module via root variables)
  frps_bind_port       = var.frps_bind_port
  frps_vhost_http_port = var.frps_vhost_http_port
  # FRP's `subDomainHost` must match qurl-router's customer-vhost domain
  # for tunnel registrations to resolve to the right `<customer>.<base>`
  # FQDN. qurl_router_config.base_domain is wired from var.qurl_site_domain
  # (terraform/main.tf's qurl_router_config local above), so thread from
  # the same source of truth here — avoids the sandbox/prod drift that
  # would happen with a hardcoded default (sandbox runs on
  # qurl.site.layerv.xyz, prod on qurl.site).
  frps_subdomain_host = var.qurl_site_domain

  # KMS encryption keys
  logs_kms_key_arn = module.kms.logs_key_arn
  ebs_kms_key_arn  = module.kms.ebs_key_arn

  # Deployment configuration (frps has its own release cadence, separate from NHP server/AC)
  image_tag = var.frps_image_tag

  # Plugin bucket for the S3-hosted FRPS init script and fallback binary
  # download path in user_data.
  # Consistent with how the AC module is wired (see `plugin_bucket_arn` on
  # the ac module above); same bucket scoped to the qurl-reverse-tunnel-server subtree.
  # Arn, name, and shared download policy are threaded from the same module:
  # arn scopes the legacy binary fallback grant, name is baked into the
  # runtime `aws s3 cp` commands, and the shared policy provides the plugin
  # bucket KMS decrypt grant required by the S3 bootstrap script.
  plugin_bucket_arn          = module.plugins.bucket_arn
  plugin_bucket_name         = module.plugins.bucket_name
  plugin_download_policy_arn = module.plugins.download_policy_arn

  # Monitoring
  enable_cloudwatch_alarms = true
  alarm_sns_topic_arn      = module.monitoring.sns_topic_arn
}

# State move for the qurl-frps → qurl-reverse-tunnel-server rebrand
# (#1742). Address changed from `module.qurl_frps[*]` to
# `module.qurl_reverse_tunnel_server[*]` without rebuilding any
# resources. Safe to remove once every workspace has applied this
# commit.
moved {
  from = module.qurl_frps
  to   = module.qurl_reverse_tunnel_server
}

# ==================== QURL Service ====================
# ECS Fargate deployment for the QURL API service
# Public API protected by Auth0 JWT, no NHP protection needed

# ACM Certificate for QURL API custom domain
resource "aws_acm_certificate" "qurl_api" {
  count             = var.deploy_qurl_service && var.qurl_service_domain != null ? 1 : 0
  domain_name       = var.qurl_service_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-api-cert"
  })
}

# DNS validation records for QURL API certificate
# Uses route53_mgmt provider for cross-account DNS validation (prod: layerv.ai zone in mgmt account)
resource "aws_route53_record" "qurl_api_cert_validation" {
  provider = aws.route53_mgmt
  for_each = var.deploy_qurl_service && var.qurl_service_domain != null ? {
    for dvo in aws_acm_certificate.qurl_api[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.qurl_hosted_zone_id
}

# Wait for certificate validation to complete
resource "aws_acm_certificate_validation" "qurl_api" {
  count                   = var.deploy_qurl_service && var.qurl_service_domain != null ? 1 : 0
  certificate_arn         = aws_acm_certificate.qurl_api[0].arn
  validation_record_fqdns = [for record in aws_route53_record.qurl_api_cert_validation : record.fqdn]
}

# DNS A record for QURL API domain pointing to ALB
# Uses route53_mgmt provider for cross-account DNS (prod: layerv.ai zone in mgmt account)
resource "aws_route53_record" "qurl_api" {
  count    = var.deploy_qurl_service && var.qurl_service_domain != null && var.qurl_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_hosted_zone_id
  name    = var.qurl_service_domain
  type    = "A"

  alias {
    name                   = module.qurl_service[0].alb_dns_name
    zone_id                = module.qurl_service[0].alb_zone_id
    evaluate_target_health = true
  }
}

# ==================== QURL Service — internal ALB cert + private DNS ====================
# Split-horizon DNS for the internal-only QURL API surface.
#
# Public mgmt zone (layerv.{xyz,ai}) gets ONLY the ACM DNS-01 validation
# CNAME — no A record. External resolvers return NXDOMAIN for
# internal-api.qurl.layerv.*.
#
# A workload-account private hosted zone of the same name is attached
# to the workload VPC; its A-alias points at the internal ALB. VPC
# Route 53 Resolver consults the PHZ regardless of caller subnet, so
# AC instances in public subnets and NHP server in private subnets
# both resolve to ENI IPs without leaving the VPC.
#
# This pattern lets ACM validate without the cert ever existing
# publicly: ACM only needs the challenge CNAME, not an A record.
# See PR #1588 body for the trust-model rationale.
locals {
  # Internal-ALB enablement is implicit: a non-null, non-empty
  # qurl_internal_service_domain means "stand up the internal ALB and
  # everything that goes with it." To disable, null out the domain
  # variable in tfvars (and re-apply). Chosen over an explicit boolean
  # because every consumer the internal ALB serves needs the hostname
  # anyway, and a "domain set but enabled=false" combination would be
  # nonsensical / a config-drift trap. The empty-string guard is
  # defense-in-depth — the variable's RFC1035 validation already
  # rejects "" (terraform/variables.tf:710-713) — but keeping the check
  # local-side means a future loosening of the variable validation
  # can't silently flip this to true on "".
  qurl_internal_alb_enabled = var.deploy_qurl_service && var.qurl_internal_service_domain != null && var.qurl_internal_service_domain != ""

  # Internal-preferring URL for /internal/v1/* consumers (AC qurl-router
  # plugin and FRP auth plugin). Single source of truth for "where do
  # internal consumers reach the QURL service": prefer the workload-
  # account internal-ALB hostname when up, fall back to the public
  # domain on greenfield envs. Centralized so adding the next consumer
  # doesn't need to re-derive the host-selection rule.
  #
  # Preconditions for evaluation:
  # - When local.qurl_internal_alb_enabled = true: var.qurl_internal_service_domain is non-empty (enforced above).
  # - When false: var.qurl_service_domain must be set non-null AND
  #   non-empty. Today's protection is uneven — null_resource.qurl_
  #   router_domain_validation catches `null` only (not `""`), and
  #   var.qurl_service_domain has no variable-level validation, so
  #   each consumer carries its own guard:
  #     - AC: relies on var.qurl_router_enabled gating + the
  #       null-only null_resource above; if an operator sets
  #       qurl_router_enabled=true and qurl_service_domain="", the
  #       local resolves to "https://" and is passed straight through
  #       (#1630 will harden empty-string handling at the variable
  #       level).
  #     - FRP: has its own explicit `!= null && != ""` ternary at the
  #       consume site (terraform/main.tf:1125).
  #   The asymmetry is documented at the FRP consume site.
  qurl_consumer_api_url = "https://${local.qurl_internal_alb_enabled ? var.qurl_internal_service_domain : var.qurl_service_domain}"
}

resource "aws_acm_certificate" "qurl_internal" {
  count             = local.qurl_internal_alb_enabled ? 1 : 0
  domain_name       = var.qurl_internal_service_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-internal-cert"
  })
}

# DNS-01 validation record on the public mgmt-account zone. Mirrors the
# qurl_api_cert_validation pattern; same provider, same IAM perms,
# same shape.
resource "aws_route53_record" "qurl_internal_cert_validation" {
  provider = aws.route53_mgmt
  for_each = local.qurl_internal_alb_enabled ? {
    for dvo in aws_acm_certificate.qurl_internal[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.qurl_hosted_zone_id
}

resource "aws_acm_certificate_validation" "qurl_internal" {
  count                   = local.qurl_internal_alb_enabled ? 1 : 0
  certificate_arn         = aws_acm_certificate.qurl_internal[0].arn
  validation_record_fqdns = [for record in aws_route53_record.qurl_internal_cert_validation : record.fqdn]
}

# Private hosted zone in the workload account, attached to the workload
# VPC. The zone name IS the FQDN (apex zone for the FQDN itself), which
# is load-bearing for the whole split-horizon design: every in-VPC
# query for $domain or any subdomain (including _acme-challenge.$domain)
# is answered authoritatively by this zone. Sibling records can't leak
# in, and a future operator running `terraform destroy
# aws_route53_zone.qurl_internal_private` can't accidentally take down
# any unrelated internal-DNS records.
resource "aws_route53_zone" "qurl_internal_private" {
  count   = local.qurl_internal_alb_enabled ? 1 : 0
  name    = var.qurl_internal_service_domain
  comment = "Workload-account PHZ for the QURL API internal ALB (qurl-service #335 network isolation). External resolvers return NXDOMAIN."

  vpc {
    vpc_id = module.networking.vpc_id
  }

  # Because this PHZ is the apex zone for ${qurl_internal_service_domain},
  # in-VPC queries for _acme-challenge.${qurl_internal_service_domain}
  # are answered by this zone authoritatively as NXDOMAIN ("no record in
  # zone"). ACM cert renewal validates externally and is unaffected. Any
  # future in-VPC tooling that tries to verify the cert validation CNAME
  # (cert-manager, internal probes, etc.) will need to either query the
  # public mgmt zone directly or add a passthrough record to this PHZ.

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-internal-phz"
  })

  # Single-record zone, but a future rename would otherwise destroy
  # before recreate and briefly NXDOMAIN the internal hostname from
  # inside the VPC — breaking every in-flight NHP plugin / Traefik
  # plugin call.
  lifecycle {
    create_before_destroy = true
  }
}

# A-alias from the internal hostname to the internal ALB. Lives in the
# private zone above, NOT in the public mgmt zone — leaking this record
# publicly would announce a private IP space to the internet.
resource "aws_route53_record" "qurl_internal_alias" {
  count   = local.qurl_internal_alb_enabled ? 1 : 0
  zone_id = aws_route53_zone.qurl_internal_private[0].id
  name    = var.qurl_internal_service_domain
  type    = "A"

  alias {
    name                   = module.qurl_service[0].internal_alb_dns_name
    zone_id                = module.qurl_service[0].internal_alb_zone_id
    evaluate_target_health = true
  }

  # The PHZ above uses create_before_destroy to avoid a NXDOMAIN window
  # on rename — that protection is incomplete unless this record also
  # creates before destroy. Without CBD here, a rename forces this
  # record through destroy→create even though the zone itself swapped
  # cleanly, briefly NXDOMAINing in-VPC callers.
  lifecycle {
    create_before_destroy = true
  }
}

# ==================== Website Email-Capture API (web-api.layerv.ai) ====================
# The APIGW v2 custom domain is provisioned in layerv-prod us-east-1 by the
# website CDK stack (LayerV-production-Api → ApiDomainName). This terraform
# root owns the Route 53 A-alias only, because the layerv.ai zone lives in
# the layerv-mgmt account and is managed here.
#
# Split rationale: the website repo has S3/CloudFront/Lambda/APIGW IAM but
# no cross-account Route 53 perms; this repo has the mgmt-account provider.
# See layervai/website#188 (api.layerv.ai was taken over by QURL and the
# website tracker silently 404'd for weeks until a new hostname was carved
# out). Source of truth for `apiDomain` is
# layervai/website/infra/lib/config.ts.
#
# The alias target is read from the website CDK stack's CloudFormation outputs
# (ApiCustomDomainRegionalDomainName + ApiCustomDomainRegionalHostedZoneId).
# The AWS provider does not ship an aws_apigatewayv2_domain_name data source,
# so reading CFN stack outputs is the supported path. This creates a plan-time
# (not just apply-time) dependency on the website CDK stack: if it is torn
# down, `terraform plan` here fails until deploy_website_api_dns is flipped
# off. Longer-term: have the website stack publish these to SSM so this repo
# reads data.aws_ssm_parameter instead of a CFN stack lookup.

locals {
  # All four inputs are load-bearing. Gate count on every one so the data
  # source and record never try to evaluate with null inputs — ugly provider
  # errors are replaced by clean precondition errors on the terraform_data
  # block below. If any input is unset while deploy_website_api_dns = true,
  # count here is 0 and the precondition fires first with a readable message.
  website_api_dns_enabled = (
    var.deploy_website_api_dns &&
    var.website_api_domain != null &&
    var.qurl_hosted_zone_id != null &&
    var.website_api_cfn_stack_name != null
  )
}

# Fail plan loudly if deploy_website_api_dns is flipped on without its inputs
# wired up. Mirrors the billing_preconditions pattern above.
resource "terraform_data" "website_api_preconditions" {
  count = var.deploy_website_api_dns ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.website_api_domain != null
      error_message = "website_api_domain is required when deploy_website_api_dns = true."
    }
    precondition {
      condition     = var.qurl_hosted_zone_id != null
      error_message = "qurl_hosted_zone_id is required when deploy_website_api_dns = true (the layerv.ai zone in mgmt account)."
    }
    precondition {
      condition     = var.website_api_cfn_stack_name != null
      error_message = "website_api_cfn_stack_name is required when deploy_website_api_dns = true (the website CDK stack name, e.g. LayerV-production-Api)."
    }
  }
}

# NOTE: no depends_on here. A data source with depends_on on a not-yet-created
# managed resource gets deferred to apply, which would make the route53 record
# alias render as `(known after apply)` on the first plan and weaken the
# review signal. The gate lives on the consumer (aws_route53_record.website_api)
# instead — same pattern as billing_preconditions → module.billing above.
data "aws_cloudformation_stack" "website_api" {
  count    = local.website_api_dns_enabled ? 1 : 0
  provider = aws.us_east_1
  name     = var.website_api_cfn_stack_name

  lifecycle {
    # Defend against the CDK output-key contract drifting under us. CDK
    # autogenerates output logical IDs unless the construct pins them;
    # assert the two keys we consume exist and are non-empty so a silent
    # rename in the website repo surfaces as a plan-time error rather
    # than as a 500 on web-api.layerv.ai weeks later. Issue #1218 (SSM
    # decoupling) removes this contract entirely when it lands.
    postcondition {
      condition     = try(length(self.outputs["ApiCustomDomainRegionalDomainName"]) > 0, false)
      error_message = "Website CDK stack ${var.website_api_cfn_stack_name} must expose ApiCustomDomainRegionalDomainName as a non-empty output (see layervai/website/infra/lib/api-stack.ts)."
    }
    postcondition {
      condition     = try(length(self.outputs["ApiCustomDomainRegionalHostedZoneId"]) > 0, false)
      error_message = "Website CDK stack ${var.website_api_cfn_stack_name} must expose ApiCustomDomainRegionalHostedZoneId as a non-empty output (see layervai/website/infra/lib/api-stack.ts)."
    }
  }
}

resource "aws_route53_record" "website_api" {
  count    = local.website_api_dns_enabled ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_hosted_zone_id # layerv.ai zone in mgmt account
  name    = var.website_api_domain
  type    = "A"

  alias {
    name                   = data.aws_cloudformation_stack.website_api[0].outputs["ApiCustomDomainRegionalDomainName"]
    zone_id                = data.aws_cloudformation_stack.website_api[0].outputs["ApiCustomDomainRegionalHostedZoneId"]
    evaluate_target_health = false # APIGW custom domains don't expose health to Route 53
  }

  # Keep the precondition gate inline with apply ordering even though
  # local.website_api_dns_enabled already short-circuits count — belt-and-
  # suspenders against a future edit that loosens the count predicate.
  depends_on = [terraform_data.website_api_preconditions]
}

# ==================== Redis (Distributed Rate Limiting) ====================

module "redis" {
  count  = var.deploy_redis ? 1 : 0
  source = "./modules/redis-cluster"

  name_prefix        = local.name_prefix
  cell_id            = var.cell_id
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids
  kms_key_arn        = module.kms.secrets_key_arn
  tags               = local.common_tags
}

data "aws_secretsmanager_secret" "billing_stripe" {
  count = var.billing_stripe_secret_name != null ? 1 : 0
  name  = var.billing_stripe_secret_name
}

module "qurl_service" {
  count  = var.deploy_qurl_service ? 1 : 0
  source = "./modules/qurl-service"

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  tags        = merge(local.common_tags, { Service = "qurl" })

  # Networking
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = module.networking.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids
  public_subnet_ids  = module.networking.public_subnet_ids

  # Container configuration
  ecr_repo_url        = module.ecr.qurl_repo_url
  image_tag_ssm_param = "/${local.name_prefix}/qurl-api-image-tag"
  container_cpu       = var.qurl_container_cpu
  container_memory    = var.qurl_container_memory
  # container_port is also threaded into module.bootstrap_alb.target_port
  # below so the two cannot drift; see var.qurl_container_port description.
  container_port           = var.qurl_container_port
  desired_count            = var.qurl_desired_count
  autoscaling_min_capacity = var.qurl_autoscaling_min_capacity
  autoscaling_max_capacity = var.qurl_autoscaling_max_capacity

  # DynamoDB
  dynamodb_table_arns   = module.dynamodb.qurl_table_arns
  dynamodb_table_prefix = "${local.name_prefix}-${var.cell_id}"

  # Auth0
  auth0_domain                     = var.qurl_auth0_domain
  auth0_audience                   = var.qurl_auth0_audience
  auth0_jwks_cache_ttl_seconds     = var.qurl_auth0_jwks_cache_ttl_seconds
  auth0_jwks_fetch_timeout_seconds = var.qurl_auth0_jwks_fetch_timeout_seconds

  # Secrets
  secrets_kms_key_arn        = module.kms.secrets_key_arn
  jwt_secret_arn             = var.qurl_jwt_secret_arn
  internal_service_token_arn = var.qurl_internal_service_token_arn

  # Shared HMAC secret for signing outbound /nhp/internal/knock requests.
  # Must match the value nhp-server reads on the verifier side.
  nhp_internal_auth_secret_arn = aws_secretsmanager_secret.nhp_internal_auth.arn

  # Stripe billing
  stripe_secret_arn           = var.billing_stripe_secret_name != null ? data.aws_secretsmanager_secret.billing_stripe[0].arn : ""
  stripe_growth_price_id      = var.billing_growth_price_id
  stripe_checkout_success_url = var.deploy_billing ? var.billing_success_url : ""
  stripe_checkout_cancel_url  = var.deploy_billing ? var.billing_cancel_url : ""

  # Usage events (billing metered usage)
  usage_events_enabled   = var.deploy_billing
  usage_events_queue_url = var.deploy_billing ? module.billing[0].usage_events_queue_url : ""
  usage_events_queue_arn = var.deploy_billing ? module.billing[0].usage_events_queue_arn : ""

  # KMS
  logs_kms_key_arn = module.kms.logs_key_arn

  # NHP integration (headless resolve)
  nhp_server_internal_url = local.nhp_server_internal_url

  # qurl-reverse-tunnel-server routing (#1499). qurl-service is the
  # upstream_addr oracle; with per-AZ public control ingress, every
  # suffix in var.frps_az_suffixes is reachable by a matching
  # qurl-tunnel-server-{suffix} NHP resource row.
  frps_az_suffixes = var.deploy_frps ? join(",", var.frps_az_suffixes) : ""
  frps_domain      = var.deploy_frps ? module.data.namespace_name : ""
  frps_port        = var.deploy_frps ? var.frps_vhost_http_port : 0

  # QURL defaults
  cookie_domain        = var.qurl_cookie_domain
  qurl_link_domain     = var.qurl_link_domain
  qurl_site_domain     = var.qurl_site_domain
  default_token_expire = var.qurl_default_token_expire
  default_open_time    = var.qurl_default_open_time

  # Rate limiting
  ip_rate_limit = var.qurl_ip_rate_limit
  ip_rate_burst = var.qurl_ip_rate_burst

  # Redis (distributed rate limiting)
  redis_enabled           = var.deploy_redis
  redis_endpoint          = var.deploy_redis ? "${module.redis[0].endpoint}:${module.redis[0].port}" : ""
  redis_security_group_id = var.deploy_redis ? module.redis[0].security_group_id : null

  # Audit
  audit_retention_days = var.qurl_audit_retention_days

  # CORS
  cors_allowed_origins = var.qurl_cors_allowed_origins

  # Security
  additional_allowed_hosts = var.qurl_additional_allowed_hosts

  # AC Fleet defaults
  default_ac_id   = var.qurl_default_ac_id
  default_ac_port = var.qurl_default_ac_port

  # QURL agent → nhp-server bootstrap chain (Wave 5 dark-launch).
  # Threaded directly from the nhp-server side outputs (nhp_keypair +
  # compute NLB) so the agent's view of the responder can never drift
  # from what nhp-server actually publishes. The module gates env-var
  # injection on `deploy_qurl_bootstrap_chain`, so passing the module
  # outputs unconditionally here is harmless when the gate is off (the
  # values reach the module but are not rendered into the task def).
  # `enable_qurl_agent_bootstrap` is the per-env activation flag —
  # kept on a separate var so the activation is a one-line tfvars edit,
  # matching the dark-launch pattern across this tree.
  #
  # The pubkey threaded here is the NHP-server IDENTITY key (from the
  # compute module's Secrets-Manager-backed keypair), NOT the
  # AC↔server registration key from module.nhp_keypair. Two distinct
  # keys are at play, and conflating them silently 100%-fails every
  # agent knock with an `[NHP-KNK] packet precheck failed: server
  # HMAC validation failed` log line on the responder side. See
  # module.compute's `server_public_key_b64` output comment for the
  # full contract. A prior revision of this wiring used
  # `module.nhp_keypair.registration_public_key` and bricked the
  # entire reverse-tunnel boot path in sandbox until isolated via
  # qurl-reverse-tunnel-client smoke.
  #
  # Cell-isolation note (retained from the prior wiring's comment,
  # retargeted): module.compute is per-cell-scoped via name_prefix
  # / cell_id, so module.compute.server_public_key_b64 is the
  # per-cell server-identity key — this wiring stays correct under
  # a future multi-cell topology because each qurl_service instance
  # is paired with the compute it actually fronts. If a future
  # topology ever has qurl-service fan out to multiple compute
  # cells, this wire becomes the spot to multiplex per-cell pubkeys.
  #
  # Apply-vs-take-effect note: aws_ecs_service.qurl carries
  # lifecycle.ignore_changes = [task_definition] (see modules/
  # qurl-service/main.tf comment near aws_ecs_task_definition.qurl)
  # because CI rolls task definitions out-of-band. So `terraform
  # apply`-ing a change to NHP_SERVER_PUBLIC_KEY_B64 registers a
  # new task-def revision but leaves the running service on the
  # prior revision. The corrected pubkey takes effect on the NEXT
  # qurl-service CI deploy (which picks up the newest revision via
  # `aws ecs describe-task-definition` + `update-service
  # --force-new-deployment`). If a smoke needs the env to apply
  # immediately post-tf-apply, trigger the deploy workflow
  # manually rather than waiting for the next merge.
  deploy_qurl_bootstrap_chain = var.deploy_qurl_bootstrap_chain
  enable_qurl_agent_bootstrap = var.enable_qurl_agent_bootstrap
  nhp_server_public_key_b64   = module.compute.server_public_key_b64
  nhp_server_host             = module.compute.nlb_dns_name
  # nhp_server_port is intentionally NOT threaded from a root variable.
  # The port is a code-level constant (62206) hardcoded in three places —
  # `modules/compute/main.tf` (UDP TG), `modules/ac/main.tf` (AC
  # ConnectorClient), and the module-side default. Threading it through
  # a root tfvar would imply per-env configurability that the AC/compute
  # side doesn't honor; #2027 tracks consolidating all three sites into
  # a shared local. Until that lands, the module-side default is the
  # qurl-service-facing source of truth.

  # Domain - use certificate created above if domain is configured
  # DNS record created in root module (not module) for cross-account Route53 support
  domain_name     = var.qurl_service_domain
  hosted_zone_id  = null
  certificate_arn = var.qurl_service_domain != null ? aws_acm_certificate_validation.qurl_api[0].certificate_arn : null

  # Internal ALB opt-in. enforce_internal_alb_only is a second-stage
  # flip — see the variable's description for the rollout sequence.
  internal_alb_enabled      = local.qurl_internal_alb_enabled
  internal_domain_name      = var.qurl_internal_service_domain
  internal_certificate_arn  = local.qurl_internal_alb_enabled ? aws_acm_certificate_validation.qurl_internal[0].certificate_arn : null
  enforce_internal_alb_only = var.qurl_enforce_internal_alb_only

  # Bootstrap-ALB attachment for the customer-sidecar bootstrap chain
  # (paired with module.bootstrap_alb). When deploy_bootstrap_alb=false
  # both expressions short-circuit to null, so the qurl-service module
  # elides both the load_balancer block and the SG ingress — pre-Wave-5
  # posture unchanged. When deploy_bootstrap_alb=true the ECS service
  # registers against the bootstrap-ALB TG and the task SG accepts
  # traffic from the bootstrap-ALB SG; this is what closes the gap
  # that produced 503 nginx-no-healthy-target responses on
  # bootstrap.layerv.<tld> until now.
  #
  # WHY NOT `try(module.bootstrap_alb[0].xxx, null)`: try() would also
  # silently absorb an output rename in bootstrap-alb (the precondition
  # would pass both-null and the wiring would quietly regress — exactly
  # the bug class this PR is fixing). The explicit conditional resolves
  # `module.bootstrap_alb[0].target_group_arn` directly when the module
  # is enabled, so a future rename fails plan-time with "Unsupported
  # attribute" — which is what we want. Issue #2083 still tracks the
  # complementary root-level `check` block for the OTHER failure mode
  # (env-root operator forgetting to thread both passthroughs at all).
  bootstrap_alb_target_group_arn  = var.deploy_bootstrap_alb ? module.bootstrap_alb[0].target_group_arn : null
  bootstrap_alb_security_group_id = var.deploy_bootstrap_alb ? module.bootstrap_alb[0].alb_security_group_id : null

  # ALB access logs (required for production)
  alb_access_logs_bucket = var.qurl_alb_access_logs_bucket

  # Idempotency (distributed via DynamoDB)
  idempotency_table_name               = module.dynamodb.qurl_idempotency_table_name
  idempotency_table_arn                = module.dynamodb.qurl_idempotency_table_arn
  idempotency_cache_ttl_seconds        = var.qurl_idempotency_cache_ttl_seconds
  idempotency_cache_max_size           = var.qurl_idempotency_cache_max_size
  idempotency_cleanup_interval_seconds = var.qurl_idempotency_cleanup_interval_seconds

  apikey_idempotency_table_name = module.dynamodb.qurl_apikey_idempotency_table_name
  apikey_idempotency_table_arn  = module.dynamodb.qurl_apikey_idempotency_table_arn

  # Health check
  health_check_timeout_seconds   = var.qurl_health_check_timeout_seconds
  health_startup_timeout_seconds = var.qurl_health_startup_timeout_seconds

  # Customer cache (tier lookups for quota/rate-limiting)
  customer_cache_ttl_seconds = var.qurl_customer_cache_ttl_seconds
  customer_cache_max_size    = var.qurl_customer_cache_max_size

  # QURL Resource Config
  qurl_default_expires_in_seconds  = var.qurl_default_expires_in_seconds
  qurl_resource_ttl_buffer_seconds = var.qurl_resource_ttl_buffer_seconds
  qurl_session_ttl_seconds         = var.qurl_session_ttl_seconds
  qurl_default_list_limit          = var.qurl_default_list_limit

  # Webhooks
  webhooks_enabled                       = var.qurl_webhooks_enabled
  webhooks_worker_count                  = var.qurl_webhooks_worker_count
  webhooks_max_webhooks_per_owner        = var.qurl_webhooks_max_webhooks_per_owner
  webhooks_delivery_timeout_seconds      = var.qurl_webhooks_delivery_timeout_seconds
  webhooks_max_retries                   = var.qurl_webhooks_max_retries
  webhooks_event_channel_size            = var.qurl_webhooks_event_channel_size
  webhooks_retry_worker_interval_seconds = var.qurl_webhooks_retry_worker_interval_seconds
  webhooks_drain_timeout_seconds         = var.qurl_webhooks_drain_timeout_seconds
  webhooks_response_body_limit           = var.qurl_webhooks_response_body_limit
  webhooks_api_version                   = var.qurl_webhooks_api_version

  # Custom Domains
  custom_domain_enabled                 = var.qurl_custom_domain_enabled
  custom_domain_acme_suffix             = var.qurl_custom_domain_enabled ? "acme.${var.hosted_zone}" : ""
  custom_domain_nlb_target              = var.qurl_custom_domain_enabled && var.deploy_ac ? module.ac[0].nlb_dns_name : ""
  custom_domain_cleanup_topic_arn       = var.qurl_custom_domain_cleanup_topic_arn
  custom_domain_cleanup_publish_enabled = var.qurl_custom_domain_cleanup_publish_enabled

  # GeoIP
  geoip_enabled        = var.qurl_geoip_enabled
  geoip_db_path        = var.qurl_geoip_db_path
  geoip_s3_uri         = var.qurl_geoip_s3_uri
  geoip_s3_kms_key_arn = var.qurl_geoip_s3_kms_key_arn

  # Observability (OpenTelemetry)
  otel_enabled           = var.qurl_otel_enabled
  otel_service_name      = var.qurl_otel_service_name
  otel_service_version   = var.qurl_otel_service_version
  otel_environment       = var.qurl_otel_environment
  otel_exporter_endpoint = var.qurl_otel_exporter_endpoint
  otel_exporter_protocol = var.qurl_otel_exporter_protocol
  otel_exporter_insecure = var.qurl_otel_exporter_insecure
  otel_trace_sample_rate = var.qurl_otel_trace_sample_rate
  otel_metrics_interval  = var.qurl_otel_metrics_interval
  otel_metrics_enabled   = var.qurl_otel_metrics_enabled
  otel_tracing_enabled   = var.qurl_otel_tracing_enabled
  otel_log_correlation   = var.qurl_otel_log_correlation

  # Grafana Cloud (ADOT Sidecar)
  grafana_cloud_enabled = var.qurl_grafana_cloud_enabled
  grafana_secret_arn    = var.qurl_grafana_secret_arn
  adot_collector_image  = var.qurl_adot_collector_image

  # Tunnel auth feature gate (qurl-service PR #277; default false until #405/#396 land)
  tunnel_auth_enabled                 = var.qurl_tunnel_auth_enabled
  tunnel_active_registrations_enabled = var.qurl_tunnel_active_registrations_enabled

  # depends_on:
  #  - terraform_data.nhp_internal_auth_seed: ensure the HMAC secret is seeded
  #    before the ECS task pulls it via valueFrom.
  #  - module.bootstrap_alb: ensure the bootstrap-ALB listener exists before
  #    aws_ecs_service.qurl runs RegisterTargets against the bootstrap-ALB TG
  #    (the cross-module ref on bootstrap_alb_target_group_arn implicitly
  #    orders on the TG only, not the listener — see the dynamic load_balancer
  #    block in modules/qurl-service/main.tf for the failure mode). When
  #    deploy_bootstrap_alb=false the count=0 module contributes nothing.
  #    The narrower dep would be `module.bootstrap_alb[0].alb_listener_rule_arn`
  #    — not the listener itself, since `aws_lb_listener.https` has a
  #    fixed-response 404 default_action; it's `aws_lb_listener_rule.bootstrap`
  #    that actually associates the TG to the LB via its forward action.
  #    `modules/bootstrap-alb/outputs.tf` deliberately omits the listener
  #    and listener-rule outputs to preserve a narrow-surface invariant
  #    (extending the bootstrap ALB via path-based rules is explicitly not
  #    the intended path). Module-level dep is therefore the right trade-off
  #    here; future maintainers should not try to "tighten" without also
  #    revisiting that invariant.
  depends_on = [
    terraform_data.nhp_internal_auth_seed,
    module.bootstrap_alb,
  ]
}

# =============================================================================
# SSM Parameters for QURL Domain Configuration
# These parameters enable CI/CD to read domain configuration from Terraform
# instead of hardcoding values in workflow files.
# =============================================================================

resource "aws_ssm_parameter" "qurl_link_url" {
  name        = "/${var.environment}/nhp/qurl/link-url"
  description = "QURL link frontend URL (e.g., https://qurl.link) - consumed by CI for smoke tests"
  type        = "String"
  value       = "https://${var.qurl_link_domain}"

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ssm-qurl-link-url"
    Component = "qurl"
  })
}

# ==================== Cost Analytics ====================
# AWS Data Exports (CUR 2.0) → S3 (Parquet) → Athena → Grafana dashboard
# Runs in mgmt/payer account for consolidated billing across all accounts.

module "cost_analytics" {
  count  = var.deploy_cost_analytics ? 1 : 0
  source = "./modules/cost-analytics"

  providers = {
    aws = aws.billing_mgmt
  }

  name_prefix                  = "layerv-nhp-mgmt" # mgmt account prefix
  grafana_cloud_aws_account_id = var.grafana_cloud_aws_account_id
  grafana_cloud_external_id    = var.grafana_cloud_external_id
  tags                         = local.common_tags
}

# CI role needs sts:AssumeRole permission to assume into mgmt account
# for cost analytics resources (same pattern as cross-account-route53)
resource "aws_iam_role_policy" "ci_cross_account_cost_analytics" {
  count = var.deploy_cost_analytics && var.cross_account_cost_analytics_role_arn != null ? 1 : 0

  name = "cross-account-cost-analytics"
  role = module.ecr.github_actions_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeCostAnalyticsCrossAccountRole"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = var.cross_account_cost_analytics_role_arn
    }]
  })
}

# ====================================================================
# Smoke-test surface for the custom-domain cleanup consumer (nhp#2000)
# ====================================================================
#
# Tier 2 smoke test (tests/smoke/18_custom_domain_cleanup_test.go) fences
# the SNS-publish → cert-lambda path #1993 introduced. These three
# resources are defined at root (not in env/main.tf) for the same reason
# `qurl_link_url` and `ci_cross_account_cost_analytics` are: the
# sandbox-vs-prod values are pure `var.environment` / `var.aws_region`
# interpolations, and duplicating across envs would require a lockstep
# "don't edit one without the other" convention.

resource "aws_ssm_parameter" "custom_domain_cleanup_topic_arn_for_smoke" {
  count       = var.deploy_custom_domain_cert ? 1 : 0
  name        = "/${var.environment}/nhp/custom-domain-cert/cleanup-topic-arn"
  description = "SNS topic ARN for the custom-domain cleanup consumer. ParameterNotFound is the smoke-test skip gate for envs where the cert lambda isn't deployed."
  type        = "String"
  value       = var.qurl_custom_domain_cleanup_topic_arn

  lifecycle {
    # Same invariant as the IAM precondition below: writing an empty
    # topic-arn into the discovery param would make the smoke test
    # skip silently on an env that actually has the cert lambda
    # deployed. The env-level wiring couples these via
    # deploy_custom_domain_cert, but mirroring the check here makes
    # the invariant self-documenting at both sites.
    precondition {
      condition     = var.qurl_custom_domain_cleanup_topic_arn != ""
      error_message = "deploy_custom_domain_cert=true requires qurl_custom_domain_cleanup_topic_arn to be a non-empty SNS topic ARN. Check the env-level wiring."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-custom-domain-cleanup-topic-arn"
  })
}

resource "aws_ssm_parameter" "custom_domain_cert_manager_log_group_for_smoke" {
  count       = var.deploy_custom_domain_cert ? 1 : 0
  name        = "/${var.environment}/nhp/custom-domain-cert/lambda-log-group"
  description = "CloudWatch log group for the cert manager lambda. Consumed by smoke via FilterLogEvents."
  type        = "String"
  value       = "/aws/lambda/${local.name_prefix}-custom-domain-cert-manager"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-custom-domain-cert-manager-log-group"
  })
}

# CRITICAL — no kms:* grant on this policy. The cleanup topic is encrypted
# with the AWS-managed `alias/aws/sns` key; sns:Publish authorizes
# kms:GenerateDataKey via that key's implicit grant for in-account callers.
# Adding an explicit kms grant would mask a regression where the implicit
# grant changes — which is the exact failure mode the #2000 smoke test is
# the safety net for. SSM resource scope mirrors the smokeCleanupDomainPrefix
# constant in tests/smoke/18_custom_domain_cleanup_test.go; keep in lockstep.
#
# Threat model accepted: IAM cannot restrict sns:Publish by message body,
# so a compromise of github_actions_role could publish a domain.cleanup
# event with an arbitrary domain_name and trigger a real cert delete. The
# narrowing factors are the dispatch-only-from-main convention in
# CLAUDE.md (only main-branch OIDC sub claims pass the trust policy) and
# the fact that github_actions_role is already broadly privileged — the
# marginal blast radius from this Sid is small. If that calculus changes
# (e.g., the role narrows), add a CloudTrail-sourced CW alarm on
# sns:Publish from this principal where the message body doesn't match
# the smoke-cleanup-* prefix.
resource "aws_iam_role_policy" "smoke_custom_domain_cleanup" {
  count = var.deploy_custom_domain_cert ? 1 : 0

  lifecycle {
    # Deliberately duplicates the precondition on
    # aws_ssm_parameter.custom_domain_cleanup_topic_arn_for_smoke above:
    # they share the same `var.deploy_custom_domain_cert ? 1 : 0` count
    # gate so they always fire together, and this is not a missed
    # `locals { ... }` extraction — the dup makes the invariant
    # self-documenting at each consumer (the SSM discovery param the
    # smoke runner reads, and the IAM policy that grants its publish).
    # Surfacing this at plan time keeps the failure mode loud instead of
    # an opaque IAM-resource-arn error at apply.
    precondition {
      condition     = var.qurl_custom_domain_cleanup_topic_arn != ""
      error_message = "deploy_custom_domain_cert=true requires qurl_custom_domain_cleanup_topic_arn to be a non-empty SNS topic ARN. Check the env-level wiring."
    }
  }

  name = "smoke-custom-domain-cleanup"
  role = module.ecr.github_actions_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishCleanupEvent"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [var.qurl_custom_domain_cleanup_topic_arn]
      },
      {
        # Reads/writes/deletes scoped to the smoke-cleanup-* prefix only,
        # and only on the /key, /chain, /meta suffixes the test writes.
        # IAM `*` is a multi-segment glob — it spans `/` — so
        # `.../smoke-cleanup-*/key` still admits
        # `.../smoke-cleanup-foo/bar/baz/key`. Pinning the suffix bounds
        # the LEAF segment, not the entire middle. The narrowing factor
        # the smoke test actually relies on is that the AC cert-sync
        # reads `/nhp/certs/<domain>/{key,chain,meta}` at canonical
        # depth — anything written by this role at a deliberately
        # crafted deeper path would never be read by the cleanup tail.
        # Discovery reads on /{env}/nhp/custom-domain-cert/* go through
        # the github_actions role's pre-existing SSMRead grant
        # (terraform/modules/ecr/main.tf::SSMRead), not this Sid. Note
        # that grant is account-wide (Resource = "*" with ssm:Get*/
        # Describe*/List*), so a compromised role can read AND
        # enumerate any SSM param — including /nhp/certs/* — even
        # though THIS Sid does not. The broader read surface is
        # pre-existing and out of scope for this fence; the threat
        # model accepted above (sns:Publish body-injection) implicitly
        # assumes the read side is at least this wide.
        Sid    = "PreStageAndVerifySmokeCertParams"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:GetParameter",
          "ssm:DeleteParameter",
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/nhp/certs/smoke-cleanup-*/key",
          "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/nhp/certs/smoke-cleanup-*/chain",
          "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter/nhp/certs/smoke-cleanup-*/meta",
        ]
      },
    ]
  })
}

# ==================== API Gateway Account Logging ====================
# Singleton per-region, per-account resource. API Gateway (v1 and v2) requires
# an account-level CloudWatch Logs role to write access logs. Managed here at
# root level so it's instantiated exactly once regardless of which modules need
# API Gateway access logging.

locals {
  deploy_any_apigw = var.deploy_developer_portal || var.deploy_billing

  # Shared CORS origins for all API Gateway modules (developer portal, billing).
  # Individual overrides take precedence; fall back to the shared default.
  dashboard_cors_origins = var.dashboard_allowed_origins
  billing_cors_origins   = length(var.billing_allowed_origins) > 0 ? var.billing_allowed_origins : local.dashboard_cors_origins
  devportal_cors_origins = length(var.developer_portal_allowed_origins) > 0 ? var.developer_portal_allowed_origins : local.dashboard_cors_origins
}

resource "aws_api_gateway_account" "this" {
  count               = local.deploy_any_apigw ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.apigateway_logging[0].arn
}

resource "aws_iam_role" "apigateway_logging" {
  count = local.deploy_any_apigw ? 1 : 0
  name  = "${local.name_prefix}-apigateway-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "apigateway.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-apigateway-logging"
  })
}

resource "aws_iam_role_policy_attachment" "apigateway_logging" {
  count      = local.deploy_any_apigw ? 1 : 0
  role       = aws_iam_role.apigateway_logging[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"

  lifecycle {
    create_before_destroy = true
  }
}

# Allow IAM propagation after the account-level logging role is configured.
# API Gateway checks the CloudWatch role asynchronously; without this delay,
# stage creation with access_log_settings fails with "Insufficient permissions
# to enable logging" due to eventual consistency.
resource "time_sleep" "apigateway_logging_propagation" {
  count           = local.deploy_any_apigw ? 1 : 0
  create_duration = "10s"
  depends_on      = [aws_api_gateway_account.this]
}

# ==================== Developer Portal ====================
# Playground proxy and credential provisioner for the developer experience.
# Separate HTTP API with Lambda backends, DynamoDB tables, and CORS.

# ACM certificate for custom domain (regional — same region as API Gateway)
resource "aws_acm_certificate" "developer_portal" {
  count             = var.deploy_developer_portal && var.developer_portal_custom_domain != null ? 1 : 0
  domain_name       = var.developer_portal_custom_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-developer-portal-cert"
  })
}

resource "aws_route53_record" "developer_portal_cert_validation" {
  for_each = var.deploy_developer_portal && var.developer_portal_custom_domain != null && var.developer_portal_hosted_zone_id != null ? {
    for dvo in aws_acm_certificate.developer_portal[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  provider = aws.route53_mgmt

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.developer_portal_hosted_zone_id
}

resource "aws_acm_certificate_validation" "developer_portal" {
  count                   = var.deploy_developer_portal && var.developer_portal_custom_domain != null ? 1 : 0
  certificate_arn         = aws_acm_certificate.developer_portal[0].arn
  validation_record_fqdns = var.developer_portal_hosted_zone_id != null ? [for record in aws_route53_record.developer_portal_cert_validation : record.fqdn] : null
}

# Route53 A record for developer portal custom domain
resource "aws_route53_record" "developer_portal" {
  count    = var.deploy_developer_portal && var.developer_portal_custom_domain != null && var.developer_portal_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.developer_portal_hosted_zone_id
  name    = var.developer_portal_custom_domain
  type    = "A"

  alias {
    name                   = module.developer_portal[0].custom_domain_target_domain_name
    zone_id                = module.developer_portal[0].custom_domain_target_hosted_zone_id
    evaluate_target_health = false
  }
}

module "developer_portal" {
  count  = var.deploy_developer_portal ? 1 : 0
  source = "./modules/developer-portal"

  # Ensure the account-level API GW logging role has propagated before the
  # module creates a stage with access_log_settings.
  depends_on = [time_sleep.apigateway_logging_propagation]

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = merge(local.common_tags, { Service = "developer-portal" })

  logs_kms_key_arn     = module.kms.logs_key_arn
  dynamodb_kms_key_arn = module.kms.secrets_key_arn

  playground_m2m_secret_name = var.developer_portal_m2m_secret_name
  auth0_mgmt_secret_name     = var.developer_portal_auth0_mgmt_secret_name

  qurl_api_url = "https://${var.qurl_service_domain}"
  auth0_domain = var.developer_portal_auth0_domain

  allowed_origins = local.devportal_cors_origins
  sns_topic_arn   = module.monitoring.sns_topic_arn

  # Custom domain — Route53 record created in root module for cross-account support
  custom_domain       = var.developer_portal_custom_domain
  hosted_zone_id      = null
  acm_certificate_arn = var.developer_portal_custom_domain != null ? aws_acm_certificate_validation.developer_portal[0].certificate_arn : null

  # CI bypass key for integration tests
  ci_bypass_secret_name = var.developer_portal_ci_bypass_secret_name

  # File-upload route's connector base URL. Each env must set this
  # explicitly in its tfvars so sandbox can't silently coalesce onto
  # the prod S3 connector. No fallback — the module variable has its
  # own default for unit-testing only; the root insists on an
  # explicit env-level value.
  connector_base_url = var.developer_portal_connector_base_url
}

# ==================== Billing ====================
# Stripe billing integration: checkout sessions, webhooks, usage reporting,
# reconciliation, payment grace periods, and invoice retrieval.

# Validate required billing variables before the module is instantiated.
resource "terraform_data" "billing_preconditions" {
  count = var.deploy_billing ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.billing_stripe_secret_name != null
      error_message = "billing_stripe_secret_name is required when deploy_billing = true."
    }
    precondition {
      condition     = var.billing_stripe_webhook_secret_name != null
      error_message = "billing_stripe_webhook_secret_name is required when deploy_billing = true."
    }
    precondition {
      condition     = var.billing_success_url != null
      error_message = "billing_success_url is required when deploy_billing = true."
    }
    precondition {
      condition     = var.billing_cancel_url != null
      error_message = "billing_cancel_url is required when deploy_billing = true."
    }
    precondition {
      condition     = length(local.billing_cors_origins) > 0
      error_message = "billing_allowed_origins (or dashboard_allowed_origins) must contain at least one origin when deploy_billing = true."
    }
    precondition {
      condition     = var.billing_from_email != null
      error_message = "billing_from_email is required when deploy_billing = true."
    }
    precondition {
      condition     = module.dynamodb.qurl_billing_audit_table_name != null
      error_message = "QURL DynamoDB tables (including billing_audit) must be deployed when deploy_billing = true. Set deploy_qurl_tables = true."
    }
  }
}

module "billing" {
  count  = var.deploy_billing ? 1 : 0
  source = "./modules/billing"

  # Ensure the account-level API GW logging role has propagated before the
  # module creates a stage with access_log_settings.
  depends_on = [time_sleep.apigateway_logging_propagation, terraform_data.billing_preconditions]

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = merge(local.common_tags, { Service = "billing" })

  # Encryption
  logs_kms_key_arn     = module.kms.logs_key_arn
  sqs_kms_key_arn      = module.kms.secrets_key_arn
  dynamodb_kms_key_arn = module.kms.secrets_key_arn

  # Auth0 / JWT
  auth0_domain   = var.qurl_auth0_domain
  auth0_audience = var.qurl_auth0_audience

  # Stripe secrets
  stripe_secret_name         = var.billing_stripe_secret_name
  stripe_webhook_secret_name = var.billing_stripe_webhook_secret_name
  stripe_api_base_url        = var.billing_stripe_api_base_url

  # DynamoDB tables (created by dynamodb module)
  customers_table_name     = module.dynamodb.qurl_customers_table_name
  customers_table_arn      = module.dynamodb.qurl_customers_table_arn
  billing_audit_table_name = coalesce(module.dynamodb.qurl_billing_audit_table_name, "")
  billing_audit_table_arn  = coalesce(module.dynamodb.qurl_billing_audit_table_arn, "")

  # Stripe Price IDs
  growth_price_id   = var.billing_growth_price_id
  base_fee_price_id = var.billing_base_fee_price_id

  # URLs
  success_url = var.billing_success_url
  cancel_url  = var.billing_cancel_url

  # CORS (falls back to shared dashboard_allowed_origins if billing-specific not set)
  allowed_origins = local.billing_cors_origins

  # Email (SES)
  from_email = var.billing_from_email
  ses_region = var.billing_ses_region

  # Monitoring
  sns_topic_arn = module.monitoring.sns_topic_arn

  # Grace period
  grace_period_days    = var.billing_grace_period_days
  downgrade_after_days = var.billing_downgrade_after_days

  # Throttling
  api_throttle_burst_limit = var.billing_api_throttle_burst_limit
  api_throttle_rate_limit  = var.billing_api_throttle_rate_limit
}

# ==================== Grafana Cloud Dashboards ====================
# Provisions QURL dashboards to Grafana Cloud
# Requires a Grafana Cloud API key with Editor permissions

locals {
  grafana_athena_enabled   = var.deploy_cost_analytics || var.grafana_athena_config != null
  grafana_athena_role_arn  = var.deploy_cost_analytics ? module.cost_analytics[0].grafana_athena_role_arn : (var.grafana_athena_config != null ? var.grafana_athena_config.assume_role_arn : "")
  grafana_athena_workgroup = var.deploy_cost_analytics ? module.cost_analytics[0].athena_workgroup_name : (var.grafana_athena_config != null ? var.grafana_athena_config.workgroup : "")
  grafana_athena_database  = var.deploy_cost_analytics ? module.cost_analytics[0].glue_database_name : (var.grafana_athena_config != null ? var.grafana_athena_config.database : "")
  grafana_athena_region    = var.deploy_cost_analytics ? module.cost_analytics[0].athena_region : (var.grafana_athena_config != null ? var.grafana_athena_config.region : "us-east-1")
}

module "grafana_dashboards" {
  source = "./modules/grafana-dashboards"
  count  = var.grafana_dashboards_enabled ? 1 : 0

  providers = {
    grafana = grafana
  }

  grafana_url               = var.grafana_url
  environment               = var.environment
  create_dashboards         = var.grafana_create_dashboards
  prometheus_datasource_uid = var.grafana_prometheus_datasource_uid
  tempo_datasource_uid      = var.grafana_tempo_datasource_uid

  # CloudWatch data source for NHP Infrastructure dashboard
  cloudwatch_datasource_enabled = var.grafana_cloudwatch_enabled
  aws_region                    = var.aws_region
  name_prefix                   = local.name_prefix
  grafana_cloud_aws_account_id  = var.grafana_cloud_aws_account_id
  grafana_cloud_external_id     = var.grafana_cloud_external_id

  # Athena data source for AWS Cost dashboard
  athena_datasource_enabled = local.grafana_athena_enabled
  athena_assume_role_arn    = local.grafana_athena_role_arn
  athena_workgroup          = local.grafana_athena_workgroup
  athena_database           = local.grafana_athena_database
  athena_region             = local.grafana_athena_region

  # QURL alert rules — see docs/slo.md and docs/runbooks/qurl-*.md.
  # Routes alerts through the existing monitoring SNS topic so the new
  # qurl-api alerts land in the same Slack/email channels as every other
  # prod alert. Ships paused; flip qurl_alerts_paused after 24h soak.
  qurl_alerts_enabled             = var.qurl_alerts_enabled
  qurl_alerts_paused              = var.qurl_alerts_paused
  qurl_alerts_sns_topic_arn       = module.monitoring.sns_topic_arn
  qurl_alerts_runbook_base_url    = var.qurl_alerts_runbook_base_url
  qurl_alerts_slo_target_percent  = var.qurl_alerts_slo_target_percent
  qurl_alerts_loki_datasource_uid = var.grafana_loki_datasource_uid

  tags = local.common_tags
}

# ==================== QURL Link Redirect Page ====================
# Hosts the redirect page that extracts access tokens and sends users
# to the NHP Server QURL plugin for authentication.
# Flow: User visits link.domain/#at_xxx → NHP Server → NHP knock → Protected resource

# Validate required variables when deploy_qurl_link is enabled
check "qurl_link_required_variables" {
  assert {
    condition = (
      var.deploy_qurl_link == false || (
        var.qurl_link_frontend_domain != null &&
        var.qurl_link_hosted_zone_id != null
      )
    )
    error_message = <<-EOT
      When deploy_qurl_link = true, the following variables are required:
        - qurl_link_frontend_domain (e.g., "qurl.link")
        - qurl_link_hosted_zone_id (e.g., "Z0693053DKJ8S3XN9WPG")
    EOT
  }
}

# ACM Certificate for QURL Link CloudFront (must be in us-east-1)
resource "aws_acm_certificate" "qurl_link" {
  count             = var.deploy_qurl_link ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = var.qurl_link_frontend_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-link-cert"
  })
}

# ACM validation records for QURL Link certificate
# When qurl_link_external_dns=true, records are created manually via AWS CLI in layerv-mgmt
resource "aws_route53_record" "qurl_link_cert_validation" {
  for_each = var.deploy_qurl_link && !var.qurl_link_external_dns ? {
    for dvo in aws_acm_certificate.qurl_link[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  provider = aws.route53_mgmt

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.qurl_link_hosted_zone_id
}

# ACM validation - waits for certificate to be validated
# When external_dns=true, validation records are created manually and we just wait
resource "aws_acm_certificate_validation" "qurl_link" {
  count                   = var.deploy_qurl_link ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.qurl_link[0].arn
  validation_record_fqdns = var.qurl_link_external_dns ? null : [for record in aws_route53_record.qurl_link_cert_validation : record.fqdn]
}

module "qurl_link" {
  count  = var.deploy_qurl_link ? 1 : 0
  source = "./modules/qurl-link"

  domain_name         = var.qurl_link_frontend_domain
  bucket_name         = "${local.name_prefix}-qurl-link"
  acm_certificate_arn = aws_acm_certificate_validation.qurl_link[0].certificate_arn
  enable_access_logs  = var.qurl_link_enable_access_logs

  tags = merge(local.common_tags, { Service = "qurl" })
}

# Route53 alias records for QURL Link CloudFront distribution
# When qurl_link_external_dns=true, these records are created manually via AWS CLI in layerv-mgmt
resource "aws_route53_record" "qurl_link" {
  count    = var.deploy_qurl_link && !var.qurl_link_external_dns ? 1 : 0
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_link_hosted_zone_id
  name            = var.qurl_link_frontend_domain
  type            = "A"

  alias {
    name                   = module.qurl_link[0].cloudfront_domain_name
    zone_id                = module.qurl_link[0].cloudfront_hosted_zone_id
    evaluate_target_health = false
  }
}

# IPv6 AAAA record for CloudFront (is_ipv6_enabled=true on distribution)
resource "aws_route53_record" "qurl_link_ipv6" {
  count    = var.deploy_qurl_link && !var.qurl_link_external_dns ? 1 : 0
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_link_hosted_zone_id
  name            = var.qurl_link_frontend_domain
  type            = "AAAA"

  alias {
    name                   = module.qurl_link[0].cloudfront_domain_name
    zone_id                = module.qurl_link[0].cloudfront_hosted_zone_id
    evaluate_target_health = false
  }
}

# ==============================================================================
# QURL Resolve Endpoint - Direct to NHP Server
# ==============================================================================
# The resolve.qurl.link endpoint must route DIRECTLY to the NHP Server NLB,
# NOT through the AC. This is because:
# 1. AC port 443 is blocked by iptables until NHP knock authenticates (zero-trust)
# 2. The QURL plugin runs on the NHP Server, not the AC
# 3. resolve.qurl.link is called BEFORE authentication to initiate the NHP knock
#
# Traffic flow:
#   qurl.link → CloudFront → resolve.qurl.link → NHP Server NLB:443 → Server:8888

# ACM Certificate for resolve.qurl.link (must be in same region as NLB)
# When CloudFront is enabled, includes an origin-specific SAN so CloudFront's
# TLS verification passes (CloudFront checks the cert against the origin domain).
resource "aws_acm_certificate" "qurl_resolve" {
  count       = var.deploy_qurl_link ? 1 : 0
  domain_name = "resolve.${var.qurl_link_frontend_domain}"
  subject_alternative_names = var.enable_resolve_cloudfront ? [
    "resolve-origin.${var.qurl_link_frontend_domain}"
  ] : []
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-resolve-cert"
  })
}

# DNS validation records for QURL resolve certificate
resource "aws_route53_record" "qurl_resolve_cert_validation" {
  for_each = var.deploy_qurl_link && !var.qurl_link_external_dns ? {
    for dvo in aws_acm_certificate.qurl_resolve[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  provider = aws.route53_mgmt

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.qurl_link_hosted_zone_id
}

# Wait for certificate validation to complete
resource "aws_acm_certificate_validation" "qurl_resolve" {
  count                   = var.deploy_qurl_link ? 1 : 0
  certificate_arn         = aws_acm_certificate.qurl_resolve[0].arn
  validation_record_fqdns = var.qurl_link_external_dns ? null : [for record in aws_route53_record.qurl_resolve_cert_validation : record.fqdn]
}

# Route53 record for QURL token resolution endpoint
# Points resolve.qurl.link to CloudFront (when enabled) or NHP Server NLB directly.
#
# When CloudFront is enabled:
#   Flow: Browser → CloudFront → NLB → Server:8888
#   Benefit: CloudFront IPs are universally trusted by ISPs (AT&T WiFi blocks NLB IPs)
#
# When CloudFront is disabled:
#   Flow: Browser → NLB → Server:8888
resource "aws_route53_record" "qurl_link_resolve" {
  count    = var.deploy_qurl_link && !var.qurl_link_external_dns ? 1 : 0
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_link_hosted_zone_id
  name            = "resolve.${var.qurl_link_frontend_domain}"
  type            = "A"

  alias {
    name                   = var.enable_resolve_cloudfront ? aws_cloudfront_distribution.qurl_resolve[0].domain_name : module.compute.nlb_dns_name
    zone_id                = var.enable_resolve_cloudfront ? aws_cloudfront_distribution.qurl_resolve[0].hosted_zone_id : module.compute.nlb_zone_id
    evaluate_target_health = !var.enable_resolve_cloudfront
  }
}

# IPv6 AAAA record for resolve.qurl.link — REMOVED.
# The resolve endpoint captures the client IP for NHP knock (ipset src matching).
# The AC NLB is IPv4-only, so the AC will only ever see IPv4 source addresses.
# Publishing AAAA records here would cause clients to connect via IPv6, resulting
# in an IPv6 address in X-Forwarded-For that can never match real AC traffic.
# See also: is_ipv6_enabled=false on the CloudFront distribution above.

# Origin-specific DNS record for CloudFront → NLB connectivity.
# CloudFront verifies the origin's TLS cert matches the origin domain name.
# Using the raw NLB DNS as origin fails because the NLB cert is for
# resolve.qurl.link, not the NLB's auto-generated hostname.
# This record provides a stable domain that matches the NLB cert's SAN.
resource "aws_route53_record" "qurl_link_resolve_origin" {
  count    = var.deploy_qurl_link && var.enable_resolve_cloudfront && !var.qurl_link_external_dns ? 1 : 0
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_link_hosted_zone_id
  name            = "resolve-origin.${var.qurl_link_frontend_domain}"
  type            = "A"

  alias {
    name                   = module.compute.nlb_dns_name
    zone_id                = module.compute.nlb_zone_id
    evaluate_target_health = true
  }
}

# ==============================================================================
# CloudFront for resolve.qurl.link (ISP compatibility)
# ==============================================================================
# ISPs (notably AT&T WiFi) intercept TLS connections to NLB IP addresses,
# causing resolve.qurl.link to fail. CloudFront IPs are universally trusted.
# This CloudFront distribution is placed in front of resolve.qurl.link ONLY —
# *.qurl.site stays direct-to-NLB to preserve true NHP (zero ports open).

# ACM Certificate for CloudFront (must be in us-east-1)
resource "aws_acm_certificate" "qurl_resolve_cloudfront" {
  count             = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = "resolve.${var.qurl_link_frontend_domain}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-qurl-resolve-cf-cert"
  })
}

# DNS validation records for CloudFront certificate
resource "aws_route53_record" "qurl_resolve_cf_cert_validation" {
  for_each = var.deploy_qurl_link && var.enable_resolve_cloudfront && !var.qurl_link_external_dns ? {
    for dvo in aws_acm_certificate.qurl_resolve_cloudfront[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  provider = aws.route53_mgmt

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.qurl_link_hosted_zone_id
}

# Wait for CloudFront certificate validation
resource "aws_acm_certificate_validation" "qurl_resolve_cloudfront" {
  count                   = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.qurl_resolve_cloudfront[0].arn
  validation_record_fqdns = var.qurl_link_external_dns ? null : [for record in aws_route53_record.qurl_resolve_cf_cert_validation : record.fqdn]
}

# WAF Web ACL for CloudFront (must be in us-east-1, CLOUDFRONT scope)
resource "aws_wafv2_web_acl" "qurl_resolve" {
  count       = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  provider    = aws.us_east_1
  name        = "${local.name_prefix}-resolve-cf-waf"
  description = "WAF for CloudFront - QURL resolve endpoint"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rate limiting
  rule {
    name     = "RateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.environment == "prod" ? 5000 : 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-resolve-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-resolve-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-resolve-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - IP Reputation
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-resolve-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-resolve-cf-waf"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

# CloudFront Distribution for resolve.qurl.link
resource "aws_cloudfront_distribution" "qurl_resolve" {
  count           = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  enabled         = true
  is_ipv6_enabled = false # Must be false: resolve endpoint captures client IP for NHP knock.
  # IPv6 clients would get their IPv6 in X-Forwarded-For, but the AC NLB is IPv4-only,
  # so the AC would never see that IPv6 address — causing ipset mismatches and knock failures.
  comment     = "CloudFront for ${local.name_prefix} QURL resolve"
  aliases     = ["resolve.${var.qurl_link_frontend_domain}"]
  web_acl_id  = aws_wafv2_web_acl.qurl_resolve[0].arn
  price_class = var.environment == "prod" ? "PriceClass_All" : "PriceClass_100"

  origin {
    # Use the origin-specific DNS record instead of the raw NLB DNS name.
    # CloudFront verifies the origin's TLS cert matches this domain. The NLB
    # cert includes resolve-origin.* as a SAN, so TLS verification passes.
    domain_name = "resolve-origin.${var.qurl_link_frontend_domain}"
    origin_id   = "nlb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      # Sourced from the CF↔server keep-alive contract (see top-of-file
      # locals + the lifecycle.precondition blocks below). Bumping these
      # without bumping the matching server-side timeouts hard-fails
      # plan via those preconditions.
      origin_read_timeout      = local.cf_origin_read_timeout
      origin_keepalive_timeout = local.cf_origin_keepalive_seconds
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "nlb"

    # Use managed policies instead of deprecated forwarded_values block.
    # CachingDisabled: TTL=0, no caching. AllViewer: forwards all headers, query strings, cookies.
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3" # AllViewer
    compress                 = true

    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.qurl_resolve_cloudfront[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags       = local.common_tags
  depends_on = [aws_acm_certificate_validation.qurl_resolve_cloudfront]
}

# Plan-time fence on the CF↔server keep-alive contract. Lives on a
# `terraform_data` resource (which always exists, regardless of toggles)
# so the precondition runs in every plan/apply — including envs that
# temporarily set `enable_resolve_cloudfront = false`. If we put the
# precondition directly on `aws_cloudfront_distribution.qurl_resolve`,
# disabling the distribution (count = 0) would make the precondition
# silently skip, letting a coupled "shrink IdleTimeout + disable CF"
# plan slip through. The terraform_data carries the locals as inputs so
# any change to the contract values shows up in the plan diff.
#
# Bumping CF's origin_keepalive_timeout without raising the server's
# IdleTimeout (or vice versa) re-opens the resolve.qurl.link 502 race:
# CF reuses an idle conn the server has FIN'd, the next POST gets RST,
# and CF returns 502 because POSTs aren't retried. WriteTimeout < CF
# origin_read_timeout keeps the server-times-out-first ordering so a
# slow handler surfaces as 502 from the server (releasing CF's slot
# promptly) rather than 504 from CF.
resource "terraform_data" "http_keepalive_contract" {
  # Mirror every contract value in `input` (not just the ones the
  # preconditions read) so a tweak to ANY of them shows up in this
  # resource's plan diff. The preconditions only check
  # idle vs cf_keepalive+buffer and write vs cf_read_timeout, but a
  # buffer-only retune would otherwise be invisible at this resource
  # and only show up at the CF distribution.
  input = {
    cf_origin_keepalive_seconds = local.cf_origin_keepalive_seconds
    cf_origin_read_timeout      = local.cf_origin_read_timeout
    cf_keepalive_buffer_seconds = local.cf_keepalive_buffer_seconds
    http_idle_timeout_ms        = local.http_idle_timeout_ms
    http_read_timeout_ms        = local.http_read_timeout_ms
    http_write_timeout_ms       = local.http_write_timeout_ms
  }

  lifecycle {
    precondition {
      condition     = local.http_idle_timeout_ms >= (local.cf_origin_keepalive_seconds + local.cf_keepalive_buffer_seconds) * 1000
      error_message = "local.http_idle_timeout_ms (${local.http_idle_timeout_ms} ms) must be at least ${local.cf_keepalive_buffer_seconds}s greater than CloudFront's origin_keepalive_timeout (${local.cf_origin_keepalive_seconds * 1000} ms). Lower IdleTimeout re-opens the resolve.qurl.link keep-alive race fixed in PR #1795."
    }
    # No buffer on this assert — server-times-out-first is the desired
    # ordering, so any margin between WriteTimeout and origin_read_timeout
    # would just delay CF's slow-handler 502 without changing the
    # outcome. Strict `<` is sufficient.
    precondition {
      condition     = local.http_write_timeout_ms < local.cf_origin_read_timeout * 1000
      error_message = "local.http_write_timeout_ms (${local.http_write_timeout_ms} ms) must be less than CloudFront's origin_read_timeout (${local.cf_origin_read_timeout * 1000} ms) so the server, not CF, owns the slow-handler timeout."
    }
  }
}

locals {
  # Gate for resolve-CF resources only (the qurl_resolve distribution
  # and its monitoring subscription). The IAM-propagation shim has
  # its own broader gate per terraform/CLAUDE.md → "IAM eventual-
  # consistency shim pattern": OR of every consumer's condition.
  deploy_qurl_resolve_cf = var.deploy_qurl_link && var.enable_resolve_cloudfront
}

# IAM eventual-consistency shim for the qurl_link_static CI policy.
# Same-apply IAM-grant + resource-create races the auth evaluator's
# propagation, surfacing as AccessDenied on the fresh resource (see
# PR #1809 / run 25594591764 for the original trip). Resources whose
# creation needs a freshly granted perm add `depends_on` here.
#
# 60s, not the 10s of `time_sleep.apigateway_logging_propagation`
# above: API Gateway's bounded async CloudWatch role check converges
# fast; the IAM authorization-evaluator propagation does not. AWS
# does not publish an SLA — 60s has held for this shim's lifetime
# (action-list edits on an already-scoped policy). Picking 10s here
# would re-trip the race.
#
# NOT bumped to the 180s used by `time_sleep.bootstrap_alb_iam_propagation`
# below: that shim's 180s is calibrated to a freshly-scoped
# *resource-prefix* grant (the CI role gaining a new bucket-ARN
# target), where the evaluator must propagate the new resource shape
# through its caches — empirically ~2m. This shim's edits have all
# been action-list additions on the existing qurl-link resource
# scope, which clears faster. Leave at 60s unless a future edit
# extends this policy's Resource set and trips the race.
#
# Triggers (any change recreates the sleep):
#   - `policy_doc_hash`: sha256 of the rendered policy. Catches
#     the common case (action added in place). Hashing keeps plan
#     diffs one line; the policy resource itself shows what changed.
#   - `policy_arn`: catches the rename-via-`name` case.
#   - `attachment_id`: NOT a recreation trigger (the id is stable
#     as `<role>/<policy_arn>`), but its presence in `triggers`
#     forces the dep graph to order this sleep AFTER
#     `aws_iam_role_policy_attachment.qurl_link_static`. Without
#     it, TF's default parallelism could let the 60s sleep start
#     in parallel with the attachment, eroding the budget.
# Substring-matching the doc would be brittle; a stale wait on
# an unrelated edit is cheap.
#
# Gate is the OR of every consumer's condition per terraform/CLAUDE.md →
# "IAM eventual-consistency shim pattern" (taint-vs-rename ARN
# detail, `replace_triggered_by` cost trade-offs, gate-OR-expansion
# when consumers multiply, greenfield-other-CF-resources gap #1813).
# The qurl.link static-distribution monitoring subscription is a
# consumer that exists when `enable_resolve_cloudfront=false`, so the
# gate must be the broader `var.deploy_qurl_link`.
resource "time_sleep" "qurl_link_static_iam_propagation" {
  count = var.deploy_qurl_link ? 1 : 0

  triggers = {
    policy_doc_hash = module.ecr.qurl_link_static_policy_doc_hash
    policy_arn      = module.ecr.qurl_link_static_policy_arn
    attachment_id   = module.ecr.qurl_link_static_attachment_id
  }

  create_duration = "60s"
}

# Enable CloudFront additional metrics on the resolve distribution.
# Adds OriginLatency (queryable as p50/p95/p99/p999 via extended statistics)
# and per-origin error breakdowns to CloudWatch — required to debug origin-
# side stalls / 502 spikes (e.g., WriteTimeout-bound resolve handler
# latency). p999 is the tail signal we care about for the resolve flow:
# the server's WriteTimeout caps end-to-end response time (see
# local.http_write_timeout_ms + the qurl_resolve distribution's
# lifecycle.precondition blocks), so an
# origin-latency p999 trending toward that ceiling is the early-warning
# shape for handler-side cutoffs that would surface as 502s. Matches the
# EMF p99/p999 convention introduced in #871.
#
# Cost: $0.30 per metric per month × 8 additional metrics (OriginLatency +
# 4xx/5xx total error rates + 6 per-status-code breakdowns) ≈ $2.40/month
# per distribution.
resource "aws_cloudfront_monitoring_subscription" "qurl_resolve" {
  count           = local.deploy_qurl_resolve_cf ? 1 : 0
  provider        = aws.us_east_1
  distribution_id = aws_cloudfront_distribution.qurl_resolve[0].id

  monitoring_subscription {
    realtime_metrics_subscription_config {
      realtime_metrics_subscription_status = "Enabled"
    }
  }

  depends_on = [time_sleep.qurl_link_static_iam_propagation]
}

# Sibling of qurl_resolve above for the qurl.link static distribution.
# Without this subscription, CacheHitRate and OriginLatency are blank,
# leaving aggregate request count + error rate as the only signals —
# insufficient to localize a user-visible "slow redirect page" report
# to the edge vs origin vs client-side hop. Placed adjacent to qurl_resolve
# so removing one without the other shows up as obvious asymmetry on review.
resource "aws_cloudfront_monitoring_subscription" "qurl_link" {
  count           = var.deploy_qurl_link ? 1 : 0
  provider        = aws.us_east_1
  distribution_id = module.qurl_link[0].cloudfront_distribution_id

  monitoring_subscription {
    realtime_metrics_subscription_config {
      realtime_metrics_subscription_status = "Enabled"
    }
  }

  depends_on = [time_sleep.qurl_link_static_iam_propagation]
}

# Auto-invalidate /index.html on every content edit so the acceptance
# gate isn't a race against the 1h cache_control TTL set on
# aws_s3_object.index. Without this, a fresh frontend deploy is invisible
# to viewers with cached HTML until their TTL expires (and to the smoke
# test in tests/smoke/16_qurl_link_frontend_test.go which reads through
# CloudFront).
#
# triggers_replace keyed on the md5 of the deployed HTML: the resource
# replaces only when the content actually changes, so unrelated applies
# don't pay the 1-10min `wait invalidation-completed` cost. First apply
# on a greenfield env issues one (free) invalidation against an empty
# cache — trivial.
#
# `wait invalidation-completed` polls every 20s with a 10min total
# budget (botocore default: delay=20 × maxAttempts=30 = 600s). Typical
# invalidations finish in 1-5min so headroom is ~2x. Blocking the
# apply on completion is the load-bearing detail — without it, the
# next CI step (smoke run, click-through) can read stale cache and
# silently green a regression.
#
# triggers_replace keys on content_hash, not distribution_id, on
# purpose: a CF distribution recreate (e.g., viewer-cert rotation that
# forces replacement) starts with an empty edge cache. There's nothing
# to invalidate. Adding distribution_id as a second trigger would
# fire a no-op invalidation against an empty cache.
#
# Lives in root rather than the qurl-link module so the IAM-propagation
# `time_sleep` (in root, see above) is in scope. The module exposes
# `index_html_content_hash` + `cloudfront_distribution_id` as outputs.
# Ordering: depends_on the whole module rather than just the distribution
# so the new s3_object.index upload completes before the invalidation
# runs — an invalidation that races the upload would have nothing to bust.
resource "terraform_data" "qurl_link_invalidation" {
  count = var.deploy_qurl_link ? 1 : 0

  triggers_replace = {
    content_hash = module.qurl_link[0].index_html_content_hash
  }

  # Apply principal needs `cloudfront:CreateInvalidation` and
  # `cloudfront:GetInvalidation`. The CI role gets these via the
  # qurl_link_static policy (see terraform/modules/ecr/main.tf). Local
  # operators running `terraform apply` from their own session need the
  # same perms or apply fails mid-run after the s3_object uploads.
  #
  # Recovery from waiter-budget exhaustion: if the 10min `wait
  # invalidation-completed` ever fails before completing, apply exits
  # non-zero and the next apply sees an unchanged content_hash → no
  # replace → no retry. To force a retry without editing content,
  # run `terraform apply -replace=terraform_data.qurl_link_invalidation[0]`.
  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    # `set -e` does NOT propagate failures out of `$(...)` to the
    # assignment line under POSIX sh — that's what makes the explicit
    # `[ -n "$INV_ID" ]` check below load-bearing, not set -e itself.
    # If you remove the empty-id check thinking set -e covers it, a
    # silent CreateInvalidation failure walks straight into the
    # subsequent `wait` with an empty id.
    command = <<-EOT
      set -e
      command -v aws >/dev/null 2>&1 || {
        echo "qurl-link CloudFront invalidation requires the AWS CLI on PATH (run from CI or install it locally; CI runners have it preinstalled)." >&2
        exit 2
      }
      # caller-reference makes the API idempotent per content hash: if
      # set -e trips between create and wait (network blip on the wait
      # call), the next apply's create-invalidation returns the SAME
      # invalidation Id rather than creating a second record against
      # identical content.
      INV_ID=$(aws cloudfront create-invalidation \
        --distribution-id ${module.qurl_link[0].cloudfront_distribution_id} \
        --invalidation-batch 'Paths={Quantity=1,Items=[/index.html]},CallerReference=qurl-link-${module.qurl_link[0].index_html_content_hash}' \
        --query 'Invalidation.Id' --output text)
      [ -n "$INV_ID" ] || {
        echo "create-invalidation returned an empty Id — refusing to wait on an unknown invalidation." >&2
        exit 1
      }
      echo "qurl-link CloudFront invalidation: $INV_ID"
      if ! aws cloudfront wait invalidation-completed \
        --distribution-id ${module.qurl_link[0].cloudfront_distribution_id} \
        --id "$INV_ID"; then
        echo "qurl-link CloudFront invalidation $INV_ID still in progress past the 10min waiter budget; next apply will retry the same caller-reference (idempotent)." >&2
        exit 1
      fi
      echo "qurl-link CloudFront invalidation $INV_ID completed."
    EOT
  }

  depends_on = [
    module.qurl_link,
    time_sleep.qurl_link_static_iam_propagation,
  ]
}

# CloudFront origin-facing IP ranges (for Gin trusted proxies)
# Uses cloudfront_origin_facing (45 CIDRs / ~705 bytes) NOT cloudfront (199 CIDRs - wrong IPs)
# Only IPv4 cidr_blocks are used: CloudFront connects to origins over IPv4 even when
# the viewer connection is IPv6, so ipv6_cidr_blocks are not needed for trusted proxies.
data "aws_ip_ranges" "cloudfront_origin" {
  count    = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  services = ["cloudfront_origin_facing"]
}

# SSM Parameter for CloudFront CIDRs (consumed by NHP Server for SetTrustedProxies)
# Covered by existing IAM wildcard: ssm:GetParameter on parameter/${env}/nhp/server/*
resource "aws_ssm_parameter" "cloudfront_cidrs" {
  count = var.deploy_qurl_link && var.enable_resolve_cloudfront ? 1 : 0
  name  = "/${var.environment}/nhp/server/cloudfront-cidrs"
  type  = "String"
  value = join(",", data.aws_ip_ranges.cloudfront_origin[0].cidr_blocks)
  tags  = local.common_tags
}

# ==============================================================================
# CloudFront CIDR Drift Detection
# ==============================================================================
# The SSM parameter is updated on `terraform apply`. If AWS publishes new
# CloudFront origin-facing CIDRs between applies, requests from those IPs
# will be untrusted. This Lambda runs daily to detect drift and alarm.

locals {
  cf_drift_enabled = var.deploy_qurl_link && var.enable_resolve_cloudfront
}

data "archive_file" "cloudfront_cidr_drift" {
  count       = local.cf_drift_enabled ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/cloudfront_cidr_drift.py"
  output_path = "${path.module}/lambda/.build/cloudfront_cidr_drift.zip"
}

resource "aws_cloudwatch_log_group" "cloudfront_cidr_drift" {
  count             = local.cf_drift_enabled ? 1 : 0
  name              = "/aws/lambda/${local.name_prefix}-cf-cidr-drift"
  retention_in_days = var.environment == "prod" ? 90 : 14
  kms_key_id        = module.kms.logs_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift-logs"
    Component = "cloudfront"
  })
}

resource "aws_iam_role" "cloudfront_cidr_drift" {
  count = local.cf_drift_enabled ? 1 : 0
  name  = "${local.name_prefix}-cf-cidr-drift"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift-role"
    Component = "cloudfront"
  })
}

resource "aws_iam_role_policy_attachment" "cloudfront_cidr_drift_logs" {
  count      = local.cf_drift_enabled ? 1 : 0
  role       = aws_iam_role.cloudfront_cidr_drift[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "cloudfront_cidr_drift" {
  count = local.cf_drift_enabled ? 1 : 0
  name  = "ssm-and-cloudwatch"
  role  = aws_iam_role.cloudfront_cidr_drift[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadSSMParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = aws_ssm_parameter.cloudfront_cidrs[0].arn
      },
      {
        Sid      = "PublishMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "cloudfront_cidr_drift" {
  count = local.cf_drift_enabled ? 1 : 0

  depends_on = [aws_cloudwatch_log_group.cloudfront_cidr_drift]

  filename         = data.archive_file.cloudfront_cidr_drift[0].output_path
  function_name    = "${local.name_prefix}-cf-cidr-drift"
  role             = aws_iam_role.cloudfront_cidr_drift[0].arn
  handler          = "cloudfront_cidr_drift.handler"
  source_code_hash = data.archive_file.cloudfront_cidr_drift[0].output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      SSM_PARAMETER_NAME = aws_ssm_parameter.cloudfront_cidrs[0].name
      ENVIRONMENT        = var.environment
    }
  }

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift"
    Component = "cloudfront"
  })
}

# Daily EventBridge trigger
resource "aws_cloudwatch_event_rule" "cloudfront_cidr_drift" {
  count               = local.cf_drift_enabled ? 1 : 0
  name                = "${local.name_prefix}-cf-cidr-drift"
  description         = "Daily check for CloudFront origin-facing CIDR drift"
  schedule_expression = "rate(1 day)"

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift-rule"
    Component = "cloudfront"
  })
}

resource "aws_cloudwatch_event_target" "cloudfront_cidr_drift" {
  count     = local.cf_drift_enabled ? 1 : 0
  rule      = aws_cloudwatch_event_rule.cloudfront_cidr_drift[0].name
  target_id = "cf-cidr-drift"
  arn       = aws_lambda_function.cloudfront_cidr_drift[0].arn
}

resource "aws_lambda_permission" "cloudfront_cidr_drift" {
  count         = local.cf_drift_enabled ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudfront_cidr_drift[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudfront_cidr_drift[0].arn
}

# Alarm: fires when CIDRs are out of sync (drift metric = 1)
resource "aws_cloudwatch_metric_alarm" "cloudfront_cidr_drift" {
  count               = local.cf_drift_enabled ? 1 : 0
  alarm_name          = "${local.name_prefix}-cf-cidr-drift"
  alarm_description   = "CloudFront origin-facing CIDRs have changed — run 'terraform apply' to update trusted proxy config"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudFrontCIDRDrift"
  namespace           = "LayerV/NHP"
  period              = 86400 # 1 day
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift-alarm"
    Component = "cloudfront"
  })
}

# Alarm: Lambda execution errors
resource "aws_cloudwatch_metric_alarm" "cloudfront_cidr_drift_errors" {
  count               = local.cf_drift_enabled ? 1 : 0
  alarm_name          = "${local.name_prefix}-cf-cidr-drift-errors"
  alarm_description   = "CloudFront CIDR drift checker Lambda errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.cloudfront_cidr_drift[0].function_name
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-cf-cidr-drift-errors-alarm"
    Component = "cloudfront"
  })
}

# ==================== E2E Echo Server ====================

module "e2e_echo_server" {
  count  = var.deploy_e2e_echo_server ? 1 : 0
  source = "./modules/e2e-echo-server"

  name_prefix = local.name_prefix
  environment = var.environment
  tags        = merge(local.common_tags, { Service = "e2e-testing" })
}

# ==================== QURL Integrations DNS ====================
# Cross-account A records (not alias) for `layervai/qurl-integrations-
# infra` prod EC2 instances. The integrations repo owns EC2 + EIP
# creation; DNS lives here because `layerv.ai` is in the mgmt-account
# Route 53 zone reached via `aws.route53_mgmt` (same pattern as
# `qurl_api` — plain A record on the same provider). Plain A records
# — the workloads are single-instance EC2 + Caddy, not ALB/NLB-backed.
#
# Caddy's ACME HTTP-01 flow needs public DNS to succeed, so without
# these records Caddy has no valid cert and the hostnames are
# unreachable.
#
# EIP source of truth: the EIPs attached to the instances in
# integrations-prod (account 886375649402). Read either from
# qurl-integrations-infra's TF outputs (`instance_public_ip`,
# `viewer_public_ip`) or `aws ec2 describe-addresses` — both are
# authoritative for the same live AWS state. If an EIP is ever
# reallocated, update the tfvars with the new value — the record
# destroy+recreate is equivalent to an intentional DNS update.
#
# Subdomain-takeover note: if the integrations repo ever *releases*
# (not just disassociates) one of these EIPs without this record
# being updated first, the IP returns to the AWS pool and can be
# re-leased to another tenant, who then gets ACME-issued TLS on
# these hostnames. EIP release is a destructive change in the
# integrations repo — flag a coordinated DNS delete PR here first.

locals {
  # All six inputs are load-bearing. Single gate dedups the six-way
  # AND repeated on each record's `count`. Matches the
  # `website_api_dns_enabled` local in the website email-capture
  # section above. The terraform_data below gates on just the flag
  # so preconditions still fire with named error messages when only
  # the flag is set.
  qurl_integrations_dns_enabled = (
    var.deploy_qurl_integrations_dns &&
    var.qurl_s3_connector_domain != null &&
    var.qurl_s3_connector_eip != null &&
    var.qurl_fileviewer_domain != null &&
    var.qurl_fileviewer_eip != null &&
    var.qurl_hosted_zone_id != null
  )
}

# Fail plan loudly if deploy_qurl_integrations_dns is flipped on
# without its inputs wired up. Mirrors website_api_preconditions.
resource "terraform_data" "qurl_integrations_dns_preconditions" {
  count = var.deploy_qurl_integrations_dns ? 1 : 0

  # Feature inputs first, zone last — matches website_api_preconditions
  # ordering so grep across preconditions groups the feature-scoped
  # vars together.
  lifecycle {
    precondition {
      condition     = var.qurl_s3_connector_domain != null
      error_message = "qurl_s3_connector_domain is required when deploy_qurl_integrations_dns = true."
    }
    precondition {
      condition     = var.qurl_s3_connector_eip != null
      error_message = "qurl_s3_connector_eip is required when deploy_qurl_integrations_dns = true."
    }
    precondition {
      condition     = var.qurl_fileviewer_domain != null
      error_message = "qurl_fileviewer_domain is required when deploy_qurl_integrations_dns = true."
    }
    precondition {
      condition     = var.qurl_fileviewer_eip != null
      error_message = "qurl_fileviewer_eip is required when deploy_qurl_integrations_dns = true."
    }
    precondition {
      condition     = var.qurl_hosted_zone_id != null
      error_message = "qurl_hosted_zone_id is required when deploy_qurl_integrations_dns = true (the layerv.ai zone in mgmt account)."
    }
  }
}

resource "aws_route53_record" "qurl_s3_connector" {
  # Gate via the shared `qurl_integrations_dns_enabled` local so a
  # future edit adding an input can't forget to widen both records'
  # count predicates. Preconditions on the terraform_data above
  # still fire first when only the flag is set.
  count      = local.qurl_integrations_dns_enabled ? 1 : 0
  provider   = aws.route53_mgmt
  depends_on = [terraform_data.qurl_integrations_dns_preconditions]

  # Omit allow_overwrite (matches plain-record `qurl_api`): these are
  # new records with no mgmt-account consumers; failing on a pre-
  # existing conflict is louder than clobbering one.
  zone_id = var.qurl_hosted_zone_id
  name    = var.qurl_s3_connector_domain
  type    = "A"
  ttl     = 300
  records = [var.qurl_s3_connector_eip]

  lifecycle {
    # Flipping deploy_qurl_integrations_dns off (or nulling the
    # inputs) would otherwise destroy this record and sever all
    # traffic to the hostname. prevent_destroy makes `terraform
    # plan` itself fail with "Instance cannot be destroyed" the
    # moment count flips to 0 — not just apply. Retiring the record
    # intentionally is a three-step dance: (1) `terraform state rm
    # aws_route53_record.qurl_s3_connector[0]`, (2) remove this
    # resource block and/or null the inputs, (3) plan+apply.
    # Mirrors the safety rail captured for the backing EIPs in
    # layervai/qurl-integrations-infra#247. In-place updates
    # (rotating the EIP via tfvars) are unaffected — `records`
    # changes are treated as updates, not destroys.
    prevent_destroy = true
  }
}

resource "aws_route53_record" "qurl_fileviewer" {
  count      = local.qurl_integrations_dns_enabled ? 1 : 0
  provider   = aws.route53_mgmt
  depends_on = [terraform_data.qurl_integrations_dns_preconditions]

  zone_id = var.qurl_hosted_zone_id
  name    = var.qurl_fileviewer_domain
  type    = "A"
  ttl     = 300
  records = [var.qurl_fileviewer_eip]

  lifecycle {
    prevent_destroy = true
  }
}

# ─────────────────────────────────────────────────────────────────────
# Bootstrap ALB — `bootstrap.layerv.{xyz,ai}` first-contact surface
#
# Distinct from `api.layerv.ai`: only `/v1/agent/bootstrap` is forwarded
# to qurl-service. Reverse-tunnel-client sidecars hit this on cold start
# to register their public key BEFORE they hold any NHP credentials.
#
# Default off (`deploy_bootstrap_alb = false`). Enable per-env in
# `terraform/environments/{sandbox,prod}/terraform.tfvars` once the
# cert is wired (sandbox: same-account `layerv.xyz` → module-
# provisioned via `provision_certificate=true`, CI-clean on first
# apply; prod: cross-account `layerv.ai` in `layerv-mgmt` →
# operator pre-provisions + supplies `existing_certificate_arn`)
# and qurl-service ECS is ready to land the `load_balancer` block
# paired with this stack's target group.

# Catches the common foot-gun on the first per-env flip:
# `deploy_bootstrap_alb=true` but the operator forgot to wire one of
# the two valid cert configurations through tfvars. Without this
# check, the module-side validations fire generic error messages
# (`dns_name must be a valid lowercase FQDN`) that don't point the
# operator at which ROOT variables to set. Same shape as
# `qurl_link_required_variables` above. Defense in depth — the
# module's own listener-side precondition stays.
#
# Two valid cert configurations (mirroring the module's
# `cert_dns.tf` header and the listener-side precondition):
#   1. **Cross-account (prod posture — `layerv.ai` zone in
#      `layerv-mgmt`)**:
#        bootstrap_alb_provision_certificate    = false
#        bootstrap_alb_existing_certificate_arn = "<operator-pre-provisioned ARN>"
#   2. **Same-account (sandbox posture — `layerv.xyz` zone in the
#      sandbox apply target, `767397897469`)**:
#        bootstrap_alb_provision_certificate    = true
#        bootstrap_alb_route53_zone_id          = "<zone ID>"
#
# Both require `bootstrap_alb_dns_name` to be non-empty. The OR
# branch captures path #2 so a future env flipping into auto-
# provision doesn't false-fail this check.
check "bootstrap_alb_required_variables" {
  # **`check` blocks emit plan-time WARNINGS, not errors.** Anyone
  # reading this expecting it to FAIL plan on a misconfigured cert
  # combo will be surprised — the actual fail-fast lives at
  # `modules/bootstrap-alb/alb.tf::aws_lb_listener.https::lifecycle.precondition`
  # (which DOES fail plan). This check is here for the
  # operator-friendly error MESSAGE pointing at the right root
  # vars; the precondition is the gate.

  assert {
    # Exactly-one-of-two cert paths must be configured (XOR), not
    # "at least one" — the OR shape would let an operator set BOTH
    # `existing_certificate_arn` AND `provision_certificate=true` and
    # the root check passes, leaving the module's listener-side
    # mutual-exclusion precondition to catch it with a less operator-
    # friendly error message. The XOR shape catches the bad combo
    # here, where the error_message can point at the right root vars.
    #
    # Path 1: `existing_certificate_arn` non-empty AND
    #         `provision_certificate` false.
    # Path 2: `provision_certificate` true AND `route53_zone_id`
    #         non-empty AND `existing_certificate_arn` empty.
    condition = (
      var.deploy_bootstrap_alb == false || (
        var.bootstrap_alb_dns_name != "" && (
          (var.bootstrap_alb_existing_certificate_arn != "" && !var.bootstrap_alb_provision_certificate) ||
          (var.bootstrap_alb_provision_certificate && var.bootstrap_alb_route53_zone_id != "" && var.bootstrap_alb_existing_certificate_arn == "")
        )
      )
    )
    error_message = <<-EOT
      When deploy_bootstrap_alb = true, bootstrap_alb_dns_name must be
      set AND EXACTLY ONE of the two cert paths must be configured
      (setting both is rejected — existing_certificate_arn would be
      silently ignored by the listener):

      Path 1 (cross-account cert, prod posture — `layerv.ai` zone in `layerv-mgmt`):
        - bootstrap_alb_existing_certificate_arn  (operator-pre-provisioned ACM cert ARN)
        - bootstrap_alb_provision_certificate    = false  (the default)

      Path 2 (same-account cert, sandbox posture — `layerv.xyz` zone in the sandbox apply target):
        - bootstrap_alb_provision_certificate    = true
        - bootstrap_alb_route53_zone_id          = "<zone ID of the parent zone>"
        - bootstrap_alb_existing_certificate_arn = ""     (the default — must be empty)

      See modules/bootstrap-alb/README.md → "First-apply runbook" for the
      cross-account cert + DNS pre-provisioning steps.
    EOT
  }

  # Independent of the cert XOR: `manage_dns_alias=true` requires
  # `route53_zone_id` to be non-empty (the alias resource targets the
  # zone). The module's data-source-level precondition catches this
  # at plan with a less operator-friendly message; covering it here
  # too lets the error point at the right ROOT variable names.
  assert {
    condition = (
      var.deploy_bootstrap_alb == false ||
      !var.bootstrap_alb_manage_dns_alias ||
      var.bootstrap_alb_route53_zone_id != ""
    )
    error_message = <<-EOT
      bootstrap_alb_manage_dns_alias = true requires
      bootstrap_alb_route53_zone_id to be non-empty (the alias
      record needs a zone to land in). Either:
        - Set bootstrap_alb_route53_zone_id = "<parent zone ID>", OR
        - Leave bootstrap_alb_manage_dns_alias = false and write
          the A-alias out-of-band in the parent-zone account
          (Path 1 posture — see modules/bootstrap-alb/README.md
          "Account topology" + Step 2).
    EOT
  }
}

# Structural fence (closes #2083). PR #2082 fixed the original empty-TG
# bug — bootstrap-ALB shipped with target_group_arn / alb_security_group_id
# outputs documented as paired-PR-bound, the paired PR never landed, and
# the customer-facing bootstrap.layerv.* endpoint sat 503 for weeks with
# no plan-time signal. This `check` block catches the same shape of
# half-wiring: when `deploy_bootstrap_alb = true`, the qurl-service
# module MUST have been threaded with both passthroughs.
#
# Reads the value via two thin qurl-service outputs (echoes of the input
# vars), so a missing passthrough at this module's call site shows up as
# null at output time and trips the assert with an operator-actionable
# error message.
#
# Severity: `check` emits a WARNING on every plan, not an apply-fail.
# Right severity here — the underlying data plane works (the validator
# 404s, customer sees 503) but no apply hazard exists to block. The
# warning will surface on every plan run until the wiring is added, so
# it can't be overlooked the way the original miss was. For HARD enforce-
# ment a precondition on a `terraform_data` could be added in a follow-up
# if operators end up ignoring the warning.
# REVISIT IF: module.qurl_service ever migrates from `count` to
# `for_each` (multi-tenant / multi-region split). `one(module.qurl_service[*]...)`
# below is shape-agnostic for count-0 vs count-1 but would silently
# pick whichever entry sorts first under for_each — at that point this
# fence needs to iterate the set and assert ALL entries are threaded.
check "bootstrap_alb_qurl_attachment_wired" {
  assert {
    # `one(module.qurl_service[*].xxx)` returns null when count=0 (no
    # qurl-service module) and the scalar value when count=1. Composes
    # cleanly with the `!= null` check and is index-safe regardless of
    # HCL evaluation order — avoids relying on `&&` short-circuit to
    # protect the `[0]` index access.
    condition = (
      var.deploy_bootstrap_alb == false || (
        one(module.qurl_service[*].bootstrap_alb_target_group_arn) != null &&
        one(module.qurl_service[*].bootstrap_alb_security_group_id) != null
      )
    )
    error_message = <<-EOT
      deploy_bootstrap_alb = true but module.qurl_service was not
      threaded with bootstrap_alb_target_group_arn /
      bootstrap_alb_security_group_id passthroughs. The bootstrap-ALB's
      target group will sit empty and customer sidecars will see
      HTTP 503 nginx-no-healthy-target on bootstrap.layerv.<tld>
      until the wiring is added in terraform/main.tf's module
      "qurl_service" block:

        bootstrap_alb_target_group_arn  = var.deploy_bootstrap_alb ? module.bootstrap_alb[0].target_group_arn  : null
        bootstrap_alb_security_group_id = var.deploy_bootstrap_alb ? module.bootstrap_alb[0].alb_security_group_id : null

      This is the same outage shape closed by PR #2082; see issue
      #2083 for the rationale on this structural fence. The warning
      ALSO fires if deploy_qurl_service is false while deploy_bootstrap_alb
      is true — bootstrap-ALB without qurl-service is unsupported (the
      bootstrap-ALB's listener-rule forwards to qurl-service exclusively).
      In that case, `one(module.qurl_service[*]...)` resolves to null,
      so the assert correctly fails — but the operator-friendly fix is
      to flip deploy_qurl_service=true (and add the passthroughs above),
      not to silence the warning.
    EOT
  }
}

module "bootstrap_alb" {
  count  = var.deploy_bootstrap_alb ? 1 : 0
  source = "./modules/bootstrap-alb"

  # **Gate-toggle limitation.** Flipping `deploy_bootstrap_alb = true
  # → false` to roll back will NOT cleanly destroy the access-log
  # bucket: it carries both `force_destroy = false` AND
  # `lifecycle { prevent_destroy = true }` (deliberate — bootstrap
  # forensics are irrecoverable). The next `terraform plan` after
  # `deploy_bootstrap_alb=false` fails with
  # `Instance cannot be destroyed`. To genuinely tear down (rare —
  # not the recommended rollback path), follow the two-fence-unwind
  # documented at `modules/bootstrap-alb/README.md` →
  # "Teardown / cleanup" → section 1.
  #
  # **Recommended operational rollback** is NOT
  # `deploy_bootstrap_alb=false`. Instead, switch problematic WAF
  # rules to count-only via `var.bootstrap_alb_waf_count_only_rule_groups`
  # (see README → "Operator note — customer sidecar reports
  # bootstrap 403"), or bump
  # `var.bootstrap_alb_elb_5xx_threshold_per_minute` to suppress
  # alarm-noise during a known maintenance window.

  environment = var.environment

  # Passed in (not read from the in-module `data.aws_caller_identity`)
  # because the `depends_on = [time_sleep.bootstrap_alb_iam_propagation]`
  # at the bottom of this block propagates pending-change status to
  # every in-module data source. The bucket-name locals in
  # `modules/bootstrap-alb/access_logs.tf` need a plan-time-known
  # `account_id` so the existing buckets (carrying
  # `lifecycle.prevent_destroy`) don't get marked
  # `# forces replacement` whenever the policy-doc hash changes and
  # the shim has to re-fire. See run 26258687592 for the trip-evidence
  # and `modules/bootstrap-alb/variables.tf::account_id` for the full
  # writeup.
  account_id = data.aws_caller_identity.current.account_id

  # Networking — direct refs since this is intra-repo.
  vpc_id            = module.networking.vpc_id
  public_subnet_ids = module.networking.public_subnet_ids
  vpc_cidr_block    = module.networking.vpc_cidr

  # DNS + cert. Empty defaults are intentional during the first-apply
  # bootstrap window; the module's listener-side precondition rejects
  # the misconfigured combo (provision_certificate=false AND
  # existing_certificate_arn=="") before plan finishes. The root-level
  # `check` block above catches the gate-on-without-tfvars case first
  # and points the operator at the right root variables.
  dns_name                 = var.bootstrap_alb_dns_name
  route53_zone_id          = var.bootstrap_alb_route53_zone_id
  manage_dns_alias         = var.bootstrap_alb_manage_dns_alias
  provision_certificate    = var.bootstrap_alb_provision_certificate
  existing_certificate_arn = var.bootstrap_alb_existing_certificate_arn

  # Per-group WAF count-only overrides (sandbox first-rollout posture
  # is typically `["AWSManagedRulesAnonymousIpList"]` — see module
  # README's operator-note on the 403-from-VPN class). Default empty.
  waf_count_only_rule_groups = var.bootstrap_alb_waf_count_only_rule_groups

  # Optional email subscribers to the alerts topic. Empty list
  # (today's default) defers to alerts-infra cross-account routing;
  # populate this for interim direct-email routing or ops-team
  # accountability copies. Each subscriber must click the AWS
  # confirmation email — see README Step 3 #7.
  alarm_email_subscriptions = var.bootstrap_alb_alarm_email_subscriptions

  # Cross-account `sns:Subscribe` principals for the alerts topic.
  # Populate with the alerts-infra IAM role ARN once that wiring is
  # ready; without it the cross-account subscribe fails silently
  # (no AuthorizationError surfaces because the subscribe call is
  # on alerts-infra's side).
  cross_account_subscriber_arns = var.bootstrap_alb_cross_account_subscriber_arns

  # Dark-launch tunability for the `alb-elb-5xx` alarm. Root var
  # defaults to `null` so the module's own default (10, dark-launch-
  # friendly) is the source of truth. Env tfvars override to `1`
  # once the data plane is attached and the surface is live (any
  # ALB-side 5xx is the outage signal at that point). The null→default
  # coercion relies on `nullable = false` on the module-side var; if
  # that's ever removed, switch this passthrough to `coalesce(...)`.
  alb_elb_5xx_threshold_per_minute = var.bootstrap_alb_elb_5xx_threshold_per_minute

  # Match bootstrap-ALB's target_port to qurl-service's container_port at a
  # single env-root source-of-truth — both module defaults are 8080 but they
  # can diverge silently (bootstrap-alb's TG would then health-check the
  # wrong port; see modules/bootstrap-alb/variables.tf::target_port).
  target_port = var.qurl_container_port

  # `bootstrap_path`, `health_check_path`, WAF rule list, access-log
  # retention, alarm thresholds — module defaults apply. Override in env
  # tfvars only with explicit evidence.

  # IAM-propagation race: the bootstrap-alb access-log + Athena buckets
  # are scoped under `arn:aws:s3:::bootstrap-alb-*` in the CI role's
  # terraform-apply-services policy. On the same apply that adds the
  # bucket prefix to the policy AND creates the buckets, the IAM auth
  # evaluator can lag by up to ~60s and CreateBucket hits AccessDenied
  # (see nhp run 26246889231 — the failure that landed this shim).
  # `depends_on` orders the WHOLE module after the sleep; module-level
  # is the cleanest scope because every bucket-creating resource here
  # racing the perm sits behind it.
  depends_on = [time_sleep.bootstrap_alb_iam_propagation]
}

# IAM eventual-consistency shim for the bootstrap-alb consumers of the
# terraform-apply-services CI policy. Same pattern + rationale as
# `time_sleep.qurl_link_static_iam_propagation` above (read that block
# for the trigger-source semantics + the taint/rename + greenfield-CF
# nuances; this shim mirrors that shape, with `create_duration`
# divergent — see the comment on `create_duration` below for the
# 180s-vs-60s rationale).
#
# Gated on `var.deploy_bootstrap_alb` per terraform/CLAUDE.md → "IAM
# eventual-consistency shim pattern": OR of every consumer's condition.
# `terraform_apply_services` is a broad CI policy; today the only
# consumer that races freshly-granted perms in it is this module. A
# future PR that adds a new perm to this policy AND a same-apply
# consumer that races it must widen the gate (and add `depends_on`
# on the new consumer) — the policy_doc_hash trigger re-fires the
# wait on any perm edit, but only resources gated through here pay it.
resource "time_sleep" "bootstrap_alb_iam_propagation" {
  count = var.deploy_bootstrap_alb ? 1 : 0

  triggers = {
    policy_doc_hash = module.ecr.terraform_apply_services_policy_doc_hash
    policy_arn      = module.ecr.terraform_apply_services_policy_arn
    attachment_id   = module.ecr.terraform_apply_services_attachment_id
  }

  # 180s (was 60s in #2071). On nhp run 26251713769 the 60s shim was
  # insufficient: `aws_s3_bucket_lifecycle_configuration.alb_access_logs`
  # retried for 56s before the IAM evaluator finally allowed
  # `s3:PutLifecycleConfiguration` on the freshly-scoped
  # `bootstrap-alb-*` prefix (observed total propagation ~2m from
  # policy mod). Its sibling `aws_s3_bucket_lifecycle_configuration.athena_query_results`
  # exhausted retries before that window closed and failed the apply.
  # 180s gives the evaluator a full 3m before any consumer attempts,
  # well above the ~2m observed. The 60s precedent on
  # `qurl_link_static_iam_propagation` predates this evidence — leave
  # it as-is until/unless that shim trips the same race.
  create_duration = "180s"
}
