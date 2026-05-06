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

  environment                  = var.environment
  cell_id                      = var.cell_id
  nlb_arn_suffix               = module.compute.nlb_arn_suffix
  target_group_arn_suffix      = module.compute.target_group_arn_suffix
  asg_name                     = module.compute.asg_name
  server_stderr_log_group_name = module.compute.log_group_stderr_name
  name_prefix                  = local.name_prefix
  tags                         = local.common_tags

  # Slack integration
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id

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
      error_message = "Exactly one of enable_canary_deployment / enable_blue_green must be true; got canary=${var.enable_canary_deployment} blue_green=${var.enable_blue_green}. New envs: pick one in tfvars (see CLAUDE.md \"Deploy-mode tier mapping\")."
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

  # FRP tunnel server integration (conditional: only when FRP is deployed alongside AC)
  frp_server_host     = var.deploy_frps ? "frps.${module.data.namespace_name}" : ""
  frp_control_port    = var.frps_bind_port
  frp_vhost_http_port = var.frps_vhost_http_port

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
# FRP tunnel server for proxying traffic to customer backends via qurl-reverse-proxy.
# Runs in private subnets, reachable only from AC security group.

# Cross-variable invariant for the qurl-frps ASG sizing knobs. Unconditional
# (no `count = deploy_frps ? 1 : 0`) so a typo like `frps_min_size = 3,
# frps_max_size = 1` in tfvars fails plan even while `deploy_frps = false` —
# matching the rationale on the per-variable `>= 1` validations. The module's
# own ASG-resource precondition (`min_size <= desired_capacity <= max_size`)
# stays in place as a second line of defense for module-direct consumers.
resource "terraform_data" "frps_asg_sizing" {
  lifecycle {
    precondition {
      condition     = var.frps_min_size <= var.frps_desired_capacity && var.frps_desired_capacity <= var.frps_max_size
      error_message = "qurl-frps ASG sizing must satisfy frps_min_size <= frps_desired_capacity <= frps_max_size (root-level guard so a typo fails plan even when deploy_frps = false)."
    }
  }
}

# Validate that everything the FRP auth plugin needs is wired before the
# module is instantiated. Without these, `qurl-frps` would boot with the
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
  }
}

module "qurl_frps" {
  source = "./modules/qurl-frps"
  # `deploy_ac` is already enforced by `terraform_data.frps_preconditions`
  # above, so the module count only needs to key off `deploy_frps`.
  count = var.deploy_frps ? 1 : 0

  # Mirror module.ac's depends_on (terraform/main.tf:953-956): the FRP
  # launch template renders local.qurl_consumer_api_url, which can
  # interpolate the internal-ALB hostname; on first apply the cert+DNS
  # must be live before any FRP instance reads its env. Today this is
  # latent because the FRP ASG has no instance_refresh block (#1629)
  # so launch template version bumps don't move fleet without operator
  # action — but adding the dependency now removes the foot-gun for
  # when #1629 lands. No-op when qurl_internal_service_domain is null
  # (count-gated resources collapse to empty).
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
  tags               = merge(local.common_tags, { Service = "qurl-frps" })

  # Security: only AC instances can reach the FRP server
  ac_security_group_id = module.ac[0].security_group_id

  # QURL API for FRP auth plugin (built-in tunnel auth in nhp-frps binary).
  # Routed through local.qurl_consumer_api_url, shared with the AC
  # qurl-router consumer above — single edit point for the host-
  # selection rule. Outer guard is just `deploy_qurl_service` because
  # `frps_preconditions` (line 1071) already enforces
  # `qurl_service_domain != null && != ""` whenever `deploy_frps = true`,
  # and the qurl-frps module's `^https://[^[:space:]]+$` validation
  # backstops the structural shape on the URL itself.
  qurl_api_internal_url     = var.deploy_qurl_service ? local.qurl_consumer_api_url : ""
  qurl_api_token_secret_arn = var.deploy_qurl_service && var.qurl_internal_service_token_arn != null && var.qurl_internal_service_token_arn != "" ? var.qurl_internal_service_token_arn : ""

  # Instance configuration
  instance_type = var.frps_instance_type

  # ASG sizing — defaults to 1/1/1 because tunnel registrations are
  # in-memory per instance. Tracked in #1499; once that lands, env tfvars
  # flip to one-per-AZ.
  min_size         = var.frps_min_size
  max_size         = var.frps_max_size
  desired_capacity = var.frps_desired_capacity

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

  # Plugin bucket for the S3 fallback binary download path in user_data.
  # Consistent with how the AC module is wired (see `plugin_bucket_arn` on
  # the ac module above); same bucket scoped to the qurl-frps subtree.
  # Both arn and name are threaded: arn scopes the IAM grant, name is
  # baked into user_data's `aws s3 cp` command via templatefile — keeping
  # them in lockstep from a single source of truth.
  plugin_bucket_arn  = module.plugins.bucket_arn
  plugin_bucket_name = module.plugins.bucket_name

  # Monitoring
  enable_cloudwatch_alarms = true
  alarm_sns_topic_arn      = module.monitoring.sns_topic_arn
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
  ecr_repo_url             = module.ecr.qurl_repo_url
  image_tag_ssm_param      = "/${local.name_prefix}/qurl-api-image-tag"
  container_cpu            = var.qurl_container_cpu
  container_memory         = var.qurl_container_memory
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
  nhp_server_internal_url = var.deploy_ac ? "http://server.${module.data.namespace_name}:8888" : ""

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
  custom_domain_enabled     = var.qurl_custom_domain_enabled
  custom_domain_acme_suffix = var.qurl_custom_domain_enabled ? "acme.${var.hosted_zone}" : ""
  custom_domain_nlb_target  = var.qurl_custom_domain_enabled && var.deploy_ac ? module.ac[0].nlb_dns_name : ""

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
  tunnel_auth_enabled = var.qurl_tunnel_auth_enabled

  # Ensure the HMAC secret is seeded before the ECS task pulls it via valueFrom.
  depends_on = [terraform_data.nhp_internal_auth_seed]
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
  nhp_resolve_url     = "https://resolve.${var.qurl_link_frontend_domain}/plugins/qurl"
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
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 30
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
