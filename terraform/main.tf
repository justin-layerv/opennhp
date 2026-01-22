# LayerV NHP Infrastructure
# Consistent with layerv/traefik-plugins terraform patterns
#
# Multi-account architecture:
# - Sandbox (layerv): Primary account, owns ECR repositories
# - Production (layerv-prod): Secondary account, pulls from sandbox ECR cross-account

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.27"
      configuration_aliases = [aws.us_east_1]
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
  }
}

# ==================== Validation ====================

# Validate NHP protection prerequisites (always enabled)
check "nhp_protection_prerequisites" {
  assert {
    condition = (
      var.console_internal_only == true &&
      var.console_protected_hostname != null &&
      var.deploy_ac == true &&
      var.hosted_zone != null
    )
    error_message = <<-EOT
      NHP protection is always enabled. The following are required:
        - console_internal_only = true
        - console_protected_hostname must be set
        - deploy_ac = true
        - hosted_zone must be set (for DNS records)
    EOT
  }
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

# ==================== Locals ====================

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
}

# Networking Module - VPC, Subnets, Security Groups
module "networking" {
  source = "./modules/networking"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # NHP protection requires NACL to allow port 443 from internet
  # so NLB can route to private subnets (iptables enforces access)
  allow_private_ingress_443 = true
}

# Data Module - etcd, EFS, Secrets, Service Discovery
module "data" {
  source = "./modules/data"

  environment        = var.environment
  multi_tenant       = var.multi_tenant
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  vpc_cidr           = var.vpc_cidr
  name_prefix        = local.name_prefix
  tags               = local.common_tags

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

# Compute Module - ASG, NLB, Launch Template
module "compute" {
  source = "./modules/compute"

  environment         = var.environment
  cell_id             = var.cell_id
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
  tags                = local.common_tags

  # KMS encryption keys
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  logs_kms_key_arn    = module.kms.logs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # Server configuration options
  dev_mode      = var.dev_mode
  resource_mode = var.resource_mode
  # auth_url: Point to Console API for passcode validation
  # Uses Console EC2 internal endpoint when deployed, otherwise falls back to var.auth_url
  auth_url         = var.deploy_console_ec2 && var.deploy_rds ? module.console_ec2[0].internal_endpoint : var.auth_url
  auth_signing_key = var.auth_signing_key
  auth_aes_key     = var.auth_aes_key

  # Deployment configuration
  image_tag = var.image_tag

  # Plugin configuration (plugins baked into Docker image, just need names for etcd seeding)
  server_plugins  = var.server_plugins
  auth_service_id = var.ac_auth_service_id

  # QURL plugin configuration
  qurl_config                   = var.qurl_config
  qurl_service_token_secret_arn = var.qurl_service_token_secret_arn

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

  # ASG Lifecycle Hook for immediate DynamoDB cleanup on server termination
  # When enabled, a Lambda cleans up assignments before the server terminates
  enable_termination_cleanup     = var.enable_termination_cleanup
  dynamodb_server_ac_index_table = module.dynamodb.server_ac_index_table_name
  dynamodb_ac_assignments_arn    = module.dynamodb.ac_assignments_table_arn
  dynamodb_server_ac_index_arn   = module.dynamodb.server_ac_index_table_arn

  # SNS topic for Lambda error alarms (from monitoring module)
  # Note: The SNS topic is created before compute resources, avoiding circular dependency
  alerts_sns_topic_arn = module.monitoring.sns_topic_arn
}

# Monitoring Module - CloudWatch Dashboard, Alarms, Slack Notifications
module "monitoring" {
  source = "./modules/monitoring"

  environment             = var.environment
  cell_id                 = var.cell_id
  nlb_arn_suffix          = module.compute.nlb_arn_suffix
  target_group_arn_suffix = module.compute.target_group_arn_suffix
  asg_name                = module.compute.asg_name
  name_prefix             = local.name_prefix
  tags                    = local.common_tags

  # Slack integration
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id

  # DynamoDB monitoring
  dynamodb_table_names = module.dynamodb.all_table_names
}

# DNS Module - Route 53 records
module "dns" {
  source = "./modules/dns"
  count  = var.hosted_zone != null ? 1 : 0

  environment      = var.environment
  domain_name      = var.domain_name
  hosted_zone_name = var.hosted_zone
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

  environment         = var.environment
  name_prefix         = local.name_prefix
  rate_limit_requests = var.environment == "prod" ? 5000 : 2000
  logs_kms_key_arn    = module.kms.logs_key_arn
  enable_cloudtrail   = var.enable_cloudtrail
  tags                = local.common_tags

  # GuardDuty alerting - sends findings to SNS for email/Slack notifications
  enable_guardduty_alerts = length(var.guardduty_alert_emails) > 0
  alerts_sns_topic_arn    = module.monitoring.sns_topic_arn
  guardduty_alert_emails  = var.guardduty_alert_emails
}

# RDS Module - Aurora PostgreSQL Serverless for console application
module "rds" {
  source = "./modules/rds"
  count  = var.deploy_rds ? 1 : 0

  environment        = var.environment
  name_prefix        = local.name_prefix
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids

  database_name       = var.rds_database_name
  min_capacity        = var.rds_min_capacity
  max_capacity        = var.rds_max_capacity
  deletion_protection = var.rds_deletion_protection
  skip_final_snapshot = var.environment != "prod"

  # KMS encryption
  secrets_kms_key_arn = module.kms.secrets_key_arn
  storage_kms_key_arn = module.kms.rds_key_arn

  tags = local.common_tags
}

# Console Module - Portal management application
module "console" {
  source = "./modules/console"
  count  = var.deploy_console && var.deploy_rds ? 1 : 0

  environment        = var.environment
  name_prefix        = local.name_prefix
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids

  console_image = "${module.ecr.console_repo_url}:latest"

  # RDS configuration
  rds_endpoint          = module.rds[0].cluster_endpoint
  rds_port              = module.rds[0].cluster_port
  rds_database_name     = module.rds[0].database_name
  rds_secret_arn        = module.rds[0].secret_arn
  rds_security_group_id = module.rds[0].security_group_id

  # AC configuration - use Terraform-managed AC IPs
  ac_configs = var.deploy_ac ? [
    {
      id       = "layerv-ac-tf"
      ip       = "10.100.0.248" # TODO: Get from AC module output
      port     = 443
      protocol = "tcp"
    }
  ] : []

  # Domain configuration
  domain_name         = var.console_domain
  hosted_zone         = var.hosted_zone
  acm_certificate_arn = var.console_acm_certificate_arn
  cookie_domain       = var.console_cookie_domain

  # KMS
  logs_kms_key_arn = module.kms.logs_key_arn

  tags = local.common_tags
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
  tags               = local.common_tags

  # KMS encryption keys
  logs_kms_key_arn    = module.kms.logs_key_arn
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # CloudFront + WAF (optional)
  enable_cloudfront = var.enable_cloudfront

  # AC configuration options
  auth_service_id   = var.ac_auth_service_id
  resource_ids      = var.ac_resource_ids
  server_endpoint   = module.compute.nlb_dns_name # External ACs use public NLB
  server_secret_arn = module.compute.server_secret_arn

  # License credentials for cloud mode registration
  customer_id        = var.ac_customer_id
  license_key        = var.ac_license_key
  license_key_hash   = var.ac_license_key_hash
  license_key_sha256 = var.ac_license_key_sha256

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

  # Console backend routing (when Console is in internal_only mode)
  # Routes Console domain directly to Console EC2, bypassing nhp-acd
  console_backend_url = var.deploy_console_ec2 && var.console_internal_only ? module.console_ec2[0].internal_endpoint : null
  console_domain      = var.deploy_console_ec2 && var.console_internal_only ? var.console_ec2_domain : null

  # QURL Router Plugin configuration (routes *.qurl.site to target backends)
  qurl_router_config = var.deploy_qurl_service && var.qurl_router_enabled ? {
    enabled            = true
    api_url            = "http://${module.qurl_service[0].alb_dns_name}"
    base_domain        = var.qurl_router_base_domain
    cache_ttl          = var.qurl_router_cache_ttl
    negative_cache_ttl = var.qurl_router_negative_cache_ttl
    max_cache_size     = var.qurl_router_max_cache_size
    api_timeout        = var.qurl_router_api_timeout
    proxy_timeout      = var.qurl_router_proxy_timeout
    cache_shards       = var.qurl_router_cache_shards
  } : null
  qurl_service_token_secret_arn = var.deploy_qurl_service && var.qurl_router_enabled ? var.qurl_internal_service_token_arn : null
}

# Demo Gateway Module - nginx + certbot for qurl.link routing to NHP Server plugins
# Routes qurl.link/{appId} to NHP Server HTTP passcode plugin
module "demo_gateway" {
  source = "./modules/demo-gateway"
  count  = var.deploy_demo_gateway ? 1 : 0

  environment       = var.environment
  domain_name       = var.demo_gateway_domain
  acme_email        = var.acme_email
  vpc_id            = module.networking.vpc_id
  vpc_cidr          = var.vpc_cidr
  public_subnet_ids = module.networking.public_subnet_ids
  name_prefix       = local.name_prefix
  tags              = local.common_tags

  # NHP Server endpoint for plugin HTTP requests
  # Uses Cloud Map DNS for service discovery within VPC
  nhp_server_endpoint = "server.${module.data.namespace_name}"
  nhp_server_port     = 8888

  # Route 53 for DNS and ACME challenges
  # For cross-account zones (e.g., qurl.link in layerv-mgmt), use cross_account_route53_role_arn
  cross_account_route53_role_arn = var.cross_account_route53_role_arn
  hosted_zone_id                 = var.demo_gateway_hosted_zone_id

  # KMS encryption
  ebs_kms_key_arn  = module.kms.ebs_key_arn
  logs_kms_key_arn = module.kms.logs_key_arn

  # Fallback redirect
  fallback_url = var.demo_gateway_fallback_url
}

# ==================== Console Image Tag (SSM Parameter) ====================
#
# Console is built from a SEPARATE repository (layervai/console), not this repo.
# Problem: Using NHP's image_tag (github.sha) for Console breaks deployments because
# Console has different commit hashes than NHP.
#
# Solution: SSM Parameter Store as the source of truth for Console image tag.
# - Console repo CI creates/updates the SSM parameter when deploying
# - NHP terraform reads the current value via data source
# - If the parameter doesn't exist, terraform fails fast (Console must deploy first)
#
# Flow:
# 1. Console repo pushes image with tag "abc123" to ECR
# 2. Console repo CI runs: aws ssm put-parameter --name /layerv-nhp-{env}/console-image-tag --value abc123
# 3. Console repo CI triggers ASG refresh
# 4. NHP deployments read current value from SSM - no interference
#
# SSM Parameter name: /${local.name_prefix}/console-image-tag
# Example: /layerv-nhp-sandbox/console-image-tag
#

# Read the Console image tag from SSM (fails if parameter doesn't exist)
data "aws_ssm_parameter" "console_image_tag" {
  count = var.deploy_console_ec2 ? 1 : 0

  name = "/${local.name_prefix}/console-image-tag"
}

# Console EC2 Module - Console API on EC2 with nginx + Docker
# Serves the Console API for portal site management (createPortalSitesByURL, etc.)
# When console_internal_only=true, Console is NHP-protected (traffic routed through AC)
module "console_ec2" {
  source = "./modules/console-ec2"
  count  = var.deploy_console_ec2 && var.deploy_rds ? 1 : 0

  environment        = var.environment
  name_prefix        = local.name_prefix
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  tags               = local.common_tags

  # Console image is resolved at boot time by reading tag from SSM
  # This allows Console CI to deploy independently without terraform
  console_image_repo          = module.ecr.console_repo_url
  console_image_tag_ssm_param = data.aws_ssm_parameter.console_image_tag[0].name
  domain_name                 = var.console_ec2_domain
  acme_email                  = var.acme_email
  cookie_domain               = var.console_cookie_domain

  # NHP Protection: When enabled, Console is internal-only (behind AC)
  # Traffic flows: Internet → AC NLB → Traefik → Console internal NLB
  internal_only        = var.console_internal_only
  ac_security_group_id = var.deploy_ac && var.console_internal_only ? module.ac[0].security_group_id : null

  # NHP Server endpoint for /plugins/* routing (required for post-login NHP auth)
  # When Console is internal-only, nginx routes /plugins/* to NHP Server
  nhp_server_endpoint = var.console_internal_only ? "server.${module.data.namespace_name}:8888" : null

  # RDS seeding for NHP Console resource
  # Seeds the portal_sites table with Console config so NHP Server/AC know how to route
  seed_console_resource = var.console_internal_only && var.deploy_ac
  console_app_id        = "console"
  ac_nlb_dns            = var.deploy_ac ? module.ac[0].nlb_dns_name : null
  ac_domain             = ".${var.domain_name}"
  # Two-domain architecture: protected_hostname is where users are redirected after auth_code knock
  # Login domain (console.nhp.layerv.xyz) is unprotected via Traefik bypass
  # Protected domain (console2.apps.layerv.xyz) is NHP-protected via AC
  protected_hostname = var.console_protected_hostname

  # RDS configuration
  rds_endpoint          = module.rds[0].cluster_endpoint
  rds_port              = module.rds[0].cluster_port
  rds_database_name     = module.rds[0].database_name
  rds_secret_arn        = module.rds[0].secret_arn
  rds_security_group_id = module.rds[0].security_group_id

  # AC configuration - use Terraform-managed AC
  ac_configs = var.deploy_ac ? [
    {
      id       = "layerv-ac-tf"
      ip       = module.ac[0].nlb_dns_name
      port     = 443
      protocol = "tcp"
    }
  ] : []

  # Route 53 for DNS (only used in external mode; internal mode DNS points to AC)
  hosted_zone_id = var.hosted_zone != null ? data.aws_route53_zone.main[0].zone_id : null

  # ECR for pulling console image
  ecr_repo_arn = module.ecr.console_repo_arn

  # KMS encryption
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  logs_kms_key_arn    = module.kms.logs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # Admin credentials (migrations handle initialization, GVA_AUTO_INIT=false)
  admin_password   = var.console_admin_password
  auth_signing_key = var.auth_signing_key

  # NHP Server Assignment - DynamoDB tables for AC assignments
  # Required when nhp_server_assignment_enabled=true (the default)
  nhp_dynamodb_ac_assignments_table  = module.dynamodb.ac_assignments_table_name
  nhp_dynamodb_server_ac_index_table = module.dynamodb.server_ac_index_table_name
  nhp_dynamodb_licenses_table        = module.dynamodb.licenses_table_name

  # NHP CloudMap - Console needs namespace to discover NHP servers
  nhp_cloudmap_namespace = module.data.namespace_name

  # Console AC License - for DynamoDB license validation in cloud mode
  # Generate with: ./terraform/scripts/generate-console-ac-license.sh <environment>
  # REQUIRED: AC registration will fail without valid license key hash
  nhp_console_ac_customer_id        = var.console_ac_customer_id
  nhp_console_ac_license_key_hash   = var.console_ac_license_key_hash
  nhp_console_ac_license_key_sha256 = var.console_ac_license_key_sha256
  nhp_console_ac_license_secret_arn = var.console_ac_license_key_hash != null && var.console_ac_license_key_hash != "" ? "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:layerv-nhp-${var.environment}/console-ac-license-key" : null

  # NHP AC Daemon - Console always needs its own AC for login flow to work
  # The AC registers with NHP Server and receives knock validations
  nhp_server_secret_arn   = var.deploy_ac ? module.compute.server_secret_arn : null
  nhp_server_cloudmap_dns = module.compute.cloudmap_service_dns
  nhp_ac_repo_url         = module.ecr.ac_repo_url
  nhp_ac_ecr_repo_arn     = module.ecr.ac_repo_arn
  image_tag               = var.image_tag

  # NHP Network-Level Protection (true network hiding with iptables DROP)
  # Console EC2 configures iptables DROP by default.
  # Port 443 is only accessible after NHP knock adds the user's IP to ipset.
  # Reuse main hosted zone - apps.layerv.xyz is a subdomain of layerv.xyz
  protected_hosted_zone_id = length(data.aws_route53_zone.main) > 0 ? data.aws_route53_zone.main[0].zone_id : null
}

# Data source for hosted zone (used by console_ec2)
data "aws_route53_zone" "main" {
  count = var.hosted_zone != null ? 1 : 0
  name  = var.hosted_zone
}

# Route 53 record for Console domain pointing to AC NLB (internal mode only)
# When Console is NHP-protected, DNS should point to AC, not Console NLB
resource "aws_route53_record" "console_via_ac" {
  count = var.deploy_console_ec2 && var.console_internal_only && var.deploy_ac && var.hosted_zone != null ? 1 : 0

  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.console_ec2_domain
  type    = "A"

  alias {
    name                   = module.ac[0].nlb_dns_name
    zone_id                = module.ac[0].nlb_zone_id
    evaluate_target_health = true
  }
}

# ==================== QURL Service ====================
# ECS Fargate deployment for the QURL API service
# Public API protected by Auth0 JWT, no NHP protection needed

module "qurl_service" {
  count  = var.deploy_qurl_service ? 1 : 0
  source = "./modules/qurl-service"

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  tags        = local.common_tags

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
  auth0_domain   = var.qurl_auth0_domain
  auth0_audience = var.qurl_auth0_audience

  # Secrets
  secrets_kms_key_arn        = module.kms.secrets_key_arn
  jwt_secret_arn             = var.qurl_jwt_secret_arn
  internal_service_token_arn = var.qurl_internal_service_token_arn

  # KMS
  logs_kms_key_arn = module.kms.secrets_key_arn

  # QURL defaults
  cookie_domain        = var.qurl_cookie_domain
  default_token_expire = var.qurl_default_token_expire
  default_open_time    = var.qurl_default_open_time

  # AC Fleet defaults
  default_ac_id   = var.qurl_default_ac_id
  default_ac_host = var.qurl_default_ac_host
  default_ac_port = var.qurl_default_ac_port

  # Domain
  domain_name     = var.qurl_service_domain
  hosted_zone_id  = var.qurl_hosted_zone_id
  certificate_arn = var.qurl_certificate_arn
}
