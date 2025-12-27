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
      version               = "~> 5.0"
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

  # Traefik plugins bucket (from AC module)
  # Allows traefik-plugins repo to upload plugins to S3
  enable_plugin_bucket_policy = var.deploy_ac
  plugin_bucket_arn           = var.deploy_ac ? module.ac[0].plugin_bucket_arn : ""
  traefik_plugins_github_repo = var.traefik_plugins_github_repo
}

# Networking Module - VPC, Subnets, Security Groups
module "networking" {
  source = "./modules/networking"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  name_prefix = local.name_prefix
  tags        = local.common_tags
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

# Compute Module - ASG, NLB, Launch Template
module "compute" {
  source = "./modules/compute"

  environment         = var.environment
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
  dev_mode         = var.dev_mode
  resource_mode    = var.resource_mode
  auth_url         = var.auth_url
  auth_signing_key = var.auth_signing_key
  auth_aes_key     = var.auth_aes_key
}

# Monitoring Module - CloudWatch Dashboard, Alarms, Slack Notifications
module "monitoring" {
  source = "./modules/monitoring"

  environment             = var.environment
  nlb_arn_suffix          = module.compute.nlb_arn_suffix
  target_group_arn_suffix = module.compute.target_group_arn_suffix
  asg_name                = module.compute.asg_name
  name_prefix             = local.name_prefix
  tags                    = local.common_tags

  # Slack integration
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id
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

  environment         = var.environment
  domain_name         = var.domain_name
  hosted_zone         = var.hosted_zone
  acme_email          = var.acme_email
  vpc_id              = module.networking.vpc_id
  vpc_cidr            = var.vpc_cidr
  public_subnet_ids   = module.networking.public_subnet_ids
  private_subnet_ids  = module.networking.private_subnet_ids
  ac_repo_url         = module.ecr.ac_repo_url
  ac_repo_arn         = module.ecr.ac_repo_arn
  etcd_endpoint       = module.data.etcd_endpoint
  etcd_secret_arn     = module.data.etcd_secret_arn
  etcd_tls_secret_arn = module.data.etcd_ca_cert_arn
  namespace_id        = module.data.namespace_id
  namespace_name      = module.data.namespace_name
  name_prefix         = local.name_prefix
  tags                = local.common_tags

  # KMS encryption keys
  logs_kms_key_arn    = module.kms.logs_key_arn
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # CloudFront + WAF (optional)
  enable_cloudfront = var.enable_cloudfront

  # AC configuration options
  auth_service_id   = var.ac_auth_service_id
  resource_ids      = var.ac_resource_ids
  server_nlb_dns    = module.compute.nlb_dns_name
  server_secret_arn = module.compute.server_secret_arn

  # Production domains (ACME for qurl.site, qurl.link, etc.)
  cross_account_route53_role_arn = var.cross_account_route53_role_arn
  production_domains             = var.production_domains
  production_zone_ids            = var.production_zone_ids
}
