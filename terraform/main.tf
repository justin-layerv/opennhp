# LayerV NHP Infrastructure
# Consistent with layerv/traefik-plugins terraform patterns
#
# Multi-account architecture:
# - Staging (layerv): Primary account, owns ECR repositories
# - Production (layerv-prod): Secondary account, pulls from staging ECR cross-account

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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
    Project     = "LayerV-NHP"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# ==================== Modules ====================

# ECR Module - Creates ECR in primary account, references cross-account in secondary
module "ecr" {
  source = "./modules/ecr"

  name_prefix        = local.name_prefix
  tags               = local.common_tags
  is_primary_account = var.is_primary_account
  primary_account_id = var.primary_account_id
  github_org         = var.github_org
  github_repo        = var.github_repo
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
}

# Compute Module - ASG, NLB, Launch Template
module "compute" {
  source = "./modules/compute"

  environment        = var.environment
  domain_name        = var.domain_name
  multi_tenant       = var.multi_tenant
  min_capacity       = var.min_capacity
  max_capacity       = var.max_capacity
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  server_repo_url    = module.ecr.server_repo_url
  server_repo_arn    = module.ecr.server_repo_arn
  etcd_endpoint      = module.data.etcd_endpoint
  etcd_secret_arn    = module.data.etcd_secret_arn
  namespace_id       = module.data.namespace_id
  namespace_name     = module.data.namespace_name
  name_prefix        = local.name_prefix
  tags               = local.common_tags
}

# Monitoring Module - CloudWatch Dashboard, Alarms
module "monitoring" {
  source = "./modules/monitoring"

  environment             = var.environment
  nlb_arn_suffix          = module.compute.nlb_arn_suffix
  target_group_arn_suffix = module.compute.target_group_arn_suffix
  asg_name                = module.compute.asg_name
  name_prefix             = local.name_prefix
  tags                    = local.common_tags
}
