# Remote state backend configuration
# Consistent with layerv/traefik-plugins terraform patterns
#
# State bucket must exist in the prod account before first terraform init.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
    auth0 = {
      source  = "auth0/auth0"
      version = "~> 1.0"
    }
  }

  backend "s3" {
    # Account ID hardcoded here because backend config doesn't support variables.
    # Keep in sync with aws_account_id in terraform.tfvars.
    bucket       = "layerv-terraform-state-235500187906"
    key          = "nhp/prod/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    # SSE-KMS for state (#1128): with encrypt=true, kms_key_id overrides the
    # explicit-AES256 header so the state object is encrypted under the CMK.
    # alias/terraform-state must exist in this account before `init` resolves
    # it. See docs/runbooks/tfstate-kms-migration.md (incl. the
    # `init -reconfigure` step and the .tflock vs state-object Phase D check).
    kms_key_id = "alias/terraform-state"
    # Note: Uses AWS_PROFILE env var locally, or IAM role in CI/CD
  }
}

provider "aws" {
  region = var.aws_region
  # Note: Uses AWS_PROFILE env var locally, or IAM role in CI/CD

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Provider for us-east-1 (required for CloudFront WAF and ACM)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  # Note: Uses AWS_PROFILE env var locally, or IAM role in CI/CD

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Provider alias for Route53 operations in the management account
#
# This provider assumes a cross-account role to access Route53 in layerv-mgmt.
# Required for qurl.link DNS records when qurl_link_external_dns=false.
#
# The role (nhp-ac-route53-access) must exist in layerv-mgmt and trust the
# GitHub Actions role in this account.
provider "aws" {
  alias  = "route53_mgmt"
  region = var.aws_region

  # Cross-account access to Route53 in management account
  # Uses dynamic block so provider is valid even when role ARN is not yet set
  dynamic "assume_role" {
    for_each = var.cross_account_route53_role_arn != null ? [1] : []
    content {
      role_arn     = var.cross_account_route53_role_arn
      session_name = "TerraformRoute53"
    }
  }

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Provider for cost analytics in management account (us-east-1)
# Data Exports API and all cost resources live in mgmt us-east-1
provider "aws" {
  alias  = "billing_mgmt"
  region = "us-east-1" # Data Exports is us-east-1 only

  dynamic "assume_role" {
    for_each = var.cross_account_cost_analytics_role_arn != null && var.cross_account_cost_analytics_role_arn != "" ? [1] : []
    content {
      role_arn     = var.cross_account_cost_analytics_role_arn
      session_name = "TerraformCostAnalytics"
    }
  }

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Auth0 provider — RETIRED, stub only (#3284).
#
# Terraform no longer manages any Auth0 resource; the tenant is owned in the
# Auth0 dashboard. See `../../modules/auth0/removed.tf` for why, and for the
# full list of resources being forgotten (`removed` + `destroy = false`).
#
# This block survives ONLY to let Terraform decode the `auth0_*` entries still
# recorded in state so it can forget them. Terraform demands an explicit
# provider configuration for that even though a forget makes no API calls —
# without this block the plan fails with `Error: Invalid provider
# configuration`. Because no call is made, the token below is a literal
# placeholder: there are deliberately NO real Auth0 credentials in this
# configuration, in CI, or in the plan environment any more.
#
# DELETE THIS BLOCK, the `auth0` entry in `required_providers` above, and
# `modules/auth0/removed.tf` once BOTH environments have applied and neither
# state contains an `auth0_*` entry:
#   terraform state list | grep auth0_    # must print nothing
# Removing it earlier strands those state entries and breaks the plan.
provider "auth0" {
  domain    = var.auth0_domain
  api_token = "retired-see-modules-auth0-removed-tf-no-api-calls-are-made"
}
