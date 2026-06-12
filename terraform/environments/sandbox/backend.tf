# Remote state backend configuration
# Consistent with layerv/traefik-plugins terraform patterns

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
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox/terraform.tfstate"
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
# Used by production for DNS records in externally hosted zones.
#
# The role (nhp-ac-route53-access) must exist in layerv-mgmt and trust the
# GitHub Actions role in this account.
provider "aws" {
  alias  = "route53_mgmt"
  region = var.aws_region

  # Cross-account access to Route53 in management account
  # Uses dynamic block so provider is valid even when role ARN is not set (same-account DNS)
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

# Auth0 provider for identity management
# Uses EITHER api_token (CI) OR client_id+client_secret (local dev) — never both,
# because the provider's schema marks them as ConflictsWith each other.
#
# CI: fetch-auth0-token.sh fetches one token, passed via TF_VAR_auth0_api_token.
#     client_id/client_secret are still passed (for the variable definitions) but
#     the ternary nulls them out so the provider only sees api_token.
# Local: auth0_api_token defaults to "" so client_id/client_secret are used.
provider "auth0" {
  domain        = var.auth0_domain
  api_token     = var.auth0_api_token != "" ? var.auth0_api_token : null
  client_id     = var.auth0_api_token == "" ? var.auth0_tf_client_id : null
  client_secret = var.auth0_api_token == "" ? var.auth0_tf_client_secret : null
}
