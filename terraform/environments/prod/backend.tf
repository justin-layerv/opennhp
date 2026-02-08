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

# Auth0 provider for identity management
# Credentials MUST be passed via environment variables (required, no defaults):
#   TF_VAR_auth0_tf_client_id     - M2M client ID with Management API access
#   TF_VAR_auth0_tf_client_secret - M2M client secret
# In CI: These are set from GitHub Secrets (AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)
# Locally: Export these env vars before running terraform
provider "auth0" {
  domain        = var.auth0_domain
  client_id     = var.auth0_tf_client_id
  client_secret = var.auth0_tf_client_secret
}
