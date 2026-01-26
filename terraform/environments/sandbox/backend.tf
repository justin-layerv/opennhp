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
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox/terraform.tfstate"
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
