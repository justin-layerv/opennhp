# Standalone production Hub DNS root. Control owns the Hub NLB in the production
# account; the public layerv.ai zone lives in the management account. Keeping
# this record outside Control preserves Control's no-Route53 resource boundary
# and gives the cross-account DNS write its own state and review surface.
terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-235500187906"
    key          = "nhp/prod-hub-dns/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    kms_key_id   = "alias/terraform-state"
  }
}

# Reads the Hub NLB in the production account.
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Writes only the explicit Hub alias in the management-account parent zone.
provider "aws" {
  alias  = "route53_mgmt"
  region = var.aws_region

  assume_role {
    role_arn     = var.management_route53_role_arn
    session_name = "TerraformProdHubDNS"
  }

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
