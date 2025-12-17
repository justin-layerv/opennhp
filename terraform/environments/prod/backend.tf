# Remote state backend configuration
# Consistent with layerv/traefik-plugins terraform patterns
#
# NOTE: Bucket name uses prod account ID (replace PROD_ACCOUNT_ID)
# Create state resources in prod account before first apply

terraform {
  backend "s3" {
    bucket         = "layerv-terraform-state-PROD_ACCOUNT_ID"  # TODO: Replace with actual prod account ID
    key            = "nhp/prod/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
    profile        = "layerv-prod"
  }
}

provider "aws" {
  region  = var.aws_region
  profile = "layerv-prod"

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
