terraform {
  # The workflow's least-privilege S3 policy depends on Terraform 1.14.3's
  # default-workspace AccessDenied handling. Keep this exact constraint aligned
  # with TF_VERSION and regenerate the golden plans before changing it.
  required_version = "= 1.14.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-235500187906"
    key          = "nhp/prod/staged/qurl-agent-transact-iam/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    # The workflow session policies pin this alias's current target,
    # key/00a0e673-cef4-41f0-bfc0-5116a9ab3aa0. Keep them in sync; an alias
    # repoint intentionally fails closed at KMS authorization.
    kms_key_id = "alias/terraform-state"
  }
}

provider "aws" {
  region              = "us-east-2"
  allowed_account_ids = ["235500187906"]
}
