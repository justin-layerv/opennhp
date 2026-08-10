# Remote state backend + provider configuration for the sandbox
# runtime-attestation store.
#
# This LEAN, standalone root composes terraform/modules/runtime-attestation-store
# — the immutable per-node runtime evidence channel for the attested cell0,
# cell1 and qRTS fleets. It creates the versioned, bucket-owner-enforced,
# public-blocked, KMS-encrypted bucket, its self-binding policy, and the
# canonical collector with its pinned State Manager repair document.
#
# It lives in its own root (like sandbox-cell1 / sandbox-hub-dns) because the
# store is a shared predecessor of three fleets owned by two different roots, so
# no single existing root owns it. It was originally also a predecessor of the
# UDP-proof deployment-manifest producer, which consumed its ARNs and read two
# SSM parameters it published; that producer was deleted in #3799 and the
# parameters retired, but the shared-predecessor reason stands on the fleets
# alone.
#
# State isolation: distinct backend key nhp/sandbox-runtime-attestation/...

terraform {
  required_version = ">= 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox-runtime-attestation/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    kms_key_id   = "alias/terraform-state"
    # Uses AWS_PROFILE locally, or the IAM role in CI/CD.
  }
}

provider "aws" {
  region = var.aws_region
  # Uses AWS_PROFILE locally, or the IAM role in CI/CD.

  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
