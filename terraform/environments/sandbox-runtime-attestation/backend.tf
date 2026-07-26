# Remote state backend + provider configuration for the sandbox
# runtime-attestation store.
#
# This LEAN, standalone root composes terraform/modules/runtime-attestation-store
# — the immutable per-node runtime evidence channel the UDP-proof
# deployment-manifest producer reads. It creates the versioned,
# bucket-owner-enforced, public-blocked, KMS-encrypted bucket, its self-binding
# policy, the canonical collector and its pinned State Manager repair document,
# and the two public SSM parameters the producer requires.
#
# It lives in its own root (like sandbox-cell1 / sandbox-hub-dns /
# sandbox-udp-proof-runner) because the store is a shared predecessor of three
# fleets owned by two different roots and of the read-only producer root — no
# single existing root owns it, and the udp-proof-runner root consumes its ARNs
# as inputs.
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
