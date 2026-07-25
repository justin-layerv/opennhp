# Remote state backend + provider configuration for the sandbox UDP-proof-runner
# root (Step 8 of the two-cell UDP substrate for the qURL Connector).
#
# This LEAN, standalone root composes terraform/modules/udp-proof-runner — the
# NHP-owned compute boundary for the ATTENDED, deployed qurl-go and qURL
# Connector UDP proof. It provisions NO standing runner: a dedicated, unpeered
# /28 VPC, one persistent EIP (the stable source /32 reviewed in the Hub + cell
# ingress), a hardened launch template, a serialized broker Lambda, a one-use
# JIT secret, and a sweeper. A later NHP controller workflow dispatches one JIT
# runner per separately-approved client proof.
#
# It lives in its own root (like sandbox-cell1 / sandbox-hub-dns) to match the
# module's strong isolation intent (unpeered VPC, dedicated broker, protected
# GitHub environment) and to stay off the B/G-broken main sandbox deploy.
#
# State isolation: distinct backend key nhp/sandbox-udp-proof-runner/...

terraform {
  required_version = ">= 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
    # The module builds its broker + cleanup Lambda zips via data.archive_file.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox-udp-proof-runner/terraform.tfstate"
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
