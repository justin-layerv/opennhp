# Remote state backend + provider configuration for the sandbox Hub-DNS root.
#
# This LEAN, standalone root emits exactly one public record —
# `hub.nhp.layerv.xyz` A-alias -> the Connector Hub's public UDP:62206 NLB
# (Step 5 slice 5c). It lives OUTSIDE the Control tree on purpose:
#
#   * `aws_route53_record` is lexically forbidden anywhere under
#     `terraform/control/**` and the connector-authority-foundation module by
#     `scripts/check-connector-authority-foundation.sh` (the dark-foundation
#     fence), and the Control convergence contract
#     (`.github/scripts/check-control-sandbox-first-apply.py`) admits only an
#     exact resource inventory — a DNS record there would need a whole new
#     admitted slice. Keeping the record in its own root avoids both.
#   * It must NOT ride the giant cell0 root (`terraform/environments/sandbox`):
#     that root owns the whole NHP server/AC/relay deploy, so coupling one Hub
#     record to it would gate the record on that deploy's health.
#
# The Hub NLB is created in the Control root but is discovered here by NAME via
# a `data "aws_lb"` lookup (see main.tf) — no cross-root state coupling, and the
# lookup survives an NLB replacement. Same AWS account as Control/cell0
# (767397897469), so a plain data source resolves it.
#
# State isolation: distinct backend key `nhp/sandbox-hub-dns/...`.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox-hub-dns/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    # SSE-KMS for state, same posture as the cell0 / cell1 sandbox roots. The
    # `alias/terraform-state` CMK already exists in this account.
    # See docs/runbooks/tfstate-kms-migration.md.
    kms_key_id = "alias/terraform-state"
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
