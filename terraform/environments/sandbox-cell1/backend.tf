# Remote state backend + provider configuration for the sandbox cell1 root.
#
# cell1 is the SECOND cell of the two-cell UDP substrate for the qURL Connector
# (Step 6). It is a LEAN, standalone NHP-server cell: its own VPC (distinct,
# non-overlapping CIDR), its own public UDP:62206 NLB, and its own
# `/sandbox-cell1/nhp/server/udp-listener-arn` SSM parameter. It deliberately
# does NOT reuse the giant cell-parameterized root module (`terraform/`): that
# module's always-on `module.security` creates account-singleton resources
# (GuardDuty detector, AWS Config recorder, Security Hub) whose gates are not
# exposed at the root, so a second full instantiation would collide with cell0
# in the same account. This root instead wires only the shared sub-modules a
# server needs, guaranteeing no account-singleton collision (see main.tf header).
#
# State isolation from cell0: distinct backend key `nhp/sandbox-cell1/...`.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
    # Consumed transitively by modules/compute (data.archive_file for the
    # keygen Lambda). Declared here so `init` resolves it deterministically.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  backend "s3" {
    bucket       = "layerv-terraform-state-767397897469"
    key          = "nhp/sandbox-cell1/terraform.tfstate"
    region       = "us-east-2"
    use_lockfile = true
    encrypt      = true
    # SSE-KMS for state, same posture as the cell0 sandbox root. The
    # `alias/terraform-state` CMK must already exist in this account (it does —
    # cell0 uses it). See docs/runbooks/tfstate-kms-migration.md.
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
