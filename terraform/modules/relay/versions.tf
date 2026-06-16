# Provider version floor for features this module exercises.
#
# Floor: `aws_wafv2_web_acl`'s `rate_based_statement.evaluation_window_sec`
# (alb.tf) was added in provider 5.21. Earlier versions silently drop the
# field and the rule falls back to AWS's default window — a hidden mismatch
# against the documented "per-5-minute-window" semantics. Root pins `~> 6.27`,
# well above the floor; this constraint documents the true module minimum.

terraform {
  # >= 1.5 because the module uses `endswith()` (cert_dns.tf dns_name/zone
  # subdomain precondition), added in Terraform 1.5. Root applies on `~> 1.14`.
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.21"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}
