# Provider version floor for features this module exercises.
# Documented as the literal minimum (not the current root pin) so
# the constraint is honest about what the module needs vs. what the
# repo currently runs.
#
# Floor: `aws_wafv2_web_acl`'s `rate_based_statement.evaluation_window_sec`
# (waf.tf) was added in provider 5.21. Earlier versions silently
# drop the field and the rule falls back to AWS's default window —
# a hidden mismatch against the stack's documented "per-5-minute-
# window" semantics. Root currently pins `~> 6.27`, well above the
# floor; this constraint is operationally non-binding today.

terraform {
  # >= 1.5 because the module uses `startswith()` (variables.tf
  # waf_managed_rule_groups validation) and `endswith()` (cert_dns.tf
  # dns_name/zone subdomain precondition) — both added in Terraform
  # 1.5. Root applies on `~> 1.14` today, so this constraint is
  # operationally non-binding; documents the true minimum.
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.21"
    }
  }
}
