# Import blocks for pre-existing resources that Terraform needs to adopt.
# These are safe to leave in place — Terraform treats them as no-ops after
# the first successful import.

# The acme.layerv.xyz NS delegation record was created manually in Route53
# before the custom-domain-cert module added it as a managed resource.
import {
  to = module.custom_domain_cert[0].aws_route53_record.acme_ns_delegation
  id = "Z10394893FM38A1RXLL32_acme.layerv.xyz_NS"
}

# The qURL v2 EnterPortal trust params were seeded by hand
# (`aws ssm put-parameter`) to unblock the qurl-service smoke
# (qurl-service#1097) before this module managed them. Adopt them so the first
# managed apply does not hit ParameterAlreadyExists. The target resources are
# keyed by environment, and these imports use matching conditional for_each
# gates so disabling qURL v2 admission leaves no stale count-indexed target.
locals {
  # Mirrors module.nhp's local.qurl_v2_admission_ready. Child-module locals are
  # not in scope here, so the admission gate is re-derived once and shared by
  # both import blocks. Keep this expression in lockstep with main.tf.
  qurl_v2_admission_ready = var.qurl_v2_admission_enabled && var.qurl_v2_issuer_key_enabled && var.qurl_v2_issuer_kid != ""
}

import {
  for_each = local.qurl_v2_admission_ready ? toset(["sandbox"]) : toset([])
  to       = module.nhp.aws_ssm_parameter.qurl_qv2_issuer_key[each.key]
  id       = "/sandbox/nhp/qurl/qv2-issuer-key"
}

import {
  for_each = local.qurl_v2_admission_ready && var.qurl_v2_relay_url != "" ? toset(["sandbox"]) : toset([])
  to       = module.nhp.aws_ssm_parameter.qurl_relay_url[each.key]
  id       = "/sandbox/nhp/qurl/relay-url"
}
