# DNS records for the qurl-integrations bot stack (sandbox).
#
# Naming convention (per Justin 2026-04-29):
#   <bot-platform>.layerv.xyz  → sandbox
#   <bot-platform>.layerv.ai   → prod
#
# Env encoded in TLD; bot platform encoded in subdomain. Future
# slack/teams/etc. bots add their own subdomain in this file (or a
# sibling) without colliding.
#
# Currently covers the Discord bot's sandbox ACM cert validation.
# The cert lives in the qurl-integrations sandbox account
# (730883236711, us-east-2); the `layerv.xyz` zone lives in this
# nhp-sandbox account (767397897469). Different accounts, no
# cross-account ACM provider alias is wired up — so the validation
# tokens below are hardcoded rather than data-sourced from
# `aws_acm_certificate.domain_validation_options` (compare the
# qurl_api cert pattern in `terraform/main.tf`, which is in-account).
# ACM reuses validation records on renewal, so this only churns on
# cert *re-issuance* (domain list change, accidental delete), not
# on the 13-month renewal cycle. If the upstream cert is ever
# re-requested, pull the new token from the ACM console and update
# the `name`/`records` values below.
#
# Lifecycle is "create once, leave alone": deleting the validation
# record stops ACM from being able to renew the cert; the failure
# only surfaces ~13 months later when renewal silently fails. The
# `lifecycle.prevent_destroy = true` block on each record makes that
# rule an enforced plan-time guard.

locals {
  # Bot platform domain. Centralized for future reuse: the alias
  # record (post-ALB-apply) will reference the same domain, and the
  # validation `name` below is built from it.
  discord_bot_domain = "discord.layerv.xyz"
}

# Validates ACM cert in qurl-integrations sandbox account
# (730883236711, us-east-2):
#   arn:aws:acm:us-east-2:730883236711:certificate/a5c27c4f-c340-4575-8777-5b9b29aaf92c
# Pinning the ARN here so a future operator debugging a renewal
# failure ~13 months out can grep this file for the cert and confirm
# they're looking at the right record.
resource "aws_route53_record" "discord_bot_cert_validation" {
  # ACM's "Add record in Route 53" console button can pre-create the
  # CNAME directly in the zone; without `allow_overwrite`, Terraform
  # refuses to claim an existing record and the apply errors. Matches
  # the `aws_route53_record.cloudfront_cert_validation` posture in
  # `terraform/modules/ac/main.tf:1123` — idempotent against console
  # pre-staging.
  allow_overwrite = true

  # `var.qurl_hosted_zone_id` is the de-facto layerv.xyz parent-zone
  # variable in this env — already wired into `module.acme_cert.parent_zone_id`
  # and `module.acme_cert.hosted_zone_id` in `main.tf` for the same purpose
  # (records under the layerv.xyz root). Using it here addresses Justin's
  # decoupling concern (the bot cert isn't tied to the qurl.site-named
  # `qurl_site_hosted_zone_id`) without introducing a new variable that
  # duplicates an existing one.
  zone_id = var.qurl_hosted_zone_id
  name    = "_156ba732d21ae344779b83723a12eaaf.${local.discord_bot_domain}"
  type    = "CNAME"
  ttl     = 60
  records = ["_2e0faef7b5213be9aaca34388d6c157a.jkddzztszm.acm-validations.aws."]

  # Mirrors `aws_route53_record.qurl_s3_connector` in
  # `terraform/main.tf`. Escape hatches:
  #   Retirement: `terraform state rm`, remove the block, apply.
  #   Cert re-issuance (token rotates): changing `name` forces
  #     resource replacement, which `prevent_destroy` blocks. So:
  #     `terraform state rm aws_route53_record.discord_bot_cert_validation`,
  #     update `name`/`records` here, plan+apply (resource is
  #     re-created with prevent_destroy on the new instance).
  lifecycle {
    prevent_destroy = true
  }
}
