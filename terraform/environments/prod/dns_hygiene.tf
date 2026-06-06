# DNS hygiene records for the LayerV apex domains hosted in the layerv-mgmt
# account: layerv.ai, qurl.site, qurl.link. Closes the Terraform-addressable
# items of nhp#1149 (CAA on every apex; SPF + DMARC on the qurl domains).
# layerv.xyz lives in the sandbox account and is handled by the sibling
# `terraform/environments/sandbox/dns_hygiene.tf`.
#
# All three zones are cross-account (layerv-mgmt), so every record uses the
# `aws.route53_mgmt` provider alias — the same posture as `qurl_bot_dns.tf`.
# Records are gated on `cross_account_route53_role_arn` so a misconfigured
# apply without the mgmt role fails closed instead of erroring at
# ChangeResourceRecordSets time.
#
# `allow_overwrite` is intentionally OFF (the default) on every record here:
# all of these names were verified ABSENT in live DNS at PR time (no CAA on any
# apex; empty apex TXT on qurl.link/qurl.site; no `_report._dmarc` records), so
# they are genuine creates. A Route53 TXT/CAA name holds a SINGLE record set —
# `allow_overwrite = true` would replace the WHOLE set, silently clobbering any
# value created out-of-band in the interim (e.g. a domain-verification token).
# Failing loud on a name collision is the right posture, matching the
# `discord_bot_alias` rationale in `qurl_bot_dns.tf`. (The two layerv.xyz
# records that already exist and must be modified — SPF + DMARC — DO use
# `allow_overwrite` and live in the sandbox sibling file.)
#
# Every record also carries `lifecycle { prevent_destroy = true }` (matching the
# durable-record posture of `qurl_bot_dns.tf`): combined with the `count` gates,
# an apply where a gating var ever resolves to null fails LOUD instead of
# silently destroying the apex CAA/SPF/DMARC set and reverting this hardening.
# To intentionally retire a record — or to apply a force-new change such as a
# zone_id repoint — delete the resource block, apply, then re-add it (the same
# retire-and-recreate dance the sibling `qurl_bot_dns.tf` records use).
#
# CAA issuer sets were derived from the live certificate-transparency history
# (crt.sh) of each domain, NOT guessed from Terraform — a CAA that omits any CA
# actively issuing for the tree silently breaks that CA's next renewal. The
# issuer building blocks live in the shared `modules/dns-hygiene-constants` so
# the prod and sandbox root modules can't drift:
#   - amazon.com / amazontrust.com / awstrust.com / amazonaws.com  → AWS ACM
#     (all four are interchangeable per the ACM docs; list all to be safe):
#     https://docs.aws.amazon.com/acm/latest/userguide/setup-caa.html
#   - letsencrypt.org                                              → the
#     centralized acme-cert module + AC per-resource ACME certs.
#   - godaddy.com / starfieldtech.com                             → GoDaddy,
#     which actively issues for email.layerv.ai (NOT used on the qurl zones):
#     https://www.godaddy.com/help/using-caa-records-with-your-ssl-certificate-27227
#
# `issuewild` is intentionally NOT set: an `issuewild` that omits an ACM value
# blocks ACM wildcard issuance (e.g. the *.layerv.ai cert). With no `issuewild`
# present, the `issue` set governs wildcard issuance too — which is what we want.

# Shared CAA issuer building blocks + TTL — single source of truth across the
# prod and sandbox root modules (Terraform can't share locals across root
# modules). See modules/dns-hygiene-constants.
module "dns_hygiene" {
  source = "../../modules/dns-hygiene-constants"
}

locals {
  dns_hygiene_ttl = module.dns_hygiene.ttl

  # Per-domain minimal-but-complete issuer sets (nhp#1149, CAA scope = per-domain
  # minimal). layerv.ai keeps GoDaddy for email.layerv.ai; the qurl zones do not.
  # caa_qurl intentionally includes ACM: qurl.link actively issues from ACM, and
  # qurl.site (Let's Encrypt-only in today's CT logs) keeps ACM too — harmless
  # and future-proofs an ACM migration. Do NOT trim ACM to match today's crt.sh
  # or a later ACM cert on qurl.site would silently fail issuance.
  caa_layerv_ai = concat(module.dns_hygiene.caa_acm, module.dns_hygiene.caa_letsencrypt, module.dns_hygiene.caa_godaddy, module.dns_hygiene.caa_iodef)
  caa_qurl      = concat(module.dns_hygiene.caa_acm, module.dns_hygiene.caa_letsencrypt, module.dns_hygiene.caa_iodef)

  # DMARC policy shared by the non-sending qurl domains. p=reject + sp=reject
  # pins the apex AND subdomains (a non-sender has no reason to let any subdomain
  # publish a weaker policy); pct=100 mirrors the live layerv.ai DMARC record.
  dmarc_qurl_policy = ["v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@layerv.ai; pct=100"]

  # Cross-account record gate: every record here needs the mgmt-account role.
  dns_hygiene_mgmt_enabled = var.cross_account_route53_role_arn != null
}

# ---------------------------------------------------------------------------
# CAA — one record set per apex.
# ---------------------------------------------------------------------------

# layerv.ai-specific records key off `var.hosted_zone_id` (the canonical
# layerv.ai zone var), NOT `var.qurl_hosted_zone_id`. Both equal Z0748… in prod
# tfvars, but `qurl_hosted_zone_id` is the "qurl parent zone" and resolves to the
# layerv.xyz zone in sandbox — using `hosted_zone_id` keeps these honest and
# unbreakable if `qurl_hosted_zone_id` is ever repointed.
resource "aws_route53_record" "caa_layerv_ai" {
  count    = local.dns_hygiene_mgmt_enabled && var.hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.hosted_zone_id # layerv.ai zone (layerv-mgmt)
  name    = var.hosted_zone    # "layerv.ai"
  type    = "CAA"
  ttl     = local.dns_hygiene_ttl
  records = local.caa_layerv_ai

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "caa_qurl_site" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_site_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_site_hosted_zone_id
  name    = var.qurl_site_domain # "qurl.site"
  type    = "CAA"
  ttl     = local.dns_hygiene_ttl
  records = local.caa_qurl

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "caa_qurl_link" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_link_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_link_hosted_zone_id
  name    = var.qurl_link_domain # "qurl.link"
  type    = "CAA"
  ttl     = local.dns_hygiene_ttl
  records = local.caa_qurl

  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# SPF + DMARC — the qurl domains send no mail (verified at PR time: no MX, no
# _amazonses identity, no DKIM selectors), so publish explicit null SPF (`-all`)
# and an enforcing DMARC policy. Spoofing `From: *@qurl.link` / `*@qurl.site` is
# rejected outright. layerv.ai already has SPF + DMARC (hardened separately) and
# is intentionally not touched here.
# ---------------------------------------------------------------------------

resource "aws_route53_record" "spf_qurl_site" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_site_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_site_hosted_zone_id
  name    = var.qurl_site_domain
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = ["v=spf1 -all"]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "spf_qurl_link" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_link_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_link_hosted_zone_id
  name    = var.qurl_link_domain
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = ["v=spf1 -all"]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "dmarc_qurl_site" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_site_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_site_hosted_zone_id
  name    = "_dmarc.${var.qurl_site_domain}"
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = local.dmarc_qurl_policy

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "dmarc_qurl_link" {
  count    = local.dns_hygiene_mgmt_enabled && var.qurl_link_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.qurl_link_hosted_zone_id
  name    = "_dmarc.${var.qurl_link_domain}"
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = local.dmarc_qurl_policy

  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Cross-domain DMARC report authorization (RFC 7489 §7.1).
# qurl.link, qurl.site, and layerv.xyz all point `rua` at dmarc@layerv.ai,
# a different organizational domain than the policy domain. RFC-compliant
# receivers will only send aggregate reports cross-domain if the rua domain
# publishes a `<reported-domain>._report._dmarc` authorization record. These
# live in the layerv.ai zone (`var.hosted_zone_id`). Without them, aggregate
# reports are silently dropped and the `rua` provides no visibility.
#
# Each record's `name` is built from the SAME domain var as that domain's own
# DMARC record (so the auth name can't desync from the policy record), and each
# qurl auth record is gated on the SAME zone var as that domain's DMARC (so we
# never publish an orphan auth record for a domain whose DMARC we aren't
# managing). The layerv.xyz auth record has no such pairing here because
# layerv.xyz's DMARC is managed in the sandbox state, not this one.
# ---------------------------------------------------------------------------

resource "aws_route53_record" "dmarc_report_auth_qurl_link" {
  count    = local.dns_hygiene_mgmt_enabled && var.hosted_zone_id != null && var.qurl_link_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.hosted_zone_id # layerv.ai zone (where the auth record lives)
  name    = "${var.qurl_link_domain}._report._dmarc.${var.hosted_zone}"
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = ["v=DMARC1"]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "dmarc_report_auth_qurl_site" {
  count    = local.dns_hygiene_mgmt_enabled && var.hosted_zone_id != null && var.qurl_site_hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.hosted_zone_id # layerv.ai zone (where the auth record lives)
  name    = "${var.qurl_site_domain}._report._dmarc.${var.hosted_zone}"
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = ["v=DMARC1"]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "dmarc_report_auth_layerv_xyz" {
  count    = local.dns_hygiene_mgmt_enabled && var.hosted_zone_id != null ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = var.hosted_zone_id # layerv.ai zone (where the auth record lives)
  name    = "layerv.xyz._report._dmarc.${var.hosted_zone}"
  type    = "TXT"
  ttl     = local.dns_hygiene_ttl
  records = ["v=DMARC1"]

  lifecycle {
    prevent_destroy = true
  }
}
