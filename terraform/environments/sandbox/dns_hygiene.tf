# DNS hygiene records for layerv.xyz, which is hosted in the sandbox account
# (same account as this apply target), so these are same-account Route53 writes
# via the default `aws` provider and the zone-id-scoped CI grant — matching the
# bot DNS records in `qurl_bot_dns.tf`. `var.qurl_hosted_zone_id` is the
# de-facto layerv.xyz parent-zone variable in this env. The layerv.ai /
# qurl.site / qurl.link apexes are cross-account and handled by the prod
# sibling `terraform/environments/prod/dns_hygiene.tf`. Closes the
# Terraform-addressable layerv.xyz items of nhp#1149.
#
# CAA issuer set derived from layerv.xyz's live crt.sh history: AWS ACM,
# Let's Encrypt, AND GoDaddy (layerv.xyz has an active GoDaddy cert). The issuer
# building blocks come from the shared `modules/dns-hygiene-constants` (single
# source of truth across this and the prod root module). `issuewild` is omitted
# so the `issue` set governs wildcards too.
#
# Every record carries `lifecycle { prevent_destroy = true }` (matching the
# durable-record posture of `qurl_bot_dns.tf`): combined with the `count` gate,
# an apply where the zone var resolves to null fails LOUD instead of silently
# destroying the apex CAA/SPF/DMARC set and reverting this hardening. To retire
# a record — or apply a force-new change — delete the block, apply, then re-add.
#
# ⚠️ DELIVERABILITY — layerv.xyz is a LIVE sending domain. This hardens it to
# SPF `-all` (hardfail) + DMARC `p=reject` per the chosen "full hardening now"
# scope. Any legitimate sender NOT covered by the two SPF includes below would
# be rejected. The domain owner CONFIRMED (PR #2349) that spf.improvmx.com +
# amazonses.com are the only senders, so the hardfail is safe. Still watch the
# post-rollout DMARC aggregate reports for a `fail` from any forgotten sender;
# if one surfaces, add its `include:`/`ip4:` here (do NOT silently revert to
# `~all`, which would re-open the spoofing gap this closes).

# Shared CAA issuer building blocks + TTL — single source of truth across the
# prod and sandbox root modules. See modules/dns-hygiene-constants.
module "dns_hygiene" {
  source = "../../modules/dns-hygiene-constants"
}

locals {
  dns_hygiene_ttl = module.dns_hygiene.ttl

  caa_layerv_xyz = concat(module.dns_hygiene.caa_acm, module.dns_hygiene.caa_letsencrypt, module.dns_hygiene.caa_godaddy, module.dns_hygiene.caa_iodef)

  dns_hygiene_layerv_xyz_enabled = var.qurl_hosted_zone_id != null
}

resource "aws_route53_record" "caa_layerv_xyz" {
  count = local.dns_hygiene_layerv_xyz_enabled ? 1 : 0

  # allow_overwrite OFF: no CAA exists on layerv.xyz today, so this is a genuine
  # create — fail loud on a collision rather than clobber an out-of-band record.
  zone_id = var.qurl_hosted_zone_id # layerv.xyz zone (same account)
  name    = var.hosted_zone         # "layerv.xyz"
  type    = "CAA"
  ttl     = local.dns_hygiene_ttl
  records = local.caa_layerv_xyz

  depends_on = [time_sleep.route53_record_change_iam_propagation]

  lifecycle {
    prevent_destroy = true
  }
}

# SPF: keep the existing improvmx + Amazon SES includes, harden ~all → -all.
# `allow_overwrite = true` is REQUIRED here — the live record already exists and
# is unmanaged. A Route53 TXT name holds a SINGLE record set, so this overwrites
# the WHOLE apex TXT set. Verified at PR time that the layerv.xyz apex TXT holds
# ONLY this SPF string (no google-site-verification / MS= / SaaS tokens), so the
# overwrite drops nothing. RE-VERIFY immediately before apply (`dig +short TXT
# layerv.xyz`): if a non-SPF token has since been added to the apex, add it to
# the `records` list below or it will be deleted. See the header warning.
resource "aws_route53_record" "spf_layerv_xyz" {
  count = local.dns_hygiene_layerv_xyz_enabled ? 1 : 0

  allow_overwrite = true
  zone_id         = var.qurl_hosted_zone_id
  name            = var.hosted_zone
  type            = "TXT"
  ttl             = local.dns_hygiene_ttl
  records         = ["v=spf1 include:spf.improvmx.com include:amazonses.com -all"]

  depends_on = [time_sleep.route53_record_change_iam_propagation]

  lifecycle {
    prevent_destroy = true
  }
}

# DMARC: p=none → p=reject, add rua for visibility. `allow_overwrite` upserts
# the existing (unmanaged) live record. The cross-domain rua to dmarc@layerv.ai
# is authorized by `layerv.xyz._report._dmarc.layerv.ai` in the prod sibling
# file (RFC 7489 §7.1) — that auth record must land in prod before/with this
# sandbox apply or layerv.xyz aggregate reports are dropped until it does (see
# the rollout ledger's apply-ordering note). Cross-env coupling to close the
# loop: that prod record hardcodes the literal `layerv.xyz` (no shared var
# spans the two root modules), so if this domain ever changes, update
# `dmarc_report_auth_layerv_xyz` in `../prod/dns_hygiene.tf` in the same change.
# `sp=reject` is stated explicitly to match the qurl DMARC records; it is
# functionally identical to the inherited default (RFC 7489: an absent `sp`
# applies the `p` value to subdomains), so this is not a policy change for
# layerv.xyz subdomains — just a consistent, self-documenting record shape.
resource "aws_route53_record" "dmarc_layerv_xyz" {
  count = local.dns_hygiene_layerv_xyz_enabled ? 1 : 0

  allow_overwrite = true
  zone_id         = var.qurl_hosted_zone_id
  name            = "_dmarc.${var.hosted_zone}"
  type            = "TXT"
  ttl             = local.dns_hygiene_ttl
  records         = ["v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@layerv.ai; pct=100"]

  depends_on = [time_sleep.route53_record_change_iam_propagation]

  lifecycle {
    prevent_destroy = true
  }
}
