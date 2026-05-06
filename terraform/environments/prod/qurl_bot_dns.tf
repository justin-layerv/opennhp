# DNS records for the qurl-integrations bot stack (prod).
#
# Naming convention (per Justin 2026-04-29):
#   <bot-platform>.layerv.xyz  → sandbox
#   <bot-platform>.layerv.ai   → prod
#
# `layerv.ai` is hosted in the layerv-mgmt account, so cross-account
# writes use the `aws.route53_mgmt` provider alias. `prevent_destroy`
# guards the validation record because ACM reuses it on every ~13-month
# renewal — deleting it stops renewal silently and the failure only
# surfaces a year later.

locals {
  discord_bot_domain            = "discord.layerv.ai"
  discord_bot_cert_arn          = "arn:aws:acm:us-east-2:886375649402:certificate/b4636b76-af85-4d22-857b-ad113e1672e4"
  discord_bot_validation_name   = "_d64daa5a8b7d342e73e5af0dac720c18.${local.discord_bot_domain}"
  discord_bot_validation_target = "_70a62389d409b0fdd83220d80e655c45.jkddzztszm.acm-validations.aws."

  # ALB DNSName for `discord_bot_alias` below. Centralized in a local
  # so the `lifecycle.precondition` can reference it — `self` isn't
  # valid in precondition blocks. Same pattern as the validation
  # locals above. Looked up post-PR-A apply via
  # `aws elbv2 describe-load-balancers` or `terraform output -raw
  # alb_dns_name` against qurl-integrations-infra#421's prod workspace.
  discord_bot_alb_dns_name = "qurl-bot-discord-production-PLACEHOLDER.us-east-2.elb.amazonaws.com"
}

# Cert lives in qurl-integrations prod (886375649402, us-east-2);
# ARN pinned in `local.discord_bot_cert_arn` above. `allow_overwrite`
# matches the `aws_route53_record.cloudfront_cert_validation` posture
# in `terraform/modules/ac/main.tf` (idempotent against the ACM
# console "Add record in Route 53" pre-staging button).
resource "aws_route53_record" "discord_bot_cert_validation" {
  provider = aws.route53_mgmt

  allow_overwrite = true
  zone_id         = var.qurl_hosted_zone_id
  name            = local.discord_bot_validation_name
  type            = "CNAME"
  ttl             = 60
  records         = [local.discord_bot_validation_target]

  # Cert re-issuance escape hatch (token rotates → name change → replace,
  # blocked by prevent_destroy): `terraform state rm
  # aws_route53_record.discord_bot_cert_validation`, edit the validation
  # locals above, plan+apply.
  lifecycle {
    prevent_destroy = true

    # Plan-time guard: original PR shipped with PLACEHOLDER literals
    # that went un-filled and silently created a bogus CNAME, leaving
    # the cert PENDING_VALIDATION and surfacing later as an opaque
    # UnsupportedCertificate error during ALB listener creation.
    precondition {
      condition = (
        !strcontains(local.discord_bot_validation_name, "PLACEHOLDER") &&
        !strcontains(local.discord_bot_validation_target, "PLACEHOLDER")
      )
      error_message = "Discord bot cert validation literals still contain PLACEHOLDER — fill from `aws acm describe-certificate --certificate-arn ${local.discord_bot_cert_arn} --region us-east-2` (DomainValidationOptions[].ResourceRecord.{Name,Value}) before applying."
    }
  }
}

# Public alias for the discord bot — points discord.layerv.ai at the
# `qurl-bot-discord-production` ALB in the qurl-integrations prod
# account (886375649402, us-east-2). Cross-account write to the
# layerv-mgmt-hosted layerv.ai zone via the `aws.route53_mgmt`
# provider alias (same posture as the cert validation above).
#
# `Z3AADJGX6KTTL2` is AWS's published ALB hosted-zone ID for us-east-2
# (constant per https://docs.aws.amazon.com/general/latest/gr/elb.html).
#
# ALB DNSName lookup post-PR-A apply (qurl-integrations-infra#421):
#   AWS_PROFILE=layerv-integrations-prod aws elbv2 describe-load-balancers \
#     --names qurl-bot-discord-production --region us-east-2 \
#     --query 'LoadBalancers[0].DNSName' --output text
# OR from the qurl-integrations-infra workspace:
#   `terraform output -raw alb_dns_name`  (PR A added this output)
#
# `prevent_destroy` OFF: alias is consumer-facing and follows the ALB
# lifecycle. `allow_overwrite` OFF: discord.layerv.ai is a fresh
# record — a name collision at first apply should fail loudly rather
# than silently overwrite something we don't know about. The cert
# validation above keeps prevent_destroy because ACM reuses it on
# the ~13-month renewal — different lifecycle, different guard.
resource "aws_route53_record" "discord_bot_alias" {
  provider = aws.route53_mgmt

  zone_id = var.qurl_hosted_zone_id
  name    = local.discord_bot_domain
  type    = "A"

  alias {
    name                   = local.discord_bot_alb_dns_name
    zone_id                = "Z3AADJGX6KTTL2"
    evaluate_target_health = false
  }

  lifecycle {
    precondition {
      condition = (
        !strcontains(local.discord_bot_alb_dns_name, "PLACEHOLDER") &&
        endswith(local.discord_bot_alb_dns_name, ".us-east-2.elb.amazonaws.com")
      )
      error_message = "local.discord_bot_alb_dns_name must be a real us-east-2 ALB DNSName (currently looks unreplaced or wrong-region). Get it via `aws elbv2 describe-load-balancers --names qurl-bot-discord-production --region us-east-2 --query 'LoadBalancers[0].DNSName' --output text` (or `terraform output -raw alb_dns_name` against the qurl-integrations-infra prod workspace)."
    }
  }
}
