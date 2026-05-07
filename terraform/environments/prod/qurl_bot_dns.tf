# DNS records for the qurl-integrations bot stack (prod).
#
# Naming convention:
#   <bot-platform>.layerv.xyz             → sandbox
#   <bot-platform>.connector.layerv.ai    → prod (was `<bot-platform>.layerv.ai`
#                                                  until 2026-05-07 — Railway
#                                                  hosting claim on the bare
#                                                  `discord.layerv.ai` forced
#                                                  the migration to
#                                                  `discord.connector.layerv.ai`)
#
# `layerv.ai` is hosted in the layerv-mgmt account, so cross-account
# writes use the `aws.route53_mgmt` provider alias. `prevent_destroy`
# guards the validation record because ACM reuses it on every ~13-month
# renewal — deleting it stops renewal silently and the failure only
# surfaces a year later.
#
# Pairs with qurl-integrations-infra#440 (cert.tf prod domain switch).
# Apply order:
#   1. Merge this PR + dispatch promote-to-prod (run_terraform=true).
#      The `moved {}` + `removed {}` blocks below rename the old state
#      entry and drop it from state without destroying the AWS record
#      (`lifecycle.destroy = false` on the removed block). The new
#      `discord_bot_cert_validation` resource creates the new
#      validation CNAME at the new name.
#   2. ACM flips new cert to ISSUED within ~5-30 min once the new
#      CNAME resolves. 72-hour ceiling on the validation window —
#      see qurl-integrations-infra cert.tf header.
#   3. After cert ISSUED, manually delete the orphaned old CNAME at
#      `_d64daa5a8b7d342e73e5af0dac720c18.discord.layerv.ai` from the
#      Route53 console (points at a deleted ACM cert; harmless).

locals {
  discord_bot_domain = "discord.connector.layerv.ai"

  # Filled via qurl-integrations-infra one-shot workflow #442 (run
  # 25478306535). ACM cert created during #440's partial apply, sits
  # in PENDING_VALIDATION until the CNAME below resolves.
  discord_bot_cert_arn = "arn:aws:acm:us-east-2:886375649402:certificate/2a48e435-2a6b-4213-a113-d766f1674361"

  # ACM validation CNAME for `discord.connector.layerv.ai`. `name` is
  # the full hostname (ACM emits with the domain suffix); `target` is
  # an AWS-internal validation host.
  discord_bot_validation_name   = "_077a5990091edcb1f8670545f07f1e5f.${local.discord_bot_domain}"
  discord_bot_validation_target = "_4c20066b507b26f3fdf272e679d69a36.jkddzztszm.acm-validations.aws."

  # ALB DNSName for `discord_bot_alias` below. Centralized so the
  # `lifecycle.precondition` can reference it (`self` isn't valid in
  # precondition blocks). Unchanged across the domain migration.
  discord_bot_alb_dns_name = "qurl-bot-discord-production-1278895084.us-east-2.elb.amazonaws.com"
}

# State-only drop of the pre-migration validation record. `moved` →
# `removed { destroy = false }` (vs. single `removed`) frees the
# original address for the new resource declared below. Old DNS CNAME
# stays in Route53 (cert it validated is gone — harmless); console-
# delete after new cert ISSUED.
moved {
  from = aws_route53_record.discord_bot_cert_validation
  to   = aws_route53_record.discord_bot_cert_validation_legacy
}

removed {
  from = aws_route53_record.discord_bot_cert_validation_legacy

  lifecycle {
    destroy = false
  }
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

  # Cert re-issuance escape hatch (token rotates → name change →
  # replace, blocked by prevent_destroy): use the same `moved {}` +
  # `removed { lifecycle { destroy = false } }` pattern as the header
  # docblock above. Laptop `terraform state rm` is the fallback only
  # when the operator can't ship a PR (e.g., emergency rollback).
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

# Public alias for the discord bot — points discord.connector.layerv.ai
# at the `qurl-bot-discord-production` ALB in the qurl-integrations
# prod account (886375649402, us-east-2). Cross-account write to the
# layerv-mgmt-hosted layerv.ai zone via `aws.route53_mgmt`.
#
# `Z3AADJGX6KTTL2` is AWS's published ALB hosted-zone ID for us-east-2
# (constant per https://docs.aws.amazon.com/general/latest/gr/elb.html).
# ALB DNSName lookup: qurl-integrations-infra one-shot workflow
# `read-cert-validation-tokens.yml` (added in qurl-integrations-infra
# #442); also surfaced as `terraform output -raw alb_dns_name` against
# that workspace.
#
# `prevent_destroy` OFF: alias is consumer-facing and follows the ALB
# lifecycle. `allow_overwrite` OFF: discord.connector.layerv.ai is a
# fresh record — a name collision at first apply should fail loudly
# rather than silently overwrite something we don't know about. The
# cert validation above keeps prevent_destroy because ACM reuses it
# on the ~13-month renewal — different lifecycle, different guard.
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
