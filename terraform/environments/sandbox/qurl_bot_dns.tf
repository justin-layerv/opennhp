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
  slack_bot_domain   = "slackbot.layerv.xyz"

  # ALB DNSName for `discord_bot_alias` below. Centralized in a local
  # so the `lifecycle.precondition` can reference it — `self` isn't
  # valid in precondition blocks (only postcondition + check). Matches
  # the `discord_bot_validation_name` / `discord_bot_validation_target`
  # pattern in the prod sibling. Looked up post-PR-A apply via
  # `aws elbv2 describe-load-balancers` or `terraform output -raw
  # alb_dns_name` against qurl-integrations-infra#421's workspace.
  # Re-homed onto the dedicated discord VPC (vpc-03a677ef13dfb3153, 10.4/16) in
  # qurl-integrations-infra#927 (issue #394). The cross-VPC ALB move forced a
  # destroy+recreate, so the ALB got a new DNSName (the old
  # ...-2094914143... name is dead). CanonicalHostedZoneId stays the us-east-2
  # ELB constant Z3AADJGX6KTTL2 (the alias `zone_id` below), so only this line
  # changes on a re-home.
  #
  # 2026-06-15 topology cutover: sandbox discord now serves from the v2 ALB
  # (`qurl-bot-discord-sandbox-v2`, fronting the `http-v2` ECS service in the
  # dedicated discord VPC) — matching prod's v2 topology. The old greenfield
  # ALB (...-1482978767...) is decommissioned in a follow-up qurl-bot-discord
  # teardown PR; this alias must point at v2 FIRST so the greenfield delete
  # cannot dangle discord.layerv.xyz. Same us-east-2 ELB zone_id, so (as
  # designed) only this one line changes.
  discord_bot_alb_dns_name = "qurl-bot-discord-sandbox-v2-1393387203.us-east-2.elb.amazonaws.com"
}

# Env-root bot DNS records are same-account Route53 writers that consume the
# Terraform CI role narrowed inside module.nhp. Wait for the scoped inline
# grants before changing these records on the cutover apply.
resource "time_sleep" "route53_record_change_iam_propagation" {
  count = length(module.nhp.route53_record_change_iam_propagation_triggers) > 0 ? 1 : 0

  triggers = module.nhp.route53_record_change_iam_propagation_triggers

  create_duration = module.nhp.route53_record_change_iam_propagation_duration
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
  # `terraform/modules/ac/main.tf` — idempotent against console
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

  depends_on = [time_sleep.route53_record_change_iam_propagation]

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

# Validates ACM cert in qurl-integrations sandbox account
# (730883236711, us-east-2):
#   arn:aws:acm:us-east-2:730883236711:certificate/f6e26ea7-aea9-4d02-b06b-feb7679ff064
# Same posture as the discord record above — hardcoded validation
# tokens (cross-account ACM, no provider alias), `prevent_destroy`
# guard, idempotent against console pre-staging.
resource "aws_route53_record" "slack_bot_cert_validation" {
  allow_overwrite = true

  zone_id = var.qurl_hosted_zone_id
  name    = "_fdbfa14f3d659c2d1586d6f833d90bfc.${local.slack_bot_domain}"
  type    = "CNAME"
  ttl     = 60
  records = ["_be6d56f1f7df4a79161075db80592027.jkddzztszm.acm-validations.aws."]

  depends_on = [time_sleep.route53_record_change_iam_propagation]

  lifecycle {
    prevent_destroy = true
  }
}

# Public alias for the slack bot — points slackbot.layerv.xyz at the
# `qurl-bot-slack-sandbox` ALB in the qurl-integrations sandbox
# account (730883236711, us-east-2). Cross-account, no provider alias
# wired up, so the ALB DNSName + the ELB hosted-zone ID are hardcoded
# (same posture as the cert validation records above).
#
# `Z3AADJGX6KTTL2` is the AWS-published hosted-zone ID for ALBs in
# us-east-2 — constant across all ALBs in that region per
# https://docs.aws.amazon.com/general/latest/gr/elb.html. ALB DNSName
# is auto-generated and stable for the life of the ALB resource; if
# the ALB is ever recreated in qurl-integrations-infra, the DNSName
# rotates and this value needs to be updated. Verifiable via:
#   AWS_PROFILE=layerv-integrations aws elbv2 describe-load-balancers \
#     --names qurl-bot-slack-sandbox --region us-east-2
#
# `allow_overwrite = true` is load-bearing: a stale A record
# (3.138.131.15) from the deleted Python-era slack stack still
# resolves under this name. Without this, the first apply errors
# with a name-collision; with it, TF claims and replaces the
# existing record cleanly.
#
# No `prevent_destroy` (unlike the cert validation records above):
# the alias is the consumer-facing endpoint and a deliberate
# `terraform destroy` of this stack should be allowed to remove it
# alongside the ALB it points at, not require a state-rm escape.
resource "aws_route53_record" "slack_bot_alias" {
  allow_overwrite = true

  zone_id = var.qurl_hosted_zone_id
  name    = local.slack_bot_domain
  type    = "A"

  alias {
    name                   = "qurl-bot-slack-sandbox-64404749.us-east-2.elb.amazonaws.com"
    zone_id                = "Z3AADJGX6KTTL2"
    evaluate_target_health = false
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

# Public alias for the discord bot — points discord.layerv.xyz at the
# `qurl-bot-discord-sandbox-v2` ALB in the qurl-integrations sandbox
# account (730883236711, us-east-2). Same posture as the slack alias
# above: cross-account, no provider alias, ALB DNSName + ELB hosted-
# zone ID hardcoded.
#
# `Z3AADJGX6KTTL2` is AWS's published ALB hosted-zone ID for us-east-2
# (constant per https://docs.aws.amazon.com/general/latest/gr/elb.html).
#
# ALB DNSName lookup post-PR-A apply (qurl-integrations-infra#421):
#   AWS_PROFILE=layerv-integrations aws elbv2 describe-load-balancers \
#     --names qurl-bot-discord-sandbox-v2 --region us-east-2 \
#     --query 'LoadBalancers[0].DNSName' --output text
# OR from the qurl-integrations-infra workspace:
#   `terraform output -raw alb_dns_name`  (PR A added this output)
#
# `allow_overwrite` is OMITTED here (unlike the slack alias above):
# discord.layerv.xyz is a fresh record with no known stale predecessor,
# so a name collision at first apply should fail loudly rather than
# silently overwrite a record we don't know about.
resource "aws_route53_record" "discord_bot_alias" {
  zone_id = var.qurl_hosted_zone_id
  name    = local.discord_bot_domain
  type    = "A"

  alias {
    name                   = local.discord_bot_alb_dns_name
    zone_id                = "Z3AADJGX6KTTL2"
    evaluate_target_health = false
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]

  lifecycle {
    precondition {
      condition = (
        !strcontains(local.discord_bot_alb_dns_name, "PLACEHOLDER") &&
        endswith(local.discord_bot_alb_dns_name, ".us-east-2.elb.amazonaws.com")
      )
      error_message = "local.discord_bot_alb_dns_name must be a real us-east-2 ALB DNSName (currently looks unreplaced or wrong-region). Get it via `aws elbv2 describe-load-balancers --names qurl-bot-discord-sandbox --region us-east-2 --query 'LoadBalancers[0].DNSName' --output text` (or `terraform output -raw alb_dns_name` against the qurl-integrations-infra sandbox workspace)."
    }
  }
}
