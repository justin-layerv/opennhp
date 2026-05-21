# bootstrap-alb — Dedicated ALB + WAF for `bootstrap.layerv.{xyz,ai}`
#
# Stands up the public, narrow surface that reverse-tunnel-client
# sidecars call as their FIRST contact with LayerV:
# `POST /v1/agent/bootstrap`. First-contact for sidecars resolves the
# chicken-and-egg with knock — the sidecar needs LayerV's server-peer
# info before it can knock, so the registration call has to land on a
# surface that doesn't itself require an NHP credential. Posture:
# TLS-only, scoped WAF, per-API-key rate limit 10/hr enforced at the
# qurl-service layer, audit-row-on-every-call.
#
# **Distinct from `api.layerv.ai`** — keeping the surface narrow
# simplifies WAF rules and access-log triage. Only `/v1/agent/bootstrap`
# is forwarded to qurl-service; every other path returns 404 at the
# listener (no default forward to the upstream).
#
# This module produces the ALB + an empty target group. The qurl-
# service ECS service registers against `module.bootstrap_alb.target_group_arn`
# in a separate follow-up PR (paired with the qurl-service ECS task
# `load_balancer` block addition).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# Note: previously included `data "aws_elb_service_account"` to source
# the legacy AWS-account-principal for the log-bucket policy. That
# data source is deprecated upstream (emits a `terraform plan` warning
# on newer aws-provider releases) and the modern service principal
# (`logdelivery.elasticloadbalancing.amazonaws.com`) — already used by
# the second statement in `access_logs.tf` — is supported in every
# region this module currently targets (us-east-2 sandbox + prod).
# The legacy statement is dropped; if this module ever lands in a
# region where the modern service principal isn't supported (none
# exist today, but AWS occasionally launches partition-isolated
# regions with delayed feature support), re-add a region-gated
# legacy statement at that time.

locals {
  # Single source of truth for the project name. Surfaces as the ALB
  # name, target-group name, log-group name, WAF WebACL name, and the
  # `Project` tag.
  #
  # **Bucket-name coupling**: `access_logs.tf::alb_access_logs_bucket_name`
  # interpolates `${local.project}-alb-logs-...`, producing the
  # deliberate double `alb-` segment. Renaming `local.project` from
  # `bootstrap-alb` to anything else requires updating that bucket
  # naming pattern AND the future CI tag-scope allowlist (#1891) in
  # lockstep — the doubled segment becomes a literal IAM policy
  # match once #1891 lands.
  #
  # CI-role posture note: nhp's `aws_iam_role.github_actions` in
  # `terraform/modules/ecr/` is not currently tag-scoped on
  # `aws:RequestTag/Project` for ELB/ACM. Confirm the role's
  # `elasticloadbalancing:CreateLoadBalancer` and
  # `acm:RequestCertificate` grants accept this `Project` tag before
  # the first `deploy_bootstrap_alb=true` apply; if a future PR adds
  # tag-scoping to those grants, `bootstrap-alb` must be in the
  # allowlist.
  project = "bootstrap-alb"

  # ALB name caps at 32 chars: `bootstrap-alb-sandbox` = 21,
  # `bootstrap-alb-prod` = 18 — both fit with headroom.
  alb_name = "${local.project}-${var.environment}"

  # TG name caps at 32 chars: `bootstrap-alb-sandbox-tg` = 24,
  # `bootstrap-alb-prod-tg` = 21 — both fit.
  target_group_name = "${local.project}-${var.environment}-tg"

  # Base tag schema. `Project` / `Environment` ship here; per-resource
  # `Name` / `LongName` land via inline `merge(local.tags, { Name = ... })`.
  # If nhp's CI role ever adds tag-scoping (`aws:TagKeys` /
  # `aws:RequestTag`) for ELBCreate / ACMRequest — currently not gated
  # in `terraform/modules/ecr/` — adding a new key here must land in
  # the same PR that widens the allowlist, or every Create verb 403s
  # at apply.
  tags = {
    Project     = local.project
    Environment = var.environment
  }

  # `effective_certificate_arn`: provision_certificate=true → use the
  # in-stack ACM cert (after validation completes) so the listener
  # doesn't race apply against a still-pending cert.
  # provision_certificate=false → use the operator-supplied
  # existing_certificate_arn (cross-account prod, where the cert lives
  # outside this state).
  #
  # `one(<splat>)` rather than `[0]`: when `provision_certificate=false`,
  # the ternary's true-branch isn't evaluated, but the splat shape is
  # additionally safe against `[0]`-against-count-0 plan-time errors
  # that have surfaced from provider/core interaction bugs.
  effective_certificate_arn = var.provision_certificate ? one(aws_acm_certificate_validation.this[*].certificate_arn) : var.existing_certificate_arn
}
