# SSM Parameters for qurl-reverse-tunnel-server
# Only parameters that an out-of-band actor (CI/CD, ops) needs to discover
# or update at runtime live here. Static config (ports, subdomain host) is
# baked into user_data.sh.tpl at plan time via templatefile() — keeping
# duplicate copies in SSM risks them diverging from the rendered script.
#
# #1668 phase 1 — canonical paths only. The old /<env>/nhp/frps/* paths
# never received a real value in any deployed environment (sandbox-side
# `deploy_frps = true` was committed but the FRPS module had not applied
# before the rebrand landed; prod-side `deploy_frps` is still false), so
# there is no CI-published image-tag to preserve via the dual-existence
# pattern Justin originally outlined in #1668. We go straight to the
# canonical /<env>/nhp/reverse-tunnel-server/* path.
#
# Ownership split:
#
#   - image-tag — managed by rts CI (qurl-reverse-tunnel-server's
#     .github/workflows/docker-publish.yml uses `aws ssm put-parameter
#     --overwrite`, which creates-or-updates). Terraform deliberately
#     does NOT declare a resource for it: the AWS-side parameter at the
#     canonical path already exists in sandbox (rts CI's `--overwrite`
#     created it on a partial run, value =
#     ca73df76a532b93f10f17f0ee9743bed9da28376), so a TF resource block
#     would fail on initial `apply` with `ParameterAlreadyExists`. The
#     local `ssm_image_tag_param_name` below carries the path string for
#     wiring into user_data and module outputs.
#
#   - asg-name — managed by Terraform. rts CI reads it for instance
#     refresh; the value is the blue-side ASG name and is set at apply
#     time. No CI-side write, so no conflict.
#
# Greenfield-bootstrap caveat: the previous TF-owned `image_tag` resource
# seeded `var.image_tag = "v0.0.0-bootstrap"` on first apply, so a fresh
# env that pre-dated any rts CI run got a placeholder image-tag in SSM.
# user_data would read it, the ECR pull would fail loud (no such tag),
# and the operator got a clear "rts CI hasn't published yet" signal. With
# rts CI now solely owning the canonical image-tag, a fresh env where rts
# CI has not yet published lands user_data on `aws ssm get-parameter` →
# ParameterNotFound (also fail-loud, just a different error message). New
# envs must get an rts main push before the FRPS ASG can boot a healthy
# instance. The condition is detected at the user_data SSM read; see the
# FATAL message in user_data.sh.tpl.

locals {
  # Canonical SSM path for the rts image-tag. Owned by rts CI's
  # docker-publish workflow (see ownership note above). Surfaced as a
  # local so user_data wiring (main.tf::module.compute templatefile)
  # and the module's `ssm_image_tag_parameter` output (outputs.tf) can
  # both reference a single source-of-truth without re-typing the path
  # string and without indirecting through a `data.aws_ssm_parameter`
  # (which would force a runtime existence dependency at plan time).
  ssm_image_tag_param_name          = "/${var.environment}/nhp/reverse-tunnel-server/image-tag"
  ssm_min_client_version_param_name = "/${var.environment}/nhp/reverse-tunnel-server/min-client-version"
  min_client_version_disabled_value = "disabled"
  min_client_version_file_path      = "/opt/layerv/qurl-reverse-tunnel-server/etc/min-client-version"
}

resource "aws_ssm_parameter" "asg_name" {
  name        = "/${var.environment}/nhp/reverse-tunnel-server/asg-name"
  description = "qurl-reverse-tunnel-server Auto Scaling Group name - used by rts CI's docker-publish workflow for instance refresh after an image_tag update."
  type        = "String"
  value       = aws_autoscaling_group.frps.name

  # Tag conventions intentionally unchanged from the legacy resource — Name
  # prefix `frps-ssm-` and Component=frps mirror the six sibling SSM
  # resources in blue_green.tf. Any tag rebrand requires a coordinated
  # CloudWatch dashboard / log query audit (see the Component tag clause
  # in #1668's acceptance criteria) and lands as a separate PR.
  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-asg-name"
    Component = "frps"
  })
}

resource "aws_ssm_parameter" "min_client_version" {
  name        = local.ssm_min_client_version_param_name
  description = "Minimum qurl-connector version allowed by qurl-reverse-tunnel-server. Ops may update this value at runtime; set to \"${local.min_client_version_disabled_value}\" to disable the gate."
  type        = "String"
  value       = var.min_client_version == "" ? local.min_client_version_disabled_value : var.min_client_version

  # The parameter is a runtime kill switch. Terraform seeds the path, but
  # incident response may raise/lower it directly in SSM without waiting for
  # a Terraform apply; do not revert those operator changes on unrelated
  # infrastructure applies.
  lifecycle {
    ignore_changes = [value]
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-min-client-version"
    Component = "frps"
  })
}
