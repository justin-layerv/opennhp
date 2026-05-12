# ALB SG: internet-facing on 443 (TLS termination here). Port 80 is NOT
# opened — bootstrap clients are reverse-tunnel-client sidecars, NOT
# browsers; there's no HTTP-to-HTTPS redirect upgrade path to support,
# and a customer sidecar that misconfigures itself for plaintext should
# fail-loud at apply time rather than silently get a 301 → HTTPS that
# masks the misconfiguration.
#
# Egress is scoped to the VPC CIDR on the configured target port; the
# actual access control between this ALB and qurl-service ENIs lands
# on the qurl-service task SG's ingress side (which references THIS
# module's `alb_security_group_id` output).
#
# Why VPC-CIDR egress here instead of referencing the qurl-service
# task SG directly: the task SG IS intra-repo (in
# `terraform/modules/qurl-service/`), so a direct ref like
# `module.qurl_service.task_security_group_id` is technically
# feasible. The real reasons not to:
#
#   1. **Inter-module ordering coupling on first-apply / destroy.**
#      A direct SG-ID ref would tie this module's create/destroy
#      ordering to qurl-service's. Destroying qurl-service before
#      bootstrap-alb (or vice versa during a partial-rollback) would
#      surface as a dependency error instead of a clean teardown.
#      VPC-CIDR egress is order-independent — qurl-service can be
#      torn down/recreated without touching this stack's SG.
#   2. **The actual access control lives on the qurl-service task SG
#      side.** The qurl-service task SG's ingress rule references
#      THIS module's `alb_security_group_id` by ID — that's the
#      load-bearing fence. The ALB-side egress only has to be wide
#      enough to reach the target; widening to VPC CIDR doesn't
#      weaken security because nothing else in the VPC accepts
#      bootstrap traffic on this port.
#
# The symmetrical ingress on the qurl-service task SG side lands in
# the paired follow-up PR `feat/bootstrap-alb-attach-qurl-service`,
# gated on the same `deploy_bootstrap_alb` variable.
#
# `ingress = [] / egress = []` strips AWS's auto-created `0.0.0.0/0`
# egress rule on FIRST APPLY. WITHOUT `ignore_changes`, every subsequent
# apply refreshes the SG, sees the standalone rules in AWS, computes
# drift against the empty inline declaration, and REVOKES them as part
# of the SG modify — a hidden first-apply-vs-refresh trap that produces
# a self-healing-on-first-apply / self-breaking-on-refresh oscillation.
resource "aws_security_group" "alb" {
  name        = "${local.alb_name}-alb"
  description = "Bootstrap ALB ingress 443 from internet; egress to qurl-service VPC on target port"
  vpc_id      = var.vpc_id

  ingress = []
  egress  = []

  tags = merge(local.tags, { Name = "${local.alb_name}-alb" })

  # No `create_before_destroy`: deterministic name + CBD would fail
  # any future replacement on `InvalidGroup.Duplicate`.
  lifecycle {
    ignore_changes = [ingress, egress]
  }
}

# Ingress: HTTPS-only on 443. No port-80 companion — see header comment.
#
# IPv4-only today (matches `aws_lb.this::ip_address_type = "ipv4"`).
# IPv6 ingress lands paired with the networking module's IPv6
# CIDR assignment + the ALB's `dualstack` flip — tracked at #1901
# (dualstack without IPv6-assigned subnets fails apply with
# `InvalidSubnet`). AWS `aws_vpc_security_group_ingress_rule`
# requires exactly one of `cidr_ipv4` or `cidr_ipv6` per rule, so
# the v6 follow-up will land as a sibling rule rather than a wider
# CIDR on this one.
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from internet (sidecar bootstrap calls)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = merge(local.tags, { Name = "${local.alb_name}-ingress-https" })
}

# Egress: ALB → qurl-service ENIs on the target port. Scoped to the
# VPC CIDR (the qurl-service task ENIs live in the same VPC's private
# subnets). The nhp-side task SG adds the symmetrical ingress rule.
#
# `cidr_ipv4 = vpc_cidr` rather than referencing the target SG: the
# target SG ID lives in nhp's tfstate, and reading it here would create
# a brittle cross-stack dependency that breaks if nhp is destroyed or
# re-applied without coordination. The CIDR-scoped egress is wider than
# strictly needed (any IP in the VPC, not just qurl-service ENIs) but
# the actual access control is ENFORCED by the qurl-service task SG's
# ingress rule (which DOES reference this stack's ALB SG by ID — that
# direction of cross-stack ref is stable: this stack publishes
# `alb_security_group_id` and the consumer is the side that must
# react).
resource "aws_vpc_security_group_egress_rule" "alb_to_target" {
  security_group_id = aws_security_group.alb.id
  description       = "Forward to qurl-service ENIs on target port (VPC CIDR scoped; access control via target SG ingress)"
  cidr_ipv4         = var.vpc_cidr_block
  from_port         = var.target_port
  to_port           = var.target_port
  ip_protocol       = "tcp"

  tags = merge(local.tags, { Name = "${local.alb_name}-egress-target" })
}
