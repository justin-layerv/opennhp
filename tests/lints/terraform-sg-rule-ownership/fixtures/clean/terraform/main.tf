# Clean fixture for check-terraform-sg-rule-ownership.py. Exercises every
# shape that is legitimate, including the two that a naive implementation
# would false-positive on. Expected exit: 0.
#
#   1. SG with no inline ingress/egress + standalone rules — the preferred
#      shape, and what terraform/modules/redis-cluster uses after #3281.
#   2. Inline `egress = []` frozen by `lifecycle.ignore_changes` + standalone
#      egress rules — the escape hatch (bootstrap-alb / relay / relay-network).
#   3. Inline `ingress` block alongside standalone *egress* rules only.
#      Direction matters: `ingress` and `egress` are separate
#      Optional+Computed attributes, so these do not fight. This is the
#      udp-proof-runner shape and must NOT be flagged.
#   4. `count`-indexed SG references (`aws_security_group.x[0].id`).
#   5. A cross-module rule whose target SG declares no inline rules.

variable "deploy_owner" {
  type    = bool
  default = true
}

module "sg_owner" {
  count  = var.deploy_owner ? 1 : 0
  source = "./modules/sg-owner"
}

module "rule_attacher" {
  source = "./modules/rule-attacher"

  # The cross-module handoff the resolver has to follow: a module output
  # carrying an SG id, passed into a sibling module's variable.
  target_security_group_id = var.deploy_owner ? module.sg_owner[0].security_group_id : null
}
