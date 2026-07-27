# Violating fixture root. Wires the cross-module handoff for class B so the
# resolver has the same chain to walk that #3281 had in production:
#   rule (rule-attacher) -> var -> module output -> aws_security_group.
# Expected exit: 1.

module "sg_owner" {
  source = "./modules/sg-owner"
}

module "rule_attacher" {
  source = "./modules/rule-attacher"

  target_security_group_id = module.sg_owner.security_group_id
}
