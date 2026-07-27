# Class 5 (continued) — a rule that reaches its target only through a module
# variable. Same shape as qurl-service's ecs_to_redis, but the target SG
# declares no inline rules, so this is legitimate.
resource "aws_security_group_rule" "clean_cross_module_attach" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = "sg-clean-source"
  security_group_id        = var.target_security_group_id
  description              = "clean-cross-module: Redis from tasks"
}
