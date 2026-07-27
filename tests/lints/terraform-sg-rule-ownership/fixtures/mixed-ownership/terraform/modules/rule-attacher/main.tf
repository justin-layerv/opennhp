# Class B (continued) — the legacy `aws_security_group_rule` form carrying
# its direction in `type`, attaching cross-module. Byte-for-byte the shape
# of qurl-service's ecs_to_redis rule that #3281 found under threat.
resource "aws_security_group_rule" "bad_cross_module_attach" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = "sg-bad-source"
  security_group_id        = var.target_security_group_id
  description              = "bad-cross-module-redis: Redis from ECS tasks"
}
