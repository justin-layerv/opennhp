# Import blocks for pre-existing resources that Terraform needs to adopt.
# These are safe to leave in place — Terraform treats them as no-ops after
# the first successful import.

# #3281 — Redis security-group rule ownership transition.
#
# The VPC-CIDR ingress rule on the prod Redis SG was created by an inline
# `ingress` block on `aws_security_group.redis`, so it had no independently
# addressable Terraform owner. Because `ingress` is Optional+Computed, that
# inline block made the SG authoritative for the whole ingress set and it
# was actively planning to revoke qurl-service's `ecs_to_redis` rule
# (sgr-0a61816b5b3038911) on the next prod apply.
#
# terraform/modules/redis-cluster/main.tf now expresses that rule as a
# standalone `aws_vpc_security_group_ingress_rule`. Adopting the live rule
# id here is what makes the transition non-disruptive: without the import,
# Terraform would try to CREATE a rule that already exists and the apply
# would fail on InvalidPermission.Duplicate — and any "fix" that revoked
# first would open a reachability gap on a security group serving live
# traffic.
#
# Rule tuple frozen at import time (us-east-2, account 235500187906):
#   sg-0bc1f0708c545afb4  ingress  tcp  6379-6379  cidr 10.200.0.0/16
#   "Redis from VPC (ElastiCache Serverless, TLS enforced)"
#
# `deploy_redis = true` in terraform.tfvars is what makes `module.redis[0]`
# exist. If Redis is ever decommissioned in prod, delete this block in the
# same change that flips the flag.
import {
  to = module.nhp.module.redis[0].aws_vpc_security_group_ingress_rule.redis_from_vpc
  id = "sgr-0af3589efb2c72289"
}
