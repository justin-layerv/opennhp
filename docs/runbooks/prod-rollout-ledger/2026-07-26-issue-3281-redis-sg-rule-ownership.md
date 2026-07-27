# 2026-07-26 · Issue #3281 · Redis security-group rule ownership transition

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/3281

Moves the Redis SG's VPC-CIDR ingress rule from an inline `ingress` block to a
standalone `aws_vpc_security_group_ingress_rule`, adopting the existing live
rule by id. The inline block was authoritative for the whole ingress set and
was already planning to revoke qurl-service's `ecs_to_redis` rule on the next
prod apply. The apply must run **with the import block present** — without it
Terraform tries to create a rule that already exists and fails on
`InvalidPermission.Duplicate`.

- [ ] Pre-rollout: apply in sandbox first and confirm the plan shows
      `1 to import` with the rule's only diff being tags — no replace, no
      revoke. Sandbox rule id `sgr-03b8a8d79b4f26e4a` on
      `sg-01d7ce6e1bfe610f2`.
- [ ] Rollout: apply prod. Expected Redis delta is exactly one adopt-in-place:
      `module.nhp.module.redis[0].aws_vpc_security_group_ingress_rule.redis_from_vpc`
      imported from `sgr-0af3589efb2c72289`, tags added.
      `module.nhp.module.redis[0].aws_security_group.redis` must NOT appear.
- [ ] Rollout: gate the saved plan with
      `python3 .github/scripts/check-sg-rule-ownership-plan.py <plan.json>`
      before approving. It fails the pre-fix plan and passes this one.
- [ ] Post-rollout: confirm both rules still exist on `sg-0bc1f0708c545afb4` —
      `sgr-0af3589efb2c72289` (VPC CIDR) and `sgr-0a61816b5b3038911`
      (from the qurl-api ECS SG). Neither may disappear.
- [ ] Post-rollout: re-run `terraform plan` and confirm zero drift for the
      Redis security group and both rule resources.
- [ ] Post-rollout: delete the two `import` blocks
      (`terraform/environments/{prod,sandbox}/imports.tf`) once both applies
      have landed, then delete this ledger entry.
- [ ] Rollback: revert the PR. The rule resources return to inline ownership
      and the pre-existing revocation risk returns with them — so rollback is
      only appropriate if the apply itself misbehaves, and the live rules must
      be re-verified afterwards. Reverting does **not** remove either live AWS
      rule by itself.
