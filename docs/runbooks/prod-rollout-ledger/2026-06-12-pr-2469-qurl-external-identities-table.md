# 2026-06-12 · PR #2469 · qurl external identities table

- **Owner:** prod rollout coordinator
- **Source:** [layervai/nhp PR #2469](https://github.com/layervai/nhp/pull/2469) · paired with [qurl-service #904](https://github.com/layervai/qurl-service/pull/904)

Creates the qurl-service #904 external identity binding table required before deploying qurl-service builds at or after `7791fcc`.

- [ ] Pre-rollout (sandbox): apply this PR's sandbox plan and confirm `layerv-nhp-sandbox-cell0-qurl-external-identities` exists with primary key `pk` and GSI `owner-index` on `owner_id` and `created_at`.
- [ ] Post-rollout (sandbox): re-run or observe the qurl-service sandbox deploy to image `7791fcc` or newer; ECS stays on the new task definition and `/health/ready` no longer reports schema drift for `qurl-external-identities`.
- [ ] Rollout (prod): apply this PR's prod plan before any prod qurl-service deployment at or after qurl-service #904; prod promote's `qurl-schema-check` also blocks until the table and `owner-index` GSI exist.
- [ ] Post-rollout (prod): confirm the prod qurl-service task role can `DescribeTable` on `*-qurl-external-identities` and qurl-service readiness remains healthy after the next qurl deploy.
- [ ] Rollback: before apply, revert this PR if qurl-service #904 is not being rolled out. After apply, roll qurl-service back first and prefer leaving the empty table in place. To destroy it in prod, first apply with deletion protection disabled, then apply the table removal.
