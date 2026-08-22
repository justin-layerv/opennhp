# 2026-08-21 · PR #3926 · qURL share lifecycle cutover

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3926 · https://github.com/layervai/qurl-service/pull/1420 · https://github.com/layervai/frp/pull/18

Move Connector sharing to durable desired state plus NHP-session/serving-epoch
fences. Sandbox must absorb the default-off migration and cross-repo contract
change before any separately authorized production rollout.

Read-only sandbox baseline on 2026-08-21: the live cell0 qurl-service task
renders `CONNECTOR_AUTH_ENABLED=true` and the now-retired active-registration
flag as `true`; IAM simulation returns `implicitDeny` for both
`dynamodb:TransactWriteItems` and `dynamodb:ConditionCheckItem` on the exact
cell0 qurl-resources table. A full 187,388-item table scan found zero
`tunnel_registration` rows, zero `tunnel_session` rows, and 169 active tunnel
resources; none has `sharing_desired_state`, so all 169 intentionally become
off rather than receiving an implicit-on backfill.

- [ ] Pre-rollout: land the reviewed FRP fork tag and pin it in
      qurl-reverse-tunnel-server; land the NHP validator, qurl-service, qRTS,
      Connector/daemon, and CLI contracts without deploying an incompatible
      partial set.
- [ ] Pre-rollout: after PR #3926 is merged, check out that merged `main` in
      sandbox and create a saved, reviewed target plan for exactly
      `module.nhp.module.qurl_service[0].aws_iam_role_policy.task_tunnel_session_fence[0]`.
      The target set must also include both
      `module.nhp.terraform_data.qurl_tunnel_active_registration_preconditions`
      and `module.nhp.terraform_data.qurl_tunnel_registration_preconditions`
      so Terraform can record their already-declared state-only move. On the
      2026-08-21 sandbox state, that target plan is exactly one IAM-policy add,
      zero changes, zero destroys, plus the no-op precondition address move.
      Apply the saved target plan only; do not run the full apply yet because
      it also creates the env-flag-free qurl-service task-definition revision.
      Wait until IAM simulation allows both actions on the exact cell0
      qurl-resources table and still returns `implicitDeny` for each action on
      a sibling table and the resources-table index. Do not deploy the
      consuming qurl-service build before this gate is green.
- [ ] Rollout: only after the targeted IAM pre-grant and its exact-scope
      simulations are green, deploy sandbox NHP token validation first, then
      qurl-service, qurl-reverse-tunnel-server, and Connector/CLI consumers in
      one attended compatibility window; finish with the full sandbox
      Terraform apply that removes the retired ECS env flag. The reviewed
      2026-08-21 full sandbox plan contains no DynamoDB resource change and no
      stateful table or data destroy. No production apply or data mutation is
      authorized by PR #3926.
- [ ] Post-rollout: confirm the 169 pre-fence resources remain off with no
      bulk backfill, a new/re-published local share automatically starts, stop
      fails closed immediately, restart rotates the serving epoch, and a
      sleep/wake reconnect reaches `serving` without operator refresh approval.
      Verify stale/pending sessions never route and the new binding/registration
      rows expire at the signed NHP session deadline.
- [ ] Cross-repo: before requesting production authorization, repeat the row
      inventory and customer-impact review, record sandbox smoke evidence, and
      use the same IAM-pregrant/NHP/qurl-service/qRTS/Connector/CLI/full-Terraform
      ordering. Existing production resources also remain default-off unless a
      separately reviewed migration explicitly changes that decision.
- [ ] Pre-prod gate: after PR #3926 merges, do not run any full production
      Terraform apply from a revision that contains this cutover until the
      cross-repo production set is ready and the attended production rollout is
      separately authorized. An unrelated production change must wait or use a
      reviewed revision that excludes this cutover; Terraform cannot authorize
      only the unrelated resource while silently retaining the legacy qURL task
      definition. On the first production plan, confirm the qURL service module
      receives a nonempty resources-table ARN before reviewing the exact-scope
      IAM pre-grant. The currently deployed service must retain the legacy env
      flag until this gate opens.
- [ ] Rollback: roll back qRTS, qurl-service, NHP validation, and consumers as
      one contract set; restore the prior Terraform task definition only after
      the old service is running. Remove the session-fence IAM pre-grant last,
      after confirming no deployed consumer can call the transaction path.
