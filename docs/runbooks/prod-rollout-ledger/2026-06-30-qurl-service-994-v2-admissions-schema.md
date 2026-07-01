# 2026-06-30 · qurl-service #994 · `qurl-v2-admissions` table

- **Owner:** prod rollout coordinator
- **Source:** this nhp PR · required by [qurl-service #994](https://github.com/layervai/qurl-service/pull/994) (the qURL v2 keyed-identity epic image, already on qurl-service `main`)

Catches nhp Terraform up to the `qurl-v2-admissions` table the qurl-service v2
image (`#994`) added to `dbclient.Tables`, so the runtime schema reconciler
(`internal/health/dynamodb_schema.go`, hardcoded on) stops `DescribeTable`-ing a
missing table. On startup the reconciler reports `drift_count=2` → `/health/ready`
503 → ECS circuit-breaker rolls every qurl-service deploy back to the last
pre-#994 task def; this table is **one** of those two drifts:

- **`qurl-v2-admissions` absent** (fixed here) — new v2 admission hot-state table
  (PK `pk`, SK `sk`, TTL `ttl`, no GSIs). Added + folded into `qurl_table_arns`
  so the qurl-api task role's `task_dynamodb` policy grants it `DescribeTable` +
  read/write automatically. The table name is prefix-derived
  (`PrefixedTable(TablePrefix, "qurl-v2-admissions")`), so no task-env wiring.
- **`qurl-agent-keys` `pubkey-index` missing `registered_at`** (NOT fixed here) —
  owned by the `KEYS_ONLY` direction that landed in nhp#2927
  (`docs/design/QURL_AGENT_KEYS_SCHEMA.md`): the schema gate reads the base row
  via `GetItem`, not an eventually-consistent GSI projection. The completion is a
  **qurl-service** change to drop the `pubkey-index` `RequiredProjection` and
  base-row the `GetByPublicKey` tie-break — paired
  [qurl-service #1060](https://github.com/layervai/qurl-service/pull/1060).
  Terraform stays `KEYS_ONLY`; do **not** re-widen the projection here.

v2 stays **dormant**: `QURL_V2_ISSUANCE_ENABLED` / `QURL_V2_RESOURCE_KEYS_ENABLED`
remain off. This PR only restores the "additive and behaviorless" invariant the
#2753 epic-merge ledger entry claimed but the schema reconciler broke. Enabling
v2 is a separate gated rollout with its own ledger entry.

- [ ] **Rollout (prod Terraform):** `terraform apply` of this PR's plan against `terraform/environments/prod/` succeeds and `aws dynamodb describe-table --table-name layerv-nhp-prod-cell0-qurl-v2-admissions --region us-east-2` returns `TableStatus=ACTIVE` BEFORE the qurl-service prod image promotes past the pre-#994 build. NOTE: the `qurl-schema-check` gate in promote-to-prod only flags missing GSIs/projections, so it does **not** block on this table's absence (no GSIs) — the runtime reconciler is its actual gate, i.e. drift for a no-GSI table fails **late** (at deploy) rather than at CI. Closing that gap with a CI lint is tracked in [#2473](https://github.com/layervai/nhp/issues/2473).
- [ ] **Cross-repo deploy ordering:** a green qurl-service deploy needs BOTH this table AND the paired qurl-service `pubkey-index` `RequiredProjection` drop. Until both land + the qurl-service image ships, the reconciler still reports the remaining drift and rolls the deploy back. This entry only clears the `qurl-v2-admissions` half.
- [ ] **Post-rollout (sandbox):** after both halves land, the next `build-and-push` sandbox deploy rolls qurl-api onto a fresh task def that reaches a steady state **past `:917`** (no circuit-breaker rollback), `/health/ready` returns 200, and the qurl-api logs show no `dynamodb schema drift detected on startup`.
- [ ] **Deferred to v2 enablement (separate ledger):** add `qurl-v2-admissions` to the `qurl_resolve_throttle_tables` for_each (`modules/dynamodb/alarms.tf`) when v2 admission goes hot — omitted now because a dormant table has no traffic and the alarm would sit in `INSUFFICIENT_DATA`.
- [ ] **Rollback:** reverting this PR returns to the failing state (the deployed v2 image health-fails on the missing table). The only clean rollback that keeps qurl-service deployable is re-pinning the `/{name_prefix}/qurl-api-image-tag` SSM param to the last pre-#994 build (`5be6a3c`) — a qurl-service-side action. Leave the table in place (prod `deletion_protection` refuses `terraform destroy`).
