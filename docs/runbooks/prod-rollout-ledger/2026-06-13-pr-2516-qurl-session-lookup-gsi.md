# 2026-06-13 · PR #2516 · qURL session lookup GSI

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2516, https://github.com/layervai/qurl-service/pull/931, https://github.com/layervai/qurl-service/issues/253

Apply this Terraform change before promoting the companion qurl-service build that requires the qurl-sessions `resource-token-ip-index` GSI.

- [x] Pre-rollout: confirm the qurl-service#931 schema registry matches this Terraform definition exactly: index name `resource-token-ip-index`, hash key `resource_id`, range key `session_lookup_key`, `INCLUDE` projection, and non-key attributes `access_token_id`, `created_at`, `first_authorized_at`, `session_duration_seconds`, `src_ip`, `ttl`. _Done/current 2026-06-17: qurl-service `cef5f89` schema registry and NHP Terraform both define `resource-token-ip-index` with `resource_id`/`session_lookup_key` and the same INCLUDE projection._
- [x] Pre-rollout: confirm the currently deployed qurl-service reconciler ignores unexpected GSIs before applying Terraform first. Current `origin/main` checks registry-to-live only and intentionally ignores live GSIs absent from the qurl-service registry. _Done/current 2026-06-17: `cmd/qurl-schema-check/main.go` builds requirements from the registry and checks for missing required indexes/projections; it does not fail on live extra GSIs._
- [x] Pre-rollout: confirm qurl-service task IAM grants Query on qurl table index ARNs. Current `terraform/modules/qurl-service/main.tf` grants every `local.qurl_service_dynamodb_table_arns` entry plus `${arn}/index/*`, which covers `qurl-sessions/resource-token-ip-index`. _Done/current 2026-06-17: IAM policy resources include all qurl-service table ARNs plus `${arn}/index/*`._
- [ ] Rollout (prod Terraform): apply the qurl-sessions `resource-token-ip-index` GSI change and wait for the index to become ACTIVE in the target environment before promoting the qurl-service image. _Current 2026-06-17: sandbox GSI is ACTIVE; prod `layerv-nhp-prod-cell0-qurl-sessions` still has no GSIs until the prod Terraform release apply creates the index, so prod qurl-service promotion remains gated._
- [ ] Migration window: accept that existing active sessions written before qurl-service#931 lack `session_lookup_key` and do not appear in the sparse GSI; those sessions drain by TTL while `CreateWithMaxCheck` continues to enforce caps with a base-table transaction. No DDB backfill is planned.
- [ ] Cross-repo: do not promote layervai/qurl-service#931 until this GSI exists in that environment.
- [ ] Burn-in: watch for hot-resource GSI throttling; dedicated per-GSI alarms are tracked in layervai/nhp#2519.
- [ ] Rollback: if the companion qurl-service rollout is reverted, leave the GSI in place; remove it only after no deployed qurl-service build declares it in the schema registry.
