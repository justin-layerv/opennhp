# 2026-06-10 · PR #2437 · Resolve CloudFront access logging (v2 → S3)

- **Owner:** prod rollout coordinator
- **Source:** [#2437](https://github.com/layervai/nhp/pull/2437), [#1799](https://github.com/layervai/nhp/issues/1799); CI-grant follow-up: [#2444](https://github.com/layervai/nhp/pull/2444)

> **Correction (post-#2437 sandbox apply).** #2437's CI grant was
> **incomplete**: it added the `logs:*` delivery verbs but not
> `cloudfront:AllowVendedLogDeliveryForResource`, which `PutDeliverySource`
> requires on the distribution when the delivery-source `resource_arn` is a
> CloudFront distribution. The first post-#2437 sandbox apply red-balled on
> `AccessDenied` for **that** action — a genuinely missing grant, which a
> re-run never clears. Fixed in the follow-up PR above (adds the
> `CloudFrontVendedLogDelivery` Sid to `qurl_link_static`). This is distinct
> from the resource-prefix propagation wait described below: that wait is real
> and remains for prod's fresh apply; the cloudfront grant was a bug, not a
> race. Prod must promote *after* the follow-up fix is on main, or it hits the
> same permanent wall.

Enables CloudFront standard logging v2 for the resolve distribution → new
`layerv-nhp-prod-qurl-resolve-logs` S3 bucket. Applies via promote with
`run_terraform=true`. The same apply adds the `CloudFrontStandardLoggingV2*`
grants to the `qurl_link_static` CI policy and creates the us-east-1 delivery
resources; the delivery resources `depends_on` the existing
`time_sleep.qurl_link_static_iam_propagation` shim.

**Expect a first-apply IAM-propagation re-run (attended).** That shim is 60s,
calibrated for action-list edits on an already-scoped policy; these grants add
*new resource-prefix ARN targets* (`delivery-source:…-qurl-resolve`,
`delivery-destination:…-qurl-resolve-s3`), which per `terraform/CLAUDE.md`
(#2072 evidence) can take ~180s to propagate. We deliberately reuse the 60s
shim rather than add a dedicated 180s one (the rollout is attended + sandbox-
first), so the **first** apply of these resources may fail with a transient
`AccessDenied` on `logs:PutDeliverySource`/`PutDeliveryDestination`. This is
expected — re-run the apply and it clears (the grant has propagated). It is NOT
a config error and a re-run is safe (these creates are idempotent).

- [ ] Rollout: validate in sandbox first (sandbox applies on merge to main), then promote to prod with `run_terraform=true`.
- [ ] Rollout (sandbox): the post-#2437 apply already failed on the missing `cloudfront:AllowVendedLogDeliveryForResource` grant (see Correction). After the follow-up fix merges, the sandbox apply adds only that one `*`-scoped grant fresh (the `logs:Put*` resource-prefix grants from #2437 have long since propagated), so it should complete in a single apply within the 60s shim. If it still `AccessDenied`s, re-run once and confirm completion before promoting.
- [ ] Rollout (**prod promote — the disruptive case**): the promote runs the same first-grant apply, so it may half-apply on the propagation `AccessDenied`. Treat a re-run as the **expected** path: re-run the promote (or its terraform step) once; do **not** treat the first `AccessDenied` as a failure to roll back. A half-applied prod promote here is recoverable by re-running, not by reverting.
- [ ] Post-rollout (delivery wired): `aws logs get-delivery-source --name layerv-nhp-prod-qurl-resolve --region us-east-1` shows `service=cloudfront`, `logType=ACCESS_LOGS`; `aws logs describe-deliveries --region us-east-1` shows the delivery into destination `layerv-nhp-prod-qurl-resolve-s3`.
- [ ] Post-rollout (logs land): a first object appears under `s3://layerv-nhp-prod-qurl-resolve-logs/AWSLogs/<account-id>/CloudFront/` within ~1h (v2 delivery is typically 5–15 min).
- [ ] Post-rollout (token-not-logged proof): pull a recent object and confirm there is **no** `cs-uri-query`/`token=` field — the curated `record_fields` omit it. This is the security gate; if a token appears, disable immediately (`enable_resolve_access_logs = false`). **Note:** disabling triggers `force_destroy`, which purges the bucket — good for removing the leaked tokens from S3, but if you need the offending object(s) for incident response, copy a sample out **first**, then disable.
- [ ] Post-rollout (cost guard): confirm S3 storage + CloudWatch vended-logs delivery (`*-S3-Egress-Bytes`) stays < $5/mo at resolve traffic (#1799 acceptance criterion).
- [ ] Rollback: set `enable_resolve_access_logs = false` and apply (the bucket is `force_destroy = true`, so it cleans up), or revert the PR.
- [ ] Note: #1799's "`aws cloudfront get-distribution-config` → `Logging.Enabled = true`" criterion does **not** apply — that field is for legacy logging; v2 leaves the distribution `LoggingConfig` empty and is verified via the delivery + S3 checks above.
- [ ] Follow-up: Athena table over these logs is deferred to [#2438](https://github.com/layervai/nhp/issues/2438) (must use a JSON SerDe matching the curated `record_fields`, not the standard CF DDL).
