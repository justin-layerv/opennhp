# 2026-07-14 · Issue #3247 · qURL sandbox lock failure alarm

- **Owner:** sandbox rollout coordinator and LayerV platform on-call
- **Source:** https://github.com/layervai/nhp/issues/3247, https://github.com/layervai/nhp/issues/3244, https://github.com/layervai/nhp/pull/3246

Apply the additive sandbox alarm, then deliberately prove the paired producer
contract: one dimensionless sample drives the standard alarm and one
`Reason`/`Action` sample preserves diagnosis. The canary pages the real sandbox
route, so do not emit either sample without first reporting both exact steps and
obtaining authorization.

- [x] IAM prerequisite (verified 2026-07-14): NHP `main`'s
  `terraform/modules/ecr/main.tf` and default version `v35` of the live managed
  policy `nhp-sandbox-github-actions-terraform-apply-services` both grant
  `cloudwatch:PutMetricData` through the same exact four-namespace allowlist:
  `LayerV/NHP`, `LayerV/NHP/Deploy`, `LayerV/QURLServiceCI`, and
  `NHP/BlueGreen`. No IAM change or IAM apply is part of this alarm rollout.
  This evidence completes the namespace-allowlist item in
  `2026-07-08-pr-3131-qurl-ci-metric-namespace.md`.
- [ ] Pre-rollout: confirm
  [qurl-service #1244](https://github.com/layervai/qurl-service/pull/1244)'s
  canonical helper independently attempts the dimensionless alarm sample first
  and the bounded `Reason`/`Action` diagnostic sample second, and
  [NHP #3246](https://github.com/layervai/nhp/pull/3246)'s vendored producer
  matches that exact order and failure behavior. Both must be merged; a
  dimensioned-only producer does not satisfy the alarm contract. Require both
  PRs' executable tests to prove that each stream is attempted when the other
  fails, that an ordinary lock collision waits without emitting a failure
  sample, and that `Reason=Contention` is emitted only after the canonical
  7,200-second wait budget is exhausted and the waiting job fails. Confirm the
  `layerv-nhp-sandbox-cell0-alerts` subscription is still owned by alerts-infra
  `sandbox-alerts-sandbox` and the platform on-call expects one ALARM plus one
  informational recovery notification per isolated event, accepts repeated
  pairs for failures in non-consecutive minutes, and confirms the downstream
  route treats OK as non-paging.
- [ ] Sandbox rollout: apply the Terraform plan and confirm it creates only
  `aws_cloudwatch_metric_alarm.qurl_ci_sandbox_live_env_lock_failure[0]` with
  name `layerv-nhp-sandbox-qurl-service-ci-live-env-lock-failure`,
  `ActionsEnabled=true`, threshold `> 0`, one-of-one 60-second evaluation,
  `Namespace=LayerV/QURLServiceCI`,
  `MetricName=SandboxLiveEnvLockFailure`, `Statistic=Sum`, no dimensions, no
  Metrics Insights query, `treat_missing_data=notBreaching`, and ALARM/OK
  actions both targeting `layerv-nhp-sandbox-cell0-alerts`. Expect one initial
  informational OK notification when the new alarm first evaluates missing data
  and transitions from INSUFFICIENT_DATA to OK; confirm it is non-paging and do
  not treat it as a recovery from a lock failure.
- [ ] Post-rollout canary (authorization required): from
  `AWS_PROFILE=layerv`, `AWS_REGION=us-east-2`, announce and run these two
  producer-shaped commands exactly once, in order:

  ```bash
  aws cloudwatch put-metric-data --region us-east-2 --namespace 'LayerV/QURLServiceCI' --metric-name 'SandboxLiveEnvLockFailure' --value 1 --unit Count
  aws cloudwatch put-metric-data --region us-east-2 --namespace 'LayerV/QURLServiceCI' --metric-name 'SandboxLiveEnvLockFailure' --dimensions 'Reason=AlarmCanary,Action=acquire' --value 1 --unit Count
  ```

  Confirm the dimensionless sample enters ALARM and the intended on-call route
  receives the ALARM notification. Separately confirm the diagnostic pair is
  queryable; its visibility does not prove alarm coverage. Record both command
  timestamps and alarm history; do not repeat either datapoint to compensate for
  normal CloudWatch ingestion or evaluation latency.
- [ ] Post-rollout recovery: publish no clearing or zero datapoint. Confirm the
  next missing-data bucket returns the alarm to OK, the same route receives the
  OK notification as informational and non-paging, and on-call understands that
  OK means no new metric event rather than proof a retained SSM lock was
  reconciled. Delivery alone is insufficient; record the observed downstream
  non-paging behavior.
- [ ] Post-rollout producer proof: after qurl-service #1244 and NHP #3246 are
  live, capture at least one non-customer-path publisher invocation and prove it
  attempts the dimensionless sample first and the map-shorthand diagnostic
  sample second even if either AWS call fails. Confirm the dimensionless sample
  is visible without dimensions and `list-metrics` shows the bounded `Reason`
  and `Action` pair. Use that evidence to finish and delete
  `2026-07-08-pr-3131-qurl-ci-metric-namespace.md`; do not delete either ledger
  entry before all of its remaining producer/ECR checks are also complete.
- [ ] Post-rollout handoff: record the platform owner and a next binding-proof
  due date no more than 90 days out. The recurring procedure in
  `docs/runbooks/qurl-sandbox-live-env-lock-alarm.md` is also required after a
  producer metric contract, alarm selector, publisher IAM grant, or notification
  route change until [#3251](https://github.com/layervai/nhp/issues/3251)
  automates non-paging liveness; each interim run is announced and
  authorization-gated because it pages the live sandbox path.
- [ ] Rollback: if the alarm or notification route is wrong, revert this PR and
  apply sandbox Terraform to remove the alarm. Do not roll back the namespace
  IAM grant or lock producers as part of alarm rollback; lock handling stays
  fail-closed and the metric remains available for manual queries.
