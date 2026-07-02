# 2026-07-01 · Issue #2974 · harden revocation deploy-window suppressor

- **Owner:** prod rollout coordinator
- **Source:** [#2974](https://github.com/layervai/nhp/issues/2974)

Moves the qURL v2 `DeploymentWindow` suppressor out of the shared
`LayerV/NHP` app namespace into the deploy-only `LayerV/NHP/Deploy` namespace,
adds the paired `DeploymentWindowRun` marker, and wires the
`revocation-deploy-window-without-run` alarm so unpaired or legacy suppressor
writes are operator-visible. IAM namespace scoping is the primary boundary
that keeps non-deploy principals from writing paired suppressor metrics. The raw
`revocation-aged-out`, paging
`revocation-aged-out-page`, and suppressed breadcrumb semantics remain
unchanged.

- [ ] Rollout: apply Terraform normally. Verify the plan updates `revocation-deploy-window` to `LayerV/NHP/Deploy`, creates `revocation-deploy-window-without-run`, scopes all Terraform-managed `cloudwatch:PutMetricData` grants by namespace, and denies server/AC instance roles from `LayerV/NHP/Deploy`.
- [ ] Rollout ordering: apply the Terraform namespace/alarm change before running a merged promote/blue-green/canary deploy that emits the new `LayerV/NHP/Deploy` heartbeat. If a deploy must run between merge and apply, treat any `revocation-aged-out-page` notification as potentially caused by the old alarm still reading the shared `LayerV/NHP` namespace.
- [ ] Audit: confirm no Terraform-managed principal outside the deploy role can emit `LayerV/NHP/Deploy`; non-deploy publishers should be scoped to their own namespaces only. Re-check deploy-role namespace coverage whenever a new deploy-time metric namespace is added, because deploy metric puts are best-effort warnings.
- [ ] Deploy validation: run or observe the next promote/blue-green/canary path and confirm the log contains `DeploymentWindow/DeploymentWindowRun metrics pushed`; then confirm fresh `LayerV/NHP/Deploy` `DeploymentWindow` and `DeploymentWindowRun` datapoints with dimensions `{Environment=prod, Cell=<cell>}`.
- [ ] Post-rollout: confirm `<name_prefix>-<cell>-revocation-deploy-window-without-run` is `OK`/`INSUFFICIENT_DATA` before the injection validation, or after any validation/suppressor hold has aged out. If it is `ALARM`, treat it as an unpaired/legacy suppressor write, manual metric injection, or a deploy-helper regression before trusting deploy-window suppression.
- [ ] Blocking post-rollout validation: before marking the rollout complete or relying on the orphan watchdog, validate the CloudWatch one-input-missing metric-math path used by this custom metric pair. The alarm uses the repo's sparse-metric `FILL(..., 0)` convention, but this exact whole-series-empty orphan case still must be proven live. In sandbox first, then prod only during an approved quiet validation window, inject exactly one `DeploymentWindow` datapoint into `LayerV/NHP/Deploy` for the target `{Environment, Cell}` without emitting `DeploymentWindowRun`; confirm `<name_prefix>-<cell>-revocation-deploy-window-without-run` transitions to `ALARM` on the first breaching datapoint and remains latched for the normal deploy-window suppressor hold. Record the timestamp, note that the test intentionally opens the normal deploy-window suppressor hold, and keep the raw `revocation-aged-out` alarm visible while the suppressor ages out. If the watchdog stays `OK`/`INSUFFICIENT_DATA`, do not trust the secondary tripwire; fix the metric math or open a labeled follow-up before closing the rollout.
- [ ] Post-rollout: confirm the existing raw `revocation-aged-out`, paging `revocation-aged-out-page`, and no-action `revocation-aged-out-suppressed` alarms still match the documented #2868 semantics.
