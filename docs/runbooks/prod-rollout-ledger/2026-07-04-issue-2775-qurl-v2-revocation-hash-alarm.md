# 2026-07-04 · issue #2775 · qURL v2 revocation-hash alarm

- **Owner:** prod rollout coordinator
- **Source:** [#2775](https://github.com/layervai/nhp/issues/2775)

Adds the `QurlV2RevocationHashError` CloudWatch alarm and dashboard visibility
for the qURL v2 fail-open revocation-hash tripwire. The alarm is additive and
uses the normal prod promote Terraform apply; no server image or runtime flag
change is required.

- [ ] Rollout: confirm the prod Terraform plan creates
      `<name_prefix>-<cell>-qurl-v2-revocation-hash-error` and updates the NHP
      dashboard with `QurlV2RevocationHashError`; both use namespace
      `LayerV/NHP` and dimensions `{Environment, Cell}`.
- [ ] Post-rollout: confirm the alarm exists, routes ALARM/OK actions to the
      per-cell `alerts` SNS topic, and rests in `OK` or `INSUFFICIENT_DATA`
      while the sparse should-never-fire counter has no samples.
- [ ] Alarm triage: if it fires, read it as per-key hash failures, not admission
      count. One admission can increment twice if both qURL-user and resource
      keys fail. Inspect NHP server logs for `revocationHashesFromClaims`
      invariant violations; affected admitted v2 flows may rely on scheduled
      timer-wheel expiry instead of targeted revocation by key.
- [ ] Rollback: revert the Terraform alarm/dashboard change and apply; this
      removes monitoring only. The Go-side metric emission remains harmless if
      left in place.
