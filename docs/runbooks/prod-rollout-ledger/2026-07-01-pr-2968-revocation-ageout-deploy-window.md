# 2026-07-01 · PR #2968 · revocation age-out deploy window

- **Owner:** prod rollout coordinator
- **Source:** [#2968](https://github.com/layervai/nhp/pull/2968), [#2868](https://github.com/layervai/nhp/issues/2868), follow-up [#2974](https://github.com/layervai/nhp/issues/2974)

Adds the qURL v2 `DeploymentWindow` suppressor, ALARM-side SNS-backed
`revocation-aged-out-page` composite, and no-action
`revocation-aged-out-suppressed` breadcrumb. The raw `revocation-aged-out`
detector remains strict at `Sum >= 1`; this PR changes paging behavior during
server/AC deploy overlap rather than pruning proof entries.

- [ ] Rollout: apply Terraform normally. Verify the plan creates or updates the no-action `revocation-deploy-window` metric alarm, no-action raw `revocation-aged-out` metric alarm, no-action `revocation-aged-out-suppressed` composite, and ALARM-side SNS-backed `revocation-aged-out-page` composite under the prod cell.
- [ ] Security acceptance: confirm this PR's bounded tradeoff does not block prod arming. A single raw `RevocationAgedOut` inside the recent deploy-heartbeat window can be suppressed from paging rather than delayed, while the raw alarm and `revocation-aged-out-suppressed` breadcrumb remain visible for audit. Issue #2974 hardens the suppressor path by moving `DeploymentWindow` to a deploy-only namespace and adding an orphaned-window alarm.
- [ ] Deploy-start triage: if `revocation-aged-out-page` briefly fires in the first 1-2 minutes after a deploy starts, confirm whether the initial `DeploymentWindow` datapoint was still waiting on CloudWatch evaluation before treating it as a non-deploy age-out.
- [ ] Apply-failure triage: if Terraform apply fails partway through the alarm migration, verify the ALARM-side SNS-backed `revocation-aged-out-page` composite exists before relying on paging; the raw detector intentionally has no direct SNS action after this change.
- [ ] Post-rollout: confirm deploy workflows can emit `DeploymentWindow` in prod by checking a promote/blue-green/canary run log for the `DeploymentWindow/DeploymentWindowRun metrics pushed` breadcrumb, or by observing fresh `LayerV/NHP/Deploy` `DeploymentWindow` and `DeploymentWindowRun` datapoints with dimensions `{Environment=prod, Cell=<cell>}`.
- [ ] Post-rollout: confirm the post-deploy monitor lists `revocation-aged-out-page` as actionable and ignores only `revocation-aged-out`, `revocation-deploy-window`, and `revocation-aged-out-suppressed`.
- [ ] Alarm triage: if `revocation-aged-out-suppressed` is ALARM, inspect the raw detector and deploy run context. This is an audit breadcrumb for raw age-outs during the recent deploy-heartbeat window; a single transient in-window age-out is not queued for a delayed page. `revocation-aged-out-page` intentionally sends ALARM actions only, not OK actions, because a later deploy window can clear the composite before the raw age-out is resolved.
- [ ] Follow-up: after [#2974](https://github.com/layervai/nhp/issues/2974) lands, confirm `<name_prefix>-<cell>-revocation-deploy-window-without-run` is `OK`/`INSUFFICIENT_DATA` after the next deploy and treat any ALARM as an unpaired/legacy suppressor write, manual metric injection, or a partial CI helper failure.
