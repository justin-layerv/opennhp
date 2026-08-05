# 2026-08-05 · Connector registration dark-path alarm

- **Owner:** prod rollout coordinator
- **Source:** this PR · deferred follow-up to [PR #3729](https://github.com/layervai/nhp/pull/3729) (added the metric) · [commit 2630cec1](https://github.com/layervai/nhp/commit/2630cec1)
- **Related:** [NHP #3455](https://github.com/layervai/nhp/issues/3455) — the synthetic-page-receipt proof pattern this reuses

PR #3729 added the `ConnectorRegistrationHandlerAbsent` nhp-server metric
(`LayerV/NHP`, dims `{Environment, Cell}`) while fixing the sandbox cell0
Connector Authority activation-rollout incident, and deferred the alarm. This
change adds the alarm: `${name_prefix}-${cell_id}-connector-registration-handler-absent`
in `terraform/modules/monitoring/main.tf`, `Sum >= 1` over one 5-minute period,
routed to the NHP server alerts SNS topic (`aws_sns_topic.alerts`). Because the
alarm lives in the shared `modules/monitoring` module (instantiated by
`module "nhp"` in every env root), it is created for sandbox **and** prod at
their own `{Environment, Cell}`. Additive infra; no protocol path changes.

The metric-emitting code already shipped with #3729 (merged to `main`), so there
is no image-must-land-first ordering for the metric to exist. The alarm uses
`treat_missing_data = "notBreaching"`: it sits green until the metric first
publishes, which on an activated cell is never (baseline is flat zero).

- [ ] Rollout: apply Terraform (sandbox via the normal `main`-push apply, prod
      via `promote-to-prod`). No ordering dependency on a server image — the
      metric already ships in the deployed server.
- [ ] Post-rollout: confirm `${name_prefix}-${cell_id}-connector-registration-handler-absent`
      exists in **both** sandbox and prod, keys on `namespace = LayerV/NHP`,
      `metric_name = ConnectorRegistrationHandlerAbsent`, dims exactly
      `{Environment, Cell}`, and routes `alarm_actions`/`ok_actions` to the NHP
      server alerts SNS topic (`layerv-nhp-<env>-<cell>-alerts`).
      `aws cloudwatch describe-alarms --alarm-name-prefix layerv-nhp-sandbox-cell0-connector-registration-handler-absent`.
- [ ] Post-sandbox rollout, **before prod promotion** — page receipt (blocking).
      Alarm state is not evidence: `treat_missing_data = notBreaching` means a
      wrong dim set sits in a permanently green `OK`, indistinguishable from a
      healthy one (CLAUDE.md "Alarm state is not evidence on a dark path"; NHP
      #3455). Prove BOTH legs and record the receipts:
      1. **Routing:** `aws cloudwatch set-alarm-state --alarm-name
         layerv-nhp-sandbox-cell0-connector-registration-handler-absent
         --state-value ALARM --state-reason "dark-path alarm synthetic routing
         proof"`; confirm the notification reaches the operator destination, then
         return it to `OK` and confirm no alarm is left in a manually-forced
         state.
      2. **Dim set:** drive one real `ConnectorRegistrationHandlerAbsent` at a
         deliberately-dark sandbox instance — send a native Connector
         registration (NHP_REG/LST/OTP, aspId=agent, over direct UDP) to a cell
         instance whose `connectorRegistrationHandler` is nil (an instance
         without the connector-authority activation config). Confirm the alarm
         transitions to `ALARM` on its own and record which `{Environment, Cell}`
         stream and `MetricDataResults` backed it. Do not accept the
         `set-alarm-state` receipt as dim-set proof.
- [ ] Pre-rollout — on-call acknowledgement of the paging profile. The alarm sets
      `ok_actions` (matching the sibling server counters `ack_token_shared_store_failure`,
      `overload_cookie_mint_failure`): the OK transition re-arms paging, so an
      intermittent dark-serving window that recurs across separate 5-minute
      buckets pages on each recurrence. A single sustained stream (every bucket
      breaching) latches `ALARM` and pages once. That is intended for a
      zero-baseline dark-path signal; damp at the notification layer if ever
      needed rather than dropping `ok_actions`.
- [ ] Rollback: alarm is purely additive; `terraform apply` of the revert removes
      it in both envs. No function, role, SNS, or network resource is touched in
      either direction.
