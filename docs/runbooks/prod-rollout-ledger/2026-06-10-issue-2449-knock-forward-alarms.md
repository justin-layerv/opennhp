# 2026-06-10 · issue #2449 · Knock forward-path alarms

- **Owner:** prod rollout coordinator
- **Source:** [#2449](https://github.com/layervai/nhp/issues/2449)

Adds two additive CloudWatch alarms (`${name_prefix}-${cell_id}-knock-forward-failure`
and `${name_prefix}-${cell_id}-knock-no-ac`), a "Knock Forward Health" dashboard
widget, and a runbook. Closes the monitoring gap that let a silently-100%-broken
server-to-server forward path hide behind a green dashboard. Applies through the
normal promote pipeline. Tuned as single-event detectors against a cold-path
prod baseline — full calibration math is in the module comments
(`terraform/modules/monitoring/main.tf`).

- [ ] Post-rollout: after the apply, confirm both alarms exist and that the dim
      set matches the live publisher. These sparse counters normally have no
      data, so resting in `OK` / `INSUFFICIENT_DATA` is EXPECTED, not a dim
      mismatch; verify the dim set via a regularly-emitted sibling
      (`KnockRequest`) or `aws cloudwatch list-metrics --namespace LayerV/NHP`,
      NOT by expecting a specific alarm state.
- [ ] Post-rollout: confirm the "Knock Forward Health" widget renders the three
      counters for the prod cell (the original bug hid behind a dashboard with no
      forward-path panel).
- [ ] Follow-up (not in this PR): the cold forward path's stronger long-term
      detector is a synthetic probe that periodically forces a forward (how
      #2449 was found). File/track it; these passive alarms are the immediate
      net, not a substitute.
- [ ] Rollback: alarms + widget are purely additive — `terraform apply` of the
      revert removes them; no Go/runtime change accompanies this PR.
