# 2026-07-14 · PR #3258 · frps reverse-tunnel owner_missing reject alarm

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3258

Additive CloudWatch metric filter (`FRPSOwnerMissingRejectCount`, `LayerV/NHP`) +
page alarm (`${name_prefix}-frps-owner-missing-rejects`) on the frps log group,
matching the byte-stable frps-core reject **wire string**
`owner_missing: connector identity missing` — works on the current server, **no
cross-repo deploy-order dependency** (full rationale in the PR body +
`monitoring.tf`). The wire string is live now (outage ongoing), so the alarm arms
and pages within one 5-min window of apply.

- [ ] **Rollout DECISION (resolve BEFORE prod apply):** with the outage live
      (~20 rejects/window vs threshold 5) the alarm goes ALARM on apply and stays
      red until #431 drains the fleet. **Recommended (b):** apply with a raised
      `owner_missing_reject_threshold` env tfvar, restore to 5 once #431 drains to
      ~0. Alt (a): prime on-call and ride it out. Record the chosen path here.
- [ ] Post-rollout: confirm the first ALARM is a genuine stuck connector (runbook
      triage), not a filter misfire.
- [ ] Post-rollout: confirm `FRPSOwnerMissingRejectCount` increments on real
      rejects. Dry-run proof (matches the frps-core `[W]` line, NOT #226's
      structured line → one match per reject, no double-count):

  ```
  aws logs test-metric-filter \
    --filter-pattern '"owner_missing: connector identity missing"' \
    --log-event-messages \
      '[W] [server/control.go:387] ... new proxy [fileviewer] ... error: owner_missing: connector identity missing' \
      'rejected event=handler_session_miss reject_reason=owner_missing run_id=abc123'
  ```
- [ ] Post-rollout: confirm the reject line is `[W]` (Warn), not `[E]`, so it does
      not also trip `log_error_rate` (this is why it hid despite the `[E]` alarm).
- [ ] Post-rollout: confirm the alarm rests in `OK` (not `INSUFFICIENT_DATA`);
      `default_value = 0` keeps the series populated, so `INSUFFICIENT_DATA` means
      the filter never initialized (broken pattern / silent log group).
- [ ] Sandbox burn-in: `evaluation_periods = 1` is spike-prone — confirm a
      simultaneous connector fleet deploy doesn't routinely cross 5 in one window;
      if it does, add `datapoints_to_alarm` (M-of-N) via env tfvars.
- [ ] Rollback: additive — `terraform apply` of the revert removes filter + alarm
      + runbook; no functional risk.
