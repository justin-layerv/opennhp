# 2026-07-12 · issue #3184 · assigned-cell UDP flood readiness

- [ ] Pre-rollout: deploy the reviewed server image and compute/monitoring
  Terraform to sandbox; confirm `nhp-udp-edge-metrics.timer` is active on every
  active server instance and `UDPEdgeCollectorHeartbeat` has the exact
  `{Environment=sandbox,Cell=cell0}` series.
- [ ] Sandbox hard gate: run **Assigned-cell UDP flood readiness** at the
  reviewed SHA with the default 8 × 2,000 pps, five-minute load and 99% / 2s-p99
  SDK SLO. Archive all workflow artifacts and record the passing run URL here.
  Pre-merge rehearsal is blocked by the independently tracked relay DMZ
  partial-apply recovery in
  [#3215](https://github.com/layervai/nhp/issues/3215). The first recovery
  failure in run
  [29219444825](https://github.com/layervai/nhp/actions/runs/29219444825)
  was fixed by #3216. Follow-up run
  [29220185236](https://github.com/layervai/nhp/actions/runs/29220185236)
  then proved the next topology cycle: a successful relay ASG refresh launched
  replacement ENIs on the still-deposed security group because the replacement
  launch template is part of the not-yet-applied plan. The workflow failed
  closed before apply. Keep this box unchecked until #3215 is resolved and a
  passing run at the reviewed SHA is recorded; direct UDP SDK traffic remains
  dark meanwhile.
- [ ] Pre-prod: confirm the prod NLB still exposes only UDP 62206, UDP 62207 is
  absent, and the prod plan contains only the reviewed server launch-template,
  dashboard, and alarm changes.
- [ ] Rollout: promote the server image and Terraform through the normal
  blue/green path. Do not enable direct UDP SDK traffic in the same change.
  The new collector-missing alarm can transiently enter `ALARM` after monitoring
  applies but before collector-equipped instances become active (three missing
  one-minute heartbeats). Treat only that bounded first-roll window as expected;
  investigate if it does not recover after the active fleet publishes heartbeats.
- [ ] Post-rollout: confirm collector heartbeat on every active prod instance,
  all four UDP dashboard panels populate, and the collector/protected-reserve/
  queue/receive-buffer alarms are OK.
- [ ] Product gate: enable direct UDP SDK traffic only after the sandbox hard
  gate above is recorded and explicitly accepted. A failed or missing run keeps
  the feature dark.
- [ ] Rollback: revert the PR and refresh the server ASG. Direct UDP SDK rollout
  remains blocked because the protected-capacity and evidence contracts are no
  longer present.
