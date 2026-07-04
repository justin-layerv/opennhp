# 2026-07-04 · PR #3030 · ac-servers-healthy-low alarm blue/green tolerance

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3030

Re-tunes the `ac-servers-healthy-low` CloudWatch alarm from `Minimum < 2` over
one 5-min period to `Average < 2` sustained 15 min (evaluation_periods=3), so it
stops false-paging on the EXPECTED blue/green registration flip (per #2658
both-attach routing, an AC's `ServersHealthy` legitimately oscillates 0↔1↔3)
while still firing on a genuine sustained AC↔server reachability loss. Alarm
config only; no metric/dimension change.

- [ ] Rollout: `terraform apply` in sandbox then prod updates the alarm in
      place (no instance/deploy dependency).
- [ ] Post-rollout (sandbox): confirm `layerv-nhp-sandbox-ac-servers-healthy-low`
      settles to `OK` and STAYS OK across a normal blue/green server deploy (the
      previous config latched ALARM on every flip). Spot-check the `ServersHealthy`
      Average stays ≥2 in steady state.
- [ ] Post-rollout (prod): same verification on the prod alarm after promote.
- [ ] Rollback: revert to `Minimum`/`threshold 2`/`evaluation_periods 1`. Safe —
      alarm-config only; reintroduces the false-page noise but no functional risk.
- [ ] Follow-up (not blocking): per-AC granularity so a single stuck AC isn't
      masked by the shared-stream average — tracked in #946 (add ACId dimension +
      per-AC SEARCH/metric-math alarm). Underlying both-attach routing flip is
      #2645/#2658.
