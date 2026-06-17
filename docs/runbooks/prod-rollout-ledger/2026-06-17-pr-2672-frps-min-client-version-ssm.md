# 2026-06-17 · PR #2672 · FRPS min client version SSM sync

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2672, https://github.com/layervai/qurl-reverse-tunnel-server/pull/208, https://github.com/layervai/qurl-connector/pull/371

Deploy the SSM-backed min-client-version sync with the gate disabled, then verify the timer before any production floor is set.

- [ ] Pre-rollout: confirm qurl-reverse-tunnel-server #208 and qurl-connector #371 are deployed or scheduled before setting a non-disabled floor.
- [ ] Rollout: apply with `/<env>/nhp/reverse-tunnel-server/min-client-version` value `disabled`.
- [ ] Post-rollout: verify FRPS user-data logs show `min-client-version synced from SSM`, the server logs show `min_client_version=disabled`, and a sandbox SSM change to a test floor then back to `disabled` is observed by the running qurl-reverse-tunnel-server logs without restarting the instance.
- [ ] Guardrail check: in sandbox, write an invalid SSM value and confirm `qurl-min-client-version-sync.service` fails without replacing the prior min-client-version file, then restore `disabled`.
- [ ] Guardrail check: confirm a boot-time SSM outage is treated as a temporary fail-open window (`disabled` local file seeded so FRPS can start) and that `FRPSMinClientVersionSyncFailure` alarms until the timer recovers.
- [ ] Rollback: set the SSM parameter to `disabled`; if the sync timer itself is unhealthy, roll back this NHP launch-template change and refresh the FRPS ASG.
