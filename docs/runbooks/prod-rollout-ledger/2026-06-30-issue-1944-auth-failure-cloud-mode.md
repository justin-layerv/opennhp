# 2026-06-30 · Issue #1944 · AuthFailure cloud-mode headroom

- **Owner:** prod rollout coordinator
- **Source:** [#1944](https://github.com/layervai/nhp/issues/1944), [#1955](https://github.com/layervai/nhp/issues/1955)

Raises the prod NHP `auth_failures` CloudWatch alarm from 50 to 250 per
5-minute bucket, with 3 of 3 datapoints required, before the first prod
cloud-mode agent-peer-validation flip. Non-prod stays at 50 so sandbox remains
an early canary. Cloud mode lets `agent_unknown_pubkey` and
`agent_empty_pubkey` rejects reach the handler and increment `AuthFailure`;
on-prem rejected those packets earlier at the Noise responder.

- [x] Pre-rollout: audited live CloudWatch on 2026-06-30. Prod (`AWS_PROFILE=layerv-prod`, `us-east-2`, `Environment=prod`, `Cell=cell0`) had zero `AuthFailure` datapoints over the prior 30 days while `KnockRequest` was non-zero (30-day hourly total 41, max 9/hour). Sandbox (`AWS_PROFILE=layerv`, `Environment=sandbox`, `Cell=cell0`) peaked at 3 `AuthFailure` events per 5-minute bucket over the prior 5 days and 7/hour over the prior 30 days.
- [ ] Rollout: apply this Terraform change before any prod env ships cloud mode / `DisableAgentPeerValidation=true`, then confirm `layerv-nhp-prod-cell0-auth-failures` has `Threshold=250`, `EvaluationPeriods=3`, and `DatapointsToAlarm=3`. Confirm sandbox/non-prod `auth_failures` remains at `Threshold=50`.
- [ ] Post-rollout: during the first prod cloud-mode flip, watch the 5-minute `AuthFailure` sum and `qurl-agent-keys` throttle alarm together. If `AuthFailure` sustains above 125 per bucket after the rollout settles, pause additional flips and retune alongside the agent-specific alarm package in #1955.
- [ ] Rollback: revert this PR to restore the prior threshold of 50. If rollback happens after cloud mode is live, expect the old threshold to page on the newly visible agent reject population until #1955 splits agent-path alarms.
