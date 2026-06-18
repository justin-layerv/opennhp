# 2026-06-12 · PR #2492 · Observability parity alarm routing

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2492

This PR wires the core AC CloudWatch alarm suite to the shared monitoring SNS
topic and adds PR-time parity fences for the prod/sandbox observability surfaces
from #1141. Coordinate the normal prod Terraform rollout with the sandbox
Chatbot ownership handoff note in the PR body.

- [x] Pre-rollout: describe the prod core AC alarms before applying and confirm
      none are already in an unexpected `ALARM` or `INSUFFICIENT_DATA` state that
      would page or mask a newly-live alarm action. _Done/current 2026-06-17:
      `aws cloudwatch describe-alarms --profile layerv-prod` shows the prod core
      AC alarm suite in `OK`._
- [ ] Post-rollout: after the prod Terraform apply, confirm the core AC alarms'
      dimension sets match their
      publishers (`terraform/CLAUDE.md` "Metric / Alarm Dim-Set Rules"; smoke
      test `TestACAlarms_DimensionsMatchPublisher` covers the audited subset).
      _Current pre-apply 2026-06-17: this smoke test fails in prod because
      `registration-failure` and `server-connection-failure` still have
      `{Component=AC}` but expect `{Component=AC, Environment=prod,
      Region=us-east-2}`. Treat this as a release-apply/post-apply verification
      item, not a separate pre-release manual fix._
- [ ] Cross-repo/sandbox: before the sandbox apply that activates both AC alarm
      actions and external Chatbot ownership, describe the sandbox core AC alarm
      states and confirm no unexpected `ALARM` or `INSUFFICIENT_DATA` state will
      surprise-page or mask a newly-live alarm action.
- [ ] Rollout: apply the Terraform change in prod so the core AC alarm action
      updates reach the shared monitoring SNS topic.
- [ ] Post-rollout: verify every prod core AC alarm has non-empty
      `alarm_actions` and `ok_actions` targeting the shared monitoring topic.
- [ ] Rollback: revert this PR and re-apply Terraform if the alarm action update
      causes unexpected alert routing noise.
