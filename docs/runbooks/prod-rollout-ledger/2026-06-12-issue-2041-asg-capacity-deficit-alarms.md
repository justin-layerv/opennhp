# 2026-06-12 · Issue #2041 · ASG capacity-deficit alarms

- **Owner:** prod rollout coordinator
- **Source:** PR (this), [#2041](https://github.com/layervai/nhp/issues/2041)

Rewires historical `*-asg-unhealthy` alarms from the non-published
`AWS/AutoScaling.GroupUnHealthyInstanceCount` metric to metric math over
published ASG metrics (`GroupDesiredCapacity - GroupInServiceInstances`).
Alarm names and SNS actions stay stable, but the first apply can move formerly
silent alarms from `INSUFFICIENT_DATA` to `OK`; alarms with `ok_actions` can
emit OK notifications.

Accepted behavior changes: the NLB-disabled frps canary rollback signal now
fires after `ceil(instance_warmup_seconds / 60) + 1` consecutive 60s deficit
datapoints instead of the previous intended ~60s tripwire. This deliberately
trades rollback latency for healthy-warmup tolerance; an oscillating deficit can
reset the all-of-N window, while post-`InService` app failures remain covered by
the Lambda health gate and empty-AZ watchdog rather than this capacity alarm. As
of this rollout, sandbox and prod both use `canary_instance_warmup_seconds = 180`
and `canary_checkpoint_delay_seconds = 300`, so the canary alarm window is 240s
and retains 60s of checkpoint margin. A module precondition now rejects any
NLB-disabled canary config where `(ceil(instance_warmup_seconds / 60) + 1) * 60`
is not strictly less than `checkpoint_delay_seconds`; raise the checkpoint delay,
lower warmup, or add a separate faster signal before enabling that shape.
Standby alarms are intentionally sustained-capacity-shortfall signals; the
asymmetric `desired` Minimum / `in_service` Maximum stats can suppress
intermittent flapping deficits so healthy refresh churn does not page.

- [ ] Rollout: validate in sandbox first, then promote to prod with `run_terraform=true`.
- [ ] Post-rollout (sandbox): confirm every changed alarm that is in the current sandbox graph is backed by a `Metrics` array using `GroupDesiredCapacity` and `GroupInServiceInstances`, not a flat `MetricName=GroupUnHealthyInstanceCount`. Also confirm the both-inputs-missing/fresh-ASG case settles `notBreaching` as expected from `FILL(..., 0)` plus `treat_missing_data = notBreaching`, and that the one-input-missing case with `desired` present treats missing `in_service` as zero and breaches for a real deficit. Current sandbox graph includes server/AC green blue-green alarms; qurl-reverse-tunnel-server green and frps canary alarms remain mode-gated until their rollout flags are enabled.
- [ ] Post-rollout (sandbox healthy-warmup gate for #2041): after the fixed alarm exists in an environment where the NLB-disabled frps canary path is enabled, run a healthy frps canary deploy/instance refresh and confirm the canary `GroupDesiredCapacity - GroupInServiceInstances` deficit settles before `ceil(instance_warmup_seconds / 60) + 1` consecutive 60s datapoints breach. This is blocking before failure injection and before enabling the NLB-disabled frps canary path in prod; if healthy warmup routinely consumes 3+ datapoints, add margin only together with a longer checkpoint delay or a separate faster rollback signal so the module precondition still preserves checkpoint margin.
- [ ] Post-rollout (sandbox failure-injection gate for #2041): after the healthy-warmup gate passes, inject a controlled capacity-deficit or stuck-launch condition and confirm the composite canary health alarm enters `ALARM` and invokes the EventBridge rollback path within the canary checkpoint window. Confirm the observed wall-clock path from deficit injection through CloudWatch `ALARM` and EventBridge rollback still leaves margin before the current 300s checkpoint cadence; the Terraform precondition should block future zero-margin or slower-than-checkpoint settings before prod enablement, but the live gate must measure propagation latency too. Also confirm the 60s canary `Average` bucket does not average away the injected deficit. Finally, inject or simulate a crash-loop that briefly reaches `InService`/registration and then fails, and confirm the Lambda health gate or empty-AZ watchdog catches it; this capacity-deficit alarm is not expected to catch an oscillating all-of-N deficit by itself.
- [ ] Post-rollout (prod): confirm prod alarm definitions match the fixed sandbox shape for all resources in graph and settle to `OK` at steady state.
- [ ] Rollback: revert the PR and re-apply. That restores the previous broken alarm definitions; no data migration or traffic rollback is involved.
