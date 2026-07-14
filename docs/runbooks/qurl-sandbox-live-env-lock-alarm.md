# qURL sandbox live-environment lock alarm

`layerv-nhp-sandbox-qurl-service-ci-live-env-lock-failure` pages when the
dimensionless `LayerV/QURLServiceCI/SandboxLiveEnvLockFailure` alarm stream
reports a nonzero value.
qurl-service and NHP share `/layerv-nhp-sandbox/qurl-live-env-lock` while they
mutate or prove the sandbox qURL ECS service. A failure can block later deploy
and admission jobs for the lock's four-hour TTL, so this signal is actionable
even when no customer path is affected.

## Notification owner and semantics

Terraform sends both ALARM and OK transitions to the shared monitoring topic,
`layerv-nhp-sandbox-cell0-alerts`. The downstream owner is alerts-infra's
`sandbox-alerts-sandbox` AWS Chatbot subscription; the LayerV platform on-call
owns acknowledgement and reconciliation. The downstream route must treat OK as
informational and non-paging; the rollout owner verifies that behavior before
the alarm is considered ready.

This alarm routes directly to the shared topic. It is not suppressed during a
deployment window: a failed or retained lock is a fail-closed coordination
fault, not expected deployment noise.

The alarm evaluates one 60-second bucket and enters ALARM when the sum is above
zero. Missing data is not breaching. An OK notification therefore means only
that no new failure datapoint appeared in the next evaluated bucket. It proves
the alarm-to-SNS-to-Chatbot recovery path, but it does **not** prove the SSM lock
was deleted, its owner finished, or the ECS service is safe. Keep the incident
open until the checks below pass.

Treat OK as informational. An isolated failure normally produces one ALARM → OK
pair, and failures in non-consecutive minutes produce repeated pairs. The
rollout owner must confirm that expectation with platform on-call. If recovery
notifications later become noisy, change `ok_actions` in a reviewed follow-up;
do not suppress the underlying ALARM path.

A newly created or recreated alarm can also send an initial OK when its first
missing-data evaluation moves it from INSUFFICIENT_DATA to OK. Treat that
notification as route initialization, not recovery from a lock failure.

This is an event alarm, not a retained-lock age gauge. A retained lock can keep
blocking work after the one-time failure metric has aged out and the alarm has
returned to OK; the manual state checks below remain mandatory.
State-based follow-up is tracked in
[#3250](https://github.com/layervai/nhp/issues/3250) and is not a blocker for
this fail-closed event alarm.

## What the alarm covers

Each failure makes two independent publication attempts in this order:

1. A dimensionless `SandboxLiveEnvLockFailure=1` sample drives the alarm.
2. A second sample for the same metric adds bounded `Reason` and `Action`
   dimensions for diagnosis.

The standard alarm deliberately has no `dimensions` block. CloudWatch treats
each dimension set as a distinct metric identity, so it selects only the first
sample. Do not remove the dimensionless producer sample or point the alarm at
the diagnostic streams. A Metrics Insights alarm over the diagnostic streams
can miss a one-shot first occurrence while CloudWatch indexes a brand-new
dimension pair; diagnostic discovery is not on the paging path.

The producer attempts both samples even if either AWS call fails. A warning for
the dimensionless publication means the diagnostic sample alone cannot page;
investigate that warning as an alarm-path failure. Automated non-paging
pipeline liveness is tracked in
[#3251](https://github.com/layervai/nhp/issues/3251).

An ordinary lock collision emits no failure metric. The canonical producers
wait while the current owner remains live; `Reason=Contention` is emitted only
after the 7,200-second wait budget is exhausted and the waiting job fails. A
shared sandbox queue blocked for two hours is page-worthy even when the owner
later proves legitimate. Treat that page as a request to investigate the owner
and service state, never as permission to delete its lock.

For a diagnostic aggregate in CloudWatch Metrics Insights, use:

```sql
SELECT SUM(SandboxLiveEnvLockFailure)
FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)
```

For a diagnostic breakdown, add `GROUP BY`:

```sql
SELECT SUM(SandboxLiveEnvLockFailure)
FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)
GROUP BY Reason, Action
ORDER BY SUM() DESC
```

In the AWS console, select region `us-east-2`, open **CloudWatch → Metrics → All
metrics → Multi source query**, switch to the query editor, and run the
breakdown query above. Set the time range around the ALARM transition.

From the CLI, query the exact dimensionless alarm stream over a bounded incident
window:

```bash
export AWS_PROFILE=layerv
export AWS_REGION=us-east-2

# Replace these with a bounded UTC window around the alarm transition.
START_TIME="2026-07-14T16:00:00Z"
END_TIME="2026-07-14T16:30:00Z"

aws cloudwatch get-metric-statistics \
  --namespace "LayerV/QURLServiceCI" \
  --metric-name "SandboxLiveEnvLockFailure" \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --period 60 \
  --statistics Sum

aws cloudwatch list-metrics \
  --namespace "LayerV/QURLServiceCI" \
  --metric-name "SandboxLiveEnvLockFailure" \
  --recently-active PT3H
```

The statistics output comes only from the dimensionless stream because the
request supplies no dimensions. The `list-metrics` output also names observed
diagnostic `Reason` and `Action` pairs. Allow normal Metrics Insights discovery
latency for a new diagnostic pair, and use the workflow logs for the detailed
AWS error; dimensions are bounded routing breadcrumbs, not a substitute for the
owning run.

## Response

If starting directly from this section, establish the sandbox AWS context first:

```bash
export AWS_PROFILE=layerv
export AWS_REGION=us-east-2
```

1. Read the lock value. If the parameter is absent, continue with the recent
   workflow and metric investigation; do not recreate it.

   ```bash
   aws ssm get-parameter \
     --name /layerv-nhp-sandbox/qurl-live-env-lock \
     --query 'Parameter.Value' --output text | jq .
   ```

2. Parse `owner` and open that exact GitHub Actions run and attempt. Expected
   owner prefixes are `qurl-service:<run_id>:<run_attempt>:` and
   `nhp:<run_id>:<run_attempt>:`. A live owner may be waiting for ECS stability;
   never delete its lock.
3. Read `/layerv-nhp-sandbox/qurl-ecs-cluster` and
   `/layerv-nhp-sandbox/qurl-ecs-service`, then inspect the ECS service. Require
   exactly one PRIMARY deployment, its rollout state `COMPLETED`, the intended
   task definition, desired running tasks, and zero pending tasks.
4. For a retained restore or roll failure, identify the active task definition's
   container image and the workflow that registered it. Do not blindly restore
   an older revision over a legitimate newer main deployment.
5. Only after the owning run is terminal and the ECS state is reconciled may the
   platform on-call delete the parameter:

   ```bash
   aws ssm delete-parameter \
     --name /layerv-nhp-sandbox/qurl-live-env-lock
   ```

6. Re-run the blocked proof job and confirm the intended task definition remains
   stable. Record the owning run, active revision/image, deletion time, rerun,
   and alarm notification in the incident or tracking issue.

The canonical publisher correction is tracked in
[qurl-service #1244](https://github.com/layervai/qurl-service/pull/1244). The
cross-repository race and shared-lock implementation are tracked in
[#3244](https://github.com/layervai/nhp/issues/3244) and
[#3246](https://github.com/layervai/nhp/pull/3246). Alarm ownership is tracked in
[#3247](https://github.com/layervai/nhp/issues/3247).

## Controlled and recurring notification proof

Missing data is intentionally non-breaching, so silence does not prove the
producer-to-alarm-to-notification pipeline is alive. Until automated non-paging
liveness is delivered by
[#3251](https://github.com/layervai/nhp/issues/3251), repeat this binding proof
at least every 90 days and after a change to either producer's namespace,
metric name, dimensionless or diagnostic publication shape; the alarm selector;
the CI publisher IAM grant; or the SNS/Chatbot route.

The publisher IAM prerequisite was verified on 2026-07-14: NHP `main` and
default version `v35` of the live
`nhp-sandbox-github-actions-terraform-apply-services` managed policy both allow
`LayerV/QURLServiceCI` in the same exact four-namespace
`cloudwatch:PutMetricData` statement. This alarm change does not add or apply an
IAM grant; reverify that source-to-live match after any publisher-policy change.

The synthetic canary mirrors both producer attempts: a dimensionless sample
first, then a diagnostic sample whose dimensions use one AWS CLI map-shorthand
token. The first command pages the sandbox on-call path. Schedule an
operator-attended window, report both exact steps, and obtain authorization
before execution. Never run them as an unannounced test.

```bash
export AWS_PROFILE=layerv
export AWS_REGION=us-east-2

aws cloudwatch put-metric-data \
  --region us-east-2 \
  --namespace 'LayerV/QURLServiceCI' \
  --metric-name 'SandboxLiveEnvLockFailure' \
  --value 1 \
  --unit Count

aws cloudwatch put-metric-data \
  --region us-east-2 \
  --namespace 'LayerV/QURLServiceCI' \
  --metric-name 'SandboxLiveEnvLockFailure' \
  --dimensions 'Reason=AlarmCanary,Action=acquire' \
  --value 1 \
  --unit Count
```

Run both commands once, in order. Confirm the dimensionless sample drives the
alarm into ALARM, the diagnostic pair becomes queryable, the intended route
receives the ALARM notification, the next missing-data bucket returns to OK
without a clearing datapoint, and the OK notification remains informational and
non-paging. Record the authorization, both command timestamps, alarm history,
diagnostic visibility, and both delivery observations in the tracking record.
If any step fails, do not publish retry datapoints to paper over normal
CloudWatch ingestion or evaluation latency; investigate the broken binding.
