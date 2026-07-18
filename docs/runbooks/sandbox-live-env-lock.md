# qURL sandbox live-environment lock

NHP and qurl-service share one mutable sandbox qURL ECS service. Every workflow
that can update that service serializes through:

```text
/layerv-nhp-sandbox/qurl-live-env-lock
```

The lock implementation is owned by qurl-service. NHP vendors its composite
action and three shell helpers byte-for-byte from qurl-service commit
`d506fa61a06c7b8b18b5d69dfe65dae15bd19270`; the machine-readable
[provenance manifest](../../.github/actions/sandbox-live-env-lock/provenance.json)
pins their source paths and hashes. The local copy is required because the
dependency-age workflow's caller-scoped token cannot verify an action pin into
an internal sibling repository. Do not change the JSON, TTL, ownership, or
failure contract independently. The canonical recovery procedure and lock
invariants are in
[qurl-service's source runbook](https://github.com/layervai/qurl-service/blob/d506fa61a06c7b8b18b5d69dfe65dae15bd19270/docs/runbooks/sandbox-live-env-lock.md).
The manifest test proves NHP's files match its committed hashes; it does not
refetch the internal source in CI. Reviewers must verify source bytes manually
until the qurl-service-side fanout fence below or the shared public action owns
that cross-repo check. Comments inside the exact vendored helpers describe
qurl-service consumers and are not an NHP caller inventory.

Until both repositories migrate to the generated public action tracked in
[ops-routines #83](https://github.com/layervai/ops-routines/issues/83), any
qurl-service change to the vendored action or any of the three helpers must
follow [qurl-service #1245](https://github.com/layervai/qurl-service/issues/1245):
open a linked NHP sync PR, copy all four files from the merged qurl-service
commit, update the provenance commit and hashes, and rerun the executable
parity/behavior tests. Never update only one helper or the manifest hashes.

## Failure telemetry

Every fail-closed producer attempts two best-effort
`LayerV/QURLServiceCI/SandboxLiveEnvLockFailure=1` samples in order:

1. A dimensionless sample drives the Terraform-managed paging alarm.
2. A diagnostic sample adds exact `Reason` and `Action` dimensions.

Each publication is attempted independently. Metric failure never replaces the
primary lock failure or weakens fail-closed behavior. The dimensionless series
is authoritative for alarming and counting; the diagnostic series is
attribution only. Alarm publication intentionally precedes diagnostic argument
validation, so a manual or divergent caller with invalid `Reason`/`Action`
still pages and then exits nonzero without publishing unsafe dimensions. NHP
publishes `RollFailedRetained` with `Action=release` when the ECS roll does not
reach verified success/no-op and the workflow therefore retains its exact-owner
lock. Here `Action` names the release-decision phase: no delete is attempted
because that phase deliberately chooses retention. The shared helper also
publishes `ReadFailed`,
`PutFailed`, `DeleteFailed`, `Malformed`, and `Contention` for the corresponding
lock paths. See the
[alarm runbook](qurl-sandbox-live-env-lock-alarm.md) for queries and response.

## Owner shapes

- qurl-service: `qurl-service:<run_id>:<run_attempt>:<job-name>`
- NHP: `nhp:<run_id>:<run_attempt>:deploy-sandbox-qurl`

Open the owning GitHub Actions run before taking recovery action. A live owner
may be waiting for ECS stability and must not have its lock removed.
Re-running a failed job does not recover its retained lock: `run_attempt`
changes the owner token, so the new attempt will wait and eventually fail.
Reconcile and release the prior attempt's lock using this runbook first.
Contention is expected only while qurl-service is running its protected
exact-image smoke/restore path or another NHP main roll is active. Queued main
pushes and the bounded runner cost are accepted in exchange for preserving that
proof; do not cancel a healthy waiter merely to free a runner.

NHP's lock-bearing job requests a 10,800-second AWS session, matching its
three-hour job timeout, and Terraform permits that duration only on the sandbox
GitHub Actions role. Both bounds are load-bearing: the default one-hour STS
session would expire during a valid two-hour wait, causing a fail-closed
`ExpiredToken` read or preventing exact-owner release after a successful roll.
The longer maximum does not grant longer credentials by itself; only the
explicit sandbox job request uses it. qurl-service lock-bearing jobs must make
the same request before relying on their shared two-hour waiter.

## Inspect

Use the sandbox account and region:

```bash
export AWS_PROFILE=layerv
export AWS_REGION=us-east-2

aws ssm get-parameter \
  --name /layerv-nhp-sandbox/qurl-live-env-lock \
  --query 'Parameter.Value' \
  --output text | jq .

CLUSTER_NAME="$(aws ssm get-parameter \
  --name /layerv-nhp-sandbox/qurl-ecs-cluster \
  --query 'Parameter.Value' --output text)"
SERVICE_NAME="$(aws ssm get-parameter \
  --name /layerv-nhp-sandbox/qurl-ecs-service \
  --query 'Parameter.Value' --output text)"

aws ecs describe-services \
  --cluster "$CLUSTER_NAME" \
  --services "$SERVICE_NAME" \
  --query 'services[0].{taskDefinition:taskDefinition,running:runningCount,pending:pendingCount,deployments:deployments[*].{status:status,taskDefinition:taskDefinition,rolloutState:rolloutState}}'
```

For an NHP owner, inspect the `Deploy Sandbox - QURL Service` job. A successful
or no-op `Roll qurl-service to latest task def` step has already verified a
stable service and normally releases the lock. A release-action failure leaves
the NHP job red and retains the lock. Any other roll outcome intentionally
retains the lock. Confirm the service is stable on either the deployer's
verified target or its circuit-breaker rollback target before release.
The job acquires before probing whether qurl-service is deployed; that can wait
unnecessarily in a dark sandbox. Probe-first was rejected because the read-only
deployment check can become stale before a later mutation, creating two lock
boundaries and a TOCTOU path around the shared contract. One acquire-first
boundary keeps every possible ECS mutation strictly behind the same lock.

Two waiters can rarely observe the same expired lock before either delete
completes; the loser currently fails closed if its delete sees
`ParameterNotFound`. Canonical peer-delete recovery must land in qurl-service
before NHP can re-vendor it; the labeled fix and required foreign-owner race
coverage are tracked in
[qurl-service #1246](https://github.com/layervai/qurl-service/issues/1246).

The canonical waiter also fails closed after one non-absence SSM read error.
Bounded retry for explicitly transient read-only failures, including the
required mid-wait fixtures, is tracked upstream in
[qurl-service #1247](https://github.com/layervai/qurl-service/issues/1247).
Unknown errors and terminal IAM/region failures must remain immediate failures;
NHP must not add an independent retry policy to the vendor.

For a qurl-service owner, use that workflow's captured
`original_task_definition` and follow the canonical qurl-service runbook. Do
not blindly restore an older revision if a newer legitimate current-main deploy
won a historical race; first classify the active task definition's image and
the workflow that registered it.

## Release

Release only after all of these are true:

1. The owning run is terminal.
2. The service has exactly the intended primary task definition.
3. The deployment is stable with no pending tasks.
4. The active image is the intended current-main or explicitly approved PR
   image for the owning workflow.

Then delete only the shared lock parameter:

```bash
aws ssm delete-parameter \
  --name /layerv-nhp-sandbox/qurl-live-env-lock
```

Do not delete or deregister task definitions, ECR tags, or images until the
service is confirmed off them. Incident evidence and the cross-repository race
that introduced this guard are tracked in [#3244](https://github.com/layervai/nhp/issues/3244).
