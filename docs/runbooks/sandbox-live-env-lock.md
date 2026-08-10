# qURL sandbox live-environment lock

NHP and qurl-service share one mutable sandbox qURL customer path. Every
workflow that can replace the qURL ECS task definition or roll the NHP
server/AC blue-green boundary serializes through:

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
publishes `RollFailedRetained` with `Action=release` when either its ECS roll or
server/AC blue-green roll does not reach a verified terminal state and the
workflow therefore retains its exact-owner lock. Here `Action` names the
release-decision phase: no delete is attempted because that phase deliberately
chooses retention. The shared helper also
publishes `ReadFailed`,
`PutFailed`, `DeleteFailed`, `Malformed`, and `Contention` for the corresponding
lock paths. See the
[alarm runbook](qurl-sandbox-live-env-lock-alarm.md) for queries and response.

## Owner shapes

- qurl-service: `qurl-service:<run_id>:<run_attempt>:<job-name>`
- NHP qurl-service roll: `nhp:<run_id>:<run_attempt>:deploy-sandbox-qurl`
- NHP server/AC blue-green: `nhp:<run_id>:<run_attempt>:blue-green`

Open the owning GitHub Actions run before taking recovery action. A live owner
may be waiting for ECS stability and must not have its lock removed.
Re-running a failed job does not recover its retained lock: `run_attempt`
changes the owner token, so the new attempt will wait and eventually fail.
Reconcile and release the prior attempt's lock using this runbook first.
Contention is expected only while qurl-service is running its protected
exact-image smoke/restore path, NHP is rolling qurl-service, or an NHP
blue/green deployment is converging the server/AC boundary. Queued main pushes
and the bounded runner cost are accepted in exchange for preserving that proof;
do not cancel a healthy waiter merely to free a runner.

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

For an NHP `deploy-sandbox-qurl` owner, inspect the `Deploy Sandbox - QURL
Service` job. A successful or no-op `Roll qurl-service to latest task def` step
has already verified a stable service and normally releases the lock. A
release-action failure leaves the NHP job red and retains the lock. Any other
roll outcome intentionally retains the lock. Confirm the service is stable on
either the deployer's verified target or its circuit-breaker rollback target
before release.
The job acquires before probing whether qurl-service is deployed; that can wait
unnecessarily in a dark sandbox. Probe-first was rejected because the read-only
deployment check can become stale before a later mutation, creating two lock
boundaries and a TOCTOU path around the shared contract. One acquire-first
boundary keeps every possible ECS mutation strictly behind the same lock.

For an NHP `blue-green` owner, inspect the complete `Blue/Green Deploy` run.
The lock is acquired before `Prepare`, so direct/manual dispatches and
build-and-push child runs share the same boundary. A successful deploy releases
only after the standby refresh, traffic switch, post-switch readiness
validation, and actual previous-color warm-standby convergence all succeed.
Rollback and switch-only runs release only after their switch and validation
succeed; explicitly skipped validation is not release-safe after a mutation. A
prepare failure, true dry run, or successful prepare that selects no deployable
component is safe to release because none can mutate live state.

A run whose `Switch Traffic` job is **skipped** also releases. `switch-traffic`
is the only job that mutates the live boundary — every `aws elbv2
modify-listener` and the authoritative `active-color` write live in
`blue-green-switch.sh`, which nothing else invokes — and its own guard is
`needs.deploy-to-standby.result == 'success' || == 'skipped'`. A skipped switch
therefore proves the roll failed or was cancelled before any listener moved and
the customer path is exactly as the run found it. The standby-only residue such
a run leaves (scaled-up standby ASG, refreshed standby fleet, updated standby
image tag) is off every live target group, is the normal mid-roll state, and is
reconciled from scratch by the next run's `Prepare`/`Deploy to Standby`.

Any other terminal shape retains the lock: reconcile active-color parameters,
listener target groups, ASG capacities/refreshes, and knock readiness before
exact-owner release. A **cancelled** `Switch Traffic` is deliberately in the
retain set even though a skipped one is not — cancellation mid-switch can leave
public UDP flipped and the internal relay listener not, which is precisely the
half-switched boundary the mutex exists to fence.

The release decision is executable and tested: see
`.github/scripts/classify-blue-green-lock-release.sh` and
`tests/scripts/test_blue_green_lock_release.py`. Narrowing retention to
boundary-moving failures closed a compounding livelock observed on 2026-07-28:
run `30337884706` failed at `[Server] Verify Knock Readiness (AC Peers
Connected)` — before any switch — and pinned the lock for its full four-hour
TTL, whereupon run `30354530304` took it the moment the TTL lapsed, failed
identically, and held it four hours more, stalling `Build and Deploy NHP` on
main. Retention there protected nothing: the boundary had never moved.

The other way a run reaches that retain set is a false post-switch failure, and
one specific false positive is now fenced. `[Server] Verify Post-Switch Knock
Readiness` runs in the `validate` job, so failing it also skips
`scale-down-previous` — the listeners have already moved, the previous color
stays scaled up, and `safe_to_release` is false for the full four-hour TTL. On
2026-08-09, run `31340465407` reached that state because
`verify-knock-ready.sh` read a systemd `NRestarts=1` and reported the PR #1096
panic class. The actual journal was `Main process exited, code=exited,
status=125/n/a` behind `Error response from daemon: ... failed to create
Cloudwatch log stream`: docker's own exit code for a run it never started,
recovered by `Restart=always` in six seconds. No nhp-server code had run at
all.

`.github/scripts/classify-nhp-server-restart-evidence.sh` now separates the two
from the unit's exit status, plus panic and OOM evidence, and a container-start
failure that self-healed passes the gate with a `::warning::` instead of
failing it. Note that this is a **pass**, not a fail-with-release: after the
switch, failing the gate is what strands the previous color scaled up, so a
fleet that converged should be allowed to finish converging. A Go panic still
fails — it exits the process with status 2, which is caught by the exit status
alone even when the stack trace only reaches CloudWatch. Behaviour is pinned by
`tests/lints/blue-green-restart-classification/run-fixtures.sh`.

When the gate does fail, read the per-instance verdict in the job log before
reaching for this runbook's Release section:

| Verdict | Means | First move |
|---|---|---|
| `app_crash` | A non-125 abnormal exit of the server process, or an OOM kill | Real regression — `journalctl -u nhp-server` on the named instance |
| `infra_unstable` | All container-start failures, but not converged or past the self-heal budget | Container runtime, log driver, or registry fault — not an nhp-server defect |
| `indeterminate` | Restarts with no recorded cause, or an unreadable report | Read the raw journal; the gate deliberately refuses to guess |

A panic marker in the journal is **corroboration, never the verdict**. A
panicking process exits 2, so the exit status alone catches a real
#1096-class crash — which matters because container output reaches CloudWatch,
not necessarily the journal. Letting the panic grep decide instead would mean
an application log line beginning at column 0 with `panic: ` could turn an
unrelated container-start self-heal into a claimed regression, which is the
original misdiagnosis pointed the other way. So the gate names #1096 only
alongside an abnormal exit, and reports a panic marker it cannot reconcile as
`indeterminate`.

That wording is load-bearing, so it is asserted rather than merely written: the
shared corpus at `tests/fixtures/nhp-server-restart-evidence/` carries
`detail-contains`/`detail-excludes` files per case (both drivers honour them),
and `TestRestartEvidenceMessagesStateObservations` in
`tests/smoke/restart_evidence_test.go` pins the cases built from a struct
rather than a parsed report. If you change what this section says, one of those
will tell you.

A panic marker that caused *no* restart — every restart already accounted for
by an exit 125 — passes with a `::warning::` rather than failing. Getting there
means the exit-status accounting is complete and says docker was at fault, so
the marker is a recovered panic or a log line beginning at column 0 with panic
text. Failing on it would make panic text decisive exactly where the evidence
says the deploy is fine, re-creating the same disproportionate block (and the
same four-hour lock) from a log-line shape instead of a bare counter.

This broader boundary was added after NHP run `29658670289` overlapped
qurl-service exact-image smoke run `29658663594`. The smoke acquired the old
ECS-only mutex while blue/green was still running both colors, then exercised
NHP during the post-switch interval before all new active servers had AC peers.
The result was NHP `52005`, not a qurl-service code failure. Repository-local
GitHub concurrency cannot close that race; the shared SSM owner does.

The mutex proves only that an exact-image qv2 smoke did not overlap an NHP
blue/green mutation or its bounded infrastructure convergence. It does **not**
certify end-to-end AC admission health, and the warm-standby capacity check is
not an admission probe. The customer-path defect observed during the incident
(`PeerGroup` address mismatch while both colors exposed six server peers) and
its six-peer/two-color acceptance coverage are owned by
[#2123](https://github.com/layervai/nhp/issues/2123). Do not treat this CI
serialization as a substitute for that product fix.

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
2. For a qurl-service owner, the service has exactly the intended primary task
   definition. The deployment is stable with no pending tasks and serves the
   intended current-main or explicitly approved PR image.
3. For a blue-green owner, server and AC active-color parameters match their
   listeners, no instance refresh is still running, previous colors are at
   warm-standby capacity, and every active server reports AC knock readiness.

Then delete only the shared lock parameter:

```bash
aws ssm delete-parameter \
  --name /layerv-nhp-sandbox/qurl-live-env-lock
```

Do not delete or deregister task definitions, ECR tags, or images until the
service is confirmed off them. Incident evidence and the cross-repository race
that introduced this guard are tracked in [#3244](https://github.com/layervai/nhp/issues/3244).
