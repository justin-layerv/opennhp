# Observability: CloudWatch Metrics

NHP components publish application metrics to the **`LayerV/NHP`** CloudWatch
namespace. Deploy automation publishes revocation deploy-window suppressor
metrics to the deploy-only **`LayerV/NHP/Deploy`** namespace.

## Shared Dimensions

Every metric includes these base dimensions:

| Dimension | Source | Description |
|-----------|--------|-------------|
| `Environment` | Server: `NHP_ENVIRONMENT` env var; AC: `Environment` in `ac.toml` | Deployment environment (e.g., `sandbox`, `prod`) |

Components add their own dimensions on top:

| Component | Extra Shared Dimensions |
|-----------|------------------------|
| Server | `Cell` — cell identifier (`NHP_CELL_ID` env var, default `cell0`) |
| AC | `Component` — always `"AC"` to distinguish from server metrics; `Region` — AWS region (from `AWS_REGION` env var, omitted if unset) |

## Server Metrics

| Metric | Type | Extra Dimensions | Description |
|--------|------|------------------|-------------|
| `KnockRequest` | Counter | — | Total NHP knock packets received |
| `AuthSuccess` | Counter | — | Successful authentication attempts |
| `AuthFailure` | Counter | — | Failed authentication attempts |
| `KnockLatency` | Latency (ms) | — | End-to-end knock processing time |
| `StorageHealthy` | Gauge (0/1) | — | etcd storage health probe |
| `ServerForwardTargetDrop` | Counter | — | Outbound NHP_FWD target preparation dropped because the peer/tuple was not a configured server target or was owned by a non-promotable connection. Steady state is zero; see [server forward-send safety](runbooks/server-forward-safety.md). |

## Server Log-Derived Metrics

The monitoring module also derives cell-scoped server metrics from CloudWatch
Logs. These metric names bake `Environment` and `Cell` into the metric name
because the log group, not the JSON event body, carries those values.
They are not emitted by the server CloudWatch publisher, so fleet-wide rollups
must enumerate the cell-scoped metric names instead of grouping by dimensions.

| Metric | Source Log Group | Description |
|--------|------------------|-------------|
| `ServerPanic-<environment>-<cell>` | `/layerv/nhp/<env>/<cell>/server-stderr` | Raw Go `panic:` output written to stderr. Each match normally means the process restarted. |
| `ServerAsyncRuntimePanic-<environment>-<cell>` | `/layerv/nhp/<env>/<cell>/server` | Structured `msgToPacketRoutine` async `ErrRuntimePanic` recovery. The process stayed up, but the outbound message was dropped. |

## AC Registration Metrics

All AC metrics include the shared `Environment` and `Component` dimensions. Some include additional per-metric dimensions as noted.

| Metric | Type | Extra Dimensions | Description |
|--------|------|------------------|-------------|
| `RegistrationAttempts` | Counter | — | Registration attempts (counted after validation, so Attempts == Success + Failure) |
| `RegistrationSuccess` | Counter | `RegistrationType` | Successful registrations. Type is `Redispatch` (multi-server) or `Direct` (single-server) |
| `RegistrationFailure` | Counter | `ACId`, `ErrorCode` | Failed registrations. ErrorCode is the server's error code or `registered_false` |
| `RegistrationLatency` | Latency (ms) | — | End-to-end registration time (NHP_AOL send to response received) |
| `ServerConnections` | Counter | `ConnectionType` | Successful server connections. Type is `Redispatch` |
| `ServerConnectionFailure` | Counter | `ACId`, `ErrorCode` | Individual server connection failures during redispatch. ErrorCode is classified (see below) |
| `ServerHealthFailures` | Counter | `ACId` | Server detected as down by keepalive health checks |
| `ReregistrationTriggers` | Counter | `ACId`, `Reason` | Re-registration triggered. Reason is classified (see below) |
| `DiskUsagePercent` | Gauge (%) | `InstanceId` | Root filesystem disk usage. Published by shell script via SSM every 30 min |

### Error Classification (`ErrorCode` dimension)

The `classifyError()` function maps errors to a bounded set of categories to prevent unbounded CloudWatch cardinality:

| Category | Matches |
|----------|---------|
| `timeout` | Timeout errors, deadline exceeded, `net.Error` with `Timeout()` |
| `connection_error` | Connection refused, connection reset |
| `crypto_error` | ECDH, decrypt, encrypt failures |
| `dns_error` | DNS resolution failures, no such host |
| NHP error codes | Typed `common.Error` values (e.g., `ErrTransactionFailedByTimeout`) |
| `other` | Anything else |

### Reason Classification (`Reason` dimension)

The `classifyReason()` function bounds re-registration trigger reasons:

| Value | Description |
|-------|-------------|
| `refresh_redirect` | Server responded with redirect during registration refresh |
| `server_connection_timeout` | Server connection timed out |
| `connection_timeout` | General connection timeout |
| `other` | Any unrecognized reason |

## Publisher Infrastructure Metrics

Emitted by the CloudWatch publisher itself (`endpoints/metrics/publisher.go`),
carrying each component's base dimension set (Server: `{Environment, Cell}`;
AC: `{Component, Environment, Region}`).

| Metric | Type | Description |
|--------|------|-------------|
| `PublisherFailures` | Counter | One per `PutMetricData` batch that errored during flush. Surfaces a publisher that is partially/intermittently dropping metrics. Does **not** cover total publisher death (nil publisher from missing AWS config) — that rides the same dead channel and is caught by the absence alarms (`ac-registration-stale`, `server-cloudmap-register-refresh-heartbeat`). See #1707. |
| `CheckpointWriteFailure` | Counter | One per failed periodic checkpoint write to disk (disk full, perms, unmounted dir). |

> **`PublisherFailures` is a presence signal, not a rate.** Its per-flush
> magnitude scales with the number of metric series (batch count), and a failure
> is attributed to the CloudWatch window of the *next successful* flush that
> carries it — so the alarms key on `Sum > 0`, not on magnitude. Don't threshold
> on or chart the value as a "failure rate"; it isn't one.

## Cardinality Design

CloudWatch charges per unique metric time series (unique combination of namespace + metric name + dimensions). To control costs:

- **`ACId` is only on failure/debug metrics** — not on success paths, keeping the high-volume happy path low-cardinality.
- **Error strings are never used as dimensions** — `classifyError()` maps to a finite set of categories.
- **Server IPs are never used as dimensions** — they change on every ASG launch, creating unbounded cardinality.
- **Re-registration reasons are classified** — `classifyReason()` maps to a known set.

## IAM Permissions

Both server and AC IAM roles need `cloudwatch:PutMetricData` for the
`LayerV/NHP` namespace and explicitly deny `LayerV/NHP/Deploy` so ordinary app
metric publishers cannot suppress qURL revocation age-out paging. This is
configured in:

- Server: `terraform/modules/compute/main.tf` (`cloudwatch_metrics` IAM policy)
- AC: `terraform/modules/ac/main.tf` (`cloudwatch_metrics` IAM policy)

Deploy workflows use the GitHub Actions Terraform apply role, whose
`cloudwatch:PutMetricData` grant is namespace-scoped to the app, deploy-window,
and blue/green deployment-count namespaces in `terraform/modules/ecr/main.tf`.

## Existing Alarms

### `LayerV/NHP` namespace

| Alarm | Metric | Component |
|-------|--------|-----------|
| `StorageHealthy` | `StorageHealthy` | Server |
| `AuthFailure` | `AuthFailure` | Server |
| `KnockLatency` | `KnockLatency` | Server |
| `DiskUsagePercent` | `DiskUsagePercent` | AC (shell script) |
| `server-forward-target-drop` | `ServerForwardTargetDrop` | Server direct counter |
| `server-async-runtime-panic` | `ServerAsyncRuntimePanic-<environment>-<cell>` | Server log-derived filter |
| `RegistrationFailure` | `RegistrationFailure` | AC (>5 failures in 5 min) |
| `ServerConnectionFailure` | `ServerConnectionFailure` | AC (>10 failures in 10 min, 2 consecutive periods) |
| `ac-publisher-failures` | `PublisherFailures` | AC (>0 in 2 of last 3 five-min windows) |
| `server-publisher-failures` | `PublisherFailures` | Server (>0 in 2 of last 3 five-min windows) |
