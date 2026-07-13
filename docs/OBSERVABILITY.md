# Observability: CloudWatch Metrics

NHP components publish application metrics to the **`LayerV/NHP`** CloudWatch
namespace. Deploy automation publishes revocation deploy-window suppressor
metrics to the deploy-only **`LayerV/NHP/Deploy`** namespace.

## Sandbox Relay DMZ Telemetry

The dedicated relay DMZ is sandbox-only; production remains relay-dark with
`deploy_relay=false`. Once the sandbox DMZ is applied, its network boundary has
two KMS-encrypted CloudWatch Logs sources:

| Source | Log Group | Retention | Purpose |
|--------|-----------|-----------|---------|
| VPC Flow Logs (`ALL`, 60-second aggregation) | `/layerv/nhp/sandbox/relay-dmz/flow` | 30 days | Accepted/rejected IP flows, packet/original addresses, AWS service fields, flow direction, and traffic path |
| Route 53 Resolver query logs | `/layerv/nhp/sandbox/relay-dmz/resolver` | 30 days | DNS allow/block decisions, including DNS Firewall rule action |

The production retention contract is 365 days if a separate production-enable
change ever creates the DMZ there. A dedicated relay-DMZ CMK encrypts these two
groups; its CloudWatch Logs grant is restricted by caller account, regional Logs
`kms:ViaService`, and encryption contexts naming exactly the Flow and Resolver
log groups. The dedicated key adds roughly $1/month and avoids changing the
shared Logs key or creating a production delta while production is relay-dark.
The DGA, dictionary-DGA, and DNS-tunneling controls use Route 53 Resolver DNS
Firewall Advanced, which adds its per-query analysis charge on top of standard
DNS Firewall and query-log ingestion; include that variable usage cost in the
sandbox budget and re-check current AWS pricing before any production enablement.

VPC Flow Logs do **not** record queries sent to AmazonProvidedDNS. Resolver
query logs are therefore the authoritative evidence for DNS allowlisting and
tunneling/DGA blocks; do not infer DNS behavior from an absence of flow records.

The relay has one public edge: the browser ALB on HTTPS 443. Its target-health,
WAF, access-log, application, and `RelayShed` signals describe the HTTPS relay
path only. The relay has no native NHP NLB alarms because it owns no public UDP
edge.

Direct SDK UDP telemetry belongs to the assigned cell's public NHP server NLB
and server metrics. Deployment evidence includes a real external UDP 62206
round trip to that server NLB plus listener/SG/Flow proof that no public UDP
listener other than 62206 exists. A UDP timeout alone is not closure evidence.

The Resolver log group's `BLOCK` events produce the no-dimension
`LayerV/NHP/RelayDmzDnsBlocked` metric. The
`<name-prefix>-relay-dmz-dns-blocked` alarm pages on the first blocked query and
also emits an OK notification on recovery. The controlled functional-gate
`example.com` lookup remains in Resolver logs but is excluded from this metric,
so routine deploy verification does not page. Any other block means an
unexpected runtime dependency or possible exfiltration attempt.
See [Relay CloudWatch alarms](runbooks/relay-alarms.md) and the
[sandbox DMZ replacement runbook](runbooks/sandbox-relay-dmz-replacement.md).

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
| `UDPRateLimitDrop` | Counter | — | Datagram dropped by the application per-source limiter before crypto work. |
| `PacketDecryptQueueDrop` | Counter | — | Bounded decrypt queue was full; steady state and flood-readiness target are zero. |
| `DecryptedMessageQueueDrop` | Counter | — | Bounded decrypted-message queue was full; steady state and flood-readiness target are zero. |
| `HandlerBudgetExhausted` | Counter | — | Total distinct agent-facing dispatch sheds because eligible partitions were full; includes every protected-reserve exhaustion. |
| `HandlerProtectedReserveExhausted` | Counter | — | Subset of `HandlerBudgetExhausted` where cookie-proven RKN or authenticated relay work exhausted both partitions; do not add the counters without subtracting this overlap. |
| `HandlerInFlight` | Gauge | — | Best-effort sum of general (3,072) plus protected (1,024) agent-facing handlers. The two partitions are sampled independently, so a scrape may span one admission/release transition; hard ceiling 4,096. |
| `HandlerProtectedInFlight` | Gauge | — | Protected-reserve handlers. Hard ceiling 1,024. |
| `HandlerPressureOverload` | Gauge (0/1) | — | Handler pressure is holding overload-cookie mode on. |
| `PacketDecryptQueueDepth` | Gauge | — | Current bounded inbound decrypt queue occupancy. |
| `DecryptedMessageQueueDepth` | Gauge | — | Current bounded decrypted-message queue occupancy. |
| `RuntimeGoroutine` | Gauge | — | Current Go goroutine count for flood-readiness bounds. |
| `RuntimeHeapAllocBytes` | Gauge (bytes) | — | Current Go heap allocation for flood-readiness bounds. |

Host EMF metrics add `InstanceId` series plus an `{Environment,Cell}` rollup:
`UDPIngressDatagram`, `UDPKernelReceiveError`, `UDPReceiveBufferDrop`,
`UDPGlobalRateLimitDrop`, `UDPPerSourceRateLimitDrop`,
`UDPEdgeCollectorError`, and `UDPEdgeCollectorHeartbeat`. See the
[assigned-cell UDP flood-readiness runbook](runbooks/assigned-cell-udp-flood-readiness.md)
for layer-by-layer interpretation and enforced live-test bounds.

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

## AC L3 Flush Metrics

All AC L3 flush metrics include the AC shared dimensions. Netlink-specific
conntrack metrics are flat (for always-registered gauges) or absent unless the
AC is running `l3FlushConntrackBackend = "netlink"`.

| Metric | Type | Description |
|--------|------|-------------|
| `L3FlushConntrackDeleted` | Gauge | Cumulative conntrack entries deleted by the netlink backend. |
| `L3FlushConntrackSlowDumps` | Gauge | Cumulative per-Flush dumps over the slow threshold. Use as a coarse fallback/authoritative-dump signal. |
| `L3FlushConntrackDumpLatency` | Histogram (ms) | Successful per-Flush fallback/authoritative netlink dump duration distribution, published with CloudWatch `Values`/`Counts` so percentiles can be queried for the <=200us/op steady-state soak gate. Indexed fast-path Flushes, failed dump attempts, and startup/resync backfill dumps do not produce samples; dump errors/timeouts ride `L3FlushFlushErr` and breaker metrics. Values are rounded to microseconds and floored at `0.001` ms, so low percentiles are not sub-microsecond ground truth. |
| `L3FlushConntrackDumpLatencyDropped` | Counter | Per-window delta of dump-latency samples dropped because the local histogram buffer filled before the publisher drained it. Alarm on period `Sum > 0`; nonzero means the matching histogram window is incomplete. Pair with `L3FlushConntrackDumpLatencyPublisherDropped` for generic publisher cap/invalid-sample drops. |
| `L3FlushConntrackDumpLatencyPublisherDropped` | Counter | Generic histogram publisher guardrail for `L3FlushConntrackDumpLatency`: publisher cap overflow or invalid NaN/Inf samples filtered before `PutMetricData`. Alarm on period `Sum > 0` with `L3FlushConntrackDumpLatencyDropped`; steady state is zero and any datapoint means the histogram window is incomplete or instrumentation changed. |
| `L3FlushConntrackDumpLatencyNegativeDurations` | Gauge | Cumulative impossible negative dump-duration measurements ignored before histogram buffering. The current `time.Since` call path cannot produce this; it is a future-caller/instrumentation guard. Steady state is zero; alarm on nonzero value or increase, not period sum. |
| `L3FlushConntrackIndexedFlushes` | Gauge | Cumulative Flush calls served from the conntrack event index. |
| `L3FlushConntrackIndexFallbackDumps` | Gauge | Cumulative Flush calls that fell back to the O(table) dump path because the event index was unavailable or unhealthy. |
| `L3FlushConntrackIndexAuthoritativeDumps` | Gauge | Cumulative immediate-revocation Flush calls that intentionally used fresh kernel ground truth. |
| `L3FlushConntrackIndexEventErrors` | Gauge | Cumulative conntrack multicast stream errors that disable indexed Flush until resync. |
| `L3FlushConntrackIndexPendingOverflows` | Gauge | Cumulative startup pending-buffer overflows during event-index backfill. |
| `L3FlushConntrackIndexEvents` | Gauge | Cumulative valid conntrack events observed by the event index. |
| `L3FlushConntrackIndexOrigins` | Gauge | Current full-origin tuple count mirrored in userspace by the event index. |
| `L3FlushConntrackIndexResyncAttempts` | Gauge | Cumulative runtime event-index resync attempts. |
| `L3FlushConntrackIndexResyncSuccesses` | Gauge | Cumulative successful runtime event-index resyncs. |
| `L3FlushConntrackIndexResyncFailures` | Gauge | Cumulative failed runtime event-index resyncs. |

If the generic metrics publisher ever drops histogram samples after collection,
or filters invalid NaN/Inf samples, it emits `<metric>PublisherDropped`. That
generic signal intentionally merges those should-never-happen guardrail causes.
For `L3FlushConntrackDumpLatency`, the AC-local cap intentionally matches the
publisher cap and the producer emits finite values, so the reachable drop signal
is the AC flusher's own `L3FlushConntrackDumpLatencyDropped`; a
`L3FlushConntrackDumpLatencyPublisherDropped` datapoint would indicate a future
producer exceeded or bypassed the generic publisher guardrails.

At the 10k-sample cap with fully unique microsecond-rounded values, the
histogram emits at most 67 `MetricDatum` entries, about four `PutMetricData`
batches per netlink AC per 60s flush. That bounded cost is acceptable for the
netlink soak; monitor `PublisherFailures` if fleet size or flush cadence changes.
Histograms intentionally skip the EMF/stdout path and publish only through
direct `PutMetricData` Values/Counts, so EMF-only consumers will not see this
distribution.
Do not treat a healthy `L3FlushConntrackDumpLatency` percentile by itself as
proof that dump work is healthy: failed or timed-out dumps do not emit histogram
samples, and startup/runtime resync backfill durations are intentionally outside
both this histogram and `L3FlushConntrackSlowDumps`. Read the histogram with
`L3FlushFlushErr`, breaker metrics, resync success/failure gauges, and the
explicit backfill wall-time evidence required by the rollout gate.
The histogram is best-effort per flush window: samples are drained from the AC
buffer immediately before `PutMetricData`, so a failing publish batch is not
replayed and should be read together with `PublisherFailures`. Companion
counters emitted by the same drain are added to the same flush window, but still
follow the publisher's normal counter checkpoint semantics across restarts
because they use the regular counter plumbing.

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
