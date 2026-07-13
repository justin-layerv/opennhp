# Assigned-cell public UDP flood readiness

This runbook is the production-rollout gate for direct UDP SDK traffic. It does
not gate the HTTPS-only browser relay.

## Accepted design

The server keeps the existing `MaxConcurrentHandlers = 4096` ceiling but splits
it into two non-blocking partitions:

- 3,072 general slots accept ordinary agent-facing work.
- 1,024 protected slots accept only `NHP_RKN` after core verifies its stateless
  overload cookie, or `NHP_RLY` after the configured relay's outer Noise
  identity authenticates.

When the general partition fills, the server enables overload-cookie mode.
Fresh `NHP_KNK` traffic is challenged before body/plugin/AC-open work; a client
that receives the challenge can return the source-bound cookie as `NHP_RKN` and
use protected capacity. A source-spoofed sender cannot receive the cookie.
Cookie mode remains on until general occupancy falls to 75% or lower, avoiding
flapping. Connection-count and handler-pressure overload reasons are combined;
recovery in one cannot clear the other.

The reserve protects progress, not unlimited throughput. A return-routable
distributed client holding valid agent credentials can still fill it. The
`HandlerProtectedReserveExhausted` alarm is the explicit signal that the
progress guarantee was lost.

All UDP edge single-event alarms use one breaching five-minute bucket in a
trailing one-hour window (`1 of 12`). A single reserve, receive-buffer,
decrypt-queue, or collector event can therefore keep its alarm in `ALARM` for
up to an hour after the last breach. That dwell is deliberate: even a brief
pre-admission or bounded-queue loss invalidates the readiness guarantee, and
the sticky alarm preserves an operator-visible incident breadcrumb rather than
auto-clearing before investigation.

## Evidence layers

Read these dashboard panels together:

1. **Public UDP NLB Traffic and Rejects** — processed packets, rejected flows,
   and NLB-security-group UDP rejects.
2. **Host and Kernel UDP Admission** — exact UDP/62206 ingress, per-source and
   aggregate iptables drops, UDP errors, and receive-buffer drops. High-rate
   sources are shed before the shared aggregate allowance, so they cannot
   randomly displace a low-rate legitimate client.
3. **Application UDP Sheds** — application per-source limit, decrypt/decrypted
   queue drops, general/protected handler sheds, and connection-cap rejects.
4. **Application UDP Capacity** — handler occupancy, protected occupancy,
   decrypt queues, goroutines, and heap.

`nhp-udp-edge-metrics.timer` reads `/proc/net/snmp`, the UDP/62206 socket's
`/proc/net/udp*` drop counter, and uniquely commented iptables rules every
minute, then writes CloudWatch EMF into the existing server log path.
`UDPEdgeCollectorHeartbeat` must be present and
`UDPEdgeCollectorError` must remain zero. Missing/duplicate rule markers are an
error, never a synthetic zero. When the aggregate cap is explicitly disabled,
its marker is the one permitted absence and its metric is emitted as zero.
The EMF file intentionally matches the CloudWatch Agent's `server-*.log` glob,
so the server log group contains both plaintext application lines and
machine-readable collector documents; downstream parsing must select by shape.
The fixed collector file is covered by `/etc/logrotate.d/nhp-udp-edge-metrics`
(`daily`, seven rotations, 10 MiB max-size trigger, compression, `copytruncate`),
so it cannot grow without bound on a long-lived instance while the agent tails
the same inode. Rotation relies on the host's standard daily logrotate schedule;
monitor that timer with the rest of the base-instance services.

The server container deliberately runs with `--net=host`; the collector relies
on that deployment contract so `/proc/net/udp*` contains the UDP/62206 listen
socket. Moving the server to a private network namespace requires moving this
collector into that namespace in the same change. Until then, a missing socket
fails loud as `UDPEdgeCollectorError`.

Bootstrap also refuses to install the collector with Python older than 3.10,
which is required by its strict zip and modern type annotations. This is a
cloud-init failure rather than a timer that appears healthy but never emits.

### What the rehearsal proves

The flood runners use invalid random datagrams by design and never receive the
canary private key; only the independent valid-SDK probe gets that sandbox-only
credential. Garbage packets must fail before decrypted handler dispatch. The
rehearsal proves the real NLB, iptables, socket buffer, decrypt
admission, process-resource bounds, external valid-SDK SLO, and UDP/62207
absence. It does **not** pretend random datagrams execute the protected handler
partition. That concurrency contract is proved deterministically by
`TestDispatchHandler_ProtectedReservePreservesRKNProgress` and
`TestDispatchHandler_ProtectedReserveExhaustionIsDistinct`, which fill both
partitions with parked handlers and verify that unproven KNKs cannot consume the
reserve while core-verified RKNs progress. The live workflow still requires the
handler gauges to exist and remain within their hard bounds, catching wiring or
runtime regressions without treating near-zero occupancy as saturation proof.

## Sandbox canary prerequisites

The GitHub `sandbox` environment contains:

- `NHP_UDP_READINESS_AGENT_PRIVATE_KEY_B64` — a sandbox-only Curve25519 key
  whose public half is registered in the sandbox `qurl-agent-keys` table;
- `NHP_UDP_READINESS_SERVER_PUBLIC_KEY_B64` — the sandbox cell server public
  key.

The synthetic identity is registered only in sandbox and the private key is not
a production credential. If it is rotated, update the DDB registration and
environment secret together; a mismatch must fail the real SDK probe.

## Run the deterministic rehearsal

Dispatch **Assigned-cell UDP flood readiness** on the reviewed SHA. Defaults
run eight GitHub-hosted sources at 2,000 pps each for five minutes. Each source
rotates 64 UDP source ports. This is deliberately described as *spoof-like*:
the runner/provider prevents arbitrary forged source addresses, while multiple
runners plus rotating tuples exercise distributed/source-rotation behavior in
an auditable way.

Every flood and probe artifact records its actual `started_epoch` and
`ended_epoch`. Verification requires all eight flood artifacts plus the probe,
rejects any start more than 30 seconds late, and requires at least
`duration_seconds - 30` seconds of common overlap. Hosted-runner queueing can
therefore invalidate the rehearsal, but it cannot silently turn reduced or
missing concurrency into a passing SDK SLO.

The workflow rejects a custom per-runner rate at or below 100 pps before the
start epoch because it cannot prove the 100 pps/source host hashlimit engaged;
such a run is invalid evidence, not a lighter passing rehearsal. The verifier
also keeps host-wide kernel receive errors, aggregate hashlimit drops, and
application connection-cap rejections as diagnostic report fields rather than
zero-tolerance gates: the first can include unrelated UDP, while the latter two
are permitted fail-safe sheds when the exact per-source and SDK SLO gates pass.

At the same start epoch, an independent hosted runner uses the real Go NHP SDK
to knock `agent/qurl-tunnel-server` once per second from outside every LayerV
VPC. The default SLO is:

- at least 99% successful NHP ACKs (`errCode=0`);
- successful-knock p99 at or below 2,000 ms.

The probe artifact's `p99_ms` and `max_ms` summarize successful knocks only;
failed attempts are represented by `success_ratio` and `last_error`, not folded
into the latency distribution.

The workflow first proves the target is the assigned cell's public NLB, that
its only UDP-capable listener is UDP 62206, and that 62207 is absent. After the
run it waits for CloudWatch ingestion, re-runs the live topology detector, and
fails unless:

- the per-source host hashlimit actually dropped packets (the test reached the
  intended admission boundary); aggregate drops are also recorded if the
  remaining distributed load reaches that backstop;
- CPU is at or below the declared ceiling (95% by default), heap is at or below
  1 GiB, goroutines at or below 10,000, handlers at or below 4,096, and protected
  handlers at or below 1,024;
- receive-buffer, decrypt-queue, decrypted-queue, collector-error, and protected-
  reserve-drop counters remain zero;
- always-emitted host/heartbeat and application gauge metrics have datapoints.
  Event-only Go drop counters are permitted to have no series when their healthy
  value is zero; any datapoint they do emit must still sum to zero.

Archive the three artifact groups: eight flood transcripts, the valid SDK
probe summary, and topology/capacity evidence. Record the workflow URL and
reviewed SHA in the rollout ledger before enabling direct UDP SDK traffic.

## Failure interpretation

- `UDPPerSourceRateLimitDrop = 0`: invalid rehearsal; the offered load did not
  reach the intended per-source host boundary.
- aggregate drops: the remaining source-capped traffic reached the distributed
  backstop. A concurrent SDK SLO failure means the shared kernel ceiling, not
  the handler reserve, is the limiting layer.
- collector error during a deployment: verify the UDP/62206 socket count. The
  host-network contract expects one listener per host; two `SO_REUSEPORT`
  listeners or a transient old/new process overlap intentionally fail closed
  until the host converges to one.
- `UDPReceiveBufferDrop > 0`: packets died before application admission; tune
  the host/NLB/fleet, not the Go handler reserve. Even one transient drop is an
  intentional hard failure of the rehearsal, not a warning or verifier bug.
- decrypt/decrypted queue drop: crypto/message pipeline saturated before the
  handler partition; do not widen handlers.
- general handler sheds with protected reserve healthy: cookie progression is
  preserving capacity as designed.
- protected reserve sheds or SDK SLO failure: direct UDP rollout remains
  blocked. Add capacity or strengthen proof/admission before retrying.

## Rollback

Re-running cloud-init/user-data on a live instance installs a top-of-chain
UDP/62206 drop guard while replacing admission rules, so knocks fail closed for
that brief maintenance window. Drain or replace the instance instead when the
cell cannot tolerate that intentional blackhole.

Revert the server partition/telemetry change and refresh the sandbox server ASG
to the last reviewed image/template. This restores one 4,096-slot pool and the
old host rules; it also removes the new evidence, so direct UDP SDK rollout
becomes blocked again. Never "fix" a failed rehearsal by weakening the
assertions, disabling the aggregate hashlimit, or raising limits without a new
measurement.
