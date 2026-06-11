# Runbook: NHP knock forward-path failures

## What fired

One of these NHP server CloudWatch alarms (per cell):

- `${name_prefix}-${cell_id}-knock-forward-failure` — `KnockForwardFailure`
  was non-zero in at least one 5-minute window in the trailing hour. The
  cross-server HTTP knock forward itself failed.
- `${name_prefix}-${cell_id}-knock-no-ac` — `KnockNoAC` was non-zero in at
  least one 5-minute window in the trailing hour. A knock returned a
  user-facing 500 (`ErrACConnectionNotFound`) because neither a local AC
  connection nor a forward could serve it.

Both are **single-event detectors** (`datapoints_to_alarm = 1` over a 1-hour
lookback), not rate alarms: at the current prod cadence of ~1 knock/hour a
"sustained rate" alarm could never accumulate, so they page on the first
occurrence. A single isolated page can therefore be one event — see
[deploy correlation](#first-five-minutes). For such a one-off the alarm
self-clears within ~1 hour, so expect a paired `ALARM` then `OK` notification
on the same SNS topic — the `OK` is the quieter half of the same transient, not
a second incident.

The "Knock Forward Health" dashboard widget plots all three counters
(`KnockForwardSuccess`, `KnockForwardFailure`, `KnockNoAC`) for the cell. At
current traffic all three normally rest at zero (the forward path is rarely
exercised), so the signal is any line lifting off zero.

## What it means

When the NLB hashes a qURL resolve / HTTP knock to an NHP server that holds no
local AC connection for the requested resource, the server **forwards** the
knock over HTTP to an assigned peer that does hold it
(`POST http://<peer-internal-ip>:8888/nhp/internal/knock`, see
[endpoints/server/http_forward.go](../../endpoints/server/http_forward.go)).
This is the designed safety net for AC-connection churn — most often blue/green
AC rolls, when a given AC's connection briefly lives on only a subset of
servers. When the forward path works it keeps user impact at ~0 while
connections move around.

The path is **cold** at current prod traffic: it is exercised only when a knock
lands on a server lacking the local AC, which is rare at ~1 knock/hour, so all
three counters normally read zero. That means there is little proof of how
forwarding behaves under load — any of these alarms firing is the first real
data point, so treat it as a genuine signal even if it is a single event.

Reading the dashboard, mind a blind spot: there is no `KnockForwardAttempt`
counter. A forward that completes at the transport layer (HTTP 200) but whose
peer returns a *structured* non-success ack — e.g. the peer also had no AC —
increments **neither** `KnockForwardSuccess` **nor** `KnockForwardFailure`; it
falls through to `KnockNoAC` only. So a zero `KnockForwardSuccess` does **not**
prove "no forward was ever attempted" (it could be forwards happening but all
returning structured no-AC), and these three counters alone can't distinguish a
truly cold path from that case — `KnockNoAC` rising while both forward counters
stay flat is the tell. (The synthetic-probe follow-up would close this gap.)

The two signals sit at different layers:

- **`KnockForwardFailure`** is the "forward machinery broke" signal. It
  increments whenever `ForwardHttpKnock` returns an error, which happens only
  after **every** assigned peer has failed (it shuffles and retries across the
  assigned set, skipping recently-failed targets). So a single flaky peer does
  not trip it — it isolates a genuine forward fault. The original incident
  (#2449) was exactly this: the forwarder shipped a request missing `resId`,
  every receiver replied `400 "missing aspId or resId"`, and a non-2xx response
  surfaces as an error here.
- **`KnockNoAC`** is the broad user-impact signal (the 500 driver). It is a
  superset of `KnockForwardFailure`: it also fires when the forward is never
  attempted (no forwarder configured, an already-forwarded hop, or the hop
  ceiling) and when a peer that received the forward also had no AC. `KnockNoAC`
  rising with flat `KnockForwardSuccess` is the "forwarding is broken or no
  server holds this AC" picture. **Origin matters:** `KnockNoAC` is emitted from
  two paths — the HTTP resolve handler (`httpserver.go`, the forward-capable
  path this runbook centers on) **and** the native NHP agent UDP knock path
  (`udpserver.go`), which has **no** HTTP forwarder at all. A `knock-no-ac` page
  driven by UDP knocks means a knock hit a no-local-AC server with no forward
  ever attempted, so the forward-rejection triage below (400/401, request shape,
  `/nhp/internal/knock`) does not apply — check `KnockForwardFailure`/`Success`
  (both flat ⇒ no forward was in play) and look for the UDP `handleNhpOpenResource`
  "no ac connection is available" warning rather than the HTTP one.

If `KnockForwardFailure` is firing, start there — it isolates the fault to the
forward hop. If only `KnockNoAC` is firing, the forward hop may be transporting
fine but no peer holds the AC (a genuine coverage gap, including a brief
back-to-back AC-deploy window where every replica of one AC is mid-restart), or
forwarding is being skipped.

Because `KnockNoAC` is a superset, a genuine broken-forward event trips **both**
alarms at once, and each self-clears within ~1 hour — so one root cause can emit
up to **four** notifications on the alerts topic (`knock-forward-failure`
ALARM+OK and `knock-no-ac` ALARM+OK). That is **one incident**, not four: treat
a simultaneous pair as the broken-forward signature and start with
`knock-forward-failure`.

## First five minutes

1. Check recent NHP deploys / Terraform applies — an AC roll in progress
   explains a transient `KnockNoAC` blip but not a sustained
   `KnockForwardFailure`:
   ```bash
   gh run list -R layervai/nhp --limit 10
   ```
2. In NHP server logs (`docker exec nhp-server cat
   /nhp-server/logs/server-$(date +%Y-%m-%d).log`), search for
   `knock forward`, `HTTP knock forward to`, `no ac connection is available`,
   and `all AC operations failed`. A repeating `server returned 400` /
   `server returned 401` / `remote error:` in the forward warnings names the
   receiver-side rejection.
3. Confirm AC peer coverage for the cell: is `ACPeerCount` non-zero and is the
   `ac-peer-count-low` alarm clear? If ACs are genuinely absent fleet-wide,
   that is the upstream cause — triage AC registration first.
4. Identify the receiver rejection class from step 2:
   - **400 (bad request)** — the forwarded body is missing a field the receiver
     requires (the #2449 signature). Check whether a recent server change
     altered the forward request shape (`HttpKnockForwardRequest` /
     `/nhp/internal/knock` handler).
   - **401 (unauthorized)** — `NHP_INTERNAL_AUTH_SECRET` drift between sender
     and receiver; the HMAC over (method, path, body) won't verify. See
     [SECURITY.md](../SECURITY.md). A half-rolled secret rotation does this.
   - **Forward hop attestation** — `ForwardHopAttest*` counters climbing on the
     receiver in strict mode means a stale assignment pubkey vs. Cloud Map
     pubkey divergence (#1127); see the forward-hop attestation design doc.
5. Confirm the path stays inside the private VPC: forwards target RFC-1918
   peers on port 8888 and the receiver requires a private source IP. A
   re-terminating proxy or public edge in front of `/nhp/internal/knock`
   turns valid forwards into 4xx (see `terraform/CLAUDE.md`,
   "qurl-reverse-tunnel-server NHP validator origin").

## Mitigation

1. If a recent NHP server deploy changed the forward request shape or the
   `/nhp/internal/knock` handler, **roll it back** — the forward path is a
   silent safety net, so a regression here is invisible to most consumers
   (qurl-service retries hide it) until a non-retrying probe hits a no-AC
   server.
2. If an in-flight `NHP_INTERNAL_AUTH_SECRET` rotation left sender and receiver
   on different secrets, complete or revert the rotation so the whole fleet
   shares one secret.
3. If ACs are genuinely absent (upstream `ac-peer-count-low`), recover AC
   registration; the forward net cannot rescue a knock when **no** server holds
   the AC.
4. There is no safe "disable forwarding" mitigation — disabling it converts
   every churn-window no-local-AC knock straight into a user-facing 500.

## After recovery

1. `KnockForwardFailure` / `KnockNoAC` stop incrementing and the dashboard
   widget returns to flat zero (the resting state — `KnockForwardSuccess` only
   climbs while the safety net is actively in use, so it is not expected to
   "track" in steady state).
2. Both alarms settle out of `ALARM`. Note that these sparse counters normally
   have no data, so the resting state is `OK` or `INSUFFICIENT_DATA` — that is
   **not** a dim-set mismatch. To verify the alarm's dimension set still matches
   the live publisher, check a regularly-emitted sibling (`KnockRequest`) or
   `aws cloudwatch list-metrics --namespace LayerV/NHP`, not the failure alarm's
   state.
3. Re-run the resolve smoke probe (the single-shot, non-retrying consumer that
   surfaced #2449) and confirm it succeeds against a server with no local AC.

> **Long-term:** because the forward path is cold, these passive counters only
> fire when real traffic happens to hit the broken path. A synthetic probe that
> periodically forces a forward (exactly how #2449 was found) is the stronger
> detector and is the recommended follow-up — these alarms are the immediate,
> traffic-driven safety net, not a substitute for it.
