# Runbook: NHP server forward-send safety

## What fired

One of these NHP server CloudWatch alarms fired for a cell:

- `${name_prefix}-${cell_id}-server-forward-target-drop`: `ServerForwardTargetDrop`
  was non-zero in at least one 5-minute window in the trailing hour.
- `${name_prefix}-${cell_id}-server-async-runtime-panic`: the structured server
  logs contained an async `ErrRuntimePanic` recovery from `msgToPacketRoutine`
  in the last 5 minutes.

Both signals should be zero in steady state. They were added after PR #2673:
that PR made residual async packet-send panics recover into dropped messages
instead of restarting the process, and added `ServerForwardTargetDrop` for
unsafe outbound NHP_FWD target preparation.

## What it means

`ServerForwardTargetDrop` is emitted by the server publisher with
`{Environment, Cell}` dimensions. It means `SendMessage` refused to prepare an
outbound server-to-server NHP_FWD connection because the requested peer/tuple
was not a configured NHP server target, or because the same UDP tuple was
already owned by a non-promotable AC/DB/WebRTC connection. Treat this as
assignment/peer-map drift or a tuple-owner collision until proven otherwise.
Because this is a sparse direct counter, the dashboard can render the Target
Drop series as no data when healthy; empty and zero both mean no drops. The
async recovery series is log-filter-derived and should render flat zero when
healthy.

`server-async-runtime-panic` is log-derived from the structured server log group
(`/layerv/nhp/<env>/<cell>/server`). It matches the stable recovery line from
`msgToPacketRoutine`: the process survived, but the affected outbound message
was dropped. The stack trace in the log event is the primary evidence.
This signal is broader than NHP_FWD: it spans any outbound message type routed
through `msgToPacketRoutine` (for example knock responses, AC/DB operations, or
NHP_FWD). `ServerForwardTargetDrop` is the forward-specific signal.
This alarm is intentionally scoped to `msgToPacketRoutine`; add or widen a
filter if another structured `recover()` site starts converting
`ErrRuntimePanic` into dropped work instead of a stderr crash.

## First five minutes

1. Check whether a recent NHP server deploy, server assignment change, or peer
   map change overlaps the first breaching datapoint:

   ```bash
   gh run list -R layervai/nhp --limit 10
   ```

2. For `ServerForwardTargetDrop`, search structured server logs for:

   ```text
   is not a known server peer target
   already owned by non-promotable connection
   SendMessage dropping outbound connection
   SendMessage failed to prepare outbound connection
   ```

   When paired with a `ServerForwardTargetDrop` datapoint, the unknown-target
   warning points at assignment/peer-map drift and the error path points at a
   tuple-owner collision. Similar `SendMessage dropping outbound connection`
   warnings for global-cap rejection or shutdown do not increment
   `ServerForwardTargetDrop`; use the specific substrings above to avoid
   mixing those unrelated cases into this alarm's triage.

3. For `server-async-runtime-panic`, search the structured server log group for:

   ```text
   msgToPacketRoutine
   runtime panic encountered
   recovered from panic
   ```

   Capture the stack trace after `!!!recovered from panic:` before the log
   retention window rolls.

4. Correlate with the forward-path dashboard. If `KnockForwardFailure`,
   `KnockNoAC`, or qURL 5xx alarms are also firing, move to the broader
   forward-path or qURL runbooks after preserving the local stack/log evidence.

## Mitigation

1. If the alarm correlates with a recent server release that touched
   `SendMessage`, NHP_FWD forwarding, peer assignment, or core packet assembly,
   roll back that server release while investigating.
2. If `ServerForwardTargetDrop` points at assignment or peer-map drift, restore
   the expected NHP server peer entries before relying on retries. The forward
   send path intentionally fails closed instead of reusing an arbitrary tuple.
3. If the async runtime panic repeats, treat it as an availability regression
   even if the process is not restarting. The recovery prevented a crash, but it
   still dropped outbound messages.

## After recovery

1. `ServerForwardTargetDrop` stops incrementing and the alarm exits `ALARM`
   after its trailing-hour lookback clears.
2. `server-async-runtime-panic` stops incrementing and exits `ALARM` after the
   next clean 5-minute evaluation window.
3. Preserve links to the relevant CloudWatch Logs Insights query or log events
   in the PR/incident thread, especially for async panic stack traces.
