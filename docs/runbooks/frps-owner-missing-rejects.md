# Runbook: FRPS reverse-tunnel `owner_missing` rejects

## What fired

`${name_prefix}-frps-owner-missing-rejects` — the `FRPSOwnerMissingRejectCount`
metric (namespace `LayerV/NHP`) summed **≥ `owner_missing_reject_threshold`**
(default 5) over a single 5-minute window and paged through the shared cell
alerts SNS topic. The metric increments on every frps log line carrying the
byte-stable wire string `owner_missing: connector identity missing` — the reject
the frps **core** logs on every owner-missing NewProxy rejection (`... new proxy
[name] ... error: owner_missing: connector identity missing`). The filter + alarm
live in `terraform/modules/qurl-reverse-tunnel-server/monitoring.tf`.

## What it means

frps rejects a reverse-tunnel connector's **NewProxy** registration when the
connector presents no connector identity. The affected connector (e.g.
`fileviewer` / `detect`) then has **no working tunnel** — its proxy never
registers, so traffic to it is dark. The connector retries on a ~30s loop,
producing ~10 rejects / 5 min per stuck connector, which is what the alarm is
tuned to catch (one genuinely-stuck connector, not a single transient blip).

**A genuinely wedged connector does not self-heal** — frps keeps rejecting
until it re-establishes identity, so it needs a restart (see Remediation). A
*transient* upstream identity-issuance hiccup can instead accumulate enough
rejects to page and then clear on its own; **First checks** below covers
telling the two apart. Historically the wedged case hid for hours because
nothing metered it — this alarm is the detector that closes that gap.

## First checks

- **Identify the stuck connector(s).** In the frps log group
  (`/layerv/nhp/<env>/frps`) filter for `owner_missing: connector identity
  missing`; the `new proxy [name]` on the same frps-core reject line names the
  connector.
- **Confirm scope.** A single proxy name repeating ~every 30s is
  one stuck connector. Multiple distinct connectors point at a broader
  regression — suspect a recent connector-image change or an identity-issuance
  change on the qurl-reverse-tunnel-server / qurl-service side rather than a
  one-off wedge.
- **Rule out a self-clearing blip.** If the count already fell back to 0 and the
  alarm returned to `OK`, a connector recovered on its own; capture the proxy
  name / `run_id` for follow-up and stand down.

## Remediation

- **Interim fix: force-restart the affected connector task** so it re-knocks and
  re-establishes identity. The tunnel recovers once frps accepts the next
  NewProxy; the `owner_missing: connector identity missing` rejects drop to 0 and
  the alarm returns to `OK` within one 5-minute window.
- **Durable fix:** the connector-side re-knock fix
  (qurl-reverse-tunnel-server-client #431, merged) removes the wedge as it rolls
  out to connectors. Until every connector runs it, expect recurrences and
  repeat the restart.

## Wire-string / cross-repo dependency

The metric filter matches the **byte-stable wire string**
`owner_missing: connector identity missing` — the RejectReason that
`qurl-reverse-tunnel-server`'s tunnel-auth handler returns and the frps **core**
logs on every owner-missing NewProxy reject (`... new proxy [name] ... error:
owner_missing: connector identity missing`). This works on the **current**
server with no cross-repo dependency: the frps core already emits this line
today, so the alarm is armed the moment NHP deploys. The string is the live,
shared contract, pinned on **both** sides by merged code (origin/main) — the
connector's owner_missing detection (qurl-reverse-tunnel-server-client #431)
keys on it verbatim, and server #226 keeps it byte-for-byte — so a reword would
break the connector's self-heal too, not just this alarm. It also counts once
per reject: the full wire string appears only in the frps-core reject line, and
#226's added structured line uses a different substring (`reject_reason=owner_missing`).

Do **not** repoint the filter at that structured `reject_reason=owner_missing`
field: #226 (merged) also emits it for dashboards, but it requires the
#226-carrying server build to be **deployed**, and NHP's terraform applies
before the server binary ships — so a field-based filter would blind-and-green
the alarm every release until the server catches up. The wire string works on
any server version. Keep the filter
(`modules/qurl-reverse-tunnel-server/monitoring.tf::owner_missing_reject_count`)
matching the wire string.

Because the filter sets `default_value = 0`, once the high-volume frps log
group is flowing the series stays populated at 0 and the alarm rests in `OK`.
Right after apply a correctly wired filter transitions `INSUFFICIENT_DATA` →
`OK` within a few minutes; if it *stays* `INSUFFICIENT_DATA` the filter never
initialized — a broken pattern, or a silent log group (the latter is itself the
`frps-no-healthy-instance` page). A resting `0` is honest here: because the
detector works on the current server, `OK` means no owner_missing rejects
(genuinely healthy), not "waiting for a field to exist."

## Tuning

The threshold is the root variable `owner_missing_reject_threshold` (default 5;
`GreaterThanOrEqualToThreshold` over a single 5-minute Sum). Raise it via env
tfvars to quiet the alarm during a **planned** connector force-restart window (a
bounce itself emits a short `owner_missing` burst). Validation blocks values
below 1, which would arm the always-on trap (`Sum ≥ 0` is always true).
