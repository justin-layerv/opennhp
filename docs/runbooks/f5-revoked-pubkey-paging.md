# Runbook: F5 revoked-pubkey alarm (52019 / `ACPubkeyRevoked`)

## What fired

One of:

- **`ACPubkeyRevoked`** non-zero — a registration was rejected (or in permit mode, would have been rejected) because the presented AC pubkey is on its acId's `RevokedPubKeys` denylist.
- **`ACPubkeyRevokedConnDropped`** non-zero — a strict-mode sweep or on-demand internal trigger severed an already-connected AC because its pubkey is now on its acId's `RevokedPubKeys` denylist.
- **`ACPubkeyRevokedLookupErr`** non-zero — F5 GetACAssignment storage error; the gate degraded to skip-the-gate. Strict mode does NOT escalate this to a reject.
- **`ACPubkeyRevokeListOversize`** non-zero — an `ACAssignment.RevokedPubKeys` list crossed the 50-entry sanity threshold. Operator workflow is one-pubkey-at-a-time during incident response; lists this large suggest a runaway-append admin tool or F5 misuse as a license-wide kill switch.
- **`ACPubkeyRevokeGateBug`** non-zero — `applyACPubkeyRevokeVerdict` hit its fail-closed default branch, indicating a server-side dispatch-table bug. Page-worthy independent of `ACPubkeyRevoked`.

Registration-time enforcement lives in `endpoints/server/ac_pubkey_revoke_gate.go` (kernel + apply + evaluate split mirroring F3/F4). Mid-session connection drop lives in `endpoints/server/ac_pubkey_revoke_sweep.go`. PR #1538 is the original registration-gate implementation context.

## How to read a 52019 spike — most-important section

When `ACPubkeyRevoked` (or its CloudWatch alarm) fires from an unfamiliar source IP, the **default operator interpretation should be "attacker is testing my acId list," NOT "attacker has the specific revoked private key in flight."** The 52019/generic error split intentionally tells a 52019-receiver "this acId has at least one revocation entry" — that lets an unauthenticated probe enumerate which acIds are "hot" (have known-stolen pubkeys).

This is not a new identity leak (acIds are not secret) and the rate limiter bounds the probe rate, but the forensic signal is "presence of revocations on this acId," not "this specific stolen key was just used." Confirmed-compromise classification needs **corroborating evidence**:

- License-validation failures from the same IP (different metric: `LicenseValidationRateLimited`).
- AC logs showing a session terminated by the operator immediately before.
- Cross-reference against the operator-driven `ADD revoked_pubkeys` action timeline — if the metric fires and no operator just revoked, *that's* the "stolen key still being presented" signal.

The information-disclosure asymmetry is documented at the top of `ac_pubkey_revoke_gate.go`'s package doc; do NOT genericize the F5 error to `ErrServerACOpsFailed` to "close the info leak" — the leak IS the audit primitive.

## First five minutes

1. **Identify the acId and source IP** from the most recent `server-ac(...)[ACPubkeyRevoked]` log line. The log carries `acId`, `transactionId`, `addrStr`, and a 12-char pubkey prefix.
2. **Check whether an operator just revoked** for that acId. If yes, this is the expected enforcement signal — the metric is confirming the revocation took effect within the propagation window (60s normally; 5s during a console-driven reassignment when the adaptive TTL drops to `ReassignmentTTL`).
3. **Check `LicenseValidationRateLimited` from the same source IP** — if it fires alongside, classify as confirmed compromise / brute-force probe. If 52019 fires alone, classify as "attacker enumerating acId namespace" and escalate to threat-intel review, not to "key in flight."
4. **Check `ACPubkeyRevokedLookupErr`** at the same time — if non-zero, F5 may be silently bypassing rejects for ALL acIds during a DDB flap. This is the strict-mode availability hedge; the gate degrades to skip rather than escalating to a fleet-wide outage. If sustained, page DynamoDB ops independently of the F5 incident.

## Common patterns

| Metric pattern | Likely cause | Action |
|---|---|---|
| `ACPubkeyRevoked` rises, operator just revoked | Expected registration-time enforcement | Confirm the AC re-registered after revocation and was rejected. No action. |
| `ACPubkeyRevokedConnDropped` rises, operator just revoked | Expected mid-session enforcement | Confirm the drop count matches the planned revoked AC connection count. The AC should reconnect and then hit the registration-time `ACPubkeyRevoked` gate. |
| `ACPubkeyRevoked` rises from unfamiliar IP, operator did NOT revoke | Stolen pubkey being presented (high signal) OR attacker probing acId namespace (low signal — see "How to read" above) | Check `LicenseValidationRateLimited` from same IP. Cross-reference operator timeline. |
| `ACPubkeyRevokedLookupErr` sustained | DDB flap — gate is silently bypassed | Page DDB ops. The metric is the only signal that strict-mode F5 is degraded; do NOT wait for a customer-visible regression. |
| `ACPubkeyRevokeListOversize` non-zero | Runaway admin tool / F5 misused as license-wide kill switch | Check the offending acId's `RevokedPubKeys` length. Operator workflow is one-pubkey-at-a-time; if length > 50, consider whether `License.Active=false` is the right primitive instead. #1547 tracks adding a hard upper bound. |
| `ACPubkeyRevokeGateBug` non-zero | Server-side dispatch-table bug — a future PR added a verdict constant without registering it in the switch | Page on-call dev. Read recent `ac_pubkey_revoke_gate.go` commits; the bug is in `applyACPubkeyRevokeVerdict`. |

## Adding / removing a revoked pubkey

Until #1536's CLI lands, manual DynamoDB:

```bash
# Add
AWS_PROFILE=layerv aws dynamodb update-item \
  --table-name nhp-ac-assignments \
  --key '{"ac_id":{"S":"<ACID>"}}' \
  --update-expression "ADD revoked_pubkeys :pk SET version = version + :one" \
  --expression-attribute-values '{":pk":{"SS":["<base64-pubkey>"]},":one":{"N":"1"}}'

# Remove
AWS_PROFILE=layerv aws dynamodb update-item \
  --table-name nhp-ac-assignments \
  --key '{"ac_id":{"S":"<ACID>"}}' \
  --update-expression "DELETE revoked_pubkeys :pk SET version = version + :one" \
  --expression-attribute-values '{":pk":{"SS":["<base64-pubkey>"]},":one":{"N":"1"}}'
```

Wait up to `CachedStorage.DefaultTTL` (60s normally, 5s during a console-driven reassignment) for in-flight servers to observe the change. In strict mode, the background sweep then severs matching already-connected ACs on the next `NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS` tick (default 60s). To avoid waiting for that tick, call signed internal `POST /nhp/internal/ac/revocations/sweep` on the NHP server; it returns `{"dropped": <count>}`.

**Pubkey encoding**: standard padded base64 (RFC 4648 §4, alphabet `A-Z a-z 0-9 + /`, `=` padding). URL-safe base64 is **not** normalized at gate-evaluation time and would cause a silent miss. Pin via `base64.StdEncoding.EncodeToString` from a Go script or copy directly from sources that emit std base64 (Secrets Manager, `aws ec2 describe-instances`).

## Rollout state

`NHP_AC_PUBKEY_REVOKE_VERIFY` env var gates strict mode. Default OFF (permit). Flip to `true` only after:

- The `ACPubkeyRevoked` metric stays at zero in permit mode through a full deploy cycle.
- All four CloudWatch alarms (#1543) are provisioned and in `OK` state.
- ACAssignment pre-provisioning lands (#1262) so F4 + F5 strict can flip together without TOFU race issues.

## Related issues

- #1535 — F5 mid-session connection drop (kick already-connected ACs whose pubkey was just revoked). Implemented by the strict-mode sweep and internal trigger.
- #1536 — Operator CLI for managing `RevokedPubKeys`. Replaces the manual DDB stopgap above.
- #1537 — Smoke Tier 2 contract test fencing the propagation window.
- #1541 — `handleACServerAssignment` rate-limit hardening (separate amplification surface).
- #1543 — CloudWatch alarms (provisioned in Terraform) for all F5 metrics.
- #1545 — Storage write-boundary normalization for `RevokedPubKeys`.
- #1547 — Hard upper bound on `RevokedPubKeys` length.
- #1548 — Admin invalidation signal to shrink propagation window below 60s.
