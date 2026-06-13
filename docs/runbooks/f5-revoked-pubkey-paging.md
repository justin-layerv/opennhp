# Runbook: F5 revoked-pubkey alarm (52019 / `ACPubkeyRevoked`)

## What fired

One of:

- **`ACPubkeyRevoked`** non-zero — a registration was rejected (or in permit mode, would have been rejected) because the presented AC pubkey is on its acId's `RevokedPubKeys` denylist.
- **`ACPubkeyRevokedConnDropped`** non-zero — a strict-mode runtime sweep severed an already-connected AC whose pubkey is now on that acId's `RevokedPubKeys` denylist.
- **`ACPubkeyRevokedLookupErr`** non-zero — F5 GetACAssignment storage error; the gate degraded to skip-the-gate. Strict mode does NOT escalate this to a reject.
- **`ACPubkeyRevokeListOversize`** non-zero — an `ACAssignment.RevokedPubKeys` list crossed the 50-entry sanity threshold. Operator workflow is one-pubkey-at-a-time during incident response; lists this large suggest a runaway-append admin tool or F5 misuse as a license-wide kill switch.
- **`ACPubkeyRevokeListCapped`** non-zero — an `ACAssignment.RevokedPubKeys` list exceeded the **hard cap of 256** (`acPubkeyRevokeListLengthMax`, #1547). Past the cap the server **skips the F5 revocation scan at registration and accepts the AOL** (availability-first), so **registration-time** revocation is **silently not enforced for that acId** until the list is trimmed to 256 or fewer (a list of exactly 256 still enforces; only >256 skips). The cap is registration-path only: in strict mode the mid-session drop sweep still scans the full uncapped list, so an over-cap revoked AC that knocks through is then severed by the next sweep (`ACPubkeyRevokedConnDropped`). Blast radius is bounded to F5: the license-validity, bound-pubkey allowlist (F-#1155), and CustomerID (F4) gates still run, so this is not an open door — only the per-acId registration-time revocation denylist is bypassed. Remediation: trim the offending acId's list (almost certainly a runaway admin tool / hand-edited `aws dynamodb update-item` typo, since the operator workflow is one-pubkey-at-a-time).
- **`ACPubkeyRevokeGateBug`** non-zero — `applyACPubkeyRevokeVerdict` hit its fail-closed default branch, indicating a server-side dispatch-table bug. Page-worthy independent of `ACPubkeyRevoked`.
- **`InternalAuthSignerUnavailable`** non-zero during an operator-triggered sweep — the server is reachable but lacks `NHP_INTERNAL_AUTH_SECRET`, so the signed fast path returns 401. Treat this as deployment/config drift and alert the platform owner before relying on the endpoint during an incident.

The registration gate lives in `endpoints/server/ac_pubkey_revoke_gate.go` (kernel + apply + evaluate split mirroring F3/F4). The mid-session drop path lives in `endpoints/server/ac_pubkey_revoke_drop.go` and is exposed for operator-triggered sweeps by `POST /nhp/internal/ac-revocations/sweep[/<acId>]`.

## How to read a 52019 spike — most-important section

When `ACPubkeyRevoked` (or its CloudWatch alarm) fires from an unfamiliar source IP, the **default operator interpretation should be "attacker is testing my acId list," NOT "attacker has the specific revoked private key in flight."** The 52019/generic error split intentionally tells a 52019-receiver "this acId has at least one revocation entry" — that lets an unauthenticated probe enumerate which acIds are "hot" (have known-stolen pubkeys).

This is not a new identity leak (acIds are not secret) and the rate limiter bounds the probe rate, but the forensic signal is "presence of revocations on this acId," not "this specific stolen key was just used." Confirmed-compromise classification needs **corroborating evidence**:

- License-validation failures from the same IP (different metric: `LicenseValidationRateLimited`).
- AC logs showing a session terminated by the operator immediately before.
- Cross-reference against the operator-driven `nhp-license-admin revoke` action timeline — if the metric fires and no operator just revoked, *that's* the "stolen key still being presented" signal.

The information-disclosure asymmetry is documented at the top of `ac_pubkey_revoke_gate.go`'s package doc; do NOT genericize the F5 error to `ErrServerACOpsFailed` to "close the info leak" — the leak IS the audit primitive.

## First five minutes

1. **Identify the acId and source IP** from the most recent `server-ac(...)[ACPubkeyRevoked]` log line. The log carries `acId`, `transactionId`, `addrStr`, and a 12-char pubkey prefix.
2. **Check whether an operator just revoked** for that acId. If yes, this is the expected enforcement signal — the registration gate is confirming the revocation took effect within the propagation window (60s normally; 5s during a console-driven reassignment when the adaptive TTL drops to `ReassignmentTTL`).
3. **Check `LicenseValidationRateLimited` from the same source IP** — if it fires alongside, classify as confirmed compromise / brute-force probe. If 52019 fires alone, classify as "attacker enumerating acId namespace" and escalate to threat-intel review, not to "key in flight."
4. **Check `ACPubkeyRevokedLookupErr`** at the same time — if non-zero, F5 may be silently bypassing rejects for ALL acIds during a DDB flap. This is the strict-mode availability hedge; the gate degrades to skip rather than escalating to a fleet-wide outage. If sustained, page DynamoDB ops independently of the F5 incident.
5. **Check `ACPubkeyRevokedConnDropped`** after an operator-driven revocation. In strict DynamoDB cloud mode, an already-connected AC should be severed by the next `NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS` sweep (default 60s) or immediately after a signed internal sweep trigger.

## Common patterns

| Metric pattern | Likely cause | Action |
|---|---|---|
| `ACPubkeyRevoked` rises, operator just revoked | Expected registration enforcement | Confirm `ACPubkeyRevokedConnDropped` fires for any already-connected AC, or run the signed internal sweep for that acId if incident response needs an immediate drop before the next scheduled sweep. |
| `ACPubkeyRevokedConnDropped` rises, operator just revoked | Expected mid-session enforcement | Confirm the dropped pubkey prefix matches the operator action. No action. |
| `ACPubkeyRevokedConnDropped` rises, operator did NOT revoke | Live AC key appeared on a denylist unexpectedly | Treat as high-signal compromise until disproven. Cross-reference DDB write audit, source IP, and AC logs. |
| `ACPubkeyRevoked` rises from unfamiliar IP, operator did NOT revoke | Stolen pubkey being presented (high signal) OR attacker probing acId namespace (low signal — see "How to read" above) | Check `LicenseValidationRateLimited` from same IP. Cross-reference operator timeline. |
| `ACPubkeyRevokedLookupErr` sustained | DDB flap — gate is silently bypassed | Page DDB ops. The metric is the only signal that strict-mode F5 is degraded; do NOT wait for a customer-visible regression. |
| `ACPubkeyRevokeListOversize` non-zero | Runaway admin tool / F5 misused as license-wide kill switch | Check the offending acId's `RevokedPubKeys` length. Operator workflow is one-pubkey-at-a-time; if length > 50, consider whether `License.Active=false` is the right primitive instead. The hard cap is 256 (`ACPubkeyRevokeListCapped` below); a list between 50 and 256 is still enforced. |
| `ACPubkeyRevokeListCapped` non-zero | `RevokedPubKeys` list past the 256 hard cap (#1547) — F5 **registration** revocation scan **skipped** for that acId | Treat as an enforcement gap, not just a sanity warning: a revoked pubkey on that acId will be **accepted at registration** until the list is trimmed to 256 or fewer (in strict mode the mid-session sweep still drops it — expect a paired `ACPubkeyRevokedConnDropped`). Find the offending acId (the metric fires per AOL; the once-per-process log line names it), audit how the list grew (runaway admin tool / hand-edited DDB row), and trim it. The license/allowlist/F4 gates still enforce, so the AC is not unauthenticated — only its registration-time revocation denylist is bypassed. |
| `ACPubkeyRevokeGateBug` non-zero | Server-side dispatch-table bug — a future PR added a verdict constant without registering it in the switch | Page on-call dev. Read recent `ac_pubkey_revoke_gate.go` commits; the bug is in `applyACPubkeyRevokeVerdict`. |
| `InternalAuthSignerUnavailable` non-zero during a sweep attempt | Missing or misrotated `NHP_INTERNAL_AUTH_SECRET` on the target server | Alert the platform owner and redeploy/fix the secret before depending on the on-demand sweep. Background sweeps still enforce revocations when F5 strict mode is on. |

## Adding / removing a revoked pubkey

Use `nhp-license-admin` from `endpoints/licenseadmin/main`. The F5 commands
mutate `ACAssignment.RevokedPubKeys` with conditional DynamoDB writes:
re-running `revoke` for an already-revoked pubkey, or `unrevoke` for a pubkey
that is not present, is a true no-op and does **not** bump `version`.

Build:

```sh
cd endpoints
go build -o nhp-license-admin ./licenseadmin/main/
```

```sh
# Inspect
nhp-license-admin list-revoked \
  --ac-assignments-table <table-name> \
  --ac-id <ACID>

# Add a revoked pubkey
nhp-license-admin revoke --operator "$USER" \
  --ac-assignments-table <table-name> \
  --ac-id <ACID> \
  --pubkey <base64-pubkey>

# Remove a revoked pubkey
nhp-license-admin unrevoke --operator "$USER" \
  --ac-assignments-table <table-name> \
  --ac-id <ACID> \
  --pubkey <base64-pubkey>
```

### Notes / edge cases

Run with AWS credentials for a role holding `dynamodb:GetItem` and
`dynamodb:UpdateItem` on the AC assignments table:

Confirm `--region` / `AWS_REGION` points at the assignments table's deployed
region before writing. The CLI default is `us-east-2`, matching the existing
license-admin commands, but an incident shell with a different profile or table
region can otherwise turn into a misleading `ErrACAssignmentNotFound`.

For AWS-managed environments, start from the Terraform
`dynamodb_write_policy_arn` output (`module.dynamodb.write_policy_arn`,
named `<name_prefix>-dynamodb-write`). That policy includes the required
`GetItem`/`UpdateItem` access to AC assignments; confirm it, or an equivalent
least-privilege grant, is attached to the incident operator/admin role before
F5 strict rollout. #2477 tracks the pre-rollout IAM confirmation.

`revoke` / `unrevoke` never create AC assignment rows: a missing `ac_id` is a
terminal `ErrACAssignmentNotFound`, not an empty denylist to upsert. This keeps
the incident tool from minting partial assignment rows; pre-emptive blocks for
never-assigned ACs need the normal assignment provisioning path first.

Successful `revoke` / `unrevoke` writes bump the assignment `version` so server
caches and console reassignment flows observe the denylist change. A concurrent
console reassignment that read the previous version may retry on its optimistic
lock; during an incident, treat that as expected cache-invalidation behavior.

Set `--audit-file` or `NHP_ADMIN_AUDIT_FILE` for a durable JSON audit line.
The generic `NHP_ADMIN_*` env vars intentionally take precedence over the
legacy `NHP_LICENSE_ADMIN_*` aliases if both are exported. `--operator` is a
self-asserted advisory label capped at 256 bytes; rely on CloudTrail for the
durable IAM principal. Missing or oversized `--operator` is rejected on stderr
before any JSON audit line is emitted, because there is no valid audit subject.
`revoke` and `unrevoke` write the audit line to stderr for state changes,
no-op attempts where the pubkey is already present or absent, and terminal
failures after `operator` / `ac_id` are known. Failure records have
`result:"error"`, `changed:false`, `version:0`, an empty `revoked_pubkeys` set,
and an `error` field; malformed `--pubkey` input is recorded as a bounded
length/hash fingerprint rather than the raw invalid string. Successful
state-observation records include `operator`, `ac_id`, `pubkey`, action,
`result` (`mutated` or `noop`), `changed` (true only when the denylist changed),
resulting version, and the resulting `revoked_pubkeys` set.
If a mutation aborts after retry exhaustion, immediately run `list-revoked` for
the same `ac_id`; the failure audit records the failed write, while the read-only
inspection captures the current denylist state for the incident timeline.

If `unrevoke` reports a non-canonical whitespace entry, the row was written by
an external or legacy path; the CLI never writes that shape. Clean the offending
String Set member directly in DynamoDB, then rerun `list-revoked` and
`unrevoke` as needed so the structured audit trail resumes from a canonical row.
If `revoke` sees only a non-canonical whitespace variant, it intentionally adds
the canonical pubkey, bumps `version`, and warns that direct DynamoDB cleanup is
still needed; this fails toward blocking the compromised key until cleanup.
`list-revoked` is read-only and intentionally does not emit a JSON audit line;
missing `ac_id` is a terminal `ErrACAssignmentNotFound`, not an empty denylist.
Capture shell/session logs if the inspection timeline matters during an
incident.

Wait up to `CachedStorage.DefaultTTL` (60s normally, 5s during a console-driven
reassignment) for in-flight servers to observe the change. The CLI repeats this
propagation expectation in the success message.

In strict DynamoDB cloud mode, connected ACs are also checked by the mid-session
sweeper. The default interval is 60s; set
`NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS=0` to disable the background sweep
or to a whole-second value of at least 5 to tune it. Cloud deployments wrap
DynamoDB in `CachedStorage`, so backend reads are normally bounded by the
assignment cache TTL; lowering the sweep interval mostly adds cache reads until
the TTL expires, while shortening the TTL or repeatedly using suffixless sweeps
can increase DynamoDB read pressure. For incident response that cannot wait for
the next tick, call the signed, private-source internal endpoint with no body
and no query string. The endpoint rejects unsigned calls even while the broader
`/nhp/internal` auth rollout is in permit mode; it uses the normal internal-auth
timestamp window but no nonce tracking because replaying a valid sweep within
that window is idempotent:

```text
POST /nhp/internal/ac-revocations/sweep/<ACID>
```

To generate the `X-Nhp-Auth` header for the empty-body POST, run from a
trusted operator shell that already has the current `NHP_INTERNAL_AUTH_SECRET`:

```bash
path="/nhp/internal/ac-revocations/sweep/<ACID>"
ts="$(date +%s)"
body_sha="$(printf '' | sha256sum | awk '{print $1}')"
sig="$(printf 'NHPv1\n%s\nPOST\n%s\n%s' "$ts" "$path" "$body_sha" | openssl dgst -sha256 -hmac "$NHP_INTERNAL_AUTH_SECRET" -binary | xxd -p -c 256)"
curl -fsS -X POST -H "X-Nhp-Auth: NHPv1 timestamp=$ts,signature=$sig" "http://<nhp-server-internal-ip>:8888${path}"
```

If a legacy environment has no internal-auth signer configured, this endpoint
returns 401; deploy the shared internal-auth secret or wait for the background
sweep.

Use the suffixless `/nhp/internal/ac-revocations/sweep` form only when
intentionally sweeping every currently connected acId on that server; it
performs one assignment lookup per active acId. If the JSON response includes
`truncated: true`, the caller's request context ended before every active acId
was checked; rerun the per-ACID form for the affected AC or rerun the suffixless
sweep and do not treat the partial counts as complete.

**Pubkey encoding**: standard padded base64 (RFC 4648 §4, alphabet
`A-Z a-z 0-9 + /`, `=` padding). URL-safe base64 is **not** normalized at
gate-evaluation time and would cause a silent miss. `nhp-license-admin` rejects
non-canonical input before writing.

## Rollout state

`NHP_AC_PUBKEY_REVOKE_VERIFY` env var gates strict mode. Default OFF (permit).
Flip to `true` only after:

- The `ACPubkeyRevoked` metric stays at zero in permit mode through a full deploy cycle.
- All F5 CloudWatch alarms (#1543) are provisioned and in `OK` state. The expected set is exactly: `ACPubkeyRevoked`, `ACPubkeyRevokedConnDropped`, `ACPubkeyRevokedLookupErr`, `LicenseValidationRateLimited`, and `ACPubkeyRevokeListCapped` (#1547). If you add an F5 metric, extend this list and #1543 together.
- ACAssignment pre-provisioning lands (#1262) so F4 + F5 strict can flip together without TOFU race issues.

The mid-session drop path only performs destructive drops when
`NHP_AC_PUBKEY_REVOKE_VERIFY=true`, the server is using DynamoDB storage, and
the sweep interval is non-zero.

## Related issues

- #1535 — F5 mid-session connection drop (kick already-connected ACs whose pubkey was just revoked). Implemented by #2462.
- #1536 — Operator CLI for managing `RevokedPubKeys` (implemented by the commands above).
- #1537 — Smoke Tier 2 contract test fencing the propagation window.
- #1541 — `handleACServerAssignment` rate-limit hardening (separate amplification surface).
- #1543 — CloudWatch alarms (provisioned in Terraform) for all F5 metrics.
- #1545 — Storage write-boundary normalization for `RevokedPubKeys` (implemented: `CachedStorage.SaveACAssignment` Clones at the boundary).
- #1547 — Hard upper bound (256) on `RevokedPubKeys` length (implemented: `acPubkeyRevokeListLengthMax`; over-cap skips the scan and fires `ACPubkeyRevokeListCapped`).
- #1548 — Admin invalidation signal to shrink propagation window below 60s.
