# Runbook: License pubkey gate — provisioning & strict flip (#1155 / #1262)

## What this covers

How to populate `License.BoundPubKeys` for every live license and then flip
`NHP_LICENSE_PUBKEY_VERIFY=true` (permit → strict) for the #1155
license_pubkey_gate, plus the key-rotation workflow that must be followed once
strict is in force.

Background: a pre-#1155 license was an unbound bearer token — anyone holding the
key could register with any keypair for any acId, and the server dumped
plaintext `NHP_AOP` to the attacker's connection. #1155/#1261 bolted identity
onto the license via `License.BoundPubKeys` (an allowlist of AC static pubkeys)
and a permit→strict gate in `validateACLicense`
(`endpoints/server/license_pubkey_gate.go`). The gate is useless until existing
licenses have their `BoundPubKeys` populated — until then every registration
lands in `verdictLicenseUnbound` and permit mode accepts everything. This
runbook is the provisioning workflow (#1262) that drains
`MetricLicensePubkeyUnbound` to zero so strict can be flipped.

## The tool: `nhp-license-admin`

Source: `endpoints/licenseadmin/` (kernel + DynamoDB client) and
`endpoints/licenseadmin/main/` (CLI). The validation/canonicalization kernel is
shared with — and parity-tested against — the server's `License` schema, so a
provisioned key can never silently mismatch a legitimate AC registration.

> The tool is intentionally **decoupled from package server**: it does not
> import the NHP server runtime (and so does not inherit the KBS /
> confidential-containers init side-effects). These license subcommands talk
> only to the `nhp-licenses` DynamoDB table; the same binary also carries
> separate F5 AC-assignment commands documented in
> `docs/runbooks/f5-revoked-pubkey-paging.md`.

> **Maintainer caveat:** this tool mutates `bound_pubkeys` with `UpdateItem`
> (partial update), which is what lets it preserve the server-owned attributes
> it doesn't model. Any future writer of license rows must likewise use
> `UpdateItem` — a full `PutItem` that doesn't carry `bound_pubkeys` forward
> would silently wipe the allowlist and quietly re-open the #1155 hole.

Build:

```sh
cd endpoints
go build -o nhp-license-admin ./licenseadmin/main/
```

Run with AWS credentials for a role holding `dynamodb:GetItem` **and**
`dynamodb:UpdateItem` on the licenses table. The server's own IAM role is
read-only by design — use an operator/admin role, not the server role.

Flags go **after** the subcommand (e.g. `bind --operator x --license-sha256 …`):
`--region` (default `us-east-2`), `--licenses-table` (default `nhp-licenses`),
`--endpoint` (local dev only), `--operator` (your identity, required for
mutations; recorded in the audit line). For shared admin shells,
`NHP_ADMIN_OPERATOR` / `NHP_ADMIN_AUDIT_FILE` intentionally win over the legacy
`NHP_LICENSE_ADMIN_*` aliases; legacy-only scripts keep working via fallback.

A license is selected by **either** `--license-sha256` (the table partition key,
which is all you can read back from the table — the plaintext key is shown only
once at issuance) **or** `--license-key` (the plaintext key, hashed locally).
Prefer `--license-sha256`: a `--license-key` value passed on the command line
leaks into `ps` / `/proc/<pid>/cmdline` / shell history. If you must use the
plaintext key, pass it via the `NHP_LICENSE_KEY` environment variable instead of
an argv flag. Selector precedence is `--license-sha256` → `--license-key` →
`NHP_LICENSE_KEY`, so an exported `NHP_LICENSE_KEY` does **not** block the
recommended `--license-sha256` selector (it's used only when no selector flag is
given). The only rejected combination is passing both `--license-sha256` and
`--license-key` explicitly.

### Commands

```sh
# Inspect the current allowlist
nhp-license-admin show --license-sha256 <sha256>

# Append one or more AC pubkeys (idempotent; dedupes; repeatable -k)
nhp-license-admin bind --operator "$USER" --license-sha256 <sha256> \
  -k <acPubkeyBase64> -k <acPubkeyBase64>

# Append from a file (one pubkey per line; # comments and blanks ignored)
nhp-license-admin bind --operator "$USER" --license-sha256 <sha256> \
  --pubkeys-file ./license-<sha256>.keys

# Remove one pubkey (add --yes if it's the LAST one — that makes the license unbound)
nhp-license-admin unbind --operator "$USER" --license-sha256 <sha256> -k <acPubkeyBase64>

# Clear the allowlist (back to unbound — requires --yes)
nhp-license-admin reset --operator "$USER" --license-sha256 <sha256> --yes
```

`unbind` only matches a **canonical** entry (the tool never writes any other
kind). In the unlikely event a license carries a non-canonical entry written by
some other path, clear the whole allowlist with `reset` and re-`bind` the
canonical key(s); `unbind` cannot target the malformed entry.

## Encoding contract (read this before pasting a key)

`BoundPubKeys` entries MUST be **padded standard base64** (RFC 4648 §4, alphabet
`A–Z a–z 0–9 + /` with `=` padding) of a **32-byte curve25519** static public
key — the exact form the AC presents at registration
(`base64.StdEncoding.EncodeToString(RemotePubKey)`). The gate compares with
exact string equality after a symmetric `TrimSpace`.

`nhp-license-admin` enforces this at write time and **rejects**:

- URL-safe base64 (RFC 4648 §5, alphabet with `-` `_`)
- unpadded base64 (missing trailing `=`)
- non-canonical trailing bits
- anything that doesn't decode to exactly 32 bytes
- leading/trailing whitespace

and stores the re-encoded canonical form. This is the whole point of routing
provisioning through the tool rather than hand-writing DynamoDB items: a
mis-encoded key is **indistinguishable from a #1155 attack** at the gate
(`ErrLicensePubkeyMismatch`), and operators would chase a phantom attacker.

## Provisioning workflow (drain the unbound counter)

1. Identify the AC static pubkey(s) for each live license. The authoritative
   source is the AC operator / enrollment record — **do not** TOFU-trust the
   first pubkey that happens to register, since the whole point of #1155 is that
   an attacker can register first. (`MetricLicensePubkeyUnbound` is the gauge of
   how many licenses still need this.)
2. `bind` the pubkey(s) to the license. Confirm with `show`.
3. Repeat until `MetricLicensePubkeyUnbound` (CloudWatch metric
   `LicensePubkeyUnbound`) reads **zero across all ingress servers**.

### Bulk backfill

There is no auto-migration: the live AC pubkey is not persisted on the
`ACAssignment` row, and the in-memory `acConnectionMap` is not a trustworthy
("TOFU") source for a security allowlist. Backfill is operator-driven — script
`bind` over an authoritative `license_sha256 → pubkey` mapping you control.

**Check each row's exit status.** Completeness is the whole point of the
backfill (drain unbound → 0), so a failed row (bad key, typo'd sha, retries
exhausted) must surface immediately, not 7 days later when the pre-flip metric
check finally notices. Collect failures and re-run until none remain:

```sh
: > failed.csv
export NHP_LICENSE_ADMIN_AUDIT_FILE=backfill-audit.jsonl   # durable before/after trail
while IFS=, read -r sha key; do
  if ! nhp-license-admin bind --operator "$USER" --license-sha256 "$sha" -k "$key"; then
    printf '%s,%s\n' "$sha" "$key" >> failed.csv
  fi
done < licenses-to-bind.csv

if [ -s failed.csv ]; then
  echo "INCOMPLETE: $(wc -l < failed.csv) row(s) failed — investigate, then re-run against failed.csv"
fi
```

(Setting `NHP_LICENSE_ADMIN_AUDIT_FILE` gives a durable record of every mutation
and silences the per-invocation "no --audit-file" warning.)

Treat the backfill as complete only when `failed.csv` is empty (and then confirm
with the `LicensePubkeyUnbound = 0` metric check below).

One-time format check before backfilling: the tool writes `bound_pubkeys` as a
DynamoDB List (`L`) and reads tolerate both `L` and String Set (`SS`), so a stray
`SS` row left by some other writer is harmless — the first `bind` normalizes it
to `L`. If you want the format transition to be understood rather than
discovered, confirm no live rows store `bound_pubkeys` as `SS` before starting.

## Key-rotation workflow (post-strict-flip ops trap)

When an AC rotates its static keypair, **add the new pubkey to `BoundPubKeys`
BEFORE flipping the AC to use it, and remove the old one only after burn-in:**

1. `bind` the **new** pubkey (allowlist now contains both old and new).
2. Switch the AC to the new keypair; confirm it registers cleanly.
3. After a burn-in window, `unbind` the **old** pubkey.

Reversing the order (flip the AC first, bind later) means the AC registers under
a pubkey that isn't on the allowlist, lands in `verdictLicenseMismatch`, and —
in strict mode — every legitimate retry increments `recordLicenseFailure` until
the AC rate-limits itself out. The mismatch counter would read exactly like an
attack.

## Pre-flip checklist (`NHP_LICENSE_PUBKEY_VERIFY=true`)

Do **not** flip strict until all of the following hold:

- [ ] `LicensePubkeyUnbound` = 0 across **all** ingress servers for **7 days**.
      A non-zero value means a live license is still unprovisioned; flipping
      strict locks out that AC and floods the log with per-reject warnings.
- [ ] `LicensePubkeyMismatch` = 0 over the same window (no unexplained
      mismatches — investigate any non-zero before flipping; it is either a real
      attack or a mis-encoded provisioned key).
- [ ] Key-rotation workflow above is socialized with whoever operates the ACs.
- [ ] (etcd deployments only — see gap below.)

Flip per the standard env-var rollout (one environment at a time, watch the
metrics): set `NHP_LICENSE_PUBKEY_VERIFY=true`.

After the flip, `LicensePubkeyUnbound`/`LicensePubkeyMismatch` change meaning
from "rollout incomplete" to "a legitimate AC is being **rejected**" — re-anchor
any alerting thresholds accordingly. Same counter, opposite actionability.

## Rollback

Set `NHP_LICENSE_PUBKEY_VERIFY=false` (or unset) and redeploy/restart the
ingress servers. Permit mode restores pre-#1155 accept behavior immediately;
no data changes are needed. `BoundPubKeys` rows are harmless in permit mode.

## Audit

The before/after record of every mutation is the **JSON audit line** the tool
emits per state change: `{action, operator, license_key_sha256, before, after,
changed, ts}`. It goes to **stderr**, and to the file named by `--audit-file`
(or `NHP_LICENSE_ADMIN_AUDIT_FILE`) if set. The before/after allowlist values
live **only** in this record, so:

- Always pass `--audit-file <path>` (or capture stderr) into your ops log —
  otherwise a script that discards stderr loses the entire mutation record.
- `--operator` is a **self-asserted, advisory** label (up to 256 bytes after
  trimming); it is not authenticated.

For a durable, non-repudiable **who/when** (the IAM principal that performed the
write), rely on CloudTrail — but note two caveats:

- The `dynamodb:UpdateItem` on `nhp-licenses` is a **data-plane** event, which
  CloudTrail does **not** log by default. Enable DynamoDB data-event logging on
  the licenses table (CloudTrail event selector / Terraform) before relying on
  CloudTrail for the who/when, and confirm it is on before the strict flip.
- Even with data events enabled, CloudTrail records the request, **not** the
  prior/next `bound_pubkeys` values — so it complements, but does not replace,
  the audit line above for before/after.

A first-class durable audit sink (CloudWatch Logs / a dedicated audit table) is
tracked as a follow-up; until then `--audit-file` is the durable record.

The audit line fires per **state change**, not per command: a no-op (`bind` of
an already-bound key, `reset` of an already-unbound license, `unbind` of a key
that isn't present) prints a "no change" message to stdout but emits no audit
line — including to `--audit-file` — by design, mirroring CloudTrail, which has
no `UpdateItem` to record in those cases. So `--audit-file` is a record of
mutations, not a complete invocation log; if you need the latter, also capture
stdout/stderr.

The F5 `revoke` / `unrevoke` commands have a separate incident-response audit
contract: they emit an audit line for no-op attempts too, with `changed:false`.

## Known gap: etcd backend

`nhp-license-admin` writes the **DynamoDB** backend (`StorageBackendDynamoDB`).
Deployments running `StorageBackendETCD` are **not** covered — do not flip strict
there until an etcd-aware provisioning path exists and the same drain-to-zero
precondition is met. Tracked alongside the strict-flip coordination in #1514.
```
