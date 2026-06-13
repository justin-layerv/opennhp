# Knock-Token Validator Placement (AC vs. nhp-server)

## Status: Proposed (2026-06)

**Author:** Justin
**Issue:** [layervai/nhp#2032](https://github.com/layervai/nhp/issues/2032)
**Prior art:** #1124 (opaque-random tokens), #1835 (`/nhp/internal/token/validate`), #2182 (DynamoDB shared store), #2259 (signed validate responses, see [`TOKEN_VALIDATE_RESPONSE_AUTH.md`](TOKEN_VALIDATE_RESPONSE_AUTH.md))

## TL;DR

Move the **FRPS-tunnel knock-token validator** off `nhp-server` onto the AC
daemon, **keeping the existing opaque-random token + DynamoDB shared-store
model**. The AC validator reads the same fleet-visible store the server
validator reads today. Migration is staged **expand → migrate → contract**,
feature-gated OFF, no flag-day.

This is **Fork A**. We considered and rejected **Fork B** (the self-describing
keyed-HMAC token the issue sketches) — see [Why Fork A](#why-fork-a-not-fork-b).

## What the spec says (and what it leaves open)

Per the CSA *Stealth Mode SDP* spec:

- **Token (Table A2.5, NHP-ART):** the AC generates it from *"a unique random
  value and the agent's device ID"* — optional, returned empty if unused.
- **Validation (Table A2.13, NHP-ACC):** *"The NHP-AC verifies the access
  token"* at its temporary listening port.
- **NHP-AOP (Table A2.4)** carries device ID, pubkey, src/dst, duration —
  **no `owner_id`, no `RunID`** (those are server-resolved).

So the spec describes an **opaque-random token the AC verifies by lookup**, and
that core flow is **already implemented** in this repo (`PreAccessInfo` →
NHP-ACC `AgentAccessMsg` → [`VerifyAccessToken`](../../endpoints/ac/tokenstore.go)).
This work does **not** touch it. The issue's "HMAC binds device ID + pubkey"
and "resource server validates" were the author's *proposal*, not spec text.

The thing #2032 actually moves — the **FRPS-tunnel HTTP validator** (#1835,
the `qurl_knock_token` check at FRP login) — is a LayerV extension the spec
does **not** cover; the issue concedes it is "within the spec's flexibility."

## Two validation paths on the AC — keep them distinct

After this work the AC validates the **same** opaque token via two independent
paths. Do not conflate them:

| Path | Caller | Store | Scope |
|------|--------|-------|-------|
| **NHP-ACC** (spec core) | the agent, to the AC's temp port | local `AccessEntry` via `VerifyAccessToken` | issuing AC |
| **FRPS HTTP validator** (this work) | FRPS, to `/nhp/internal/token/validate` | DynamoDB shared store (`ACTokenEntry`) | any AC |

They **cannot** unify: the local `AccessEntry` lacks `KnockSrcIP`/`RunID` (which
the FRPS response carries), and FRPS isn't pinned to the issuing AC (blue/green
replaces the fleet wholesale). So the FRPS path **must** read the shared store —
it can't reuse `VerifyAccessToken`. The new handler stays distinct from it.

## Why Fork A, not Fork B

**Fork A** keeps the spec's opaque-random token + the existing code, and reuses
the proven #2182 shared store. The AC gains a scoped, read-only DynamoDB
dependency for the FRPS path.

**Fork B** (self-describing keyed-HMAC token, verified statelessly) was set
aside because it: (a) **departs from the spec's token model** ("unique random
value" + "the AC verifies"); (b) would push server-resolved identity
(`owner_id`/`RunID`) into the AC's token-minting via an **NHP-AOP wire
extension**, breaking the spec's authN(server)/enforce(AC) separation; (c) is
the bigger change and makes revocation TTL-only. Meanwhile the issue's headline
benefit — decoupling FRP-login availability from `nhp-server`'s HTTP — is
**already achieved by Fork A** (the AC→DynamoDB path never touches `nhp-server`).
Fork B would only win if validating during a total DynamoDB outage were a hard
requirement; it isn't.

**`nhp-server` stays the writer.** The AC cannot write the shared store — it
lacks `KnockSrcIP` (server-observed, ≠ agent-declared `SrcAddrs` under NAT) and
`RunID`. So `nhp-server` keeps the publish-write path permanently; the AC is
read-only.

## Migration plan

Expand → migrate → contract, one reviewable PR per boundary, gated OFF:

| PR | Scope | Notes |
|----|-------|-------|
| **A** | Extract `endpoints/internal/acktoken` (shared entry + read path); server uses it via a type alias. | `refactor`, no behavior change. |
| **B** | AC DynamoDB client + config + scoped read-only IAM + `NHP_INTERNAL_AUTH_SECRET` grant + feature-gated validator handler + tests. Default OFF. **No bind change.** | The bulk. |
| **C** | FRPS→AC reachability: a **dedicated port + an ingress scoped to the FRPS security group** (never the world-open `8888`/`0.0.0.0` `ac_portal`). | Gated. |
| **D** | Consumers add `NHP_VALIDATOR_URL` (default nhp-server). Unset/malformed → fall back; validator-unreachable fails **closed** under `LAYERV_REQUIRE_KNOCK`. | cross-repo. |
| **E** | Sandbox flip → soak → prod flip. | Ledger entries; rollback per boundary. |
| **F** | Remove nhp-server's validate *route* + read role; repoint the consumer default to the AC. **KEEP** `NHP_INTERNAL_AUTH_SECRET` (dual-use: `/knock`, `/ac-revocations/sweep`, qurl-service signing) **and** the publish-write path. | Contract step. |

Prod-affecting PRs (E, F) carry their own `docs/runbooks/prod-rollout-ledger/`
entries; this design and PRs A–B (gated OFF) create no rollout task.

## Secret distribution: add-then-remove

The AC is *granted* `NHP_INTERNAL_AUTH_SECRET` at PR-B; the dual-validator soak
runs with `{nhp-server, AC, FRPS, qurl-service}` all holding it; PR-F only
*removes* the validator route from nhp-server — **not** the secret (it still
serves `/knock` + revocation sweeps and verifies qurl-service's signed knocks).
