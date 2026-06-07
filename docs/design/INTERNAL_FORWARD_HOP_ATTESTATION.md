# Cross-server forward hop attestation

Status: implemented (permit-mode default), rollout pending
Issue: [layervai/nhp#1127](https://github.com/layervai/nhp/issues/1127)
Code: `endpoints/server/forward_hop_attest.go`, `http_forward.go`, `httpserver.go`

## Problem

`/nhp/internal/knock` lets one nhp-server forward a knock to another when the
receiving server has no local AC connection for the target. Loop prevention
was a plaintext boolean (`HttpKnockRequest.Forwarded`) plus an
attacker-settable `Source` field:

- `Source == "api"` → origin (e.g. qurl-service); the receiver may forward.
- `Source == ""` → server-to-server; the receiver sets `Forwarded = true` and
  will not re-forward.

The shared-secret HMAC gate added for
[#1122](https://github.com/layervai/nhp/issues/1122) authenticates "a party
holding `NHP_INTERNAL_AUTH_SECRET`". But **every** fleet server holds that one
secret, so a **compromised server** can forge `Source="api"` / `Forwarded=false`
exactly as a non-key-holder could before #1122. A hop counter signed with the
same shared secret adds nothing — the compromised holder re-signs it. This is
why #1127 stays open after #1122 closed.

## What this change actually buys (scope honesty)

`forwardToServer` never propagates `Source` (it always sends `""`), so the
receiver always sets `Forwarded = true` on a forwarded knock — meaning a knock
is already re-forwarded **at most once** today via the boolean. The issue's
"infinite-forward DoS" framing was therefore largely unreachable in practice.

What this change adds is narrower and real:

- **Attribution + impersonation-resistance on the server-to-server leg** — the
  receiver knows *which* registered server forwarded, and a compromised member
  cannot forge a hop as a different server.
- **Defense-in-depth if `NHP_INTERNAL_AUTH_SECRET` leaks** — a secret-holder
  that is not a registered fleet keypair-holder still cannot mint accepted
  server hops.
- **A hard hop ceiling** independent of the boolean.

It does **not** close the `Source="api"` origin-spoof path (see Residual). This
change therefore *bounds and attributes* #1127; it does not by itself warrant
closing it.

## Why a shared secret cannot fix it

Loop-prevention that resists a compromised insider requires the receiver to
**attribute** each hop to a specific server identity, which a single shared
symmetric secret cannot provide (anyone holding it is indistinguishable from
anyone else holding it). The fix needs **per-server identity**.

## Design

NHP is a Noise/ECDH system: every server already has a static X25519 keypair,
and the fleet registry (AWS Cloud Map) already advertises each server's public
key (`ServerInfo.PubKey`, attribute `PUBLIC_KEY`). We reuse those — **no new
key distribution**.

### Per-pair MAC key

A forwarding server (sender `A`) and its target (recipient `B`) derive a
symmetric per-pair key from their static keys:

```
k_pair = HMAC-SHA256(key = ECDH(privA, pubB), data = "nhp-internal-forward-hopbind-v1")
       = HMAC-SHA256(key = ECDH(privB, pubA), data = "nhp-internal-forward-hopbind-v1")   // B computes the same
```

`ECDH(privA, pubB) == ECDH(privB, pubA)`, so only `A` and `B` can compute
`k_pair`. The HMAC PRF step domain-separates it from the raw Noise shared
secret. A third compromised member `E` cannot compute `k_pair(A,B)` — it holds
neither `privA` nor `privB`.

### Attestation envelope

Carried on the forward body (`HttpKnockForwardRequest.Attestation`):

```
sender_pubkey : base64 X25519 pubkey of the forwarding server
hop           : server-to-server hop count (origin = 0; first forward = 1)
ts            : unix seconds (freshness)
mac           : lowercase hex HMAC-SHA256(k_pair, signing_string)
```

Signing string (newline-joined, no trailing newline):

```
NHP-FWD-HOP-v1 \n <sender_pubkey> \n <hop> \n <ts> \n <source> \n <reqBindHex>
```

- `sender_pubkey` is **signed** so the symmetric A↔B key cannot reflect a B→A
  attestation back as an A→B one.
- `source` is the envelope `Source` the attestation is minted with (empty for a
  server-to-server hop). Binding it pins the attestation to that `Source`, so a
  captured `hop=1` attestation cannot be resubmitted with `Source` flipped to
  `"api"` (which would keep `Forwarded=false` and induce one extra honest
  forward) — the flip becomes a MAC mismatch.
- `reqBindHex = SHA-256(asp|res|user|device|org|srcIp|token)` binds the
  attestation to **this specific knock**, so a compromised peer cannot lift a
  valid attestation off one knock and replay it onto a different one inside the
  freshness window.

### Verification (receiver)

In `handleInternalKnock`, in order:

1. Structural: `sender_pubkey` present; `1 ≤ hop ≤ maxForwardHops` (= 2). An
   out-of-range hop is a **hard reject in any mode** — a loop bound, not an
   auth decision.
2. Freshness: `|now − ts| ≤ 5 min` (`internalauth.DefaultMaxClockSkew`).
3. **Trust anchor**: `sender_pubkey ∈ trusted fleet pubkeys`. A valid MAC alone
   only proves the sender holds the matching private key; this check binds it to
   a registered fleet member.

   The set is a **sticky last-seen map**, not raw discovery output.
   `DiscoverServerInstances` is **health-filtered** (`HealthStatusFilterHealthy`),
   so a forwarder that briefly fails health checks during a deploy would
   otherwise drop out and be rejected/permit-warned — flapping
   `ForwardHopAttestPermit` and blocking the strict flip. Instead a pubkey seen
   in any discovery stays trusted for `forwardHopTrustTTL` (10 min) after its
   last sighting; discovery itself is throttled to 30s. This decouples trust
   from instantaneous health.

   **Revocation** therefore has a bounded latency: a genuinely removed
   (terminated/deregistered) server ages out of the trust set within
   `forwardHopTrustTTL` of its last healthy sighting. A discovery **error**
   never evicts (keeps the prior sticky set) so a transient Cloud Map blip does
   not fail-closed in strict mode. To revoke a *compromised* peer faster than
   this window, rotate `NHP_INTERNAL_AUTH_SECRET` and/or terminate — do not rely
   on the sticky window alone.
4. MAC: recompute under `k_pair = ECDH(myPriv, sender_pubkey)`; constant-time
   compare.

The verified hop propagates (via request context) to any onward forward, which
emits `verifiedHop + 1`, keeping the counter monotonic.

## Threat model

**Defended:**

- **Impersonation** — `E` cannot forge a hop that claims to come from `A`
  (`TestForwardHop_ImpersonationResistant`).
- **Spoofed/un-attested server hop** — in strict mode a `Source==""` forward
  with no valid attestation is rejected.
- **Loop amplification** — `maxForwardHops` bounds any chain through honest
  servers; the hop ceiling rejects regardless of mode.
- **Path concealment** — every server-to-server hop is attributable to a
  registered pubkey (logged).
- **Replay onto a different knock** — `reqBind`.
- **Source-flip replay** — a captured server-to-server attestation resubmitted
  with `Source` flipped to `"api"` is a MAC mismatch (`source` is signed).

**Residual (NOT closed — documented):**

- A single compromised fleet member can still emit its **own** attested `hop=1`
  forwards. The MAC proves *which* server it is, not that the request is
  benign. This is bounded by `maxForwardHops` through honest servers and is
  **revocable** (remove from Cloud Map). Eliminating it entirely would require
  per-request authorization the forward path does not have.
- Origin spoofing via `Source="api"` (a compromised server claiming to be
  qurl-service) is **out of scope** here — origins legitimately carry no
  attestation (qurl-service is not an NHP server with a fleet keypair). That
  surface belongs to the shared-secret origin credential and the replay-cache
  follow-up [#1223](https://github.com/layervai/nhp/issues/1223), which is
  complementary to this change.
- Same-knock replay (resubmitting an identical valid attestation to the same
  receiver inside the 5-min freshness window) is not prevented and is also
  deferred to [#1223](https://github.com/layervai/nhp/issues/1223). It is benign
  here because the forward is **idempotent**: a replayed forward re-enters
  `handleHttpOpenResource` and re-opens the AC for the *same* `srcIp` the
  attestation is bound to (via `reqBind`), authorizing nothing the original
  knock didn't. It counts nothing per-knock that double-counting would distort.

## Rollout

Mirrors the #1122 shared-secret rollout. `NHP_INTERNAL_FORWARD_ATTEST_REQUIRE`
(permit/strict grammar, default permit):

- **permit** (default): verify, warn, allow. Counter `ForwardHopAttestPermit`
  fires on any unverifiable hop. Ship this first so a mixed-version fleet keeps
  forwarding.
- **strict** (`=true`): reject unverifiable server-to-server hops with 401.

Verification only runs in **cloud mode** (device keypair + Cloud Map present);
local/test deployments skip it (legacy posture). Signing is enabled whenever
the server has a device keypair.

Metrics:

- `ForwardHopAttestSuccess` — a hop verified. Note this also fires for an API
  origin that carries a valid attestation (the compromised-member
  re-origination path), not only `Source==""` hops — so it means "a valid
  attested hop arrived", slightly broader than "signed server-to-server
  traffic". The `Permit==0 && Success>0` flip heuristic is unaffected.
- `ForwardHopAttestPermit` — permit-mode unverifiable hop (the rollout signal).
- `ForwardHopAttestReject` — strict-mode auth reject (dominant cause: an
  un-upgraded sender, not an attack).
- `ForwardHopCeilingReject` — the always-on hop-ceiling 403 (hop outside
  `[1, maxForwardHops]`), independent of rollout mode. Legitimate traffic never
  trips it, so any nonzero value is a real over-hop / loop signal worth
  investigating on its own — kept separate from the strict reject so it isn't
  masked by rollout-window noise.

Flip to strict once `ForwardHopAttestPermit` holds at zero across a stable
window while `Success` is non-zero (all forwarders signing).

Operational note: an attested hop only appears when a server actually forwards
(no local AC). A long-zero `Success` may mean "no cross-server forwarding
happening", not "signing broken" — corroborate with `KnockForwardSuccess`
before flipping strict.

### Dual-registry pubkey invariant

The two sides of the MAC derive the peer key from **different registries**: the
**sender** uses `srv.PubKey` from the AC assignment / `ServerInfo` (storage),
while the **receiver's** trust anchor uses Cloud Map's `PUBLIC_KEY`
(`knownFleetPubKeys`). For an attestation to verify, both must equal the peer's
real `device.PublicKeyBase64()`. Both are populated from each server's own
device key at registration, so they agree in steady state — but a divergence
(stale assignment, mismatched registration) makes the per-pair ECDH MAC silently
fail to verify, surfacing as `ForwardHopAttestPermit` that **never drains**
(blocking the strict flip) rather than a loud error. The permit counter is thus
the transitive health check for this invariant; see the rollout-ledger pre-task.
