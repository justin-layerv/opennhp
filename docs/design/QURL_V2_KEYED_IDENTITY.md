# qURL v2 Keyed Identity and Immediate Revocation Design

## Status

Proposed. This is a design document only. It is grounded in the current
`nhp`, `qurl-service`, and `traefik-plugins` code as of 2026-06-20.

## TL;DR

New qURLs should stop using `at_` bearer tokens. A new qURL becomes a small
signed bootstrap artifact that contains:

- the cell NHP server public key, used only to route the browser/headless agent
  through the relay to the correct cell;
- a per-qURL user public key and matching private key, used as the NHP agent
  identity for this one qURL;
- the long-lived protected-resource public key, used by NHP/AC for resource
  admission and future AC routing;
- issuer, expiry, and qURL state identifiers, signed by qurl-service.

The relay should remain boring: `POST /relay/{serverId}` routes by the cell
public-key fingerprint and forwards an opaque NHP packet. It does not need to
know the resource public key, qURL status, policy, session count, or tenant.

qurl-service remains the qURL issuer and the immediate-state authority. KMS is
the private-key custody boundary, but it cannot replace the hot qURL/session
state store for immediate semantics. DDB, or an equivalent strongly conditional
hot store, is still required for per-qURL status, one-time-use, max-session, and
revocation state.

Immediate revocation means more than "future resolves fail." If a qURL is
killed while sessions are open, qurl-service must push revocation to NHP/AC.
AC then uses its existing hashed timer-wheel flushing architecture as the
mechanism to tear down active L3 flow state immediately, not only at normal
expiry.

The security model is math-first. Software guards are allowed to reject, rate
limit, revoke, observe, and fail closed, but they should not be what makes a
forged or tampered qURL fail. A qURL should fail because the issuer signature,
NHP proof-of-possession, cell binding, or resource binding does not verify.

## Current Code Reality

### qurl-service

Current production qURL identity is still token-shaped.

- `domain.Qurl` is keyed by `token_hash`, with status, expiry, use count,
  `ResourceID`, `NHPResourceID`, and session policy. (`NHPAgentPublicKey` exists
  only on the `justin/provisioned-qurl-agent-key` branch, not canonical `main`,
  which carries `Resources` for per-qURL AC assignments instead.)
- `ResolveCommit` loads by `HashToken(access_token)`, validates policy, registers
  the authenticated browser-relay agent key when present, consumes/increments the
  token, and creates the session.
- `AuthorizeResourceAccess` is the L7/session check used by qurl-router and NHP
  re-knocks. It authorizes by resource plus client/session facts, not by a qURL
  public key.
- The active feature branch `justin/provisioned-qurl-agent-key` already generates
  per-qURL X25519 keys and emits a `qv1.` fragment, but that fragment still
  carries `access_token`. That branch is a useful key-lifecycle starting point,
  not the final no-token design.

### NHP

The relay path is already aligned with the desired cell-routing model.

- `endpoints/relay` routes `POST /relay/{serverId}` by the NHP server public-key
  fingerprint.
- The relay forwards opaque inner NHP packets to a private NHP server and cannot
  read encrypted qURL semantics.
- `endpoints/js-agent` derives `serverId` from the server static public key and
  sends the NHP knock to the relay.

The qURL server path is not yet aligned with the desired qURL identity model.

- `endpoints/server/staticplugins/qurl` is still a static plugin.
- `AuthWithHttp` still calls `/internal/v1/resolve` with `access_token`.
- `AuthWithNHP` is tokenless for re-knocks, but it authorizes by `resourceID`
  plus client IP/session state and does not forward the authenticated NHP agent
  public key to qurl-service.
- The current catalog distinction is `r_` public resource ID versus `q_` dynamic
  NHP catalog ID, not cell public key versus resource public key.
- Dynamic `q_` catalog rows are strongly read from DDB on miss, but NHP also
  caches positive and negative dynamic-row results briefly. Deleting a catalog
  row is therefore not an immediate revocation primitive.

### traefik-plugins

`qurl-router` does not see URL fragments and does not consume qURL tokens.

- `*.qurl.site` routing extracts an `r_...` resource ID from the host.
- It resolves resource routing through qurl-service.
- It authorizes through qurl-service with a short positive cache bounded by
  `remaining_seconds`.
- Tunnel placement HRW is keyed by today's resource ID, not by a cell key or
  resource public key.

This means qURL v2 is additive across repos. It is not a rename of `r_`, `q_`,
or `at_`.

## Cryptographic Security Invariants

The implementation should be reviewed around these invariants first. Software
checks are supporting controls. A grant is eligible only if the math is valid;
qurl-service state may still deny it for expiry, revocation, consume, policy, or
session-limit reasons.

1. Issuer integrity: qurl-service signs the public qURL claims. Any change to
   cell public key, resource public key, qURL user public key, `exp`, `nbf`, or
   `jti` breaks the signature.
2. qURL user proof: the browser/headless client must complete the NHP handshake
   using the per-qURL private key. NHP admission must compare the authenticated
   public key from the handshake to the signed `qurl_user_public_key_b64`.
3. Cell binding: the relay route ID is derived from the signed cell public key,
   and the private NHP server must verify that the claim's cell key is its own
   active cell key before opening AC access.
4. Resource binding: the knock resource identity must be the signed protected
   resource public key. The relay never uses this value.
5. No server-side-replayable bearer token: a new qURL cannot be authorized by
   possession of an opaque `at_` string replayed against a lookup. Possession must
   be demonstrated by private-key proof. This does not make the qURL non-bearer:
   the per-qURL private key still rides in the link fragment, so anyone holding
   the link holds the credential. The real wins are narrower and worth stating
   honestly: (i) the secret is never sent in the HTTP request to `qurl.link`
   (fragments are not transmitted), so it cannot leak via server logs/Referer/
   proxies the way an `at_` in a path or query can; (ii) PoP defeats passive
   replay of a captured encrypted knock; (iii) the claims are tamper-evident. Link
   confidentiality remains the primary threat, unchanged from v1.
6. State is liveness, not identity: DDB/qurl-service state answers "is this
   signed qURL still allowed right now?" It must not be the only thing binding
   user, cell, and resource identities.
7. Private-key custody: persisted private keys are either avoided or protected by
   KMS/KMS-wrapped storage. A leaked software database row should not be enough
   to mint arbitrary new qURL identities.

## Goals

1. qURL admission is cryptographic: signed claims plus NHP proof-of-possession.
2. New qURLs have no `at_` bearer token.
3. Every qURL has a unique per-qURL NHP agent identity.
4. Relay routing uses only the cell NHP server public key.
5. The protected-resource public key is long-lived and tied to the protected
   resource lifecycle.
6. The resource public key is for AC admission/routing. It is not a relay route
   key.
7. qurl-service remains the issuer/orchestrator.
8. Immediate qURL semantics are preserved: revoke, consume, expiry, and session
   limits must take effect for future admission and already-open sessions.
9. Private keys are protected by KMS custody or KMS-wrapped storage when they are
   persisted server-side.

## Non-goals

- Do not make the relay understand qURL policy.
- Do not require legacy `at_` tokens on the relay path.
- Do not remove legacy `at_` support for already-issued qURLs in one cut.
- Do not remove all DDB usage from NHP/qURL runtime state. KMS is not a hot
  conditional session-state system.
- Do not finish the plugin removal in the first PR. The target architecture
  removes "qURL plugin" as a security concept, but implementation can first land
  behind the existing static qURL package.

## qURL v2 Artifact

Format:

```text
https://qurl.link/#qv2.<base64url(claims_json)>.<base64url(secret_json)>.<base64url(issuer_sig)>
```

The fragment is three dot-separated base64url parts: the signed `claims`, the
unsigned `secret`, and the issuer signature. This mirrors the NHP Server Contract,
which takes `qurl_claims_b64` and `qurl_issuer_sig_b64` as separate blobs.

The JSON is plaintext. It is not a secret container. The private key in the
fragment is protected by browser fragment semantics only: it is not sent in the
HTTP request to `qurl.link`, but any holder of the link has the qURL credential.

Recommended payload: Part 1, `claims` (signed), base64url-encoded JSON:

```json
{
  "v": 2,
  "iss": "qurl-service",
  "kid": "qurl-issuer-key-2026-06",
  "iat": 1781910000,
  "nbf": 1781910000,
  "exp": 1781910300,
  "jti": "qurl_01J...",

  "cell_public_key_b64": "...",
  "cell_id": "optional-human-or-config-id",
  "relay_url": "https://relay.example.com",

  "resource_public_key_b64": "...",

  "qurl_user_public_key_b64": "..."
}
```

Part 2, `secret` (unsigned), base64url-encoded JSON:

```json
{ "qurl_user_private_key_b64": "..." }
```

Part 3, `sig`: the issuer signature over the exact ASCII bytes of Part 1's
base64url string, base64url-encoded.

Signature rules:

- The signature is computed over the exact ASCII bytes of the base64url-encoded
  `claims` string as it appears on the wire (Part 1), prefixed with the fixed
  domain-separation string `NHP-QURL-V2-ISSUER\0`. The `\0` is one literal
  `0x00` byte, not the two ASCII characters backslash and zero. Verifiers MUST
  verify against the received bytes and MUST NOT parse-then-re-serialize the
  claims object: re-canonicalization is a classic signature-bypass vector, and
  signing the transmitted encoding removes all canonicalization ambiguity.
- All key/identifier fields use base64url (never standard base64) so the signed
  bytes are unambiguous.
- The base64url encoding is unpadded. Padded encodings, non-base64url alphabet
  characters, empty parts, and fragments with anything other than exactly three
  parts are invalid.
- The private key is not trusted because it is present in the fragment. It is
  trusted only when the browser/headless agent proves possession by completing
  the NHP handshake as `qurl_user_public_key_b64`. Swapping the unsigned secret
  for an attacker key makes PoP fail (the signed public key no longer matches), so
  the secret needs no signature.
- The signed claims must bind `cell_public_key_b64`, `resource_public_key_b64`,
  `qurl_user_public_key_b64`, `exp`, `nbf`, and `jti`.

Parsing rules:

- Claims and secret JSON use a strict allowlist schema. Reject duplicate keys,
  unknown fields, missing required fields, wrong types, null values, arrays where
  scalars are expected, and numeric values outside the allowed range.
- Time fields are integer Unix seconds only. Reject floats, strings, exponent
  notation, negative values, and ambiguous local-time forms.
- Key fields are fixed-length base64url strings for the expected key type. Decode
  and length-check them before use. The resource public key may be a different
  algorithm and length than the X25519 cell and per-qURL keys (e.g. a P-256 KMS
  key), so length-check each field against its own expected size.
- `relay_url` must be HTTPS, must pass the qURL deployment allowlist, and is used
  only after client-side issuer signature verification succeeds.
- Use the same strict parser profile in JS/headless and Go server verification.
  In particular, do not rely on default JSON parsers that silently accept
  duplicate object keys with last-wins semantics.

Why include expiry if DDB is authoritative:

- It lets the NHP server fail-fast on stale links before the qurl-service lookup.
  (The relay cannot read encrypted `exp`, so expiry bounds NHP-server work, not
  relay work; the relay forwards opaque packets regardless.)
- It gives headless/browser clients a cheap local fail-fast.
- It is part of the signed anti-tamper envelope. If someone changes the resource
  or cell IDs, the signature fails before admission.
- It does not replace DDB state. DDB still decides immediate revocation,
  one-time-use, max sessions, and policy.

Encoding notes:

- Raw public keys stay in the signed claims as base64url. Pin one encoding
  (see signature rules); "base64 or base64url" is itself a canonicalization hazard.
- Do not put raw standard base64 in DNS labels. If a resource public key is ever
  represented in a hostname, use a stable URL/DNS-safe identifier, such as
  base32/base58 or a keyed hash alias, while the signed qURL still carries the
  full public key.

## Key Lifecycle

### Issuer signing key

This is the highest-value key in the system: anyone who can sign issuer claims can
mint a valid qURL for any resource or cell. It deserves the strongest custody.

- Private key: lives in KMS; issuance signs via a KMS `Sign` call and never
  exports the key material. A leaked qurl-service database row or host must not
  yield the issuer key.
- Algorithm: pin the issuer key type, KMS signing algorithm, and wire signature
  encoding in config and verifier code. The initial profile should be one
  algorithm only, for example `ECC_NIST_P256` with `ECDSA_SHA_256`. Do not allow
  algorithm negotiation from the qURL payload. P256/ECDSA is chosen partly
  because AWS KMS has no Ed25519 key spec; switching to Ed25519 would mean giving
  up KMS-custody signing.
- Signature wire format: use fixed-width raw ECDSA `r || s` for P-256
  (64 bytes, base64url-encoded, low-S normalized). AWS KMS returns ASN.1 DER for
  ECDSA, so qurl-service converts KMS output to the pinned wire format before
  issuing the qURL. Go and JS verifiers convert from the pinned wire format to
  their local crypto API format as needed. Verifiers MUST reject signatures that
  are not exactly 64 bytes or not low-S normalized, so the pinned encoding is
  enforced and not merely produced. Add golden vectors that prove KMS output, Go
  verification, and WebCrypto verification agree byte-for-byte, plus a high-S and
  a wrong-length rejection vector.
- Signing input: `NHP-QURL-V2-ISSUER\0` + the exact unpadded base64url claims
  part from the fragment. The `\0` separator is a single `0x00` byte.
- Public key distribution: verifiers (NHP servers, and the first-party JS agent;
  see Browser and Headless Flow) resolve the public key for a claim's `kid` from a
  small published trust store. Unknown or retired `kid`s are rejected.
- Rotation: overlap-publish multiple `kid`s. New qURLs sign with the current
  `kid`; verifiers keep accepting recently-retired `kid`s until outstanding qURLs
  expire, then drop them.

### Cell NHP server key

The cell public key is the NHP server static public key for the deployment/cell.
It defines the relay trust domain and routing target.

- Public key: embedded in qURL v2 and relay configuration.
- Private key: NHP server custody, protected by KMS or current deployment key
  custody model.
- Rotation: cell-level operational event. New qURLs receive the new key. Old
  qURLs can continue until expiry if the old cell key remains in the relay table.

### Protected-resource key

The protected-resource key is long-lived and tied to the protected resource
lifecycle. Long term it replaces the protected resource ID for AC routing.

- qurl-service creates it when the protected resource is created, either by
  creating a KMS-backed asymmetric resource keypair or by receiving a public key
  from a future resource-key authority.
- In v2, `resource_public_key_b64` is the actual protected-resource public key.
  It is the NHP knock resource identity and the AC routing/admission key. It is
  not a lookup alias, and it is not interchangeable with `resource_key_id`.
- v2 admission does not perform a resource-private-key signature/proof. If
  qurl-service owns the private half, it remains non-exportable in KMS, reserved
  for a future resource-delegation proof, with no hot read/sign path in v2. The
  KMS key policy MUST grant `kms:Sign` to no v2 principal (Sign is added only when
  the delegation feature ships), so a code regression cannot quietly sign with a
  resource key. Do not claim resource-private-key authorization until that proof
  protocol exists.
- `resource_key_id` may exist as a DNS/API-safe alias derived from the public key,
  but it is never the NHP knock resource identity and never the authorization
  cache key.
- Rotation: resource-level event. Rotation must either revoke active qURLs or
  support a transition window with both old and new resource public keys.

### Per-qURL user key

The per-qURL user key is ephemeral in the product sense: every issued qURL gets a
fresh NHP agent identity.

- qurl-service generates it at qURL creation time.
- Public key: persisted as the qURL identity and embedded in the qURL.
- Private key: returned once in the qURL fragment.
- Recommended server-side storage: do not persist the per-qURL private key unless
  a clear recovery or audit requirement needs it. The safest private key is the
  one qurl-service cannot later leak.
- If policy requires storing it, store only a KMS-wrapped blob with qURL TTL,
  strict audit, and no hot read path. It should not be needed for resolve,
  authorize, revoke, or relay routing.

## Persistent State

KMS should own private-key custody. It should not replace the qURL/session hot
state store.

Use a new qURL v2 state shape. It can be a new table or a staged migration of
the current `qurl-access-tokens` table, but the domain name should stop saying
"token" for new records.

Recommended qURL state:

```text
pk: QURL#<qurl_user_public_key_hash>
sk: STATE

qurl_id
qurl_user_public_key_b64
resource_public_key_b64
resource_key_id           optional DNS/API alias; not admission identity
legacy_resource_id        optional migration bridge
cell_public_key_hash
owner_id
target_path
qurl_site_url
status                   active | consumed | expired | revoked
one_time_use
max_uses
use_count
max_sessions
session_duration_seconds
issued_at
not_before
expires_at
ttl
revocation_epoch
```

`revocation_epoch` is a per-`(scope, scope_key)` monotonic counter bumped with a
conditional write on every revoke for that scope/key. Persist it next to the
revocable object for that scope: qURL state for `qurl`, protected-resource state
for `resource`, session state for `session`, and cell control state for `cell`.
It is the idempotency and ordering token end-to-end: it rides in the AOP metadata
and the revocation event, and AC applies an event only if its epoch exceeds the
last epoch AC applied for that `(scope, scope_key)`, dropping stale or duplicate
events. Initial value is 0.

Recommended session state:

```text
pk: RESOURCE#<resource_public_key_hash>
sk: SESSION#<session_id>

qurl_user_public_key_hash
resource_public_key_hash
client_ip
visitor_session_id
target_path
created_at
first_authorized_at
expires_at
ttl
status
admitted_ac_ids          recorded at commit before AC open; drives targeted-revoke completeness
```

Conditional writes (the hard reason a strongly-conditional hot store stays in the
design):

- one-time-use consume (exists today: `status = active AND not expired`);
- max-session counter (exists today: `active_count < max`);
- max-use ceiling - NET-NEW: there is no `MaxUses` field today and the current
  `use_count` increment is unconditional, so a race-safe `use_count < max_uses`
  ceiling must be built, not reused;
- pending admission lease (net-new; see prepare/commit);
- revoke-if-active state transitions.

That is the hard reason DDB, or a same-strength hot state store, remains in the
design. KMS lookup can replace catalog lookup for private key custody, but KMS
does not give us high-volume conditional session semantics.

## Issuance Flow

### Protected resource creation

1. qurl-service creates or receives the target resource definition.
2. qurl-service creates or receives the protected-resource public key.
3. qurl-service stores the resource public key on the protected-resource record.
4. qurl-service may derive a DNS/API-safe `resource_key_id` alias from the public
   key, but the alias is not an NHP admission identity.
5. qurl-service publishes or updates NHP/AC catalog data keyed by the resource
   public key.

### qURL creation

1. qurl-service loads the protected resource.
2. qurl-service selects the cell public key for the deployment/cell.
3. qurl-service generates a fresh per-qURL user X25519 keypair.
4. qurl-service writes qURL v2 state with conditional put:
   `qurl_user_public_key_hash` must not already exist.
5. qurl-service builds signed public claims and appends the private key in the
   plaintext fragment payload.
6. qurl-service returns the qURL once. No `at_` token is created for v2.

Failure rule: do not return a qURL until the qURL state write and signature have
both succeeded.

## Browser and Headless Flow

The browser and headless clients use the same qURL semantics.

1. Parse `#qv2.<payload>`.
2. Verify the issuer signature locally - REQUIRED for the first-party JS/headless
   client, not merely recommended. The client acts on `relay_url` and
   `cell_public_key_b64` (steps 3-4 and 7) to choose where to POST and what to
   encrypt to, all before any server sees the knock; server-side admission cannot
   protect against client misdirection. A tampered `relay_url`/cell key on an
   unverifying client yields DoS and claims disclosure (bounded: the private key
   never leaves the `secret` block and is not recoverable from the Noise
   handshake). Ship the issuer trust anchor (per `kid`) to the first-party client.
   Server-side verification remains authoritative for admission.
3. Compute `serverId = fingerprint(cell_public_key_b64)`.
4. Build an NHP knock using `qurl_user_private_key_b64` as the agent static
   private key and `cell_public_key_b64` as the server static public key.
5. Set the NHP knock resource identity to the protected-resource public key.
6. Put the signed qURL claims in encrypted knock user data.
7. POST the opaque NHP packet to `relay_url + "/relay/" + serverId`.

The relay sees only:

- HTTP source address;
- `serverId`;
- an opaque NHP packet header/counter needed for dispatch.

The private NHP server sees, after decrypting the knock:

- authenticated qURL user public key from the NHP handshake;
- resource public key from the knock body;
- qURL signed claims from encrypted user data;
- relay-derived source IP.

Server-side checks:

1. Signature over qURL claims is valid.
2. `cell_public_key_b64` matches this server/cell.
3. Authenticated NHP agent public key equals `qurl_user_public_key_b64`.
4. Knock resource identity equals `resource_public_key_b64`.
5. qurl-service state is active and not expired/revoked/consumed.
6. Session policy permits admission for the source/client.

Checks 1 through 4 are the integrity boundary. Checks 5 and 6 are liveness and
policy. No code path should reach AC open if the cryptographic checks fail,
even when qurl-service state says the qURL is active.

Issuer verification is deliberately duplicated:

- NHP server verifies the issuer signature and claim bindings before it asks AC
  to open anything.
- qurl-service independently verifies the issuer signature in prepare before it
  reads or mutates qURL/session state.
- Neither layer trusts the other layer's parse result. They use the same strict
  wire-byte signature input and parser profile, but they verify independently.

### Per-qURL key authorization model

This operationalizes invariants 2 and 6, and is the single most important thing to
get right. The per-qURL agent public key is authorized **only** by the issuer
signature plus proof-of-possession: it is NOT pre-registered in any catalog the
NHP server reads. The NHP server completes the Noise IK handshake with a
previously-unknown per-qURL key (IK lets the responder learn the initiator static
key during the handshake), then admits based on the signed claims + PoP.

Concretely, qURL v2 must NOT reuse the existing patterns that would silently
reintroduce staleness:

- Do NOT register the per-qURL public key as a browser-relay/agent catalog row
  (the `justin/provisioned-qurl-agent-key` branch does this via
  `browserRelayKeys.Upsert`; v2 drops it).
- The only DDB read on the admission path is the authoritative qURL **state** row
  (keyed by `qurl_user_public_key_hash`), used for liveness only. It is read
  strongly-consistent and is NOT positively cached; unlike the `q_` catalog path,
  which caches positive results ~5s and is therefore not an immediate primitive.

So signature + PoP are load-bearing for *identity*; DDB is authoritative only for
*liveness*. If an implementation finds itself adding a positive admission cache or
a per-qURL key catalog, it has regressed the design back into the staleness this
work exists to remove.

## NHP Server Contract

Near-term implementation can evolve the existing static qURL package. Target
architecture should make qURL a first-class NHP auth path, not a customer
"plugin" concept.

Add a qURL v2 resolver contract:

```http
POST /internal/v2/qurl/admissions/prepare
Content-Type: application/json

{
  "qurl_claims_b64": "...",
  "qurl_issuer_sig_b64": "...",
  "authenticated_qurl_public_key_b64": "...",
  "src_ip": "203.0.113.10",
  "user_agent": "...",
  "request_id": "..."
}
```

qurl-service MUST derive `resource_public_key_b64`, `cell_public_key_b64`,
`qurl_user_public_key_b64`, expiry, and `jti` from the verified signed claims.
Do not send duplicate unsigned copies in the request. If a future debug field is
added, it must be named `observed_*`, ignored for authorization, and compared
only after signature verification.

Prepare is a verifier, not just a state lookup. qurl-service MUST verify the
issuer signature and strict-parse the claims itself even if NHP already verified
them before calling prepare.

Response:

```json
{
  "admission_id": "adm_...",
  "qurl_id": "qurl_...",
  "resource_public_key_b64": "...",
  "resource_key_id": "rk_...",
  "qurl_user_public_key_hash": "...",
  "open_time": 60,
  "session_duration": 300,
  "remaining_seconds": 300,
  "qurl_site_url": "https://r_legacy-or-alias.qurl.site/path",
  "ac_routing": {
    "ac_id": "...",
    "dest_host": "...",
    "dest_port": 443
  }
}
```

`resource_key_id` in this response is a DNS/API alias for UI and HTTP routing
only. NHP admission and qurl-router authorization cache keys must use
`resource_public_key_b64` or its hash.

Then:

```http
POST /internal/v2/qurl/admissions/{admission_id}/commit
POST /internal/v2/qurl/admissions/{admission_id}/cancel
```

Why two phase:

- The current token-era flow has to coordinate qurl-service state mutation with
  NHP/AC side effects.
- Prepare reserves the qURL with a short lease so two simultaneous first knocks
  cannot both progress toward commit.
- Commit finalizes the one-time-use consume or max-session counter and writes the
  session durably, including the `ac_id` that prepare selected (in `ac_routing`)
  into `admitted_ac_ids`. NHP opens the AC named in that `ac_routing`, so the
  recorded id matches the opened AC. Re-knocks that select a different AC at
  authorize record that `ac_id` the same way, before NHP opens it. Because every
  admitting AC is in the set before it can forward, the set is complete by
  construction, which is what lets a revoke assert `target_set_complete = true`.
- NHP opens AC last, after commit succeeds. If AC open fails after commit, the
  session/admission is marked failed and no pinhole remains open. For a
  one-time-use qURL, this can burn the link even though the user never reached
  the resource. That is an explicit fail-closed reliability tradeoff; product may
  choose a retry/reissue UX, but security must not silently un-consume it.
- Cancel releases the pending lease only before commit. After commit succeeds,
  consume/session state is durable; AC-open failure records a failed admission and
  must not silently un-consume a one-time-use qURL.

Failure-branch and lease rules (must be specified, not left implicit):

- Commit-fails-after-AC-open is not allowed in the target design. If an
  implementation opens AC before durable commit, the AC grant must be a
  non-forwarding provisional grant that cannot pass traffic until commit
  activation. If AC cannot stage non-forwarding grants, NHP MUST commit state
  before AC open. A reconciliation sweep is not an acceptable primary safety
  mechanism for this branch.
- The prepare lease MUST have a TTL and an abandoned-lease reclaim. If a client
  prepares and then vanishes (never commits or cancels), the lease must expire so
  a one-time-use or max-session slot is not wedged permanently.

The first implementation may keep a one-shot endpoint if needed, but the DE
target should preserve the same state machine: prepare, commit durable state, then
open AC. That order makes one-time-use, max-session, and AC failure behavior
reviewable.

Steady-state re-knocks should call an idempotent authorize endpoint:

```http
POST /internal/v2/qurl/admissions/authorize

{
  "qurl_user_public_key_b64": "...",
  "resource_public_key_b64": "...",
  "src_ip": "203.0.113.10",
  "visitor_session_id": "...",
  "request_id": "..."
}
```

The response returns `remaining_seconds` and AC routing metadata. NHP clamps
`OpenTime` to `remaining_seconds` before opening/refreshing the AC pinhole.

Re-knock semantics for one-time-use qURLs: a one-time-use qURL becomes `consumed`
after first admission, but its session must remain valid for `session_duration`.
The authorize path MUST key on resource + session facts (client/visitor session,
remaining lifetime), NOT on qURL `status = active`; otherwise re-knocks for a
still-open session of a consumed qURL are wrongly denied and the session dies at
the first `OpenTime` expiry. Today's `AuthorizeResourceAccess` already behaves
this way; v2 must preserve it and not regress into a qURL-status check.

## AC Admission and Immediate Revocation

Current AC expiry flushing already uses a hashed timer wheel. That is the right
mechanism family for million-scale scheduled flow teardown. It is not, by
itself, a cross-AC immediate revocation plane.

Add qURL/session metadata to the NHP-AOP path so AC can index active flows:

```text
qurl_user_public_key_hash
resource_public_key_hash
session_id
admission_id
revocation_epoch
deadline
```

AC stores secondary indexes:

```text
qurl_user_public_key_hash -> flow keys / access entries
resource_public_key_hash  -> flow keys / access entries
session_id                -> flow keys / access entries
```

On normal admission:

1. NHP sends AOP with resource and qURL metadata.
2. AC writes kernel allow state.
3. AC schedules the normal expiry flush in the existing timer wheel.
4. AC indexes the flow under qURL, resource, and session keys.

On immediate revoke:

1. qurl-service changes qURL/resource/session state with a conditional write.
2. qurl-service emits a revocation event to the NHP control plane.
3. NHP forwards the revocation to every AC that may hold matching state. The
   admitted AC set is an optimization only when complete: every AC that opens or
   refreshes a flow, including re-knocks that land on a different AC, MUST be
   added to the session's admitted AC set. The set is not pruned while any flow
   can still be live. If completeness cannot be guaranteed, for example after a
   control-plane failover or lost admission ack, revoke MUST fall back to
   cell-wide fan-out rather than silently targeting a subset.
4. AC looks up matching flow keys.
5. AC cancels future scheduled entries and calls the existing flusher now, or
   reschedules them with deadline `now`.
6. AC removes tokenStore/access entries so refresh/re-knock cannot extend them.

Implementation caveat (forwarded flows): the carrier of this metadata onto the
AOP/AccessEntry (P4a, nhp PR #2772) populates the per-admission fields
(`qurl_user_public_key_hash`, `admission_id`, `deadline`) only on the local
admission path. A flow admitted via the **server-to-server forward path** carries
`resource_public_key_hash` only (from the catalog row), because the forward
receiver re-resolves the resource rather than re-running v2 admission. Until the
forward path carries the per-admission fields, **forwarded flows are revocable by
resource key only** — a `qurl`/`session`/`admission`-scoped revoke will not match
them. Tracked in #2774; may be mooted by #2208 (which removes the forward path).

Use the existing "Kafka / Netty pattern" hashed wheel algorithm; do not add
Kafka infrastructure. The new work is the revocation fanout and the immediate
fire path, not a new timer architecture.

### Flow granularity caveat

Current AC `FlowKey` is network-shaped: source IP, destination IP, destination
port, and protocol. It has no qURL, session, browser public key, or resource
public-key dimension.

That means a qURL-level revoke cannot be perfectly surgical at L3 if two live
sessions share the same network tuple. The secure initial behavior is to flush
the shared `FlowKey`, which may interrupt other sessions from the same source to
the same destination. qurl-service/NHP/L7 then prevent the revoked qURL from
re-opening. This preserves confidentiality but may have availability collateral.

The same network-shaped `FlowKey` produces a symmetric **under-flush** race in
the P4b apply primitive (`ApplyRevocation`). It pulls the shared key's deadline
to now and then removes the revoked entry from the token store; in that window a
concurrent natural expiry of a sibling holding the same `FlowKey` can re-derive
the key's deadline from a token-store snapshot that still lists the revoked
entry and push the deadline back (longest-wins `Schedule`), leaving the revoked
flow alive to natural expiry. This is non-urgent (no production caller until the
P4e receive path; microsecond window) and is closed by the same per-session
kernel discriminator below — both the over-flush and under-flush directions
dissolve once revoke is surgical. Tracked in #2784.

Because the product requires "kill exactly this qURL and preserve every other
holder of the same src/dst tuple," AC needs a new kernel-visible discriminator
before we can make that claim: for example BPF flow metadata or another
kernel-visible session tag. Without that, L3 only sees the shared flow.

Before relying on immediate revocation, also audit and retire the current orphan
flush paths used for temp access. Orphan scheduler entries are not tied to an
`AccessEntry`, so they are weak ownership points for explicit admin cancel. This
was tracked as a precision gap by #2172 / #2213. The orphan-retirement half
(#2213, slice P4g) has landed: temp-access (NAT'd / `PASS_PRE_ACCESS_IP`) flows
now own their scheduled flush via a long-lived `AccessEntry`
(`registerTempAccessFlushEntry`), so they are walkable by an admin Cancel. Each
admission parks up to two such entries — the TCP and UDP temp handlers each mint
one — so the admin-Cancel *selection* surface (#2172) must enumerate both. That
surface remains to be built, and it must match these entries by their
kernel-keyed (NAT'd) `FlowKey`, not by `SrcAddrs` (the AOL-declared IP), since
the two deliberately diverge for NAT'd temp access.

Filter-mode/IPv6 caveat: the current conntrack flusher is IPv4-only, and
established-flow teardown differs by filter mode (iptables conntrack delete vs
eBPF/XDP map delete). Immediate revocation of IPv6 established flows must either be
confirmed reachable in the eBPF/XDP path or be declared out of scope for the
iptables path.

Backpressure rule:

- If AC cannot apply revocation, it must fail closed for new admissions in the
  affected scope and emit paging metrics.
- If the revocation fanout cannot prove delivery, qurl-service/NHP should mark
  the revoke as degraded and retry until all known ACs acknowledge or age out.

## qurl-service Revocation Events

Event shape:

```json
{
  "event_id": "evt_...",
  "event_type": "qurl.revoked",
  "scope": "qurl",
  "scope_key": "qurl:<qurl_user_public_key_hash>",
  "qurl_user_public_key_hash": "...",
  "resource_public_key_hash": "...",
  "session_id": "optional for session scope",
  "cell_public_key_hash": "optional for cell scope",
  "fanout_mode": "targeted",
  "target_set_complete": true,
  "target_ac_ids": ["ac_..."],
  "revocation_epoch": 42,
  "effective_at": "2026-06-20T12:00:00Z",
  "reason": "creator_revoke"
}
```

Hash-preimage contract (load-bearing across repos): `qurl_user_public_key_hash`
and `resource_public_key_hash` here MUST be computed with the SAME preimage the
AC indexes under — lowercase-hex SHA-256 of the **decoded** key bytes (raw key
for the qURL-user key; decoded DER for the resource key), matching NHP's single
canonical hasher `qurlv2.PublicKeyHashFromB64` (P4a). If the revoke side ever
hashes the base64 string, a padded variant, or a DER-renormalized form, the AC's
P4b indexes silently never match and the revoke misses every flow. The in-repo
producers are pinned by tests; the residual risk is the qurl-service revoke
emitter. Tracked: qurl-service #1010, nhp #2752.

Supported scopes:

- `qurl`: kill one qURL's active sessions;
- `resource`: kill all active qURLs for a protected resource;
- `session`: kill one session;
- `cell`: operational drain/rotation scope.

Today's `RevokeQurl` is resource-scoped only and does best-effort async catalog
cleanup with no push; the `qurl`/`session`/`cell` scopes and push delivery are all
net-new.

Delivery requirements:

- at-least-once;
- idempotent by `(scope, scope_key, revocation_epoch)`;
- `target_ac_ids` is valid only when `fanout_mode = targeted` and
  `target_set_complete = true`; otherwise the event MUST use cell-wide fanout
  keyed by `cell_public_key_hash`;
- `cell_public_key_hash` is required for cell-wide fanout and optional only for a
  complete targeted event;
- NHP MUST reject or safely upgrade an incomplete targeted event to cell-wide
  fanout rather than deliver to a known-partial AC subset;
- bounded retry with dead-letter visibility;
- AC ack recorded for operational proof;
- a defined end-to-end revocation-latency SLO (e.g. p99 from revoke API to AC
  flush-complete < N seconds), measured and tested. "Immediate" must be a number,
  since fan-out + index lookup + flush is not instantaneous.

Transport can be selected during implementation. The design requirement is
push-based delivery into the NHP/AC control plane, not polling from qurl-router.

## Traefik / qurl-router Migration

Traefik cannot see URL fragments, so all qURL v2 bootstrap state must be
exchanged by browser/headless code before the data-plane HTTP request reaches
`qurl-router`.

Short term:

- Keep existing `r_...qurl.site` or custom-domain HTTP host routing.
- qurl-service maps the legacy/public host identifier to the new resource public
  key internally.
- `/authorize` can accept legacy `resource_id` and resolve it to resource public
  key before checking v2 sessions.
- For v2 sessions, disable positive L7 auth caching unless revocation-cache
  invalidation is wired, tested, and acknowledged before a revoke call reports
  success. Legacy v1 may keep the existing short positive cache during migration.

Medium term:

- Add `/internal/v2/resource/{resource_key_id}/authorize`.
- Update qurl-router auth cache keys so authorization is scoped to resource
  public key, not `r_` or `resource_key_id`. Host/key-ID aliases must resolve to
  the resource public key before authorization or cache lookup.
- Add revocation-cache invalidation from the same push plane used by AC. A v2
  positive cache is allowed only when invalidation is in the revoke success path
  and the cache TTL is still clamped to `remaining_seconds`.

Long term:

- If resource public keys become user-visible host identifiers, introduce a
  DNS-safe resource key ID. Do not put raw standard base64 public keys in host
  labels.
- If tunnel control and HTTP dispatch need deterministic co-location, switch HRW
  placement from legacy `resource_id` to the chosen cell/resource routing key.
  Keep route-cache and auth-cache keys separate: cell key routes to a relay/cell,
  resource key identifies the protected resource for AC routing/access checks.

## Migration Plan

Phase 0: document and test current state.

- Add contract tests that prove legacy `at_` qURLs still work.
- Add relay tests proving the relay routes only by server public-key fingerprint.

Phase 1: resource keys.

- Add protected-resource public key creation in qurl-service.
- If qurl-service owns the private half, keep it non-exportable in KMS, grant
  `kms:Sign` to no v2 principal, and leave it unused by v2 admission. Do not add
  resource-private-key authorization until a separate resource-delegation proof is
  designed and tested.
- Add resource public key to resource rows and catalog rows. Add `resource_key_id`
  only as a DNS/API alias derived from the public key.
- Keep `r_` IDs as public/legacy aliases.

Phase 2: qURL user keys without token removal.

- Land the per-qURL key generation branch after hardening.
- Persist public key on qURL state.
- Return private key once in the fragment.
- Keep token path only for compatibility while tests are built.

Phase 3: qURL v2 no-token bootstrap.

- Add signed `qv2.` fragments.
- Add JS/headless parser and NHP knock construction from qURL private key.
- Add NHP qURL v2 admission endpoints.
- Add qurl-service v2 prepare/commit/authorize.
- New qURLs use qv2 by default. No `at_` is minted.

Phase 4: immediate revocation.

- Extend AOP metadata to AC.
- Add AC secondary indexes and immediate flush path.
- Add a kernel-visible per-session discriminator (e.g. BPF flow metadata) so a
  qURL-level revoke flushes exactly the target qURL's flows without tearing down
  other sessions on the same src/dst tuple. Over-flush is acceptable only as an
  interim during this phase, not as the Phase 4 exit state.
- Add qurl-service revocation events and NHP/AC delivery.
- Add proof metrics and runbooks.

Phase 5: cleanup.

- Stop issuing qv1/`at_`.
- Remove relay/browser support for token bootstrap.
- Keep legacy server-side token resolve only until old links expire or product
  decides to force invalidation.
- Collapse the NHP qURL static plugin into a first-class auth provider.

## Test Plan

qurl-service:

- qv2 payload contains no `access_token`.
- tampering with cell public key, resource public key, qURL public key, `exp`, or
  `jti` fails signature validation.
- authenticated qURL public key mismatch fails admission.
- one-time-use race allows one commit and denies the rest.
- max-session race enforces the configured cap.
- private qURL user key is not persisted by default.
- revoke emits an idempotent revocation event.
- signature check verifies the exact wire bytes: a re-serialized claims object
  (reordered or re-encoded fields) is rejected even when semantically equal.
- issuer signature vectors pin the P-256 raw `r || s` wire encoding across KMS
  signing output, Go verification, and WebCrypto verification; a high-S or
  wrong-length signature is rejected by both the Go and WebCrypto verifiers.
- v2 admission uses no positive cache: a revoked qURL is denied on the very next
  admission with no stale-cache window.
- abandoned prepare lease (no commit/cancel) expires and frees the one-time-use /
  max-session slot.
- prepare/commit order never exposes a forwarding AC pinhole before durable state
  commit unless AC supports an explicitly non-forwarding provisional grant.
- AC-open failure after commit leaves no pinhole open, records failed admission,
  and may consume a one-time-use qURL by design.
- strict parser rejects duplicate JSON keys, unknown fields, padded base64url,
  non-base64url characters, wrong types, and non-integer time fields.

NHP:

- JS/headless computes relay `serverId` from cell public key.
- relay never receives or parses qURL claims.
- qURL v2 knock uses the qURL private key as the agent static identity.
- NHP server denies when claim cell key does not match the current cell.
- NHP server denies when knock resource identity does not match signed resource
  key.
- NHP verifies the issuer signature before AC open and does not trust
  qurl-service as the sole verifier.
- AC-open failure after durable commit is fail-closed and may burn a one-time-use
  qURL; it must not leave a forwarding pinhole.
- the first-party client refuses to build a knock when the issuer signature is
  invalid (relay/cell misdirection is blocked client-side, before any POST).

AC:

- AOP metadata indexes active flows by qURL, resource, and session.
- normal expiry still uses the existing hashed wheel.
- immediate revoke flushes active flow state before normal expiry.
- qURL-level revoke is surgical: with the per-session kernel discriminator, a
  revoke kills only the target qURL's flows and leaves a same-src/dst-tuple
  sibling session intact. (Shared-`FlowKey` over-flush is acceptable only as an
  interim during rollout, not as the final tested behavior.)
- repeated revoke events are idempotent.
- scheduler breaker/fanout failure fails closed for new admissions.

traefik-plugins:

- legacy `r_` host maps to resource public key for authorize.
- qURL v2 session authorize returns remaining seconds.
- v2 positive auth cache is disabled until push invalidation is part of the revoke
  success path; when enabled, revoke invalidates cache before reporting success.
- any enabled v2 auth cache TTL is clamped to remaining seconds.
- HRW placement tests are updated if routing key changes.

Smoke:

- browser qv2 qURL opens through relay and reaches protected resource.
- headless qv2 qURL opens through relay and reaches protected resource.
- qv2 link with any tampered signed ID is denied.
- revoked qv2 link denies future admission.
- revoked qv2 link kills an already-open streaming HTTP session.
- revoking one qv2 link does not kill a second qv2 session sharing the same
  src/dst tuple (surgical revoke).
- legacy `at_` qURL continues on the legacy path until sunset.

## DE Review Risks

1. Any path that binds qURL user, cell, or resource identity only through a
   software lookup is wrong. The binding must be signed and/or proven by NHP key
   possession.
2. Per-qURL private-key persistence is a security decision, not an implementation
   detail. Recommendation: do not persist it unless a requirement forces it.
3. Prepare/commit/AC-open adds complexity, but it is the cleanest way to make
   one-time-use and max-session semantics correct across AC side effects.
4. Resource public key is not a DNS-safe identifier. We need a canonical
   resource key ID for hostnames and APIs.
5. Immediate semantics require AC push delivery and ACKs. DDB state alone cannot
   kill established TCP flows.
6. AC cannot currently distinguish two qURLs that share the same network
   `FlowKey`. The product requires killing exactly one qURL while preserving
   other holders of the same tuple, which needs a new kernel-visible
   discriminator; until it exists, over-flush plus deny re-open is secure but not
   product-complete, so the discriminator is a Phase 4 deliverable and an
   acceptance gate, not an optional enhancement.
7. Existing orphan flush paths must be fixed or proven irrelevant before admin
   revocation can claim comprehensive AC cleanup. (Temp-access orphan flush
   retired in #2213 / slice P4g — temp flows now own their flush via a
   long-lived `AccessEntry`. The boot-enumeration `Schedule` calls in
   `expiry_enumerate_*_linux.go` remain deliberately owner-less; they
   reconstruct scheduler state for kernel rules that outlived the AC process,
   where no in-memory `AccessEntry` exists — proven irrelevant to admin Cancel,
   which targets live in-memory entries.)
8. Removing "plugins" from NHP is a target architecture change. It should be
   staged after qURL v2 behavior is proven behind the current static package.
9. KMS lookup cannot replace qurl-service's hot state store unless we choose a
   different system with DDB-equivalent conditional writes, TTL, and throughput.

## Proposed Acceptance Bar

A DE should not accept the implementation until all of these are true:

- new qURLs are issued without `at_`;
- relay routing is still only by cell public-key fingerprint;
- qURL private key is generated per qURL and returned once;
- server admission proves possession of that key before any state/policy allow;
- the per-qURL key is authorized by signature + PoP, with no catalog
  pre-registration and no positive admission cache on the v2 admission path;
- signed claims bind qURL user key, cell key, resource key, expiry, and `jti`;
- tampering with any signed binding fails before AC open;
- the first-party client verifies the issuer signature before acting on
  `relay_url`/cell key;
- resource public key is carried through NHP admission as the exact AC-routing
  identity; relay routing remains cell-key only, `resource_key_id` is only an
  alias, and the design must not claim resource-private-key authorization unless
  a resource-key delegation signature/proof is added;
- qURL/session state has conditional writes for one-time-use and max sessions;
- immediate revoke kills already-open sessions at AC;
- immediate revoke is surgical: it kills exactly the revoked qURL's flows and does
  not flush other holders of the same src/dst tuple (requires the kernel-visible
  discriminator; over-flush is not acceptable as the final behavior);
- tests cover tamper, race, revoke, and legacy compatibility paths;
- metrics prove revocation delivery and AC flush completion;
- signed payload parsing is strict and rejects duplicate keys, unknown fields,
  alternate base64url encodings, wrong types, and non-integer time fields;
- revocation targeting records admitted AC ownership; `scope_key` and
  `revocation_epoch` drive idempotency;
- targeted revocation events prove `target_set_complete = true`; otherwise NHP
  uses cell-wide fanout.
