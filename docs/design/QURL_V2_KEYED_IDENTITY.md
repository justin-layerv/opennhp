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

Canonical cryptographic artifact:

```text
qv2.<base64url(claims_json)>.<base64url(secret_json)>.<base64url(issuer_sig)>
```

The fragment is three dot-separated base64url parts: the signed `claims`, the
unsigned `secret`, and the issuer signature. This mirrors the NHP Server Contract,
which takes `qurl_claims_b64` and `qurl_issuer_sig_b64` as separate blobs.

Public share transport:

```text
https://qurl.link/#qv2t1.<claims_count>.<secret_count>.<sig_count>.<claims_chunks...>.<secret_chunks...>.<sig_chunks...>
```

`qv2t1` is a transport wrapper, not a new cryptographic artifact version. It
splits every canonical base64url field into dot-delimited chunks of at most 240
characters so messaging clients such as iMessage detect the complete URL as one
link. Every non-final chunk is exactly 240 characters. Counts are canonical
positive decimal integers, capped at 26 claims chunks, 3 secret chunks, and 1
signature chunk, derived from the canonical qv2 encoded-part caps of 6144, 512,
and 128 characters. Readers reject empty/oversized chunks, characters outside
the base64url alphabet, leading-zero counts, count/layout mismatches, unknown
transport versions, and total transport sizes above the derived bound before
reconstructing the exact `qv2.<claims>.<secret>.<sig>` bytes. The transport
decoder deliberately does not base64-decode its chunks: impossible lengths,
non-canonical trailing bits, schema errors, and invalid signatures remain the
unchanged strict inner parser and verifier's responsibility.

The public reader boundary accepts only `qv2t1`; legacy `#qv2.` public links are
not supported because qURL v2 has not entered production. The reconstructed
inner artifact is passed to the existing strict parser unchanged, and issuer
verification remains over the exact reconstructed claims string.

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
- v2 admission does not perform a resource-private-key signature/proof. The
  private half is reserved for a future resource-delegation proof, with no hot
  read/sign path in v2, under one of two custody modes chosen per owner
  (nhp #3137 / qurl-service #1175): HARDWARE custody keeps it non-exportable in
  a per-resource KMS CMK whose key policy MUST grant `kms:Sign` to no v2
  principal (Sign is added only when the delegation feature ships), so a code
  regression cannot quietly sign with a resource key; SOFTWARE custody (the
  default for unentitled owners) generates the keypair in-process and stores the
  private half only KMS-envelope-wrapped in `qurl-resource-key-material` —
  satisfying Goal 9's "KMS custody or KMS-wrapped storage" — with the
  compile-time no-Sign provider seam as the equivalent no-signing guarantee.
  Do not claim resource-private-key authorization until that proof protocol
  exists.
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

1. Strictly decode the framing of `#qv2t1.<counts>.<chunks...>` to the exact
   inner `qv2.<claims>.<secret>.<sig>` artifact, rejecting legacy/unknown
   transports. This step validates only bounded framing and the base64url
   alphabet; it does not create a second inner decoder.
2. Parse and canonicality-check the inner artifact with the strict qv2 parser.
3. Verify the issuer signature locally - REQUIRED for the first-party JS/headless
   client, not merely recommended. The client acts on `relay_url` and
   `cell_public_key_b64` (steps 4-5 and 8) to choose where to POST and what to
   encrypt to, all before any server sees the knock; server-side admission cannot
   protect against client misdirection. A tampered `relay_url`/cell key on an
   unverifying client yields DoS and claims disclosure (bounded: the private key
   never leaves the `secret` block and is not recoverable from the Noise
   handshake). Ship the issuer trust anchor (per `kid`) to the first-party client.
   Server-side verification remains authoritative for admission.
4. Compute `serverId = fingerprint(cell_public_key_b64)`.
5. Build an NHP knock using `qurl_user_private_key_b64` as the agent static
   private key and `cell_public_key_b64` as the server static public key.
6. Set the NHP knock resource identity to the protected-resource public key.
7. Put the signed qURL claims in encrypted knock user data.
8. POST the opaque NHP packet to `relay_url + "/relay/" + serverId`.

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
Content-Type: application/json

{
  "qurl_user_public_key_hash": "...",
  "src_ip": "203.0.113.10",
  "visitor_session_id": "..."
}
```

Both commit and cancel take the `admission_id` in the path AND a body. The
`qurl_user_public_key_hash` is REQUIRED: it is the state-row key qurl-service
partitions the admission by (path `admission_id` alone does not locate the
partition), not a trust input — the transaction stays conditioned on the lease
held by `admission_id`. `src_ip` is the observed client IP recorded on the
committed session (accepted empty). `visitor_session_id` is optional. Cancel
reuses the same body shape; `src_ip`/`visitor_session_id` are inert for a lease
release. This body was under-specified in an earlier revision, which let NHP send
bodiless commit/cancel POSTs that qurl-service 400'd — keep the schema explicit.

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
X-Request-ID: ...

{
  "authenticated_qurl_public_key_b64": "...",
  "client_ip": "203.0.113.10",
  "visitor_session_id": "...",
  "ac_id": "..."
}
```

Unlike prepare, authorize does not accept unsigned duplicate resource or qURL
identity fields. NHP must first run the local qv2 integrity boundary again on the
re-knock (issuer signature, signed `nbf`/`exp` liveness with skew, cell binding,
proof-of-possession, and resource binding). qurl-service then resolves the
already-authenticated qURL public key plus session match facts against its
authoritative hot state. A live session returns `remaining_seconds` and AC
routing metadata; no positive admission cache may allow a revoked or expired
session to refresh. NHP clamps `OpenTime` to `remaining_seconds` before
opening/refreshing the AC pinhole.

Re-knock semantics for one-time-use qURLs: a one-time-use qURL becomes `consumed`
after first admission, but its session must remain valid for `session_duration`.
The authorize path MUST key on resource + session facts (client/visitor session,
remaining lifetime), NOT on qURL `status = active`; otherwise re-knocks for a
still-open session of a consumed qURL are wrongly denied and the session dies at
the first `OpenTime` expiry. Today's `AuthorizeResourceAccess` already behaves
this way; v2 must preserve it and not regress into a qURL-status check.

### Admission-wire contract fixtures (canonical checksum)

This admission wire (the prepare / commit / cancel / authorize request and
response bodies above) is the source of truth for two independent contract-test
fixture sets that MUST stay byte-identical:

- **nhp** — `endpoints/server/staticplugins/qurl/testdata/qurlv2_admission_contract/`
  (asserted by `TestAdmissionWireContract`, which pins the nhp-server client DTOs).
- **qurl-service** — `tests/contract/testdata/qurlv2_admission/` (asserts the
  server side).

Both repos additionally assert that their own fixture set hashes to a single
canonical value:

```
canonical admission-wire fixture-set SHA256 =
0967eb6f4107a43028848867b6353db4f6cb2ef14bcdcc74d366009c8aea5678
```

Computation (identical in both repos): take every `*.json` in the fixture
directory (`README.md` excluded), sort filenames in byte order, concatenate the
raw file bytes in that order with **no separators**, then SHA256 and lowercase-hex.

What this checksum does and does not guarantee — be precise:

- It **does** catch a local fixture edit: changing a fixture in one repo without
  also updating that repo's committed checksum (this value) fails that repo's CI,
  forcing the editor to bump the hash here and re-copy the fixtures deliberately.
- It does **not** mechanically detect the other repo silently diverging. Each repo
  hashes only its own directory against its own copy of this constant; neither
  side reads the other's bytes. Two-repo byte-identity is a human lockstep
  discipline, not a mechanically-closed invariant. A green check means "the
  committed fixtures still hash to this value", not "the two repos agree" and not
  "these bytes match the live service".

Any change to a fixture MUST therefore update, in lockstep in the same change:
this hash (in the design doc and each repo's test constant), the fixtures in
**both** repos, and (if the wire itself changed) the request/response bodies
documented above.

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

Forwarded-flow carrier: the native server-to-server forward path re-resolves the
resource on the receiving server so AC routing and ACK construction stay local
to that receiver. To preserve targeted revocation metadata across that hop, the
origin server carries a narrow `admissionRevocationData` sidecar on `NHP_FWD`
only when the origin admission produced per-admission qURL v2 metadata; catalog
flows that carry only `resource_public_key_hash` omit the sidecar. Both
first-success `ForwardKnock` and coverage-only peer `FanoutKnock` use this same
carrier, so peer fan-out AOPs receive the same targeted-revocation metadata. The
receiver overlays only the qURL v2 revocation fields
(`qurl_user_public_key_hash`, `resource_public_key_hash`, `session_id`,
`admission_id`, `deadline`) onto its locally resolved catalog resource before
building the AOP. The receiver keeps its local catalog
`resource_public_key_hash` authoritative when present and uses the sidecar only
to fill a missing resource hash on forwarded v2 admissions; a stale receiver
catalog hash can therefore miss a resource-scoped revoke until the catalog
catches up, which is deliberate because pre-fix behavior was already
catalog-only and the receiver catalog remains the local source of truth. If the
sidecar hash differs from a present catalog hash, the receiver keeps the catalog
hash and emits `ForwardAdmissionResourceHashMismatch` plus a debug log for
rollout triage. The receiver trusts the
per-admission fields from an authenticated forwarding cell member over
server-to-server `NHP_FWD` and does not recompute or revalidate the
deadline/user/admission tuple; this is the same trust boundary as the forwarded
AOP itself. A faulty or compromised cell member could stamp a future forwarded
`deadline`, or mismatched `session_id`, `admission_id`, or
`qurl_user_public_key_hash` values, so a later targeted revoke may miss that
forwarded pinhole. That failure mode is within the same in-cell authority the
member already has to create forwarded AOPs directly, and is no worse than the
pre-fix resource-key-only fallback. On the AC, `deadline` is stored as qURL
revocation-index metadata only: `OpenTime`/`ExpireTime`, not this signed-claim
deadline, still bound firewall and token lifetime. This fix is scoped to the
native `NHP_FWD` path: the HTTP internal-knock re-entry path currently does not
originate the signed-claims per-admission fields (`buildV2ResourceData`), so it
has nothing to carry; if a future HTTP admission path does, it needs a matching
carrier. During a mixed-version rollout, forwards from old senders still fall
back to catalog metadata only, so targeted revoke coverage for forwarded flows
becomes complete once the server fleet has rolled past nhp #2774.

Implementation caveat (pre-epoch re-revoke window): until qurl-service #1010
emits real per-`(scope, scope_key)` monotonic epochs end-to-end, every revoke
carries `revocation_epoch = 0`, so the AC epoch gate (`admitEpoch` in
`endpoints/ac/revocation_index.go`) — a faithful mirror of the `revocation_epoch`
contract, with NO epoch-0 carve-out, since a carve-out would trade this
under-revoke for an over-revoke (a stale epoch-0 straggler re-firing on a newer
session) — can revoke-APPLY a given `(scope, scope_key)` only once. A revoke, a
re-admission under the same hash, then a second epoch-0 revoke is dropped
(`0 <= 0`), leaving the re-admitted session to natural expiry; **resource scope
is the sharp case** (its hash is a durable resource key, not a per-session
value). This is safe pre-epoch ONLY because of the no-positive-cache contract
above: a revoked key is denied on its very next admission, so it cannot recur to
hit the once-only-apply limit. **Verified on qurl-service main (2026-06-30):**
admission gates fresh on `!resource.IsActive()` → `ErrResourceRevoked` and
`QurlStatusRevoked` → `ErrQurlRevoked` (`internal/service/resolve_service.go`),
and v2 disables the qurl-router L7 positive-auth cache (the `IsV2()` signal) so a
revoke takes effect on the next re-check — there is no positive admission cache
on the v2 path. The window dissolves once qurl-service #1010 lands (a re-revoke
then carries a strictly greater epoch); the symmetric qurl-service #1028 TOCTOU
relies on this same AC high-water mark as its backstop. This precondition must
stay verified before v2 admission and the revoke Sink are enabled in any live
environment. Tracked in #2781.

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
the P4b apply primitive (`ApplyRevocation`). The original ordering pulled the
shared key's deadline to now and *then* removed the revoked entry from the token
store; in that window a concurrent natural expiry of a sibling holding the same
`FlowKey` could re-derive the key's deadline from a token-store snapshot that
still listed the revoked entry and push the deadline back (longest-wins
`Schedule`), leaving the revoked flow alive to natural expiry. The #2784 interim
narrows this by **removing the revoked entry from the token store BEFORE the
flush** (`flushEntryNow` drains the entry's tracked keys off the entry pointer,
not the token store, so it still fires after the delete). A sibling that
snapshots after the delete then sees no live holder and `Cancel`s the shared key
instead of pushing its deadline back — closing the dominant push-back. Two
residuals remain (a sibling that snapshotted just before the delete can still
push the deadline back; a sibling `Cancel` landing after the reschedule drops the
coarse reschedule). Both touch only the coarse allow-rule re-open barrier —
`flushEntryNow`'s surgical conntrack teardown runs synchronously per key, so on
eBPF/XDP v4 ACs the revoked established flows are already gone and only the
allow-rule lingers to its kernel TTL; iptables-mode and v6 flows fall back to
kernel TTL entirely. The apply path is wired (`NHP_REV` → `HandleUdpACRevocation`
→ `ApplyRevocation`, #2753), so these are live-but-bounded windows: each needs a
real revoke applying in the microsecond window of a sibling's natural expiry on
the same `FlowKey`, bounded by the kernel TTL. Both are fully closed by the same
per-session kernel discriminator below — the over-flush and under-flush
directions dissolve once revoke is surgical. Tracked in #2784.

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

Filter-mode/IPv6 caveat — DECLARED DISPOSITION (#2778/#2794/#2837/#2165, DE Risk #6).
Immediate revocation of IPv6 established flows is now **resolved on the eBPF/XDP
datapath** and resolved under iptables when the #2165 netlink backend is selected.
Status by mode:

- **eBPF/XDP (`FilterMode_EBPFXDP`) — RESOLVED (#2837)**: v6 established flows are
  torn down surgically by `FlushConnV6` + `EnumerateConnTrackSrcPortsV6` against a
  pinned `conn_track_v6` map (the IPv6 twin of the v4 `conn_track` path), driven
  from `flushEntryNow` → `surgicalFlushFlowKey` → `surgicalFlushFlowKeyV6`. A v6
  revoke is immediate, proven at the map-op level (the live-XDP next-packet-drop
  proof is the #2779 kernel-rig gate). When the v6 seam is **unwired** (a v4-only
  build / non-Linux) the path hard-fails loudly (below) rather than silently
  treating the v6 flow as killed.
- **iptables + exec (`FilterMode_IPTABLES`, `l3FlushConntrackBackend="exec"`) —
  DECLARED GAP (#2794)**: the `ConntrackFlusher` shells `conntrack -D` with no
  `-f ipv6`, so it rejects a v6 key at its boundary and tears nothing down, and
  the surgical seam is EBPFXDP-only. A revoked v6 flow under this backend dies
  only at its kernel TTL.
- **iptables + netlink (`FilterMode_IPTABLES`, `l3FlushConntrackBackend="netlink"`)
  — RESOLVED (#2165)**: the `ConntrackFlusher` uses direct ctnetlink operations
  and handles both IPv4 and IPv6. `flushEntryNow` therefore reschedules v6 keys
  through the same coarse immediate-flush path iptables already uses for v4, and
  `MetricRevocationIPv6HardFail` stays quiet. The sibling-preserving netlink
  surgical path is tracked separately; this keeps iptables' existing coarse
  mass-delete semantics while making them v6-capable.

This gap is **surfaced, not silently swallowed**: `(*UdpAC).flushEntryNow` ticks
the dedicated `MetricRevocationIPv6HardFail` for every v6 key it cannot tear
down — eBPF v6-seam-unwired via `surgicalFlushFlowKey`, iptables+exec via its
explicit `FilterMode_IPTABLES` branch, plus once per failed per-flow
`FlushConnV6` on a wired seam. With the netlink backend
(`coarseConntrackHandlesV6`) the iptables v6 revoke is torn down and no hard-fail
fires. The metric is distinct from the benign per-flusher skip counters
(`BpfFlusherSkippedCount` / `ConntrackFlusher` `metricSkipped`) that track
scheduled-expiry v6 leaks. ANY nonzero reading is a real immediate-revocation gap
to alarm on.

**Expiry-skip vs revoke-skip — SPLIT (#2778 part 2).** The coarse allow-rule
reschedule in `flushEntryNow` (`Scheduler.RescheduleEarlier`) is **IPv4-only
except for iptables+netlink**. It is never issued for a v6 key under eBPF/XDP or
iptables+exec, because the established-flow teardown it would trigger there is
IPv4-only (eBPF allow-rule maps; `conntrack -D`), making a v6 reschedule a pure
no-op. Issuing it would IMMEDIATELY tick the v4-only flushers' expiry-skip
counters (`BpfFlusherSkippedCount` / `ConntrackFlusher` `metricSkipped`,
published as `MetricL3FlushBpfSkipped`) on every revoke, conflating a benign
scheduled-expiry v6 leak with a failed v6 revoke. With the reschedule gated to v4
or netlink-capable iptables, those counters are the **expiry-skip** signal alone
and `MetricRevocationIPv6HardFail` is the **revoke-skip** signal — the two are
cleanly distinguishable, which is what DE Risk #6 requires (a silent failed
revoke must not hide inside a benign counter). Note this *defers* rather than
*eliminates* a revoked v6 flow's expiry-skip tick under the v4-only paths:
`deleteToken` uses `tokenStore.Delete` (no `OnExpire` hook →
no `cancelAllScheduledFlows`), so the revoked flow's lingering scheduled flush
still fires one benign no-op tick at its natural firewall deadline — what the gate
removes is the revoke-correlated *spike*, not the per-flow tick.
Dropping that orphan tick entirely (routing the revoke path through
`cancelAllScheduledFlows`) is tracked separately in #2901 — it touches the #2201
multi-session reschedule consult, so it is out of scope here.

Note this is a teardown-of-*established*-flows gap only (and only under
iptables+exec / an unwired eBPF v6 seam now): re-open is barred regardless — the
entry is removed from the token store so a refresh / re-knock cannot extend it,
and the ipset / allow-rule entry self-expires on its own timeout. The residual v6
established flow's lifetime (to kernel TTL) is the only exposure, never a
re-openable hole.

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
- `target_ac_ids` is matched on the NHP server by string equality against
  `ACConn.ACId` (the AC's configured id) — the same identifier space qurl-service
  records in a session's `admitted_ac_ids` and copies into `target_ac_ids`. This
  is a cross-repo, string-equality contract with no shared schema: if either side
  ever changes what it stores in that field (a pubkey hash, a DB row id, a
  blue/green-suffixed id, a re-normalized form), targeted fanout silently matches
  nothing and **fails open** (the missed `NHP_REV` leaves the AC entry to expire);
- until the remaining nhp #2790 gates pass, the incomplete-targeted reject is the
  interim backstop;
- the server side (P4e Slice 2, nhp #2789) builds and unit-tests the targeted
  path, and the **"targeted matched zero ACs" observability guard now exists**
  (`RevocationTargetedZeroMatch`, nhp #2790). A targeted event that named a
  non-empty `target_ac_ids` set but matched no connected AC on a server increments
  the counter, so an identifier-space drift is a countable signal instead of a
  silent no-op. Read it FLEET-WIDE: a single server legitimately zero-matches when
  the named ACs are connected to sibling servers, so the drift signature is every
  server zero-matching at once while fleet `RevocationFanoutSent` for targeted
  events collapses to 0. The counter catches this all-or-nothing drift; a PARTIAL
  intra-event drift leaves the match set non-empty and is NOT caught, so the
  drifted id's `NHP_REV` still fails open. That is an accepted blind spot given
  the single shared id encoding;
- three things gate enabling targeted fanout cross-repo, all tracked in nhp
  #2790: (1) qurl-service emits **cell-wide only** until the P3c
  `admitted_ac_ids` builder wiring lands; (2) the id-correspondence MUST be
  proven end-to-end; and (3) the fleet-wide CloudWatch alarm on
  `RevocationTargetedZeroMatch` MUST be deployed and verified before targeted
  fanout is enabled;
- that alarm is now provisioned by `terraform/modules/monitoring` and reads the
  two series' shapes, NOT a literal ratio: `RevocationTargetedZeroMatch` is +1
  per event while `RevocationFanoutSent` is +N per event (N = ACs matched), so
  dividing them mixes events with AC-deliveries. It watches for zero-match
  activity while the `FanoutMode=targeted` `RevocationFanoutSent` stream stays at
  0 in the same window; using the targeted-only stream prevents unrelated
  cell-wide revokes from masking id drift;
- the alarm is an intentional fail-loud triage signal, not proof by itself that
  the identifier contract drifted. A legitimate event whose named ACs are all
  disconnected fleet-wide can produce the same shape. The inverse blind spot is
  also possible inside a single 5-minute bucket: a drifted targeted event can be
  masked if a different targeted event in that bucket successfully fans out, so
  incident review must inspect raw zero-match logs/events around the alarm window;
- any dashboard that graphs `RevocationFanoutSent` should pin the base
  `{Environment, Cell}` stream or a specific `FanoutMode` stream; broad
  all-dimension aggregation double-counts the base and breakdown series;
- the alarm remains no-data/not-breaching until targeted events exist. During a
  pure zero-match bucket, the metrics publisher drops the zero-valued
  `RevocationFanoutSent{FanoutMode=targeted}` counter, so the alarm is
  intentionally proving FILL over an absent targeted-fanout series rather than
  over an explicit zero datapoint. Before enabling targeted fanout, the rollout
  gate must exercise the breach path as a hard, non-skippable gate with a
  controlled synthetic `RevocationTargetedZeroMatch` datapoint and no matching
  `FanoutMode=targeted` fanout datapoint, proving the
  `FILL(targeted_fanout, 0)` expression enters ALARM for the actual absent-series
  drift shape. The applied/not-ALARM check is not a substitute for this proof; it
  only verifies the alarm exists after the absent-series ALARM transition has
  been proven;
- the remaining pre-enable work is to complete the qurl-service builder wiring,
  prove id-correspondence end to end, prove the alarm breach path, and confirm
  the applied alarm is present, actions are enabled, and the alarm is not ALARM;
- bounded retry with dead-letter visibility;
- AC ack recorded for operational proof;
- a defined end-to-end revocation-latency SLO (e.g. p99 from revoke API to AC
  flush-complete < N seconds), measured and tested. "Immediate" must be a number,
  since fan-out + index lookup + flush is not instantaneous.

  ACTIVE IN TERRAFORM-MANAGED FLEETS (nhp #2808 + #2793): the number is
  defined, tested, and explicitly armed by server user data —
  `p99 < 15s` (`RevocationDeliveryLatencyP99SLO`) over the server-measurable
  proxy span, `NHP_REV` emit (`firstSentAt`) → `NHP_RVA` ack-attributed
  (`clearAck`), with a p99 CloudWatch alarm and a companion
  `RevocationAgedOut` non-delivery alarm, plus `RevocationUntrackable` for
  impossible live-connection identity invariant breaks. The histogram samples
  ACKED revokes only; never-delivered revokes surface as `RevocationAgedOut`
  (the two delivery alarms are read together). The Go binary's absent-env
  default remains off only for unmanaged/pre-ACK deployments; sandbox/prod set
  `NHP_REVOCATION_RETRY_ENABLED=true` with a 5s resend cadence and 60s age-out.

  Operational-proof boundaries:
  - The pending tracker keys proof by targeted live AC slot:
    `(acId, authenticated AC pubkey, scope, scope_key)`. `acId` remains the
    qurl-service targeting identifier, but `acConnectionMap` can hold multiple
    blue/green slots under one `acId`; each targeted slot must ack or age out
    independently. One sibling's `NHP_RVA` does not clear another sibling's
    pending entry or record its latency sample.
  - The `RevocationDeliveryLatency` p99 is therefore per targeted AC slot, not
    per `acId` or per revoke event. A blue/green overlap can produce multiple
    samples for one revoke and can increase `RevocationAgedOut` counts if a
    targeted slot drains before it acks; read the SLO as per-slot delivery.
    Pending proof cardinality is bounded by `revoke_rate * ageOut * live_slots`
    because entries are keyed per targeted slot and are removed on ack or
    deadline.
  - If fanout was enqueued but the server cannot key the live connection to
    `ACId` + authenticated AC pubkey, the retry engine emits
    `RevocationUntrackable` instead of overloading retry age-out.
  - `NHP_RVA` is sent only after the AC validates the `NHP_REV` and calls
    `ApplyRevocation`; this is a convergence ack ("no live flow for this
    identity at/below this epoch on this AC slot"), not a count of flushed flows.
  - Proof is tracked only for scopes the AC actually applies and acks
    (`qurl`/`resource`/`session` — the AC's `wireRevocationScope` allowlist,
    mirrored server-side by `revocationAckableScopes`). The `cell` scope is a
    server-side fanout selector with no AC-local index: the server still accepts
    and fans out `cell`, but the AC drops it without acking, so the server does
    **not** create a pending proof entry for it. Tracking it would otherwise
    guarantee a never-arriving ack and a false `RevocationAgedOut` on every
    targeted AC once the engine is armed (nhp #2793). A `cell` revoke therefore
    produces neither a latency sample nor an age-out — its "delivery" is the
    fanout itself, not a per-flow AC ack.
  - Because proof is per live slot, a revoke that overlaps a blue/green drain can
    age out for a slot that was targeted and then decommissioned before its ack
    arrived. nhp #2868 intentionally keeps this as a raw
    `RevocationAgedOut` signal rather than pruning on ordinary disconnect,
    UDP loss, or unknown AC drop: the server does not yet receive an AC-side
    decommission proof that the exact `(acId, authenticated AC pubkey, scope,
    scope_key)` slot can no longer host the revoked flow. Until that proof
    exists, retry keeps pending entries through disconnect and ages them out.
    Production paging is tuned around the known deploy overlap instead: the raw
    `revocation-aged-out` alarm remains `Sum >= 1`, deploy workflows emit and
    refresh a short-lived `{Environment, Cell}` `DeploymentWindow` metric in
    the deploy-only `LayerV/NHP/Deploy` namespace while long ASG/canary polls
    are still active, and
    `revocation-aged-out-page` pages only when the raw detector is ALARM outside
    the roughly 10-minute window after the latest deploy heartbeat. During the
    window the raw alarm remains visible for audit; outside it, a single
    non-deploy age-out still pages.
  - This is a bounded paging tradeoff, not a weakening of the raw detector:
    a transient age-out that happens inside the deploy-heartbeat window is
    suppressed from paging rather than queued for a later page. It pages only
    if the raw detector remains or repeats after the suppressor clears. The raw
    `RevocationAgedOut` metric and no-action alarm remain visible throughout
    for dashboards, audits, and incident review; the no-action
    `revocation-aged-out-suppressed` composite is an explicit breadcrumb for
    the `raw ALARM && deploy-window ALARM` case. Issue #2974 hardens the
    suppressor by moving it out of the shared app namespace: server/AC app
    metric roles are explicitly denied from `LayerV/NHP/Deploy`, deploy
    automation emits a paired `DeploymentWindowRun` marker, and
    `revocation-deploy-window-without-run` pages on unpaired or legacy
    suppressor writes that omit that run marker. The IAM namespace boundary is
    the primary control that prevents non-deploy principals from writing paired
    suppressor metrics.
  - The retry engine is explicitly armed by Terraform-managed server fleets via
    `NHP_REVOCATION_RETRY_ENABLED=true`; changing or disabling it should be
    treated as a security-relevant rollback because it returns server→AC
    delivery to fire-and-forget semantics. The binary still treats an absent env
    var as disabled so unmanaged/pre-ACK fleets can upgrade safely.

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

- Add signed canonical `qv2.` artifacts carried publicly as `qv2t1` transports.
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
