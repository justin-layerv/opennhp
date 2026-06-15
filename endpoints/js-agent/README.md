# @layervai/nhp-js-agent

Browser NHP agent (#2208): knocks the **NHP-Relay** over HTTPS to open access to
a qURL-protected resource, so the NHP-Server can stay off the public internet.

```
Browser (this package) --HTTPS POST /relay/{serverId}--> NHP-Relay --NHP_RLY--> NHP-Server --> AC
```

This package is **wire-compatible with the Go `nhp/core` implementation in this
repo** — the server decrypts exactly what the browser produces — so it lives
here, beside the wire-format source of truth and the cross-language golden
vectors it is fenced against (`nhp/utils/crypto_fingerprint_test.go`,
`nhp/core/kdf_test.go`), rather than in a separate repo where the two could
silently drift.

## Status / PR sequence

Ported incrementally, each step its own PR:

1. **Fingerprint foundation** (#2555) — `pubKeyFingerprint`, the
   `POST /relay/{serverId}` routing id, fenced against the Go golden vectors.
2. **Cipher-suite primitives** (#2560) — X25519, AES-256-GCM,
   BLAKE2s/SHA-256, and the NHP HKDF (`NoiseFactory`) under `src/crypto/`. Each
   primitive is fenced against the Go golden vectors / known-answer tests it
   must agree with (`nhp/core/kdf_test.go` for the KDF; RFC 7748 / RFC 7693 /
   FIPS 180-4 / a standard AES-256-GCM KAT for the rest). Deterministic, so no
   handshake state yet.
3. **Noise IK handshake + packet wire format** (#2567) — `packet.ts` (the
   240-byte `HeaderCurve` codec + nonce + header digest) and `handshake.ts`
   (`buildKnock`, the Noise IK key schedule from `nhp/core/initiator.go`).
   Interop is proven mechanically by a committed fixture
   (`test/testdata/knock.json`): the TS side pins the bytes
   (`handshake.test.ts`) and the **real Go responder decrypts them**
   (`nhp/core/js_agent_roundtrip_test.go`). Test-only — no Go production change.
4. **ACK decrypt** (#2600) — `ack.ts` (`decryptReply`), the responder side:
   the browser decrypts the server's `NHP_ACK` / `NHP_COK` reply
   (`responder.go` from the agent's perspective). The recovered server static
   key is checked against the one knocked — pinning the server identity, with the
   `ss`-keyed timestamp/body open completing the authentication — and the body is
   zlib-inflated via the native `DecompressionStream` (no zlib dependency). Fenced
   by a frozen Go-generated
   fixture (`test/testdata/ack.json`) decrypted by **both** TS (`ack.test.ts`)
   and the Go responder (`nhp/core/js_agent_ack_roundtrip_test.go`).
5. **Agent loop** — landing incrementally:
   - **a. Production knock builder** (#2606) — `agent/knock.ts` (`createKnock`)
     wraps the fixture-fenced `buildKnock` with the per-knock values the agent
     randomises/stamps at runtime: a fresh CSPRNG ephemeral, transaction counter,
     and header preamble, plus the send timestamp (capped to Go's int64
     `UnixNano`). `buildKnock` stays fixture-fenced; the wrapper is
     property-tested (distinct ephemeral / counter / nonce per knock).
   - **b. Relay transport + knock loop (this PR)** — `agent/relay.ts`
     (`relayPost`: `POST /relay/{serverId}`, octet-stream, mirroring
     `endpoints/relay/relay.go`), `agent/knock.ts` (`buildKnockBody`: the
     `AgentKnockMsg` body, owning the #1154 `headerType`), and `agent/loop.ts`
     (`knock`: build → POST → `decryptReply` → dispatch). Dispatch returns a
     discriminated `KnockResult` — `success` (resource hosts + AC tokens),
     `reResolve` (the `52024` session-expired deny, #2550), `serverError`, or
     `cookieChallenge` — and `throw`s only on faults (transport, crypto, the
     ACK-counter correlation #2603). The transport is injectable (mock-tested);
     the body and the success/`52024`/cookie dispatch are Go-fenced
     (`nhp/core/js_agent_loop_roundtrip_test.go`).
   - **c. Overload cookie-challenge** — `NHP_COK` → `NHP_RKN` re-knock folding in
     the server cookie (`responder.go` sends it only when overloaded; it is _not_
     the renewal path).
   - **d. Re-knock renewal scheduler** — re-knock (a fresh `NHP_KNK`, spec Step 8)
     before Access Duration expires; the background-tab renewal contract is a
     product decision, deferred.
6. **Bundling** for the qurl.link page.

GMSM (SM2/SM3/SM4) is intentionally **not** ported — this fork strips it, so the
runtime dependency surface is the noble suite only: `@noble/hashes` (BLAKE2s /
SHA-256 / HMAC), `@noble/curves` (X25519), and `@noble/ciphers` (AES-256-GCM).

## Develop

```sh
cd endpoints/js-agent
npm ci
npm test           # vitest — Go-golden-vector fences (fingerprint, KDF) + crypto KATs
npm run build      # typecheck: tsc over the src (browser-only) AND test (Node) configs
npm run lint       # ESLint (flat config; mirrors the Go golangci-lint gate)
npm run format     # Prettier --write (CI runs `format:check` to verify)
```

`src/` typechecks against browser/DOM types only; Node globals (`Buffer`,
`process`, …) are scoped to `test/` via `tsconfig.test.json`. A `Buffer` in
`src/` therefore fails `npm run build` — enforced permanently by
`src/node-isolation.guard.ts`.

The Go-golden-vector fences are no longer kept in sync by hand: the marked
vectors here and in their Go counterparts (`nhp/utils/crypto_fingerprint_test.go`
for the fingerprint, `nhp/core/kdf_test.go` for the KDF) are cross-checked by
`scripts/check-golden-vectors.sh` (run in CI via `validate-workflows.yml`), so a
one-sided change fails the build.
