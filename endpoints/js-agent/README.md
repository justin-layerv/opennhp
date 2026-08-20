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

The qURL v2 public reader accepts the share-safe
`#qv2t1.<counts>.<chunks...>` transport only. `src/qurl/transport.ts` bounds and
validates that wrapper, reconstructs the exact inner
`qv2.<claims>.<secret>.<sig>` artifact, and hands it to the unchanged strict
parser/signature verifier. The 240-character canonical chunks prevent one long
dot-delimited component from being cut out of a link by messaging-client URL
detectors. Legacy `#qv2.` public transport is intentionally rejected because v2
has not entered production.

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
   - **b. Relay transport + knock loop** (#2609) — `agent/relay.ts`
     (`relayPost`: `POST /relay/{serverId}`, octet-stream, mirroring
     `endpoints/relay/relay.go`), `agent/knock.ts` (`buildKnockBody`: the
     `AgentKnockMsg` body, owning the #1154 `headerType`), and `agent/loop.ts`
     (`knock`: build → POST → `decryptReply` → dispatch). Dispatch returns a
     discriminated `KnockResult` — `success` (resource hosts + AC tokens),
     `reResolve` (the `52024` session-expired deny, #2550), `serverError`, or
     `cookieChallenge` — and `throw`s only on faults (transport, crypto, or
     ACK-counter correlation #2603). The transport is injectable (mock-tested);
     the body and the success/`52024`/cookie dispatch are Go-fenced
     (`nhp/core/js_agent_loop_roundtrip_test.go`).
   - **c. Overload cookie-challenge** — `NHP_COK` → `NHP_RKN` re-knock folding in
     the server cookie. **Deferred (tracked by #2611):** #2648 makes the
     overload COK routable through the relay again; the remaining work is the
     agent's COK→RKN handling plus the fork's stateless-cookie follow-up. The
     agent handles a delivered COK gracefully meanwhile via the `cookieChallenge`
     result. Lands once the rest of #2611 does.
   - **d. Re-knock renewal scheduler** (#2612) — `agent/scheduler.ts`
     (`startRenewal`): keeps an open grant alive by re-knocking a fresh `NHP_KNK`
     (via the loop's `knock`, so it's live-reachable — no relay-COK dependency) at
     `openTime × (1 − margin) ± jitter`, rescheduling off each new grant. The
     `margin` is a **retry budget**: a transient transport/server fault is an
     unknown outcome with session left, so it retries within the budget (a
     re-knock is idempotent) and only signals `onExpired` on a `52024` deny or an
     exhausted budget. **Background-tab limitation** (the hard part): clamped /
     suspended background timers can miss the deadline, and the JS-side fix is
     **foreground recovery** (a Page Visibility handler re-knocks on return if
     overdue) — so a backgrounded session may need a fresh knock on return. The
     server/relay-side **grace window** that would avoid that is a separate
     follow-up. No Go fence — pure browser orchestration; the load-bearing tests
     are the foreground-recovery and single-flight paths.
6. **Bundling** — `npm run bundle` (esbuild) emits one self-contained
   ESM file, `dist/nhp-agent.min.js` (~23 KB gzipped), with the `@noble` suite
   inlined, for the qurl.link page to load as a same-origin
   `<script type="module" src>` with `integrity="sha384-..."`. The
   qurl-link Terraform module renders the relay origin and server static pubkey
   into the page when `js_agent_enabled` is true, then the page imports this
   bundle and performs the bootstrap knock through the relay. `test/bundle.test.ts`
   gates the gzip budget and the runtime public-export surface via esbuild's
   metafile (no execution — node has no DOM; that end-to-end seam is #2616).
   The qurl-link Terraform module hash-pins its inline verifier scripts with
   CSP `sha256` source expressions and
   relaxes CSP only when the bundle is intentionally served: `script-src` gains
   `'self'` for the same-origin module, and `connect-src` gains the relay origin
   so `POST /relay/{serverId}` is not blocked by `default-src 'self'`. The
   external bundle's exact-byte pin lives on the script tag's SRI metadata, not
   as a CSP source expression. Terraform consumes the generated
   `nhp-agent.min.js.sri` sidecar to render the `integrity` metadata. When the
   agent is mounted, qurl.link serves the HTML and bundle with `no-cache` so
   browsers revalidate the SRI-pinned pair during bundle rotations. The package
   test and deployed smoke coverage recompute SHA-384 from the bundle bytes so
   artifact and HTML metadata drift fails loudly.

GMSM (SM2/SM3/SM4) is intentionally **not** ported — this fork strips it, so the
runtime dependency surface is the noble suite only: `@noble/hashes` (BLAKE2s /
SHA-256 / HMAC), `@noble/curves` (X25519), and `@noble/ciphers` (AES-256-GCM).
The runtime deps and esbuild are exact-pinned for bundle/SRI reproducibility;
`.github/dependabot.yml` watches `/endpoints/js-agent` so security and version
bumps still arrive as explicit PRs.

## Develop

```sh
cd endpoints/js-agent
npm ci
npm test           # vitest — Go-golden-vector fences (fingerprint, KDF) + crypto KATs
npm run build      # typecheck: tsc over the src (browser-only) AND test (Node) configs
npm run bundle     # esbuild → dist/nhp-agent.min.js (ESM, @noble inlined), gzip-budget gated
npm run sync:qurl-link # rebuild, copy to Terraform qurl-link assets, and write nhp-agent.min.js.sri
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
