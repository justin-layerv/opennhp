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
2. **Cipher-suite primitives (this PR)** — X25519, AES-256-GCM,
   BLAKE2s/SHA-256, and the NHP HKDF (`NoiseFactory`) under `src/crypto/`. Each
   primitive is fenced against the Go golden vectors / known-answer tests it
   must agree with (`nhp/core/kdf_test.go` for the KDF; RFC 7748 / RFC 7693 /
   FIPS 180-4 / a standard AES-256-GCM KAT for the rest). Deterministic, so no
   handshake state yet.
3. **Noise IK handshake + packet wire format** — assemble a knock from the
   primitives (the 240-byte header + encrypted body). Interop is proven by
   having Go **decrypt a TS-produced knock** (a committed round-trip fixture):
   TS owns the ephemeral/timestamp/counter and emits the bytes; a Go test
   decrypts them and asserts the recovered static key / timestamp / payload. No
   Go production change, no fragile byte-reproduction.
4. **Agent loop** — knock / re-knock, ACK handling, and the qurl-service
   contracts the server pinned: the `r_` resource id and the `52024`
   "session expired → re-resolve" deny code (#2550).
5. **Bundling** for the qurl.link page.

GMSM (SM2/SM3/SM4) is intentionally **not** ported — this fork strips it, so the
runtime dependency surface is the noble suite only: `@noble/hashes` (BLAKE2s /
SHA-256 / HMAC), `@noble/curves` (X25519), and `@noble/ciphers` (AES-256-GCM).

## Develop

```sh
cd endpoints/js-agent
npm ci
npm test        # vitest — Go-golden-vector fences (fingerprint, KDF) + crypto KATs
npm run build   # tsc --noEmit typecheck
```
