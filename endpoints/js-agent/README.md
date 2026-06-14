# @layervai/nhp-js-agent

Browser NHP agent (#2208): knocks the **NHP-Relay** over HTTPS to open access to
a qURL-protected resource, so the NHP-Server can stay off the public internet.

```
Browser (this package) --HTTPS POST /relay/{serverId}--> NHP-Relay --NHP_RLY--> NHP-Server --> AC
```

This package is **wire-compatible with the Go `nhp/core` implementation in this
repo** — the server decrypts exactly what the browser produces — so it lives
here, beside the wire-format source of truth and the cross-language golden
vectors (`nhp/utils/crypto_fingerprint_test.go`), rather than in a separate repo
where the two could silently drift.

## Status / PR sequence

Ported incrementally, each step its own PR:

1. **Fingerprint foundation (this PR)** — `pubKeyFingerprint`, the
   `POST /relay/{serverId}` routing id, fenced against the Go golden vectors.
2. **Crypto core** — Noise IK handshake + packet wire format
   (`@noble/curves` / `@noble/ciphers` / `@noble/hashes`), cross-tested against
   a Go-produced knock.
3. **Agent loop** — knock / re-knock, ACK handling, and the qurl-service
   contracts the server pinned: the `r_` resource id and the `52024`
   "session expired → re-resolve" deny code (#2550).
4. **Bundling** for the qurl.link page.

GMSM (SM2/SM3/SM4) is intentionally **not** ported — this fork strips it, so the
runtime dependency surface is just `@noble/hashes` (plus the curve/cipher
packages when the crypto core lands).

## Develop

```sh
cd endpoints/js-agent
npm ci
npm test        # vitest — includes the Go-golden-vector fingerprint fence
npm run build   # tsc --noEmit typecheck
```
