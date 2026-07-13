# Access-Token Touch Inventory

Project-wide inventory of every code site in this repository that **handles,
logs, or persists** an NHP access token, plus the recorded decision on the
post-leak replay window. Completes the in-repo (Go) portion of
[#1426](https://github.com/layervai/nhp/issues/1426) (cross-repo work stays
tracked there — see the last section); the per-component follow-ups it
superseded are [#1421](https://github.com/layervai/nhp/issues/1421)
and [#1424](https://github.com/layervai/nhp/issues/1424).

## Why this exists

After [nhp#1124](https://github.com/layervai/nhp/issues/1124) the AC access
token is no longer a SHA-256 hash of public inputs — it is opaque random bytes
(`common.GenerateOpaqueToken`), i.e. **the token IS the entire auth secret**.
Any log line, error string, or struct dump that exposes a full token hands an
attacker a usable credential. The same applies to the NHP session JWTs minted
by the passcode plugin (`nhp_token` / refresh token). This document is the
single place that enumerates the token touch-surface so a future change can be
checked against it.

## What counts as an access token here

| Token | Type | Minted by | Carried in |
|---|---|---|---|
| AC access token | 32 opaque bytes, base64-StdEncoding (44 chars) | `UdpAC.GenerateAccessToken` | `ACOpsResultMsg.ACToken`, `PreAccessInfo.ACToken`, `ServerKnockAckMsg.ACTokens`, `AgentAccessMsg.ACToken`, `HttpRefreshRequest.Token` |
| NHP session JWT / refresh JWT | HS256 JWT | passcode plugin (`JWTToken.GenerateAll`) | `nhp_token` cookie, `nhpplugins.RefreshResponse.NHPToken` / `.NHPRefreshToken` |
| AuthProviderToken (`aspToken`) | provider-issued bearer | upstream auth service | `ServerKnockAckMsg.AuthProviderToken` |

The redaction contract for a token *value* is `common.RedactToken` (Go), which
keeps the first `tokenLogPrefixLen` (= 8) characters and appends an ellipsis.
For a *URL query string* that may carry `token=`, the server uses
`redactSensitiveQuery` (replaces the `token` param with `[REDACTED]`, no-op
otherwise). Non-Go components pin the same 8-char prefix convention.

## Audit method

The sweep was **type-aware**, not keyword-only: every `%+v` / `%#v` / `%v`
struct-dump in a `log.*` call across `endpoints/server`, `endpoints/ac`,
`endpoints/agent`, and `nhp/` was cross-referenced against the token-bearing
types/fields above (`ACToken`, `ACTokens`, `AuthProviderToken`,
`PreAccessInfo`, `RefreshResponse`, passcode `nhpToken`/`refreshToken`). This
catches dumps under variable names that never contain the word "token" (e.g.
`log.Info("Done %+v", resp)`), which a literal `token` grep misses.

A second pass covered **raw `%s` of response/body strings** (`string(body)`,
`string(respBody)`, `io.ReadAll` results) — a class the struct-dump pass
misses because the bytes have no Go type. That pass found the IAM `200`-body
log below; the remaining hits are non-`200` *error* bodies (see out-of-scope).

A third pass covered **inbound request credentials** — `Authorization` /
`Cookie` headers and `ctx.Request.URL.RawQuery` (the `nhp_token` cookie and the
legacy `?token=` query param are both in-scope). The `Authorization` header and
the `nhp_token` cookie value are never logged (only presence/absence is). The
`RawQuery` logs are now all routed through `redactSensitiveQuery` (below).

## Log sites

Status legend: **FIXED** = changed in the PR that introduced this doc; **SAFE**
= reviewed, already redacted or never carries a token (no change).

| Site | Token reachable | How touched | Status |
|---|---|---|---|
| [`endpoints/server/staticplugins/passcode/main.go`](../endpoints/server/staticplugins/passcode/main.go) `AuthWithHttpRefresh` (invalid-token branch) | NHP session JWT (validated then rejected) | `%s` of full `nHPToken` — **active leak** | **FIXED** → `common.RedactToken` |
| [`endpoints/server/staticplugins/passcode/main.go`](../endpoints/server/staticplugins/passcode/main.go) `log.Info("Done %+v", resp)` | `RefreshResponse.NHPToken` + `.NHPRefreshToken` | `%+v` struct dump — **active leak** | **FIXED** → log only the sanitized redirect URL (scheme/host/path) |
| `nhpplugins.GetRedirectUrlByResource` calls from passcode/OIDC | redirect `access_token` JWT | SDK `v0.1.30` always appends `access_token` to the redirect query and logs the generated token internally (`ServiceInfo JSON...`) — **active leak** | **FIXED** → in-repo `staticplugins/internal/redirecturl.GetByResource` preserves the client URL but emits only sanitized, query/fragment-free logs |
| [`endpoints/server/staticplugins/passcode/main.go`](../endpoints/server/staticplugins/passcode/main.go) ×2 (`GenerateAll`, refresh) | NHP session JWT | ad-hoc 10-char prefix `nhpToken[:min(10,…)]` | **FIXED** → `common.RedactToken` |
| [`endpoints/server/staticplugins/passcode/main.go`](../endpoints/server/staticplugins/passcode/main.go) (`AuthWithHttpRefresh` empty branch) | none | logged `nHPToken` inside `len==0` guard (always empty) + misleading "expired" wording | **FIXED** → `nhp_token cookie missing`, value dropped |
| [`endpoints/server/staticplugins/passcode/main.go`](../endpoints/server/staticplugins/passcode/main.go) `authAccessFromRaaS` | upstream IAM config payload | `%s` of full `string(body)` — the IAM `200` portal-site response, logged verbatim at Info; body is otherwise **unused** (defense-in-depth: may carry config secrets/tokens) | **FIXED** → log `len(body)` only |
| [`endpoints/ac/httpac.go`](../endpoints/ac/httpac.go) `/refresh` unescape | AC access token (1–3 bytes) | `url.QueryUnescape` `EscapeError` echoes the malformed percent-escape ([#1424](https://github.com/layervai/nhp/issues/1424)) | **FIXED** → generic message, `err` dropped |
| [`endpoints/server/udpserver.go`](../endpoints/server/udpserver.go) `processACOperation` | `ACOpsResultMsg.ACToken` | `%+v artMsg` on the error path (token empty in practice; defensive) | **FIXED** → `errCode`/`errMsg` |
| [`endpoints/server/udpserver.go`](../endpoints/server/udpserver.go) `handleNhpOpenResource` | `map[string]*ACOpsResultMsg` `.ACToken` | `%+v artMsgs` on all-failed path (defensive) | **FIXED** → sorted `name=errCode` list |
| [`endpoints/server/nhpauth.go`](../endpoints/server/nhpauth.go) `HandleKnockRequest` succeed | none yet | dangling `%+v` with **no argument** (`%!v(MISSING)`); footgun — a future "fix" would dump `ackMsg` (carries `ACTokens` + `AuthProviderToken`) | **FIXED** → verb removed |
| [`endpoints/server/httpserver.go`](../endpoints/server/httpserver.go) legacy plugin GET `/:aspid/:resid/valid` | AC/session token via legacy `?token=` | raw `ctx.Request.URL.RawQuery` logged — the deprecated GET path carries the token in-query (the sibling handler at `/:aspid` already redacted; this one didn't) | **FIXED** → `redactSensitiveQuery` |
| [`endpoints/server/httpserver.go`](../endpoints/server/httpserver.go) internal-knock + [`internal_token_validate.go`](../endpoints/server/internal_token_validate.go) no-query rejection | `nhp_token` if mis-appended to URL | `%q` of `RawQuery` on the "URL must have no query" reject path (internal endpoints take the token in the body) | **FIXED** → `redactSensitiveQuery` (defense-in-depth) |
| [`endpoints/server/httpserver.go`](../endpoints/server/httpserver.go) plugin handler `/:aspid` | AC/session token via legacy `?token=` | `query` log | SAFE — already `redactSensitiveQuery` |
| `Authorization` header (`authAccessFromRaaS`) / `nhp_token` cookie | forwarded bearer / session JWT | only presence/absence logged (`"Authorization header is empty"`, `"nhp_token cookie missing"`) — value never logged | SAFE |
| [`endpoints/ac/httpac.go`](../endpoints/ac/httpac.go) `/refresh` request log | AC access token | `get refresh request` log line | SAFE — already `common.RedactToken` |
| [`nhp/common/tokenstore.go`](../nhp/common/tokenstore.go) (expire/panic) ×2 | AC access token | store maintenance logs | SAFE — already `common.RedactToken` |
| [`endpoints/ac/msghandler.go`](../endpoints/ac/msghandler.go) `udpTempAccessHandler` | — | `%+v pkt.Content` of an `NHP_ACC` packet, `log.Trace` | SAFE — content is still **ciphertext** at this point (decrypt happens after `PacketData` is built two lines below) |
| passcode `ackMsg.ResourceHost` ×5; `qurl`/`oidc` `ackMsg.ResourceHost`/`ErrMsg` | — | specific non-token field only | SAFE |
| passcode `knock succeeded.%+v res.Resources` ×2 | — | dumps the resource-target sub-field; config secrets (`AppSecret`/`SecretKey`/`ExInfo`) are siblings on `ResourceData`, not in `.Resources` | SAFE (see out-of-scope note) |
| [`endpoints/agent/knock.go`](../endpoints/agent/knock.go) | `AgentAccessMsg.ACToken` | assigns `info.ACToken` to the outbound struct; all logs use `accMsg.UserId` only — **token never logged** | SAFE |

## Config-secret log sites

The focused follow-up in
[#3158](https://github.com/layervai/nhp/issues/3158) reviewed the server's
config load, parse, apply, and watch paths for full TOML bodies, whole config
structs, and secret-bearing maps. Adjacent secret-bearing local-file paths log
only filenames, fixed counts/outcomes, or non-decoder errors; they do not dump
the loaded TOML or parsed configuration. The remote-config leak and adjacent
decoder boundaries were:

| Site | Secret reachable | How touched | Status |
|---|---|---|---|
| [`endpoints/server/config.go`](../endpoints/server/config.go) `updateEtcdConfig` plus its startup/watch callers | `ResourceData.AppSecret`, `AccessKey`, `SecretKey`, and `ExInfo` values such as `JWTSecret` | `%q` of the complete etcd TOML at Info before parsing; malformed updates also propagated decoder errors into caller logs | **FIXED** → byte length plus fixed parse/update outcome metadata; parse failures cross the caller boundary as generic `errLoadConfig`; credential-free operational apply errors retain their diagnostic detail; the terminal marker is deliberately neutral because apply failures remain non-fatal; `TestEtcdAndLocalConfigLogsRedactSecrets` fences successful and malformed secret-bearing TOML |
| [`endpoints/server/config.go`](../endpoints/server/config.go) `loadResources` initial load/reload parse failures | the same `ResourceData` credentials in local `resource.toml` | `%v` of the TOML decoder error; the pinned decoder currently emits structural diagnostics, but relying on dependency error formatting is brittle | **FIXED** → filename plus fixed failure metadata only; the malformed local-config canary in `TestEtcdAndLocalConfigLogsRedactSecrets` fences the initial-load boundary |
| [`endpoints/server/config.go`](../endpoints/server/config.go) `initRemoteConn` | etcd `Password` in local `remote.toml` | `%v` of the TOML decoder error locally, then the same error returned to a startup `%v` warning | **FIXED** → filename-only local metadata and generic `errLoadConfig` across the caller boundary; canary-tested |
| [`endpoints/server/config.go`](../endpoints/server/config.go) `loadBaseConfig` | server `PrivateKeyBase64` and `CookieSigningKeyBase64` in local `config.toml` | TOML decoder error returned through the startup error boundary | **FIXED** → filename plus generic `errLoadConfig`; canary-tested |
| [`endpoints/server/config.go`](../endpoints/server/config.go) `loadStorageConfig` | etcd `Password` in local `storage.toml` | TOML decoder error returned through the startup error boundary | **FIXED** → filename plus generic `errLoadConfig`; canary-tested |

Decoder details are deliberately not retained even at Debug level for these
secret-bearing files. Production and support environments may run at Debug, so
log level is not a redaction boundary. Operators retain the failing filename
and outcome plus an explicit `validate TOML in a controlled environment; syntax
detail withheld to avoid logging secrets` hint. Detailed syntax diagnosis for a
local file should happen where its credential contents are already authorized
for inspection; a malformed remote etcd payload should likewise be retrieved
and validated only through authorized tooling rather than copied into logs.

The fixed hint is emitted at the existing operator-visible error boundary:
`updateEtcdConfig`, `loadResources`, and `initRemoteConn` log it in place, while
`loadBaseConfig` and `loadStorageConfig` return it with the generic sentinel for
their callers to log. This preserves one diagnostic per failure without
returning decoder detail. Etcd payload byte length is deliberately retained as
non-secret delivery metadata for diagnosing empty or truncated updates; no
payload content or content-derived identifier is recorded.

The canary test directly executes each initial-load parser. The base/resource
file-watch reload branches use the same filename-only shapes and are verified
by inspection rather than a timing-dependent filesystem watcher test; their
scope is recorded explicitly here so that distinction is not mistaken for
direct runtime coverage. Deterministic callback-injection coverage without
filesystem timing is tracked in
[#3238](https://github.com/layervai/nhp/issues/3238).

Decoder diagnostics remain on credential-free files such as `srcip.toml`
(network-address mappings), peer files (public keys and addresses), and TEE
attestation allowlists. Those paths cannot expose a credential value through a
source excerpt and remain outside this credential-boundary fix.
Equivalent secret-bearing decoder boundaries in the agent, AC, and DB
components are tracked explicitly in
[#3237](https://github.com/layervai/nhp/issues/3237) under the broader
[#2517](https://github.com/layervai/nhp/issues/2517) hygiene effort.

## Persistence sites

| Site | Token | How persisted | Notes |
|---|---|---|---|
| [`endpoints/ac/tokenstore.go`](../endpoints/ac/tokenstore.go) | AC access token | in-memory `common.TokenStore` keyed by token | Process memory only; never serialized. `AccessEntry.FirstKnockTime` has a `json:"-"` structural fence. |
| [`endpoints/server/ack_token_store.go`](../endpoints/server/ack_token_store.go) | ACK token (lookup key) | DynamoDB `AckTokensTable` (when configured) | **Raw token never persisted** — the partition key is `sha256(token)` via `hashACKToken`, so a DB compromise yields no usable token. Keep hashing on any schema change. |
| passcode `ctx.SetCookie("nhp_token", …)` | NHP session JWT | `Secure`+`HttpOnly` cookie to the browser | Transport to client; not logged. |

## Transport sites (token-in-flight, no redaction needed in-process)

`ACOpsResultMsg` (AC→server), `ServerKnockAckMsg` (server→agent),
`AgentAccessMsg` (agent→AC), `PreAccessInfo` (embedded). These are
JSON-marshalled onto the encrypted NHP wire; the tokens are protected by the
transport cipher. The risk is only when one of these structs is **logged** —
covered by the log-site table above.

## Replay-window decision

> **Decision: cap-extension. Already implemented, independently of this audit,
> in [#1942](https://github.com/layervai/nhp/issues/1942).**

`(*UdpAC).VerifyAccessToken` ([`endpoints/ac/tokenstore.go`](../endpoints/ac/tokenstore.go))
slides `ExpireTime` forward by `OpenTime` on each `/refresh`, but clamps it at
`AccessEntry.absoluteTokenDeadline()` = `FirstKnockTime + OpenTime + buffer`.
`FirstKnockTime` is set once at `GenerateAccessToken` and never mutated, so the
total token lifetime is bounded regardless of how many `/refresh` hits occur.
This is exactly the "cap-extension" option #1426 asked us to choose between
(cap / remove / accept). The unbounded indefinite-extension behavior the
Round-14 review flagged on #1416 no longer exists. No change is required by
this PR; the decision is recorded here per acceptance criterion 3.

## Out of scope for this audit (observed, flagged for separate review)

These surfaced during the sweep but are **not** access tokens and are not
changed here, to keep the audit scoped to #1426:

- **Config secrets on `ResourceData`** (`AppSecret`, `SecretKey`, `ExInfo`
  incl. `JWTSecret`). The active complete-etcd-body leak is fixed and inventoried
  above by [#3158](https://github.com/layervai/nhp/issues/3158). No site dumps a
  whole parsed `ResourceData`; the existing `knock succeeded.%+v res.Resources`
  dumps (passcode `knockAndIssueTokens` / `exchangeAndKnock`) remain SAFE only
  because secrets are `ResourceData` siblings, not inside `.Resources`. The
  remaining plugin-config and brittle struct-log cleanup stays tracked in
  [#2517](https://github.com/layervai/nhp/issues/2517).
- **OIDC plugin** — `log.Info("User profile: %+v", profile)` logs ID-token
  *claims* (PII), not the bearer token (`oauth_token` is stored to session
  separately and never logged); `GetConfig()` dump is plugin config. Upstream
  IdP material, distinct from the post-#1124 token threat model.
- **Upstream API error bodies** (passcode auth API, custom-auth API, IAM
  portal-sites, QURL resolve API) — logged only on **non-200**; issued tokens
  appear only in 200 bodies. The IAM **200** body was the one exception and is
  now FIXED above.

## Remaining cross-repo work — tracked in [#1426](https://github.com/layervai/nhp/issues/1426)

This PR completes the **in-repo (Go)** scope. The following live in other
repos and require their own PRs + CODEOWNERS sign-off (acceptance criteria 2
non-Go and 4). They remain tracked in the #1426 meta-issue:

- **qurl-service** — `internal/nhp/types.go` `acTokens` map and any log site
  that touches the NHP response body.
- **traefik-plugins** — any custom middleware that logs the request including
  the NHP cookie or token.
- **Agent SDKs** (`qurl-typescript`, `qurl-mcp`, `qurl-python`,
  `qurl-integrations`) — network layers that may log full request URLs/bodies;
  pin to the same 8-char prefix convention.

## Keeping this current

When you add a log/persist/transport site that touches any token in the "What
counts" table, add a row here. The redaction contracts are pinned by tests —
`common.RedactToken` (8-char prefix) by `TestRedactToken` in
[`nhp/test/tokenstore_test.go`](../nhp/test/tokenstore_test.go), and
`redactSensitiveQuery` (incl. the malformed-query path) by
`TestRedactSensitiveQuery` in
[`endpoints/server/redact_query_test.go`](../endpoints/server/redact_query_test.go).
Do not re-implement ad-hoc truncation.
