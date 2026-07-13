# OpenNHP Upstream Synchronization

This document tracks the synchronization status between this fork (LayerV NHP) and the upstream [OpenNHP](https://github.com/OpenNHP/opennhp) repository.

## Baseline

| Field | Value |
|-------|-------|
| **Last reviewed upstream SHA** | 0589c360 |
| **Last review date** | 2026-07-01 |
| **Reviewer** | Claude Code |

> **HOW TO USE:** When checking for updates, run:
> ```bash
> git log 0589c360..upstream/main --oneline
> ```
> This shows ONLY new commits since last review. Update the SHA after each review.

> **NHP plugins SDK bumps:** Before updating
> `github.com/fengyily/nhp-plugins-sdk`, re-run the redirect helper parity
> tests in `endpoints/server/staticplugins/internal/redirecturl`. That helper
> intentionally mirrors `GetRedirectUrlByResource` while removing token-bearing
> logs, so SDK behavior drift must be reviewed before changing the pinned
> parity version.

---

## Relay + JS-Agent: now ADOPTED (was skipped) — #2208

**Policy reversal (2026-06).** Earlier syncs marked the upstream **relay**
(`endpoints/relay/`, server `HandleRelayForward`, `common.RelayForwardMsg`) and
**JS agent** (`endpoints/js-agent/`) as SKIP ("fork doesn't use relay"). That is
no longer true: issue #2208 adopts them (browser → HTTPS relay → the cell's
internal NHP NLB; native UDP SDKs connect directly to the assigned cell's public
NHP NLB).
The historical per-commit log below still records the original SKIP decisions —
those are not rewritten — but do **not** skip these going forward. The following
previously-skipped commits must be **ported** (tracked under #2208):

| Commit | What | Action |
|--------|------|--------|
| `bf927049` | feat(relay): add nhp-relay component | Port (the relay; HTTPS POST). |
| `e2c5336a` | fix(security): relay DoS + source IP validation | **Port — security; lands with the relay/handler.** |
| `ad98e1f4` | fix(server-http): tighten XFF defence | **Port — security; adapt to our X-Real-IP front door.** |
| `d0836539` | feat(relay): multi-cluster via pubkey-derived id | **Port as the cell router** (reverses the earlier "strip the multi-cluster load-balancer" call) — `/relay/{serverId}` routes per cell. Rationale + the per-cell-LB-retained detail: `docs/design/NHP_RELAY_TOPOLOGY.md` → Cloud deployment. |
| `6709d00c`, `cc36a684` | feat(js-agent): browser SDK + CBOR | Port the JS agent (`relay.ts` HTTPS transport). |

GMSM/SM2/SM3/SM4 paths inside these commits remain auto-skipped per the catalog
above.

## Auto-Skip Categories

These are PERMANENTLY skipped. Don't waste time reviewing them:

| Category | Pattern | Reason |
|----------|---------|--------|
| GMSM/Chinese crypto | `gmsm`, `SM2`, `SM3`, `SM4` | Intentionally removed from fork |
| KGC component | `endpoints/kgc/*` | Not needed |
| CI workflows | `.github/workflows/*` | Fork has custom CI |
| Dependabot PRs | `chore(deps): bump` | Managed separately |
| Release Please | `release-please` | Fork has own process |
| CODEOWNERS | `.github/CODEOWNERS` | Fork has different team |
| codecov config | `codecov.yml` | Fork uses different coverage |

> **When reviewing new commits:** Immediately skip any matching these patterns.

---

## Fork Divergence Catalog

Values where the fork intentionally diverges from upstream. **If an upstream commit reverts any of these, do not sync the revert** — re-apply the divergence locally and document why.

| File / value | Upstream | LayerV fork | Why |
|---|---|---|---|
| `endpoints/server/constants.go::DefaultHttpRequestReadTimeoutMs` | `4500` | `30000` | LayerV runs the server behind a CloudFront-fronted topology; CF's `origin_keepalive_timeout = 30s`. The original 4500/5500/6000 default produced an intermittent 502 race (PR #1795). |
| `endpoints/server/constants.go::DefaultHttpResponseWriteTimeoutMs` | `5500` | `30000` | Same — paired with the read timeout, sized below CF's `origin_read_timeout` (60s). |
| `endpoints/server/constants.go::DefaultHttpServerIdleTimeoutMs` | `6000` | `36000` | Same — IdleTimeout MUST exceed CF's `origin_keepalive_timeout` + a 5s buffer. **Note:** 36000 is intentionally not exactly 30000 + 5000. The contract floor is 35000 (CF keep-alive 30s + 5s buffer); 36000 sits 1s above the floor so the precondition's `>=` check has real slack instead of passing by exact equality. Lower values re-open the keep-alive race fixed in PR #1795. |
| `endpoints/server/config.go::applyHttpTimeoutDefaults` floor logic | `if X == 0 { X = default }` | `if X < 1000 { X = default }` | Diverges from upstream's "default-if-zero" semantics: any positive-but-below-1000ms value gets defaulted up + warned. Catches operator overrides via http.toml or etcd seeding that bypass TF validation. If you sync from upstream and the floor semantics revert to "default only when the value is zero" (whether spelled `== 0`, `<= 0`, or any refactor that re-introduces "zero is the only sub-floor sentinel"), an etcd-seeded `IdleTimeoutMs = 500` would silently re-open the keep-alive race. The `< 1000` guard is the durable contract — review every sync against this row. PR #1795. |
| `nhp/core/transaction.go::Device.LocalTransactionCount()` | absent | fork-only addition | Powers `endpoints/server/udpserver.go::awaitTransactionDrain` (graceful-shutdown wait introduced for the canary-drain `knock_failed` race). Acquires `localTransactionMutex` and returns `len(localTransactionMap)`. If upstream later adds a same-named method with a different signature, prefer the fork's signature — `awaitTransactionDrain` is its only caller. `nhp/core/testing.go::SeedLocalTransactionForTest` + `RemoveLocalTransactionForTest` are similarly fork-only test helpers that share the same mutex contract. |
| Header integrity field + helpers: `curve.HeaderCurve.HMAC`/`HMACBytes()`, `addHMAC`/`checkHMAC`, `hmacHash`, `ErrHMACCheckFailed`/`ErrServerHMACCheckFailed` | named `HMAC`/`*HMAC*` | renamed `HeaderDigest`/`HeaderDigestBytes()`, `addHeaderDigest`/`checkHeaderDigest`, `digestHash`, `ErrHeaderDigestCheckFailed`/`ErrServerHeaderDigestCheckFailed` | #1126: the value is an UNKEYED hash over public header inputs, not a MAC, so the upstream "HMAC" name misleads readers into treating a passing check as authentication. Pure rename — wire format and noise crypto are unchanged (`Bytes()` is offset-based; field order/size untouched). When syncing, an upstream commit that touches these identifiers will conflict on the rename — **re-apply the fork name, don't revert to `HMAC`.** Two things are deliberately NOT renamed: the error CODES (`errNhpHmacCheckFailed`=32005 / `errNhpServerHmacCheckFailed`=32006) and the operator-facing message strings ("HMAC validation failed" / "server HMAC validation failed"), which are quoted as a log breadcrumb in `terraform/main.tf`. Unrelated to the real KDF HMAC (`kdf.go::HMAC1`/`HMAC2`), which keeps its name. |
| `nhp/core/responder.go::ResponderScheme` + `nhp/core/initiator.go::InitiatorScheme` (vestigial interfaces) | present, unused (introduced by the module-split `95172262`, authored upstream) | removed | Both interfaces are dead in the fork **and** upstream: a whole-repo `git grep` finds only the two declaration lines — no implementers, no `var _ Scheme = ...` assertions, no references. `ResponderScheme` declares unexported methods (`validatePeer`/`decryptBody`), so it can only be satisfied inside `package core` — and isn't. Their method sets never matched the real methods anyway: the real `(ppd *PacketParserData) validatePeer()`/`decryptBody()` are arg-less; the real `createMsgAssemblerData`/`encryptBody`/`setPeerPublicKey` are unexported; and `DeriveMsgAssemblerDataFromPrevParserData`/`DerivePacketParserDataFromPrevAssemblerData` have no implementation at all. Removed in PR #2659. **On sync: an upstream commit that touches either interface must NOT re-introduce the type — keep them removed** (don't resolve a `responder.go`/`initiator.go` cherry-pick conflict toward the upstream interface block). |

---

## Decision Matrix

| If commit is... | Action | Time to decide |
|-----------------|--------|----------------|
| Security fix / panic prevention | **SYNC IMMEDIATELY** | < 1 min |
| Bug fix in code we use | **SYNC THIS WEEK** | < 1 min |
| Lint/code quality | **EVALUATE** - run linter fresh | 5 min |
| Refactoring | **SKIP** unless it fixes a problem we have | 2 min |
| New feature | **EVALUATE** - do we need it? | 5 min |
| Documentation | **SKIP** - fork has own docs | < 1 min |

---

## Sync History

### 2026-07-01 - Routine Review (No Direct Sync — 4 Follow-Up Ports Tracked)

- **Reviewed up to:** 0589c360
- **Commits reviewed:** 113 (non-merge)
- **PRs created:** None
- **Commits synced:** None — but the #1552 / #1563 cross-check below found pre-existing shared-code bugs that apply to the fork; tracked for separate ports in #3084–#3087.
- **Summary:**
  - 30 Dependabot/dependency updates (auto-skipped) — includes 2 GMSM bumps, 2 docs-site CVE bumps (vite, basic-ftp/ws), 2 upstream-plugin go-toml alignments (`66bc7815`, `a3c3e8f6`), and a wazero+etcd build-dep bump (`7e0ecc8d`)
  - 1 Version bump to 0.8.0 (`1d638cbd`, skipped — upstream versioning)
  - 12 Demo infrastructure changes (upstream multi-cluster demo, skipped)
  - 3 CI/GitHub Actions workflow changes (auto-skipped — Claude PR review tweaks from justin-layerv)
  - 3 Documentation/sponsor changes (auto-skipped)
  - 1 js-agent multi-cluster demo host-picker (`322fa9d1`, skipped — upstream multi-cluster demo wiring)
  - 2 HeaderType authentication commits (`cfa08718`, `d10afec2`) — already tracked as SKIP (fork is the SOURCE; see 2026-06-15 entries below)
  - 1 Test maintenance PR #1563 (`449e2c0d`) — SKIP as a whole (fork's `log_test.go` is already superior), but its `api_test.go` dead-code cleanup **does apply** — **resolved in #3087** (PR #3090; see the `449e2c0d` row for detail)
  - 60 commits in PR #1552 (feat/phase2-multi-instance-peers) — multi-instance server clusters. The **feature** is skipped (fork has its own AWS ASG/NLB/etcd approach). Its fix/perf commits were cross-checked commit-by-commit: most are **already carried in the fork** or feature-coupled N/A, but a residual set of **pre-existing shared-code bugs applies** and is tracked for separate ports — **#3084** (agent panics — **PORTED**, see the `f8e471c0` row), **#3085** (AC data race + eBPF — RESOLVED: adapted from `3e56ffc7`), **#3086** (server hardening). See the `f8e471c0` row under Individual Commit Decisions for the per-commit split.
- **Notes:** PR #1552 is the most significant upstream development this period (multi-cluster support, stateless overload cookies, per-connection stickiness). Two durable notes for future reviewers:
  1. **Don't conflate the two "multi-cluster" concepts.** #1552 is **server-side** clustering — skipped, since the fork uses AWS ASG/NLB/etcd. The relay's **per-cell** routing is a separate thing, adopted under #2208 (see "Relay + JS-Agent: now ADOPTED" above).
  2. **"Skip the feature" ≠ "skip the branch."** The per-commit cross-check surfaced shared-code fixes that DO apply even though the feature is skipped (panic prevention → SYNC, per the Decision Matrix) — see the bullet above and the `f8e471c0` row. If the relay adoption (#2208) later needs multi-cluster routing, revisit PR #1552's cluster abstraction then.

### 2026-06-01 - Routine Review (No Sync Required)

- **Reviewed up to:** e903f92c
- **Commits reviewed:** ~76 (non-merge)
- **PRs created:** None
- **Commits synced:** None
- **Summary:**
  - ~23 Dependabot/dependency updates (auto-skipped, includes 2 GMSM bumps)
  - ~7 Release Please / version bumps (auto-skipped)
  - ~7 CI/GitHub Actions workflow changes (auto-skipped)
  - ~13 Demo infrastructure/TLS proxy changes (upstream-specific, skipped)
  - ~16 JS-Agent browser SDK feature + fixes (upstream-only component, skipped)
  - ~5 Relay multi-cluster feature (fork doesn't use relay, skipped)
  - 1 auth-plugin demo polish (`599eb8cc`) — upstream-specific plugin (skipped)
  - 1 plugin dep alignment (`5390ffa1`) — upstream plugin layout (authenticator/basic/oidc), fork has different layout (skipped)
  - 1 cgo removal from errors.go (`6558da64`) — **already fixed** in fork (fork's errors.go never had cgo import)
  - 2 noise chain key fix + tests (`d0cb1683`, `b75b5614`) — **already synced** from `enable_webrtc` branch (2026-05-19 entry); now also landed on `upstream/main` via PR #1557
- **Notes:** The chain key fix we cherry-picked from `upstream/enable_webrtc` on 2026-05-19 has now been merged to `upstream/main`. As anticipated in the 2026-05-19 entry (which called it a clean "revert"), this registers as a clean duplicate of our existing commit — the same no-op outcome — no action needed. Our upstream contribution PR [OpenNHP#1557](https://github.com/OpenNHP/opennhp/pull/1557) was merged 2026-05-23 (`e7886f8e`).

### 2026-05-19 - Noise Intermediate Chain Key Fix (Feature-Branch Cherry-Pick)

- **Reviewed up to:** unchanged baseline (still `f53b7e2d`)
- **Commits synced:** 1 (cherry-picked from `upstream/enable_webrtc`, NOT on `upstream/main`)
- **Summary:**
  - `03619015e` ("fix a bug in reusing empty intermediate chain key. All packages starts with initial key now.") — **synced** (adapted to fork's signature style). This commit lives only on the upstream `enable_webrtc` feature branch and has not been merged to `upstream/main`, which is why the May 2026 review (which walks `upstream/main`) did not surface it. Brought to our attention by upstream maintainer.
  - Bug: `derivePacketParserData` and `deriveMsgAssemblerData` copied the previous transaction's chain key into the new MAD/PPD, but `encryptBody`/`decryptBody`'s deferred `SetZero(chainKey)` had already zeroed the source — so the "intermediate" key the response was supposed to chain from was actually all zeros. Go-to-Go absorbed the bug silently (both ends symmetrically derived from zeros and agreed); Go-to-JS interop broke because the JS implementation didn't replicate the zero-carry-over quirk.
  - Fix: always initialize chain hash + chain key to ChainHash0/ChainKey0 per packet (move init out of the no-prev `else` branch in `createMsgAssemblerData`/`createPacketParserData`; remove the chainHash init + chainKey copy from the derive functions, dropping their now-unused err return).
- **Wire-compat note (deliberately coordinated rollout):** this fix changes the on-the-wire AEAD key for response-direction packets (anything that flows through `PrevParserData` / `PrevAssemblerData` — knock ACKs, AOP/ART forwarding, AC online/registration responses, FRT). Old code derives the response body-AEAD key from a zeroed `chainKey`; new code derives it from canonical `ChainKey0`. Old↔new peers therefore fail body-AEAD on response packets with `ErrAEADDecryptionFailed`, while request-direction packets (fresh transactions) are unaffected. No protocol version gate exists, so the failure is silent body-decrypt failures on transaction-continuation packets only. Mitigations: (a) sandbox blue/green and prod canary both deploy server + AC sequentially within a single release window; (b) NHP transactions are fail-open with agent-side retries, so transient mismatch during the deploy window self-heals; (c) field agents auto-update via the agent SDK release cadence and have always tolerated transient knock failure. If a customer-deployed agent fleet ever gets out of sync with the server fleet for a long window, the symptom is failed knocks until the agent upgrades.
- **Follow-up to consider:** keep an eye on `upstream/main` — when this fix eventually lands there it will register as a clean revert of our own commit. The next sync reviewer should recognize it (don't unwind our local commit on the assumption that upstream "removed it").
- **Open follow-ups** tracking the residual risk and operational coverage:
  - `#2017` — SRE runbook for `ErrAEADDecryptionFailed` during cutover (operator-facing telemetry for the long-tail customer-agent skew case).
  - `#2018` — JS-reference compat smoke (Go-side decode of a recorded JS-emitted ACK). This is the **mechanical gate** that should fence the wire-format contract long-term; `#2018` must land before this PR's behavior can be relied on by a JS client release.

### 2026-05-01 - Crypto Key Material Log Leak

- **Reviewed up to:** f53b7e2d
- **Commits reviewed:** ~129 (non-merge)
- **PRs created:** 1 (security)
- **Commits synced:** 1 (adapted from `dd8a86dd`)
- **Summary:**
  - ~30 Dependabot/dependency updates (auto-skipped)
  - ~15 CI/GitHub Actions workflow changes (auto-skipped)
  - ~35 Documentation/README/branding changes (auto-skipped)
  - ~3 GMSM dependency bumps (auto-skipped)
  - ~25 Demo infrastructure/deploy changes (upstream-specific, skipped)
  - ~15 NHP-Relay new feature (upstream relay component, skipped — fork doesn't use relay)
  - ~5 Terraform demo stack (upstream-specific, skipped)
  - 1 security fix in `nhp/core/responder.go` (`dd8a86dd`) — **synced** (adapted): removed debug log lines that dumped Noise chain key and AES-GCM symmetric key material to disk on every packet when debug logging enabled
  - 1 security info-leak fix in `nhp/core/responder.go` (`6547b3d5`) — **already fixed** in fork (our validatePeer doesn't log registered peer keys)
  - 1 server db.toml optional fix (`50726ad8`) — **already fixed** in fork
  - 1 webrtc removal (`757c6476`) — **skipped** (fork still has webrtc; separate decision)
  - 1 server relay DoS protection (`e2c5336a`) — **skipped** (relay-specific; fork doesn't use HandleRelayForward)

### 2026-03-25 - Iptables Security Fixes

- **Reviewed up to:** 7e71ebe8
- **Commits reviewed:** ~70 (non-merge)
- **PRs created:** 1 (iptables security)
- **Commits synced:** 3 (adapted, not cherry-picked due to fork Dockerfile differences)
- **Summary:**
  - ~25 Dependabot/dependency updates (auto-skipped)
  - ~6 CI/GitHub Actions workflow changes (auto-skipped)
  - ~4 GMSM dependency bumps (auto-skipped)
  - ~3 Documentation changes (auto-skipped)
  - ~20 OIDC plugin additions/fixes (upstream authenticator plugin, we use QURL - skipped)
  - ~10 Plugin build/deploy workflow changes (upstream-specific - skipped)
  - 3 iptables security fixes (`0110dbb`, `19348e7`, `dc3e709`) - **synced** (adapted)
  - 1 command injection fix (`6c160c7`) in `quick_start.sh` - **skipped** (file doesn't exist in fork)
  - 1 DefaultCipherScheme config fix (`78e5b37`) - **skipped** (upstream changed 0→1 for GMSM scheme; our fork correctly uses 0 for curve25519-only)

### 2026-01-23 - Routine Review (No Sync Required)

- **Reviewed up to:** 3344ab68
- **Commits reviewed:** ~75
- **PRs created:** None
- **Commits synced:** None
- **Summary:**
  - ~50 Dependabot/dependency updates (auto-skipped)
  - ~20 CI/CD workflow changes (auto-skipped, fork has custom CI)
  - 5 demo template changes (upstream examples only)
  - 3 plugin refactors (we use QURL, not upstream's authenticator)
  - 2 config.go bug fixes (`b9e5885a`, `21703687`) - **already fixed independently in our fork**
- **Notes:** The config.go bug (unmarshal to wrong variable in file watcher callback) was identified in upstream but our fork already fixed this in recent commits with the `freshAspMap` pattern.

### 2026-01-09 - Shared Constants & PKCS7 Tests

- **PRs created:** #106, #107
- **Commits synced:**
  - `9d1b7711` - extract shared constants to common package
  - `95d5e228` - PKCS7 padding consolidation (adapted, not cherry-picked due to GMSM refs)
- **Commits skipped:**
  - `ecdsa_test.go` - GMSM-specific (SM2), not applicable to fork

### 2026-01-09 - Security, IPv6, Crypto Error Handling

- **Reviewed up to:** bd6b7538
- **PRs created:** #80, #81, #82, #86
- **Commits synced:**
  - `65082485` - bounds checking for panics
  - `1b69b375` - panic prevention in crypto/peer
  - `8892bf8b` - Secure flag on session cookies
  - `27e3d6bc` - IPv6 critical bugs
  - `9ed0cf6c` - IPv6 iptables support
  - `45470091` - crypto error handling
- **Time spent:** ~8 hours (first full audit)

### 2026-01-05 - Initial Fork Sync

- **PRs created:** #15, #19
- **Commits synced:** 30
- **Notes:** Bulk sync after fork creation

---

## Pending Review

Items identified during 2026-01-09 audit that need future attention:

| SHA | Title | Priority | Notes |
|-----|-------|----------|-------|
| c05a0ded | Enable gosec linter | DONE | PR #103 |
| 42f39409 | Loop variable capture fix | DONE | PR #103 |
| 9d1b7711 | Shared constants | DONE | PR #106 |
| 95d5e228 | PKCS7 consolidation | DONE | PR #107 (adapted) |

---

## Individual Commit Decisions

Non-obvious skips that don't fit Auto-Skip Categories:

| SHA | Title | Decision | Reason | Date |
|-----|-------|----------|--------|------|
| 634e3d8c | feat(cli): add --json output | SKIP | Fork doesn't use CLI this way | 2026-01-09 |
| 1bbece70 | refactor(httpauth): dedup handlers | PENDING | Low priority, may do later | 2026-01-09 |
| 9ef61076 | refactor(logging): standardize format | SKIP | Fork has own logging patterns | 2026-01-09 |
| b9e5885a | fix: config.go codecov/aspMap bug | SKIP | Already fixed independently in fork | 2026-01-23 |
| 21703687 | feat: QR/OTP login + config.go fix | SKIP | Feature not needed; bug already fixed in fork | 2026-01-23 |
| 9b115972 | fix: OTP static key in templates | SKIP | Upstream authenticator plugin (we use QURL) | 2026-01-23 |
| 320a90c4 | refactor: move server_plugin to basic/ | SKIP | Upstream example reorganization only | 2026-01-23 |
| f32bd371 | refactor: rename qrauth to authenticator | SKIP | Upstream plugin rename (we use QURL) | 2026-01-23 |
| 6c160c7 | fix: prevent command injection in quick_start.sh | SKIP | File doesn't exist in fork | 2026-03-25 |
| 78e5b37 | fix: align DefaultCipherScheme with docker config | SKIP | Upstream 0→1 for GMSM; fork uses 0 for curve25519-only | 2026-03-25 |
| 01362f4 | fix: clear ackMsg.RedirectUrl when no redirect | SKIP | Upstream OIDC plugin (we use QURL) | 2026-03-25 |
| f8f4e43 | fix: return error state on OIDC redirect failure | SKIP | Upstream OIDC plugin (we use QURL) | 2026-03-25 |
| 55db41f | fix: harden OIDC redirect with HTML error fallback | SKIP | Upstream OIDC plugin (we use QURL) | 2026-03-25 |
| 63552e0 | fix: validate RedirectUrl in OIDC plugin | SKIP | Upstream OIDC plugin (we use QURL) | 2026-03-25 |
| 978901f | refactor: standardize plugin module names | SKIP | Upstream plugin reorganization | 2026-03-25 |
| 31206cc | feat(oidc): auto-redirect after auth | SKIP | Upstream OIDC plugin (we use QURL) | 2026-03-25 |
| dd8a86dd | fix: remove debug key material logging | SYNCED | Adapted — removed debug log lines dumping crypto keys | 2026-05-01 |
| 6547b3d5 | fix: stop logging registered peer pubkeys | SKIP | Already fixed in fork (our validatePeer doesn't log peer list) | 2026-05-01 |
| 50726ad8 | fix(server): make db.toml optional | SKIP | Already fixed independently in fork | 2026-05-01 |
| 757c6476 | chore(server): remove webrtc transport | SKIP | Fork still uses webrtc; separate design decision | 2026-05-01 |
| e2c5336a | fix(security): relay DoS + source IP validation | SKIP | Relay-specific; fork doesn't use HandleRelayForward | 2026-05-01 |
| ad98e1f4 | fix(server-http): tighten XFF defence | SKIP | Relay-specific nginx/XFF changes; fork has own proxy setup | 2026-05-01 |
| bf927049 | feat(relay): add nhp-relay component | SKIP | New upstream feature; fork doesn't need relay | 2026-05-01 |
| 2c4e5859 | fix(plugin): align plugin deps with endpoints | SKIP | Upstream example plugin (basic/); fork has own plugin layout | 2026-05-01 |
| 8813ca76 | fix(infra): drop nhp-acd from root | SKIP | Upstream demo infra; fork has own Terraform | 2026-05-01 |
| 6558da64 | fix(core): remove cgo dependency from errors | SKIP | Already fixed in fork (fork's errors.go never had cgo import) | 2026-06-01 |
| 5390ffa1 | fix(plugins): align shared deps with endpoints | SKIP | Upstream plugin layout (authenticator/basic/oidc); fork has different layout | 2026-06-01 |
| d0cb1683 | fix: reusing empty intermediate chain key | SKIP | Already synced from `enable_webrtc` branch (2026-05-19) | 2026-06-01 |
| b75b5614 | test(nhp/core): chain-key regression tests | SKIP | Already synced from `enable_webrtc` branch (2026-05-19) | 2026-06-01 |
| 599eb8cc | feat(server-plugin): polish basic auth-plugin demo | SKIP | Upstream authenticator plugin demo (we use QURL) | 2026-06-01 |
| d0836539 | feat(relay): multi-cluster via pubkey-derived id | SKIP | Fork doesn't use relay | 2026-06-01 |
| 6709d00c | feat(js-agent): vendor browser SDK | SKIP | Upstream-only JS agent component | 2026-06-01 |
| 738a996f | feat(demo): add demo.nhp TLS proxy to AC nginx | SKIP | Upstream demo infrastructure | 2026-06-01 |
| 3e4a8172 | fix(terraform): mark demo_nhp_cert as sensitive | SKIP | Upstream demo Terraform | 2026-06-01 |
| 9501ba23 | fix(terraform): mark derived-from-sensitive outputs | SKIP | Upstream demo Terraform | 2026-06-01 |
| cc36a684 | feat(js-agent): CBOR token support | SKIP | Upstream-only JS agent component | 2026-06-01 |
| cfa08718 | fix(server,agent): authenticate knock HeaderType (reject on-path flips) | SKIP — fork is the SOURCE | Our own #1154/#1257 work, re-contributed upstream as [OpenNHP#1584](https://github.com/OpenNHP/opennhp/pull/1584) (author justin-layerv). Merged 2026-06-15, **after** the e903f92c baseline, so it WILL surface in the next `git log e903f92c..upstream/main` walk — and the Decision Matrix would mis-classify it "security → SYNC IMMEDIATELY." The fork already carries a strict SUPERSET: the gated permit→strict `endpoints/server/knock_headertype_gate.go` + errors 52009/52010/**52011** (landed in #1249). **Do NOT replace the gate with upstream's unconditional reject** — it would lock out fork-only non-agent knock clients (qurl-tunnel-client/fileviewer/e2e) that still emit a legacy zero headerType (#1257). | 2026-06-15 |
| d10afec2 | fix(js-agent): authenticate knock HeaderType (mirror wire type in body) | SKIP — fork is the SOURCE | js-agent half of OpenNHP#1584. The fork's js-agent already sets the body `headerType`, in different files (`endpoints/js-agent/src/agent/knock.ts`, not upstream's `NHPAgent.ts`). Upstream's cookie-resend RKN mutation fix is N/A here — the fork's RKN re-knock path isn't built yet (#2208 PR-5c, gated on #2611, where the body-`headerType`=`NHP_RKN` requirement is recorded). | 2026-06-15 |
| f8e471c0 | feat: phase2 multi-instance peers (PR #1552, 60 commits) | SKIP (feature) — partial ports tracked | Multi-instance **server-side** clusters (load balancing, stateless overload cookies, cluster abstraction). The feature is skipped: fork has its own multi-instance approach (AWS ASG/NLB/etcd), distinct from the relay per-cell routing under #2208. The 60-commit branch was cross-checked commit-by-commit — most fix/perf commits are **already in the fork** (stateless cookies, conn-counter accounting, config-reload fail-close, and the `e9be6c7a` attestation-bypass/nil-deref fixes — e.g. the fork's DAV handler in `endpoints/server/msghandler.go` already skips attestation on a config-read error) or feature-coupled N/A. Pre-existing shared-code bugs that DO apply are tracked for manual adaptation: agent-lifecycle panics (`af931432`, `bf3e5efe`, `8e983f1d`, `568cb53f` non-blocking-signal slice, `c6f9c769` SDK-crash slice) → **#3084 — PORTED** (adapted to fork signatures in `endpoints/agent/`: select-on-`signals.stop` sends + a shared `knockTargetStopOnce` re-armed in `Start()`; the fork additionally stops closing `sendMsgCh` — the same treatment `8e983f1d` gave `knockTargetMapUpdated` — because select-on-stop alone leaves a residual send-on-closed window; the cluster-cookie half of `568cb53f`, the AC endpoint-key half of `c6f9c769`, and `16b71809` are N/A per the issue); AC `config.Servers` data race + empty-SrcIP eBPF rule (`3e56ffc7`) → **#3085** (RESOLVED — adapted, not cherry-picked: writer assigns under `serverPeerMutex` + boot-loop reader snapshots under the same lock, and `ebpfInfraExemptRules` skips DNS-only peers); optional server-dispatch handler bound (`bc499d7c` H2) → **#3086**. `16b71809` (AC etcd-load fail-close) is N/A — fork's AC loads peers from a file, not etcd. | 2026-07-01 |
| 449e2c0d | chore: improve opennhp maintenance path (PR #1563) | SKIP (whole PR) — `api_test.go` cleanup resolved (#3087) | Fork's `log_test.go` already has superior tests (`TestLog_CloseTwice`, JSON format tests, etc.), so the PR as a whole is SKIP. But its `api_test.go` cleanup **does apply**: the fork still carries the dead `/* ... */` block (`nhp/test/api_test.go:8-87`) — vestigial upstream Zhejiang-gov SSO demo code + hardcoded demo creds (dead in the fork; an upstream integration we don't use) — and a no-op `TestUrlEncoding`. **Resolved in #3087** (PR #3090): deleted the dead `/* ... */` block and rewrote the no-op `TestUrlEncoding` into a real round-trip + encode-contract test (mirrors 449e2c0d's assertions, keeps `api_test.go`). (Prior "cherry-pick not possible without upstream git access" reasoning was wrong — the fork adapts manually.) | 2026-07-01 |
| 7e0ecc8d | build(deps): bump wazero to v1.12.0 and etcd client to v3.6.12 | SKIP | Fork manages dependencies separately | 2026-07-01 |
| a3c3e8f6 | fix: bump go-toml to v2.4.1 in plugin modules | SKIP | Upstream plugin modules; fork has different plugin layout | 2026-07-01 |
| 66bc7815 | chore(deps): align example plugins with go-toml v2.4.2 | SKIP | Upstream plugin modules; fork has different plugin layout | 2026-07-01 |
| 5764feb1 | fix(deps): bump vite in docs for CVE | SKIP | Upstream docs website only | 2026-07-01 |
| e5542bdf | fix(deps): fix basic-ftp and ws vulnerabilities in docs | SKIP | Upstream docs website only | 2026-07-01 |
| 1d638cbd | chore: bump version to 0.8.0 | SKIP | Upstream versioning | 2026-07-01 |

---

## Monthly Sync Process

Run this process monthly (or immediately for security fixes).

> **Note:** The helper script automatically adds the `upstream` remote if missing.
> Manual setup: `git remote add upstream https://github.com/OpenNHP/opennhp.git`

```bash
# 1. Check for new commits
./scripts/check-upstream.sh

# 2. Triage (use Decision Matrix above)
# - Security? → Sync now
# - Matches auto-skip? → Ignore
# - Other? → Quick evaluate

# 3. Create branch and sync
git checkout -b sync/upstream-<desc>
git cherry-pick -x <sha>  # -x adds "(cherry picked from commit ...)"

# 4. Test before committing (subshells preserve working directory)
(cd nhp && go build ./... && go test ./...) || exit 1
(cd endpoints && go build ./... && go test ./...) || exit 1
(cd examples/server_plugin && go build ./...) || exit 1

# 5. Create PR
gh pr create --title "chore: sync upstream <category>"

# 6. After PR merges, update this file (see below)
```

### When Cherry-Pick Fails

> **"Can't cherry-pick cleanly" is never by itself a SKIP reason.** The fork routinely adapts upstream fixes by hand — a SKIP must stand on the change *not applying to fork code*, not on cherry-pick friction. If it applies, adapt it (or open a tracking issue to adapt it).

If cherry-pick fails due to fork differences (e.g., GMSM removal):

1. **Adapt manually** - apply the changes by hand
2. **Document in commit message** - note it was "adapted from" not "cherry-picked from"
3. **Explain why** - mention what couldn't be cherry-picked (e.g., "GMSM references")

Example commit message:
```
chore: sync upstream PKCS7 tests

Adapted from upstream commit 95d5e228. Manual adaptation required
because original commit references GMSM which was removed from fork.
```

### Updating This File

**When to update:**
- Add sync history entry: after PR is created (use actual PR number)
- Update baseline SHA: only after ALL sync PRs from a batch are merged
- Update Pending Review: mark items DONE with PR number

**Avoiding conflicts:** If multiple sync PRs are open, only the LAST one should update this file. Or update in a separate `docs/sync-bookkeeping` PR after all syncs merge.

---

## Fork-Specific Differences

This fork intentionally differs from upstream in these ways:

| Area | Upstream | Fork | Reason |
|------|----------|------|--------|
| Crypto | GMSM + Curve25519 | Curve25519 only | Chinese crypto not needed |
| CI/CD | GitHub Actions only | Terraform + GH Actions | AWS deployment automation |
| Authentication | Generic OIDC | Console integration | LayerV-specific auth flow |
| Logging | JSON format | CloudWatch structured | AWS observability |
| Config | File-based | etcd + Secrets Manager | Multi-tenant support |

---

## Contributing Back to Upstream (Fork → Upstream)

This section tracks changes made in this fork that could benefit the upstream OpenNHP project.

### Contribution Criteria

A change is a good upstream candidate if it:
- Fixes a bug that affects all NHP users (not just LayerV)
- Improves security or prevents panics
- Adds tests for existing functionality
- Improves error handling or logging
- Is NOT specific to LayerV infrastructure (no Terraform, etcd, Console)

### Contribution Status

| Fork PR | Description | Upstream PR | Status | Notes |
|---------|-------------|-------------|--------|-------|
| #75 | DNS re-resolution on server discovery | - | CANDIDATE | General improvement, benefits all users |
| #93 | DNS cache invalidation on failures | - | CANDIDATE | Pairs with #75 |
| #86 | Crypto error handling improvements | - | CANDIDATE | Already adapted from upstream #1338 |
| #2010 | Noise intermediate chain key fix | [OpenNHP#1557](https://github.com/OpenNHP/opennhp/pull/1557) | MERGED | Cherry-picked the existing `enable_webrtc` commit `03619015` onto `upstream/main`; merged 2026-05-23 (`e7886f8e`). Downstream follow-up **resolved**: [qurl-reverse-tunnel-client#178](https://github.com/layervai/qurl-reverse-tunnel-client/pull/178) bumped the OpenNHP submodule straight to the post-fix merge commit and stayed on the public OpenNHP pin (no `layervai/nhp` binary-distribution fingerprint) — pinning the merge commit avoided any wait on an upstream release. |
| #1249 | Authenticate knock HeaderType — block on-path NHP_KNK↔NHP_EXT flips (#1154/#1257) | [OpenNHP#1584](https://github.com/OpenNHP/opennhp/pull/1584) | MERGED | Secure-by-default re-contribution of the fork's gated work; merged 2026-06-15 (merge `306a73f0`; substantive commits `cfa08718` server+agent, `d10afec2` js-agent). Fork keeps its permit→strict gate (it has fork-only legacy knock clients, #1257); upstream went unconditional (two first-party agents only). SKIP guard rows added under Individual Commit Decisions so a future sync doesn't port it back over the gate. |

### Fork-Only (Never Contribute)

These changes are intentionally fork-specific:

| Fork PR/Area | Description | Reason |
|--------------|-------------|--------|
| `terraform/*` | AWS infrastructure | LayerV-specific deployment |
| `tests/local/*` | etcd integration tests | Uses LayerV's etcd setup |
| Console auth integration | OIDC with Console | LayerV product integration |
| CloudWatch logging | Structured AWS logs | AWS-specific observability |
| Secrets Manager integration | AWS secrets | AWS-specific config |

### How to Contribute Upstream

**Prerequisites:**
- You need a **personal fork** of [OpenNHP](https://github.com/OpenNHP/opennhp) on GitHub
- Add your personal fork as a remote: `git remote add myfork https://github.com/YOUR_USERNAME/opennhp.git`

```bash
# 1. Identify a general-purpose fix in this fork
#    Check it meets Contribution Criteria above

# 2. Check upstream hasn't already fixed it
git fetch upstream
git log upstream/main --oneline --grep="<relevant keywords>"

# 3. Create a clean branch from upstream/main
git checkout -b contribute/<feature> upstream/main

# 4. Cherry-pick or rewrite the changes (cleaner history preferred)
git cherry-pick <fork-commit-sha>
# OR manually apply changes for cleaner commit message

# 5. Ensure it builds/tests without LayerV-specific deps
cd nhp && go build ./... && go test ./...
cd ../endpoints && go build ./... && go test ./...

# 6. Push to YOUR PERSONAL FORK and open PR
git push myfork contribute/<feature>
# Open PR at https://github.com/OpenNHP/opennhp/pulls

# 7. Update this file:
#    - Add entry to Contribution Status table with upstream PR link
#    - Add entry to Upstream Contribution Log
```

### Upstream Contribution Log

Record all contribution attempts here:

| Date | Description | Upstream PR | Result |
|------|-------------|-------------|--------|
| 2026-05-22 | Backport noise intermediate chain key fix to `upstream/main` (cherry-pick of `03619015` from `enable_webrtc`) | [OpenNHP#1557](https://github.com/OpenNHP/opennhp/pull/1557) | MERGED 2026-05-23 (`e7886f8e`) |
| 2026-06-15 | Authenticate knock HeaderType — reject on-path NHP_KNK↔NHP_EXT flips (secure-by-default version of the fork's #1154/#1257 gate, #1249) | [OpenNHP#1584](https://github.com/OpenNHP/opennhp/pull/1584) | MERGED 2026-06-15 (merge `306a73f0`) |

---

## Related Issues

These GitHub issues track upstream sync work:

- #85 - NewHash/AeadFromKey error handling (DONE - PR #86)
- #87 - Unit tests for crypto functions
- #92 - Error handling consistency
- #99 - PKCS7 tests
- #101 - Non-standard PKCS7 padding evaluation
