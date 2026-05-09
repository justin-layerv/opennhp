# OpenNHP Upstream Synchronization

This document tracks the synchronization status between this fork (LayerV NHP) and the upstream [OpenNHP](https://github.com/OpenNHP/opennhp) repository.

## Baseline

| Field | Value |
|-------|-------|
| **Last reviewed upstream SHA** | f53b7e2d |
| **Last review date** | 2026-05-01 |
| **Reviewer** | Claude Code |

> **HOW TO USE:** When checking for updates, run:
> ```bash
> git log f53b7e2d..upstream/main --oneline
> ```
> This shows ONLY new commits since last review. Update the SHA after each review.

---

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
| (none yet) | | | |

---

## Related Issues

These GitHub issues track upstream sync work:

- #85 - NewHash/AeadFromKey error handling (DONE - PR #86)
- #87 - Unit tests for crypto functions
- #92 - Error handling consistency
- #99 - PKCS7 tests
- #101 - Non-standard PKCS7 padding evaluation
