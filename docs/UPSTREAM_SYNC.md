# OpenNHP Upstream Synchronization

This document tracks the synchronization status between this fork (LayerV NHP) and the upstream [OpenNHP](https://github.com/OpenNHP/opennhp) repository.

## Baseline

| Field | Value |
|-------|-------|
| **Last reviewed upstream SHA** | bd6b7538 |
| **Last review date** | 2026-01-09 |
| **Reviewer** | @posey |

> **HOW TO USE:** When checking for updates, run:
> ```bash
> git log bd6b7538..upstream/main --oneline
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
| c05a0ded | Enable gosec linter | HIGH | Need to add `.golangci.yml` first |
| 42f39409 | Loop variable capture fix | HIGH | Part of lint PR |
| 9d1b7711 | Shared constants | MEDIUM | `nhp/common/constants.go` |
| 95d5e228 | PKCS7 consolidation | LOW | May conflict with fork changes |

---

## Individual Commit Decisions

Non-obvious skips that don't fit Auto-Skip Categories:

| SHA | Title | Decision | Reason | Date |
|-----|-------|----------|--------|------|
| 634e3d8c | feat(cli): add --json output | SKIP | Fork doesn't use CLI this way | 2026-01-09 |
| 1bbece70 | refactor(httpauth): dedup handlers | PENDING | Low priority, may do later | 2026-01-09 |
| 9ef61076 | refactor(logging): standardize format | SKIP | Fork has own logging patterns | 2026-01-09 |

---

## Monthly Sync Process

Run this process monthly (or immediately for security fixes).

> **Note:** The helper script automatically adds the `upstream` remote if missing.
> Manual setup: `git remote add upstream https://github.com/OpenNHP/opennhp.git`

```bash
# 1. Check for new commits (use the helper script)
./scripts/check-upstream.sh

# 2. Quick triage
# - Security? → Sync now
# - Matches auto-skip? → Ignore
# - Other? → Quick evaluate

# 3. If syncing, cherry-pick with -x flag
git checkout -b sync/upstream-<desc>
git cherry-pick -x <sha>  # -x adds "(cherry picked from commit ...)"

# 4. Update this file
# - Change "Last reviewed upstream SHA" to new HEAD
# - Add sync history entry
# - Log any non-obvious skip decisions

# 5. Create PR
gh pr create --title "chore: sync upstream <category>"
```

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
