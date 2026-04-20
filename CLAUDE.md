# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL RULES - NEVER VIOLATE

> **NEVER push directly to `main` branch.** All changes MUST go through a Pull Request, no exceptions. This applies even for "quick fixes" or "urgent" changes. Create a branch, open a PR, and let CI run.

> **All commits must be GPG/SSH signed.** Unsigned commits will be rejected by GitHub branch protection rules.

## Code Change Workflow

Follow this process for all code changes:

1. **Switch to main and fetch latest**
   ```bash
   git checkout main && git pull origin main
   ```

2. **Create branch for code change**
   ```bash
   git checkout -b <type>/<short-description>
   ```

3. **Make code changes** - Think deeply about the implementation. Consider edge cases, error handling, and maintainability.

4. **Consider documentation updates** - If the change affects behavior, APIs, or configuration, update relevant docs.

5. **Create a PR**
   ```bash
   git push -u origin <branch>
   gh pr create --title "<type>(scope): description" --body "..."
   ```

6. **Wait for code review feedback** - CI runs automatically. Review comments will be posted on the PR.

7. **Address review feedback** - Think critically about each suggestion:
   - Fix what makes sense
   - For deferred items, create a GitHub issue to track

8. **Update the PR** - Push fixes, update PR description if needed.

9. **Repeat steps 6-8** until feedback requires no further action.

---

Quick reference for the LayerV NHP (Network Hiding Protocol) infrastructure project.

> **Note:** This is a fork of [OpenNHP](https://github.com/OpenNHP/opennhp). See `docs/UPSTREAM_SYNC.md` for the upstream synchronization process.

**For detailed documentation, see:**
- `docs/ARCHITECTURE.md` - Complete system architecture, auth flows, debugging
- `docs/TESTING.md` - Test categories, build tags, running tests
- `docs/server_plugin.md` - Plugin development guide
- `docs/UPSTREAM_SYNC.md` - Upstream sync tracking and process

## Project Structure

```
nhp/                 # Core NHP protocol library (Go module)
endpoints/           # Services: server, ac, agent, db (Go module)
examples/            # Example plugins (Go module)
terraform/           # IaC with modules and environments (sandbox, prod)
docker/              # Dockerfile.server, Dockerfile.ac.aws
tests/               # local/, integration/, e2e/
release/             # Build output (gitignored)
```

**Multi-Module Workspace:** Three Go modules with `replace` directives pointing to local paths. Always run `go mod tidy` in all three when updating dependencies.

**Related Repos:** `console` (UI/API), `website` (layerv.ai), `traefik-plugins` (middleware)

## AWS Profiles

```bash
AWS_PROFILE=layerv          # Sandbox operations
AWS_PROFILE=layerv-mgmt     # Management/Org operations
```

## Commit Convention (Release Please)

This repository uses [Release Please](https://github.com/googleapis/release-please) for automated releases. Commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/) format.

### Format

```
type(scope): description

[optional body]

[optional footer(s)]
```

### Commit Types and Version Impact

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | **Minor** (0.X.0) |
| `fix` | Bug fix | **Patch** (0.0.X) |
| `docs` | Documentation only | None |
| `style` | Code style (formatting, semicolons) | None |
| `refactor` | Code change that neither fixes nor adds | None |
| `perf` | Performance improvement | **Patch** |
| `test` | Adding or updating tests | None |
| `build` | Build system or dependencies | None |
| `ci` | CI configuration | None |
| `chore` | Maintenance tasks | None |

### Breaking Changes (Major Version)

Use `!` after the type or add `BREAKING CHANGE:` in the footer:

```bash
feat(api)!: remove deprecated endpoints

# Or with footer:
feat(api): redesign authentication flow

BREAKING CHANGE: JWT tokens now require audience claim
```

### Scopes

| Scope | Component |
|-------|-----------|
| `ac` | Access Controller |
| `server` | NHP Server |
| `agent` | NHP Agent |
| `db` | Database service |
| `nhp` | Core protocol library |
| `terraform` | Infrastructure |
| `docker` | Container configuration |
| `ci` | GitHub Actions workflows |

### Examples

```bash
feat(ac): add IPv6 support for iptables rules
fix(server): prevent panic on nil knock packet
docs(readme): update installation instructions
refactor(nhp): extract crypto utilities to separate package
feat(api)!: require authentication for all plugin endpoints
chore: sync with upstream OpenNHP
```

### Release Please Behavior

1. **On merge to main**: Release Please creates/updates a release PR
2. **Release PR**: Accumulates changes, updates CHANGELOG.md, bumps version
3. **Merge release PR**: Creates GitHub release with tag and artifacts

## Common Commands

### Build (Makefile)

```bash
make all              # Full build: all binaries, SDKs, plugins, archive
make init             # Clean and go mod tidy all modules
make lint             # Run golangci-lint on nhp/ and endpoints/
make lint-workflows   # Run actionlint + shellcheck on .github/workflows/ (mirrors CI)
make test             # Run unit tests
make test-local       # Run local e2e tests (requires etcd container)
make fuzz-quick       # Run fuzz tests briefly (FUZZTIME_QUICK, default 15s)
make fuzz             # Run fuzz tests at full budget (FUZZTIME_LONG, default 60s)

# Override the per-target fuzz budget (e.g., fast local smoke or long manual run):
FUZZTIME_QUICK=2s make fuzz-quick
FUZZTIME_LONG=5m  make fuzz
```

### Go (Manual)

```bash
# Run go mod tidy on all modules
cd nhp && go mod tidy && cd ../endpoints && go mod tidy && cd ../examples/server_plugin && go mod tidy

# Run all tests (KBS_SKIP_INIT prevents private key dir creation)
KBS_SKIP_INIT=1 go test ./... -v -race

# Run a single test by name
cd endpoints && KBS_SKIP_INIT=1 go test -v ./server/... -run TestACRegistry

# Build single binary (static, no CGO)
cd endpoints && CGO_ENABLED=0 go build -o ../release/nhp-server/nhp-serverd ./server/main/main.go
```

### Terraform

```bash
# Always format before committing
terraform fmt -recursive terraform/

# Sandbox operations (from terraform/environments/sandbox/)
AWS_PROFILE=layerv terraform init
AWS_PROFILE=layerv terraform plan
AWS_PROFILE=layerv terraform apply

# State operations
AWS_PROFILE=layerv terraform state list
AWS_PROFILE=layerv terraform state show 'module.ac.resource'
```

**State Drift Protection for CI/CD-Managed Values:**

Some SSM parameters are created by Terraform but updated by CI/CD (e.g., image tags, blue/green deployment state). These use `lifecycle { ignore_changes = [value] }` to prevent Terraform from overwriting CI/CD updates:

```hcl
resource "aws_ssm_parameter" "image_tag" {
  name  = "/${var.environment}/nhp/server/image-tag"
  value = var.image_tag  # Initial value from Terraform

  lifecycle {
    ignore_changes = [value]  # CI/CD updates this
  }
}
```

Parameters using this pattern:
- `/${env}/nhp/server/image-tag` - Docker image tag (CI updates on deploy)
- `/${env}/nhp/server/green-image-tag` - Green ASG image tag (blue/green)
- `/${env}/nhp/server/active-color` - Current active deployment color
- `/${env}/nhp/server/last-switch-timestamp` - Deployment audit trail
- `/${env}/nhp/ac/image-tag` - AC Docker image tag
- Auth0 backend credentials secret version - Auth0 provider returns empty `client_secret`
- Dev portal management credentials secret version - same Auth0 provider limitation

### Docker

```bash
docker buildx build -f docker/Dockerfile.server -t nhp-server .
docker buildx build -f docker/Dockerfile.ac.aws -t nhp-ac .
trivy image nhp-server --severity HIGH,CRITICAL
```

### GitHub CLI

```bash
gh run list --limit 10
gh run watch
gh pr create --title "feat(scope): description" --body "..."
```

### Deployment

```bash
# Trigger production deployment (interactive — reads state, validates, confirms)
./scripts/trigger-prod-deploy.sh

# Dry-run: show what would be deployed without prompting
./scripts/trigger-prod-deploy.sh --dry-run

# Machine-readable JSON output for tooling
./scripts/trigger-prod-deploy.sh --json
```

## Key Ports

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 62206 | UDP | NHP Server | Knock packets (via NLB) |
| 8888 | TCP | NHP Server | HTTP plugin endpoints |
| 443 | TCP | AC Traefik | HTTPS (TLS termination) |

## Quick Debugging

### Instance Access

```bash
# Find instances
AWS_PROFILE=layerv aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*sandbox*" "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0]]' --output table

# SSM session
AWS_PROFILE=layerv aws ssm start-session --target i-XXXXX
```

### Logs

```bash
# AC logs (native binary)
tail -100 /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log

# Server logs (inside Docker - NOT docker logs!)
docker exec nhp-server cat /nhp-server/logs/server-$(date +%Y-%m-%d).log | tail -100
```

### ASG Operations

```bash
# Start instance refresh
AWS_PROFILE=layerv aws autoscaling start-instance-refresh \
  --auto-scaling-group-name "nhp-sandbox-server"

# Cancel stuck refresh
AWS_PROFILE=layerv aws autoscaling cancel-instance-refresh \
  --auto-scaling-group-name "nhp-sandbox-server"
```

## Common Issues

| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| AC "accept iptables input" | Can't reach server | Check NLB DNS, security groups |
| AC "ECDH failed" | Key mismatch | Check ac.toml/server.toml keys |
| 502 on /plugins/* | Server HTTP down | Check port 8888, security groups |
| Server "0 AC peers" | No ACs in etcd | Check AC registration |
| Test panic "private key" | Missing env var | Set `KBS_SKIP_INIT=1` |

## Cloud Map DNS (Internal)

```
server.nhp.sandbox.internal     # NHP Server
ac.nhp.sandbox.internal         # Access Controller
etcd.nhp.sandbox.internal:2379  # etcd cluster
```

## etcd Keys

```
/nhp/config                     # Shared config
/nhp/ac-registry/{instance-id}  # Per-AC registration
```

## Quick URLs (Sandbox)

| URL | Purpose |
|-----|---------|
| `https://console.nhp.layerv.xyz` | Console UI |
| `https://qurl.link/{appId}` | Login portal |
| `https://{appId}.qurl.site/` | Protected resource |

## QURL API (Creating QURLs)

**Auth0 Domain:** `https://auth.layerv.ai` (NOT the tenant domain)

**API Endpoint:** `https://api.layerv.xyz` (NOT api.qurl.link)

```bash
# 1. Get Auth0 token
AUTH0_SECRET=$(AWS_PROFILE=layerv aws secretsmanager get-secret-value \
  --secret-id "layerv-nhp-sandbox-auth0-backend-credentials" \
  --query SecretString --output text)
CLIENT_ID=$(echo "$AUTH0_SECRET" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$AUTH0_SECRET" | jq -r '.client_secret')
AUDIENCE=$(echo "$AUTH0_SECRET" | jq -r '.audience')

TOKEN_RESPONSE=$(curl -s --request POST \
  --url "https://auth.layerv.ai/oauth/token" \
  --header "content-type: application/json" \
  --data "{\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"audience\":\"$AUDIENCE\",\"grant_type\":\"client_credentials\"}")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# 2. Create QURL (POST /v1/qurls)
# IMPORTANT: expires_in is a DURATION STRING like "1h", "168h", NOT an integer
curl -s --request POST \
  --url "https://api.layerv.xyz/v1/qurls" \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{
    "target_url": "https://example.com",
    "expires_in": "168h",
    "max_sessions": 10,
    "description": "My QURL"
  }' | jq '.data.qurl_link'
```

**Response structure:** `{ "data": { "resource_id": "...", "qurl_link": "https://qurl.link/#at_xxx", "qurl_site": "..." } }`

## Smoke Test Suite

Location: `tests/smoke/` (own Go module, build tag `smoke`).

The smoke suite runs against the **deployed** sandbox or prod
environment after a deploy completes. It fences NHP's own contract —
every guarantee the server and AC make to their consumers (QURL
plugin, Traefik plugin, the NHP wire protocol, the blue/green deploy
workflow). Unlike unit/local/integration/e2e tests, smoke exercises
the actual binary that is running in production.

### When to run

- CI: `.github/workflows/build-and-push.yml` runs it against sandbox
  after `deploy-sandbox-validate`. `.github/workflows/promote-to-prod.yml`
  runs it against prod alongside `qurl-smoke-tests`. Both paths
  currently run in report-only mode (burn-in).
- Manual: `gh workflow run nhp-smoke-tests.yml --ref <branch> -f environment=sandbox -f tier=tier1 -f allow_ssm_probes=true`
- Local: `make test-smoke-sandbox` (reads AWS credentials from the
  `layerv` profile and fetches Auth0 from Secrets Manager).

### Tiers

Tests are organized by file-name prefix so `go test` runs them in a
deterministic order:

| Prefix | Tier | Purpose |
|---|---|---|
| `01_`–`09_` | Tier 1 | Regression guards for fenced bug classes |
| `10_`–`19_` | Tier 2 | Consumer contract (guarantees NHP makes) |
| `20_`–`29_` | Tier 3 | NHP capability coverage + informational telemetry |

PR1 ships Tier 1 only. PR2 adds Tier 2. PR3 adds Tier 3 + flips
`continue-on-error` to false in the CI wiring so smoke becomes a
required check.

### Maintenance rules (enforced at review)

1. **One file per NHP capability.** File name = capability in
   snake_case + `_test.go`. New capability ⇒ new file; retired
   capability ⇒ deleted file. If deleting the file would orphan
   assertions about other capabilities, the file is too broad and
   needs to split.
2. **Every test name references a capability or a bug class.**
   `TestHealth_KnockReadyReflectsACPeerCount` passes.
   `TestHealth_Works` fails review.
3. **Every Tier 1 test has a Go comment tagging the PR whose
   regression it fences.** Format: `// Regression fence for PR #1005
   (knock-ready gate used docker exec wget).`
4. **Every Tier 3 timing test has an SLO it fences.** No SLO
   documented in CLAUDE.md or code comments, no timing test.
5. **Deletion is a valid PR.** When a bug class is structurally
   eliminated, the Tier 1 test is **deleted** — not updated to
   point at a new class. The new mechanism gets its own test.
6. **CODEOWNERS.** Every PR that adds or changes a smoke test
   requires sign-off from `justin@layerv.ai` (see
   `.github/CODEOWNERS`).
7. **Banned file names**: `coverage_test.go`, `advanced_test.go`,
   `features_test.go`. These give no information. If the right file
   name isn't obvious, the capability doesn't exist yet.
8. **SSM probes are named helpers.** No `runCommand(cmd, args)` API.
   Every new probe is a reviewed function in `ssm_probe.go` with the
   command baked in as a Go constant. The reject-list in
   `ssm_probe.go` is defense in depth — it must never be the only
   thing catching a bad command.
9. **When shipping a new NHP capability, the same PR ships its
   Tier 2 contract test.**
10. **No test-only endpoints in production binaries.** If a contract
    can't be tested from smoke without test-mode code, it's an
    integration test, not a smoke test.
11. **30-day SSM burn-in.** Prod starts with `allow_ssm_probes: false`
    until the scheduled unlock workflow confirms 30 days of green
    sandbox runs.

### Shipping a new NHP capability

If you add a new NHP capability (endpoint, protocol message, deploy
gate, etc.), the PR that ships it should also:

1. Add a new `XX_<capability>_test.go` file under `tests/smoke/`.
2. Pick the appropriate tier:
   - Tier 1 if it fences a specific bug class fresh from a fixed PR.
   - Tier 2 if it's a consumer contract clause.
   - Tier 3 if it's capability observation or timing.
3. Cross-reference the PR number in Go comments (`// Regression
   fence for PR #NNNN` or `// Capability added in PR #NNNN`).
4. If the test needs SSM, add the probe as a named helper in
   `ssm_probe.go` with the command as a Go constant. Get review
   from `justin@layerv.ai`.

## Security Notes

- Never commit secrets - use AWS Secrets Manager
- All storage encrypted with KMS CMKs
- IMDSv2 required on EC2
- AC private keys NEVER in etcd - only Secrets Manager
