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
internalauth/        # Shared HMAC canonicalization (Go module — published path:
                     # github.com/OpenNHP/opennhp/internalauth, consumed by
                     # nhp-server, qurl-service, qurl-reverse-tunnel-server)
endpoints/           # Services: server, ac, agent, db (Go module)
examples/            # Example plugins (Go module)
terraform/           # IaC with modules and environments (sandbox, prod)
docker/              # Dockerfile.server, Dockerfile.ac.aws
tests/               # local/, integration/, e2e/
release/             # Build output (gitignored)
```

**Multi-Module Workspace:** Five Go modules — `nhp/`, `internalauth/`, `endpoints/`, `examples/server_plugin/`, `tests/local/`. The first four are wired with `replace` directives pointing to local paths (`internalauth` is also published externally so qurl-service and qurl-reverse-tunnel-server can import the same HMAC canonicalization). Always run `go mod tidy` in all five when updating dependencies; `make init` does this. Other Go modules (`tests/e2e/`, `tests/integration/`, `tests/smoke/`, `docker/web-app/`) have their own lifecycle and aren't auto-tidied — tracked in #1290.

**Related Repos:** `console` (UI/API), `website` (layerv.ai), `traefik-plugins` (middleware)

## AWS Profiles

```bash
AWS_PROFILE=layerv          # Sandbox operations
AWS_PROFILE=layerv-prod     # Production operations (used by promote-to-prod + the prod /internal/v1/* triage runbook)
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
| `internalauth` | Shared HMAC canonicalization module (cross-repo) |
| `terraform` | Infrastructure |
| `docker` | Container configuration |
| `ci` | GitHub Actions workflows |

> Keep this table in lockstep with the Component dropdown in
> `.github/ISSUE_TEMPLATE/bug_report.yml`. Drift is enforced at CI by
> `scripts/check-scope-drift.sh` (invoked from `make lint-workflows` and
> `.github/workflows/validate-workflows.yml`); add a new scope to both
> places in the same PR.

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

Both fuzz targets route through `scripts/run-fuzz.sh`, which distinguishes a real crasher (writes `testdata/fuzz/<NAME>/<sha>`) from the upstream Go-fuzz coordinator deadline-race flake (no reproducer file). If `fuzz-quick` ever goes red on a PR that didn't touch Go code, check the wrapper first — and after a Go toolchain bump, re-validate the deadline-race signature it greps for. The wrapper's decision tree is fenced by `tests/lints/run-fuzz/run-fixtures.sh`.

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

**ASG capacity is co-owned with CI/CD.** Three ASGs use
`lifecycle { ignore_changes = [desired_capacity, min_size] }` for
the same reason as the SSM params above — CI/CD scales them during
blue/green flips and canary rollouts, and the next `terraform apply`
must not revert that. Operator-side `aws autoscaling
update-auto-scaling-group` against these ASGs sticks until something
else flips it (no plan-time revert):

- `aws_autoscaling_group.server` (`modules/server/main.tf`)
- `aws_autoscaling_group.ac` (`modules/ac/main.tf`)
- `aws_autoscaling_group.frps` blue + green (`modules/qurl-reverse-tunnel-server/main.tf`, `blue_green.tf`)

`max_size` is deliberately NOT in `ignore_changes` so a CI scale-up
that exceeds the static cap fights the rehearsal — the cap is the
safety net.

**IAM eventual-consistency shim pattern.** When the same `terraform
apply` both grants a new permission to a CI role's policy AND
creates a resource that needs that permission, the IAM
authorization evaluator can lag the API call by up to ~60s and the
fresh resource hits AccessDenied. The shim is a `time_sleep` keyed
on a policy fingerprint; the consumer adds `depends_on` on the
sleep. Existing instances of the pattern:

- `time_sleep.apigateway_logging_propagation` (10s; APIGW async
  CloudWatch role check, bounded). Trigger source: a *resource
  dependency* (`depends_on = [aws_api_gateway_account.this]`).
- `time_sleep.qurl_link_static_iam_propagation` (60s; IAM
  evaluator propagation, no published SLA). Trigger source: a
  *content dependency* (sha256 of the policy doc + the policy ARN).

Pick by what you're racing: a resource creation → resource-dep
trigger; an in-place policy doc edit → content-hash trigger.

To add a shim for another CI policy when it next trips: expose
`<policy>_policy_doc_hash` AND `<policy>_policy_arn` as outputs
from whichever module owns the policy (today: `modules/ecr/`;
after #1812: `modules/ci-policies/`) computed as
`sha256(aws_iam_policy.<policy>.policy)` and
`aws_iam_policy.<policy>.arn`. Add a `time_sleep` keyed on both
in `terraform/main.tf`, gated on the OR of every consumer's
condition (so envs without consumers don't pay the 60s), and add
`depends_on` on each consumer needing the freshly granted perm.
The 10s value is for APIGW only — for IAM-evaluator races use 60s.

The two triggers cover different races: the doc hash catches
in-place perm edits (the common case); the ARN rotates on a
rename-via-`name`. Note `policy_arn` does NOT cover `terraform
taint` of a same-name policy — IAM policy ARNs are deterministic
from `arn:aws:iam::ACCT:policy/NAME`, so a taint+recreate reads
back an identical string and `triggers` compares strings, not
resource identities. For the taint case, also taint the
`time_sleep` so the wait re-fires.

`depends_on` defends create + replace paths only. For an in-place
update on an existing resource that exercises a freshly granted
perm, the right escape hatch depends on the resource's replacement
cost:

- **Cheap to recreate** (most resources): `replace_triggered_by =
  [time_sleep.<policy>_iam_propagation]` on the consumer's
  `lifecycle` forces it to recreate when the policy doc changes,
  paying the 60s on the recreate path.

  ```hcl
  resource "aws_some_cheap_resource" "example" {
    # ...config that exercises a newly granted perm...

    lifecycle {
      replace_triggered_by = [time_sleep.qurl_link_static_iam_propagation[0]]
    }
  }
  ```

- **Expensive to recreate** (CF distribution: 15–30 min global
  propagation; ECS service: traffic disruption): DO NOT use
  `replace_triggered_by`. Either split the perm-grant apply from
  the consumer-config apply (two-phase), or manually `terraform
  taint` the consumer once after the perm lands. Both pay the 60s
  exactly once instead of on every policy edit.

Greenfield envs aren't covered by the existing shim's consumer
set — all CF resources consuming the policy need their own
`depends_on` on first apply (tracked in #1813).

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

### Sandbox dispatch contract

`build-and-push.yml`'s `workflow_dispatch` is **only valid from
`refs/heads/main`**. The OIDC trust policy on the AWS roles
(`terraform/modules/ecr/{main,packer}.tf`) accepts only main-branch
or environment-scoped sub claims; a dispatch from any feature
branch produces `repo:layervai/nhp:ref:refs/heads/<branch>` and is
rejected with `sts:AssumeRoleWithWebIdentity` denial. This is
intentional security per #1121 (PR-time terraform plan can exfil
short-lived STS credentials). The setup job's `Validate dispatch
ref` step fails fast with this guidance; don't loosen the trust
policy to "fix" a feature-branch dispatch.

```bash
# Force a sandbox build/deploy after a path-only merge (e.g.,
# .trivyignore-only PRs that didn't trigger the workflow on push):
gh workflow run build-and-push.yml --ref main \
  -f environment=sandbox -f force_build=true -f deploy=true
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

### Debugging qurl-service `/internal/v1/*` from a laptop

`/internal/v1/*` is no longer reachable from the public internet
(`api.layerv.{xyz,ai}/internal/*` returns 404 — qurl-service #335 PR4).
It serves only on the internal ALB at `internal-api.qurl.layerv.{xyz,ai}`,
which resolves only inside the VPC via the workload-account private
hosted zone.

To curl an internal endpoint for triage:

```bash
# 0. Set ENV first — it parameterizes the AWS profile, the instance
#    tag filter, the secret name, AND the internal hostname. Hard-
#    coding any one of these breaks the prod path on copy-paste.
ENV=sandbox  # or "prod"
PROFILE=$([ "$ENV" = "prod" ] && echo "layerv-prod" || echo "layerv")
TLD=$([ "$ENV" = "prod" ] && echo "ai" || echo "xyz")

# 1. Find any private-subnet NHP-server EC2 in the target env. The
#    no-instances guard catches a tag-filter typo or an ASG-scaled-
#    to-0 incident state — without it, step 2 silently runs against
#    the placeholder `i-XXXXX` literal.
INSTANCE=$(AWS_PROFILE=$PROFILE aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*${ENV}*server*" \
            "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text | tr '\t' '\n' | head -1)
[ -n "$INSTANCE" ] || { echo "ERROR: no running NHP server instances in $ENV" >&2; exit 1; }

# 2. SSM session
AWS_PROFILE=$PROFILE aws ssm start-session --target "$INSTANCE"

# 3. Inside the session — fetch service token from Secrets Manager.
#    The NHP server EC2 role grants secretsmanager:GetSecretValue on
#    var.qurl_service_token_secret_arn (verified at
#    terraform/modules/compute/main.tf:465), so this curl works
#    in-session without additional IAM scoping.
#
#    Fail-safe shape detection across two shapes only:
#      (a) today's raw plaintext, or
#      (b) an explicit `{"token": "..."}` envelope after a future
#          migration. The `jq -er '.token'` branch fail-fasts on a
#          non-`.token` envelope and the fallback preserves today's
#          plaintext behavior. Any OTHER JSON shape (e.g., `.value`,
#          `.secret`, `.data.token`) is then explicitly rejected by
#          the case-statement guard below — this prevents curl
#          proceeding with a literal JSON object as the
#          X-Service-Token header, which would produce a confusing
#          401 at the handler. If the envelope is ever migrated to a
#          shape other than `.token`, update the jq filter here.
# jq isn't shipped on AL2023 by default; if cloud-init didn't
# install it, the `jq -er '.token' 2>/dev/null` invocation below
# would silently fall through to TOKEN_RAW for ANY shape (not just
# plaintext) — defeating the envelope-detection guard. Surface
# the missing dep explicitly first.
command -v jq >/dev/null 2>&1 || {
  echo "ERROR: jq is not installed in this SSM session. Install via your distro's package manager (AL2023/RHEL: sudo dnf install -y jq; Debian/Ubuntu: sudo apt-get install -y jq) or update cloud-init to bake it in. Without jq the envelope-shape detection below cannot run." >&2
  exit 1
}
TOKEN_RAW=$(aws secretsmanager get-secret-value \
  --secret-id "layerv-nhp-${ENV}/qurl-internal-service-token" \
  --query SecretString --output text)
TOKEN=$(printf '%s' "$TOKEN_RAW" | jq -er '.token' 2>/dev/null || printf '%s' "$TOKEN_RAW")
case "$TOKEN" in
  '{'*|'['*)
    echo "ERROR: secret envelope shape changed (TOKEN starts with JSON delimiter). Update the jq filter at CLAUDE.md \"qurl-internal-service-token\" — likely a key other than .token (e.g., .value, .secret, .data.token)." >&2
    exit 1
    ;;
esac

# 4. Curl
curl -H "X-Service-Token: $TOKEN" \
  "https://internal-api.qurl.layerv.${TLD}/internal/v1/resource/r_xxx/target"
```

Public-resolver test (verify hostname is NOT externally resolvable).
**Both `.xyz` (sandbox) and `.ai` (prod) probed regardless of `ENV`** —
the test is "no env's internal hostname has leaked to the public zone,"
not "this env's hostname is private," so we want both reading
NXDOMAIN every time.

```bash
dig internal-api.qurl.layerv.xyz @1.1.1.1   # must return NXDOMAIN
dig internal-api.qurl.layerv.ai  @1.1.1.1   # must return NXDOMAIN
```

If either resolves, a record has leaked into the public zone — file a
P0 incident.

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

**Env-keyed feature gating in the smoke suite is currently a
multi-place coordination** — see #1640. Today four sites must update
in lockstep when adding a new env that participates in the qurl-
service internal-ALB rollout:

1. `.github/workflows/nhp-smoke-tests.yml` — `||` chain on
   `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED`.
2. `tests/smoke/dns.go::deriveEndpoints` — internal hostname mapping.
3. The env's tfvars — `qurl_internal_service_domain`.
4. `tests/smoke/09_public_alb_internal_lockdown_test.go` —
   `httpListenerOptOutEnvs` map (env that disables the public HTTP
   listener opts out of the HTTP-redirect fence).

#1640 tracks moving all four onto SSM-sourced reads at `TestMain`,
collapsing the coordination to a single Terraform-owned parameter
per gate. Until that lands, adding a new env to the suite is a
four-place edit.

The `scripts/check-smoke-tier-filter-coverage.sh::tier3_no_ssm_expected_omissions`
list is a fifth env-independent maintenance list — it documents
which Test prefixes are SSM-required and so legitimately omitted
from the tier3-no-ssm RUN_FILTER. Update it when a test gains or
loses a hard SSM dependency.

### Deploy-mode tier mapping

NHP runs two deployment regimes side-by-side. The runtime source of
truth is the SSM parameter `/{env}/nhp/deploy/mode` (Terraform-owned,
see `terraform/main.tf::aws_ssm_parameter.deploy_mode`); the table
below is just the current tfvars snapshot — flipping any env's
toggles updates SSM on the next `terraform apply` and smoke adapts
automatically. The TF preconditions on `deploy_mode` reject
half-flips (e.g., `enable_blue_green=true, enable_ac_blue_green=false`)
at plan time so smoke's mode-keyed assertions can't silently
mis-fence.

| Environment | `enable_blue_green` | `enable_canary_deployment` | Mode (today) |
|---|---|---|---|
| sandbox | `true` | `false` | `blue_green` |
| prod | `false` | `true` | `canary` |

The smoke suite reads the SSM key once in `TestMain` and uses it to
route mode-specific tests:

- `skipIfNotBlueGreen(t)` — skip cleanly on canary envs. Used by
  `TestBlueGreen_*` tests that fence active/inactive ASG color flips,
  color-coded TG ARNs, and listener default-action switching.
- `skipIfNotCanary(t)` — skip cleanly on blue/green envs. Used by
  `TestCanary_*` tests that fence the canary state machine's
  post-deploy invariants (state == idle, state-machine ARN exists).

The `requireActive*ASG` helpers are deploy-mode-aware: in blue/green
they resolve to the active-color ASG via SSM; in canary they resolve
to the single ASG name. Tests that just want "the ASG currently
serving traffic" can call these without caring about the mode.

When adding new tests:
- A bug class in blue/green-only state goes in a `TestBlueGreen_*`
  test gated by `skipIfNotBlueGreen`.
- A bug class in canary-only state goes in a `TestCanary_*` test
  gated by `skipIfNotCanary`.
- Mode-agnostic invariants (listener health, deployed-commit SSM,
  AC EIPs are present) skip neither and use `requireActive*ASG`
  to find the serving ASG.

Greenfield envs must explicitly set exactly one of
`enable_blue_green` (with matching `enable_ac_blue_green`) or
`enable_canary_deployment` in tfvars — both default to `false` and
the precondition on `aws_ssm_parameter.deploy_mode` will reject the
first plan otherwise. The same precondition asserts AC and server
blue/green flags agree, so smoke's mode-keyed assertions stay valid.

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

## Metric / Alarm Dim-Set Rules

CloudWatch alarms select their metric stream by **exact** dimension match. A
publisher that emits a partial dim set selects a different (non-existent)
stream and the alarm sits in `INSUFFICIENT_DATA` forever — the operator never
gets paged on a real fault.

The AC publisher's base dim set is `{Component, Environment, Region}` (see
`endpoints/ac/registration.go::NewACRegistration` and `metrics/publisher.go`).
Every alarm in `terraform/modules/ac/monitoring.tf` that keys on the AC
publisher's metrics MUST list those three dims exactly. Metrics emitted from
user_data scripts via the `aws cloudwatch put-metric-data` CLI (e.g.
`CertSyncFailures`) follow their own dim conventions and are out of scope
for this rule.

- **AWS_REGION is required at AC startup.** `NewACRegistration` returns an
  error when `AWS_REGION` is unset (issue #1659). The AWS SDK can't resolve
  the CloudWatch endpoint without a region, and the alarm dim-set guarantee
  above breaks if Region is missing. The live prod startup path is the
  `nhp-acd.service` systemd unit in `terraform/modules/ac/user_data.sh.tpl`
  — `Environment="AWS_REGION=${region}"` must be on that unit, because
  systemd does **not** inherit env from the boot shell. The AC docker image
  (`docker/Dockerfile.ac.aws`) is built and the binary extracted via
  `docker cp` at boot; the supervisord config inside the image never runs
  in prod, so its env wiring is not load-bearing.

- **New AC alarms must mirror the publisher's dim set.** When adding a new
  Region-keyed alarm, audit the metric's emit path and confirm it lands on
  `IncrCounter` / `IncrCounterWithDims` with the publisher base dims. If a
  metric is emitted with extra dims (e.g., `ACId` on failure metrics), the
  alarm must either match all dims exactly, use a SEARCH expression (what
  the registration-event widgets do), or aggregate via `MetricMath` to
  collapse the extra dim into a fleet-wide series.

- **Older AC alarms with the partial-set bug** (`registration_failure`,
  `server_connection_failure`) are tracked in issue #239. Don't add new
  alarms in that style; the `servers_healthy_low` / `registration_stale`
  block is the correct precedent.

## Lock Order (server)

When acquiring multiple mutexes in `endpoints/server/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

- **Peer maps before peers**: `acPeerMapMutex` / `dbPeerMapMutex` /
  `agentPeerMapMutex` are acquired before any `peer.Lock()` (which
  `MatchesIP`, `RecvAddr`, `UpdateRecv`, `LastSendTime`, etc. take
  internally). Do not invert: `isKnownPeerIP` (`udpserver.go`) holds
  the map mutex while iterating peers, and a reverse-order site would
  deadlock against it.
- **`remoteConnectionMapMutex` is leaf-most for the conn lifecycle**:
  no other mutex is acquired while holding it. The connection
  routine's defer takes it briefly to remove the global-map entry.
- **`acConnectionMapMutex` then `remoteConnectionMapMutex`, never
  reversed.** `HandleACOnline`'s stale-conn cleanup acquires
  `acConnectionMapMutex` first to find the stale entry, releases it,
  then acquires `remoteConnectionMapMutex` to remove the global-map
  entry. Holding both at once would invert against the connection
  routine's defer (which removes from `acConnectionMap` first, then
  from `remoteConnectionMap` via `removeConnection`).

## Lock Order (ac)

When acquiring multiple mutexes in `endpoints/ac/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

- **`r.mu` then `device.peerMapMutex`, never reversed.** `r.mu` is
  acquired in `handleRegistrationResponse`'s direct-AAK branch and in
  `Stop()`; both call into `device.RemovePeerByAddress` /
  `device.LookupPeer` (which acquire `peerMapMutex` internally) while
  still holding `r.mu`. `core.Device` methods do not call back into
  `ACRegistration`, so `peerMapMutex` is leaf-most for the AC; a
  future change that takes `r.mu` while holding `peerMapMutex` would
  deadlock against the direct-AAK reconcile path.
- **`reconcileDevicePeers` does not acquire `r.mu` itself.** Callers
  decide. `HandleRedispatch` releases `r.mu` after the
  `assignedServers` swap and calls reconcile lock-free (the orphan
  family it admits is documented + surfaced via
  `MetricReconcileOverlap`). `handleRegistrationResponse`'s
  direct-AAK branch holds `r.mu` across reconcile to close the
  orphan-until-restart hole on that path.

## AC Plugin Source-of-Truth Invariant

The Traefik plugins on AC instances are pulled from
`s3://layerv-nhp-{env}-plugins/traefik/<plugin>/latest/` at boot via
`terraform/modules/ac/user_data.sh.tpl`. Three independent files must
agree on the plugin list, or AC instances cycled by a canary boot
into a degraded state:

1. `terraform/environments/{env}/terraform.tfvars` — `traefik_plugins`
   map. The `version = "latest"` entries here drive what `plugin_key`
   resolves to in `terraform/modules/plugins/main.tf` (it's literal
   string concat: `traefik/${k}/${v.version}/`).
2. `.github/workflows/promote-to-prod.yml` — `TRAEFIK_PLUGIN_SPARSE_PATHS`
   env on the `deploy-traefik-plugins` job. Drives both the
   cross-repo sparse-checkout filter and the upload loop.
3. `layervai/traefik-plugins` — must contain a directory at
   `plugins-local/src/<plugin>/` for every entry in the lists above.

The dangerous direction is **tfvars has plugin X, sparse-paths
doesn't** → AC user_data 404s on boot. The job's preflight catches
this (and missing `version` keys, and non-`"latest"` pins, and
empty plugin directories) — but the structural lint that would
catch it at lint time rather than at deploy time is tracked in
issue #1750. Until that lands, the preflight is the only fence.

The reverse direction (**sparse-paths has plugin Y, tfvars
doesn't**) is **benign**: the workflow uploads to an S3 key AC
never reads, wasting bandwidth but breaking nothing. Don't add a
defensive lint that flags it — that direction has no failure mode.

When the sandbox mirror in #1753 lands, this list grows from
three files to five (sandbox tfvars + `build-and-push.yml`'s
deploy-traefik-plugins-sandbox env). Update this doc in the same
PR so future maintainers don't encode a stale 3-file invariant.

When adding a new Traefik plugin:

1. Land it in `layervai/traefik-plugins` (its own CI ships it to the
   sandbox plugin bucket via `traefik-plugins/.github/workflows/deploy.yml`).
2. Add the entry to **both** sandbox and prod `terraform.tfvars`
   `traefik_plugins` maps with `version = "latest"`.
3. Add `plugins-local/src/<plugin>` to `TRAEFIK_PLUGIN_SPARSE_PATHS`
   in `promote-to-prod.yml`'s `deploy-traefik-plugins` job.
4. Mirror the same change in `build-and-push.yml` once #1753 (sandbox
   mirror) lands.

If you forget step 2 or step 3, the prod promote's preflight fails
loud with a copy-pasteable resolution.

**Plugin renames** require a paired-PR landing across BOTH repos:
the `layervai/traefik-plugins` PR that renames the directory must
land in the same release window as the `nhp` PR that updates
`TRAEFIK_PLUGIN_SPARSE_PATHS` and the `traefik_plugins` tfvars
keys. The tfvars↔sparse-paths preflight catches additions and
removals (drift in either list) but doesn't notice a *rename* if
both lists are updated in lockstep — the failure mode for a
half-landed rename is the directory-existence guard tripping at
upload time, which is correct fail-loud behavior but is downstream
of where you'd want the catch.

## Security Notes

- Never commit secrets - use AWS Secrets Manager
- All storage encrypted with KMS CMKs
- IMDSv2 required on EC2
- AC private keys NEVER in etcd - only Secrets Manager
- `NHP_INTERNAL_AUTH_SECRET` (≥ 32 bytes) signs `/nhp/internal/knock` requests
  between qurl-service and nhp-server. Terraform provisions and seeds the
  value (`aws_secretsmanager_secret.nhp_internal_auth`); the app-layer gate
  defaults to permit mode — flip `NHP_INTERNAL_AUTH_REQUIRE=true` only after
  the permit-mode mismatch counter stays at zero through a full deploy cycle.
  **Entropy comes from upstream provisioning.** The shared module
  (`internalauth.MinSecretLength`) only fences the length floor — a 32-byte
  all-`a` string passes the construction check and is trivially guessable.
  Production secrets MUST be CSPRNG-sourced: Terraform's `random_password`
  resource (with `special = false` + `min_lower/upper/numeric` set) or AWS
  Secrets Manager's `generate_secret_string` are the canonical sources.
  An operator who hand-types or provisions a guessable secret bypasses the
  brute-force fence the floor is supposed to enforce.
  Operational notes:
  - **Plan-role permissions:** the `check` block that asserts the secret is
    populated refreshes `data.aws_secretsmanager_secret_version` on every
    plan, so the caller's role needs `secretsmanager:GetSecretValue` (and
    `kms:Decrypt` on the secrets CMK). The runtime IAM grants already cover
    this on the ECS task + EC2 roles; laptop/CI plans need it on the
    terraform principal. **Security implication:** any principal permitted
    to run `terraform plan` can now read this HMAC secret's cleartext (held
    briefly in plan-time memory; sensitive-marked so it doesn't land in
    state or diff output, but reachable via a custom `output`). Scope the
    plan role to trusted CI runners / operators accordingly.
  - **First plan on a greenfield env** fires a warning from the `check`
    block because the secret doesn't exist yet. Post-apply plans are clean.
    Any CI workflow that fails on terraform warnings should ignore the
    `nhp_internal_auth_secret_populated` check until the first apply lands.
  - **Rotation ≠ dynamic pickup.** nhp-server reads the secret once at
    instance boot in `user_data.sh.tpl`. Rotating the Secrets Manager value
    without an ASG instance refresh will break knock verification on
    existing instances. qurl-service is fine — ECS `valueFrom` re-resolves
    per task start, so a rolling deploy (or stop-task) picks up the new
    value. #1312 tracks a proper current/previous rotation envelope.
