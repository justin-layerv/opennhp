# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL RULES - NEVER VIOLATE

> **NEVER push directly to `main` branch.** All changes MUST go through a Pull Request, no exceptions. This applies even for "quick fixes" or "urgent" changes. Create a branch, open a PR, and let CI run.

> **All commits must be GPG/SSH signed.** Unsigned commits will be rejected by GitHub branch protection rules.

## Code Change Workflow

1. `git checkout main && git pull origin main`
2. `git checkout -b <type>/<short-description>`
3. Make changes — consider edge cases, error handling, maintainability; update relevant docs if behavior/APIs/config change.
4. `git push -u origin <branch>` then `gh pr create --title "<type>(scope): description" --body "..."`
5. Wait for CI + review. Address feedback (fix what makes sense, open issues for deferred items). Repeat until clean.

Commit format and full details: see [`docs/COMMIT_CONVENTION.md`](docs/COMMIT_CONVENTION.md).

### Scopes

| Scope | Component |
|-------|-----------|
| `ac` | Access Controller |
| `admin` | Operator/admin tooling (including `endpoints/licenseadmin`) |
| `server` | NHP Server |
| `agent` | NHP Agent |
| `js-agent` | Browser NHP agent (`endpoints/js-agent`) |
| `relay` | NHP-Relay forwarder (`endpoints/relay`) |
| `hub` | qURL Connector Hub |
| `control` | Environment-global Connector Authority infrastructure |
| `db` | Database service |
| `nhp` | Core protocol library |
| `ebpf` | eBPF datapath and committed BPF objects |
| `internalauth` | Shared HMAC canonicalization module (cross-repo) |
| `terraform` | Infrastructure |
| `docker` | Container configuration |
| `ci` | GitHub Actions workflows |

> Keep this table in lockstep with the Component dropdown in
> `.github/ISSUE_TEMPLATE/bug_report.yml`. Drift is enforced at CI by
> `scripts/check-scope-drift.sh` (which parses this exact `### Scopes`
> heading and table; invoked from `make lint-workflows` and
> `.github/workflows/validate-workflows.yml`); add a new scope to both
> places in the same PR.

## Prod Rollout Ledger

Any PR that creates a concrete task that must happen before, during, or after
prod rollout adds a succinct entry file under
[`docs/runbooks/prod-rollout-ledger/`](docs/runbooks/prod-rollout-ledger/)
(one file per entry — see the README there) before merge. **Delete the entry
file once its tasks are done**; the ledger is not a behavior-change log or an
archive. The CI PR-body check enforces the checkbox choice for ready, non-draft
PRs; reviewers enforce whether the selected checkbox is truthful and the entry
covers only required rollout tasks.

---

> **Note:** This is a fork of [OpenNHP](https://github.com/OpenNHP/opennhp). See `docs/UPSTREAM_SYNC.md` for the upstream synchronization process.

## Project Structure

```
nhp/                 # Core NHP protocol library (Go module)
internalauth/        # Shared HMAC canonicalization (Go module — published path:
                     # github.com/layervai/nhp/internalauth, consumed by
                     # nhp-server, qurl-service, qurl-reverse-tunnel-server)
endpoints/           # Services: server, ac, agent, db (Go module)
examples/            # Example plugins (Go module)
terraform/           # IaC with modules and environments (sandbox, prod)
docker/              # Dockerfile.server, Dockerfile.ac.aws
tests/               # local/, integration/, e2e/, smoke/
release/             # Build output (gitignored)
```

**Multi-Module Workspace:** Six Go modules are auto-tidied by `make init`: `nhp/`, `internalauth/`, `endpoints/`, `examples/server_plugin/`, `tests/local/`, and `tests/e2e/`. The first four are wired with `replace` directives pointing to local paths (`internalauth` is also published externally so qurl-service and qurl-reverse-tunnel-server can import the same HMAC canonicalization). Always run `go mod tidy` in these modules when updating dependencies; `make init` does this. Other Go modules (`tests/integration/`, `tests/smoke/`, `docker/web-app/`) have their own lifecycle and aren't auto-tidied — tracked in #1290. `tests/e2e/` is included because root `make test` runs the qURL expiry contract fence from that module, and it remains covered by Go-version drift checks and e2e-tag lint coverage.

**Related Repos:** `console` (UI/API), `website` (layerv.ai), `traefik-plugins` (middleware)

## AWS Profiles

```bash
AWS_PROFILE=layerv          # Sandbox operations
AWS_PROFILE=layerv-prod     # Production operations (used by promote-to-prod + the prod /internal/v1/* triage runbook)
AWS_PROFILE=layerv-mgmt     # Management/Org operations
```

## Common Commands

```bash
# Build / lint / test
make all              # Full build: all binaries, SDKs, plugins, archive
make init             # Clean and go mod tidy all modules
make lint             # Run golangci-lint on nhp/ and endpoints/
make lint-workflows   # Run actionlint + shellcheck on .github/workflows/ (mirrors CI)
make test             # Run unit tests
make test-local       # Run local e2e tests (requires etcd container)
make test-ebpf        # Run eBPF datapath tests in-kernel (Linux + clang + CAP_BPF; run under sudo). See docs/TESTING.md
make fuzz-quick       # Run fuzz tests briefly (FUZZTIME_QUICK, default 15s)
make fuzz             # Run fuzz tests at full budget (FUZZTIME_LONG, default 60s)

# Go (manual, when needed)
KBS_SKIP_INIT=1 go test ./... -v -race                                   # All tests (env var prevents key dir creation)
cd endpoints && KBS_SKIP_INIT=1 go test -v ./server/... -run TestACRegistry  # Single test

# Terraform
terraform fmt -recursive terraform/                                       # Always format before committing
AWS_PROFILE=layerv terraform -chdir=terraform/environments/sandbox plan

# Docker
docker buildx build -f docker/Dockerfile.server -t nhp-server .
docker buildx build -f docker/Dockerfile.ac.aws -t nhp-ac .
trivy image nhp-server --severity HIGH,CRITICAL

# Deployment
./scripts/trigger-prod-deploy.sh              # Interactive — reads state, validates, confirms
./scripts/trigger-prod-deploy.sh --dry-run    # Show what would deploy
./scripts/trigger-prod-deploy.sh --json       # Machine-readable output
```

Both fuzz targets route through `scripts/run-fuzz.sh`, which distinguishes a real crasher (writes `testdata/fuzz/<NAME>/<sha>`) from the upstream Go-fuzz coordinator deadline-race flake (no reproducer file). If `fuzz-quick` ever goes red on a PR that didn't touch Go code, check the wrapper first — and after a Go toolchain bump, re-validate the deadline-race signature it greps for. The wrapper's decision tree is fenced by `tests/lints/run-fuzz/run-fixtures.sh`.

The eBPF datapath workflow commits the native AC XDP object after stripping
DWARF/debug sections while retaining BTF, so the required freshness gate compares
load-relevant bytes and non-loadable metadata drift cannot churn git history or
block branch protection; detailed triage lives in
`docs/runbooks/ebpf-committed-object-freshness.md`.
Current canonical eBPF toolchain pins (guarded by `scripts/check-ebpf-toolchain-pin-lockstep.sh`): EBPF_APT_SNAPSHOT=20260628T000000Z, EBPF_CLANG_PACKAGE=clang-18=1:18.1.3-1ubuntu1, EBPF_LLVM_PACKAGE=llvm-18=1:18.1.3-1ubuntu1, EBPF_LIBBPF_DEV_PACKAGE=libbpf-dev=1:1.3.0-2build2.

The blue/green stale-target-group preflight in `.github/scripts/prune-missing-asg-target-groups.sh` uses an AWS CLI JMESPath query with JSON string literals for tab/newline output and classifies retryable AWS CLI failures from stderr text. Its shell fixtures cover the parsed `count<TAB>ARNs` layout and representative error strings, but not the real AWS CLI evaluator/output formatter; after an AWS CLI or jmespath major bump, re-run the script in `DRY_RUN=true` against a real standby ASG before trusting that path.

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

`terraform-plan-pr.yml` is the narrow PR-time exception for sandbox
planning. Its OIDC trust uses the `pull_request` subject, so same-repo
PR authors are inside the trust boundary; fork PRs are rejected before
secrets or AWS credentials are used. AWS IAM cannot scope this trust to
`workflow_ref`, so the file-level controls are workflow-side, not IAM-side.
Keep that workflow sandbox-only and non-mutating, but remember the role can
read sandbox tfstate, NHP-scoped SSM SecureStrings, Secrets Manager values, and
KMS-decrypted material from the Terraform state alias and NHP KMS aliases. S3
object reads are scoped to Terraform state plus NHP-managed/plugin bucket
patterns, while S3 metadata/list and IAM reads remain broad for Terraform
refresh. It uses a dedicated plan-read policy, not the normal CI
`terraform_read` policy.
Avoid passing live app-level secrets unless a provider actually needs them for
plan accuracy. Before exposing the long-lived Auth0 client secret, the workflow
restores its local helper action/script paths and the Auth0 token-fetch tfvars
from the trusted base commit, but `terraform plan` still executes PR-head
HCL/tfvars with the short-lived Auth0 token and sandbox read role. Security
sign-off must explicitly accept plan-time exfil paths such as `data.http`, the
`external` provider, and provider endpoint overrides. The Auth0 Terraform
client grant must be explicitly accepted before the check is made required,
especially if the grant can mutate Auth0. Prod-only Terraform PRs should remain
an informational skip in this workflow instead of gating unrelated prod changes
on sandbox state.

```bash
# Force a sandbox build/deploy after a path-only merge (e.g.,
# .trivyignore-only PRs that didn't trigger the workflow on push):
gh workflow run build-and-push.yml --ref main \
  -f environment=sandbox -f force_build=true -f deploy=true
```

### Sandbox app-image drift gate

`build-and-push.yml` intentionally treats live sandbox app-image drift as a
deploy blocker. On every workflow-triggering `main` push and sandbox deploy
dispatch, `sandbox-app-image-drift` reads the configured server, AC, and relay
image tags from SSM and compares their app trees to the workflow SHA. While
drift is unhealed, even infra-only or CI-only pushes build, scan, and roll fresh
app images; a broken app tree therefore blocks sandbox deploys until the app fix
lands or the breakage is reverted. This is deliberate: do not bypass the gate or
manually advance `/sandbox/nhp/deploy/deployed-commit` while live tags cannot
prove the target SHA. `force_build=true` only asks the workflow to build the
target tree; it is not an escape hatch for a broken app tree.

The SSM reads are strict by design. A transient AWS/SSM failure in either the
pre-build drift job or the post-switch `Update Deployment Tracking` gate should
fail the run red and be rerun after AWS recovers, not guessed clean. If the
post-switch gate fails after a healthy rollout, leave `deployed-commit` stale so
the next deploy (main push or sandbox dispatch) re-proves the live configured
tags before recording the SHA.

If an active image tag points at a commit GitHub can no longer fetch, the drift
gate also fails closed into a forced app build/roll until the live tags converge
and deployment tracking can be stamped honestly again.

Only pushes matching `build-and-push.yml`'s `on.push.paths` start this gate, so
a docs-only `main` push does not heal pre-existing drift by itself. An explicit
sandbox `workflow_dispatch` runs the same drift gate and can heal drift by
building/rolling the target tree when the app is healthy. On-call triage lives
in `docs/runbooks/sandbox-app-image-drift.md`.

Keep the GitHub `sandbox` environment free of required reviewers/protection
rules while `sandbox-app-image-drift` is on the main-push path, or revisit this
workflow first; otherwise every `main` push can pause for manual approval before
the drift gate runs.

## Key Ports

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 443 | UDP | Public cell/Hub NLB | Client-facing knock edge (what SDKs dial) |
| 62206 | UDP | NHP Server | Knock packets the NLB forwards to (private bind) |
| 8888 | TCP | NHP Server | HTTP plugin endpoints |
| 443 | TCP | AC Traefik | HTTPS (TLS termination) |

## Quick Debugging

```bash
# Find instances
AWS_PROFILE=layerv aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*sandbox*" "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0]]' --output table

# SSM session
AWS_PROFILE=layerv aws ssm start-session --target i-XXXXX

# AC logs (native binary)
tail -100 /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log

# Server logs (inside Docker — NOT docker logs!)
docker exec nhp-server cat /nhp-server/logs/server-$(date +%Y-%m-%d).log | tail -100

# Instance refresh
AWS_PROFILE=layerv aws autoscaling start-instance-refresh  --auto-scaling-group-name "nhp-sandbox-server"
AWS_PROFILE=layerv aws autoscaling cancel-instance-refresh --auto-scaling-group-name "nhp-sandbox-server"
```

For triaging `/internal/v1/*` on qurl-service: [`docs/runbooks/qurl-internal-v1-triage.md`](docs/runbooks/qurl-internal-v1-triage.md).
For creating a QURL via the API: [`docs/runbooks/create-qurl.md`](docs/runbooks/create-qurl.md).

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

## Where to look for deeper context

This file stays light. Subtree-scoped rules live in nested `CLAUDE.md` files (auto-loaded when Claude works in that subtree); other detailed context lives under `docs/`.

| Topic | Source of truth |
|---|---|
| Architecture, auth flows, debugging | `docs/ARCHITECTURE.md` |
| Test categories, build tags, running tests | `docs/TESTING.md` |
| Plugin development | `docs/server_plugin.md` |
| Upstream sync process | `docs/UPSTREAM_SYNC.md` |
| Session enforcement (server-side authz) | `docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md` |
| NHP-Relay topology + re-knock authz (HTTPS DMZ plus direct assigned-cell UDP, #2208) | `docs/design/NHP_RELAY_TOPOLOGY.md` |
| Relay DMZ boundary (plan contract, live deployed-state detector, and replacement sequence) | `.github/scripts/check-relay-dmz-plan.py`; `scripts/check-relay-dmz-live.py`; `docs/runbooks/sandbox-relay-dmz-replacement.md` |
| Relay active-cell routing decision (server blue/green switch point, #2658) | `docs/design/RELAY_ACTIVE_CELL_ROUTING.md` |
| qURL agent-key DDB schema contract | `docs/design/QURL_AGENT_KEYS_SCHEMA.md` |
| qURL v2 keyed identity + admission contract (signed claims, NHP Server Contract) | `docs/design/QURL_V2_KEYED_IDENTITY.md` |
| Agent lifecycle / `Stop()`/`RestartAgent()` teardown invariants (#3084) | `docs/design/AGENT_LIFECYCLE_TEARDOWN.md` |
| Auth0 is dashboard-owned, not Terraform-managed (#3284) | `docs/design/AUTH0_IDENTITY_POLICY.md` |
| Commit convention + scopes table | `docs/COMMIT_CONVENTION.md` |
| Runbooks index | `docs/runbooks/README.md` |
| Security monitoring + secrets / `NHP_INTERNAL_AUTH_SECRET` / KMS exception | `docs/SECURITY.md` |
| Access-token touch inventory (log/persist/transport sites + replay-window decision) | `docs/SECURITY_TOKEN_TOUCH_INVENTORY.md` |
| GuardDuty finding triage (alert routing + stale-finding watchdog) | `docs/runbooks/guardduty-finding-triage.md` |
| Prod Rollout Ledger | `docs/runbooks/prod-rollout-ledger/README.md` |
| qurl-service `/internal/v1/*` triage | `docs/runbooks/qurl-internal-v1-triage.md` |
| Create a QURL via API | `docs/runbooks/create-qurl.md` |
| Renew a LayerV-owned domain (+ Domain Expiry Watchdog) | `docs/runbooks/domain-renewal.md` |
| L3 flush scheduler breaker open — recovery | `docs/runbooks/l3-flush-breaker-recovery.md` |
| L3 flush scheduler ScheduleWaitTimeout firing | `docs/runbooks/l3-flush-schedule-wait-timeout.md` |
| L3 flush quiet-stream residual + backend-keepalive recipe | `docs/design/QUIET_STREAM_RESIDUAL.md` |
| Lock order in `endpoints/server/` | `endpoints/server/CLAUDE.md` |
| Lock order in `endpoints/ac/` | `endpoints/ac/CLAUDE.md` |
| Smoke test suite (tiers, deploy-mode mapping, maintenance rules) | `tests/smoke/CLAUDE.md` |
| Terraform: state drift, ASG co-ownership, IAM shim, AC plugin invariant, alarm dim-set rules | `terraform/CLAUDE.md` |

Touching `.github/workflows/promote-to-prod.yml` or `build-and-push.yml`?
The Traefik plugin source-of-truth invariant lives in `terraform/CLAUDE.md` —
both repos and both tfvars must agree on the plugin list.
