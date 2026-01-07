# Claude Code Configuration for NHP

## CRITICAL RULES - NEVER VIOLATE

> **NEVER push directly to `main` branch.** All changes MUST go through a Pull Request, no exceptions. This applies even for "quick fixes" or "urgent" changes. Create a branch, open a PR, and let CI run.

Quick reference for the LayerV NHP (Network Hiding Protocol) infrastructure project.

> **Note:** This is a fork of [OpenNHP](https://github.com/OpenNHP/opennhp). Periodically sync upstream changes via `git fetch upstream && git merge upstream/main`.

**For detailed documentation, see:**
- `docs/ARCHITECTURE.md` - Complete system architecture, auth flows, debugging
- `docs/TESTING.md` - Test categories, build tags, running tests
- `docs/server_plugin.md` - Plugin development guide

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

### GPG Signing Requirement

**All commits must be GPG signed.** Configure git to sign automatically:

```bash
git config commit.gpgsign true
git config user.signingkey YOUR_KEY_ID
```

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
make test             # Run unit tests
make test-local       # Run local e2e tests (requires etcd container)
make fuzz-quick       # Run fuzz tests (10s each, for CI)
make fuzz             # Run fuzz tests (60s each)
```

### Go (Manual)

```bash
# Run go mod tidy on all modules
cd nhp && go mod tidy && cd ../endpoints && go mod tidy && cd ../examples/server_plugin && go mod tidy

# Tests (KBS_SKIP_INIT prevents private key dir creation)
KBS_SKIP_INIT=1 go test ./... -v -race

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
| Push rejected "unsigned" | Missing GPG signature | Configure `git config commit.gpgsign true` |

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

## Security Notes

- Never commit secrets - use AWS Secrets Manager
- All storage encrypted with KMS CMKs
- IMDSv2 required on EC2
- AC private keys NEVER in etcd - only Secrets Manager
- All commits must be GPG signed
