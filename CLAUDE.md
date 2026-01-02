# Claude Code Configuration for NHP

Quick reference for the LayerV NHP (Network Hiding Protocol) infrastructure project.

**For detailed documentation, see:**
- `docs/ARCHITECTURE.md` - Complete system architecture, auth flows, debugging
- `docs/TESTING.md` - Test categories, build tags, running tests
- `docs/server_plugin.md` - Plugin development guide

## Project Structure

```
nhp/                 # Core NHP protocol (Go)
endpoints/           # Services: server, ac, agent, db, kgc
terraform/           # IaC with modules and environments (sandbox, prod)
docker/              # Dockerfile.server, Dockerfile.ac.aws
tests/               # local/, integration/, e2e/
```

**Related Repos:** `console` (UI/API), `website` (layerv.ai), `traefik-plugins` (middleware)

## AWS Profiles

```bash
AWS_PROFILE=layerv          # Sandbox operations
AWS_PROFILE=layerv-mgmt     # Management/Org operations
```

## Commit Convention

```
type(scope): message

# Types: fix, feat, refactor, docs, test, style, build
# Scopes: ac, console-ec2, sandbox, security
```

Examples: `fix(console-ec2): Set maskhost=false`, `feat(ac): Add TLS domains`

## Common Commands

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

### Go
```bash
# Build (static, no CGO)
CGO_ENABLED=0 go build -o bin/nhp-server ./endpoints/server

# Tests (KBS_SKIP_INIT prevents private key dir creation)
KBS_SKIP_INIT=1 go test ./... -v -race

# Local e2e (auto-starts etcd container)
make test-local
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
gh pr create --title "feat: description" --body "..."
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

## Security Notes

- Never commit secrets - use AWS Secrets Manager
- All storage encrypted with KMS CMKs
- IMDSv2 required on EC2
- AC private keys NEVER in etcd - only Secrets Manager
