# Claude Code Configuration for NHP

## Project Overview

This is the LayerV NHP (Network Hiding Protocol) infrastructure project. It includes:
- **Go codebase**: `nhp/` (core protocol) and `endpoints/` (services: server, ac, agent, etc.)
- **Terraform IaC**: `terraform/` with modules and environments (sandbox, prod)
- **Docker containers**: Server and Access Controller images
- **CI/CD**: GitHub Actions with automated testing and deployment

## AWS Profile Conventions

Always use the appropriate AWS profile:
- **Sandbox operations**: `AWS_PROFILE=layerv`
- **Management/Org operations**: `AWS_PROFILE=layerv-mgmt`

```bash
# Terraform commands
AWS_PROFILE=layerv terraform plan
AWS_PROFILE=layerv terraform apply

# AWS CLI commands
AWS_PROFILE=layerv aws ec2 describe-instances
AWS_PROFILE=layerv-mgmt aws organizations list-accounts
```

## Commit Message Convention

Use conventional commits with optional scopes:

```
type(scope): message

# Types (most common first)
fix:      Bug fixes
feat:     New features
refactor: Code restructuring
docs:     Documentation updates
test:     Test additions/changes
style:    Formatting, no logic changes
build:    Build system or dependencies

# Common scopes
ac          Access Controller module
console-ec2 Console EC2 module
sandbox     Sandbox environment
security    Security-related changes
```

Examples:
```
fix(console-ec2): Set maskhost=false to enable redirect_url
feat(ac): Add additional_tls_domains for wildcard cert
refactor: Remove CGO dependency from nhp/core package
docs: Update ARCHITECTURE.md for staticplugins directory
build(deps): bump golang.org/x/crypto in /tests/local
```

## Terraform Workflow

### Directory Structure
```
terraform/
├── environments/
│   ├── sandbox/    # Working directory for sandbox
│   └── prod/       # Working directory for prod
├── modules/        # Reusable modules
│   ├── ac/         # Access Controller
│   ├── compute/    # NHP Server ASG
│   ├── console-ec2/# Console EC2 instance
│   ├── data/       # etcd, EFS, Cloud Map
│   ├── dns/        # Route 53 records
│   ├── kms/        # Encryption keys
│   ├── monitoring/ # CloudWatch dashboards
│   ├── networking/ # VPC, subnets, security groups
│   ├── rds/        # Aurora database
│   └── security/   # WAF, GuardDuty, Config
└── main.tf         # Root module
```

### Commands
```bash
# Always format before committing
terraform fmt -recursive terraform/

# Sandbox operations (from terraform/environments/sandbox/)
AWS_PROFILE=layerv terraform init
AWS_PROFILE=layerv terraform plan
AWS_PROFILE=layerv terraform apply

# Validate changes
AWS_PROFILE=layerv terraform validate
```

### State Management
```bash
# List resources
AWS_PROFILE=layerv terraform state list

# Show specific resource
AWS_PROFILE=layerv terraform state show 'module.ac.aws_instance.example'

# Import existing resource
AWS_PROFILE=layerv terraform import 'module.ac.aws_instance.example' i-1234567890abcdef0
```

## Go Development

### Module Structure
- `nhp/` - Core NHP protocol (Curve25519, UDP handling, config)
- `endpoints/` - Service implementations (server, ac, agent, db, kgc)

### Build Commands
```bash
# Build with static linking (no CGO)
CGO_ENABLED=0 go build -o bin/nhp-server ./endpoints/server

# Run tests with race detector
cd nhp && go test ./... -v -race
cd endpoints && go test ./... -v -race

# Vet for issues
go vet ./...

# Tidy dependencies
go mod tidy
```

### Testing
```bash
# Unit tests
go test ./... -v -race

# Local e2e tests (requires docker compose)
make test-local

# Integration tests (requires AWS credentials)
cd tests/integration && go test -v -tags=integration ./...

# E2E tests
cd tests/e2e && go test -v -tags=e2e ./...
```

## Docker

### Images
- **Server**: `docker/Dockerfile.server` → `layerv/nhp-server`
- **AC (AWS)**: `docker/Dockerfile.ac.aws` → `layerv/nhp-ac`

### Build Commands
```bash
# Build server image
docker buildx build -f docker/Dockerfile.server -t nhp-server .

# Build AC image
docker buildx build -f docker/Dockerfile.ac.aws -t nhp-ac .

# Scan for vulnerabilities
trivy image nhp-server --severity HIGH,CRITICAL
```

## GitHub CLI Patterns

### Workflow Operations
```bash
# List recent workflow runs
gh run list --limit 10

# Watch a running workflow
gh run watch

# View workflow run details
gh run view <run-id>

# Rerun failed workflow
gh run rerun <run-id>
```

### PR Operations
```bash
# Create PR
gh pr create --title "feat: description" --body "..."

# View PR status
gh pr view

# Check PR CI status
gh pr checks
```

## Infrastructure Debugging

### EC2/ASG Operations
```bash
# List instances in ASG
AWS_PROFILE=layerv aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "nhp-sandbox-server" \
  --query 'AutoScalingGroups[0].Instances[*].[InstanceId,LifecycleState]'

# Start instance refresh (rolling deploy)
AWS_PROFILE=layerv aws autoscaling start-instance-refresh \
  --auto-scaling-group-name "nhp-sandbox-server"

# Check refresh status
AWS_PROFILE=layerv aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name "nhp-sandbox-server"
```

### SSM Session
```bash
# Connect to instance
AWS_PROFILE=layerv aws ssm start-session --target i-1234567890abcdef0

# Run command on instance
AWS_PROFILE=layerv aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["docker ps"]'
```

### CloudWatch Logs
```bash
# Tail logs
AWS_PROFILE=layerv aws logs tail /aws/nhp/server --follow

# Search logs
AWS_PROFILE=layerv aws logs filter-log-events \
  --log-group-name /aws/nhp/server \
  --filter-pattern "ERROR"
```

### Route 53
```bash
# List hosted zones
AWS_PROFILE=layerv aws route53 list-hosted-zones

# List records
AWS_PROFILE=layerv aws route53 list-resource-record-sets \
  --hosted-zone-id Z1234567890ABC
```

### ECS (etcd cluster)
```bash
# List clusters
AWS_PROFILE=layerv aws ecs list-clusters

# List services
AWS_PROFILE=layerv aws ecs list-services --cluster nhp-sandbox

# Describe service
AWS_PROFILE=layerv aws ecs describe-services \
  --cluster nhp-sandbox \
  --services etcd
```

## Network Debugging

```bash
# DNS lookup
dig nhp.layerv.xyz
nslookup nhp.layerv.xyz

# Test HTTPS endpoint
curl -svk https://nhp.layerv.xyz/health

# Test with timeout
timeout 15 curl -sk https://endpoint/path

# Check certificate
openssl s_client -connect nhp.layerv.xyz:443 -servername nhp.layerv.xyz
```

## Common Troubleshooting

### Terraform State Issues
```bash
# Refresh state from AWS
AWS_PROFILE=layerv terraform refresh

# Remove resource from state (dangerous!)
AWS_PROFILE=layerv terraform state rm 'module.example.resource'
```

### Docker Issues
```bash
# View container logs
docker logs nhp-server --tail 100

# Exec into container
docker exec -it nhp-server /bin/sh

# Clean up
docker system prune -f
```

### ASG Not Updating
```bash
# Cancel stuck instance refresh
AWS_PROFILE=layerv aws autoscaling cancel-instance-refresh \
  --auto-scaling-group-name "nhp-sandbox-server"

# Force terminate instance
AWS_PROFILE=layerv aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id i-1234567890abcdef0 \
  --should-decrement-desired-capacity
```

## Security Notes

- Never commit secrets or credentials
- Use AWS Secrets Manager for sensitive values
- All EBS/EFS/S3 must be encrypted with KMS CMKs
- IMDSv2 required on all EC2 instances
- Trivy scans run on all container builds
- CodeQL scans run on all code changes

## File Naming Conventions

- Terraform: `main.tf`, `variables.tf`, `outputs.tf`, `<resource>.tf`
- Go: Standard Go conventions, `_test.go` for tests
- Docker: `Dockerfile.<variant>` (e.g., `Dockerfile.server`, `Dockerfile.ac.aws`)
- Scripts: `scripts/<name>.sh`
