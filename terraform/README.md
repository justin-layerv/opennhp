# NHP Terraform Infrastructure

This directory contains Terraform configuration for deploying NHP (Network Hiding Protocol) infrastructure to AWS.

## Architecture

```
terraform/
├── main.tf              # Root module - orchestrates all sub-modules
├── variables.tf         # Input variables
├── outputs.tf           # Output values
├── environments/        # Environment-specific configurations
│   ├── sandbox/         # Sandbox environment (primary account)
│   └── prod/            # Production environment
├── modules/             # Reusable Terraform modules
│   ├── ac/              # Access Controller (Traefik + NHP-AC)
│   ├── compute/         # NHP Server compute resources
│   ├── data/            # etcd cluster for multi-tenant config
│   ├── dns/             # Route 53 DNS records
│   ├── ecr/             # ECR repositories + GitHub Actions IAM
│   ├── kms/             # KMS encryption keys
│   ├── monitoring/      # CloudWatch alarms and Slack notifications
│   ├── networking/      # VPC, subnets, security groups
│   └── security/        # CloudTrail audit logging
├── bootstrap/           # Initial account setup
└── scripts/             # Helper scripts
```

## Key Features

### Access Controller (AC) Module

The AC module (`modules/ac/`) deploys:
- EC2 Auto Scaling Group with Traefik + NHP-AC
- Network Load Balancer for TLS termination
- Let's Encrypt certificate automation
- CloudMap service discovery

### Traefik Plugin Persistence

AC instances fetch Traefik plugins from S3 on boot, ensuring plugins persist across ASG instance refreshes:

```
┌─────────────────────────────────────────────────────────────────┐
│  traefik-plugins repo                                            │
│  └── Syncs plugins to S3 bucket on every push                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  S3 Bucket: layerv-nhp-{env}-traefik-plugins                    │
│  └── Contains: plugins-local/src/github.com/traefik/...         │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  AC Instance Boot                                                │
│  1. Fetch plugins from S3                                        │
│  2. Start Traefik with plugins in place                          │
│  3. Register with CloudMap                                       │
└─────────────────────────────────────────────────────────────────┘
```

**Key outputs for traefik-plugins repo:**
- `plugin_bucket_name` - S3 bucket name for plugins
- `plugin_bucket_arn` - S3 bucket ARN for IAM policies

### GitHub Actions Integration

The ECR module creates IAM roles for GitHub Actions CI/CD:
- `nhp-github-actions` role with OIDC authentication
- Permissions for ECR push, Terraform apply, SSM commands
- **Cross-repo access**: Allows `traefik-plugins` repo to sync plugins to S3

## Usage

### Deploy Sandbox

```bash
cd environments/sandbox
terraform init
terraform plan
terraform apply
```

### View Outputs

```bash
# Get plugin bucket name for traefik-plugins repo
terraform output plugin_bucket_name

# Get GitHub Actions role ARN
terraform output github_actions_role_arn
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `environment` | Environment name (sandbox/prod) | - |
| `aws_region` | AWS region | us-east-2 |
| `domain_name` | Domain for NHP server | - |
| `deploy_ac` | Deploy Access Controller | true |
| `traefik_plugins_github_repo` | GitHub repo for plugins | traefik-plugins |

## Related Repositories

| Repository | Purpose |
|------------|---------|
| **layervai/nhp** (this repo) | Infrastructure: VPC, EC2, NLB, Traefik, etcd |
| **layervai/traefik-plugins** | Traefik middleware plugins deployed via SSM |

## Module Documentation

See individual module directories for detailed documentation:
- [AC Module](modules/ac/) - Access Controller with Traefik
- [ECR Module](modules/ecr/) - Container registry and GitHub Actions
- [Monitoring Module](modules/monitoring/) - CloudWatch and Slack alerts
