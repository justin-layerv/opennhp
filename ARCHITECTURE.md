# NHP Infrastructure Architecture

This document describes the infrastructure architecture for the LayerV NHP (Network Hiding Protocol) system, including how components work together and the separation of concerns between repositories.

## Overview

The NHP system provides network-level security through the "hiding" of services behind cryptographic authentication. The infrastructure consists of three main components with comprehensive security controls.

```
                                    ┌─────────────┐
                                    │  Internet   │
                                    └──────┬──────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         │                                 │                                 │
         │                    ┌────────────┴────────────┐                    │
         │                    │   CloudFront + WAF      │                    │
         │                    │   (prod only)           │                    │
         │                    │   • Rate limiting       │                    │
         │                    │   • Common rules        │                    │
         │                    │   • IP reputation       │                    │
         │                    └────────────┬────────────┘                    │
         │                                 │                                 │
         ▼                                 ▼                                 ▼
  ┌───────────────┐           ┌───────────────┐              ┌─────────────────┐
  │  NLB (UDP)    │           │  NLB (TCP)    │              │  Direct Access  │
  │  Port 62206   │           │  Port 443     │              │  (Public IPs)   │
  └───────┬───────┘           └───────┬───────┘              └────────┬────────┘
          │                           │                               │
          │ knock                     │ *.apps proxy                  │ post-knock
          ▼                           └──────────┬────────────────────┘
  ┌───────────────────┐                          │
  │    NHP Server     │                          ▼
  │    (ASG/EC2)      │              ┌───────────────────┐
  │    Private        │◄────────────▶│ Access Controller │
  │                   │  NHP protocol│    (ASG/EC2)      │
  │ • Curve25519      │  (discovery  │    Public         │
  │ • UDP 62206       │   + control) │                   │
  │ • Validates knocks│              │ • Traefik :443    │
  └──┬──────────┬─────┘              │ • Portal :8888    │
     │          │                    │ • nhp-acd :62206  │
     │          │ config             └──┬───────────┬────┘
     │          │                       │           │
     │          └───────────┬───────────┘           │
     │                      │                       │
     │ register             ▼                       │ register
     │      ┌───────────────────────────────┐      │
     │      │        etcd Cluster           │      │
     │      │       (ECS Fargate)           │      │
     │      │                               │      │
     │      │ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
     │      │ │ etcd-0  │ │ etcd-1  │ │ etcd-2  │  │  (3-node in prod)
     │      │ └─────────┘ └─────────┘ └─────────┘  │
     │      │                               │      │
     │      │ • Tenant config               │      │
     │      │ • User/policy data            │      │
     │      │ • AC ↔ Server coordination    │      │
     │      │ • EFS-backed persistence      │      │
     │      └──────────────┬────────────────┘      │
     │                     │                       │
     │                     │ ECS auto-registers    │
     │                     │                       │
     ▼                     ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Cloud Map + Route 53                                 │
│                                                                              │
│  Private DNS Namespace: nhp.{env}.internal                                   │
│                                                                              │
│  ┌────────────────────┐ ┌────────────────────┐ ┌─────────────────────────┐  │
│  │ server.nhp.{env}   │ │ ac.nhp.{env}       │ │ etcd-{0,1,2}.nhp.{env}  │  │
│  │ .internal          │ │ .internal          │ │ .internal               │  │
│  │                    │ │                    │ │                         │  │
│  │ ← user_data        │ │ ← user_data        │ │ ← ECS service discovery │  │
│  │   registers        │ │   registers        │ │                         │  │
│  └────────────────────┘ └────────────────────┘ └─────────────────────────┘  │
│                                                                              │
│  Route 53 Private Hosted Zone: A records auto-managed, TTL 30s               │
└──────────────────────────────────────────────────────────────────────────────┘

Security Layer:
┌──────────────────────────────────────────────────────────────────────────────┐
│                         AWS Security Services                                 │
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ GuardDuty   │  │ Security    │  │ AWS Config  │  │ CloudTrail          │ │
│  │             │  │ Hub         │  │             │  │                     │ │
│  │ Threat      │  │ Centralized │  │ Compliance  │  │ API audit logging   │ │
│  │ detection   │  │ findings    │  │ monitoring  │  │ S3 + CloudWatch     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘

Traffic Flows:
  1. Client → CloudFront (WAF) → NLB (TCP) → AC Traefik: HTTPS proxy for *.apps
  2. Client → NLB (UDP) → NHP Server: Cryptographic knock
  3. NHP Server validates knock, signals AC via protocol
  4. AC discovers NHP Servers via Cloud Map (server.nhp.{env}.internal)
  5. Client → AC (direct public IP): Post-knock access to protected resources
```

## Components

### 1. NHP Server (ASG/EC2)

**Purpose**: Handles the core NHP protocol - cryptographic "knocking" that allows clients to authenticate and get firewall rules opened.

**Deployment**:
- Auto Scaling Group with EC2 instances in private subnets
- Network Load Balancer (UDP) in public subnets on port 62206
- Docker container running the `nhp-server` binary
- EBS volumes encrypted with KMS customer-managed keys

**Key Features**:
- Curve25519 key pairs for cryptographic authentication
- UDP-based protocol for minimal latency
- Multi-tenant configuration via etcd
- Registers with Cloud Map for service discovery

**Configuration**:
- `/etc/nhp/config.toml` - Main server config (keys, ports)
- `/etc/nhp/remote.toml` - etcd connection for multi-tenant config

**Security**:
- Private keys stored in Secrets Manager with KMS encryption
- CloudWatch Logs encrypted with KMS
- IMDSv2 required (hop limit 1)
- Detailed monitoring enabled

### 2. Access Controller (AC) - EC2 ASG

**Purpose**: Multi-service platform that provides:
- HTTPS web proxy for applications (Traefik)
- User portal UI/API
- NHP connector for knock-based access control

**Deployment**:
- Auto Scaling Group with EC2 instances in **public subnets**
- Network Load Balancer (TCP 443) for web proxy traffic (`*.apps.layerv.xyz`)
- Optional CloudFront distribution with WAF for DDoS protection (recommended for production)
- Direct public IP access for NHP protocol

**Services on AC Instance**:
```
┌─────────────────────────────────────────────────────────────┐
│                      AC Instance                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐ │
│  │  Traefik    │  │   Portal    │  │  ConnectorClient     │ │
│  │  :443/:80   │  │   :8888     │  │  :4732, UDP :62206   │ │
│  │  (public)   │  │  (public)   │  │  (public)            │ │
│  │             │  │             │  │         │            │ │
│  │ HTTPS proxy │  │ User UI/API │  │         ▼            │ │
│  │ *.apps      │  │             │  │  ┌─────────────┐     │ │
│  └─────────────┘  └─────────────┘  │  │  nhp-acd    │     │ │
│                                    │  │  :62206     │     │ │
│                                    │  │ (localhost) │     │ │
│                                    │  └─────────────┘     │ │
│                                    └──────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

| Service | Port | Interface | Purpose |
|---------|------|-----------|---------|
| `traefik` | 443/tcp, 80/tcp | public | HTTPS reverse proxy for `*.apps` |
| `portal` | 8888/tcp | public | User portal UI and API (Zero Trust auth entry point) |
| `connectorclient` | 4732/tcp, 62206/udp | public | NHP connector (protocol-secured) |
| `nhp-acd` | 62206/tcp | **localhost only** | Internal AC daemon |

**Security Note**: Ports 8888, 4732, and 62206 are intentionally open to 0.0.0.0/0. This is by design for the Zero Trust architecture - security is enforced at the application layer via the NHP protocol, not network restrictions.

**Traffic Flows**:
1. **Web proxy** (`*.apps.layerv.xyz`): CloudFront → NLB → Traefik → backend apps
2. **Portal access**: Direct to `:8888` → Portal service
3. **NHP knock**: UDP `:62206` → ConnectorClient → nhp-acd (localhost)
4. **Post-knock access**: Direct to public IP after authentication

**Key Features**:
- **Traefik**: TLS termination with Let's Encrypt (DNS-01 via Route53)
- **CloudFront + WAF**: Optional DDoS protection with AWS Managed Rules
- **Public IPs**: Each AC instance has a public IP
- **Cloud Map**: Registration with public IP for discovery and health checks
- **NHP hiding**: nhp-acd on localhost only - not directly exposed

### 3. etcd Cluster (ECS Fargate)

**Purpose**: Stores multi-tenant configuration including user authentication, portal mappings, and policy rules.

**Deployment**:
- **Staging**: 1 Fargate task
- **Production**: 3-node cluster for high availability
- EFS volumes with per-member access points for data isolation
- Cloud Map registration for DNS-based discovery
- Automatic EFS backup enabled

**Security**:
- EFS encrypted with KMS customer-managed keys
- Credentials stored in Secrets Manager with automatic rotation (30-day cycle)
- TLS infrastructure prepared (requires cfssl for proper X509 certificate generation)
- Security group restricts peer communication to cluster members only

**Key Path Structure**:
```
/nhp/
├── config               # Global NHP configuration
├── tenants/
│   ├── tenant-1/
│   │   ├── users/       # User authentication data
│   │   ├── portals/     # Portal configurations
│   │   └── policies/    # Access policies
│   └── tenant-2/
│       └── ...
```

### 4. CloudFront + WAF (Production)

**Purpose**: Edge protection for the AC module with DDoS mitigation and web application firewall.

**Deployment** (when `enable_cloudfront = true`):
- CloudFront distribution in front of AC NLB
- ACM certificate in us-east-1 for CloudFront
- WAF Web ACL with CLOUDFRONT scope

**WAF Rules**:
| Rule | Priority | Action |
|------|----------|--------|
| Rate Limiting | 1 | Block (5000 req/5min prod, 2000 sandbox) |
| AWS Common Rule Set | 2 | Block malicious requests |
| Known Bad Inputs | 3 | Block known attack patterns |
| IP Reputation List | 4 | Block known malicious IPs |

## Security Architecture

### Encryption

| Resource | Encryption | Key Management |
|----------|------------|----------------|
| EBS Volumes | AES-256 | KMS CMK (ebs-key) |
| EFS | AES-256 | KMS CMK (efs-key) |
| Secrets Manager | AES-256 | KMS CMK (secrets-key) |
| CloudWatch Logs | AES-256 | KMS CMK (logs-key) |
| CloudTrail Logs | AES-256 | KMS CMK (logs-key) |
| S3 Buckets | AES-256 | KMS CMK |

### Security Services

| Service | Purpose | Configuration |
|---------|---------|---------------|
| GuardDuty | Threat detection | S3 logs, malware protection enabled |
| Security Hub | Centralized findings | AWS Foundational Best Practices, CIS (prod) |
| AWS Config | Compliance monitoring | EBS encryption, S3 encryption, MFA, VPC flow logs |
| CloudTrail | API audit logging | Multi-region, log file validation, S3 + CloudWatch |
| WAF | Web application firewall | CloudFront scope (prod), rate limiting |

### IAM Security

**Permission Boundaries**: All IAM roles should have the `{name_prefix}-permission-boundary` policy attached to prevent privilege escalation.

**Denied Actions** (enforced by permission boundary):
- Creating IAM users, roles, or policies
- Attaching policies to users/roles
- Deleting permission boundaries
- Accessing Organizations or Account management
- Deactivating MFA or deleting access keys

**GitHub Actions OIDC**: Restricted to `main` branch only for ECR push and Terraform state access.

### Network Security

**Network ACLs** (stateless firewall rules):

| Subnet Type | Inbound | Outbound |
|-------------|---------|----------|
| Public | HTTPS, HTTP, NHP ports, ephemeral, VPC | All |
| Private | VPC, ephemeral | VPC, HTTPS, HTTP, ephemeral |
| Isolated | VPC only | VPC only |

**VPC Endpoints Security Group**:
- Ingress: HTTPS from VPC CIDR only
- Egress: HTTPS to VPC CIDR only (restricted from 0.0.0.0/0)

## Repository Responsibilities

### This Repository (layervai/nhp)

This repository is responsible for:

1. **Core NHP Protocol Implementation**
   - `nhp/` - NHP protocol code (Go)
   - `endpoints/` - Service endpoints

2. **Container Images**
   - `docker/Dockerfile.server` - NHP Server image
   - `docker/Dockerfile.ac.aws` - AC image with embedded Traefik

3. **Infrastructure Deployment** (Terraform)
   - `terraform/modules/networking/` - VPC, subnets, security groups, NACLs
   - `terraform/modules/ecr/` - Container registries, GitHub OIDC
   - `terraform/modules/compute/` - NHP Server ASG, NLB
   - `terraform/modules/ac/` - Access Controller ASG, NLB, TLS, CloudFront + WAF
   - `terraform/modules/data/` - etcd cluster, EFS, Cloud Map, secrets rotation
   - `terraform/modules/dns/` - Route 53 records
   - `terraform/modules/monitoring/` - CloudWatch dashboards, alarms, Slack notifications
   - `terraform/modules/kms/` - Customer-managed encryption keys
   - `terraform/modules/security/` - WAF, GuardDuty, Security Hub, Config, CloudTrail

4. **CI/CD Pipeline**
   - `.github/workflows/build-and-push.yml` - Build, push, deploy

### Related Repository (layervai/traefik-plugins)

The `traefik-plugins` repository is responsible for:

1. **Traefik Middleware Plugins**
   - NHP authentication middleware
   - Custom routing plugins
   - Rate limiting / security plugins

2. **Plugin Deployment**
   - Builds and packages Traefik plugins
   - Deploys plugins TO existing AC instances via SSM
   - Does NOT deploy Traefik itself (Traefik is embedded in AC)

**Important**: The traefik-plugins repo updates the AC's Traefik configuration with new plugins. It assumes the AC infrastructure already exists.

## Deployment Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Developer pushes to main branch                                            │
│  (Only main branch has deployment permissions via OIDC)                     │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  GitHub Actions: build-and-push.yml                                         │
│                                                                             │
│  1. Run tests (nhp/*, endpoints/*)                                          │
│  2. Build Docker images:                                                    │
│     - layerv/nhp-server (Dockerfile.server)                                 │
│     - layerv/nhp-ac (Dockerfile.ac.aws)                                     │
│  3. Push to ECR (sandbox account)                                           │
│  4. Terraform plan/apply (sandbox)                                          │
│  5. Trigger NHP Server ASG instance refresh                                 │
│  6. Trigger AC ASG instance refresh                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Network Architecture

### Security Groups

| Component | Inbound | Outbound | Notes |
|-----------|---------|----------|-------|
| NHP Server | UDP 62206 (public), TCP 22 (VPC - health check) | All | Private subnets |
| AC | TCP 443/80 (public), TCP 8888 (public), TCP 4732 (public), UDP 62206 (public), TCP 22 (VPC) | All | Public subnets, WAF protected via CloudFront |
| etcd | TCP 2379 (VPC), TCP 2380 (self) | TCP 2380 (VPC), TCP 2049 (EFS), TCP 443 (AWS APIs) | Private subnets |
| EFS | TCP 2049 (VPC) | All | Mount targets in private subnets |
| VPC Endpoints | TCP 443 (VPC) | TCP 443 (VPC) | Restricted egress |

### DNS

| Record | Target | Purpose |
|--------|--------|---------|
| `nhp.layerv.xyz` | CloudFront / AC NLB | HTTPS API endpoint |
| `*.nhp.layerv.xyz` | CloudFront / AC NLB | Tenant subdomains |
| (internal) `server.nhp.{env}.internal` | NHP Servers | Cloud Map discovery |
| (internal) `ac.nhp.{env}.internal` | AC | Cloud Map discovery |
| (internal) `etcd-{0,1,2}.nhp.{env}.internal` | etcd members | Peer discovery |
| (internal) `etcd.nhp.{env}.internal` | etcd cluster | Client connections |

## Multi-Account Setup

| Account | Environment | Role | ECR Access |
|---------|-------------|------|------------|
| layerv (767397897469) | Sandbox | Primary - owns ECR repositories | Push + Pull |
| layerv-prod (TBD) | Production | Secondary - pulls from sandbox ECR | Pull only |

**Cross-Account ECR Access**:
- Configured via `secondary_account_ids` variable in sandbox
- Uses explicit account principals (not `Principal: "*"`)
- Only allows `GetDownloadUrlForLayer`, `BatchGetImage`, `BatchCheckLayerAvailability`

## Environment Variables

### NHP Server
- `SECRET_ARN` - Secrets Manager ARN for Curve25519 private key
- `MULTI_TENANT` - Enable etcd configuration
- `ETCD_ENDPOINT` - etcd connection string

### Access Controller
- `NHP_ENVIRONMENT` - Environment name (sandbox/prod)
- `NHP_DOMAIN` - Domain for TLS certificate
- `ACME_EMAIL` - Let's Encrypt registration email
- `ACME_CA_SERVER` - Let's Encrypt server URL
- `AWS_REGION` - AWS region for Route53
- `ETCD_ENDPOINT` - etcd connection string
- `NHP_SERVER_DISCOVERY` - Cloud Map DNS for server discovery

## Monitoring

### CloudWatch Dashboards
- NHP Server metrics (connections, latency, errors)
- AC metrics (TLS handshakes, API requests)
- etcd metrics (key operations, cluster health)

### Alarms
- High CPU utilization (>80%)
- Unhealthy target count
- Error rate thresholds (>1% 5xx errors)
- etcd cluster health

### Slack Notifications
- AWS Chatbot integration via SNS
- Alerts sent to configured Slack channel
- Workspace ID and Channel ID configured in tfvars

## Disaster Recovery

### Data Persistence
- **etcd**: EFS volume with automatic backups enabled
- **Certificates**: EFS volume in AC for ACME certificates
- **Secrets**: AWS Secrets Manager with 30-day recovery window (prod)
- **Audit Logs**: CloudTrail to S3 with Glacier transition after 90 days

### Recovery Procedures
1. etcd failure: ECS will restart task, EFS data persists
2. AC failure: ASG replaces instance, certificates persist on EFS
3. NHP Server failure: ASG replaces instance, re-registers with Cloud Map
4. etcd cluster quorum loss (prod): 2 of 3 nodes must be healthy

### Secrets Rotation
- etcd credentials: 30-day automatic rotation (production)
- Lambda function updates etcd password and verifies connectivity
- Applications should handle credential refresh gracefully

## Local Development

For local development, use the standard `docker-compose.yaml` which doesn't include AWS-specific features like Route53 DNS-01. The local setup uses:
- `docker/Dockerfile.ac` (without embedded Traefik)
- Local Traefik config mounted as volumes
- Self-signed certificates

## Configuration Variables

### Key Terraform Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `enable_cloudfront` | Enable CloudFront + WAF for AC | `false` (set `true` for prod) |
| `secondary_account_ids` | Account IDs for ECR cross-account access | `[]` |
| `enable_slack_notifications` | Enable Slack alerts via AWS Chatbot | `false` |
| `multi_tenant` | Enable etcd for multi-tenant config | `true` |

### Environment-Specific Settings

| Setting | Staging | Production |
|---------|---------|------------|
| etcd cluster size | 1 | 3 |
| NAT Gateways | 1 | 3 (per AZ) |
| AC min capacity | 1 | 2 |
| CloudFront + WAF | Disabled | Enabled |
| Secrets recovery window | 0 days | 30 days |
| Log retention | 30 days | 365 days |
| WAF rate limit | 2000 req/5min | 5000 req/5min |
