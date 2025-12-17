# LayerV NHP Server - AWS Infrastructure

This directory contains AWS CDK infrastructure for the LayerV NHP Server control plane.

> **Note**: AC deployment infrastructure has moved to the [traefik-plugins](https://github.com/layerv/traefik-plugins) repository.

## Directory Structure

```
aws/
├── cdk/                    # AWS CDK infrastructure
│   ├── lib/
│   │   ├── compute-stack.ts    # NHP Server ASG, NLB, Cloud Map
│   │   ├── data-stack.ts       # etcd, Secrets Manager
│   │   ├── network-stack.ts    # VPC, subnets, security groups
│   │   ├── ecr-stack.ts        # ECR repositories
│   │   ├── dns-stack.ts        # Route 53
│   │   └── monitoring-stack.ts # CloudWatch (optional)
│   ├── bin/app.ts              # CDK app entry point
│   └── package.json
├── docker/
│   └── Dockerfile.server       # NHP Server container image
└── README.md
```

## Prerequisites

1. Node.js 18+ and npm
2. AWS CLI configured with appropriate credentials
3. AWS CDK CLI: `npm install -g aws-cdk`

## Quick Start

```bash
cd cdk
npm install
npx cdk bootstrap  # First time only

# Deploy all stacks
npx cdk deploy --all -c environment=dev

# Deploy specific stack
npx cdk deploy LayerV-NHP-Compute-dev -c environment=dev
```

## Stacks

### EcrStack
ECR repositories for container images:
- `layerv/nhp-server` - NHP Server image
- `layerv/nhp-ac` - AC image (pulled by customers)

### NetworkStack
VPC infrastructure:
- Multi-AZ VPC (10.100.0.0/16)
- Public, private, and isolated subnets
- NAT Gateways for outbound access

### DataStack
Data layer:
- etcd cluster for multi-tenant configuration
- Secrets Manager for keys
- EFS for persistent storage

### ComputeStack
NHP Server compute:
- Auto Scaling Group with Launch Template
- Network Load Balancer (UDP 62206)
- Cloud Map service discovery
- Route 53 DNS integration

### DnsStack
DNS configuration:
- Route 53 hosted zone
- NLB alias records

## Architecture

```
                    Internet
                        │
                        ▼
              ┌─────────────────┐
              │  Network Load   │
              │   Balancer      │
              │  (UDP 62206)    │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │   NHP   │   │   NHP   │   │   NHP   │
   │ Server  │   │ Server  │   │ Server  │
   │  (AZ-a) │   │  (AZ-b) │   │  (AZ-c) │
   └────┬────┘   └────┬────┘   └────┬────┘
        │             │             │
        └─────────────┼─────────────┘
                      │
              ┌───────┴───────┐
              │   Cloud Map   │
              │   (Route 53)  │
              └───────────────┘
```

## Health Monitoring

Health monitoring is NHP-compliant (no exposed HTTP ports):
- Cloud Map with custom health checks
- Instances self-register on boot
- Health status reported via AWS API
- Route 53 DNS updated automatically

## Configuration

Environment-specific configuration via CDK context:

```bash
# Development
npx cdk deploy --all -c environment=dev

# Production
npx cdk deploy --all -c environment=prod
```

## Docker Image

Build and push the server image:

```bash
# Build locally
docker build -f docker/Dockerfile.server -t layerv/nhp-server .

# Push to ECR (after CDK deploy)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker tag layerv/nhp-server:latest <account>.dkr.ecr.us-east-1.amazonaws.com/layerv/nhp-server:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/layerv/nhp-server:latest
```

## Support

- Documentation: https://docs.layerv.ai
- Support: support@layerv.ai
