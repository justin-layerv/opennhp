# Packer Templates for NHP AMIs

This directory contains Packer templates for building NHP AMIs.

## AMI Types

| AMI | Purpose | Distribution |
|-----|---------|--------------|
| **NHP AC** | Access Controller with Traefik | **AWS Marketplace** + internal |
| **NHP Server** | NHP Server (internal only) | Internal use only |

## Use Cases

### NHP AC AMI (Marketplace)
- **AWS Marketplace**: Customers deploy AC to protect their resources
- **Air-gapped Deployments**: Environments without internet access
- **Customer self-service**: Configure via user_data at boot

### NHP Server AMI (Internal)
- **Internal testing**: Development and QA environments
- **Enterprise self-hosted**: Large customers who run their own servers
- **Not for Marketplace**: Customers connect to LayerV-managed servers

## Prerequisites

- [Packer](https://www.packer.io/downloads) installed (v1.9+)
- AWS credentials configured with permissions to:
  - Create EC2 instances
  - Create AMIs and snapshots
  - Read from ECR and S3
- Docker images pushed to ECR
- Plugins uploaded to S3 plugin bucket

## Building AMIs

### Development/Testing Build

```bash
cd packer

# Initialize Packer plugins
packer init nhp-ac.pkr.hcl

# Build AC AMI for sandbox
packer build \
  -var 'environment=sandbox' \
  -var 'image_tag=abc123' \
  -var 'plugin_bucket=layerv-nhp-sandbox-plugins' \
  nhp-ac.pkr.hcl

# Build Server AMI for sandbox
packer init nhp-server.pkr.hcl
packer build \
  -var 'environment=sandbox' \
  -var 'image_tag=abc123' \
  -var 'plugin_bucket=layerv-nhp-sandbox-plugins' \
  nhp-server.pkr.hcl
```

### AWS Marketplace Build (AC Only)

For Marketplace submission, use the `marketplace=true` flag which enables:
- EBS encryption
- Stricter cleanup (no credentials, logs, or SSH keys)
- Multi-region AMI copying
- Marketplace-compliant naming

```bash
# Build AC AMI for Marketplace
packer build \
  -var 'marketplace=true' \
  -var 'product_version=1.0.0' \
  -var 'image_tag=v1.0.0' \
  -var 'plugin_bucket=layerv-nhp-prod-plugins' \
  -var 'plugin_version=v1.0.0' \
  -var 'ami_regions=["us-east-1","us-west-2","eu-west-1"]' \
  nhp-ac.pkr.hcl
```

### Internal Server AMI

The Server AMI is for internal use only (not Marketplace):

```bash
packer build \
  -var 'environment=sandbox' \
  -var 'image_tag=abc123' \
  -var 'plugin_bucket=layerv-nhp-sandbox-plugins' \
  nhp-server.pkr.hcl
```

## AMI Contents

### NHP AC AMI

```
/usr/local/bin/traefik           # Traefik binary
/opt/layerv/
├── nhp-ac/
│   ├── nhp-acd                  # AC daemon binary
│   ├── etc/                     # Configuration (populated at boot)
│   └── log/                     # Logs
├── traefik/
│   ├── plugins-local/src/       # Pre-installed Traefik plugins
│   │   └── nhp-token-validator/
│   ├── traefik.toml             # Configuration (populated at boot)
│   └── conf.d/                  # Dynamic configuration
└── configure-nhp-ac.sh          # First-boot configuration script
/acme/                           # ACME certificates (Let's Encrypt)
```

### NHP Server AMI

```
/opt/layerv/
├── nhp-server/
│   ├── nhp-server               # Server binary (native, no Docker)
│   ├── etc/                     # Configuration (populated at boot)
│   ├── logs/                    # Logs
│   └── plugins/                 # Pre-installed plugins
│       ├── passcode/
│       │   ├── main.so
│       │   └── etc/config.toml  # Populated at boot
│       └── oidc/
│           ├── main.so
│           └── etc/config.toml
└── configure-nhp-server.sh      # First-boot configuration script
```

**Note:** Both AMIs run native binaries - no Docker required at runtime. Docker is only used during AMI build to extract binaries from ECR images.

## Customer Deployment

### User Data Example (AC)

Customers launch instances with user_data that configures the instance:

```bash
#!/bin/bash
# Required environment variables
export DOMAIN_NAME="app.example.com"
export ACME_EMAIL="admin@example.com"
export NHP_SERVER_HOST="nhp-server.example.com"
export NHP_SERVER_PORT="62206"

# Run first-boot configuration
/opt/layerv/configure-nhp-ac.sh
```

### User Data Example (Server)

```bash
#!/bin/bash
export NHP_LISTEN_PORT="62206"

# Configure passcode plugin
cat > /opt/layerv/nhp-server/plugins/passcode/etc/config.toml << EOF
ResourceMode = "api"
AuthUrl = "https://console.example.com"
SigningKey = "your-signing-key"
AesKey = "your-aes-key"
EOF

# Run first-boot configuration
/opt/layerv/configure-nhp-server.sh
```

## Marketplace Submission Checklist (AC Only)

Before submitting the AC AMI to AWS Marketplace:

- [ ] Build with `marketplace=true`
- [ ] Use specific `product_version` (e.g., "1.0.0")
- [ ] Test AMI in fresh AWS account
- [ ] Verify no credentials or secrets in AMI
- [ ] Verify SSH host keys regenerate on boot
- [ ] Verify cloud-init runs on first boot
- [ ] Test user_data configuration flow
- [ ] Verify all ports documented
- [ ] Create CloudFormation/Terraform quick-start template
- [ ] Write usage instructions for listing

### Required Ports (AC AMI)

| Port  | Protocol | Description |
|-------|----------|-------------|
| 80    | TCP      | HTTP (redirect to HTTPS) |
| 443   | TCP      | HTTPS (Traefik) |

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Build Marketplace AMI

on:
  release:
    types: [published]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Packer
        uses: hashicorp/setup-packer@main

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-2

      - name: Build AMI
        run: |
          cd packer
          packer init nhp-ac.pkr.hcl
          packer build \
            -var 'marketplace=true' \
            -var "product_version=${{ github.event.release.tag_name }}" \
            -var "image_tag=${{ github.event.release.tag_name }}" \
            -var 'plugin_bucket=layerv-nhp-prod-plugins' \
            -var "plugin_version=${{ github.event.release.tag_name }}" \
            nhp-ac.pkr.hcl
```

## Troubleshooting

### AMI build fails with ECR authentication error

Ensure the Packer build instance has IAM permissions to pull from ECR:
```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer"
  ],
  "Resource": "*"
}
```

### AMI build fails with S3 access error

Ensure the Packer build instance has IAM permissions to read from the plugin bucket:
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": [
    "arn:aws:s3:::layerv-nhp-*-plugins",
    "arn:aws:s3:::layerv-nhp-*-plugins/*"
  ]
}
```

### Services don't start after boot

Check cloud-init logs:
```bash
cat /var/log/cloud-init-output.log
journalctl -u nhp-acd
journalctl -u traefik
```
