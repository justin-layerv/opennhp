# Packer Templates for NHP AMIs

This directory contains Packer templates for building NHP AMIs.

## AMI Types

| AMI | Purpose | Distribution | Startup Time |
|-----|---------|--------------|--------------|
| **NHP AC** | Access Controller with Traefik | **AWS Marketplace** + internal | ~30s |
| **NHP Server** | NHP Server (native binary) | Internal use only | ~30s |
| **NHP Server Docker** | NHP Server (Docker runtime) | Internal use only | ~30s |

### Terraform Runtime AMIs (Required)

Terraform-managed Server and AC launch templates both read custom AMI IDs from
SSM and have no fallback to vanilla Ubuntu:

- Server: `/<env>/nhp/server/ami-id`
- AC: `/<env>/nhp/ac/ami-id`

The `nhp-server-docker.pkr.hcl` template builds an AMI optimized for the
Terraform-managed infrastructure which uses Docker to run NHP Server. The
`nhp-ac.pkr.hcl` template can build either a full self-service/Marketplace AC
image or the runtime-package-only AMI used by Terraform-managed AC. Live AC
instances still pull the deploy-selected Docker image from ECR at boot; the AMI
bakes the OS/runtime package layer so user_data can fail closed instead of
running apt.

These AMIs pre-install the packages each user_data path assumes:

- Docker (docker.io)
- AWS CLI v2
- jq, curl, unzip
- AC-only: gettext-base, iptables, ipset, netcat-openbsd,
  iptables-persistent, python3-cryptography, ca-certificates
- Server-only: DNS configuration for Go's pure resolver

**Without this AMI**: Terraform fails at plan time (no fallback to vanilla Ubuntu)
**With this AMI**: Instance startup takes ~30 seconds

```bash
# Build Server Docker-optimized AMI (one-time setup per environment)
cd packer
packer init nhp-server-docker.pkr.hcl

# For sandbox
AWS_PROFILE=layerv packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl

# For prod
AWS_PROFILE=layerv-mgmt packer build -var 'environment=prod' nhp-server-docker.pkr.hcl

# Build AC runtime-package AMI (same environments)
packer init nhp-ac.pkr.hcl
AWS_PROFILE=layerv packer build -var 'environment=sandbox' -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
AWS_PROFILE=layerv-mgmt packer build -var 'environment=prod' -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
```

After building, the AMI ID is automatically published to SSM Parameter Store:
- Sandbox: `/sandbox/nhp/{server,ac}/ami-id`
- Prod: `/prod/nhp/{server,ac}/ami-id`

These names align with the existing `/${env}/nhp/server/*` convention used by
sibling parameters (`image-tag`, `asg-name`, `active-color`, ...). Terraform
reads from this SSM parameter — no manual steps required.

### First-time bootstrap (and emergency recovery)

Sandbox and prod live in **separate AWS accounts** (sandbox: `layerv` profile,
prod: `layerv-mgmt` profile), so each account has its own AMI and its own
SSM parameter. AMIs are not automatically copied across accounts. Both
accounts use the **us-east-2** region (matches `terraform/variables.tf`,
`terraform/environments/{sandbox,prod}/terraform.tfvars`, and the workflow
`AWS_REGION:` env var in `.github/workflows/build-and-push.yml`).

The CI workflow (`.github/workflows/build-and-push.yml::packer-build`)
handles steady-state builds: when packer files change on `main`, CI builds a
new AMI in the target account and publishes the ID to SSM. CI passes
`publish_ssm=false` to the AC Packer template and publishes
`/<env>/nhp/ac/ami-id` from the workflow after switching back to the
environment deploy role; this avoids a first-merge ordering trap while the
dedicated Packer role's new AC SSM permission is being applied. The
`promote-to-prod` workflow refuses to deploy if `/prod/nhp/{server,ac}/ami-id`
is missing — by design, since neither launch template has a fallback to vanilla
Ubuntu.

First prod rollout checklist: publish `/prod/nhp/ac/ami-id` before the first
post-merge `promote-to-prod` run with `run_terraform=true`, or the AMI preflight
will block the deploy by design.

You only need this section in two situations:

1. **First-ever deploy to a new environment** (the SSM parameter has never
   been populated and CI hasn't run a packer build yet for that env).
2. **Emergency recovery** (the SSM parameter was deleted, or the AMI it
   points to was deregistered, and you need to rebuild before the next
   scheduled CI run).

There are two paths. **Strongly prefer Option A.** Option B (cross-account
AMI copy) involves a four-step IAM/snapshot/copy/wait dance that hits
KMS-grant edge cases, and a wrong step leaves a half-shared snapshot
behind. Only fall back to Option B if you genuinely cannot get
packer-build credentials for the target account (e.g. it's blocked by an
organization policy you can't temporarily lift).

#### Option A — Build in the target account directly (strongly preferred)

Easiest if you have packer-build credentials for the target account.

```bash
# Sandbox bootstrap
cd packer
packer init nhp-server-docker.pkr.hcl
AWS_PROFILE=layerv packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
# The shell-local post-processor publishes the AMI ID to
# /sandbox/nhp/server/ami-id automatically.
packer init nhp-ac.pkr.hcl
AWS_PROFILE=layerv packer build -var 'environment=sandbox' -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
# Publishes to /sandbox/nhp/ac/ami-id.

# Prod bootstrap
AWS_PROFILE=layerv-mgmt packer build -var 'environment=prod' nhp-server-docker.pkr.hcl
# Publishes to /prod/nhp/server/ami-id.
AWS_PROFILE=layerv-mgmt packer build -var 'environment=prod' -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
# Publishes to /prod/nhp/ac/ami-id.
```

This produces a freshly-built AMI in the target account and publishes the ID
to that account's SSM parameter in one step. No cross-account copy needed.

#### Option B — Copy an existing sandbox AMI into prod

Useful if sandbox already has a known-good AMI and you want to mirror it
into prod without re-running packer.

All Terraform runtime AMIs are encrypted. Cross-account copy only works when
the source snapshot is encrypted with a customer-managed CMK that grants the
prod account access; snapshots encrypted with the default `aws/ebs` key cannot
be shared cross-account. If you do not already have that CMK path set up, use
Option A instead.

The same KMS caveat applies to full self-service, non-Marketplace AC AMIs:
build directly in the target account, or use a customer-managed CMK before
sharing the image cross-account.

```bash
# 1. Read the sandbox AMI ID
AWS_PROFILE=layerv aws ssm get-parameter \
  --name /sandbox/nhp/server/ami-id --query 'Parameter.Value' --output text
# → ami-0123456789abcdef0  (example)

# 2. Share the snapshot from sandbox to prod
SANDBOX_AMI=ami-0123456789abcdef0
PROD_ACCOUNT=<prod-account-id>
AWS_PROFILE=layerv aws ec2 modify-image-attribute \
  --image-id "$SANDBOX_AMI" \
  --launch-permission "Add=[{UserId=$PROD_ACCOUNT}]"
# Also share the underlying snapshot (required for copy):
SNAPSHOT_ID=$(AWS_PROFILE=layerv aws ec2 describe-images --image-ids "$SANDBOX_AMI" \
  --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)
AWS_PROFILE=layerv aws ec2 modify-snapshot-attribute \
  --snapshot-id "$SNAPSHOT_ID" \
  --create-volume-permission "Add=[{UserId=$PROD_ACCOUNT}]"

# 3. Copy the AMI into the prod account (run with prod credentials).
# Region matches the rest of the deployment — see workflow AWS_REGION env var.
PROD_AMI=$(AWS_PROFILE=layerv-mgmt aws ec2 copy-image \
  --source-image-id "$SANDBOX_AMI" \
  --source-region us-east-2 \
  --region us-east-2 \
  --name "nhp-server-docker-bootstrap-$(date +%Y%m%d%H%M%S)" \
  --encrypted \
  --query 'ImageId' --output text)

# 4. Wait for the copy to become available, then publish to SSM
AWS_PROFILE=layerv-mgmt aws ec2 wait image-available --image-ids "$PROD_AMI"
AWS_PROFILE=layerv-mgmt aws ssm put-parameter \
  --name /prod/nhp/server/ami-id \
  --value "$PROD_AMI" --type String --overwrite
```

After either option, re-run the failing workflow (`promote-to-prod` or
`terraform plan`). It will now find the SSM parameter and proceed.

#### What CI does on a normal build

For reference, the CI packer-build job is roughly:

1. Detect if the Server or AC Packer template changed on `main` (or if that
   component's SSM parameter is missing).
2. Run `packer build` only for the component(s) that need a fresh AMI.
3. The Server Packer post-processor publishes `/<env>/nhp/server/ami-id`;
   the workflow parses the AC manifest and publishes `/<env>/nhp/ac/ami-id`
   after switching back to the environment deploy role.
4. The terraform-plan job waits for packer-build to complete before reading
   the SSM parameter.

You should never need to run the bootstrap procedure under normal operation —
if you do, file an issue so we can understand why CI didn't handle it.

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
