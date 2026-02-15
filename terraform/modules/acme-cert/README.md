# ACME Certificate Manager Module

Manages centralized TLS certificates for the AC fleet using Let's Encrypt ACME protocol with DNS-01 challenges.

## Overview

This module deploys a Lambda function that:
- Requests wildcard certificates from Let's Encrypt
- Uses Route 53 for DNS-01 challenge validation
- Stores certificates in Secrets Manager (KMS encrypted)
- Runs on a schedule to auto-renew before expiry

## Prerequisites

Before running `terraform apply`, you must build the Lambda package:

```bash
# From repository root
bash terraform/modules/acme-cert/lambda/build.sh

# Verify the build
bash terraform/modules/acme-cert/lambda/test_build.sh
```

The build script:
- Installs Python dependencies with manylinux wheels (Lambda-compatible)
- Bundles everything into `build/package/`
- Requires Python 3.12 and pip with `--platform` support

## Usage

```hcl
module "acme_cert" {
  source = "../../modules/acme-cert"

  environment    = "sandbox"
  domains        = ["nhp.layerv.xyz", "*.nhp.layerv.xyz"]
  hosted_zone_id = "Z1234567890"
  acme_email     = "admin@layerv.xyz"

  # Optional: use staging for testing
  acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
}
```

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `environment` | Environment name (sandbox, prod) | `string` | - |
| `domains` | List of domains for the certificate | `list(string)` | - |
| `hosted_zone_id` | Route 53 hosted zone ID for DNS challenges | `string` | - |
| `acme_email` | Email for Let's Encrypt notifications | `string` | - |
| `acme_directory` | ACME directory URL | `string` | Let's Encrypt production |

## Outputs

| Name | Description |
|------|-------------|
| `secret_arn` | ARN of the Secrets Manager secret containing the certificate |
| `lambda_function_name` | Name of the certificate manager Lambda |

## Lambda Invocation

```bash
# Check certificate status
aws lambda invoke --function-name <lambda-name> \
  --payload '{"type": "check_status"}' /dev/stdout

# Force renewal
aws lambda invoke --function-name <lambda-name> \
  --payload '{"type": "force_renew"}' /dev/stdout
```

## Testing

```bash
# Build verification (structure, size, platform)
bash terraform/modules/acme-cert/lambda/test_build.sh

# Python unit tests
cd terraform/modules/acme-cert/lambda
pip install -r requirements-dev.txt
pytest test_acme_cert_manager.py -v

# Go integration tests (requires deployed infrastructure)
go test -tags=integration ./tests/integration/... -run TestACME
```

## Architecture

See [docs/design/CERTIFICATE_MANAGEMENT.md](../../../docs/design/CERTIFICATE_MANAGEMENT.md) for detailed architecture documentation.
