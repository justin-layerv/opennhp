# Terraform Scripts

Operational scripts for NHP infrastructure management.

## License Credential Scripts

AC (Access Controller) instances authenticate with the NHP Server using license credentials stored in DynamoDB. Each license has:

- **License Key**: Random 32-char string (stored in Secrets Manager, passed via `TF_VAR_*`)
- **Bcrypt Hash**: For validation (safe to commit to tfvars)
- **SHA256 Hash**: For DynamoDB lookup (safe to commit to tfvars)
- **Customer ID**: ULID identifier (safe to commit to tfvars)

### generate-ac-license.sh

Generates credentials for standalone AC deployments (customer ACs).

```bash
AWS_PROFILE=layerv ./generate-ac-license.sh <environment> [customer_id]

# Examples:
AWS_PROFILE=layerv ./generate-ac-license.sh sandbox
AWS_PROFILE=layerv ./generate-ac-license.sh prod 01HXYZ1234567890ABCDEFGHIJ
```

Output values go in `terraform.tfvars`:
```hcl
ac_customer_id        = "00000000000000000000000000"
ac_license_key_hash   = "$2b$10$..."
ac_license_key_sha256 = "a762d8af..."
```

The plaintext `ac_license_key` is stored in Secrets Manager and passed via GitHub Secret `AC_LICENSE_KEY`.

## Other Scripts

### seed-etcd.sh

Seeds etcd with initial NHP configuration. Used during bootstrap.

```bash
AWS_PROFILE=layerv ./seed-etcd.sh <environment>
```

### etcd-seed-config.json

Template configuration for etcd seeding.

## GitHub Actions Integration

For CI/CD, license keys are passed as environment variables:

```yaml
env:
  TF_VAR_ac_license_key: ${{ secrets.AC_LICENSE_KEY }}
```

The hashes in `terraform.tfvars` are safe to commit since they cannot be reversed.
