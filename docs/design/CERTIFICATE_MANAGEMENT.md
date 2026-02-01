# Certificate Management Strategy

This document describes the TLS certificate management approach for NHP Access Controllers (ACs) and the planned migration path from centralized Secrets Manager to HashiCorp Vault PKI.

## Table of Contents

- [Background](#background)
- [Why NLB Can't Terminate TLS](#why-nlb-cant-terminate-tls)
- [Phase 1: Centralized Secrets Manager](#phase-1-centralized-secrets-manager)
- [Phase 2: HashiCorp Vault PKI](#phase-2-hashicorp-vault-pki)
- [Operations Runbook](#operations-runbook)

---

## Background

### The Problem

Each AC instance runs Traefik as a reverse proxy with TLS termination. Initially, each AC requested its own Let's Encrypt certificate using ACME DNS-01 challenge. This approach fails at scale:

| Issue | Impact |
|-------|--------|
| **Rate Limits** | Let's Encrypt allows 5 certificates per exact domain set per week |
| **Duplicate Requests** | Multiple ACs requesting certs for `*.nhp.layerv.xyz` hit limits quickly |
| **ASG Scaling** | New instances during scale-out can't get certificates |
| **Instance Refresh** | CI/CD deployments trigger new cert requests |

### Requirements

1. TLS termination must happen on the AC (not the load balancer)
2. Certificates must cover wildcard domains (`*.nhp.layerv.xyz`, `*.qurl.site`)
3. Solution must scale to thousands of AC instances
4. Automatic renewal without manual intervention
5. Security: Private keys encrypted at rest, audit trail

---

## Why NLB Can't Terminate TLS

NHP operates at the network layer (L3/L4). When a user authenticates, the NHP Server instructs the AC to add the user's source IP to an ipset, and iptables rules allow traffic from that IP.

```
User (IP: 203.0.113.50) → NLB → AC
                                 │
                                 ├─ iptables checks source IP
                                 ├─ ipset contains 203.0.113.50? → ALLOW
                                 └─ Otherwise → DROP
```

**If NLB terminates TLS:**

```
User (IP: 203.0.113.50) → NLB (TLS termination) → AC
                          │                        │
                          │ New connection from    │
                          │ NLB IP: 10.0.1.50     │
                          │                        │
                                                   ├─ iptables sees 10.0.1.50
                                                   ├─ ipset contains 203.0.113.50
                                                   └─ MISMATCH → DROP (or wrong allow)
```

The AC would see the NLB's internal IP, not the user's real IP. This breaks NHP's core security model.

**Solution:** NLB operates in TCP passthrough mode. TLS termination happens on the AC, preserving the original client IP through the TLS handshake.

---

## Phase 1: Centralized Secrets Manager

**Status:** Implemented in PR #277 (disabled by default)

### Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  EventBridge        │  daily  │  Lambda             │
│  (cron schedule)    │────────►│  acme_cert_manager  │
└─────────────────────┘         └──────────┬──────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
         ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
         │  Let's Encrypt   │   │  Route 53        │   │  Secrets Manager │
         │  (ACME API)      │   │  (DNS-01)        │   │  (cert storage)  │
         └──────────────────┘   └──────────────────┘   └──────────────────┘
                                                                │
                                                                ▼
                                                       ┌──────────────────┐
                                                       │  AC instances    │
                                                       │  (fetch on boot) │
                                                       └──────────────────┘
```

### How It Works

1. **Lambda Function** (`acme_cert_manager.py`):
   - Runs daily via EventBridge
   - Checks certificate expiry (renews if < 30 days remaining)
   - Uses ACME DNS-01 challenge via Route 53
   - Stores certificate in Secrets Manager (KMS encrypted)
   - Persists ACME account key to avoid rate limits on account creation
   - Publishes `DaysUntilExpiry` metric to CloudWatch for monitoring

2. **AC Boot Process**:
   - User data script fetches certificate from Secrets Manager
   - Writes cert files directly to `/home/ubuntu/traefik/certs/` (no shell variables)
   - Traefik uses file-based TLS configuration (not ACME certResolver)

3. **Secret Structure**:
   ```json
   {
     "private_key": "<PEM-encoded RSA key>",
     "certificate": "<PEM-encoded certificate>",
     "chain": "<PEM-encoded CA chain>",
     "fullchain": "cert + chain combined",
     "renewed_at": "2024-01-15T00:00:00Z",
     "domains": ["nhp.layerv.xyz", "*.nhp.layerv.xyz"]
   }
   ```

### Configuration

```hcl
# terraform/environments/sandbox/terraform.tfvars

# Enable centralized certificate management
centralized_cert_enabled = true

# Domains to include in the certificate
centralized_cert_domains = [
  "nhp.layerv.xyz",
  "*.nhp.layerv.xyz",
  "apps.layerv.xyz",
  "*.apps.layerv.xyz"
]
```

### Security Controls

| Control | Implementation |
|---------|----------------|
| Encryption at rest | KMS CMK for Secrets Manager |
| Least privilege | Lambda has minimal IAM permissions |
| Audit trail | CloudTrail logs all Secrets Manager access |
| Alerting | CloudWatch alarms for renewal failures and expiry |
| No secrets in logs | Lambda redacts sensitive values |
| No secrets in memory | AC user_data writes directly to files (no shell variables) |
| Rate limit protection | ACME account key persisted to avoid account creation limits |

### Limitations

- Certificate lifetime: 90 days (Let's Encrypt limit)
- Single certificate for all ACs (no per-tenant certs)
- Renewal requires Route 53 access
- No instant revocation capability
- Lambda dependencies (cryptography, acme, dnspython) are bundled directly in the deployment package via `build.sh`. No external Lambda layers are used.

---

## Phase 2: HashiCorp Vault PKI

**Status:** Planned (not yet implemented)

### Why Vault?

| Aspect | Secrets Manager (Phase 1) | Vault PKI (Phase 2) |
|--------|---------------------------|---------------------|
| Certificate lifetime | 90 days (Let's Encrypt) | Minutes to hours |
| Issuance | External CA (rate limits) | Internal CA (unlimited) |
| Revocation | Manual/slow | Instant via CRL/OCSP |
| Audit | CloudTrail | Vault audit log + SIEM integration |
| Rotation | Lambda + EventBridge | Automatic on expiry |
| Multi-region | Cross-region replication | Native HA clusters |
| Per-tenant certs | Not practical | Easy with roles |

### Target Architecture

```
┌─────────────────────┐
│  Vault Cluster      │
│  (HA, 3+ nodes)     │
│                     │
│  ┌───────────────┐  │
│  │ PKI Engine    │  │
│  │ (Intermediate │  │
│  │  CA)          │  │
│  └───────────────┘  │
└──────────┬──────────┘
           │
           │ IAM Auth
           ▼
┌──────────────────────┐
│  AC Instance         │
│                      │
│  1. Authenticate     │
│     (IAM role)       │
│  2. Request cert     │
│     (24h TTL)        │
│  3. Auto-renew       │
│     (before expiry)  │
└──────────────────────┘
```

### Implementation Plan

1. **Deploy Vault Cluster**
   - Option A: Self-managed on EKS
   - Option B: HCP Vault (managed service)
   - HA configuration with 3+ nodes

2. **Configure PKI Secrets Engine**
   ```bash
   # Enable PKI engine
   vault secrets enable pki

   # Configure as intermediate CA
   vault write pki/intermediate/generate/internal \
     common_name="LayerV NHP Intermediate CA"

   # Sign with offline root CA
   # Import signed certificate
   ```

3. **Create Certificate Roles**
   ```bash
   # Role for AC certificates
   vault write pki/roles/nhp-ac \
     allowed_domains="nhp.layerv.xyz,qurl.site" \
     allow_subdomains=true \
     max_ttl="24h"

   # Role for per-tenant certificates (future)
   vault write pki/roles/tenant-cert \
     allowed_domains="*.qurl.site" \
     max_ttl="1h"
   ```

4. **Configure IAM Authentication**
   ```bash
   vault auth enable aws
   vault write auth/aws/role/nhp-ac \
     auth_type=iam \
     bound_iam_principal_arn="arn:aws:iam::*:role/nhp-*-ac-role" \
     policies=nhp-ac-cert
   ```

5. **Update AC User Data**
   - Replace Secrets Manager fetch with Vault API call
   - Implement certificate renewal sidecar/cron
   - Handle Vault unavailability gracefully

### Migration Path

1. Deploy Vault alongside existing Secrets Manager setup
2. Test with non-production ACs
3. Gradually migrate environments (sandbox → staging → prod)
4. Deprecate Secrets Manager certificate storage
5. Reduce certificate TTL incrementally (90d → 30d → 24h → 1h)

### When to Implement Phase 2

Trigger conditions:
- Production deployment with SLA requirements
- Compliance requirement for short-lived certificates
- Need for instant certificate revocation
- Per-tenant certificate isolation required
- Scale beyond single-region deployment

---

## Operations Runbook

### Manual Certificate Renewal (Phase 1)

```bash
# Trigger Lambda manually
AWS_PROFILE=layerv aws lambda invoke \
  --function-name nhp-sandbox-acme-cert-manager \
  --payload '{"force_renew": true}' \
  /dev/stdout

# Verify new certificate
AWS_PROFILE=layerv aws secretsmanager get-secret-value \
  --secret-id nhp-sandbox-tls-certificate \
  --query 'SecretString' --output text | jq -r '.renewed_at'
```

### Check Certificate Expiry

```bash
# From Secrets Manager
AWS_PROFILE=layerv aws secretsmanager get-secret-value \
  --secret-id nhp-sandbox-tls-certificate \
  --query 'SecretString' --output text | \
  jq -r '.certificate' | \
  openssl x509 -noout -enddate

# From running AC
aws ssm start-session --target <instance-id>
openssl x509 -in /home/ubuntu/traefik/certs/fullchain.pem -noout -enddate
```

### Troubleshooting

| Symptom | Possible Cause | Resolution |
|---------|----------------|------------|
| AC shows self-signed cert | Failed to fetch from Secrets Manager | Check IAM permissions, secret ARN |
| Lambda renewal fails | Route 53 permissions | Verify Lambda role has route53:ChangeResourceRecordSets |
| Certificate expired | EventBridge not triggering | Check CloudWatch Events rule |
| New AC has old cert | Secret not updated | Trigger manual renewal |
| 429 from Let's Encrypt | Rate limit hit | Wait 1 week or use staging endpoint |

### CloudWatch Alarms

The `acme-cert` module creates these alarms:

| Alarm | Trigger | Action |
|-------|---------|--------|
| `CertificateRenewalFailed` | Lambda errors > 0 | Check Lambda logs, fix issue, re-run |
| `CertificateExpiringSoon` | < 14 days to expiry | Investigate why auto-renewal failed |

### Monitoring Queries

```sql
-- CloudWatch Logs Insights: Recent renewal attempts
fields @timestamp, @message
| filter @logStream like /acme-cert/
| filter @message like /renew/
| sort @timestamp desc
| limit 20

-- Certificate age distribution across ACs
-- (requires custom metric from AC user data)
```

---

## Related Documentation

- [ARCHITECTURE.md](../ARCHITECTURE.md) - Overall system architecture
- [terraform/modules/acme-cert/](../../terraform/modules/acme-cert/) - Module implementation
- [terraform/modules/ac/user_data.sh.tpl](../../terraform/modules/ac/user_data.sh.tpl) - AC boot process

## References

- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [HashiCorp Vault PKI Engine](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
