# Security Monitoring

This document covers AWS security services configured for LayerV NHP infrastructure.

## GuardDuty

AWS GuardDuty provides intelligent threat detection by analyzing CloudTrail logs, VPC flow logs, and DNS logs to identify malicious activity.

### Enabled Protection Features

| Feature | Purpose | Coverage |
|---------|---------|----------|
| **S3_DATA_EVENTS** | Detects suspicious S3 access patterns | All S3 buckets |
| **EBS_MALWARE_PROTECTION** | Scans EBS volumes for malware during EC2 events | EC2 instances |
| **RDS_LOGIN_EVENTS** | Detects brute force attacks on Aurora PostgreSQL | RDS instances |
| **LAMBDA_NETWORK_LOGS** | Detects compromised Lambda functions | Lambda functions |
| **RUNTIME_MONITORING** | OS-level threat detection via agent | EC2 instances |

### Severity Levels

GuardDuty findings use a 0.1-8.9 severity scale:

| Level | Range | Description |
|-------|-------|-------------|
| **High** | 7.0 - 8.9 | Resource is compromised and actively used for malicious purposes |
| **Medium** | 4.0 - 6.9 | Suspicious activity that deviates from normal behavior |
| **Low** | 0.1 - 3.9 | Attempted suspicious activity that did not compromise resources |

Default alert threshold is **4** (Medium and above).

### Alerting Architecture

```
GuardDuty Finding
       │
       ▼
┌─────────────────┐
│  EventBridge    │  ← Filters by severity threshold
│     Rule        │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐  ┌───────┐
│ Email │  │ Slack │  ← Two targets with format-specific templates
│Target │  │Target │
└───┬───┘  └───┬───┘
    │          │
    ▼          ▼
┌─────────────────┐
│   SNS Topic     │  ← Single topic (monitoring module)
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐  ┌──────────┐
│ Email │  │   AWS    │
│ Subs  │  │ Chatbot  │
└───────┘  └──────────┘
               │
               ▼
           ┌───────┐
           │ Slack │
           └───────┘
```

### Alert Content

Alerts include the following GuardDuty finding details:

**Core Fields:**
- Severity, Type, Title, Description
- Region, Account, Time, Finding ID

**Resource Details (when available):**
- Resource Type (EC2, S3, IAM, etc.)
- Instance ID and Type (EC2 findings only)
- Action Type (network connection, API call, etc.)

> **Note**: Some fields may be empty depending on finding type. For example, IAM findings won't have instanceId, and S3 findings won't have instanceType. The alerts are designed to handle missing fields gracefully.

**Quick Links:**
- Direct link to the finding in GuardDuty console

---

## Responding to GuardDuty Alerts

### Triage Process

1. **Assess Severity**: High severity findings require immediate attention
2. **Review Finding Type**: Check the [GuardDuty finding types documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
3. **Identify Affected Resource**: Note instance ID, S3 bucket, or IAM principal
4. **Check for Related Findings**: Multiple findings may indicate a coordinated attack

### Common Finding Types

#### EC2 Findings

| Finding | Description | Response |
|---------|-------------|----------|
| `UnauthorizedAccess:EC2/SSHBruteForce` | SSH brute force attack detected | Check security groups, review SSH logs, consider rotating keys |
| `Backdoor:EC2/C&CActivity.B` | Instance communicating with known C&C server | Isolate instance immediately, capture forensic image |
| `CryptoCurrency:EC2/BitcoinTool.B` | Crypto mining detected | Check for unauthorized access, terminate if compromised |

#### S3 Findings

| Finding | Description | Response |
|---------|-------------|----------|
| `Policy:S3/BucketAnonymousAccessGranted` | Bucket made publicly accessible | Review bucket policy, revert if unintended |
| `Exfiltration:S3/AnomalousBehavior` | Unusual data access pattern | Review CloudTrail logs, check for credential compromise |

#### IAM Findings

| Finding | Description | Response |
|---------|-------------|----------|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | Instance credentials used from external IP | Rotate credentials, check instance for compromise |
| `Persistence:IAMUser/UserPermissions` | Permissions escalation attempt | Review IAM changes, revert unauthorized modifications |

### Suppression Rules

To suppress known benign activities:

1. Go to GuardDuty console → Settings → Findings → Suppression rules
2. Create a rule with filters matching the benign activity
3. Document the reason for suppression in the rule description

**Examples of commonly suppressed findings:**
- Security scanner IP addresses (known pentest tools)
- Authorized third-party integrations
- Development/testing activities in sandbox

---

## Testing the Alert Pipeline

### Generate Sample Findings

```bash
# Get detector ID
DETECTOR_ID=$(AWS_PROFILE=layerv aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Generate sample findings (multiple types)
AWS_PROFILE=layerv aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types \
    "UnauthorizedAccess:EC2/SSHBruteForce" \
    "Backdoor:EC2/C&CActivity.B" \
    "CryptoCurrency:EC2/BitcoinTool.B"
```

### Verify Alert Delivery

1. **Email**: Check inbox of subscribed addresses (check spam folder)
2. **Slack**: Check #all-layerv channel for Chatbot message
3. **Console**: GuardDuty → Findings should show sample findings

### Email Subscription Confirmation

After Terraform apply, each email recipient must confirm their SNS subscription:
1. Check email for "AWS Notification - Subscription Confirmation"
2. Click the confirmation link
3. Verify subscription status in SNS console

---

## Cost Considerations

### GuardDuty Pricing Components

| Feature | Pricing Model | Notes |
|---------|---------------|-------|
| Base (CloudTrail, VPC Flow Logs) | Per million events | First 30 days free |
| S3 Protection | Per million S3 data events | After S3 free tier |
| EBS Malware Protection | Per GB scanned | Triggered by EC2 events |
| RDS Login Events | Per million RDS login events | Aurora PostgreSQL only |
| Lambda Network Logs | Per GB analyzed | VPC-enabled Lambdas |
| Runtime Monitoring | Per vCPU-hour monitored | 30-day free trial |

### Estimated Monthly Costs (Sandbox)

| Component | Estimate |
|-----------|----------|
| Base GuardDuty | $2-5/month |
| S3 Protection | $1-2/month |
| Runtime Monitoring (post-trial) | $10-30/month |
| **Total** | **~$15-40/month** |

### Cost Monitoring

Set up AWS Budget alerts before the 30-day trial expires:

```bash
# Get account ID first
ACCOUNT_ID=$(AWS_PROFILE=layerv aws sts get-caller-identity --query Account --output text)

# Create a budget for GuardDuty costs
AWS_PROFILE=layerv aws budgets create-budget \
  --account-id "$ACCOUNT_ID" \
  --budget file:///dev/stdin \
  --notifications-with-subscribers file:///dev/stdin <<'EOF'
{
  "Budget": {
    "BudgetName": "GuardDuty-Monthly",
    "BudgetLimit": {"Amount": "50", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST",
    "CostFilters": {"Service": ["Amazon GuardDuty"]}
  },
  "NotificationsWithSubscribers": [{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80
    },
    "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "security@layerv.ai"}]
  }]
}
EOF
```

Alternatively, create the budget via AWS Console: Billing → Budgets → Create budget.

---

## Related Services

### Security Hub

Security Hub aggregates findings from GuardDuty and other security services:
- GuardDuty findings are automatically sent to Security Hub
- View consolidated security posture dashboard
- Compliance standards: AWS Foundational Best Practices, CIS Benchmarks

### AWS Config

Monitors configuration compliance:
- EBS encryption
- S3 server-side encryption
- IAM MFA requirements
- VPC Flow Logs enabled
- CloudTrail enabled

### CloudTrail

API audit logging:
- All AWS API calls logged
- Logs encrypted with KMS
- Archived to S3 with lifecycle policies

---

## Configuration Reference

### Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `enable_guardduty` | `true` | Enable GuardDuty detector |
| `enable_guardduty_alerts` | `false` | Enable EventBridge alerting |
| `guardduty_alert_severity_threshold` | `4` | Minimum severity (1-8) |
| `guardduty_alert_emails` | `[]` | Email addresses for alerts |
| `enable_slack_target` | `true` | Enable Slack-optimized target |

### Example Configuration

```hcl
# terraform/environments/sandbox/terraform.tfvars
enable_guardduty        = true
enable_guardduty_alerts = true
guardduty_alert_emails  = [
  "security@layerv.ai",
  "oncall@layerv.ai"
]
guardduty_alert_severity_threshold = 4  # Medium+
enable_slack_target                = true
```

---

## NHP-Specific Security Notes

### Secrets and Encryption

- Never commit secrets — use AWS Secrets Manager.
- All storage encrypted with KMS CMKs (documented exception:
  `terraform/modules/bootstrap-alb/`'s access-log + Athena-results
  buckets are SSE-S3, not CMK. AWS ALB log delivery does NOT
  support cross-account CMKs, and the Athena bucket follows the
  same shape for consistency. Rationale + suppression target lives
  inline at `access_logs.tf` — point AWS Config / scanner
  suppressions there. Relevant AWS Config rule names:
  `s3-default-encryption-kms` /
  `s3-bucket-server-side-encryption-enabled`.)
- IMDSv2 required on EC2.
- AC private keys NEVER in etcd — only Secrets Manager.

### `NHP_INTERNAL_AUTH_SECRET`

`NHP_INTERNAL_AUTH_SECRET` (≥ 32 bytes) signs internal requests between LayerV
services. The nhp-server `NHP_INTERNAL_AUTH_REQUIRE` gate enforces that secret
on `/nhp/internal/knock` and `/nhp/internal/token/validate`. Terraform
provisions and seeds the value (`aws_secretsmanager_secret.nhp_internal_auth`)
and exposes the `nhp_internal_auth_require` gate; environments set it true only
after per-env/cell permit-mode burn-in has completed. In strict environments
the server receives `NHP_INTERNAL_AUTH_REQUIRE=true` and rejects unsigned or
badly signed internal requests instead of permit-allowing them. The app binary
still defaults to permit mode when the env var is unset; that fallback is
reserved for rollback, burn-in, or non-Terraform local runs.

The same shared secret can also be used by other service-to-service auth paths
outside nhp-server. For example, qurl-reverse-tunnel-server's
`/internal/v1/tunnel/auth-by-owner` call is a qurl-service endpoint, not an
nhp-server route, so it is not controlled by `NHP_INTERNAL_AUTH_REQUIRE`.

**Entropy comes from upstream provisioning.** The shared module
(`internalauth.MinSecretLength`) only fences the length floor — a 32-byte
all-`a` string passes the construction check and is trivially guessable.
Production secrets MUST be CSPRNG-sourced: Terraform's `random_password`
resource (with `special = false` + `min_lower/upper/numeric` set) or AWS
Secrets Manager's `generate_secret_string` are the canonical sources.
An operator who hand-types or provisions a guessable secret bypasses the
brute-force fence the floor is supposed to enforce.

Operational notes:

- **Plan-role permissions:** the `check` block that asserts the secret is
  populated refreshes `data.aws_secretsmanager_secret_version` on every
  plan, so the caller's role needs `secretsmanager:GetSecretValue` (and
  `kms:Decrypt` on the secrets CMK). The runtime IAM grants already cover
  this on the ECS task + EC2 roles; laptop/CI plans need it on the
  terraform principal. **Security implication:** any principal permitted
  to run `terraform plan` can now read this HMAC secret's cleartext (held
  briefly in plan-time memory; sensitive-marked so it doesn't land in
  state or diff output, but reachable via a custom `output`). Scope the
  plan role to trusted CI runners / operators accordingly.
- **First plan on a greenfield env** fires a warning from the `check`
  block because the secret doesn't exist yet. Post-apply plans are clean.
  Any CI workflow that fails on terraform warnings should ignore the
  `nhp_internal_auth_secret_populated` check until the first apply lands.
- **Burn-in before strict:** before setting `nhp_internal_auth_require = true`,
  verify `InternalAuthFailPermit` stays zero over the burn-in window while
  `InternalAuthSuccess` confirms signed internal traffic, and confirm all
  nhp-server instances plus qurl-service tasks and any qurl-reverse-tunnel-server
  instances have rolled with `NHP_INTERNAL_AUTH_SECRET`. This is a manual
  promote gate: Terraform can seed and wire the secret, but it cannot prove
  signer fleets are actively signing live internal requests.
  The forward strict flip requires the same user_data refresh as rollback:
  include a server image deploy in the rollout, or explicitly refresh the
  server ASG after applying the tfvars change.
  `InternalAuthSuccess`, `InternalAuthFailPermit`, and
  `InternalAuthFailStrict` are aggregate counters across the strict-gated
  nhp-server endpoints; use server logs or a future endpoint-dimensioned metric
  when you need per-route proof for `/nhp/internal/token/validate`.
  If a new signer fleet is introduced after an environment is already strict
  (for example, first prod qurl-reverse-tunnel-server deployment), roll it with
  the shared secret and verify its signed `/nhp/internal/token/validate` calls
  before sending live traffic.
- **Rollback:** set `nhp_internal_auth_require = false` in the affected
  environment tfvars and apply Terraform. Then make sure existing server
  instances actually re-run user_data: either include a server image deploy in
  that deployment, or start an explicit server ASG instance refresh (prod:
  `aws autoscaling start-instance-refresh --profile layerv-prod --region us-east-2 --auto-scaling-group-name layerv-nhp-prod-server`).
  This follows the instance-refresh convention in
  [`CLAUDE.md`](../CLAUDE.md#quick-debugging); swap the profile and ASG name for
  non-prod environments.
  Leave `NHP_INTERNAL_AUTH_SECRET` in place; signer fleets can keep signing
  during the rollback window.
- **Rotation ≠ dynamic pickup.** nhp-server reads the secret once at
  instance boot in `user_data.sh.tpl`. Rotating the Secrets Manager value
  without an ASG instance refresh will break knock verification on
  existing instances. qurl-reverse-tunnel-server has the same instance-refresh
  requirement because its `user_data.sh.tpl` fetches and persists the secret at
  boot. qurl-service is fine — ECS `valueFrom` re-resolves per task start, so a
  rolling deploy (or stop-task) picks up the new value. #1312 tracks a proper
  current/previous rotation envelope.
