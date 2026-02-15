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
