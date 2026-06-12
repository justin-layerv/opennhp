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

## CloudTrail Tamper Detection

An EventBridge rule pages on-call when anyone disables, deletes, or reconfigures
a CloudTrail trail — the "attacker disables logging" step in an intrusion. Added
in [#1143](https://github.com/layervai/nhp/issues/1143).

Watched API calls (`eventSource = cloudtrail.amazonaws.com`):

| Event | Why it matters |
|-------|----------------|
| `StopLogging` | Halts log delivery without deleting the trail |
| `DeleteTrail` | Removes the trail entirely |
| `UpdateTrail` | Can redirect logs to an attacker bucket or disable validation |
| `PutEventSelectors` | Narrows a trail's scope to blind it without stopping it |

### Delivery

The rule targets the main alerts SNS topic (the on-call page path), formatted
for AWS Chatbot — the same delivery shape as the GuardDuty Slack target, and
gated on the same `enable_slack_target`. It is deliberately independent of
**this module's** trail (`enable_cloudtrail`): the API-call events reach the
default event bus while *some* us-east-2 trail is logging management events
(this module's trail, the org trail, or the SCP-locked sandbox trails), so it
also protects trails this module does not own. The call that stops the *last*
such trail is itself captured and pages (best-effort — EventBridge delivery is
at-least-once and the event must be emitted while a trail is still logging, so
treat this as closing the obvious blind spot, not a hard guarantee).

> **Region scope:** control-plane CloudTrail calls are emitted in the trail's
> home region. The rule runs in the module's region (`us-east-2`), which is the
> home region of the canonical, hardened trails — `layerv-nhp-prod-trail` and
> `layerv-nhp-sandbox-trail` — so those **are** covered today. The one trail not
> covered is the redundant, unhardened `layerv-prod-trail` (homed in `us-east-1`),
> which #1143 Bucket B deletes; tampering with it alone blinds nothing, because
> the canonical and org trails still capture the same management events. The
> tamper defense is fully effective for prod's relied-upon trail now, and the
> us-east-1 residue closes out with Bucket B.

### Expected pages (legitimate trail changes)

The rule matches **any** principal — including the Terraform/CI deploy role —
on purpose: a compromised deploy role is exactly the threat a tamper alert
exists to catch, so it is deliberately *not* excluded (an `anything-but` carve
on `userIdentity.arn` would create a blind spot, and the assumed-role session
ARN format makes such a carve fragile anyway). The practical consequences:

- A normal `terraform apply` only emits `UpdateTrail` when it actually changes
  the account-local trail's config — rare in steady state, so day-to-day noise
  is low. `StopLogging`/`DeleteTrail` are the high-signal events; `UpdateTrail`
  is the noisy one.
- The **#1143 Bucket B consolidation** deletes/reconfigures trails and *will*
  page repeatedly. Run it in an announced maintenance window and expect the
  pages — do not let on-call tune them out as a standing pattern.

### Responding to a Tamper Alert

1. **Confirm intent.** A blank `errorCode` in the alert means the call
   *succeeded* — logging actually changed. A populated `errorCode` (e.g.
   `AccessDenied`, expected in sandbox where an SCP blocks trail mutation) means
   the attempt was *blocked* but still worth investigating.
2. **Identify the caller** from the alert's `userArn` and source IP. If it isn't
   a known operator or pipeline, treat as an active intrusion.
3. **Contain:** rotate the caller's credentials and re-enable logging
   (`aws cloudtrail start-logging --name <trail>`).

### Testing

Trigger a benign watched call and confirm the page lands:

```bash
# Prod (no SCP on trail mutation): a successful change → blank errorCode.
AWS_PROFILE=layerv-prod aws cloudtrail update-trail \
  --name layerv-nhp-prod-trail --no-include-global-service-events  # then revert

# Sandbox: cloudtrail:UpdateTrail is SCP-blocked, so the call is DENIED — but
# the denied attempt still emits a CloudTrail event, so the alert STILL fires
# (with errorCode=AccessDenied). This is the better test: it proves blocked
# attempts are caught, not just successful ones.
AWS_PROFILE=layerv aws cloudtrail update-trail --name layerv-nhp-sandbox-trail \
  --no-include-global-service-events

# PutEventSelectors render check: re-apply the trail's CURRENT selectors (a
# config no-op that still emits the event). This is the one event whose trail
# name comes from requestParameters.trailName, so it proves the
# <trailName><trailNameSel> coalescing renders correctly (not `nullname`).
sel=$(AWS_PROFILE=layerv-prod aws cloudtrail get-event-selectors \
  --trail-name layerv-nhp-prod-trail --query EventSelectors --output json)
AWS_PROFILE=layerv-prod aws cloudtrail put-event-selectors \
  --trail-name layerv-nhp-prod-trail --event-selectors "$sel"
```

On the **first** successful (prod) test, confirm the Chatbot message renders the
`Error code` field as blank rather than a literal `null` — the "blank = call
succeeded" UX depends on EventBridge substituting an absent `$.detail.errorCode`
with an empty string. The placeholder sits inside a quoted JSON value, so even an
odd substitution can't malform the message, but verify the wording reads right.
Also confirm a `PutEventSelectors` event shows the trail name (it is sourced from
`requestParameters.trailName`, not `.name` like the other three events).

> The `trail` field is expected to look different across event types:
> `StopLogging`/`DeleteTrail`/`UpdateTrail` usually render the **full trail ARN**
> (CloudTrail populates `requestParameters.name` with the ARN), while
> `PutEventSelectors` renders the **short name**. Both are correct — don't flag
> the ARN form as a bug. A blank or literal `nullname`/`namenull`, however, *is*
> a transformer regression.

## CloudTrail Log Integrity

The trail this module owns writes to a versioned, KMS-encrypted S3 bucket. An
optional break-glass delete guard
(`cloudtrail_bucket_delete_guard_role_arns`) attaches a bucket-policy `Deny` on
`s3:DeleteObject`/`DeleteObjectVersion` for every principal except the listed
roles, so an attacker holding `s3:Delete*` cannot destroy audit history.
CloudTrail's own writes and S3 lifecycle expiration are unaffected (lifecycle
deletes are performed by the S3 service, not evaluated against the bucket
policy). The guard is **off by default** (empty list) to avoid a lockout when no
break-glass role is defined.

The guard intentionally scopes to object deletion only — it does **not** cover
`s3:PutBucketPolicy`, so this Terraform keeps managing the policy, but a
principal with bucket-policy-write could strip the guard before deleting. **S3
Object Lock** is the stronger follow-up that closes that residual path. Also note
the guard is keyed on `aws:PrincipalArn`, which is the IAM **role** ARN (not the
STS `assumed-role/…/SESSION` session ARN) and is present for the account root —
see the `cloudtrail_bucket_delete_guard_role_arns` variable for the allowlist
format gotchas.

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
- Streamed to a CloudWatch Logs group for real-time metric filters/alarms
- Tamper detection + log-integrity guard — see [CloudTrail Tamper Detection](#cloudtrail-tamper-detection) and [CloudTrail Log Integrity](#cloudtrail-log-integrity)

#### CloudTrail CIS alarms

`terraform/modules/security/cloudtrail_metric_filters.tf` defines the CIS
AWS Foundations Benchmark **v1.4.0** CloudWatch monitoring controls as
metric filters + alarms on the CloudTrail log group. Implementing them
flips the corresponding Security Hub controls (CloudWatch.1/4/5/6/7/8/9/
10/11/12/13/14) from FAILED to PASSED.

- **Gating:** created only when `enable_cloudtrail = true`. That is prod
  today (sandbox has CloudTrail disabled), so these are prod-only until
  sandbox enables a trail.
- **Routing:** all alarms notify `alerts_sns_topic_arn` (the shared
  monitoring topic — email + Slack via Chatbot). A control only PASSes
  when its alarm notifies a subscribed topic, so this is part of the
  control, not cosmetic.
- **Expect a paired page on trail tampering.** The `cloudtrail_config_changes`
  alarm (CloudWatch.5) overlaps by design with the
  `enable_cloudtrail_tamper_alerts` EventBridge rule (see
  [CloudTrail Tamper Detection](#cloudtrail-tamper-detection)): a real
  Stop/Delete/Update trail event fires **both**. This is intentional
  defense-in-depth (the EventBridge rule also covers SCP-locked /
  cross-region trails, and CloudWatch.5 is required for the CIS control),
  not a misconfiguration — don't "fix" the duplicate by removing either.
- **Frozen patterns:** Security Hub fails the control if the exact
  CIS-prescribed filter pattern is not used and forbids extra terms. Do
  **not** add noise-reduction terms to a `pattern` — a "helpful" edit
  silently reverts the control to FAILED. Tune noise via `Severity` /
  downstream subscription filtering instead. This invariant is enforced
  at PR time by the `cis-metric-filter-patterns` lint
  (`.github/scripts/check-cis-metric-filter-patterns.py` +
  `tests/lints/cis-metric-filter-patterns/golden.json`): editing a
  `pattern` fails CI unless the golden is updated in the same PR (a
  deliberate, re-validated change), so a typo can't slip through to a
  FAILED control ~18h after the prod apply.
- **Severity:** `page` for rare high-signal events (root usage,
  CloudTrail tampering, CMK disable/delete); `ticket` for the
  change-detection controls (IAM/SG/NACL/VPC/route/gateway/config/
  S3-policy), which fire on routine `terraform apply` from CI and exist
  primarily for CIS posture + forensics. To halve routine-apply noise,
  `ok_actions` (the "resolved" notification) is wired only for `page`
  alarms; `ticket` alarms notify on ALARM only and self-clear silently.
  Splitting the `ticket` stream onto its own lower-urgency destination
  (so apply noise can't desensitize operators to the `page` stream) is a
  near-term follow-up tracked in
  [#2353](https://github.com/layervai/nhp/issues/2353).
- **Not included:** CloudWatch.2 (unauthorized API) and CloudWatch.3
  (console sign-in without MFA) are manual-only controls under CIS
  v1.4.0, so a metric filter does not move them; they are omitted from
  the auto-PASS set. CloudWatch.2 is still covered as a custom
  detection below; console-sign-in-without-MFA is covered separately by
  `console_login_mfa_alarm.tf`.

To verify after a prod apply: in Security Hub, filter the CIS v1.4.0
standard by the `CloudWatch.*` controls and confirm they report PASSED
(allow up to ~18 hours for the first periodic evaluation).

#### CloudTrail custom detections

`terraform/modules/security/cloudtrail_custom_detection_filters.tf` adds
the #1140 finding-specific signals that are useful for detection but are
not part of the CIS exact-pattern set:

- Unauthorized API calls (`UnauthorizedAPICallCount`)
- IAM trust policy edits via `UpdateAssumeRolePolicy`
- Direct `kms:Decrypt` calls against the sensitive CMKs passed in
  `cloudtrail_sensitive_kms_direct_decrypt_detections` (root wires the NHP
  secrets and logs keys separately by default)

These filters use the same CloudTrail log group, metric namespace, and
alerts SNS topic as the CIS alarms. `ticket` custom alarms still notify that
shared topic on ALARM; they only omit OK notifications. The secrets-key
decrypt alarm starts at one direct call because direct decrypts should be
rare, while the logs-key decrypt alarm starts at a higher ticket threshold to
avoid sending a shared-alert notification for one expected role-direct logs
decrypt. The sensitive-key signal is intentionally `Decrypt`-only; it does
not cover `GenerateDataKey`, `ReEncrypt`, or `Encrypt` usage. The filters stay
in a separate file so tuning custom patterns cannot accidentally break
Security Hub's CIS grading.

The `UpdateAssumeRolePolicy` detector deliberately does not exclude the
Terraform/CI deploy role. A compromised deploy role modifying trust policy is
inside the #1140 threat model, so expected apply-time events should be treated
as ticket-class apply evidence rather than filtered out of the detection.

---

## Configuration Reference

### Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `enable_guardduty` | `true` | Enable GuardDuty detector |
| `enable_guardduty_alerts` | `false` | Enable EventBridge alerting |
| `guardduty_alert_severity_threshold` | `4` | Minimum severity (1-8) |
| `guardduty_alert_emails` | `[]` | Email addresses for alerts |
| `enable_slack_target` | `true` | Enable Slack-optimized target (also gates CloudTrail tamper alerts) |
| `enable_cloudtrail` | `true` | Enable the account-local CloudTrail trail |
| `enable_cloudtrail_tamper_alerts` | `true` | Page on-call when a trail is disabled/deleted/reconfigured |
| `cloudtrail_bucket_delete_guard_role_arns` | `[]` | Break-glass roles exempt from the log-delete `Deny`; empty = guard off |

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
- All storage encrypted with KMS CMKs (documented exceptions below).
  - `terraform/modules/bootstrap-alb/`'s access-log + Athena-results
    buckets are SSE-S3, not CMK. AWS ALB log delivery does NOT
    support cross-account CMKs, and the Athena bucket follows the
    same shape for consistency. Rationale + suppression target lives
    inline at `access_logs.tf` — point AWS Config / scanner
    suppressions there. Relevant AWS Config rule names:
    `s3-default-encryption-kms` /
    `s3-bucket-server-side-encryption-enabled`.
  - The Terraform remote-state buckets (`layerv-terraform-state-<acct>`)
    are SSE-S3/AES256 (finding [#1128](https://github.com/layervai/nhp/issues/1128)).
    These are bootstrap-layer and unmanaged by Terraform, so the move to
    SSE-KMS is an operator/out-of-band migration tracked in
    [`runbooks/tfstate-kms-migration.md`](runbooks/tfstate-kms-migration.md).
    Until then, this is a known AES256 exception: the `s3-default-encryption-kms`
    AWS Config rule (which evaluates the bucket *default*, not individual
    objects) keeps flagging both state buckets through the (possibly multi-week)
    migration window — accept it as known-noise tracked by #1128 (suppress
    against #1128 if it pages), not a new regression. Note the rule clears only
    when the bucket *default* flips to `aws:kms` (the runbook's **Phase B**); the
    backend `kms_key_id` cutover (Phase C) encrypts the state *objects* for the
    audit trail but does not by itself flip this Config rule. Remove this bullet
    when #1128 closes (i.e. after Phase B has run in both accounts).
- IMDSv2 required on EC2.
- AC private keys NEVER in etcd — only Secrets Manager.

### Supply-chain: SBOM and build attestations

Every `nhp-server` and `nhp-ac` image built by `build-and-push.yml` produces a
Software Bill of Materials (SBOM) and, on main builds, signed build
attestations. This is the integrity half of the supply-chain hardening tracked
in [#1148](https://github.com/layervai/nhp/issues/1148) (SBOM #1333,
SLSA provenance #1335). The remaining piece — verifying these at deploy/boot
time — is tracked separately in
[#1334](https://github.com/layervai/nhp/issues/1334); today the attestations
are *produced and queryable* but not yet *enforced* as a deploy gate.

**What is produced**

- **SBOM (SPDX-JSON)** for each image, generated by `syft` from the same local
  image the Trivy scan runs against. Generated on every build (PRs included).
- **SLSA build provenance** (`actions/attest-build-provenance`) binding the
  image digest → workflow run → commit SHA. Main builds only.
- **SBOM attestation** (`actions/attest-sbom`) attaching the SBOM to the image
  digest. Main builds only.

All three are non-blocking (`continue-on-error`): a failure never breaks the
build → scan → push path.

**Retrieval — incident response**

1. **Workflow artifact (always available, the primary path).** Each build
   uploads a `sbom-server` / `sbom-ac` artifact (SPDX-JSON, 30-day retention)
   to its `Build and Deploy NHP` run:

   ```bash
   # Find the run that built a given commit, then pull the SBOM artifact:
   gh run list --workflow build-and-push.yml --commit <SHA> --limit 1
   gh run download <RUN_ID> --name sbom-server --dir ./sbom
   ```

2. **OCI referrer (main builds, best-effort).** When ECR accepts the OCI 1.1
   referrers push, the SLSA provenance and SBOM attestations live alongside the
   image and can be verified by digest. The examples below use the server image
   (`layerv/nhp-server` / `sbom-server`); for the AC image substitute
   `layerv/nhp-ac` / `sbom-ac`. The provenance check needs only `gh` (which an
   operator already has); the SBOM download uses `cosign`, a separate install —
   if you don't have it, use the workflow artifact in (1), which is the
   `gh`-only route and needs no extra tooling.

   ```bash
   # Provenance: image digest -> this repo's CI -> source commit (gh only)
   gh attestation verify oci://<ecr-registry>/layerv/nhp-server@sha256:<digest> \
     --repo layervai/nhp

   # Download the attached SBOM attestation (requires cosign — separate install)
   cosign download attestation <ecr-registry>/layerv/nhp-server@sha256:<digest>
   ```

   If the referrer push was unsupported/failed for a given image, fall back to
   the workflow artifact in (1). The provenance is also retained in GitHub's
   attestation store regardless of the registry push.

**Deploy-time verification (#1334 Phase 1)**

The deploy paths verify the SLSA provenance of the image they are about to roll,
before it ships. The shared composite action
[`.github/actions/verify-image-attestation`](../.github/actions/verify-image-attestation/action.yml)
resolves the tag's immutable digest in ECR and runs `gh attestation verify` with
a `--cert-identity-regex` pinned to `build-and-push.yml` **on `main`**, so only
an image built by *this repo's* CI on main passes. It is wired
into the **deploy jobs** of `blue-green-deploy.yml` (sandbox server/AC),
`canary-deploy.yml` (prod canary, cross-account to sandbox ECR), and
`promote-to-prod.yml` (the prod-promotion gate) — pipeline-side, so a failure
aborts a deploy rather than crash-looping a running fleet. Instance-boot
verification (`user_data.sh.tpl`) is the separate, later Phase 2.

This is a **two-stage burn-in**, mirroring `NHP_INTERNAL_AUTH_REQUIRE`:

- **`audit` (default).** Runs the verification, logs the outcome, and **never
  blocks a deploy**. Pre-#2339 images have no attestation and would all fail an
  enforcing gate, so audit is the only safe default until attested images
  accumulate.
- **`enforce`.** A genuine *no-valid-attestation verdict* **fails the deploy
  job**. Infrastructure/tooling errors (AWS throttle, `docker login` blip,
  GitHub API 403/5xx) **fail open** with a loud warning even under enforce — a
  transient error must not block a prod promotion the way a real missing
  attestation does. The mode value is normalized (trimmed + lowercased); an
  unrecognized value defaults to `audit` with a warning, so a typo during the
  flip can't wedge every deploy.

The mode is read from the `IMAGE_ATTESTATION_VERIFY_MODE` repo/environment
variable (unset → `audit`). To flip fleet-wide after soak:

```bash
# Pre-req: confirm recent server+AC images carry provenance (post-#2339 builds).
gh attestation verify \
  "oci://<sandbox-ecr>/layerv/nhp-server@sha256:<recent-digest>" \
  --repo layervai/nhp \
  --cert-identity-regex '^https://github\.com/layervai/nhp/\.github/workflows/build-and-push\.yml@refs/heads/main$' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com   # expect: success

# Flip to enforce — ONLY after the hard gates below are all satisfied:
gh variable set IMAGE_ATTESTATION_VERIFY_MODE --repo layervai/nhp --body enforce
# Rollback: gh variable set IMAGE_ATTESTATION_VERIFY_MODE --body audit
```

**Hard gates before flipping to `enforce` (all must hold — not just a clean
soak):**

1. The identity/ref-mismatch classifier is **finalized and fail-closed**
   (the [#1334](https://github.com/layervai/nhp/issues/1334) acceptance item).
   Until then, `enforce` does **not** actually guarantee built-by-this-repo's-CI-
   on-`main` — an attestation signed by the wrong workflow/ref currently
   classifies as `error` (fail-open). This is the load-bearing gate.
2. A soak window with `ATTEST_RESULT=pass` across all deploy paths and **no**
   `fail`/`error` (see below).
3. The cross-account ECR pull grant is confirmed present (see below).

The verify step uses the default `GITHUB_TOKEN`; each deploy workflow grants it
`attestations: read`. Each run emits one greppable marker —
`ATTEST_RESULT=pass|fail|error` — so soak-readiness is mechanical rather than a
visual log scan. Before flipping to `enforce`, confirm recent audit runs across
all deploy paths (server, AC, canary, promote) show `ATTEST_RESULT=pass` with no
`fail` (a real no-attestation verdict, which *would* block under enforce) and no
`error` (an infra/permission issue — fails open under enforce, but means the
gate isn't actually verifying and must be fixed first). The verify step needs
ECR **login + pull** (`ecr:GetAuthorizationToken` + `BatchGetImage`/
`GetDownloadUrlForLayer`), not just `DescribeImages`, so the manifest fetch can
run:

- **Same-account paths (blue-green, promote)** use `AWS_ROLE_ARN` — the same
  role `build-and-push.yml` uses to `amazon-ecr-login` and `docker push`, which
  inherently has login + pull, so no extra grant is needed.
- **Cross-account prod canary** authenticates with the prod role against the
  sandbox registry, so confirm the **sandbox ECR repo policy** still grants the
  prod account `ecr:BatchGetImage`/`GetDownloadUrlForLayer`.

A permission gap on either surfaces only as `ATTEST_RESULT=error` (fail-open).

Two classifier caveats to resolve **before** flipping to `enforce` (tracked in
[#1334](https://github.com/layervai/nhp/issues/1334)):

- **Identity/ref-mismatch is unvalidated.** Today an attestation that exists but
  whose signer identity/ref doesn't match classifies as `error` (fail-open), not
  a blocking verdict. The exact `gh` wording for that case (and for the various
  infra errors) can't be observed until attested images exist. Against a real
  post-#2339 image, capture `gh`'s output for an identity mismatch and finalize
  the verdict-vs-infra split so a wrong-CI attestation fails **closed** under
  enforce.
- **The verdict classification greps `gh`'s human-readable output**, so it is
  coupled to the installed `gh` version. Re-validate the verdict grep against the
  runner's `gh` after a `gh`/runner image bump (mirrors the `run-fuzz.sh`
  deadline-race-signature caveat in `CLAUDE.md`).

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
  `/nhp/internal/ac-revocations/sweep[/<acId>]` is permanently strict because
  it triggers destructive AC disconnects; its HMAC verification failures
  increment `InternalAuthFailStrict` even before the broader
  `NHP_INTERNAL_AUTH_REQUIRE` rollout flag flips to strict. A server missing
  signer configuration rejects the sweep before verification and emits
  `InternalAuthSignerUnavailable` instead, so dashboards can separate operator
  misconfiguration from bad caller signatures.
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
