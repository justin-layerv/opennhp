# Runbook: qurl-resources DynamoDB Query failures

## What fired

**`qurl-dynamodb-query-failures`** — the qurl-service's own OpenTelemetry instrumentation reported a sustained rate of failed Query operations against the `qurl-resources` DynamoDB table exceeding `0.05/s` over a 5-minute window.

## What it means

This alert is the **direct, narrow signal for the 2026-03-24 incident class**. On that date, terraform PR #877 removed the legacy `owner-target-index` GSI while the deployed qurl-service still queried it. Every `POST /v1/qurls` called `FindByOwnerAndTarget`, which raised a `ValidationException` from DynamoDB, which propagated as a generic HTTP 500. **This alert would have fired within 5 minutes of the bad terraform apply.**

The alert is pinned to:
- `aws_dynamodb_table=~".*qurl-resources"` — only the resources table
- `aws_dynamodb_operation="Query"` — only Query operations (not Get/Put/Update, which legitimately fail with `ConditionalCheckFailedException` in normal operation)
- `aws_dynamodb_success="false"` — only failures

This narrow filter is intentional. A broader alert on `aws_dynamodb_operation_total{success="false"}` would false-fire constantly because of `ConditionalCheckFailedException` from `attribute_not_exists` checks in PutItem, which is the qurl-service's primary mechanism for atomic resource creation.

## First action: assume schema drift, prove it's not

When this alert fires, the most likely cause is a schema mismatch between the deployed binary and the live DynamoDB schema:

1. **Check for recent terraform applies**: `gh run list -R layervai/nhp -w promote-to-prod.yml --limit 5`. Anything completed in the last hour, especially with `terraform-apply: success` and `deploy-qurl: skipped`, is a strong suspect.
2. **Run the schema-check subcommand against the live schema**:
   ```bash
   # In a prod-credentialed shell
   AWS_PROFILE=layerv-prod aws dynamodb describe-table --table-name layerv-nhp-prod-qurl-resources \
     --query 'Table.GlobalSecondaryIndexes[].IndexName' --output text
   ```
   Compare against the GSIs the deployed qurl-service expects. If you have the deployed qurl-api binary handy:
   ```bash
   docker run --rm -v $(pwd)/plan.json:/plan.json $ECR_QURL_REPO:$PROD_TAG schema-check --plan /plan.json
   ```
   (Generate `plan.json` from the most recent terraform plan artifact in the workflow run.)
3. **If schema drift is confirmed**: roll terraform back to the previous state. The destructive apply should not have been allowed; investigate why `qurl-schema-compat` did not block it (was the job skipped? was the gate not enforced? was the binary used in the gate older than the deployed binary?).

## If it's not schema drift

Other causes of Query failures on qurl-resources:

| Symptom | Cause | Action |
|---|---|---|
| Throttling errors in DynamoDB metrics | On-demand capacity burst exceeded | Check `dynamodb_throttled_qurl-resources` CloudWatch alarm; raise burst limits or switch to provisioned capacity for sustained load |
| `ResourceNotFoundException` | Table itself was deleted (catastrophic) | Restore from backup; declare a Sev1 incident |
| `InternalServerError` from DynamoDB | AWS-side fault (rare) | Check AWS Personal Health Dashboard for us-east-2 DynamoDB issues |
| Network timeouts | VPC endpoint or NAT gateway issue | Check VPC endpoint health for `com.amazonaws.us-east-2.dynamodb` |

## How to prevent this class of incident

Three independent layers should catch it before customers do:

1. **`qurl-schema-compat` workflow job** in `promote-to-prod.yml` (separate PR — refuses to advance to terraform-apply if the post-apply schema doesn't satisfy the deployed binary's index requirements)
2. **Periodic schema reconciler in `internal/health`** (separate qurl PR — checks live schema every 60s and fails `/health/ready` on drift)
3. **This alert** (the backstop — fires within 5 minutes if both prevention layers fail)

If only this alert caught a real drift event, that's a sign the prevention layers were bypassed. File a post-incident artifact and investigate why.
