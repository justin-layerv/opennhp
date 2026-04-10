# Verify qurl-service schema-drift prevention (sandbox)

## What this runbook is for

End-to-end verification that the three independent layers preventing the 2026-03-24 incident class are actually working in production. Run this against a sandbox cell quarterly, or after any change to the prevention infrastructure (the schema registry, the workflow gate, or the periodic reconciler).

The 2026-03-24 incident: PR #877 removed the legacy `owner-target-index` GSI from `qurl-resources` while production qurl-service was still running an older image whose `FindByOwnerAndTarget` query path depended on it. The promote-to-prod workflow ran with `run_terraform=true, deploy_qurl=false`. Terraform applied; every deploy and smoke-test job was skipped. **`POST /v1/qurls` returned 500 for over a week before customers noticed.**

The three layers this runbook verifies:

| # | Layer | Where | Expected behavior |
|---|---|---|---|
| 1 | **Workflow gate** — `qurl-schema-compat` job | `nhp/.github/workflows/promote-to-prod.yml` | Runs between `terraform-plan` and `terraform-apply`. Pulls the qurl-service image about to be in prod, runs `qurl-schema-check --plan tfplan.json`, fails the workflow on schema mismatch. |
| 2 | **Runtime reconciler** — `dynamodb_schema` health check | `qurl-service/internal/health/dynamodb_schema.go` | Background goroutine calls `DescribeTable` every 60s. On drift, `/health/ready` flips to `503`, ALB de-registers the task, ECS deploy circuit breaker rolls back. |
| 3 | **Detection alerts** — Grafana rules + Loki | `nhp/terraform/modules/grafana-dashboards/alerts.tf` | Within 5 minutes of the first 500, `qurl-error-logs-spike` (Loki) and `qurl-dynamodb-query-failures` (Prometheus) both fire and page the existing prod-alerts channel. |

The runbook simulates PR #877 as closely as possible against a sandbox cell, then verifies each layer catches it independently.

## Prerequisites

- Sandbox AWS access (`AWS_PROFILE=layerv`)
- `gh` CLI authenticated against `layervai/nhp` with `workflow:write`
- A sandbox cell to test against. Default: `cell0`. **Do NOT run this against production.**
- Approximately 30 minutes of focused time. Layer 1 takes ~5 min; layer 2 takes ~5 min plus a 60s wait; layer 3 takes ~10 min plus the 5-min alert evaluation window.
- A Slack/email channel where the existing prod-alerts SNS topic posts. You'll watch it during layer 3.

## Setup

```bash
# Sandbox cell to test against. Override if your team uses a different cell.
export CELL_ID=cell0

# The logical table whose GSI we'll temporarily remove. qurl-resources is
# the right choice — it has the most GSIs, and missing them produces an
# obvious 5xx storm on POST /v1/qurls (mirroring the original incident).
export TARGET_TABLE=qurl-resources

# The GSI to remove. owner-target-hash-index matches the production
# failure mode most closely (FindByOwnerAndTarget breaks immediately).
export TARGET_GSI=owner-target-hash-index

# Get the prefixed runtime table name for the sandbox cell.
export PREFIXED_TABLE="layerv-nhp-sandbox-${CELL_ID}-${TARGET_TABLE}"

# Confirm we're on sandbox, not prod.
AWS_PROFILE=layerv aws sts get-caller-identity --query Account --output text
# Expect: 767397897469 (sandbox). DO NOT proceed if this prints 235500187906 (prod).
```

## Layer 1 — Workflow gate blocks `terraform-apply`

This is the primary defense. The `qurl-schema-compat` job fails before `terraform-apply` even runs, so no destructive change reaches AWS.

### Step 1.1 — Create a contrived destructive terraform PR

In a temporary branch, edit `terraform/modules/dynamodb/main.tf`. Find the `aws_dynamodb_table.qurl_resources` block, locate the `global_secondary_index` block named `"owner-target-hash-index"`, and **comment it out** (don't delete it — we'll restore it via `git checkout` afterwards):

```hcl
# global_secondary_index {
#   name            = "owner-target-hash-index"
#   hash_key        = "owner_id"
#   range_key       = "target_url_hash"
#   projection_type = "ALL"
# }
```

Open the PR with the title `chore(terraform): VERIFY-PREVENTION-DO-NOT-MERGE remove owner-target-hash-index`. Mark it as a draft to make accidental merging impossible.

### Step 1.2 — Trigger promote-to-prod against sandbox

```bash
# IMPORTANT: this is the exact PR #877 flag combination — terraform with no qurl deploy.
# In production this would have caused the original incident; in sandbox the
# qurl-schema-compat job MUST block it.
gh workflow run promote-to-prod.yml -R layervai/nhp --ref <your-branch> \
  -f image_tag=$(git rev-parse HEAD) \
  -f run_terraform=true \
  -f deploy_qurl=false \
  -f cell_id=$CELL_ID
```

Wait for the run to start, then watch it:

```bash
gh run list -R layervai/nhp -w promote-to-prod.yml --limit 1
gh run watch <run-id> -R layervai/nhp
```

### Step 1.3 — Verify the gate failed

The workflow should fail at the `QURL Schema Compatibility Check` job, **before** `terraform-apply` ran. Verify:

```bash
gh run view <run-id> -R layervai/nhp --json jobs --jq '.jobs[] | {name, conclusion, status}'
```

Expected output:
- `Promotion Manifest` → success
- `Preflight Checks` → success
- `Terraform Plan (prod)` → success
- `QURL Schema Compatibility Check` → **failure**
- `Terraform Apply (prod)` → **skipped** (not "failure" — the gate prevented it from running at all)

Pull the gate's logs to confirm the diagnostic is precise:

```bash
gh run view <run-id> -R layervai/nhp --log | grep -A 20 "QURL Schema Compatibility Check"
```

Expected diagnostic output (verbatim from the schema-check binary):

```
qurl-schema-check: required GSI(s) missing in post-apply state:
  - table "qurl-resources" index "owner-target-hash-index" (index will be removed (not in plan's planned_values))

Either:
  1. Bump the qurl-service deploy to an image whose code no longer needs the missing index, OR
  2. Restore the index in terraform.
```

**Layer 1 PASS criteria:** workflow failed at `qurl-schema-compat`, `terraform-apply` was skipped, the diagnostic names `qurl-resources` and `owner-target-hash-index` precisely.

### Step 1.4 — Layer 1 cleanup

Close the verification PR (do NOT merge). The contrived terraform change never reached AWS because the gate did its job. Nothing to revert.

```bash
gh pr close <pr-number> -R layervai/nhp -c "Layer 1 verification complete — qurl-schema-compat blocked the destructive apply as expected. See [runbook](docs/runbooks/verify-qurl-schema-prevention.md)."
```

## Layer 2 — Periodic reconciler de-registers the task

This is the runtime backstop for the case where terraform is applied out-of-band (manual `terraform apply`, AWS-side change, future workflow path that bypasses layer 1). Verifying it requires actually mutating the live DynamoDB schema in sandbox — the gate cannot help here because we are explicitly going around it.

### Step 2.1 — Snapshot the live schema before mutating

```bash
AWS_PROFILE=layerv aws dynamodb describe-table \
  --table-name "$PREFIXED_TABLE" \
  --query 'Table.GlobalSecondaryIndexes[*].IndexName' \
  --output json > /tmp/sandbox-gsis-before.json
cat /tmp/sandbox-gsis-before.json
```

Save this output — you'll restore from it in step 2.5.

### Step 2.2 — Verify the qurl-service is currently healthy

Find the sandbox qurl-service ALB target group health endpoint. The service exposes `/health/ready` on its container port; the ALB forwards externally on the qurl API URL.

```bash
# Replace with your sandbox qurl API URL.
export QURL_SANDBOX_URL=https://api.layerv.xyz
curl -sf "$QURL_SANDBOX_URL/health/ready" | jq '{status, checks: .checks | to_entries | map({name: .key, status: .value.status})}'
```

Expected: `status: "healthy"`, every check `pass` (or `skip` for unconfigured optional checks). The `dynamodb_schema` checker should be in the list with `status: pass`.

### Step 2.3 — Remove the GSI directly via the AWS API

This is the destructive step. Acceptable on sandbox, **never on prod**.

```bash
AWS_PROFILE=layerv aws dynamodb update-table \
  --table-name "$PREFIXED_TABLE" \
  --global-secondary-index-updates '[{"Delete": {"IndexName": "'"$TARGET_GSI"'"}}]'
```

Wait for the update to complete:

```bash
AWS_PROFILE=layerv aws dynamodb wait table-exists --table-name "$PREFIXED_TABLE"

# Confirm the GSI is gone:
AWS_PROFILE=layerv aws dynamodb describe-table \
  --table-name "$PREFIXED_TABLE" \
  --query 'Table.GlobalSecondaryIndexes[*].IndexName' \
  --output json
# Expected: list does NOT contain "owner-target-hash-index"
```

### Step 2.4 — Verify the reconciler detects the drift within ~60s

Poll `/health/ready` every 5 seconds. Within ~60s of the GSI removal, the next reconcile tick should detect the drift and flip the `dynamodb_schema` checker to `fail`. Within another ~30s, the ALB should de-register the task and the URL should return 503.

```bash
for i in $(seq 1 24); do
  echo "[$(date +%H:%M:%S)] poll #$i:"
  curl -sf "$QURL_SANDBOX_URL/health/ready" | jq '{status, dynamodb_schema: .checks.dynamodb_schema}' || echo "(503 — task de-registered)"
  sleep 5
done
```

**Layer 2 PASS criteria:** within ~90 seconds of step 2.3:

1. The `dynamodb_schema` check transitions from `pass` to `fail`
2. The fail message names `qurl-resources` and `owner-target-hash-index` precisely
3. Eventually the entire `/health/ready` response transitions to `unhealthy` and then to a 503 (ALB de-registration)
4. The ECS service in the sandbox cell shows the task being replaced (CloudWatch / ECS console)

If the task does NOT get de-registered, the bug is in the ALB target group health check configuration or the ECS deploy circuit breaker. Verify both are still configured per `nhp/terraform/modules/qurl-service/main.tf`.

### Step 2.5 — Restore the GSI

```bash
AWS_PROFILE=layerv aws dynamodb update-table \
  --table-name "$PREFIXED_TABLE" \
  --attribute-definitions \
    AttributeName=owner_id,AttributeType=S \
    AttributeName=target_url_hash,AttributeType=S \
  --global-secondary-index-updates '[{
    "Create": {
      "IndexName": "owner-target-hash-index",
      "KeySchema": [
        {"AttributeName": "owner_id", "KeyType": "HASH"},
        {"AttributeName": "target_url_hash", "KeyType": "RANGE"}
      ],
      "Projection": {"ProjectionType": "ALL"}
    }
  }]'

# Wait for the GSI to be active (this can take 1-2 minutes for backfill).
AWS_PROFILE=layerv aws dynamodb wait table-exists --table-name "$PREFIXED_TABLE"
```

Then poll `/health/ready` again until it returns to `healthy`. The reconciler should pick up the restored GSI on its next tick (~60s).

If the new ECS task is still in a crashloop / unhealthy state and won't pick up the restored schema, **check the ECS service** — the deploy circuit breaker may have rolled the deploy back, in which case there's nothing to recover and the next deploy will succeed.

## Layer 3 — Detection alerts page within 5 minutes

This is the last-resort detection layer. If layers 1 and 2 both fail (the workflow was bypassed AND the reconciler was somehow disabled), the existing Grafana / Loki alerts must still page operators within 5 minutes of the first customer-facing 500.

Verifying this layer requires actually breaking the sandbox qurl-service so it serves 500s. The cleanest way is to repeat the GSI removal from layer 2, but **disable the reconciler first** (so layer 2 doesn't intervene) and let the service serve 500s long enough for the alerts to fire.

### Step 3.1 — Disable the periodic reconciler temporarily

The reconciler is gated by the `QURL_SCHEMA_RECONCILER_ENABLED` env var on the qurl-service ECS task definition (default `false`; set to `true` per environment after the IAM grant is confirmed). To exercise layer 3 cleanly, temporarily flip it back to `false` in the sandbox cell only:

```bash
export TASK_DEF_FAMILY="layerv-nhp-sandbox-${CELL_ID}-qurl-api"

# Read current task definition.
AWS_PROFILE=layerv aws ecs describe-task-definition \
  --task-definition "$TASK_DEF_FAMILY" \
  --query 'taskDefinition' > /tmp/sandbox-task-def.json

# Strip the read-only fields ECS rejects on register-task-definition,
# then flip QURL_SCHEMA_RECONCILER_ENABLED to "false" on the qurl-api
# container's environment array.
jq '
  del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)
  | .containerDefinitions |= map(
      if .name == "qurl-api" then
        .environment |= map(
          if .name == "QURL_SCHEMA_RECONCILER_ENABLED" then .value = "false" else . end
        )
      else . end
    )
' /tmp/sandbox-task-def.json > /tmp/sandbox-task-def-clean.json

AWS_PROFILE=layerv aws ecs register-task-definition \
  --cli-input-json file:///tmp/sandbox-task-def-clean.json

AWS_PROFILE=layerv aws ecs update-service \
  --cluster "layerv-nhp-sandbox-${CELL_ID}" \
  --service "${TASK_DEF_FAMILY}" \
  --task-definition "$TASK_DEF_FAMILY" \
  --force-new-deployment

# Wait for the new task to be RUNNING and STEADY before proceeding to 3.2.
AWS_PROFILE=layerv aws ecs wait services-stable \
  --cluster "layerv-nhp-sandbox-${CELL_ID}" \
  --services "$TASK_DEF_FAMILY"
```

Step 3.5 restores the env var to `true` and force-deploys again.

If you want to skip 3.1 entirely, layer 3 still fires — the Grafana rules don't depend on the reconciler being absent — but the time window is shorter because the task is also being de-registered, and the test becomes a layer 2 + layer 3 combined exercise rather than clean layer 3 isolation.

### Step 3.2 — Remove the GSI

Repeat step 2.3.

### Step 3.3 — Drive traffic to produce 500s

```bash
# A handful of requests to the broken endpoint. The exact endpoint to
# hit depends on which GSI you removed; for owner-target-hash-index,
# POST /v1/qurls is the failing path.
for i in $(seq 1 30); do
  curl -sf -X POST "$QURL_SANDBOX_URL/v1/qurls" \
    -H "Authorization: Bearer $SANDBOX_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"target_url":"https://example.com","expires_in":"1h"}' \
    -o /dev/null -w "[%{http_code}] " || true
  sleep 1
done
echo
```

Expected: a stream of `[500]` responses.

### Step 3.4 — Watch for the alert

In the existing prod-alerts channel (Slack / email subscribers configured by `nhp/terraform/modules/monitoring/`), within 5 minutes you should see two alerts fire (in roughly this order):

1. **`qurl-dynamodb-query-failures`** — direct narrow signal, fires within ~1-2 min of the first failed Query
2. **`qurl-error-logs-spike`** — broader signal, fires within ~5 min via the Loki rate threshold

Both alerts should:
- Name `qurl-api`, the `prod` environment label
- Link to the runbook `docs/runbooks/qurl-dynamodb-query-failures.md` or `qurl-error-logs.md`
- Route through the existing SNS topic to the existing Slack/email channel

### Step 3.5 — Layer 3 cleanup

1. Restore the GSI per step 2.5
2. If you disabled the reconciler in step 3.1, re-enable it: re-run the `register-task-definition` flow with `QURL_SCHEMA_RECONCILER_ENABLED=true`, force a new deploy, and `services-stable` wait
3. Confirm `/health/ready` returns to `healthy` (the `dynamodb_schema` checker should reappear with `status: pass`)
4. Confirm the alerts auto-resolve (Grafana rule status returns to `Normal` within the rule's `for:` window)

## Pass criteria summary

The runbook PASSES if **all three layers fired independently**:

- [ ] **Layer 1**: workflow gate blocked `terraform-apply` with the precise diagnostic naming the table and index
- [ ] **Layer 2**: periodic reconciler flipped `/health/ready` to `unhealthy` within ~90s of the live schema mutation, ECS de-registered the task
- [ ] **Layer 3**: Grafana alerts fired in the existing prod-alerts channel within 5 minutes of the first 500

If any layer fails, file an issue tagged `area: qurl`, `area: terraform`, or `area: monitoring` as appropriate, link this runbook, and include the failing layer's logs.

## When to run this runbook

- **Quarterly** as part of the team's ops cadence
- **After any change** to the prevention infrastructure:
  - The schema registry (`internal/repository/dynamodb/schema.go`)
  - The schema-check binary (`cmd/qurl-schema-check/`)
  - The workflow gate (`nhp/.github/workflows/promote-to-prod.yml::qurl-schema-compat`)
  - The periodic reconciler (`internal/health/dynamodb_schema.go`)
  - The Grafana rules (`nhp/terraform/modules/grafana-dashboards/alerts.tf`)
  - The ECS task definition or ALB target group health check
- **After any incident** where one of the prevention layers misfired (false positive or false negative)

## References

- The original incident: nhp PR #877, workflow run [23517653065](https://github.com/layervai/nhp/actions/runs/23517653065)
- Layer 1 implementation: nhp PR #1015 (`feat(ci): add qurl-schema-compat gate to promote-to-prod workflow`)
- Layer 2 implementation: layervai/qurl-service#249 (`feat(observability): add periodic DynamoDB schema reconciler`)
- Layer 2 prerequisite (IAM grant): nhp PR #1020 (`fix(terraform): grant qurl-service task role dynamodb:DescribeTable`)
- Layer 3 implementation: nhp PR #1008 (`feat(terraform): add Grafana alert rules and SLO doc for qurl-api`)
- Schema registry foundation: layervai/qurl-service#247 (`feat(repo): add DynamoDB schema registry and schema-check subcommand`)
- Tracking issue for the e2e regression test (this runbook): #1013
