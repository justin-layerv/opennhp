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

The reconciler is gated by the `QURL_SCHEMA_RECONCILER_ENABLED` env var on the qurl-service ECS task definition. The terraform module hardcodes this to `"true"` in [`terraform/modules/qurl-service/main.tf`](../../terraform/modules/qurl-service/main.tf), so the kill-switch path is a manual ECS task-definition override, not a tfvar flip.

**Before applying the override, pause every workflow that runs `terraform apply` against this environment AND every workflow that runs an ECS service deploy against the qurl-api service.** Quick reference for what to pause and why:

- **Lifecycle interaction:** `aws_ecs_service.qurl` has `lifecycle { ignore_changes = [desired_count, task_definition] }` (the `task_definition` element is the relevant one here). A `terraform apply` during the override does NOT immediately revert the running task — it just registers a new task-definition revision with the module default (`"true"`). The kill switch silently drops on the **next service deploy** that picks up the latest revision. So the failure window is "any service deploy following a terraform-apply during the override," not the terraform-apply itself.
- **What to pause (sandbox):** `build-and-push.yml` (auto-applies on every push to `main`) plus the `qurl-service` repo's own `build-and-deploy.yml` (auto-deploys on every qurl-service push to `main`).
- **What to pause (prod):** `promote-to-prod.yml` (manual `trigger-prod-deploy.sh` runs; prod promotion has no scheduled path).
- **Multi-cell:** these workflows apply across all cells in their environment, not per-cell, so disabling them halts drift-revert for every cell — that's expected for the override window. Today only `cell0` exists in each env, so this is operationally fine; revisit when the fleet expands beyond cell0 ([nhp#1697](https://github.com/layervai/nhp/issues/1697)).
- **Out-of-band paths:** a laptop-driven `terraform apply` or a `trigger-prod-deploy.sh` run with `run_terraform=true` will do the same — coordinate on Slack before either.

To exercise layer 3 cleanly, temporarily flip the env var to `false` in the sandbox cell only.

Run the block below as a single paste. Each path is its own function so any abort inside it (`return 1`) leaves your interactive shell intact — `$TASK_DEF_FAMILY` / `$CELL_ID` survive a failed step. The describe/register/update/wait pattern intentionally re-implements (rather than reuses) `.github/scripts/deploy-ecs-service.sh` because the runbook needs (a) env-var mutation, (b) capturing the pre-override TD ARN for an exact-ARN restore, and (c) disk persist — none of which the script exposes.

```bash
export TASK_DEF_FAMILY="layerv-nhp-sandbox-${CELL_ID}-qurl-api"

# Internal helper. Reads the running TD, asserts the env var is
# present, mutates it to $1, registers the new revision, and rolls
# the service. Used by both disable (§3.1) and enable (§3.5 fallback)
# paths. Caller is responsible for capture+persist; this helper does
# not touch shell state outside its own jq tempfiles.
_register_qurl_td_with_reconciler_val() {
  local desired="$1"
  local td_json="/tmp/${TASK_DEF_FAMILY}-task-def.json"
  local td_clean="/tmp/${TASK_DEF_FAMILY}-task-def-clean.json"

  AWS_PROFILE=layerv aws ecs describe-task-definition \
    --task-definition "$TASK_DEF_FAMILY" \
    --query 'taskDefinition' > "$td_json"

  # Loud-fail if the source TD doesn't already carry
  # QURL_SCHEMA_RECONCILER_ENABLED — the jq below only mutates an
  # existing entry (its `map` is not an append). Catches the case
  # where someone runs the block against an old rolled-back TD
  # revision that pre-dates the env var.
  if ! jq -e '.containerDefinitions[] | select(.name == "qurl-api") | .environment | map(select(.name == "QURL_SCHEMA_RECONCILER_ENABLED")) | length == 1' \
       "$td_json" > /dev/null; then
    echo "QURL_SCHEMA_RECONCILER_ENABLED not present in source TD — refusing to no-op" >&2
    return 1
  fi

  jq --arg val "$desired" '
    del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy, .deregisteredAt)
    | .containerDefinitions |= map(
        if .name == "qurl-api" then
          .environment |= map(
            if .name == "QURL_SCHEMA_RECONCILER_ENABLED" then .value = $val else . end
          )
        else . end
      )
  ' "$td_json" > "$td_clean"

  AWS_PROFILE=layerv aws ecs register-task-definition \
    --cli-input-json "file://$td_clean" > /dev/null
  AWS_PROFILE=layerv aws ecs update-service \
    --cluster "$TASK_DEF_FAMILY" --service "$TASK_DEF_FAMILY" \
    --task-definition "$TASK_DEF_FAMILY" --force-new-deployment > /dev/null
  AWS_PROFILE=layerv aws ecs wait services-stable \
    --cluster "$TASK_DEF_FAMILY" --services "$TASK_DEF_FAMILY" || {
      echo "services-stable wait timed out after deploy — investigate the new tasks via 'aws ecs describe-services ... --query services[0].deployments' before retrying" >&2
      return 1
  }
}

# §3.1 entry point: capture the running TD ARN, persist it for §3.5,
# then flip the env var to "false". Splitting capture from the §3.5
# fallback avoids re-capturing a false-flipped TD on re-entry.
disable_qurl_schema_reconciler() {
  # Wait for steady state — if a previous deploy is in-flight (e.g.,
  # a circuit-breaker rollback is settling), services[0].taskDefinition
  # returns the configured TD, not the running one. Polls 15s up to
  # a 10-min ceiling.
  AWS_PROFILE=layerv aws ecs wait services-stable \
    --cluster "$TASK_DEF_FAMILY" --services "$TASK_DEF_FAMILY" || {
      echo "services-stable wait timed out before capture — refusing to proceed" >&2
      return 1
  }

  local pre_override_td_arn
  pre_override_td_arn=$(AWS_PROFILE=layerv aws ecs describe-services \
    --cluster "$TASK_DEF_FAMILY" --services "$TASK_DEF_FAMILY" \
    --query 'services[0].taskDefinition' --output text)

  # AWS CLI returns the literal "None" on null fields and empty on
  # --query miss. Either way, refuse to proceed rather than persist
  # garbage and surprise §3.5 with `update-service --task-definition None`.
  if [[ -z "$pre_override_td_arn" || "$pre_override_td_arn" == "None" ]]; then
    echo "Failed to capture pre-override TD ARN (got: '$pre_override_td_arn') — refusing to proceed" >&2
    return 1
  fi
  PRE_OVERRIDE_TD_ARN="$pre_override_td_arn"

  # Persist to disk so the §3.5 restore survives tmux detach / terminal
  # crash / hour-long context switch. Filename namespaced by family so a
  # future prod-side dry-run won't collide. /tmp is tmpfs on most
  # modern distros and clears on reboot — the §3.5 fallback covers that.
  local persist_path="/tmp/${TASK_DEF_FAMILY}-pre-override-td-arn"
  echo "$PRE_OVERRIDE_TD_ARN" > "$persist_path"
  echo "Pre-override TD: $PRE_OVERRIDE_TD_ARN (also written to $persist_path)"

  _register_qurl_td_with_reconciler_val "false"
}

# §3.5 fallback entry point: re-register a fresh true-bearing TD
# revision and roll the service. No capture (the running TD is the
# false-flipped one); no persist (the §3.1 capture is what §3.5
# wants to restore from).
enable_qurl_schema_reconciler() {
  _register_qurl_td_with_reconciler_val "true"
}

disable_qurl_schema_reconciler
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
2. If you disabled the reconciler in step 3.1, re-enable it by pointing the service back at the exact TD ARN you captured at the start of §3.1. The shell variable falls back to the disk persist so this works across tmux detach / terminal crash. The block is wrapped in a function so any abort leaves the interactive shell intact:
   ```bash
   restore_qurl_pre_override_td() {
     local arn="${PRE_OVERRIDE_TD_ARN:-$(cat "/tmp/${TASK_DEF_FAMILY}-pre-override-td-arn" 2>/dev/null)}"
     if [[ -z "$arn" ]]; then
       echo "PRE_OVERRIDE_TD_ARN unavailable from shell or disk — use the fallback below" >&2
       return 1
     fi
     AWS_PROFILE=layerv aws ecs update-service \
       --cluster "$TASK_DEF_FAMILY" --service "$TASK_DEF_FAMILY" \
       --task-definition "$arn" --force-new-deployment > /dev/null
     AWS_PROFILE=layerv aws ecs wait services-stable \
       --cluster "$TASK_DEF_FAMILY" --services "$TASK_DEF_FAMILY" || {
         echo "services-stable wait timed out — deploy is not stabilizing; investigate before retrying" >&2
         return 1
     }
   }
   restore_qurl_pre_override_td
   ```
   This restore is positional-index-free and family-match-free by construction — `$PRE_OVERRIDE_TD_ARN` was the ARN running before the override, so re-pointing at it is unambiguous regardless of how many revisions registered in between or whether any sibling families exist.

   `aws ecs wait services-stable` polls every 15 seconds with a 40-poll (10-minute) ceiling; if it hangs to the timeout the deploy is not stabilizing — investigate the new tasks via `aws ecs describe-services ... --query 'services[0].deployments'` and the ECS event stream before retrying.

   **Fallback (only if `restore_qurl_pre_override_td` returned 1 because both the shell variable and the disk persist are gone — e.g., reboot lost both shell *and* tmpfs):**
   ```bash
   enable_qurl_schema_reconciler
   ```
   `enable_qurl_schema_reconciler` is the §3.1 helper that re-registers a fresh task-definition revision with `QURL_SCHEMA_RECONCILER_ENABLED=true` and rolls the service — no capture, no persist, just registers + deploys + waits. Re-pasting §3.1 will re-define it.

   Note: the §3.5 simple-restore block above and §3.1 both use `--cluster "$TASK_DEF_FAMILY"` because in this module the cluster name, ECS service name, and task-definition family name are all derived from `local.service_name` — see `aws_ecs_cluster.qurl`, `aws_ecs_service.qurl`, and `aws_ecs_task_definition.qurl` in `terraform/modules/qurl-service/main.tf` (grep for `local.service_name` to find them).
3. Confirm `/health/ready` returns to `healthy` (the `dynamodb_schema` checker should reappear with `status: pass`)
4. Confirm the alerts auto-resolve (Grafana rule status returns to `Normal` within the rule's `for:` window)

## Pass criteria summary

The runbook PASSES if **all three layers fired independently**:

- [ ] **Layer 1**: workflow gate blocked `terraform-apply` with the precise diagnostic naming the table and index
- [ ] **Layer 2**: periodic reconciler flipped `/health/ready` to `unhealthy` within ~90s of the live schema mutation, ECS de-registered the task
- [ ] **Layer 3**: Grafana alerts fired in the existing prod-alerts channel within 5 minutes of the first 500

If any layer fails, file an issue tagged `area: qurl`, `area: terraform`, or `area: monitoring` as appropriate, link this runbook, and include the failing layer's logs.

## Failure modes worth recognizing during activation

1. **Reconciler still dormant after a rolled-back deploy (specific to the first promote-to-prod after #1690 lands).** Delete this entry after the first successful post-#1690 prod deploy lands; tracked in [#1698](https://github.com/layervai/nhp/issues/1698).

   _TL;DR for incident-time skim: if a post-#1690 prod deploy hits the circuit breaker before any post-#1690 deploy succeeds, the running TD predates the env var and `/health/ready` won't show the `dynamodb_schema` checker — re-deploy and verify._

   **Mechanism.** The first post-#1690 `promote-to-prod` run lands `terraform-apply`, which registers a new task definition with `QURL_SCHEMA_RECONCILER_ENABLED=true`. If the subsequent ECS deploy's circuit breaker rolls back for an unrelated reason (new image crashloops, ALB unhealthy threshold reached during rollout, etc.), ECS reverts the service to the *previous* task-definition revision — which was registered before the env var was added. The reconciler stays dormant; `/health/ready` does not show the `dynamodb_schema` checker.

   **When the symptom stops recurring.** Once at least one post-#1690 deploy has fully succeeded, both the running revision and the rollback target carry the env var, and subsequent rolled-back deploys do not reproduce the symptom. If two or more consecutive deploys all hit the circuit breaker before any succeeds, the running revision stays at pre-#1690 and the symptom recurs.

   **Diagnostic.** If `/health/ready` doesn't show the checker after a deploy you believe succeeded, confirm the deploy actually completed (ECS service `runningCount == desiredCount` on the new revision, not stuck on the prior one) before assuming the activation itself failed.

2. **Reconciler still dormant in sandbox after the nhp PR merges.** `aws_ecs_service.qurl` has `lifecycle { ignore_changes = [task_definition] }`. nhp's `build-and-push.yml` runs `terraform apply` on push to `main` and registers a new task-definition revision with the env var, but does **not** call `update-service` on the qurl-api service (that's the qurl-service repo's responsibility). So `/health/ready` won't show the `dynamodb_schema` checker until the next qurl-service push-to-main runs `build-and-deploy.yml` (which calls `update-service --force-new-deployment` and picks up the latest revision), or an operator runs `aws ecs update-service --cluster layerv-nhp-sandbox-cell0-qurl-api --service layerv-nhp-sandbox-cell0-qurl-api --force-new-deployment` against the sandbox cluster.

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
