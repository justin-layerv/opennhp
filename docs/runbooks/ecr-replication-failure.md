# Runbook: ECR cross-account replication failure

## What fired

One of two checks tripped:

1. The **`layerv-nhp-sandbox-ecr-replication-failure-*`** CloudWatch alarm (one per repository: `layerv/nhp-server`, `layerv/nhp-ac`, `layerv/nhp-console`, `layerv/nhp-qurl`). This is the steady-state probe — a Lambda runs every 15 minutes in sandbox, walks recent image pushes, and emits `ECRReplicationFailureCount` per repo to the `LayerV/NHP` namespace. Alarm fires at `> 0` for 2 consecutive 15-minute periods. Worst-case detection is up to ~15 min waiting for the next probe tick + 2 × 15 min evaluation = ~45 min total, comfortably inside the 1-hour SLO from #1320; the "~30 min discovery" figure cited elsewhere refers to the evaluation window only and assumes the failed push lines up favourably with a probe tick. Source: `terraform/ecr_replication_check.tf` and `terraform/lambda/ecr_replication_check.py`.
2. The **promote-to-prod preflight** step "Verify images replicated to prod ECR" failed. One or more container images that exist in sandbox ECR (account 767397897469) were not found in prod ECR (account 235500187906). This is the deploy-time backstop and should rarely be the first signal — if it fires without (1) having fired first, investigate why the steady-state probe missed it.

The alarm description points back to this runbook; the rest of the document applies regardless of which signal tripped.

## What it means

ECR cross-account replication from sandbox to prod is broken or delayed. Images pushed to sandbox are not propagating to prod. Prod deploys will fail at image pull time because the ECS task definition references a tag that doesn't exist in the prod registry.

**Reading the metric value.** `ECRReplicationFailureCount` counts FAILED entries **per destination registry**, not per image. Today there is one secondary account so the count is also the per-image-failure count. When a second secondary account is added, an image failing replication to both destinations contributes 2 to the count, not 1. The alarm threshold (`> 0`) is invariant under this choice — *any* failure pages — but the magnitude of the metric value is otherwise destination-weighted. If you want per-image counts, group the spot-check output by `imageDigest` (each digest is unique in `describe-images` output, so the dedup is cosmetic — the grouping is what collapses N destinations to 1).

## First five minutes

1. **Check the replication configuration** (from sandbox account):
   ```bash
   AWS_PROFILE=layerv aws ecr describe-registry --query 'replicationConfiguration'
   ```
   Verify there's a rule with `destinationRegistryId` matching the prod account and a `repositoryFilter` of `layerv/`.

2. **Check the prod registry policy** (from prod account):
   ```bash
   AWS_PROFILE=layerv-prod aws ecr get-registry-policy
   ```
   Verify the `AllowReplicationFromPrimary` statement exists, allowing `ecr:CreateRepository` and `ecr:ReplicateImage` from the sandbox account.

3. **Check replication status for a specific image**:
   ```bash
   # Find the latest image tag in sandbox
   LATEST_TAG=$(AWS_PROFILE=layerv aws ecr describe-images \
     --repository-name layerv/nhp-server \
     --query 'sort_by(imageDetails, &imagePushedAt)[-1].imageTags[0]' \
     --output text)

   # Check its replication status
   AWS_PROFILE=layerv aws ecr describe-image-replication-status \
     --repository-name layerv/nhp-server \
     --image-id imageTag="$LATEST_TAG"
   ```
   Look at the `replicationStatuses` array — `status` should be `COMPLETE`. If it's `FAILED`, the `failureCode` tells you why.

## Common causes

| Pattern | Likely cause | Action |
|---------|-------------|--------|
| `describe-registry` shows empty replication rules | Replication configuration was deleted (Terraform drift or manual change) | Re-apply Terraform in sandbox with `enable_replication=true` |
| `get-registry-policy` returns "no policy" | Prod registry policy was removed | Re-apply Terraform in prod with `enable_replication=true` |
| Replication status shows `FAILED` with `REPOSITORY_NOT_FOUND` | The repo doesn't exist in prod yet (first-time replication) | ECR creates repos automatically on replication — check IAM permissions |
| Replication status shows `FAILED` with `PERMISSION_DENIED` | IAM or registry policy mismatch | Compare the sandbox replication config with the prod registry policy; check for recent IAM changes |
| Replication status shows `FAILED` with `DESTINATION_REGISTRY_ACCESS_DENIED` despite a policy that *looks* correct | See "Known gotcha: aws:SourceAccount / aws:SourceArn" below | Remove those Condition keys from the destination registry policy |
| Images exist in sandbox but `describe-image-replication-status` shows no entries | Replication was never attempted — the image was pushed before replication was enabled, or the repo doesn't match the `layerv/` filter | Manually push the image to prod (see mitigations) |
| **Errors alarm fires** with `RepositoryNotFoundException` in the Lambda logs | A repo named in the Lambda's `REPOSITORIES` env was renamed or deleted but Terraform hasn't re-applied yet (TF apply lag, manual console edit, or a half-applied PR) — this is a Lambda-probe failure, not an actual replication failure | `aws ecr describe-repositories` to confirm what exists, then re-run `terraform apply` so the Lambda env catches up. The replication-failure alarms below are unaffected and don't need investigation until the errors alarm clears |
| **Throttles alarm fires** | Most likely a tick overlapped the previous one and `reserved_concurrent_executions = 1` rejected it. Reserved-concurrency rejections increment `Throttles` (not `Errors`), so the errors alarm stays green; this alarm fences that case at +5min, before the not-invoking alarm would trip at +45min | Don't manually re-invoke; the prior tick may still be alive and a retry will hit the same throttle. Check `Duration` trend (#1485 tracks a dedicated alarm); if runtime has grown past 900s, bump `timeout` AND the not-invoking alarm's `evaluation_periods` together |
| **Not-invoking alarm fires** AND `AWS/Lambda Throttles` metric is non-zero for the function | Sustained throttling — the throttles alarm above should have fired first. If the throttles alarm didn't fire, missed-data on `Throttles` may have masked it; investigate the function's recent invocation pattern | Same diagnosis as the throttles row above |
| **Errors alarm fires** for one or more repos (per-repo isolation) | The Lambda walks repos sequentially but isolates per-repo errors: a non-`ImageNotFoundException` failure on one repo no longer aborts the rest. Surviving repos still publish their `ECRReplicationFailureCount` datapoints; the post-loop raise fires the errors alarm so on-call sees the broken probe. The `RuntimeError` message names every failed repo, and per-repo CloudWatch logs carry full tracebacks at ERROR level | The surviving per-repo alarms' OK/ALARM state is trustworthy. The error message lists which repo(s) failed — query `/aws/lambda/layerv-nhp-sandbox-ecr-replication-check` filtered to `ERROR` level for the per-repo tracebacks |

## Mitigations (in order of preference)

1. **Restore replication via Terraform.** If the config was deleted or modified:
   ```bash
   # Sandbox (creates replication configuration)
   cd terraform/environments/sandbox && AWS_PROFILE=layerv terraform apply

   # Prod (creates registry policy allowing replication)
   cd terraform/environments/prod && AWS_PROFILE=layerv-prod terraform apply
   ```
   After restoring, re-push or re-tag the image in sandbox to trigger replication:
   ```bash
   # This triggers replication for the specific tag
   AWS_PROFILE=layerv aws ecr put-image \
     --repository-name layerv/nhp-server \
     --image-tag "$IMAGE_TAG" \
     --image-manifest "$(AWS_PROFILE=layerv aws ecr batch-get-image \
       --repository-name layerv/nhp-server \
       --image-ids imageTag="$IMAGE_TAG" \
       --query 'images[0].imageManifest' --output text)"
   ```

2. **Manual workaround** — pull from sandbox, push to prod:
   ```bash
   # Set the missing-from-prod tag (git SHA from the failed deploy, or
   # `$LATEST_TAG` from the "First five minutes" step above).
   IMAGE_TAG="<short-sha-or-tag>"

   # Login to both registries
   AWS_PROFILE=layerv aws ecr get-login-password | docker login --username AWS --password-stdin 767397897469.dkr.ecr.us-east-2.amazonaws.com
   AWS_PROFILE=layerv-prod aws ecr get-login-password | docker login --username AWS --password-stdin 235500187906.dkr.ecr.us-east-2.amazonaws.com

   # Pull from sandbox, retag, push to prod
   docker pull 767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server:$IMAGE_TAG
   docker tag 767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server:$IMAGE_TAG \
     235500187906.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server:$IMAGE_TAG
   docker push 235500187906.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server:$IMAGE_TAG

   # Repeat for nhp-ac and nhp-qurl if needed
   ```
   Then re-run promote-to-prod.

3. **Skip the gate** — only if the image is already confirmed to exist in prod by other means. Comment out the step and re-run. This should be an absolute last resort.

## Known gotcha: `aws:SourceAccount` / `aws:SourceArn`

ECR cross-account replication uses a service-internal authorization context that **does not populate the `aws:SourceAccount` or `aws:SourceArn` condition keys**. If the destination registry policy includes a `Condition.StringEquals` block keyed on either one, the statement fails to match at evaluation time and the implicit deny takes over — so replication fails with `DESTINATION_REGISTRY_ACCESS_DENIED` even though the policy *looks* like it should allow the call.

This is specific to ECR replication. Other AWS service-to-service integrations (S3 → SNS/SQS, EventBridge, etc.) *do* populate these keys and the common defense-in-depth pattern of pinning them is correct there. Copying that pattern into an ECR registry policy silently breaks replication.

**Reviewer rule of thumb (resource policies only):** if `Principal.Service` is set, pin `aws:SourceAccount`. If `Principal.AWS` is set (cross-account IAM), don't — the principal pin is the enforcement. For IAM trust policies (`assume_role_policy`) the cross-account analogue is `sts:ExternalId`, not `aws:SourceAccount`. (Canonical version, with the full audit and out-of-scope cases like KMS, `Principal.Federated`, and mixed principals, lives in [`docs/incidents/2026-04-24-ecr-source-account-trap.md`](../incidents/2026-04-24-ecr-source-account-trap.md) — the rule is duplicated here for in-incident readability; if it ever needs refining, refine it there and re-sync this paragraph.)

**Symptom:** `describe-image-replication-status` returns `FAILED` / `DESTINATION_REGISTRY_ACCESS_DENIED` for every digest, even freshly-pushed ones, despite a registry policy whose Principal and Action appear correct.

**Diagnostic:** `aws ecr get-registry-policy --region us-east-2 --query 'policyText' --output text | jq` and look for a `Condition.StringEquals.aws:SourceAccount` or `aws:SourceArn` block. If present, that's the bug.

**Fix:** Remove the Condition block. The Principal scoping (`arn:aws:iam::<primary>:root`) is load-bearing and sufficient — it's what AWS's own [cross-account ECR replication reference policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions-cross-account-examples.html) use.

**Incident:** 2026-04-24 prod release was blocked by this for ~30 min of debugging; see `terraform/modules/ecr/main.tf` comment for the root-cause story. Fixed in PR #1316; pattern-level audit referenced in the rule paragraph above.

## After the fact

- Investigate what changed the replication configuration or registry policy. Check `terraform state list | grep replication` in both sandbox and prod.
- If an AWS service issue caused the failure, check the [AWS Health Dashboard](https://health.aws.amazon.com/health/status) for ECR events in us-east-2.
- File a post-incident artifact in `docs/incidents/` if the failure impacted a deploy timeline.

## Sibling metric: `ECRReplicationImagesCheckedCount`

The Lambda emits a per-repo `ECRReplicationImagesCheckedCount` metric alongside `ECRReplicationFailureCount` to the same `LayerV/NHP` namespace. **No alarm is wired against it today** — it surfaces "is the look-back window actually covering deploys?" for dashboard inspection and for future alarm wiring tracked in:

- **#1486** — per-repo silent-cadence alarm (no pushes inside `LOOKBACK_HOURS` for sustained ticks)
- **#1485** — Duration / Throttles trend alarms on the Lambda runtime envelope
- **#1476** — persistence-window second alarm (folds in look-back-vs-lifecycle CI lint)

A repo going dark for sustained ticks is not currently observable from alarms — only from the metric itself. If you suspect a deploy-cadence drop without a failure, query `ECRReplicationImagesCheckedCount` per repo over the last 24h before assuming the `notBreaching` failure-count alarm is meaningful.

## Why this alert is wired this way

ECR cross-account replication is asynchronous and has no built-in CloudWatch metric for failures. The `describe-image-replication-status` API exists but only works for individual images you already know about — there's no "show me all failed replications" query. To close that gap, a scheduled Lambda walks recent pushes per repository and emits a custom `ECRReplicationFailureCount` metric (terraform/ecr_replication_check.tf, issue #1320). That metric drives the steady-state alarm above; the pre-deploy gate in promote-to-prod is retained as a backstop so a Lambda-side regression can't reopen the silent-failure window.

**Why the alarm routes to the sandbox-cell SNS topic.** The Lambda only runs on the source side of replication — i.e., the sandbox account — so its alarms naturally route to `module.monitoring.sns_topic_arn` in the sandbox cell. There is no equivalent prod-cell topic to fan out to today; even if there were, both cells fan into the same Slack channel and on-call email list, so the operational delta is zero. A future operator looking for the wired route on prod cell shouldn't waste time hunting — the alarm lives in sandbox by design.

**Why `alarm_actions` and `ok_actions` route to the same SNS topic.** The failure-count, errors, and throttles alarms configure identical `alarm_actions` and `ok_actions`. The downstream SNS topic fans out to Slack where the `OK` transition is operationally useful — it confirms recovery without requiring on-call to manually re-check. If routing ever changes to a PagerDuty integration with ack-required semantics, the `ok_actions` should be removed (OK transitions on PD pages are noise, not signal).

**Asymmetry: the not-invoking alarm has `alarm_actions` only, no `ok_actions`.** With `treat_missing_data = "breaching"`, this alarm starts in `INSUFFICIENT_DATA`, transitions through `ALARM` once the 3-period evaluation window elapses on a fresh deploy, then clears to `OK` after the first scheduled invocation. That `OK` transition is a documented false alarm (the probe wasn't actually broken — the ALARM was an apply-time artifact), so routing it to Slack would noise on-call without signal. The `ALARM`-side notification still fires, runbook says \"acknowledge and wait one schedule cycle.\"

**Alarm `unit = "Count"` pin and INSUFFICIENT_DATA surprise.** The failure-count alarm pins `unit = "Count"` to match the publisher's `MetricData` `Unit` field. CloudWatch silently treats unit-mismatched datapoints as "no data" — so a future refactor that drops `"Unit": "Count"` from the per-repo `metric_data` dict in `ecr_replication_check.py` would surface as an `INSUFFICIENT_DATA` alarm transition, not an `OK` clear. If you're debugging "why is this alarm in INSUFFICIENT_DATA when I can see datapoints in Metrics Explorer," check the publisher-side Unit field first. The publisher-side test (`test_emits_one_metric_per_repository`) fences this on the unit literal.

**Cell-id is intentionally absent from the alarm name.** Most CW alarms in the repo use the `${name_prefix}-${cell_id}-…` naming convention (see `terraform/main.tf` for the pattern). These alarms use bare `${name_prefix}-…` to match the `cloudfront_cidr_drift` template — both probes are source-account-only and not cell-scoped. An operator grepping CW alarms by `cell_id` will not find these; grep by `ecr-replication-` instead.

**The `Environment` dimension is Terraform-owned, not console-edited.** The Lambda's `ENVIRONMENT` env var comes from `var.environment` and is set exhaustively in the `environment.variables` block, so a manual console edit to flip it (e.g., to `prod` on a sandbox-account Lambda) would be reverted by the next `terraform apply`. The IAM `cloudwatch:namespace` condition prevents pollution of other namespaces but does not pin the dimensions themselves; if a future change relaxes the Terraform ownership of env vars (or runs the Lambda outside Terraform's reach), the dimension contract has to be re-evaluated.

A companion alarm — `layerv-nhp-sandbox-ecr-replication-check-errors` — fires on Lambda execution errors. If that alarm trips, the steady-state replication-failure alarm cannot fire, so investigate the Lambda failure first (CloudWatch Logs `/aws/lambda/layerv-nhp-sandbox-ecr-replication-check`). The errors alarm is intentionally tighter than the failure-count alarm (5-minute period, single datapoint) — there is no benefit to waiting for a second datapoint when the probe itself is broken.

A throttles alarm — `layerv-nhp-sandbox-ecr-replication-check-throttles` — fires when `AWS/Lambda Throttles` is non-zero. `reserved_concurrent_executions = 1` rejects overlapping invocations, and `maximum_retry_attempts = 0` drops them silently — no `Errors` metric, no log line. Without this alarm, throttling would only surface at +45min via the not-invoking alarm; this one catches it at +5min, matching the errors-alarm cadence.

A meta-alarm — `layerv-nhp-sandbox-ecr-replication-check-not-invoking` — fires when the Lambda hasn't run for 45 minutes (~3 schedule cycles) by checking the `AWS/Lambda Invocations` metric with `treat_missing_data = "breaching"`. Closes the gap where the EventBridge schedule itself gets disabled, the IAM permission is revoked, or the function gets account-throttled — all cases where neither the failure-count nor the errors alarm would fire because no datapoints reach CloudWatch. If this alarm fires:

1. `aws events describe-rule --name layerv-nhp-sandbox-ecr-replication-check` — verify `State = ENABLED`.
2. `aws lambda get-function --function-name layerv-nhp-sandbox-ecr-replication-check` — verify the function exists and the role is intact.
3. Check account-wide Lambda concurrency throttle settings and recent Service Health events.

`treat_missing_data = "breaching"` makes the alarm correct-by-construction, but it does mean a brand-new deploy will briefly transition through ALARM until the first invocation lands; that's the right trade-off — false alarm during bootstrap is cheaper than missed alarm in steady state.

**First-time apply (operator note).** The first time you `terraform apply` this stack into a fresh environment, expect a transient `*-ecr-replication-check-not-invoking` page within ~45 minutes of the apply completing. The alarm starts in `INSUFFICIENT_DATA`, then transitions through `ALARM` once the 3-period evaluation window elapses with no invocations recorded, then clears to `OK` after the first scheduled invocation lands and stays clear thereafter. **The page may arrive before `terraform apply` finishes streaming logs** — CloudWatch alarm-evaluation timing can fire the SNS notification before the apply step that created the resource completes its post-create wait. **If this is your first apply, acknowledge the page and wait one schedule cycle before escalating** — only escalate if the alarm fails to clear within an hour of the apply, or if it re-enters `ALARM` after having reached `OK`.

## Adjusting the look-back window

The Lambda only inspects images pushed within `LOOKBACK_HOURS` of the current run (default `25`, sized for daily deploys with a 1-hour cushion). If deploy cadence ever drops below daily — for example, a weekly release train, or a long quiet stretch where only vendor base-image churn lands — failures on images older than the window will go undetected.

`LOOKBACK_HOURS` is plumbed through Terraform: `var.ecr_replication_check_lookback_hours` (declared in `terraform/variables.tf`, validated to `[1, 720]`) feeds the Lambda's `environment.variables` block in `terraform/ecr_replication_check.tf`. To change the live value, set the variable in the appropriate tfvars (`terraform/environments/sandbox/terraform.tfvars` or `terraform/environments/prod/terraform.tfvars`) and apply. Toggling the env var directly in the AWS console is not durable — the next `terraform apply` clears the manual edit because the env block is exhaustive.

The Python `DEFAULT_LOOKBACK_HOURS` constant in `terraform/lambda/ecr_replication_check.py` is the project-wide default and only takes effect if the env var is somehow unset (an unreachable path under the current Terraform wiring). A non-positive or unparseable env value hard-raises `RuntimeError` into the errors alarm rather than soft-falling-back to the default — symmetric with the empty-`REPOSITORIES` path. A manual console edit that produces garbage values therefore pages on-call rather than silently zeroing the metric.

Widening the window costs only a handful of extra `describe_image_replication_status` calls per run.

**Lockstep with lifecycle policy.** `LOOKBACK_HOURS` and the ECR lifecycle policy must stay in lockstep — if untagged-image expiry runs faster than the look-back window, an image could be deleted before the probe inspects it. The current settings are:

| Setting | Value | Source |
|---|---|---|
| `LOOKBACK_HOURS` (default) | `25` | `terraform/variables.tf` |
| Untagged-image expiry | 7 days (168h) | `terraform/modules/ecr/main.tf` `local.ecr_untagged_expiry_days` |
| Tagged-image expiry | 90 days | same |

There is a 6.7× cushion between the look-back window and untagged expiry today. A future tightening of either side needs to keep that cushion positive — if you ever set `LOOKBACK_HOURS=200` you also need to push untagged expiry past 200h, or the probe starts skipping recent images that lifecycle has already cleaned up.

The cushion is enforced at plan time by a `lifecycle.precondition` on `aws_lambda_function.ecr_replication_check` (see `terraform/ecr_replication_check.tf`); a `terraform plan` that would invert it will fail with a clear error before any apply runs. #1476 tracks broadening this from a single-Lambda precondition to a fleet-wide CI-enforced check.

## Stale-failure caveat

The look-back window is a **detection-latency** signal, not a **persistence** signal. If image X fails replication at T=0 and nobody remediates, then images Y, Z push successfully at T+1h, T+2h, …, the alarm clears at T+(LOOKBACK_HOURS) even though prod still has a hole in the repository for digest X. The deploy-time preflight in `promote-to-prod` catches the hole on the next prod deploy attempt — that's the backstop — but if you see the alarm transition cleanly to OK without anyone having taken remediation action, **don't trust the OK transition as proof that no failed digests remain in the source repo**. Spot-check with:

```bash
# Walks every digest under tagged-lifecycle retention (90d). DELIBERATELY
# EXHAUSTIVE — earlier drafts limited to the 50 most recent pushes and a
# stale FAILED digest older than that would have been missed. At today's
# deploy cadence this is hundreds of `describe-image-replication-status`
# calls per repo; expect 30s–2min runtime per repo under real-incident
# pressure. The command is not hung; it is being thorough.
AWS_PROFILE=layerv aws ecr describe-images --repository-name layerv/nhp-server \
  --query 'sort_by(imageDetails, &imagePushedAt)[].imageDigest' --output text \
  | tr '\t' '\n' \
  | while read -r digest; do
      result=$(AWS_PROFILE=layerv aws ecr describe-image-replication-status \
        --repository-name layerv/nhp-server \
        --image-id imageDigest="$digest" \
        --query 'replicationStatuses[?status==`FAILED`]' \
        --output json)
      if [[ "$result" != "[]" ]]; then
        echo "FAILED: $digest"
        echo "$result" | jq '.'
      fi
    done
```

Empty output means everything under tagged-lifecycle retention is clean (per-tick API count is bounded by tagged-retention image count, not look-back). Tracking #1476 to convert this manual command into a second alarm (lifecycle-window scan rather than recent-push window).

**Bonus failure mode: IN_PROGRESS forever.** The probe only counts entries with `status == "FAILED"`. If AWS's replication subsystem ever leaves an image stuck at `IN_PROGRESS` indefinitely (rare but observed during AWS service degradations), the metric stays at zero, the alarm doesn't fire, and after `LOOKBACK_HOURS` the digest is invisible to this probe. If you see prod missing an image that sandbox has, and `describe-image-replication-status` shows `IN_PROGRESS` rather than `FAILED` or `COMPLETE`, the issue is on AWS's side and needs an [AWS Health Dashboard](https://health.aws.amazon.com/health/status) check rather than a registry-policy fix.

**Bonus failure mode: tag rotation within the look-back.** *This failure mode is theoretical under today's deploy pipeline — the SHA-backbone convention prevents it.* The probe filters `describe_images` to `tagStatus == "TAGGED"` so untagged build artefacts and orphans don't dominate the per-tick page walk. If an image gets pushed with a tag, replicates successfully, then has its tag rotated to a newer digest *within `LOOKBACK_HOURS`* (e.g., a `latest`-style tag), the original digest becomes untagged and falls out of the probe's view. Tag-rotation isn't part of the deploy flow today: every digest carries an immutable git-SHA tag alongside the rotating `latest` / `environment` tags, so the SHA backbone keeps the digest TAGGED-visible for the lifecycle window. If a future workflow ever pushes a digest tagged ONLY with a rotating tag (no SHA backbone), the probe goes blind on it. **#1489 tracks a CI lint to enforce the SHA-backbone convention** so this prose guard doesn't rot. Until that lands, the deploy-time preflight in `promote-to-prod` is what backstops the actual prod-deploy path; this probe will not catch a failure on a rotated digest.
