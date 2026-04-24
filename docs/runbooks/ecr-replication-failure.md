# Runbook: ECR cross-account replication failure

## What fired

The **promote-to-prod preflight** step "Verify images replicated to prod ECR" failed. One or more container images that exist in sandbox ECR (account 767397897469) were not found in prod ECR (account 235500187906).

## What it means

ECR cross-account replication from sandbox to prod is broken or delayed. Images pushed to sandbox are not propagating to prod. Prod deploys will fail at image pull time because the ECS task definition references a tag that doesn't exist in the prod registry.

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

**Symptom:** `describe-image-replication-status` returns `FAILED` / `DESTINATION_REGISTRY_ACCESS_DENIED` for every digest, even freshly-pushed ones, despite a registry policy whose Principal and Action appear correct.

**Diagnostic:** `aws ecr get-registry-policy --region us-east-2 --query 'policyText' --output text | jq` and look for a `Condition.StringEquals.aws:SourceAccount` or `aws:SourceArn` block. If present, that's the bug.

**Fix:** Remove the Condition block. The Principal scoping (`arn:aws:iam::<primary>:root`) is load-bearing and sufficient — it's what AWS's own [cross-account ECR replication reference policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions-cross-account-examples.html) use.

**Incident:** 2026-04-24 prod release was blocked by this for ~30 min of debugging; see `terraform/modules/ecr/main.tf` comment for the root-cause story. Fixed in PR #1316.

## After the fact

- Investigate what changed the replication configuration or registry policy. Check `terraform state list | grep replication` in both sandbox and prod.
- If an AWS service issue caused the failure, check the [AWS Health Dashboard](https://health.aws.amazon.com/health/status) for ECR events in us-east-2.
- File a post-incident artifact in `docs/incidents/` if the failure impacted a deploy timeline.

## Why this alert is wired this way

ECR cross-account replication is asynchronous and has no built-in CloudWatch metric for failures. The `describe-image-replication-status` API exists but only works for individual images you already know about — there's no "show me all failed replications" query. The pre-deploy gate in promote-to-prod catches the problem at the exact moment it matters: before a prod deploy that would fail at image pull time.
