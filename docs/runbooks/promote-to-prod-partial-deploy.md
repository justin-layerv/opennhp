# Runbook: promote-to-prod partial-deploy / split-state

## What fired

A **promote-to-prod** workflow run reported `success` but the deployment did not actually land cleanly. Symptoms include any of:

- New nhp-server / nhp-ac binaries running in prod against terraform that was **not** applied for this run.
- ECS service for qurl-service rolled back to the previous task definition while the workflow's `Deploy QURL Service` job reported success.
- `Terraform Apply` and one or more `Deploy *` jobs both show as `skipped` in the workflow summary.

This is the failure mode tracked in **issue #1322** — the 2026-04-24 prod release surfaced it. The DAG fix shipped with #1322 should make the bad state unreachable on subsequent runs; this runbook covers (a) recognising the original 2026-04-24 footprint if it recurs, and (b) verifying the fix is doing what it says.

> **Naming note**: the qurl-schema-compat job appears under three labels depending on the surface. The actual job name in the workflow is `QURL Schema Compatibility Check`; the GitHub UI table and this runbook abbreviate it to `QURL Schema Compat`; the SNS notification body abbreviates further to `Schema Compat` for column alignment. Searching for any of those strings (or for `qurl-schema-compat` — the YAML job ID) will find every reference.

## What it means

`promote-to-prod.yml` orchestrates four lifecycle stages:

1. `preflight` (image presence, AMI age, secrets, deployment lock, **stale-terraform check**).
2. `terraform-plan` → `qurl-schema-compat` → `terraform-apply`.
3. `deploy-server` → `deploy-ac` → `deploy-qurl`, plus `deploy-qrts`
   (qurl-reverse-tunnel-server). Note: `deploy-qrts` is **decoupled** from the
   server/ac/qurl chain — it gates only on `terraform-apply` + `deploy_qrts`,
   because qrts is functionally independent of the NHP control plane (a
   server-canary failure should not block the qrts image refresh).
4. `smoke-test` → `qurl-smoke-tests` → `nhp-smoke-tests` → `monitor` → `finalize`.

Pre-#1322, the deploy-* jobs gated on `needs.terraform-apply.result == 'success' || == 'skipped'`. When `qurl-schema-compat` failed, GitHub Actions skipped `terraform-apply` (because of `needs:`), and the deploy-* jobs *also* observed `skipped` — so they ran anyway, rolling new binaries onto the previous terraform state. `finalize` then walked job results looking only for `failure || cancelled`, saw none, and reported the run as `success`.

Post-#1322, the gate is:

```yaml
(inputs.run_terraform && needs.terraform-apply.result == 'success') ||
(!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
```

— and `qurl-schema-compat` is wired into `finalize`'s `needs:` list and FAILED loop, so a schema-compat failure produces an unambiguous workflow failure.

## First five minutes

1. **Open the failing run and grab its summary**: <https://github.com/layervai/nhp/actions/workflows/promote-to-prod.yml>.

2. **Check the per-job result table** in the run summary. The expected pattern when `qurl-schema-compat` fails is:

   | Job | Expected post-#1322 status |
   |-----|----------------------------|
   | Manifest | success |
   | Preflight | success |
   | Terraform Plan | success |
   | **QURL Schema Compat** | **failure** |
   | Terraform Apply | skipped |
   | Deploy NHP Server | skipped |
   | Deploy Access Controller | skipped |
   | Deploy QURL Service | skipped |
   | Deploy qurl-reverse-tunnel-server | skipped |
   | Smoke Test | skipped |
   | Finalize | (overall: failed) |

   If you see deploy-* jobs as `success` while `qurl-schema-compat` is `failure`, the gate has regressed — re-open #1322.

3. **Check for ECS rollback** (qurl-service):
   ```bash
   AWS_PROFILE=layerv-prod aws ecs describe-services \
     --cluster <cluster> --services <service> \
     --query 'services[0].events[:10]' --output table
   ```
   Look for `rolling back to deployment ecs-svc/...`. The `deploy-ecs-service.sh` script now compares the running task def to the one it registered and fails the job on rollback (#1322), so this should already be reflected in the workflow conclusion.

4. **Verify what's actually running in prod** before deciding to re-deploy:
   - Server / AC: read `/prod/nhp/server/image-tag` and `/prod/nhp/ac/image-tag` from SSM. Compare with `/prod/nhp/deploy/deployed-commit`.
   - QURL: `aws ecs describe-services` and read the `taskDefinition` ARN; compare with `/prod/nhp/last-qurl-task-def-arn` (if tracked) or with the latest revision in `aws ecs list-task-definitions`.
   - Terraform: `/prod/nhp/deploy/last-terraform-apply-commit` is the SHA of the last applied prod terraform.

## Recovery

The right recovery depends on what landed and what didn't.

### Case A: schema-compat blocked everything (post-#1322 expected behaviour)

`Terraform Apply` and all `Deploy *` were correctly `skipped`. Nothing landed. Fix the schema-compat root cause (it's almost always either a destructive terraform plan that drops a registered GSI, or a qurl-schema-check binary bug — see [`verify-qurl-schema-prevention.md`](verify-qurl-schema-prevention.md)) and re-trigger the promote.

### Case B: split-state from a pre-#1322 run

If you're recovering from a recurrence (or from the 2026-04-24 incident itself):

1. **Confirm the qurl image is schema-compatible BEFORE re-promoting.** If schema-compat is what blocked the original run, re-running with the same image just reproduces the failure. Either pick a newer `qurl_image_tag` known to be compatible, or verify the schema fix has landed in the image by running `qurl-schema-check --version` against it (the workflow's own pre-gate smoke does this).

   Then re-promote with the chosen image + `run_terraform=true` to land the missing terraform:
   ```bash
   gh workflow run promote-to-prod.yml --ref main \
     -f image_tag=<sha> -f qurl_image_tag=<schema-compat-known-good> \
     -f run_terraform=true \
     -f deploy_server=false -f deploy_ac=false -f deploy_qurl=true
   ```
   Setting `deploy_qurl=true` re-runs the qurl deploy with the now-applied terraform (incl. any new env vars that caused the previous rollback).

2. **Server / AC**: if their binaries already landed against the stale infra, decide based on what infra changed:
   - Pure additive infra changes (new IAM permissions, new SSM params): no need to redeploy server/AC; `terraform-apply` alone is sufficient.
   - Infra changes that the binaries depend on (env vars, mount paths, port changes): redeploy server / AC after `terraform-apply` succeeds.
   - **How to tell**: grep the diff between the last applied SHA and the new SHA for `aws_ssm_parameter` writes (binaries read these at boot via `user_data.sh.tpl`), `aws_security_group_rule` changes (port/protocol changes affect what the binaries can reach), and `aws_iam_*` policy changes (new permissions binaries rely on). A clean diff in `terraform/modules/ecr/`, `terraform/modules/canary-deployment/`, or `terraform/environments/prod/main.tf` for IAM-only fields is usually safe to land via terraform-apply alone.

3. **Capture forensics** before recovering, in case the post-mortem is downstream-facing:
   - Workflow run URL.
   - SSM values at the time of the bad run (`deployed-commit`, `last-terraform-apply-commit`).
   - `aws ecs describe-services ... events[:20]` for any service that rolled back.

### Case C: stale-terraform guard fired

The new preflight step "Verify terraform is current with deployed code" failed with:

> `Stale terraform: N prod-affecting file(s) changed between last-apply <a> and deploy SHA <b>.`

The check ran and found a real diff that the deploying operator hasn't accounted for. Re-run with `run_terraform=true` (preferred — applies the pending infra change before the deploy), or with `allow_stale_terraform=true` after **reading the diff** and confirming it doesn't affect the components you're deploying. The bypass surfaces the diff in the step summary; document the rationale in the deploy ticket. (See "Bypasses you should know about" below.)

### Case D: stale-tf check failed-CLOSED on a real AWS error

The stale-tf preflight emitted:

> `::error::Failed to read /prod/nhp/deploy/last-terraform-apply-commit from SSM. Refusing to fail-open on a transient AWS error.`

This is the **fail-closed** branch — the gate refuses to assume "no drift" when it can't read the SSM key. Common triggers: IAM denial (rare; the prod role already has `ssm:GetParameter` on `/prod/nhp/*`), throttling under load, transient AWS service degradation. The error message includes the captured stderr so the cause is visible in the run log.

Recovery options, in order of preference:

1. **Wait and re-run.** Most transient SSM errors clear within minutes. Re-dispatching the workflow with the same inputs is the safest option.
2. **Re-run with `run_terraform=true`.** If the original dispatch was app-only (`run_terraform=false`), running terraform makes the SSM read irrelevant — the gate is skipped because the terraform-plan + terraform-apply path lands any drift directly.
3. **Manually verify and bypass with `allow_stale_terraform=true`.** Only after reading the relevant terraform diff yourself (`git diff <last-applied-sha>..<deploy-sha> -- terraform/environments/prod/ terraform/modules/`) and confirming nothing affects the components you're deploying. The bypass surfaces the diff in the step summary; document the rationale in the deploy ticket.

Do **not** ssh-and-fix-by-hand. The fail-closed branch is intentional — silently fail-opening on a transient AWS error would re-create the exact partial-deploy class #1322 was meant to prevent.

### Case E: qrts decoupling end-states

`deploy-qrts` is decoupled from the server/ac/qurl chain (it gates only on `terraform-apply` + `deploy_qrts`), so its partial-state shapes differ from the chained jobs.

**qrts-only dispatch** (`deploy_qrts=true`, everything else false):

| Job | Expected status |
|-----|-----------------|
| Manifest / Preflight | success |
| Terraform Plan / Apply | skipped (app-only dispatch) |
| Deploy NHP Server / AC / QURL | skipped |
| **Deploy qurl-reverse-tunnel-server** | **success** |
| Smoke Test / QURL / NHP smoke | **skipped** — the smokes gate on "≥1 of server/ac/qurl succeeded", which a qrts-only dispatch never satisfies; this is intentional (qrts has no app-layer smoke). |
| Finalize | (overall: deployed) |

A qrts-only run that shows the smokes as `skipped` is the **expected** shape, not a regression.

**Mixed dispatch where a chained job fails but qrts succeeds** (e.g. `deploy_server=true deploy_qrts=true`, server-canary fails): because qrts is decoupled, it **still rolls forward** to the new image even though `deploy-server` failed. End-state: prod runs **new-qrts + old-server**, `finalize=failed`, lock released as `failed`. This is a genuine split-state — reconcile qrts independently of the server rollback (qrts has its own image-tag SSM param `/prod/nhp/reverse-tunnel-server/image-tag`; roll it back with a `deploy_qrts=true -f frps_image_tag=<prior-tag>` dispatch, see the trigger script's rollback hint).

**First promotion that lands without qrts.** `trigger-prod-deploy.sh`'s first-deploy path force-enables server/ac/terraform/qurl, but **gates qrts** on the same bootstrap check as the steady-state path: if sandbox rts CI hasn't published a real image yet (tag is `(not set)` or `v0.0.0-bootstrap*`), it sets `deploy_qrts=false` with a `[SKIP]` reason and a `warn`, rather than letting the workflow's bootstrap pre-check hard-fail the whole promotion. So a **first prod promotion showing `deploy_qrts=false` is expected** when sandbox qrts hasn't published — not a missed step. To add qrts once rts CI publishes, re-dispatch with `deploy_qrts=true` (or pass `-f frps_image_tag=<tag>` explicitly). The skip reason is printed by the trigger script at dispatch time; the workflow run page itself only records the resolved `deploy_qrts=false` input.

### Lock-state vocabulary (`/prod/nhp/deploy/state`)

The finalize step writes one of four terminal values to `/prod/nhp/deploy/state` based on what happened in this run:

| Value | Meaning |
|-------|---------|
| `deployed` | Workflow succeeded end-to-end. Prod is now running the new artifacts. |
| `failed` | Workflow failed AND at least one of `terraform-apply` or any `deploy-*` job ran (success or failure). Prod state may be inconsistent — investigate which job failed; reconcile against `/prod/nhp/deploy/deployed-commit` and the terraform state file. A mid-graph terraform-apply failure leaves resources partially-converged, so this branch fires (correctly) for that case too. |
| `rejected` | Workflow failed BEFORE `terraform-apply` AND every `deploy-*` job was skipped (preflight stopped, stale-tf check tripped, schema-compat blocked, OR `terraform-plan` failed and cascaded a skipped apply). Nothing landed on prod; the previous deploy-state still describes prod accurately. |
| `deploying` | Lock held by an in-flight workflow (transient). |

### Tracking-failure aftermath (post-CR-round-38 reordering)

The `Update terraform apply tracking` step now runs BEFORE `Release deployment lock`. A tracking failure (3 retries exhausted on a transient SSM throttle) propagates via the conditional status expression: lock writes `failed`, SNS reports `FAILURE`, the workflow conclusion is `failure`. Operator sees consistent signals.

If the tracking step fails after a successful terraform-apply, recovery is the same as any other `LOCK_VALUE=failed` post-deploy investigation: the underlying terraform DID apply, but `last-terraform-apply-commit` was never written, so the next promote's stale-tf gate may trip on the stale baseline. Manually re-seed:

```bash
AWS_PROFILE=layerv-prod aws ssm put-parameter \
  --name "/prod/nhp/deploy/last-terraform-apply-commit" \
  --value "<sha-that-applied>" --type String --overwrite
AWS_PROFILE=layerv-prod aws ssm put-parameter \
  --name "/prod/nhp/deploy/last-terraform-apply-at" \
  --value "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --type String --overwrite
```

**Always rewrite BOTH parameters during recovery, even if only one looks stale.** The tracking step writes them sequentially: a successful first put + failed second put leaves `last-terraform-apply-commit` fresh and `last-terraform-apply-at` stale. Operators reading both for forensics could misread the timeline (newer commit, older timestamp). The re-seed snippet above writes both unconditionally to keep them aligned.

The trade-off (failing finalize on a tracking-put failure rather than warn-and-proceed) is intentional — see the workflow comment on `Update terraform apply tracking` for the rationale.

**Asymmetric story for the second tracking write (`Update deployment tracking`).** That step uses `retry_put_warn` (warn-only return) instead of `retry_put` (fail-loud). Rationale: `deployed-commit` / `deployed-at` / `deployed-commit-previous` are forensic / rollback-resolution writes, not gate-relevant — losing them on sustained SSM throttle does NOT introduce a partial-deploy regression. But on-call investigating a deploy where `lock_state=deployed` + workflow=success but `deployed-commit` reads stale should know the asymmetry: re-seed both `deployed-commit` and `deployed-commit-previous` (`aws ssm put-parameter --overwrite`) to align forensics with reality. #1374 tracks alarm wiring for the silent-degradation case.

Preflight lock acquisition only blocks on `deploying`. Operators investigating an unexpected `rejected` should look at the workflow run log for the preflight failure (Cases A / D / stale-tf reject). `failed` warrants checking each ran job's logs and reconciling prod state against `/prod/nhp/deploy/deployed-commit` plus the terraform state file.

### Force-push protection assumption (for the OrphanedAncestor branch)

The stale-terraform preflight's `git merge-base --is-ancestor` failure path is **fail-OPEN** (warns + proceeds + emits a CloudWatch counter). The asymmetry is documented in the workflow comment as "operator-caused, not AWS outage." The justification depends on **prod main being force-push protected** so a previously-applied commit cannot disappear from the reachable history.

Verify the assumption holds:

```bash
gh api "repos/layervai/nhp/branches/main/protection" \
  --jq '{enforce_admins: .enforce_admins.enabled, allow_force_pushes: .allow_force_pushes.enabled}'
```

Expected output:
- `enforce_admins.enabled: true`
- `allow_force_pushes.enabled: false`

If protection is ever relaxed, the `Verify prod main has force-push protection` preflight step **already auto-fails the workflow** (allow_force_pushes != false → set_status disabled → exit 1). The OrphanedAncestor warn-pass branch only fires when the protection check passed; relaxed protection is caught at the preflight gate, not the OrphanedAncestor branch. Filing a recurring quarterly check on the protection settings is still reasonable until #1346's alarm makes the SNS Protection row actionable in real-time.

### Bypasses you should know about

The gate has four escape hatches. Three are user-facing **input flags** at workflow dispatch; one is a **manual SSM write** that no operator should need on the happy path:

- `allow_stale_terraform=true` (input flag) — explicit operator opt-in at dispatch. The next run's gate consumes the flag, surfaces the diff in the step summary, and proceeds.
- `rollback=true` (input flag) — auto-bypasses the stale-tf check at dispatch; the diff is still emitted inline so the operator sees what they bypassed.
> **Common false positives**: a sandbox-only change to a module under `terraform/modules/` that's *also* consumed by prod will trip the stale-tf check even if the change is logically scoped to sandbox (e.g., a sandbox-specific feature flag in a shared module). The current scope (`terraform/environments/prod/` + `terraform/modules/`) favors false-positives over false-negatives — read the diff, confirm sandbox scope, and bypass with `allow_stale_terraform=true`. Per-module ownership scoping in #1345 will make this less common.

- `force_unlock=true` (input flag) — bypasses the deployment-lock check when a stuck `"deploying"` state is blocking a new dispatch. Lock-bypass rather than gate-bypass, so it does not affect the stale-terraform check itself; included here for audit-completeness. Use only after confirming no other promote run is actually in flight (the workflow run log for the previous dispatch will show whether finalize ran).
  > **Heads-up**: `force_unlock=true` alone (with `run_terraform=false` and every `deploy_*=false`) is rejected as a no-op dispatch — `force_unlock` only takes effect on a run that ALSO deploys something. To clear a stuck lock without redeploying, use the manual SSM fallback below instead.

- **Manual SSM lock-state write (stuck-lock-only path)** — when the deploy lock is stuck on `"deploying"` and you need to clear it WITHOUT triggering a new deploy, write the lock state directly:
  ```bash
  AWS_PROFILE=layerv-prod aws ssm put-parameter \
    --name "/prod/nhp/deploy/state" \
    --value "failed" --type String --overwrite
  ```
  Use `failed` (not `deployed`) so subsequent forensics correctly indicate the prior run did not complete. This is the audit-trail-leaving alternative to `force_unlock=true`-with-deploy. Same IAM-gated surface as the `"initial"` sentinel below.
- `aws ssm put-parameter --name /prod/nhp/deploy/last-terraform-apply-commit --value initial` — manual SSM write. The `"initial"` sentinel resets the gate to first-deploy mode, which warns-and-proceeds. Useful for greenfield bootstraps; misuse means anyone with `ssm:PutParameter` on this path can silently disable the check on the next promote. SSM write to `/prod/nhp/*` is IAM-gated by `AWS_PROD_ROLE_ARN`, so this is operator-with-prod-credentials surface, not a public attack vector — but include it in security audits alongside the input flags. Equivalent variants: writing `""` (empty string), `None`, or any other value the gate's first-deploy sentinel test treats as "no prior apply" (search the workflow for `"initial"` to enumerate the matched sentinels). The audit boundary is "anyone who can write `/prod/nhp/deploy/last-terraform-apply-commit`," not the literal `"initial"` string.

> **Not a bypass, but on-call should know**: a mixed dispatch where a chained job fails but `deploy_qrts=true` succeeds leaves prod in a new-qrts + old-everything-else split-state (`finalize=failed`). This is the decoupling trade-off, not a gate bypass — see **Case E: qrts decoupling end-states** above for the reconcile path.

### SSM write surface (audit boundary)

Two `/prod/nhp/deploy/*` parameters are operator-writable surfaces with the same `AWS_PROD_ROLE_ARN`-gated boundary:

| Parameter | Misuse impact |
|---|---|
| `/prod/nhp/deploy/last-terraform-apply-commit` | Writing `""` / `"initial"` / `"None"` resets stale-tf gate to first-deploy mode (warn-pass). Tracked by the `StaleTerraformCheckCouldNotVerify{Reason=FirstDeploySentinel}` metric. |
| `/prod/nhp/deploy/state` | Writing arbitrary lock states (`"deployed"` / `"failed"` / `"rejected"` / `"deploying"`) bypasses the deployment lock. Documented as the manual stuck-lock-clear path above; misuse would mask a deploy that's actually in flight. |

Audit policy: any `ssm:PutParameter` event on these paths from a principal other than the prod terraform-apply role + the GitHub Actions runner role should fire a CloudWatch alarm (#1357 IAM audit + #1361 alarm wiring + #1364 protection-status alarm collectively cover this).

### Scope

"Prod-affecting" means the diff is scoped to `terraform/environments/prod/` and `terraform/modules/` — sandbox-only terraform changes will not trip this gate.

**Deliberately excluded** from the scope:
- `terraform/lambda/` — Python source for Lambdas built in CI; not invoked at `terraform-apply` time.
- `terraform/bootstrap/` — one-time account/state bootstrap; never run from `promote-to-prod`.
- `terraform/scripts/` — operator helper scripts (etcd seed, AC license generation); not consumed by terraform-apply.
- `terraform/examples/` — sample configs.

If a future change moves prod-relevant code into one of those directories, widen the scope in `promote-to-prod.yml` (the `git diff --name-only` paths) and `tests/scripts/test_promote_to_prod_gating.py::STALE_TF_MUST_HAVE`. The dedupe issue #1343 is the right vehicle for centralizing the path list.

The intended fix is to re-run with `run_terraform=true`. Use `allow_stale_terraform=true` only if you have **read the diff** and confirmed it doesn't affect the components you're deploying (or you're rolling back to an earlier known-good binary against current infra). When `rollback=true`, the check auto-bypasses but emits the diff inline so you can still see what's been bypassed.

## Verifying the gate (manual)

The acceptance test from #1322 is "simulate schema-check failure → confirm image deploys DO NOT run." Because `promote-to-prod` is prod-only there's no sandbox twin to dry-run against. The structural assertions live in `tests/scripts/test_promote_to_prod_gating.py` (run via `make lint-workflows`, also wired into `.github/workflows/validate-workflows.yml`).

> **Telemetry gap**: the `LayerV/NHP::StaleTerraformCheckCouldNotVerify` CloudWatch metric (PR #1341) emits a counter on every "could not verify — proceeding" warning path (`Reason` dimension: `ParameterNotFound`, `FirstDeploySentinel`, `OrphanedAncestor`). Until the alarm wired in **#1346** lands, this metric is observable only from the CloudWatch metric explorer — check it manually after each promote that flagged a "could not verify" warning until the alarm is in place.

To verify behaviour at runtime:

1. Stage a deliberately-failing schema-check by setting `inputs.qurl_image_tag=<tag-known-to-fail-schema-check>`. Any qurl-service image that exits non-zero from `qurl-schema-check --plan <tfplan.json>` works — at the time of writing this includes any image predating the addition of the schema-check binary, or any image that registered a GSI that the post-apply plan removes. The workflow's own pre-gate smoke (`qurl-schema-check --version`) catches binary-not-runnable cases at exit 126/127.

2. Trigger the workflow with `deploy_server=true deploy_ac=true deploy_qurl=true run_terraform=true`.

3. Observe:
   - `QURL Schema Compatibility Check` → failure.
   - `Terraform Apply` → skipped.
   - `Deploy *` → all skipped (the gate fix).
   - Workflow conclusion → failure.
   - `/prod/nhp/server/image-tag` and `/prod/nhp/ac/image-tag` unchanged.
   - **`/prod/nhp/deploy/state` reads `rejected`** (not `failed`). Verify with: `aws ssm get-parameter --name /prod/nhp/deploy/state --query Parameter.Value --output text`. The `rejected` value distinguishes "preflight stopped, nothing landed" from "partial mid-deploy failure" — confirms the lock-state vocabulary fired correctly.

4. Cancel any in-flight `monitor` job; the deployment lock will be cleaned up by `finalize`.

## Related

- Issue: #1322 (this runbook's source)
- Originating incident: prod release run #24915082368 (2026-04-24)
- Adjacent runbook: [`verify-qurl-schema-prevention.md`](verify-qurl-schema-prevention.md) — schema-compat root-cause path.
- Adjacent runbook: [`ecr-replication-failure.md`](ecr-replication-failure.md) — preflight image-presence check.
