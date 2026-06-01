# CI/CD Workflows

## Deployment Workflows

### `build-and-push.yml` — Build & Deploy (Sandbox)

Triggered on every push to `main` with app or infra changes. Builds Docker images, pushes to ECR, runs Terraform apply, and triggers instance refresh. Also runs on PRs (plan only, no deploy).

### `promote-to-prod.yml` — Promote to Production

> **Preferred method:** Use `./scripts/trigger-prod-deploy.sh` instead of running `gh workflow run` manually. The script reads SSM state from both accounts, validates sandbox health, auto-detects which components changed, and generates the correct command. Run with `--dry-run` to preview without executing.

**Manual workflow** for promoting existing sandbox ECR images to production. No rebuild — uses images already built and validated in sandbox. Orchestrates deployment through canary (server/AC) and ECS task def registration (QURL).

**Components deployed:**
- **NHP Server** (`layerv/nhp-server`) — Canary deploy via `canary-deploy.yml` (Step Functions, health checks, auto-rollback). Falls back to direct SSM + instance refresh on first deploy.
- **Access Controller** (`layerv/nhp-ac`) — Same canary pattern, deployed sequentially after server.
- **QURL Service** (`layerv/nhp-qurl`) — ECS task definition re-registration via `deploy-ecs-service.sh` (circuit breaker auto-rollback).

Each component can be independently enabled/disabled via workflow inputs.

**Deployment flow:**
```
manifest ──→ preflight (approval) ──→ terraform ──→ server ──→ AC ──→ QURL ──→ smoke test ──→ monitor ──→ finalize
```

**Manifest (pre-approval):** Runs immediately before the approval gate so reviewers see:
- Artifacts table with image repos, tags, and ECR push dates
- Commit details (SHA, message, author, date) and full changelog since last prod deploy
- Sandbox validation state (active color, tag match, soak duration)
- Current prod state vs. what will change (diff table)

**Safety features:**
- **Deployment lock** — SSM-based lock prevents concurrent deployments
- **Sequential deploys** — Server must be healthy before AC, AC before QURL
- **5-minute monitoring window** — Watches CloudWatch alarms post-deploy
- **Smoke tests** — Infrastructure validation + QURL health/readiness/API checks
- **Tracking** — SSM deployed-commit/deployed-at, CloudWatch deployment metrics, SNS notifications

#### Standard deployment

```bash
# Recommended: auto-detects components, validates health, confirms before executing
./scripts/trigger-prod-deploy.sh

# Preview what would be deployed without executing
./scripts/trigger-prod-deploy.sh --dry-run
```

#### Manual deployment (fallback)

<details>
<summary>Raw <code>gh workflow run</code> commands (use trigger-prod-deploy.sh instead)</summary>

##### First-time deployment (new infrastructure)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<commit-sha> \
  -f run_terraform=true
```

`run_terraform=true` runs `terraform apply` to create VPC, NLBs, ASGs, ECS, DynamoDB, etc.

##### Subsequent deployments (image update only)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<commit-sha> \
  -f run_terraform=false
```

##### Deploy only QURL service

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<any-valid-sha> \
  -f run_terraform=false \
  -f deploy_server=false \
  -f deploy_ac=false \
  -f deploy_qurl=true \
  -f qurl_image_tag=<qurl-tag>
```

If `qurl_image_tag` is omitted, the workflow reads the current tag from sandbox SSM.

</details>

#### Rollback (automatic)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<any-valid-sha> \
  -f rollback=true
```

Reads the previous `deployed-commit` from SSM and re-deploys that version. **Note:** QURL is not tracked by `deployed-commit`. To roll back QURL, provide `qurl_image_tag` explicitly or set `deploy_qurl=false`.

#### Rollback (manual)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<previous-good-sha> \
  -f run_terraform=false
```

#### Force-unlock a stale deployment lock

If a workflow was cancelled mid-deploy and the lock is stuck:

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<commit-sha> \
  -f force_unlock=true
```

#### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Deployment lock is held` | Previous workflow cancelled or failed without releasing lock | Re-run with `-f force_unlock=true` |
| Smoke tests fail after successful deploy | QURL health checks failing, service still starting | Check ECS task status and CloudWatch logs; ECS circuit breaker may auto-rollback |
| Canary deploy times out | Step Functions execution stuck or health checks never pass | Check canary workflow run (linked in step summary); canary auto-rolls back on failure |
| Rollback re-deploys same broken version | No `deployed-commit-previous` in SSM (first deploy) | Use manual rollback with explicit `-f image_tag=<known-good-sha>` |
| `QURL_IMAGE_TAG is empty` | No explicit tag and sandbox SSM has no value | Provide `-f qurl_image_tag=<tag>` or set `-f deploy_qurl=false` |
| Terraform plan fails with state lock | Concurrent CI run holds the lock | Wait for the other run, or `terraform force-unlock -force <lock-id>` |

### `blue-green-deploy.yml` — Blue/Green Deploy (Sandbox)

Switches NLB listener between blue and green ASGs for zero-downtime deployments. Used by `scheduled-release.yml` for sandbox deploys.

### `canary-deploy.yml` — Canary Deploy (Production)

Step Functions-based gradual rollout with automatic rollback. Used by `scheduled-release.yml` for production deploys.

### `scheduled-release.yml` — Scheduled Release Pipeline

Automated pipeline (weekdays 7am UTC): check for pending changes → deploy to sandbox (blue/green) → soak period → promote to prod (canary) → tag release.

## Support Workflows

| Workflow | Purpose |
|----------|---------|
| `ubuntu-build.yml` | Build and test Go code on Ubuntu |
| `build-binaries.yml` | Build release binaries |
| `codeql.yml` | GitHub CodeQL security analysis |
| `claude-code-review.yml` | AI code review on PRs |
| `claude.yml` | Claude Code agent for issue triage |
| `release-please.yml` | Automated changelog and version bumps |
| `dependabot-go-tidy.yml` | Auto-fix `go mod tidy` for Dependabot PRs |
| `prod-rollout-tasks.yml` | Enforce the PR Prod Rollout Tasks checkbox and task-ledger diff contract |
