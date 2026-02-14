# CI/CD Workflows

## Deployment Workflows

### `build-and-push.yml` — Build & Deploy (Sandbox)

Triggered on every push to `main` with app or infra changes. Builds Docker images, pushes to ECR, runs Terraform apply, and triggers instance refresh. Also runs on PRs (plan only, no deploy).

### `promote-to-prod.yml` — Promote to Production

**Manual workflow** for promoting existing sandbox ECR images to production. No rebuild — uses images already built by `build-and-push.yml`.

#### First-time deployment (new infrastructure)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<commit-sha> \
  -f run_terraform=true \
  -f deploy_server=true \
  -f deploy_ac=true
```

`run_terraform=true` runs `terraform apply` to create VPC, NLBs, ASGs, ECS, DynamoDB, etc. Required on first deploy or when Terraform code changes.

#### Subsequent deployments (image update only)

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<commit-sha> \
  -f run_terraform=false \
  -f deploy_server=true \
  -f deploy_ac=true
```

`run_terraform=false` skips Terraform and only updates SSM image tags + triggers instance refresh. Use this when only the application code changed.

#### Rollback

```bash
gh workflow run promote-to-prod.yml --ref main \
  -f image_tag=<previous-good-sha> \
  -f run_terraform=false
```

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
