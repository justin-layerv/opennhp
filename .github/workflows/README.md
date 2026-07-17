# CI/CD Workflows

## Deployment Workflows

### `build-and-push.yml` — Build & Deploy (Sandbox)

Triggered on every push to `main` with app or infra changes. Builds Docker
images, pushes to ECR, runs Terraform apply, and triggers instance refresh. Also
runs on PRs (plan only, no deploy).

For the sandbox relay DMZ, the workflow separates deployed proof into two hard
gates. Immediately after Terraform apply it runs
`scripts/check-relay-dmz-live.py --mode structural --environment sandbox
--wait-seconds 300` to
enumerate the live VPC, routes, SGs, endpoints and policies, DNS Firewall/query
logging, browser ALB, absence of relay UDP/NLB resources, the assigned-cell
public server NLB's sole UDP 62206 listener, WAF, canonical ASG handoff, exact
fleet convergence, and
absence of the pre-DMZ fleet. After `deploy-relay.sh` refreshes that canonical
ASG and waits for convergence, functional mode runs with `--wait-seconds 1200`
and proves target health, SSM Online
and Run Command, GuardDuty coverage, approved DNS resolution, catch-all DNS
blocking, direct-public TCP isolation, the HTTPS target group, and active relay
services. The window is 1200s (not the structural 300s) because the refresh
replaces every instance and the GuardDuty auto-managed runtime coverage the gate
asserts is observed through the eventually-consistent ListCoverage read, which
can lag the fast control-plane HEALTHY transition by >10 min on a fresh
instance; the window is a ceiling that a converged read clears in minutes. The later
`qurl-relay-bootstrap-smoke` step proves the public browser
hostname/path. The rollout runbook separately requires a real external SDK NHP
round trip through the assigned cell's server NLB UDP 62206 listener and
listener/SG/Flow proof that UDP 62207 is not public. WAF evidence applies only
to the relay HTTP path; WAF cannot inspect direct server UDP.
Neither live-detector mode is the warning-only general deployment validator.
Production is unaffected because `deploy_relay=false` and has no relay fleet.

The initial sandbox relay-DMZ cutover is complete. Every push-to-main and manual
Terraform deployment now uses `--require-dmz-boundary-noop` before any
state/taint/relay-refresh recovery and again before apply. The job fails if the
dedicated network/fleet, main-private route-table ownership, server return
rule, assigned-cell public NHP edge, sandbox CI IAM, or durable ASG handoff
would change. A future boundary migration must introduce a newly reviewed,
temporary authorization path; there is no standing workflow input that can
bypass this steady-state fence. The
[sandbox relay DMZ runbook](../../docs/runbooks/sandbox-relay-dmz-replacement.md)
documents normal deployment and verification.

### `terraform-plan-pr.yml` — Terraform Plan (PR)

Runs on every PR so branch protection can require the check; the per-PR runner cost is an accepted tradeoff for a non-deadlocking required check. It skips without AWS credentials unless the PR touches Terraform plan inputs. Markdown-only changes under `terraform/` are treated as docs and do not request AWS credentials, including prod-environment markdown because docs are classified before the prod-only Terraform glob. Prod-only `terraform/environments/prod/**` PRs report `prod-only skipped` instead of hard-gating on unrelated sandbox state.

For sandbox/shared Terraform PRs, the workflow assumes the sandbox-only `AWS_TERRAFORM_PLAN_PR_ROLE_ARN` OIDC role, runs `terraform plan -refresh=false -lock=false -var='cross_account_cost_analytics_role_arn='`, and updates a structured PR comment with add/change/destroy counts, status, and a run link. Detailed redacted failure excerpts stay in the workflow run summary and 7-day artifact rather than the durable PR comment; that artifact exposure assumes this repository stays private. The workflow never applies, but the role is still confidentiality-sensitive: it can read sandbox Terraform state, NHP-scoped SSM values including SecureStrings, Secrets Manager values, KMS-decrypted material, and account-wide IAM, CloudTrail, GuardDuty, Security Hub, and Config metadata needed for data sources and non-refreshing plan setup.

When the relay DMZ is in the planned graph,
`.github/scripts/check-relay-dmz-plan.py` consumes the actual
`terraform show -json` artifact. It checks resource cardinality and the
no-public-IP/no-default-route contract, the HTTPS-only relay ALB and SG, the
assigned-cell server NLB's sole public UDP 62206 listener and exact target-group
wiring, no public UDP 62207 or second UDP-capable edge, endpoint policies, S3
allowlists, fail-closed DNS/query logging, the dedicated DMZ logs CMK
conditions, and the narrow guardduty-data policy exception. Negative fixtures
must prove each assertion can fail. This is structural PR evidence only: endpoint
connectivity, DNS blocking, GuardDuty installation, authenticated UDP return,
target health, browser relay behavior, a valid external SDK UDP 62206 round trip,
and listener/SG/Flow negative proof that UDP 62207 is not public remain
post-apply/post-refresh gates. Deploy
and converge the compatible server return-envelope build before refreshing the
relay build; the inverse order is not supported.

The PR role uses a dedicated plan-read managed policy rather than the normal CI `terraform_read` policy, so future apply-role read expansions do not automatically widen the PR-time identity. `ssm:GetParameter*` is scoped to NHP environment paths, the three Auth0 public SPA-output parameters (`api-audience`, `domain`, `spa-client-id`), the shared registration public-key path, and the public Canonical AMI path. Adding another Auth0 SSM output requires an explicit policy and lint allowlist update. `ssm:GetDocument` is scoped to NHP and traefik-plugins sandbox document names. EC2 `Get*` is an explicit allowlist that excludes console output, console screenshots, launch-template data, and password data. S3 object-content reads are scoped to Terraform state plus NHP-managed/plugin bucket patterns. Secrets Manager reads are scoped to `Describe*`/`Get*` on NHP secrets with no account-wide `ListSecrets`. DynamoDB access is metadata-only (`Describe*`/`List*`) with no item reads, so the PR plan runs without live refresh rather than granting access to `aws_dynamodb_table_item` row contents. SQS reads are limited to queue attributes, queue URL, and queue tags on `layerv-nhp-*` queues; ElastiCache reads are `Describe*`/`List*`; API Gateway reads use `apigateway:GET` and are treated as value-bearing by the lint because API Gateway can return plaintext API key values. The cross-account cost-analytics provider assume-role is disabled only for this PR plan, so the PR role does not need `sts:AssumeRole` into the billing account. KMS metadata reads intentionally use `StringEqualsIfExists` because some KMS list APIs do not carry `aws:ResourceAccount` and can therefore expose metadata beyond a strict sandbox-account-only boundary; `kms:Decrypt` is constrained to the Terraform state alias plus NHP key aliases with `kms:ResourceAliases`.

The sole non-read-verb exception is `lambda:InvokeFunction` on the exact `${name_prefix}-relay-status:$LATEST` qualified function ARN. The invocation data source pins `$LATEST` explicitly because Lambda authorizes a qualified request against the qualified ARN; the unqualified function ARN is insufficient. That function uses a distinct handler and execution role limited to reading and validating the relay secret and public-key parameter, aside from writing its own scoped log stream; the PR role cannot invoke the multi-action relay identity/keygen Lambda. The policy lint pins this Sid, action, and exact qualified ARN so the exception cannot silently broaden to other versions, aliases, or functions.

Bootstrap order: the PR that first adds this workflow may report `bootstrap pending` while the role and secret do not exist. After that, Terraform-touching PRs fail if `AWS_TERRAFORM_PLAN_PR_ROLE_ARN` is missing. Merge the bootstrap PR, let sandbox apply create `github_actions_terraform_plan_pr_role_arn`, configure the repo secret from that output, confirm the workflow reports a successful Terraform-touching plan that exercises the scoped sandbox SSM, Secrets Manager, S3, and KMS reads behind the plan role, then add `Terraform Plan (PR)` to required PR checks. Do not require `Comment Terraform Plan (PR)`; that job is advisory/comment-only and is skipped for Dependabot and fork-token cases.

Fork PRs that touch sandbox/shared Terraform fail this check because GitHub does not expose the required repo secrets to forked `pull_request` runs; forked prod-only Terraform PRs still report `prod-only skipped` because they do not need sandbox secrets or AWS credentials. That red check is expected for non-prod Terraform fork PRs rather than evidence that the forked code is broken; a maintainer must re-push the branch inside `layervai/nhp` if a forked Terraform change needs the sandbox plan gate. The fork explanation is written to the failing check summary instead of a PR comment because the fork token cannot safely write comments. Dependabot Terraform PRs report `dependabot skipped` instead of failing because Dependabot `pull_request` runs also cannot read regular repository secrets; the comment job is skipped for Dependabot to avoid turning its read-only token into a noisy 403. Provider lockfile bumps still get Terraform validation, and a maintainer can re-push the branch if a full sandbox plan is needed.

The workflow uses deterministic placeholders for app-level Terraform variables such as auth signing/AES, AC license, and Grafana auth. The Auth0 provider still uses a short-lived token fetched from repo secrets because Auth0-managed resources remain in the Terraform graph; before making the check required, the rollout sign-off must confirm the Auth0 Terraform client grant is read-only or explicitly accept same-repo PR exposure to any write-capable grant.

Before using the long-lived Auth0 client secret, the workflow restores `build-lambda-packages`, `fetch-auth0-token.sh`, the plan summarizer, and a base-commit copy of sandbox `terraform.tfvars` from the trusted base commit so PR-head edits cannot tamper with those helper paths or redirect the client-secret token request to a different `auth0_domain`. `terraform plan` still executes PR-head HCL and tfvars, so same-repo PR authors can still exfiltrate the short-lived Auth0 token or sandbox read material through plan-time constructs such as `data.http`, the `external` provider, or provider endpoint overrides.

Helper-path changes are therefore reviewed and linted in their own PR, but this secrets-bearing plan gate deliberately exercises the trusted base helper versions until those changes merge. A PR that changes `build-lambda-packages` is not exercising its PR-head Lambda packaging logic in this plan gate; that trusted-helper change is first exercised here after merge. Summarizer-only PRs do not request sandbox credentials because the summarizer is output-only and fixture-covered, and the workflow restores the base-copy summarizer before formatting plan output. A legitimate `auth0_domain` change may need to land before the plan gate can validate dependent Terraform changes.

The IAM trust is repo-wide `pull_request` because AWS cannot evaluate GitHub `workflow_ref` custom claims, so the fork rejection and secret gating are workflow-level controls. A future tighter design can use a GitHub Environment because that changes the OIDC subject to an environment-scoped `sub`. The Terraform-execution job has only `contents: read` and `id-token: write`; PR comment writes happen in a separate job that downloads a comment-safe summary artifact. Failure excerpts are redacted on a best-effort basis, kept out of the PR comment, and intended for this private repository run summary/artifact path with 7-day retention; revisit even that artifact exposure before making the repository public. Treat add/change/destroy counts as review signals: image tags come from the PR head/current SSM values, and placeholder app secrets may make launch-template-sensitive resources appear changed.

### `promote-to-prod.yml` — Promote to Production

> **Preferred method:** Use `./scripts/trigger-prod-deploy.sh` instead of running `gh workflow run` manually. The script reads SSM state from both accounts, validates sandbox health, auto-detects which components changed, and generates the correct command. Run with `--dry-run` to preview without executing.

**Manual workflow** for promoting existing sandbox ECR images to production. No rebuild — uses images already built and validated in sandbox. Orchestrates deployment through canary (server/AC), ECS task def registration (QURL), and ASG instance refresh (qurl-reverse-tunnel-server).

**Components deployed:**
- **NHP Server** (`layerv/nhp-server`) — Canary deploy via `canary-deploy.yml` (Step Functions, health checks, auto-rollback). Falls back to direct SSM + instance refresh on first deploy.
- **Access Controller** (`layerv/nhp-ac`) — Same canary pattern, deployed sequentially after server.
- **QURL Service** (`layerv/nhp-qurl`) — ECS task definition re-registration via `deploy-ecs-service.sh` (circuit breaker auto-rollback).
- **qURL Reverse Tunnel Server** (`layerv/qurl-reverse-tunnel-server`) — SSM image-tag update plus ASG instance refresh, followed by the QRtS smoke workflow.

Each component can be independently enabled/disabled via workflow inputs.

**Deployment flow:**
```
manifest ──→ preflight (approval) ──→ terraform ──→ server ──→ AC ──→ QURL ──→ QRtS ──→ smoke tests ──→ monitor ──→ finalize
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
- **Smoke tests** — Infrastructure validation + QURL/NHP/API checks + QRtS ASG smoke
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
| `claude.yml` | Claude Code for issue triage and PR slash commands (explicit model pin) |
| `release-please.yml` | Automated changelog and version bumps |
| `dependabot-go-tidy.yml` | Auto-fix `go mod tidy` for Dependabot PRs |
| `prod-rollout-tasks.yml` | Enforce the PR Prod Rollout Tasks checkbox and task-ledger diff contract |

### Updating the Claude model pin

The Claude workflows intentionally use the same proven model. A model upgrade
must make all of these changes in one PR:

1. Validate the candidate model with the repository credential.
2. Update `claude_args` in both `claude.yml` and `claude-code-review.yml`.
3. Add the validated model to `PROVEN_MODELS` in
   `scripts/check-claude-model-lockstep.py`.
4. Update the current-pin assertions in
   `tests/scripts/test_check_claude_model_lockstep.py` when the pinned model
   changes.
5. Run `make lint-workflows`.

Keep each `claude_args` value on one single-quoted line and set the model only
through `--model`. Alternate scalar forms, embedded single quotes, native
`model:` inputs, and one-sided or unproven pins require an explicit guard design
change rather than a workflow-only edit.
