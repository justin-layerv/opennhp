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
public server NLB's sole UDP 443 listener, WAF, canonical ASG handoff, exact
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
instance; the window is a ceiling that a converged read clears in minutes. So the
wider window does not also slow detection of a *real* break, the gate fails fast
once coverage stays `UNHEALTHY` with an `Issue` continuously past a provisioning
bound — persistence, not a single read, so a still-provisioning agent's transient
`"Waiting for SSM notification"` never false-fails. The later
`qurl-relay-bootstrap-smoke` step proves the public browser
hostname/path. The rollout runbook separately requires a real external SDK NHP
round trip through the assigned cell's server NLB UDP 443 listener and
listener/SG/Flow proof that UDP 62207 is not public. WAF evidence applies only
to the relay HTTP path; WAF cannot inspect direct server UDP.
Neither live-detector mode is the warning-only general deployment validator.
Production is unaffected because `deploy_relay=false` and has no relay fleet.

The initial sandbox relay-DMZ cutover is complete. Every push-to-main and manual
Terraform deployment now uses `--require-dmz-boundary-noop` before any
state/taint/relay-refresh recovery and again before apply. The current
sandbox-only migration adds `--allow-udp-source-fence-replacement`, which
admits only the exact create-before-destroy public cell0 NLB replacement,
bounded listener handoff, creation of its SG rules, and deletion of the legacy
public server-SG rule. The listener itself deliberately uses Terraform's
destroy-before-create replacement order because AWS forbids one target group
from serving listeners on two different load balancers. The ordinary
post-apply convergence plan does not carry that allowance; it instead uses
`--require-udp-source-fenced-topology` and must prove both the complete fenced
topology and DMZ boundary are back to no-op. The job otherwise fails if the
dedicated network/fleet, main-private route-table ownership, server return
rule, assigned-cell public NHP edge, sandbox CI IAM, or durable ASG handoff
would change. A future boundary migration must introduce a newly reviewed,
exact authorization path; there is no workflow input that can broadly bypass
this steady-state fence. The
[sandbox relay DMZ runbook](../../docs/runbooks/sandbox-relay-dmz-replacement.md)
documents normal deployment and verification.

#### Sandbox Control auto-deploy (`deploy-sandbox-control`)

`build-and-push.yml` applies the isolated sandbox Control root
(`terraform/control/environments/sandbox` — the Connector Authority foundation,
the `ca-*` runtime functions, and the Hub edge + Fargate worker) on every
sandbox deploy. Control runs first and holds the same `deploy-sandbox-infra`
writer lock, because Control and cell0 must never apply concurrently. After its
selector is settled, Control emits a positive `consumer_rollout_ready` receipt.
Only then does cell0 create a fresh saved plan; cell1 creates its own plan after
cell0 applies. There is no pre-Control cell plan artifact to reuse. Both roots
publish the selected aliases into their S3 bootstrap objects, and each
blue/green leg refreshes the affected server fleet before validation. This order
is load-bearing: the alias ARNs are materialized at Terraform/apply and instance
boot, not read dynamically by an already-running server. It plans with
`-detailed-exitcode`, reports `converged` and stops when there is nothing to do,
and otherwise applies in-run. `Control` renders in the Slack pipeline before
Validate, distinguishing an apply from a no-op convergence, from a leg
superseded by a newer push. Supersession remains a successful no-op, but emits
no consumer receipt, so that old run cannot plan or roll a predecessor graph.

Validation gates on both cell refreshes and then fails closed unless every
Authority operation has the selected color in all three materialization layers:
the Control pointer, each cell's S3 bootstrap object, and every InService active
server's host env file plus running container. A stale consumer therefore blocks
the pipeline before SDK enrollment gates can be asked to trust the cutover.

Turning all seven gates dark is a teardown of the Hub and the Authority
runtime, not a deploy. The reader accepts that shape (it is the documented
rollback) but the automatic leg fails closed on it, so a full rollback stays
attended. A partial rollback auto-applies.

The seven Authority/Hub runtime gates come from
`.github/control-sandbox-runtime-gates.json`. That file exists because every
gate's committed Terraform default is the DARK value while live sandbox is the
opposite on all seven: an unattended plan that fell back to those defaults would
not deploy the Hub, it would destroy it — returning the gates to their
committed-closed defaults is the documented *rollback*. `control-sandbox-update.yml`
asserts its own dispatch inputs against the same file, so the attended and
unattended paths cannot diverge and then revert one another. Changing a value
there changes live sandbox on the next main push; land it in the same commit as
the Terraform that needs it. `scripts/check-control-leg-surfaced.sh` fences the
wiring, the shared writer lock, the gate-file sourcing, the positive consumer
receipt, and the complete Control → fresh cell plans → runtime refreshes →
validation DAG. Its fixtures also prove that superseded and partial-apply
Control states cannot release a consumer plan.

On an infra-skipped push (a gate-file or docs-only change) Control applies and
`deploy-sandbox-validate` does not run, because validate still requires both cell
infra/refresh paths. That is deliberate: the Control job's in-job post-apply
refresh-enabled no-op and live dark-boundary proof cover Control itself. Any run
that materializes cell infrastructure must complete both refreshes and the live
consumer-convergence gate.

**Keep this workflow's rationale short.** `build-and-push.yml` sits near a size
ceiling that GitHub does not surface as a normal error: a file that grows past
it stops producing `pull_request` runs entirely and instead emits a `push` run
named after the file path, with zero jobs and a bare `failure`, no annotations
and no logs. Because `Test`, `Build server`, and `Build ac` are required checks
that live here, they simply never report and the PR is unmergeable with nothing
saying why. Detail belongs in this README; the workflow keeps pointers.

Plan and apply share one job and one state binding, so the attended workflow's
cross-run artifact custody (saved-plan digests, the two-day window, single-use
artifact consumption, the apply-rerun ban) does not apply here; the staleness
guard is the state `{serial, sha256}` re-proved immediately before apply, which
is what it is in that workflow too. Every source-owned CONTENT check still runs:
`check-control-sandbox-first-apply.py`, `check-connector-authority-foundation.sh`,
the pre-apply live dark-boundary proof, and the post-apply refresh-enabled no-op.
A failed apply does not retry: it directs recovery to an attended
`control-sandbox-update.yml` plan from current main and current live state.

### `control-sandbox-update.yml` — Control Sandbox Update

Manually plans, applies, or verifies the isolated sandbox Connector Control
Terraform root. Routine convergence is now automatic (see the
`deploy-sandbox-control` section above); this workflow remains the attended path
for reviewing a diff before it lands and for recovering from a failed automatic
apply. Its guard binds the seven runtime-gate inputs to
`.github/control-sandbox-runtime-gates.json` before any AWS access, so a
dispatch cannot apply gates the automatic leg would then revert.
`plan` and `apply` are separate dispatches: the apply operator
must copy the reviewed plan run, commit, saved-plan digest, and exact versioned
state identity from the plan summary. The apply then revalidates the successful
source run, two-day age window, artifact hashes, live `main`, source-owned
Control plan contract, and unchanged S3 state immediately before applying the
saved binary plan. Immediately before apply it also proves the untracked live
dark-network boundary, then deletes the source artifact so the reviewed plan is
single-use. Apply workflow reruns are rejected. All operations use the
`sandbox` environment and share the ordinary `deploy-sandbox-infra` writer
lock. There is no production operation; production Control remains blocked on
#3279.

The uploaded binary `tfplan` is confidentiality-equivalent to its JSON
rendering and includes the state snapshot Terraform needs for an exact saved-
plan apply. Omitting `tfplan.json` and raw `state.tfstate` minimizes retained
copies; it does not sanitize the binary plan. The exact Control contract is
currently safe for repository Actions readers because it contains only
infrastructure and secret metadata: the OTP pepper is seeded out of band,
Redis is IAM-only and passwordless, and the checked inputs contain no sensitive
variable. Adding a secret-bearing resource or input requires a newly reviewed
artifact-custody design before this workflow may carry it.

An apply failure is not retried with the stale plan. The failed run publishes a
sanitized post-failure state identity when it can safely capture one; recovery
is a new `plan` dispatch from current `main` and current live state. The
source-owned Control checker must explicitly accept that partial-retry shape.
Successful applies and explicit `verify` runs require a refresh-enabled no-op
and upload only sanitized state, inventory, live-boundary, and secret-readiness
summaries—not raw Terraform state or plan JSON.

### `publish-hub-image.yml` — Publish Connector Hub Image

Manual artifact-only carrier for the dark Connector Hub. It runs only from
`main` and declares the dedicated `hub-publish-sandbox` or
`hub-publish-production` GitHub Environment. Before requesting an AWS identity,
the job reads the live Environment settings and requires exactly Justin
(`178750268`) as the sole reviewer plus exactly one custom `main` branch policy;
the shared deployment Environments are rejected.

The workflow builds the existing Hub image contract for linux/amd64 with the
exact source SHA and commit time, applies the repository's HIGH/CRITICAL Trivy
policy, then re-reads live `main` and rejects a dispatch SHA that became stale
during approval/build. It assumes only the environment-specific Hub publisher
role, scopes those AWS credentials to the publish/scan/pin step, and removes
the registry login before provenance upload. It
publishes no mutable tag: the sole remote tag is the source SHA. The carrier
binds the registry manifest digest back to the built config, architecture, and
OCI source/revision labels; waits for the independent ECR scan to complete with
zero HIGH/CRITICAL findings; writes only the environment's
`/<env>/nhp/control/hub/image-digest`; and requires exact readback. A private
90-day JSON artifact records secret-free source, role, image, scan, and pin
provenance.

The carrier creates no ECS task, service, NLB, DNS, Authority permission, or
traffic path. The ordinary `build-and-push.yml` Hub matrix row remains
`publish: false`; publication is deliberately separate from normal application
build/deploy credentials.

### `terraform-plan-pr.yml` — Terraform Plan (PR)

Runs on every PR so branch protection can require the check; the per-PR runner cost is an accepted tradeoff for a non-deadlocking required check. It skips without AWS credentials unless the PR touches Terraform plan inputs. Markdown-only changes under `terraform/` are treated as docs and do not request AWS credentials, including prod-environment markdown because docs are classified before the prod-only Terraform glob. Prod-only `terraform/environments/prod/**` PRs report `prod-only skipped` instead of hard-gating on unrelated sandbox state.

For sandbox/shared Terraform PRs, the workflow assumes the sandbox-only `AWS_TERRAFORM_PLAN_PR_ROLE_ARN` OIDC role, runs `terraform plan -refresh=false -lock=false -var='cross_account_cost_analytics_role_arn='`, and updates a structured PR comment with add/change/destroy counts, status, and a run link. Detailed redacted failure excerpts stay in the workflow run summary and 7-day artifact rather than the durable PR comment; that artifact exposure assumes this repository stays private. The workflow never applies, but the role is still confidentiality-sensitive: it can read sandbox Terraform state, NHP-scoped SSM values including SecureStrings, Secrets Manager values, KMS-decrypted material, and account-wide IAM, CloudTrail, GuardDuty, Security Hub, and Config metadata needed for data sources and non-refreshing plan setup.

The sandbox Control plan needs the seven Authority/Hub runtime gates, and it reads them from `.github/control-sandbox-runtime-gates.json` via `control-sandbox-runtime-gates.py flags` — the same reader `build-and-push.yml` and `control-sandbox-update.yml` use. It plans the gates **the PR proposes**, not the gates live sandbox currently has, so a PR that retires one plans its retirement; the gate file and its reader are therefore plan inputs in `classify-terraform-plan-pr-changes.sh` and a gate-only PR gets a real plan instead of a credential-free skip. `verify-tfvars` binds the generated tfvars back to the gate file so a generator rename cannot make this lane plan a shape nobody chose. Unlike the unattended deploy leg, an all-dark gate file is planned rather than refused: nothing is applied here, and that destroy plan is the review evidence a rollback PR exists to produce. Whether such a plan may merge remains `check-control-sandbox-first-apply.py`'s decision, which admits only named, reviewed transitions.

When the relay DMZ is in the planned graph,
`.github/scripts/check-relay-dmz-plan.py` consumes the actual
`terraform show -json` artifact. It checks resource cardinality and the
no-public-IP/no-default-route contract, the HTTPS-only relay ALB and SG, the
assigned-cell server NLB's sole public UDP 443 listener and exact target-group
wiring, no public UDP 62207 or second UDP-capable edge, endpoint policies, S3
allowlists, fail-closed DNS/query logging, the dedicated DMZ logs CMK
conditions, and the narrow guardduty-data policy exception. Negative fixtures
must prove each assertion can fail. This is structural PR evidence only: endpoint
connectivity, DNS blocking, GuardDuty installation, authenticated UDP return,
target health, browser relay behavior, a valid external SDK UDP 443 round trip,
and listener/SG/Flow negative proof that UDP 62207 is not public remain
post-apply/post-refresh gates. Deploy
and converge the compatible server return-envelope build before refreshing the
relay build; the inverse order is not supported.

The PR role uses a dedicated plan-read managed policy rather than the normal CI `terraform_read` policy, so future apply-role read expansions do not automatically widen the PR-time identity. `ssm:GetParameter*` is scoped to NHP environment paths, the three Auth0 public SPA-output parameters (`api-audience`, `domain`, `spa-client-id`), the shared registration public-key path, and the public Canonical AMI path. Adding another Auth0 SSM output requires an explicit policy and lint allowlist update. `ssm:GetDocument` is scoped to NHP and traefik-plugins sandbox document names. EC2 `Get*` is an explicit allowlist that excludes console output, console screenshots, launch-template data, and password data. S3 object-content reads are scoped to Terraform state plus NHP-managed/plugin bucket patterns. Secrets Manager reads are scoped to `Describe*`/`Get*` on NHP secrets with no account-wide `ListSecrets`. DynamoDB access is metadata-only (`Describe*`/`List*`) with no item reads, so the PR plan runs without live refresh rather than granting access to `aws_dynamodb_table_item` row contents. SQS reads are limited to queue attributes, queue URL, and queue tags on `layerv-nhp-*` queues; ElastiCache reads are `Describe*`/`List*`; API Gateway reads use `apigateway:GET` and are treated as value-bearing by the lint because API Gateway can return plaintext API key values. The cross-account cost-analytics provider assume-role is disabled only for this PR plan, so the PR role does not need `sts:AssumeRole` into the billing account. KMS metadata reads intentionally use `StringEqualsIfExists` because some KMS list APIs do not carry `aws:ResourceAccount` and can therefore expose metadata beyond a strict sandbox-account-only boundary; `kms:Decrypt` is constrained to the Terraform state alias plus NHP key aliases with `kms:ResourceAliases`.

The sole non-read-verb exception is `lambda:InvokeFunction` on the exact `${name_prefix}-relay-status:$LATEST` qualified function ARN. The invocation data source pins `$LATEST` explicitly because Lambda authorizes a qualified request against the qualified ARN; the unqualified function ARN is insufficient. That function uses a distinct handler and execution role limited to reading and validating the relay secret and public-key parameter, aside from writing its own scoped log stream; the PR role cannot invoke the multi-action relay identity/keygen Lambda. The policy lint pins this Sid, action, and exact qualified ARN so the exception cannot silently broaden to other versions, aliases, or functions.

Bootstrap order: the PR that first adds this workflow may report `bootstrap pending` while the role and secret do not exist. After that, Terraform-touching PRs fail if `AWS_TERRAFORM_PLAN_PR_ROLE_ARN` is missing. Merge the bootstrap PR, let sandbox apply create `github_actions_terraform_plan_pr_role_arn`, configure the repo secret from that output, confirm the workflow reports a successful Terraform-touching plan that exercises the scoped sandbox SSM, Secrets Manager, S3, and KMS reads behind the plan role, then add `Terraform Plan (PR)` to required PR checks. Do not require `Comment Terraform Plan (PR)`; that job is advisory/comment-only and is skipped for Dependabot and fork-token cases.

Fork PRs that touch sandbox/shared Terraform fail this check because GitHub does not expose the required repo secrets to forked `pull_request` runs; forked prod-only Terraform PRs still report `prod-only skipped` because they do not need sandbox secrets or AWS credentials. That red check is expected for non-prod Terraform fork PRs rather than evidence that the forked code is broken; a maintainer must re-push the branch inside `layervai/nhp` if a forked Terraform change needs the sandbox plan gate. The fork explanation is written to the failing check summary instead of a PR comment because the fork token cannot safely write comments. Dependabot Terraform PRs report `dependabot skipped` instead of failing because Dependabot `pull_request` runs also cannot read regular repository secrets; the comment job is skipped for Dependabot to avoid turning its read-only token into a noisy 403. Provider lockfile bumps still get Terraform validation, and a maintainer can re-push the branch if a full sandbox plan is needed.

The workflow uses deterministic placeholders for app-level Terraform variables such as auth signing/AES, AC license, and Grafana auth. The Auth0 provider still uses a short-lived token fetched from repo secrets because Auth0-managed resources remain in the Terraform graph; before making the check required, the rollout sign-off must confirm the Auth0 Terraform client grant is read-only or explicitly accept same-repo PR exposure to any write-capable grant.

The workflow restores `build-lambda-packages` and the plan summarizer from the trusted base commit so PR-head edits cannot tamper with those helper paths. `terraform plan` still executes PR-head HCL and tfvars, so same-repo PR authors can still exfiltrate sandbox read material through plan-time constructs such as `data.http`, the `external` provider, or provider endpoint overrides. **No Auth0 credential is exposed any more:** #3284 retired the Auth0 Terraform provider, deleting the token fetch, the long-lived client secret, and the base-tfvars `auth0_domain` pin that protected it.

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

Switches NLB listener between blue and green ASGs for zero-downtime deployments. Dispatched by `build-and-push.yml` sandbox deploys.

### `canary-deploy.yml` — Canary Deploy (Production)

Step Functions-based gradual rollout with automatic rollback. Used by `promote-to-prod.yml` for production deploys.

## Support Workflows

| Workflow | Purpose |
|----------|---------|
| `ubuntu-build.yml` | Build and test Go code on Ubuntu |
| `build-binaries.yml` | Build release binaries |
| `codeql.yml` | GitHub CodeQL security analysis |
| `claude-code-review.yml` | Ready-candidate AI review from a default-branch-trusted `pull_request_target` workflow |
| `claude.yml` | Claude Code for trusted default-branch PR issue-comment commands |
| `release-please.yml` | Automated changelog and version bumps |
| `dependabot-go-tidy.yml` | Auto-fix `go mod tidy` for Dependabot PRs |
| `prod-rollout-tasks.yml` | Enforce the PR Prod Rollout Tasks checkbox and task-ledger diff contract |

### Updating the Claude workflow contract

The Claude workflows intentionally use the same proven action and model. An
action or model upgrade must make all of these changes in one PR:

1. Validate the candidate action and model with the repository credential,
   including a fail-closed `is_error: true` result.
2. Update the immutable action SHA and `claude_args` in both `claude.yml` and
   `claude-code-review.yml`.
3. Update `PROVEN_ACTION_REF` and, for a model change, `PROVEN_MODELS` in
   `scripts/check-claude-model-lockstep.py`.
4. Update the current-pin assertions in
   `tests/scripts/test_check_claude_model_lockstep.py`.
5. Run `make lint-workflows`.

The pinned SHA is hardcoded in three places on purpose. It is a tamper fence,
not a cache: the pin may only move when a human has re-proved the properties
below against the candidate tree, so it must not be derived from the workflow
files the bump edits. Dependabot can therefore never green its own
`claude-code-action` PR — every bump needs the paired edit above, and a red
`validate-workflows` on such a PR is the fence working, not a flake.

The properties that must be re-proved on each bump, because the workflows
depend on them rather than on the action's documented interface:

- `base-action/src/run-claude-sdk.ts` — a terminal SDK result with
  `subtype: success` and `is_error: true` fails the step.
- `src/github/operations/restore-config.ts` — the dereferencing `.claude-pr/`
  snapshot, and its `SENSITIVE_PATHS` list still matching the `sensitive_paths`
  array the interactive preflight fences.
- `src/github/operations/git-config.ts` — with `use_commit_signing: true`, the
  action installs no Git credentials and leaves `origin` alone.

**Held at v1.0.186: do not bump to v1.0.187 or later without redesigning the
local-origin shim.** v1.0.187 added `replaceCheckoutCredentials()` and calls it
from the `use_commit_signing: true` branch of both `src/modes/tag/index.ts` and
`src/modes/agent/index.ts` — the branch that previously did nothing. It runs
`git remote set-url origin` against a `github.com` URL, so it overwrites the
local-origin shim both workflows install and points Git back at a credentialed
remote. Because neither workflow sets `allowed_non_write_users`, it takes the
`else` path and embeds the token directly in `.git/config`
(`https://x-access-token:<token>@github.com/...`) inside the tree Claude runs
in. That contradicts two invariants asserted above — the shim exposing only the
validated head and base refs, and API signing not installing Git credentials —
so a bump past v1.0.186 is a guard design change, not a version edit.
`.github/dependabot.yml` holds the pin at `<1.0.187` with the same rationale.

Keep each `claude_args` value on one single-quoted line and set the model only
through `--model`. Alternate scalar forms, embedded single quotes, native
`model:` inputs, and one-sided or unproven pins require an explicit guard design
change rather than a workflow-only edit. Interactive commands are PR-only and
enter only through `issue_comment`, whose workflow definition GitHub loads from
the default branch. They require a current write-capable collaborator, reject
fork heads, and check out the API-resolved immutable head SHA. They omit the
workflow token input and use the action's OIDC/GitHub App token with commit
signing for accepted edits;
checkout credentials remain disabled. Before the pinned action performs that
checkout, the workflow rejects symlinks, gitlinks, and other non-regular leaves
under v1.0.186's startup-sensitive preservation paths; otherwise the action's
dereferencing `.claude-pr/` snapshot could materialize an out-of-tree secret.
Both workflows replace the GitHub remote
with a local-origin shim that exposes only the validated head and base refs
while retaining their required reachable history. The interactive path
preflights the pinned action's dynamic head-depth and shallow-base fetches; the
automatic path keeps the local workspace on a trusted default-branch snapshot,
reads PR data only through its GitHub MCP allowlist, and preflights its head/base
snapshot fetches. Neither path points Git at a credentialed GitHub remote.

Automatic review must retain its default-branch-trusted
`pull_request_target` event, PR-author bot exclusion, same-repository head and
base, ready-candidate guard, `opened`/`synchronize`/`reopened`/
`ready_for_review` triggers, and per-PR cancellation. It uses the narrowly
scoped workflow token with API signing so v1.0.186 does not install Git
credentials. Its model receives only the enumerated read/comment GitHub MCP
tools; local file, shell, network, delegation, and GitHub file-write tools stay
denied. The interactive tag-mode entry point excludes only the exact
`github-actions[bot]` login from model context, and human feedback remains in
scope. Do not add `pull_request`, `pull_request_review`, or
`pull_request_review_comment` to either secrets-bearing workflow: GitHub loads
those workflow definitions from the PR merge ref before any job-level guard,
checkout, or shell preflight can run.

A terminal PR refresh must prove the current and expected repository, branch,
and commit snapshots still match, the interactive checkout is on the expected
head, the automatic checkout remains on its recorded trusted snapshot, and both
checkouts still use their credential-free local origin, submodule-safe fetch
configuration, and exact head/base source and remote-tracking refs before either
workflow can pass. Automatic review additionally requires a run-specific marker
on the final line of the workflow bot's published PR comment; a nonempty action
execution artifact alone is not publication proof.
An interactive edit intentionally fails that old-head run and requires a fresh
terminal pass on the new head.
