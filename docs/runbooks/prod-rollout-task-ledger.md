# Prod Rollout Task Ledger

This ledger tracks concrete PR-specific tasks that must happen before, during,
or after a production rollout. It is not a behavior-change log; add an entry
only when a person or automation must do something, verify something, or own a
rollback step for prod.

## PR Update Rule

Update this ledger in the same PR when a change creates any concrete prod
rollout task, including:

- Pre-rollout tasks such as smoke tests, config checks, secret readiness,
  migration readiness, or customer-risk review.
- Rollout tasks such as deploy ordering, feature flag flips, ASG refreshes,
  manual console work, migrations, or secrets/config writes.
- Post-rollout tasks such as smoke tests, metrics, dashboards, logs,
  alarms, or customer-visible probes.
- Rollback tasks such as exact config reverts, deploy rollback steps, or known
  rollback limits.
- Cross-repo contracts with qurl-service, qurl-reverse-tunnel-server/client, or
  traefik-plugins.

Add new entries immediately above the `New active entries` anchor comment
(newest last) to preserve chronology. If concurrent PRs edit the same insertion
point, keep both entries in commit order.

The CI PR-body check requires exactly one Prod Rollout Tasks checkbox for
ready, non-draft PRs and verifies this file changed when `Updated` is selected.

- Checkbox labels: do not edit the label text or add trailing notes to those
  checkbox lines; the workflow intentionally matches the labels exactly. Put
  context in the ledger entry or in separate PR-body prose. Do not select
  `Confirmed this PR has no prod rollout tasks` when release coordination
  belongs in this ledger. Do not add a ledger entry just to describe behavior;
  add one only for required rollout tasks.
- Required status: the workflow produces the `Check PR body` status (shown as
  `prod-rollout-tasks / Check PR body` in branch-protection selectors). Until
  branch protection or the repo's aggregate merge gate requires that status, it
  is advisory only.
- New PRs: ready, non-draft PRs fail this check until the author selects exactly
  one checkbox. This is intentional; it forces the prod rollout task decision
  before merge.
- Draft PRs: draft PRs return success early from the CI body check so required
  checks still report a conclusion while work is in progress. Draft PRs are
  checked when they transition to `ready_for_review`.
- Automation PRs: bot-authored PRs and automation that authors PRs as a `User`
  via a PAT or user token must include this section once ready for review,
  including release and dependency automation. If automation cannot populate the
  PR body, a maintainer must edit the PR body before merge.
- Reviewer duty: reviewers still enforce whether the selected checkbox is
  truthful and whether any task entry is complete.
- Deferrals: if release work is intentionally deferred, create or link a GitHub
  issue and label it with existing repo labels that apply. Prefer
  component/area, type, and priority labels when those namespaces already exist.
  Do not invent missing release labels just for this ledger.
  Do not defer a required task entry to a follow-up PR; add the entry in the
  current PR, and record any deferred work in that entry's follow-up list.

Do not paste secret values, customer data, or private production hostnames into
entries. Record parameter names, check names, metrics, run links, and evidence
links instead.

## Entry Ownership

The PR author adds the entry before merge and leaves `Status: Open` unless the
listed pre-rollout tasks are already satisfied. The rollout coordinator is the
person owning the prod deploy or release checklist for that environment. The
rollout coordinator moves an entry to `Ready` when pre-rollout tasks are
satisfied, `Deferred` when linked issues own the remaining tasks, and `Verified`
after post-rollout evidence is available. Review `Deferred` entries at each prod
release cut until the linked issue closes or the entry is `Verified`. When the
linked issue closes, move the entry back to `Ready` if rollout or verification
tasks remain, or to `Verified` if evidence is already complete. The rollout
coordinator also owns moving `Verified` entries to Completed Entries. If that
happens after the original PR is merged, use a follow-up docs PR. A linked issue
comment can hold temporary evidence, but reconcile the ledger at the next release
cut.

## Status Values

- `Open`: prod rollout tasks exist but are not yet ready to execute.
- `Ready`: pre-rollout tasks are satisfied and the entry is waiting for rollout,
  is actively rolling out, or is waiting for post-rollout tasks.
- `Deferred`: follow-up tasks are tracked by a linked GitHub issue.
- `Verified`: post-rollout tasks are complete; move the entry to
  Completed Entries and add completed date/evidence.

Keep `Status` to one of these values. Put extra rollout context in
`Status note`. For `Ready`, `Status note` must say whether the entry is waiting
for rollout, actively rolling out, or waiting for post-rollout tasks.

## Active Entries

Entries stay here while any pre-rollout, rollout, post-rollout, rollback, or
deferred task remains. `Ready` and `Deferred` entries are still active; move an
entry to Completed Entries only after `Status: Verified`.

### 2026-06-05 - PR #2326 - qurl-scanner Lambda + EventBridge + IAM

- Ledger PR: [#2326](https://github.com/layervai/nhp/pull/2326)
- Source PR / issue: [PR #2326](https://github.com/layervai/nhp/pull/2326) /
  [layervai/qurl-service#852](https://github.com/layervai/qurl-service/pull/852)
- Component: `terraform/modules/qurl-service` (scanner Lambda + cron + alarm),
  `terraform/modules/ecr` (scanner-lambda repo)
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Confirm qurl-service `main` build has published at least one
    `layerv/qurl-scanner-lambda` image to ECR and written its SHA to
    `/<name_prefix>/qurl-scanner-lambda-image-tag` SSM. The Lambda's
    `package_type = "Image"` validates the image at create time, so a flag-ON
    apply against an empty repo fails with
    `InvalidParameterValueException: Source image ... does not exist`.
  - Confirm the qurl-service repo's branch-protection check requires the
    `Docker Build (scanner-lambda)` job before merge to main (pre-merge task A
    from PR #852 cr round 3). Without it, a later qurl-service main merge can
    push a broken image whose deploy here fails-loud on next apply.
  - **Prod SSM image-tag write (HARD PROD PRECONDITION — cr round 6 on
    PR #2326)**: qurl-service `build-and-deploy.yml` writes ONLY the
    SANDBOX SSM image-tag path (`SSM_SCANNER_LAMBDA_IMAGE_TAG_SANDBOX`);
    the prod path (`/layerv-nhp-prod/qurl-scanner-lambda-image-tag`) is
    seeded `"latest"` by Terraform and never touched by qurl-service
    CI. If the prod flag flips while the SSM param still says
    `"latest"`, `image_uri` resolves to `<prod-ecr>:latest` — and
    ECR replication copies images by tag, so unless a `latest` tag
    happens to exist in prod ECR (qurl-service CI doesn't push one),
    the Lambda create fails with `InvalidParameterValueException:
    Source image ... does not exist`. Three valid resolutions:
    1. **Operator manual write before flag flip (current intent)**:
       `aws ssm put-parameter --name /layerv-nhp-prod/qurl-scanner-lambda-image-tag \
         --value <sandbox-SHA-verified-via-replication-preflight-below> \
         --overwrite --profile <prod-profile>` BEFORE the
       second prod apply with `qurl_scanner_lambda_enabled = true`.
    2. **promote-to-prod workflow step** (mirrors how
       `qurl-reverse-tunnel-server` propagates its SSM image-tag
       across envs — see `terraform/modules/qurl-reverse-tunnel-server`
       for the precedent). Track as a qurl-service follow-up if the
       manual write proves error-prone.
    3. **`latest` tag replication**: have qurl-service CI push a
       `latest` tag alongside the SHA; ECR replication would copy it
       to prod. Not recommended — defeats the "explicit SHA pin per
       apply" property the data-source pattern provides.
    Default to (1) until prod rollout is happening at a cadence that
    motivates automating it.
  - **Reserved-concurrency account-pool check (cr round 8 low/ops)**:
    `reserved_concurrent_executions = 1` on the scanner Lambda
    permanently subtracts 1 from the account's unreserved-concurrency
    budget. AWS rejects the apply at create time with
    `InvalidParameterValueException: Specified ReservedConcurrentExecutions
    for function decreases account's UnreservedConcurrentExecution below
    its minimum value of 100` if the account is near its quota. Almost
    certainly fine in these accounts today, but worth a preflight in
    near-quota envs:

    ```
    aws lambda get-account-settings --query 'AccountLimit.UnreservedConcurrentExecutions' \
      --profile <env-profile>
    ```

    Should report ≥ 101 before flipping `qurl_scanner_lambda_enabled = true`.
    If lower, request a concurrency-quota increase via AWS support
    BEFORE the second apply.
  - **Cross-account image pull (HARD PROD PRECONDITION — cr round 3 #3
    on PR #2326)**: Lambda container-image pull requires the image in
    the SAME ACCOUNT + REGION as the function. ECS pulls cross-account
    freely; Lambda does NOT. In prod (`is_primary_account = false`),
    the `qurl_scanner_lambda_repo_url` output points at the secondary-
    account ECR by design — so prod relies on ECR replication
    (`aws_ecr_replication_configuration.cross_account` in
    `modules/ecr/main.tf`, filter `layerv/` prefix) having actually
    propagated the image from sandbox to prod BEFORE the flag-ON apply.
    Without that, the apply fails at create time with
    `InvalidParameterValueException: Lambda does not have permission
    to access the ECR image`. Concrete check before flipping
    `qurl_scanner_lambda_enabled = true` in prod tfvars:

    ```
    aws ecr describe-images --repository-name layerv/qurl-scanner-lambda \
      --image-ids imageTag=<SHA-from-sandbox-SSM-param> \
      --profile <prod-profile> --region <prod-region>
    ```

    Should return the same digest as sandbox. If it returns
    `ImageNotFoundException`, replication hasn't caught up — wait
    ~5 minutes (typical replication lag), re-check, then proceed. If
    it still doesn't show up, check
    `docs/runbooks/ecr-replication-failure.md` for the standard
    replication-debugging path.
- Rollout tasks:
  - Sandbox first apply with `qurl_scanner_lambda_enabled = false` (default).
    Creates `layerv/qurl-scanner-lambda` ECR repo +
    `/layerv-nhp-sandbox/qurl-scanner-lambda-image-tag` SSM param. No Lambda,
    no cron, no alarm.
  - Sandbox second apply with `qurl_scanner_lambda_enabled = true` in
    `terraform/environments/sandbox/terraform.tfvars` AFTER qurl-service CI
    has published at least one image. Creates Lambda + EventBridge cron +
    scan-gap alarm. The `data.aws_ssm_parameter.scanner_lambda_image_tag_current`
    reads the CI-written SHA at plan time; each subsequent apply picks up
    fresh SHAs.
  - Manual entrypoint smoke (pre-merge task B from PR #852 cr round 3):
    from administrator console, run `aws lambda invoke
    --function-name layerv-nhp-sandbox-cell0-qurl-scanner /dev/null` against
    the deployed Lambda. Confirm:
    1. `provided.al2023` entrypoint executes `/var/runtime/bootstrap`.
    2. `AWS_LAMBDA_RUNTIME_API` runtime detection dispatches to
       `lambda.Start(handler)` rather than CLI flag parsing.
    3. `scanner starting` log fires in CloudWatch.
    4. `scanner tick complete` log fires for an empty bucket (no DDB
       throttle errors, no panic).
  - **Data-path smoke (PR #2326 cr round 4 #2 — REQUIRED BEFORE PROD
    FLAG FLIP)**: the entrypoint smoke above exercises NONE of the IAM
    write path, GSI Query grants, or `kms:Decrypt` (empty bucket →
    zero items → zero decryption). To close that gap before flipping
    the flag in prod tfvars, in sandbox:
    1. Use the qurl-service API to mint a qURL with a short expiry
       (e.g. `expires_in = 60s`) against a transit-style resource so
       the row carries the bucket-shard composite key.
    2. Wait the minute + a tick.
    3. Trigger an operator-replay invoke against the bucket that just
       expired:
       `aws lambda invoke --function-name layerv-nhp-sandbox-cell0-qurl-scanner \
         --payload '{"bucket": <bucket-int>}' --cli-binary-format raw-in-base64-out /dev/null`
    4. Confirm CloudWatch logs show the GSI Query returned non-zero
       items, the UpdateItem write succeeded (no KMSAccessDeniedException,
       no IAM denial), and `scanner_errors_burning` alarm stayed in OK.
    Recovery if it fails: read the error message; common cases are
    `KMSAccessDeniedException` (KMS grant missing → check
    `aws_iam_role_policy.scanner_lambda_dynamodb`'s `KMSDecryptDynamoDB`
    statement), `AccessDeniedException` on a GSI Query (index ARN not
    listed → check the `time-bucket-index` / `resource-token-index`
    entries), `TooManyRequestsException` (a cron tick is currently
    running and consuming the single concurrency slot — retry the
    invoke after ~50s, or temporarily disable the EventBridge rule via
    `aws events disable-rule --name <scanner-tick-rule>` for the
    duration of the smoke and re-enable afterward), or a panic
    (binary-side bug → roll back the SSM image-tag to the prior SHA +
    re-apply).
  - Prod rollout: repeats the two-apply sequence in
    `terraform/environments/prod/`. NOT covered by this PR's merge — gated by
    the hard preconditions on task #85 in the qurl-service work tracker (SQS
    queue infra, qurl-service consumer dedupe, `--allow-prod-emit` opt-in,
    additional CloudWatch alarms on `TombstoneErrors` /
    `CandidatesUnprocessed` / etc.).
- Post-rollout tasks:
  - Confirm scan-gap CloudWatch alarm
    (`layerv-nhp-<env>-cell0-qurl-scanner-invocation-gap`) is in OK state
    after first apply with flag ON — alarm fires on
    `Sum(Invocations) ≤ 3 over 5 min × 2 periods` (i.e. ≥ 4 missed ticks
    across a 10-min window), so OK means at least 4 invocations landed
    in each of the last two 5-min windows. The `≤ 3` threshold (rather
    than `≤ 4`) absorbs legitimate `5,4,5,4` jitter from `rate(1 minute)`
    drift against CloudWatch's fixed 5-min wall-clock windows.
  - Confirm log group `/aws/lambda/layerv-nhp-<env>-cell0-qurl-scanner` is
    KMS-encrypted and has 30-day retention (not Lambda's default Never-expire).
  - Confirm Lambda is operating in log-only emit mode (no `EMIT_MODE` env var
    set, no `--allow-prod-emit`). Operator emit-mode flip is a SEPARATE
    Terraform apply with explicit tfvars edits and is NOT part of this PR's
    rollout.
  - On next Terraform apply that includes a new qurl-service main push,
    confirm the Lambda's `image_uri` updates to the new SHA (via the SSM
    data-source read) without manual intervention.
- Rollback tasks:
  - Flip `qurl_scanner_lambda_enabled = false` in the env's tfvars and
    re-apply. Destroys Lambda + EventBridge cron + scan-gap alarm. Leaves
    ECR repo + SSM image-tag param intact (so qurl-service CI keeps
    publishing; nothing consumes the images during the rollback window).
  - Per-event kill switch: when `EMIT_MODE=sqs` is later set, an operator
    can unset it (or set it to `log-only`) and re-apply to silence emissions
    without destroying the Lambda. Sub-second kill via the SQS-grant-conditional
    posture if needed.
  - Full unwind: if the ECR repo must go too, remove
    `qurl-scanner-lambda` from `local.ecr_repos` in
    `terraform/modules/ecr/main.tf` AND delete the SSM param via console
    (Terraform will plan-destroy after the next apply but the ECR repo has
    `prevent_destroy = true` — operator must `terraform state rm` + manual
    `aws ecr delete-repository --force`).
- Follow-ups / deferred tasks:
  - [layervai/qurl-service#853](https://github.com/layervai/qurl-service/issues/853)
    — memoize AWS clients at cold start to reduce per-tick latency.
  - [layervai/qurl-service#854](https://github.com/layervai/qurl-service/issues/854)
    — retire ECR-probe scaffolding in `qurl-service` `build-and-deploy.yml`
    once this PR is applied in sandbox AND prod for at least one cycle.
  - **SQS+KMS grant on activation PR (cr round 12 on PR #2326)**: when
    the SQS queue activation PR wires `resource_lifecycle_queue_arn` to
    the queue's ARN, it MUST also thread the queue's KMS key ARN through
    the module and add `kms:GenerateDataKey` + `kms:Decrypt` to
    `aws_iam_role_policy.scanner_lambda_sqs` against that key. Without
    it, `SendMessage` to the SSE-KMS-encrypted queue fails with
    `KMSAccessDeniedException` at runtime. Mirror the
    `task_usage_events` policy's `Sid = "QueueAccess"` +
    `Sid = "KMSEncryptSQS"` shape in `modules/qurl-service/main.tf`. An
    inline TODO is on the `aws_iam_role_policy.scanner_lambda_sqs`
    resource pointing at the precedent.
  - Hard precondition (1) on qurl-service task #85: ship the SQS
    `resource-lifecycle` queue (separate PR) before any operator flips
    `--emit-mode=sqs` env vars. When that lands, wire
    `resource_lifecycle_queue_arn` in this module to activate the
    `sqs:SendMessage` IAM grant + alarm SNS topic ARN.
  - **SNS-wiring binary-error-handling verify (cr round 13 #2)**:
    BEFORE wiring `scanner_lambda_alarm_sns_topic_arn` to a paging
    topic, audit the qurl-scanner binary's error-handling path. The
    `scanner_errors_burning` alarm pages on `Sum(Errors) >= 1` over
    a single 5-min window — so any handler-level error bubbling out
    of `lambdaHandler` will fire the alarm. If the binary surfaces
    transient DynamoDB throttles as handler errors (rather than
    retrying them internally), expect occasional pages on healthy
    operation. Either confirm the binary retries transient infra
    errors before returning, or accept the noise consciously
    (`ok_actions` is wired so it self-clears). Out of scope here
    because the binary lives in qurl-service; track as a verify
    step in the SNS-wiring follow-up PR.
- Status: Open
- Status note: Awaiting sandbox first apply (flag OFF) post-merge, then
  qurl-service CI image publish, then sandbox second apply (flag ON), then
  manual smoke (pre-merge task B from PR #852).

### 2026-05-31 - PR #2268 - Internal Knock HMAC Prod Tasks

- Ledger PR: [#2281](https://github.com/layervai/nhp/pull/2281)
- Source PR / issue: [PR #2268](https://github.com/layervai/nhp/pull/2268) /
  [issue #1311](https://github.com/layervai/nhp/issues/1311). Issue #1311 was
  closed by merge; this ledger entry remains open until prod rollout
  verification is recorded.
- Merge commit: `28d268434412cbb74fd56e9f30188664bda1172a`
- Component: `terraform`, `server`, `internalauth`
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Confirm prod qurl-service ECS tasks and prod NHP server instances are
    configured to read the same `NHP_INTERNAL_AUTH_SECRET` parameter.
  - Run a prod qurl-service headless resolve smoke and capture
    `InternalAuthSuccess` plus `InternalAuthFailPermit=0` before the strict
    flip.
  - Confirm follow-up issues
    [#2269](https://github.com/layervai/nhp/issues/2269),
    [#2271](https://github.com/layervai/nhp/issues/2271), and
    [#2274](https://github.com/layervai/nhp/issues/2274) are non-blocking for
    this prod rollout.
- Rollout tasks:
  - Run the prod promote path that includes the NHP server launch-template/user
    data change.
  - If Terraform apply updates only the launch template, explicitly refresh the
    `layerv-nhp-prod-server` ASG so instances pick up
    `NHP_INTERNAL_AUTH_REQUIRE=true`.
- Post-rollout tasks:
  - Confirm refreshed NHP server instances are running the expected environment.
  - Re-run the prod qurl-service headless resolve smoke.
  - Confirm `InternalAuthFailStrict=0`, `InternalAuthFailPermit=0`, and
    `InternalAuthSuccess>0` after the refresh.
- Rollback tasks:
  - Set prod `NHP_INTERNAL_AUTH_REQUIRE=false`, apply, and refresh the prod
    server ASG if strict-mode failures appear.
- Follow-ups / deferred tasks:
  - [#2269](https://github.com/layervai/nhp/issues/2269) - plan-time guard for
    strict internal-auth secret readiness.
  - [#2271](https://github.com/layervai/nhp/issues/2271) - sandbox strict-mode
    evaluation.
  - [#2274](https://github.com/layervai/nhp/issues/2274) - per-endpoint
    internal-auth metric dimensions.
- Status: Open
- Status note: waiting for prod rollout tasks and verification for the
  2026-05-31 rollout.
- Completed date:
- Evidence:

### 2026-06-02 - PR #2306 - Resolve WAF IP-reputation count + logging

- Ledger PR: [#2306](https://github.com/layervai/nhp/pull/2306)
- Source PR / issue: [PR #2306](https://github.com/layervai/nhp/pull/2306)
- Component: `terraform`
- Task owner: prod rollout coordinator
- Rollout tasks:
  - Promote with `run_terraform=true` so the resolve WebACL change applies in
    prod. Validate in sandbox first (`build-and-push` applies the same shared
    terraform).
  - No deploy ordering or ASG refresh required for this change itself (WAF /
    CloudFront config only). BUT `run_terraform=true` applies the **entire**
    pending prod terraform diff (last-apply `c9db0f19` -> HEAD), not just the
    WAF rule — at the time of writing that includes auth0 + ACME/custom-domain
    cert-lambda drift. Prod is currently split-stated (`state=failed`, server/AC
    binaries behind applied terraform); coordinate this apply with the broader
    split-state recovery rather than treating it as an isolated WAF apply.
  - Watch the first apply for a WAF→CloudWatch-Logs resource-policy size error.
    Delivery to the new `aws-waf-logs-layerv-nhp-{prod,sandbox}-resolve` group is
    authorized by a single AWS-managed CloudWatch Logs resource policy with a
    5120-char cap, shared across all `aws-waf-logs-*` destinations in the
    account/region. Almost certainly fine (few WAF→CW configs here), but if the
    account is near the cap the logging-config apply fails with a policy-size
    error — if so, consolidate/prune `aws-waf-logs-*` destinations or switch this
    group's delivery to S3/Firehose.
- Post-rollout tasks:
  - Deterministic config proof (does not depend on which CI IP the runner
    draws): `aws wafv2 get-web-acl` on the resolve WebACL and confirm the
    `AWSManagedRulesAmazonIpReputationList` rule's `OverrideAction` is now
    `Count`; `get-sampled-requests` on rule metric
    `<env>-resolve-ip-reputation` should show matches as `action=COUNT` with the
    request allowed overall.
  - Supporting behavioral evidence: re-run the prod `QURL Smoke Tests (prod)`
    job and confirm the resolve->proxy tests pass (`TestQURLEndToEndFlow`,
    `TestMultiInstance_*`, `TestCustomDomain_EndToEnd_ResolveAndProxy`). Treat a
    single green run as supporting only — the block is IP-dependent and GitHub
    runner IPs are dynamic, so green proves the path works for that run, not that
    the rule changed; the config proof above is authoritative.
  - Confirm WAF logging is delivering to CloudWatch log group
    `aws-waf-logs-layerv-nhp-prod-resolve` (us-east-1) and that logged requests
    have the `token` query string redacted.
  - Review the IP-reputation count labels in the logs to decide whether the rule
    should return to Block (flip `resolve_waf_ip_reputation_block = true`) or be
    narrowed. This disposition decision is tracked with an explicit owner +
    deadline in [#2308](https://github.com/layervai/nhp/issues/2308) (assign the
    WAF-posture owner; decide before the next prod release cut) so count-mode
    does not silently become permanent-by-default. A surgical CI-runner-IP
    allowlist was considered and rejected as the fix — GitHub-hosted runner
    egress IPs are dynamic across large Azure ranges, so an allowlist is
    impractical and high-maintenance.
- Rollback tasks:
  - Restore IP-reputation Block by setting
    `resolve_waf_ip_reputation_block = true` (or reverting this PR) and applying;
    no data migration or refresh involved.
- Follow-ups / deferred tasks:
  - [#2308](https://github.com/layervai/nhp/issues/2308) - decide the
    IP-reputation rule's permanent fate (count vs. block) from log review.
  - [#2307](https://github.com/layervai/nhp/issues/2307) - add Terraform
    security scanning (tfsec/checkov) to CI; includes an inline-justified
    suppression for this log group's deliberate us-east-1 KMS omission.
  - Optional us-east-1 customer-managed KMS key for the resolve WAF log group
    (currently CloudWatch default encryption; token is redacted).
- Status: Open
- Status note: Waiting for rollout (sandbox validation, then prod promote with
  `run_terraform=true`).

### 2026-06-04 - PR #2318 - qURL Internal Knock Placement Hotfix

- Ledger PR: [#2318](https://github.com/layervai/nhp/pull/2318)
- Source PR / issue: [PR #2318](https://github.com/layervai/nhp/pull/2318) /
  [layervai/qurl-service#821](https://github.com/layervai/qurl-service/pull/821) /
  [layervai/qurl-service#827](https://github.com/layervai/qurl-service/pull/827) /
  [#2322](https://github.com/layervai/nhp/issues/2322)
- Component: `server`, internal knock API
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Confirm qurl-service merge commit
    `b81abc58133d871135aa4f0e87c8909f7e125c0d` failed sandbox smoke because
    `/v1/resolve` returned `502 knock_failed` after route-less internal knocks
    reached the deployed NHP server.
  - Confirm the qurl-service build being smoked preserves #821's headless
    resolve contract: `PublicResolveHandler` derives `srcIP` from `c.ClientIP()`
    and `KnockClient.TriggerKnock` sends it as `request.srcIp` on every
    `/v1/resolve` internal knock. With only per-AZ catalog rows, empty `srcIp`
    fails closed as `InternalKnockResourceNotFound`.
  - Confirm qurl-service #827 dynamic `q_` resource rows are visible through
    NHP's direct exact-resource lookup without waiting for the ASP-level
    catalog cache to expire, and that an elapsed app-level `ttl` is rejected
    even before DynamoDB's asynchronous TTL sweeper removes the row.
  - Confirm downstream `KnockSrcIP` validation compares the same canonical IP
    shape qurl-service sends from `c.ClientIP()`; NHP trims whitespace after
    internal-auth verification and before writing the ACK-token metadata.
  - Confirm sandbox `nhp_resources` has per-AZ `qurl-tunnel-server-{suffix}`
    rows and no placement-neutral direct row, matching current Terraform.
  - Confirm Terraform passes the reserved dynamic qURL customer-id prefix
    (`local.nhp_qurl_dynamic_customer_id_prefix`) to the qurl-service module's
    `nhp_resources_customer_id_prefix`, so IAM `dynamodb:LeadingKeys` admits
    only `<prefix>-??` dynamic shard keys and excludes Terraform-owned static
    `qurl-tunnel-server*` and `agent` rows in the system partition.
  - Confirm qurl-service writes dynamic `q_` rows and NHP server reads them in
    the same DynamoDB regional table replica; the direct lookup uses
    `ConsistentRead`, which does not provide cross-region read-after-write if
    `nhp_resources` later becomes a global table.
- Rollout tasks:
  - Deploy this NHP server hotfix to sandbox before re-running the qurl-service
    #821 sandbox smoke and before validating #827 dynamic-resource publishing.
  - Promote to prod before any qurl-service prod rollout that depends on #821's
    route-less internal knock payload or #827's dynamic `q_` resource rows.
- Post-rollout tasks:
  - Re-run the qurl-service #821 merge workflow sandbox smoke and confirm
    headless `/v1/resolve` succeeds with no `knock_failed` failures.
  - Run qurl-service #827 sandbox smoke and confirm freshly minted dynamic
    `q_` resources resolve through NHP without catalog-cache delay.
  - Confirm NHP internal knock metrics do not show sustained
    `InternalKnockResourceNotFound` or strict-auth failures after rollout.
  - Confirm qurl-service emits no sustained `NHP resource catalog publish
    failed` errors and no DynamoDB `PutItem` failures for the `nhp_resources`
    table in the qurl-operations DynamoDB failed-operations panel.
  - Confirm `ResourceLookupExpiredDirectRow` stays near zero outside expected
    revoke/expiry races. A single lingering expired-but-unswept hot row can
    emit roughly once per second per server process until qurl-service cleanup
    or DynamoDB TTL removes it; sustained multi-row rates mean qurl-service is
    leaving expired dynamic rows behind long enough for users to hit them.
  - Confirm `ResourceLookupMissingDirectTTL` stays zero; any nonzero value means
    qurl-service is publishing malformed dynamic rows and dynamic knocks are
    failing closed.
  - Confirm direct `q_` lookups read the resource_id-derived dynamic shard and
    do not require or admit a same-ID row from the static system partition or a
    wrong dynamic shard.
  - Confirm `ac_id-index` consumers tolerate dynamic `q_` rows and watch the
    index's write/read capacity during burn-in; dynamic catalog rows are
    storage-backed resources and intentionally share the AC lookup index.
  - Watch qURL tunnel-server per-AZ selection for unexpected concentration if
    the qurl-service egress IP set is smaller than the tunnel-server AZ set.
- Rollback tasks:
  - Roll back this NHP server image if qurl-service headless resolves still fail
    after the hotfix deploy; reassess whether qurl-service #821 or #827 needs
    a revert or the `nhp_resources` seed data needs repair.
  - If direct `q_` lookups return `ResourceLookupDirectAspMismatch` or
    `ResourceLookupMissingDirectTTL`, roll back the qurl-service writer and
    inspect the affected dynamic shard key before re-enabling catalog writes.
- Follow-ups / deferred tasks:
  - [#2319](https://github.com/layervai/nhp/issues/2319) tracks whether dynamic
    qURL `q_` exact resource lookups need a short-TTL cache after real QPS is
    measured.
  - [#2322](https://github.com/layervai/nhp/issues/2322) is resolved by this
    PR's resource_id-derived dynamic shard keys once PR #2318 and qurl-service
    #827 merge.
- Status: Open
- Status note: Waiting for sandbox rollout and qurl-service smoke evidence.

### 2026-06-03 - PR #2310 - Internal Knock Storage-Resolved Resources

- Ledger PR: [#2310](https://github.com/layervai/nhp/pull/2310)
- Source PR / issue: [PR #2310](https://github.com/layervai/nhp/pull/2310) /
  [issue #1209](https://github.com/layervai/nhp/issues/1209)
- Component: `server`, internal knock API
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Confirm qurl-service companion PR
    [layervai/qurl-service#821](https://github.com/layervai/qurl-service/pull/821)
    remains draft or otherwise blocked from prod rollout until this NHP server
    change is deployed.
  - Confirm prod NHP server instances are already enforcing strict
    `NHP_INTERNAL_AUTH_REQUIRE=true` before relying on storage-resolved
    internal knocks.
  - Confirm prod qurl-service still sends request-level `resId` before
    NHP deploy. Evidence from qurl-service `origin/main` / PR #821:
    `HTTPKnockRequest.ResourceID` is populated from `NHPResourceID`; the
    `resource` body is not the lookup identity source.
- Rollout tasks:
  - Deploy this NHP server change before qurl-service PR
    [#821](https://github.com/layervai/qurl-service/pull/821).
  - After the NHP deploy is healthy, mark the qurl-service companion ready for
    review/merge and include it in a later qurl-service rollout.
- Post-rollout tasks:
  - Before qurl-service PR #821 deploys, verify prod NHP health reports the
    expected image tag for this PR's merge commit.
  - After qurl-service PR #821 deploys, run a prod headless qURL resolve smoke
    and confirm NHP internal knock success with no strict-auth failures.
    Also confirm the returned/effective open window is the storage catalog
    cap (120s in prod), not qurl-service's default 300s. Pre-merge prod
    evidence: `layerv-nhp-prod-cell0-resources` has only
    `qurl-tunnel-server-{a,b,c}` rows for the system customer and all three
    rows have `open_time=120`; qurl-service task definition
    `layerv-nhp-prod-cell0-qurl-api:46` has `QURL_DEFAULT_OPEN_TIME=300`.
- Rollback tasks:
  - If storage-resolved internal knocks fail before qurl-service PR #821
    deploys, roll back this NHP server image.
  - If failures appear only after qurl-service PR #821 deploys, roll back
    qurl-service first to restore the previous body-supplied `resInfo` payload,
    then evaluate whether this NHP server image also needs rollback.
- Follow-ups / deferred tasks:
  - [#1210](https://github.com/layervai/nhp/issues/1210) remains open for any
    independent-trust-root SrcIp attestation design; do not close it with a
    duplicate same-key request signature.
- Status: Open
- Status note: waiting for NHP rollout first, then qurl-service companion
  rollout and smoke evidence.
- Completed date:
- Evidence:

### 2026-06-05 - PR #2366 - Metric publisher failure alarms (#1707)

- Ledger PR: [PR #2366](https://github.com/layervai/nhp/pull/2366)
- Source PR / issue: [PR #2366](https://github.com/layervai/nhp/pull/2366) / [#1707](https://github.com/layervai/nhp/issues/1707)
- Component: ac, server, terraform
- Task owner: PR author
- Post-rollout tasks:
  - After the terraform apply that creates `${name_prefix}-ac-publisher-failures`
    and `${name_prefix}-${cell_id}-server-publisher-failures`, confirm both
    alarms settle in `OK` and NOT `INSUFFICIENT_DATA`. `INSUFFICIENT_DATA`
    means the alarm dim set does not match the live publisher's emitted dims
    (the silent-selector failure this very alarm class exists to prevent) —
    audit `dimensions {}` against `acBaseDims` / `buildServerMetricDimensions`
    before considering the rollout done.
  - Optional validation: temporarily revoke `cloudwatch:PutMetricData` on a
    sandbox AC/server (or rely on a natural throttle) and confirm
    `PublisherFailures` increments and the alarm transitions to `ALARM`.
- Rollback tasks: alarms are purely additive (no behavior change); `terraform
  apply` of the revert removes them. The Go counter is inert when no batch
  fails.
- Follow-ups / deferred tasks: none. Total-publisher-death coverage stays on
  the pre-existing absence alarms (`ac-registration-stale`,
  `server-cloudmap-register-refresh-heartbeat`); not in scope here.
- Status: Open
- Status note:
- Completed date:
- Evidence:

### 2026-06-05 - PR #2338 - CloudTrail Tamper-Detection Alerting

- Ledger PR: [#2338](https://github.com/layervai/nhp/pull/2338)
- Source PR / issue: [PR #2338](https://github.com/layervai/nhp/pull/2338) /
  [issue #1143](https://github.com/layervai/nhp/issues/1143)
- Component: `terraform`, security module (CloudTrail tamper alert + delete guard)
- Task owner: prod rollout coordinator
- Post-rollout tasks:
  - After the prod apply lands the EventBridge rule, run the Slack-page smoke
    test in `docs/SECURITY.md` → "CloudTrail Tamper Detection" → Testing:
    trigger a benign `update-trail` on `layerv-nhp-prod-trail` and confirm the
    `:rotating_light: CloudTrail tampering` page reaches the on-call Slack
    channel. This is the only end-to-end proof that the EventBridge input
    transformer renders and the alert delivers — required, not optional.
  - On that first page, confirm the `Error code` field renders blank (not the
    literal `null`) for the successful call.
  - Also exercise a `PutEventSelectors` event (re-apply the trail's current
    selectors — a config no-op; command in `docs/SECURITY.md` Testing) and
    confirm the page renders the trail name, not `nullname`/`namenull`. This is
    the only event sourced from `requestParameters.trailName` and is what proves
    the `<trailName><trailNameSel>` coalescing works in the live transformer.
- Rollback tasks:
  - The rule and target are additive and side-effect-free; to disable, set
    `enable_cloudtrail_tamper_alerts = false` (or revert the apply). No data or
    traffic impact.
- Follow-ups / deferred tasks:
  - Interim coverage gap: the rule runs in us-east-2 and covers the canonical
    `layerv-nhp-prod-trail` (us-east-2, hardened). The redundant
    `layerv-prod-trail` (us-east-1, unhardened) is not covered until #1143
    Bucket B deletes it — tracked on
    [#1143](https://github.com/layervai/nhp/issues/1143). Tampering with that
    trail alone blinds nothing (canonical + org trails still capture the same
    management events).
- Status: Open
- Status note: Additive, default-on resources apply through the normal promote
  pipeline; the post-rollout Slack-page smoke is the only required task.
- Completed date:
- Evidence:

### 2026-06-06 - PR #2329 - Custom-domain renewal alarm aggregation

- Ledger PR: [#2329](https://github.com/layervai/nhp/pull/2329)
- Source PR / issue: [PR #2329](https://github.com/layervai/nhp/pull/2329)
- Component: `terraform/modules/custom-domain-cert`,
  `tests/smoke/19_custom_domain_dns_ownership_test.go`,
  `docs/runbooks/custom-domain-cert-dns-ownership.md`
- Task owner: prod rollout coordinator
- Rollout tasks:
  - Promote the custom-domain cert Lambda, renewal scan alarms, heartbeat alarm,
    and smoke IAM/test wiring through the normal prod promote flow.
- Post-rollout tasks:
  - Watch `layerv-nhp-prod-cert-renewal-scan-missing`; acknowledge a one-time
    first-deploy or alarm-replacement page if it fires before the first
    heartbeat datapoint, wait one scan interval, and escalate if it does not
    clear within an hour or re-enters `ALARM` after reaching OK.
  - Confirm `RenewalScanRuns` publishes for `Environment=prod` and the prod
    `CellID`, and confirm the three renewal count alarms move to OK or to an
    expected ALARM backed by explicit scan-count datapoints.
  - If the heartbeat alarm fires alongside Lambda Errors, treat it as a
    telemetry publish outage first and inspect the cert Lambda logs before
    starting customer DNS cleanup.
- Rollback tasks:
  - Roll back the custom-domain cert Lambda/alarm Terraform change to the prior
    release if renewal scan telemetry cannot be stabilized. Expect the old
    scheduled-renewal failure signals to return until the rollback is recovered.
- Follow-ups / deferred tasks:
  - Scale the scheduled renewal scanner for thousands of certs:
    [#2379](https://github.com/layervai/nhp/issues/2379).
- Status: Open
- Status note: waiting for prod rollout and post-deploy heartbeat/alarm
  verification.
- Completed date:
- Evidence:

### 2026-06-05 - PR #2344 - CloudTrail CIS metric-filter alarms (#1140)

- Ledger PR: [#2344](https://github.com/layervai/nhp/pull/2344)
- Source PR / issue: [PR #2344](https://github.com/layervai/nhp/pull/2344) /
  [issue #1140](https://github.com/layervai/nhp/issues/1140)
- Component: `terraform/modules/security`
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Confirm the prod monitoring `alerts` SNS topic
    (`module.monitoring.sns_topic_arn`) has at least one **confirmed**
    subscriber (email subscription confirmed and/or Chatbot config
    active). A CIS CloudWatch.x control only reports PASSED when its
    alarm notifies a topic with a subscriber; an unconfirmed email-only
    topic leaves the controls FAILED even though the alarms exist.
  - **Sandbox cannot pre-validate this change.** Sandbox sets
    `enable_cloudtrail = false`, so the `for_each` is empty there and
    the standard "sandbox first" promote step is a no-op for these
    resources — first real creation is the prod apply. Review the plan
    diff carefully (12 metric filters + 12 alarms, all additive) before
    the prod apply rather than relying on a sandbox dry run.
  - **Decide the #2353 routing sequencing (deliberate, not default).**
    The 8 `ticket` change-detection alarms (IAM/SG/route/gateway/NACL/
    VPC/config/S3-policy) notify on ALARM on **every** `terraform apply`
    from the CI role, on the same `alerts` topic that carries the 3
    `page` alarms. `ok_actions` is already `page`-only (halves the
    chatter), but the ALARM-side noise is predictable from day one.
    **Recommended:** land the
    [#2353](https://github.com/layervai/nhp/issues/2353) routing /
    subscription-filter split first or in the same window so apply noise
    never reaches the `page` audience — repeated apply-driven ticket
    noise on the page channel is exactly the desensitization that defeats
    a paging control. Only fall back to consciously accepting the
    day-one shared-topic noise (until #2353 lands) if #2353 can't make
    the same window. Record the choice here.
- Rollout tasks:
  - Pure observability change, applied by the normal prod promote
    terraform apply. No deploy ordering, no ASG refresh, no data
    migration. Resources are additive (no replacements/deletions).
  - The apply itself emits IAM/security-group/route-table change events
    from the CI role, which will trip the corresponding `ticket`
    alarms during/after the apply — expected, not a failure.
- Post-rollout tasks:
  - **Hard gate (the only real test of the frozen patterns):** in
    Security Hub (prod), filter the CIS AWS Foundations v1.4.0 standard
    for the `CloudWatch.*` controls and confirm
    CloudWatch.1/4/5/6/7/8/9/10/11/12/13/14 report PASSED. Allow up to
    ~18h for the first periodic evaluation. A control still FAILED here
    despite the alarm existing means a filter-pattern divergence (typo/
    whitespace vs the canonical CIS term set) or an unconfirmed SNS
    subscriber — treat this as a release-blocking check, not a
    formality, since sandbox cannot pre-validate it. The
    `cis-metric-filter-patterns` PR lint now catches the pattern-typo
    class before merge, but the confirmed-subscriber + live-eval proof
    still only exists post-apply.
  - Confirm delivery end-to-end: verify the apply-driven
    `*-cis-iam_policy_changes` / `*-cis-security_group_changes` alarms
    transitioned to ALARM and that a notification landed in the alert
    email and Slack channel. These are `ticket`-severity, so they do NOT
    emit an OK notification (only `page` alarms wire `ok_actions`); they
    self-clear in the console after the 5-min window with no events.
  - Confirm the `page`-severity alarms (`*-cis-root_account_usage`,
    `*-cis-cloudtrail_config_changes`, `*-cis-cmk_disable_or_delete`)
    are in OK/INSUFFICIENT_DATA and did not fire spuriously on the apply.
    Note: a real trail-tamper will page **twice** (this CloudWatch.5
    alarm + the `enable_cloudtrail_tamper_alerts` EventBridge rule) — by
    design, not a misconfiguration.
- Rollback tasks:
  - Revert this PR (or delete
    `terraform/modules/security/cloudtrail_metric_filters.tf`) and apply.
    Removes the filters + alarms only; CloudTrail logging, the log
    group, and S3 archival are untouched. Do NOT roll back by setting
    `enable_cloudtrail = false` — that disables the trail itself, a much
    broader change.
- Follow-ups / deferred tasks:
  - #1140 remains open after this PR. Still outstanding: the four
    application-level metrics (`resolve_xff_mismatch_total`,
    `internal_knock_total`, `nhp_replay_detected_total`,
    `token_verify_fail_total`), the CI prod-⊇-sandbox metric-filter
    parity test, and the manual-only CIS controls CloudWatch.2
    (unauthorized API) / CloudWatch.3 (console sign-in without MFA).
  - Sandbox CloudTrail enablement decision: enabling
    `enable_cloudtrail` in sandbox would give genuine prod/sandbox
    parity (and a real testbed for these alarms) at the cost of
    CloudWatch Logs ingestion. Deferred pending that cost/value call.
  - [#2353](https://github.com/layervai/nhp/issues/2353) — severity-based
    SNS routing to split the `ticket` stream off the `page` topic (see
    the sequencing pre-rollout task above).
  - If apply-time noise on the `ticket`-severity alarms is excessive,
    filter by the `Severity` tag in the Chatbot/email subscription —
    do not edit the (Security-Hub-frozen) filter patterns.
- Status: Open
- Status note: Waiting for prod rollout. Not validatable in sandbox
  (`enable_cloudtrail = false`); first creation is the prod apply.

### 2026-06-05 - PR #2345 - GuardDuty security alias + triage-runbook links

- Ledger PR: [#2345](https://github.com/layervai/nhp/pull/2345)
- Source PR / issue: [PR #2345](https://github.com/layervai/nhp/pull/2345) /
  [#2334](https://github.com/layervai/nhp/issues/2334)
- Component: `terraform/modules/security`, `terraform/environments/{prod,sandbox}`
- Task owner: prod rollout coordinator
- Rollout tasks:
  - Adds `security@layerv.ai` to `guardduty_alert_emails`, which creates one new
    `email` subscription on the `layerv-nhp-prod-guardduty-email` SNS topic. SNS
    email subscriptions start as `PendingConfirmation`; the alias receives no
    findings until someone clicks the confirmation link delivered to the
    `security@layerv.ai` inbox. No total-blackout window — the three existing
    individual subscribers and the Slack/Chatbot path keep delivering during the
    pending period. Confirm the subscription after the prod apply:

    ```
    aws sns list-subscriptions-by-topic \
      --topic-arn arn:aws:sns:<region>:<acct>:layerv-nhp-prod-guardduty-email \
      --profile layerv-prod \
      --query "Subscriptions[?Endpoint=='security@layerv.ai'].SubscriptionArn"
    ```

    A `PendingConfirmation` value (not a real ARN) means the link is unclicked.
  - The EventBridge email/Slack input-transformer change and the watchdog
    Lambda's `TRIAGE_RUNBOOK_URL` env var apply with no manual step — they take
    effect on the next finding/weekly run after apply.
- Post-rollout tasks:
  - Confirm the next real or synthetic GuardDuty alert (email + Slack) carries
    the triage-runbook link. A cheap synthetic check: GuardDuty console →
    Settings → generate sample findings, then confirm the alert body links to
    `docs/runbooks/guardduty-finding-triage.md`. Archive the samples afterward
    so the stale-finding watchdog does not re-alert on them.
- Rollback tasks:
  - Revert this PR (remove `security@layerv.ai` from `guardduty_alert_emails`
    and the runbook-link additions) and re-apply. Removing the alias deletes its
    SNS subscription; no data migration. The pending/confirmed subscription is
    harmless if left in place.
- Follow-ups / deferred tasks:
  - Sandbox carries the same new `security@layerv.ai` subscription on
    `layerv-nhp-sandbox-guardduty-email` (applied via build-and-push on merge);
    it also needs one confirmation click from the alias inbox. Not a prod task,
    tracked here so it is not dropped.
  - Issue [#2334](https://github.com/layervai/nhp/issues/2334) remains open for
    its lower-priority items (severity-tiered SNS topics; confirming the
    externally-owned Chatbot routes GuardDuty alerts to a dedicated security
    channel). The pager-escalation item is won't-do — no pager facility exists;
    the stale-finding watchdog is the compensating control.
- Status: Open
- Status note: Waiting for prod apply, then the `security@layerv.ai` SNS
  confirmation click, then the synthetic-finding link check.

### 2026-06-06 - PR #2336 - nhp-server container runs as non-root user

- Ledger PR: [#2336](https://github.com/layervai/nhp/pull/2336)
- Source PR / issue: [PR #2336](https://github.com/layervai/nhp/pull/2336) /
  [issue #1090](https://github.com/layervai/nhp/issues/1090)
- Component: `terraform` (compute / nhp-server), `server` runtime
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - Sandbox functional validation after the compute ASG instance refresh
    (a `terraform plan`/`apply` does not exercise this runtime change):
    - `docker inspect nhp-server` shows the process user as `10001`.
    - Server starts and reads its 0600 config as uid 10001 from the `:ro` etc
      mount (config.toml always; tls/client.key only under the etcd backend) —
      this is the whole reason the chown is load-bearing — and binds 8888/TCP
      + 62206/UDP.
    - `ls -l /opt/layerv/nhp-server/etc/{secrets.env,config.toml}` confirms the
      shipped ownership: secrets.env stays `root:root` (0600), config.toml is
      `10001` — i.e. the recursive chown + root re-assert behaved as intended.
    - Logs write to `/opt/layerv/nhp-server/log`, and if the file-tail
      CloudWatch stream (`server-*.log`) is relied on, confirm it still ships
      (files are now 10001-owned 0600; the agent reads as root).
    - A knock round-trip succeeds end-to-end.
    - The in-container Docker HEALTHCHECK still reports healthy under the
      dropped privileges: `docker inspect --format '{{.State.Health.Status}}'
      nhp-server` == `healthy` (the curl probe runs inside the unprivileged,
      cap-dropped container).
    - If/when deploying with the etcd storage backend (LayerV prod is dynamodb,
      so this is N/A there): additionally confirm the 0600 `tls/client.key` is
      readable as uid 10001 — that file exists only on the etcd path and is the
      reason the etc chown is recursive rather than an explicit file list.
- Rollout tasks:
  - Deploy is a launch-template bump: roll the `nhp-server` ASG via instance
    refresh per environment (sandbox first, then prod). No data migration, no
    cross-repo ordering.
- Post-rollout tasks:
  - Confirm prod NHP server `/health` reports the expected image tag for this
    PR's merge commit and the NLB target group stays healthy through the
    refresh.
- Rollback tasks:
  - Revert this PR and instance-refresh the `nhp-server` ASG to the prior
    launch-template version. The change is self-contained to compute
    `user_data`; no other component depends on it.
  - AMI-collision failure mode: if a future base AMI ever ships an account at
    uid/gid 10001, the fail-loud `FATAL ... exit 1` guard boots the instance
    with no server and crash-loops the ASG against that AMI. The surfaced
    signal is NLB targets going unhealthy → the existing
    `servers_healthy_low`/target-group health alarms page on it; the fix is to
    repin `nhp_server_uid`/`nhp_server_gid` to a free id and re-bake/refresh.
- Follow-ups / deferred tasks:
  - PR 2 (Traefik non-root) and PR 3 (nhp-acd non-root) remain open under
    [#1090](https://github.com/layervai/nhp/issues/1090); each ships its own
    ledger entry.
- Status: Open
- Status note: awaiting sandbox functional validation post-merge before prod
  instance refresh.
- Completed date:
- Evidence:

### 2026-06-05 - PR #2349 - DNS hygiene: CAA + SPF/DMARC across apex domains

- Ledger PR: [#2349](https://github.com/layervai/nhp/pull/2349)
- Source PR / issue: [PR #2349](https://github.com/layervai/nhp/pull/2349) /
  [issue #1149](https://github.com/layervai/nhp/issues/1149)
- Component: `terraform` (Route53 records:
  `terraform/environments/prod/dns_hygiene.tf` for the layerv-mgmt apexes
  layerv.ai / qurl.site / qurl.link, and
  `terraform/environments/sandbox/dns_hygiene.tf` for layerv.xyz; shared CAA
  issuer constants in `terraform/modules/dns-hygiene-constants`)
- Task owner: prod rollout coordinator
- Pre-rollout tasks:
  - **CAA completeness re-check (HARD PRECONDITION).** A CAA that omits any CA
    actively issuing for a domain silently breaks that CA's next renewal. The
    issuer sets in the two `dns_hygiene.tf` files were derived from each
    domain's live crt.sh history at PR time (ACM `amazon.com`/`amazontrust.com`/
    `awstrust.com`/`amazonaws.com`; `letsencrypt.org`; GoDaddy `godaddy.com`/
    `starfieldtech.com` on layerv.ai + layerv.xyz only). Re-run before apply to
    catch any CA added since:
    `for d in layerv.ai layerv.xyz qurl.link qurl.site; do curl -s "https://crt.sh/?q=%25.$d&output=json" | jq -r '.[]|select(.not_after>"<today>")|.issuer_name' | sort -u; done`
    and add any new issuer's CAA identifier in the same change. The issuer
    building blocks are a single source of truth in
    `terraform/modules/dns-hygiene-constants` — add a new CA THERE and it lands
    in both envs at once (no two-file sync). Note `crt.sh?q=%25.<domain>` covers
    subdomain certs too, so a CDN/SaaS fronting e.g. `status.layerv.xyz` via
    Google Trust Services / Cloudflare would show up — at PR time only
    {ACM, Let's Encrypt, GoDaddy} were active across all four trees.
  - ✅ **CONFIRMED — layerv.xyz deliverability gate.** layerv.xyz is a live
    sender; this PR hardens it to SPF `-all` + DMARC `p=reject`. The domain
    owner confirmed spf.improvmx.com + amazonses.com are the ONLY senders, so
    the hardfail SPF drops no legitimate mail. (Still watch the post-rollout
    DMARC aggregate reports for any unexpected `fail` from a forgotten sender.)
  - **SUBDOMAIN senders (HARD PRECONDITION).** The `p=none → p=reject` flip
    applies to EVERY `*.layerv.xyz` subdomain (DMARC subdomains inherit `p`, and
    the record also states `sp=reject` explicitly), not just the apex. The apex
    sign-off above does not cover subdomains. Before the sandbox apply, confirm
    no layerv.xyz subdomain sends mail under its own envelope domain (e.g. a
    `mail.`/`newsletter.`/marketing or status host) — any that does starts
    bouncing at `p=reject`. If one exists, give it an aligned SPF/DKIM + its own
    `_dmarc` record, or scope this DMARC down, before flipping.
  - ✅ **VERIFIED — qurl.link / qurl.site are non-senders.** They get
    `v=spf1 -all` + `p=reject` on the premise they emit no mail. Confirmed at PR
    time: neither has an MX record, an `_amazonses` SES verification TXT, nor any
    DKIM selector (`s1`/`default`/`google._domainkey`), and nothing in the repo
    sends mail from them. qurl.link is the login portal, but its magic-link /
    transactional mail (if any) originates from layerv.ai's SES identity, not
    `@qurl.link`. If qurl.* is ever wired to send mail, this SPF/DMARC must be
    revisited first.
  - **Apex TXT single-set clobber check (HARD PRECONDITION).** The layerv.xyz
    SPF + DMARC records use `allow_overwrite = true` and a Route53 TXT name holds
    ONE record set, so the apply replaces the WHOLE set at that name. At PR time
    the layerv.xyz apex TXT held only the SPF string and `_dmarc.layerv.xyz` held
    only DMARC. Immediately before apply, re-run `dig +short TXT layerv.xyz` and
    `dig +short TXT _dmarc.layerv.xyz`; if any non-SPF / non-DMARC value (e.g. a
    `google-site-verification` / `MS=` token) has since appeared, add it to the
    resource's `records` list in `sandbox/dns_hygiene.tf` or the overwrite will
    delete it. Also `dig +short TXT qurl.link qurl.site` and
    `dig +short TXT _dmarc.qurl.link _dmarc.qurl.site` before the prod apply:
    those records use `allow_overwrite = false`, so an out-of-band TXT/DMARC that
    appeared since PR time won't clobber anything but WILL fail the apply loud
    (`record already exists`) mid-rollout — fold any such value into the matching
    `records` list in `prod/dns_hygiene.tf` first.
  - **Confirm the iodef / rua mailboxes are real and monitored.** CAA `iodef`
    points at `security@layerv.ai` and DMARC `rua` at `dmarc@layerv.ai`. The
    rua mailbox is already live (the existing layerv.ai DMARC uses it); confirm
    `security@layerv.ai` is a monitored inbox before CAs start delivering policy-
    violation reports there.
  - ✅ **VERIFIED (no action needed) — cross-account role permits CAA/TXT.**
    The layerv-mgmt role `nhp-ac-route53-access` (acct 165115313779) has one
    inline policy `route53-acme-access` granting `route53:ChangeResourceRecordSets`
    on the full zone ARNs for layerv.ai (Z0748438C8EK6UAW94ST), qurl.site
    (Z06942509AYXSB91X7CD), and qurl.link (Z0693053DKJ8S3XN9WPG) with **no**
    `Condition` block — i.e. no `route53:ChangeResourceRecordSetsRecordTypes` /
    `...NormalizedRecordNames` restriction, so all record types (incl. CAA/TXT)
    are permitted zone-wide. No permissions boundary, no managed policies, no
    Deny. `aws iam simulate-principal-policy` returns `allowed` for
    ChangeResourceRecordSets on all three zone ARNs. (SCP at the org level not
    separately audited, but the existing CNAME/A records via this same role
    apply cleanly, and IAM here is zone-scoped not type-scoped.)
- Rollout tasks:
  - Sandbox apply (`build-and-push` shared terraform) writes the layerv.xyz
    CAA/SPF/DMARC records (same-account, zone-id-scoped CI grant). SPF + DMARC
    use `allow_overwrite` to upsert the existing unmanaged live records.
  - Prod apply (`promote-to-prod`, `run_terraform=true`) writes the layerv.ai /
    qurl.site / qurl.link CAA, the qurl.* SPF/DMARC, and the three
    `_report._dmarc` cross-domain authorization records, all cross-account via
    `aws.route53_mgmt`.
  - **Apply ordering — run the prod apply before (or together with) the sandbox
    apply.** layerv.xyz's `p=reject; rua=...` lands in sandbox, but its
    `layerv.xyz._report._dmarc.layerv.ai` authorization record lands in prod. If
    sandbox goes first, RFC-7489 receivers drop layerv.xyz aggregate reports
    until the prod apply runs — i.e. you lose DMARC visibility in exactly the
    window right after flipping a live sender to `p=reject`. The qurl.* domains
    have no such gap (their reject + auth records are both in prod).
- Post-rollout tasks:
  - **Verify cert renewals still succeed after CAA.** Watch the centralized
    `acme-cert` renewal Lambda + any ACM `RenewalEligibility` and confirm no
    `CAA` errors. Specifically confirm GoDaddy's `email.layerv.ai` cert (next
    renewal ~2026-08/09) renews — the CAA must keep `godaddy.com`/
    `starfieldtech.com` for layerv.ai.
  - Confirm DNS resolves: `dig CAA <each apex>`, `dig TXT qurl.link`,
    `dig TXT _dmarc.qurl.link`, `dig TXT qurl.link._report._dmarc.layerv.ai`.
  - **DMARC aggregate monitoring must be live on day 1.** Confirm reports begin
    arriving at dmarc@layerv.ai for qurl.link / qurl.site / layerv.xyz (proves
    the `_report._dmarc` auth records work) starting at the apply, not days
    later — with `p=reject` from the first minute, a forgotten qurl.link or
    layerv.xyz-subdomain sender otherwise surfaces as a user-visible bounce
    instead of a report line. Watch for any rise in legitimate-mail rejections.
- Rollback tasks:
  - SPF/DMARC: the layerv.xyz revert is an IN-PLACE update — set SPF back to
    `~all` / DMARC back to `p=none` and re-apply (`prevent_destroy` allows
    updates; `allow_overwrite` restores the value). To remove the qurl.* SPF/DMARC
    records entirely, use the same drop-`prevent_destroy`-then-delete dance as the
    CAA rollback below.
  - CAA: the fast rollback is an IN-PLACE update — add the missing CA to
    `terraform/modules/dns-hygiene-constants` and re-apply; `prevent_destroy`
    does not block updates, so a widened issuer set lands immediately. To remove
    a CAA record entirely, first delete its `lifecycle { prevent_destroy = true }`
    block, apply, then delete the resource block (a bare deletion while
    `prevent_destroy` is set fails the apply rather than rolling back).
- Follow-ups / deferred tasks:
  - issue [#1149](https://github.com/layervai/nhp/issues/1149) stays OPEN after
    this PR. Item 4 (DNSSEC parity on layerv.xyz/qurl.link/qurl.site — needs
    `aws_route53_key_signing_key` + registrar DS upload) and item 5 (Namecheap
    registrar locks — console action) are NOT addressed here.
  - **Raise the TTL after bake-in.** `dns_hygiene_ttl` is 300s for fast rollback
    during initial rollout. Once the records are stable, bump the `ttl` output in
    `terraform/modules/dns-hygiene-constants` (e.g. to 3600) so permanent hygiene
    records don't pay 300s-TTL query volume.
  - **Null-MX (RFC 7505) on the non-sending qurl domains** — tracked under
    [#1149](https://github.com/layervai/nhp/issues/1149) as additional DNS
    hygiene. A `0 .` MX on qurl.link / qurl.site would complete the "neither
    sends nor receives" signal alongside `v=spf1 -all`. NOT for layerv.xyz, which
    receives inbound via improvmx. Out of scope for this PR (MX ≠ CAA/SPF/DMARC).
- Status: Ready
- Status note: Waiting for rollout. Both merge-blocking preconditions are
  cleared — cross-account role CAA/TXT grant VERIFIED, and layerv.xyz senders
  CONFIRMED (improvmx + Amazon SES only). The two remaining pre-rollout items
  (CAA-completeness re-check + apex-TXT clobber re-check) are at-apply
  re-verifications owned by the rollout coordinator.

### 2026-06-05 - PR #2341 - AC alarm dimension-mismatch fix (#968)

- Ledger PR: [#2341](https://github.com/layervai/nhp/pull/2341)
- Source PR / issue: [PR #2341](https://github.com/layervai/nhp/pull/2341) /
  [issue #968](https://github.com/layervai/nhp/issues/968)
- Component: `ac`, `terraform`
- Task owner: prod rollout coordinator
- Summary: three AC CloudWatch alarms (`registration_failure`,
  `server_connection_failure`, `disk_usage_high`) had been silently
  non-functional because their dimension set matched no published metric
  stream. This PR makes the Go failure paths dual-publish a base counter at
  `{Component, Environment, Region}`, points those two alarms at that set, and
  drops `InstanceId` from `disk-monitor.sh` so `disk_usage_high` (and the
  dashboard widget) match the `{Component=AC}` stream. `cert_sync_failures` was
  already functional and is unchanged.
- Pre-rollout tasks: none.
- Rollout tasks:
  - Standard `terraform apply` recreates the three alarms with their corrected
    dimension sets. No ordering constraints.
  - The `disk-monitor` SSM document content changes; the next scheduled
    association run (30-min cadence) is the first to publish
    `DiskUsagePercent` at `{Component=AC}` (no `InstanceId`).
- Post-rollout tasks (alarm/metric verification — this is the whole point of
  the PR, so verify rather than assume):
  - Confirm the Go base-dim publish path exists in prod:
    `AWS_PROFILE=layerv-prod aws cloudwatch list-metrics --namespace LayerV/NHP
    --metric-name RegistrationSuccess` returns a stream whose dimensions are
    exactly `{Component=AC, Environment=prod, Region=<prod-region>}`.
  - Confirm `DiskUsagePercent` has a `{Component=AC}` stream and NO stream
    carrying an `InstanceId` dim after the disk-monitor association re-runs.
  - Confirm the three alarms are in `OK`/`ALARM` (not the historical
    permanent-`OK`-on-no-data) by inducing or waiting for real data; the Tier 1
    smoke fences `TestACAlarms_DimensionsMatchPublisher` and
    `TestACAlarms_PublisherStreamsExistForAlarmDims` assert the contract and run
    in the promote-to-prod smoke leg (report-only/burn-in).
  - Calibration watch — `server_connection_failure` has NO lifecycle/transport
    drop exclusion (unlike `registration_failure`), so connection `timeout`s feed
    the base counter it watches during BOTH a server blue/green flip (timeouts to
    torn-down old-color servers) AND an AC-side instance refresh (in-flight
    `connectToServer` calls failing as the AC tears down). It also increments on
    the ~90s periodic NLB re-registration path, so a single persistently-
    unreachable assigned server produces steady-state fleet-wide increments.
    Confirm neither the first sandbox blue/green flip nor a fleet instance refresh
    pushes >10 `ServerConnectionFailure` across two consecutive 5-min windows
    before treating that alarm as load-bearing; raise the threshold or
    `evaluation_periods` if it cry-wolfs.
  - Threshold scope — the base counters carry no `ACId`, so `Sum` aggregates
    fleet-wide; the absolute thresholds (5 / 10) scale with fleet size, not per
    AC. A fleet-size change (capacity bump) is therefore a re-calibration trigger,
    not just the first flip. Thresholds for all three newly-live alarms are
    unvalidated (they never fired before #968).
  - Day-1 false-page option (coordinator choice) — to avoid a brand-new alarm
    crying wolf on the first refresh before a baseline exists, the coordinator MAY
    stage `server_connection_failure` (and optionally `registration_failure`) with
    its SNS action removed, or a deliberately high initial threshold, until the
    first sandbox flip is observed, then dial in. Note `registration_failure`'s
    day-1 exposure is already low: as of #968 the dominant flip-time transient
    (transaction `timeout`) is dropped off its alarmable counter, so only genuine
    server-side rejections feed it. `server_connection_failure` is the residual
    risk (timeouts there cannot be dropped without losing real-outage detection —
    a sustained reach failure is the fault, distinguished only by the threshold).
  - All-timeout outage detection — because timeout-classified registration
    response errors now drop (breakdown only), a "servers all timing out"
    condition no longer feeds `registration_failure`; it is detected by
    `registration_stale` instead (`RegistrationSuccess < 1` Sum over two 5-min
    periods, `treat_missing_data=breaching` → fires after ~10 min with no
    success). Confirm that 10-min window is acceptable as the sole detector for
    that case.
- Rollback tasks:
  - Revert the PR and re-apply. The alarms revert to their prior dimension
    sets; this is harmless because those alarms were already non-functional
    before this PR (no monitoring is lost relative to the pre-PR baseline).
- Follow-ups / deferred tasks:
  - [issue #946](https://github.com/layervai/nhp/issues/946) remains for the
    separate `ServersHealthy` gauge work — out of scope here.
- Status: Open
- Status note: post-rollout verification owns confirming the alarms are now
  load-bearing.
- Completed date:
- Evidence:

### 2026-06-06 - PR #2343 - Traefik runs as non-root nhp-traefik user

- Ledger PR: [#2343](https://github.com/layervai/nhp/pull/2343)
- Source PR / issue: [PR #2343](https://github.com/layervai/nhp/pull/2343) /
  [issue #1090](https://github.com/layervai/nhp/issues/1090)
- Component: `terraform` (ac / Traefik), AC Traefik runtime
- Task owner: prod rollout coordinator
- Cross-repo contract: `traefik-plugins`. After this change Traefik runs as
  `nhp-traefik`, which only READS the SSM-deployed plugin sources under
  `/home/ubuntu/traefik/plugins-local`. Those files must remain
  world-readable (644 files / 755 dirs — the default). Verify a
  `traefik-plugins` SSM plugin redeploy still loads after rollout; if that
  repo ever tightens plugin file perms, it must chown to `nhp-traefik`.
- Pre-rollout tasks:
  - Sandbox functional validation after the AC ASG instance refresh
    (`terraform plan`/`apply` does not exercise this runtime/capability
    change, and a missed perm is a prod-TLS-outage class failure):
    - `systemctl show traefik -p User -p AmbientCapabilities` reports
      `nhp-traefik` + `CAP_NET_BIND_SERVICE`; unit is `active`.
    - HTTPS serves on `:443` (centralized cert, and ACME `acme.json`
      read/write if per-instance ACME is enabled).
    - Auth middleware plugin loads (read by `nhp-traefik`) — hit a protected
      route and confirm the middleware runs.
    - Trigger the `*-ac-custom-domain-cert-sync` SSM association and confirm
      the re-synced `privkey.pem` (0600) is owned by `nhp-traefik` and the
      custom-domain route (not just the centralized cert) serves correctly.
    - `:8080` ping endpoint healthy (the AC target-group health check).
    - frps-control bind-wait loop still passes under the new user, and Traefik
      creates `/var/log/traefik/{traefik,access}.log` cleanly as `nhp-traefik`
      on a fresh boot (the dir-only chown is sufficient; nothing pre-creates a
      root-owned log file Traefik then can't reopen).
    - Mixed-version SSM case: trigger the cert-sync association against an ASG
      mid-refresh and confirm no `CertSyncFailures` / cert_sync_failures alarm
      noise (the `ubuntu` fallback handles not-yet-refreshed instances). Inverse
      window (self-healing, no action needed): if the 6h association fires on a
      *refreshing* post-#1090 instance after mkdir but before the useradd+sentinel
      block, both user and sentinel are absent → benign `ubuntu` fallback that
      briefly owns custom-domain privkeys as ubuntu; the in-boot cert-sync after
      user creation (and the next 6h run) re-chown to nhp-traefik, so it
      self-corrects within one cycle.
    - Under `ProtectSystem=strict`, confirm outbound TLS still works: ACME /
      Route53 / Secrets Manager reads `/etc/ssl/certs` (readable under strict),
      and the cross-account assume-role (`AWS_ASSUME_ROLE_ARN`) DNS-challenge
      path succeeds on a per-instance-ACME instance.
    - Confirm `plugins-local` is read-only to Traefik (now `ReadOnlyPaths` +
      ubuntu-owned) yet the auth middleware still loads — i.e. the read-only
      carve-out didn't break Yaegi plugin loading.
- Rollout tasks:
  - Launch-template bump: roll the AC ASG via instance refresh per
    environment (sandbox first, then prod).
  - NOTE: the `custom-domain-cert-sync.sh` change takes effect at `terraform
    apply` (it ships in the SSM document; the association re-runs on all AC
    instances on doc change + every 6h), i.e. BEFORE instance refresh. It is
    written to be transition-safe — it falls back to the `ubuntu` owner when
    the `nhp-traefik` user is absent (old launch template) — so apply does not
    regress cert sync on not-yet-refreshed instances. No separate ordering
    step required.
- Post-rollout tasks:
  - Confirm AC target groups stay healthy through the refresh and no TLS /
    middleware errors appear in `traefik.log`.
  - Cert-sync now fails LOUD (exit 1) rather than silently re-owning the 0600
    privkey to `ubuntu` when `nhp-traefik` is absent on a refreshed instance —
    it keys off the `/etc/nhp-traefik-nonroot` sentinel user_data drops after
    the useradd. IMPORTANT: this early exit fires BEFORE the `CertSyncFailures`
    put-metric-data, so the `cert_sync_failures` alarm does NOT catch it — it
    surfaces only as SSM State Manager association non-compliance + the `FATAL`
    log line. So: (a) confirm the cert-sync association's non-compliance is
    actually routed somewhere a human sees it, and (b) post-rollout confirm no
    refreshed instance logs `FATAL: '...' absent but non-root sentinel present`
    (would mean a partial user_data). A dedicated fail-loud metric/alarm is
    tracked in #2387.
  - Plugin redeploy: `plugins-local` is now a `ReadOnlyPaths` bind mount in the
    unit. Validate that a `traefik-plugins` SSM redeploy's UPDATED code is
    actually served by the running Traefik after the deploy's restart (Yaegi
    loads plugins at startup, so a restart is required regardless; this confirms
    the read-only carve-out didn't introduce bind-mount staleness).
  - Sanity: nothing world-readable and sensitive sits directly under
    `/home/ubuntu` (the `chmod o+x` is traverse-only, but traverse still
    exposes known filenames to other local uids).
- Rollback tasks:
  - Revert this PR and instance-refresh the AC ASG to the prior
    launch-template version. Self-contained to AC `user_data` +
    `custom-domain-cert-sync.sh`.
- Follow-ups / deferred tasks:
  - PR 3 (nhp-acd non-root) deferred under
    [#1090](https://github.com/layervai/nhp/issues/1090): nhp-acd must retain
    `CAP_NET_ADMIN`/`CAP_NET_RAW` to drive iptables, so non-root buys only
    filesystem/process isolation at high fail-open/closed risk.
- Status: Open
- Status note: awaiting sandbox functional validation (TLS + middleware +
  custom-domain cert sync) before prod instance refresh.
- Completed date:
- Evidence:

<!-- New active entries go immediately ABOVE this comment, newest last. Keep this comment in place. -->

## Completed Entries

<!-- Move verified entries here, newest last. -->

When moving an entry here, keep the same block shape, set `Status: Verified`,
and fill `Completed date` and `Evidence`.

## Entry Template

Copy this block under Active Entries and fill applicable fields before merge.
Remove placeholder comments for sections that do not apply; do not leave
placeholder comments in merged entries.

```markdown
<!-- Remove placeholder comments before merge; omit sections that do not apply. -->

### YYYY-MM-DD - <PR #NNNN | external owner/repo#NNNN> - Short Title

- Ledger PR:
- Source PR / issue:
- Component:
- Task owner:
- Pre-rollout tasks:
  <!-- Replace with bullets, or delete this section. -->
- Rollout tasks:
  <!-- Replace with bullets, or delete this section. -->
- Post-rollout tasks:
  <!-- Replace with bullets, or delete this section. -->
- Rollback tasks:
- Follow-ups / deferred tasks:
- Status: Open
- Status note:
- Completed date:
- Evidence:
```
