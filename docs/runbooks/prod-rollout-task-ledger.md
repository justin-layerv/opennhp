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
