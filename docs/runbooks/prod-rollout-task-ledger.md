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
