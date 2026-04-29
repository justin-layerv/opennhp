# Incident: 2026-04-24 prod terraform drift

## Summary

Two distinct prod-only terraform failures hit the 2026-04-24 prod release
within ~30 minutes of each other. Each had passed every PR-time CI check
and every sandbox `terraform plan/apply` since being introduced — neither
was caught until the prod-promote workflow tried to evaluate against
prod's real state.

This writeup is the post-incident artifact referenced in #1324; the
preventive fix is the static-analysis lint suite landed alongside this
file under `.github/scripts/check-terraform-iam-coverage.py` and
`.github/scripts/check-terraform-policy-conditions.py`.

## What happened

### Failure 1 — ECR cross-account replication silently broken

Replication from sandbox ECR to prod ECR had been failing with
`DESTINATION_REGISTRY_ACCESS_DENIED` for an unknown window — the
prod ECR had zero `layerv/*` images. The promote-to-prod preflight
caught it at attempt time (no images to deploy).

Root cause: `aws_ecr_registry_policy.replication` carried

```hcl
Condition = {
  StringEquals = {
    "aws:SourceAccount" = var.primary_account_id
  }
}
```

as defense-in-depth on the `Principal` restriction. ECR's
cross-account replication service-linked role does not populate
`aws:SourceAccount` in the destination-side auth context — the
Condition always evaluated to the implicit deny. Every replication
attempt failed.

PR-time `terraform validate` doesn't refresh resource policies. The
sandbox-side policy (`count = !var.is_primary_account ? 1 : 0`) is
not instantiated in the sandbox account at all (sandbox is the
*source* account, not the destination), so sandbox apply never
exercised the policy. The error window was the entire span between
the original policy applying in prod and the 2026-04-24 release
attempt.

Fixed in #1316 (drop the Condition).

### Failure 2 — `aws_cloudformation_stack` data source IAM gap

`data "aws_cloudformation_stack" "website_api"` was added in #1212
along with `deploy_website_api_dns = true` in prod tfvars (sandbox
left default false). The data source is gated on
`local.website_api_dns_enabled`, which is true only when prod tfvars
opt in.

The `nhp-prod-github-actions` role had no
`cloudformation:DescribeStacks` or `cloudformation:GetTemplate`
grants — those weren't added in #1212 either. Sandbox `terraform
plan` never refreshed the data source (`count = 0`), so the missing
grants stayed invisible. The first prod plan after #1212 failed
with `AccessDenied` at the data source's read.

Fixed live during the incident with an inline IAM policy
(`incident-2026-04-24-cfn-describe-website-api`), tracked as drift
in #1323. Reconciled into terraform in #1414. Manual cleanup of the
inline tracked in #1415.

## Timeline (2026-04-24, all times UTC)

| Time | Event |
|---|---|
| ~22:00 | Promote-to-prod workflow starts |
| ~22:05 | Preflight surfaces zero `layerv/*` images in prod ECR |
| ~22:10 | Investigation finds `DESTINATION_REGISTRY_ACCESS_DENIED` on replication status; isolates `aws:SourceAccount` Condition as cause |
| ~22:25 | Live policy patch: `aws ecr put-registry-policy` without the Condition; replication unblocks |
| ~22:30 | Re-run promote-to-prod; terraform plan fails with `cloudformation:DescribeStacks` AccessDenied on `LayerV-production-Api` |
| ~22:35 | Inline IAM policy applied to `nhp-prod-github-actions` granting `cloudformation:DescribeStacks` (later extended to add `GetTemplate` once provider source confirmed both were needed) |
| ~22:50 | Prod plan + apply complete; release proceeds |
| ~23:00 | #1322 (image-deploy DAG bug) surfaces — separate sibling incident, see that issue |

Total operator time across the two terraform failures: ~30–60 min during a release window already tight from #1322's DAG issues.

## Why both broke at prod and not sandbox

Both failures share a structural property: **prod-only feature gating
or environment role**.

- The ECR registry policy is only instantiated in destination-account
  terraform. Sandbox is the source account; that policy resource has
  `count = 0` there. Sandbox apply never evaluates it.

- The CFN data source is gated on `deploy_website_api_dns = true`,
  which is set only in prod tfvars. Sandbox apply skips the data
  source entirely (`count = 0`).

Both made it through:

- `terraform fmt -check` — formatting only, no semantic checks.
- `terraform validate` (PR-time, both envs) — schema check; data
  sources don't refresh during validate, and resource-policy
  Conditions are evaluated by AWS at runtime, not by terraform.
- `terraform plan` on sandbox merge — runs but skips the conditional
  resources entirely.
- `terraform apply` on sandbox merge — same, skipped.

The first time anything in CI actually exercised either configuration
was the prod-promote `terraform plan`. Which fails the entire release.

## Why we couldn't just "plan against prod at PR time"

The obvious fix — run `terraform plan` against prod credentials on
every PR — was closed off by #1121 in February. PR authors can run
arbitrary code during `terraform plan` via `data "external"` blocks,
provider hooks, or other escape hatches. Minting prod creds at PR
time, even read-only, hands every contributor a one-step IAM
fingerprinting and state-exfil vector against prod.

#1221 is the open follow-up for restoring per-PR plan visibility for
**sandbox** with a tightly-scoped read-only role; doing the same for
prod multiplies the blast radius of any privesc found in the role's
policy. We chose not to.

## Detector landed (this PR)

Two static-analysis lints under `.github/scripts/`, both runnable
without AWS credentials:

1. **`check-terraform-iam-coverage.py`** — enumerates every
   `data "aws_*"` block, looks up required IAM actions in a curated
   per-data-source map, and asserts the union of policies attached
   to `aws_iam_role.github_actions` covers each action. Fail-closed on
   unknown data source types (the next slip lands loud, not silent).

2. **`check-terraform-policy-conditions.py`** — denylist of
   `(resource_type, condition_key)` pairs known to evaluate
   incorrectly under AWS service-linked auth contexts. Initial seed:
   `(aws_ecr_registry_policy, aws:SourceAccount)`.

Both run as steps in the existing `terraform-validate` job in
`.github/workflows/build-and-push.yml`. Fixtures under
`tests/lints/terraform-prod-drift/fixtures/` reproduce the #1316
and #1323 conditions and assert each lint catches them.

Design tradeoffs for the four candidate detectors are in
`docs/design/TERRAFORM_PROD_DRIFT_DETECTOR.md`. Operator runbook
for findings is in `docs/runbooks/terraform-prod-drift.md`.

## What the detector doesn't catch

- **Per-environment role-attachment differences.** A grant that's
  conditionally attached only to the sandbox role would pass even
  though prod doesn't get it. Catching this requires walking
  conditional `count` predicates per env. Tracked separately.
- **Resource-ARN scope mismatches.** The lint checks action names,
  not whether the Resource glob actually covers the data source's
  target. Tightening this is follow-up work.
- **Runtime AWS auth misbehavior other than the listed denylist.**
  We can only guard against known anti-patterns; new gotchas need an
  incident + a denylist entry. The detector reduces the blast radius
  of a *recurrence*, not the first occurrence of a new class.

## Cross-references

- #1212 — added `aws_cloudformation_stack.website_api` (failure 2 origin).
- #1316 — fix for failure 1 (ECR Condition removal).
- #1319 → [`docs/incidents/2026-04-24-ecr-source-account-trap.md`](2026-04-24-ecr-source-account-trap.md) — companion artifact: full audit of `aws:SourceAccount`/`aws:SourceArn` use across `terraform/modules/`, plus the reviewer-facing `Principal.Service` vs `Principal.AWS` rule.
- #1322 — sibling incident in the same release window (image-deploy DAG).
- #1323 → #1414 — terraform reconciliation of the manual IAM grant.
- #1415 — cleanup of the legacy inline IAM policy (post-apply).
- #1324 — this incident's root-cause-fix issue (the detector).
- #1121 — PR-time creds removal (the constraint that ruled out
  Candidate 1 / 2 from the issue's candidate list).
- #1221 — open follow-up for sandbox readonly plan visibility.
