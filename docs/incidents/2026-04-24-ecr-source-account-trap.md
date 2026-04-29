# Incident artifact: 2026-04-24 ECR `aws:SourceAccount` trap

## Scope

Narrow, pattern-focused companion to
[`docs/incidents/2026-04-24-prod-terraform-drift.md`](2026-04-24-prod-terraform-drift.md).
That document is the broader root-cause-fix artifact for #1324 (the
prod-only-drift detector). This document is the artifact for **#1319**
and answers three pattern-level questions the broader writeup deferred:

1. How did `Condition.StringEquals.aws:SourceAccount` end up on
   `aws_ecr_registry_policy.replication` originally?
2. Was it caught at review, or did it look correct compared to other
   modules that *do* populate `aws:SourceAccount`?
3. What's the distinguishing property a reviewer can apply to tell the
   two cases apart, going forward?

The fix itself shipped in [#1316](https://github.com/layervai/nhp/pull/1316).
The regression fence shipped in #1324's
`.github/scripts/check-terraform-policy-conditions.py`.

## How the Condition got added

The Condition arrived via a staff-review fixup on the
ECR-cross-account-replication feature branch (PR
[#869](https://github.com/layervai/nhp/pull/869), squash-merged to
`main` as `be98f82b` on 2026-04-10; reviewers on a shallow clone may
need `git fetch --unshallow` before `git show be98f82b` resolves).
The block landed as:

```hcl
Condition = {
  StringEquals = {
    "aws:SourceAccount" = var.primary_account_id
  }
}
```

with the in-tree comment "defense-in-depth in case the AWS principal
evaluation drifts -- it ensures only requests originating in the
primary account can use the policy even though we already pinned the
principal to that account's root." (The verbatim quote above is the
durable record of the rationale; the commit hashes — `be98f82b` for
the squash-merge into `main`, `7b2b4e9e` for the pre-squash
feature-branch commit on `refactor/ecr-cross-account-replication`,
no longer reachable from `main` — are convenience pointers, and the
squash message preserves the same "defense-in-depth alongside the AWS
principal pin" rationale verbatim if a future reader wants to
cross-check.)

It was **suggested during staff review and applied as a hardening
change**, not slipped through. The reviewer's mental model was the
generic confused-deputy pattern AWS documents for service-to-service
access policies (S3 → SNS, EventBridge → SNS, BCM → S3), where
`aws:SourceAccount` is recommended defense-in-depth alongside the
`Service` principal pin. That mental model is correct for those cases.
It is not correct for an `aws_ecr_registry_policy` whose Principal is
an `AWS` principal in another account — see "the distinguishing rule"
below.

The Condition applied cleanly to prod on the day it merged. It was
never empirically verified against a real cross-account replication
attempt. Replication then silently failed — every push to the primary
ECR returned `DESTINATION_REGISTRY_ACCESS_DENIED` from the secondary —
for the entire window between that apply and the 2026-04-24 promote
attempt. Sandbox CI never exercised the policy at all (sandbox is the
*source* account; the secondary-side resource is `count = 0` there),
and PR-time `terraform validate` does not evaluate resource-policy
Conditions (AWS evaluates them at runtime). The first observation came
from the promote-to-prod preflight noticing zero `layerv/*` images in
prod ECR.

## The distinguishing rule

**Reviewer heuristic** (resource policies; copy-paste-safe):

- If `Principal.Service` is set → pin `aws:SourceAccount` (load-bearing,
  AWS populates the key).
- If `Principal.AWS` is set on a resource policy → verify empirically
  before pinning; for ECR cross-account replication specifically,
  don't.

"Verify empirically" here means **exercise the auth path the prod
call will actually take, from the side that evaluates the policy** —
not just `terraform apply`. The 2026-04-24 incident is the cautionary
tale: the policy applied cleanly to prod, sandbox CI passed, the only
thing the policy ever rejected was the cross-account replication
attempt that nothing in CI ever made (sandbox is the source account;
the destination-side resource is `count = 0` there). A real check
means a destination-account caller making the kind of request the
policy is supposed to grant, against the live policy. Building a
smoke-time / pre-deploy probe to make this enforceable rather than
reviewer-discipline-only is tracked in
[#1466](https://github.com/layervai/nhp/issues/1466).

The longer form: resource-policy `aws:SourceAccount` / `aws:SourceArn`
is only load-bearing where AWS populates the key in the auth context,
and AWS only populates it where the authoring assumption is the
"confused deputy" pattern — an AWS service is the *caller* and your
account owns the triggering resource.

| `Principal` shape | Calling identity at auth time | Does AWS populate `aws:SourceAccount`/`aws:SourceArn`? | Pin the keys? |
|---|---|---|---|
| `Service: <foo>.amazonaws.com` | An AWS service principal acting on behalf of *some* customer's resource | Yes — AWS sets it to the account that owns the triggering resource | **Yes**, defense-in-depth against cross-tenant confused-deputy |
| `AWS: arn:aws:iam::<other-account>:root` (or a specific role/user there) | An IAM principal in another account, often via a service-linked role | Not guaranteed — for ECR cross-account replication, empirically not populated; the call falls through to implicit deny | **No** — the IAM principal pin *is* the enforcement; pinning a key AWS doesn't populate produces a silent deny |

If a reviewer wants belt-and-braces on an `AWS` principal, the safe
form is `StringEqualsIfExists`, which evaluates true when the key is
absent — but **`IfExists` is not "harmless to sprinkle around"**: if
AWS *does* populate the key and the value doesn't match what the
policy author expected, the statement still denies. The bar for adding
it should be empirical verification that AWS populates the key on this
auth path *and* that the expected value is correct, not the generic
confused-deputy framing.

The right belt-and-braces lever for a `Principal.AWS` policy is
**`aws:PrincipalAccount`** (or `aws:PrincipalOrgID` if cross-org
allow-listing is what's wanted). Unlike `aws:SourceAccount`, those keys
are populated by IAM for *any* request from any principal — including
the cross-account `Principal.AWS` cases this rule covers — so a
`StringEquals` (not `IfExists`) on `aws:PrincipalAccount` is a real
guard that fails closed if AWS ever changes the auth context.
Pinning it on top of the `Principal.AWS = arn:...:root` already in
this repo's ECR registry policy would have failed safe in the
2026-04-24 incident: the `Principal` pin would have caught the same
account, and the Condition would have been redundant rather than
blocking. The artifact's load-bearing claim is that **this** is the
correct lever to reach for, not `aws:SourceAccount`. Whether to
actually apply that lever to `aws_ecr_registry_policy.replication`
on top of the existing principal pin is tracked in
[#1465](https://github.com/layervai/nhp/issues/1465) — the case for
defense-in-depth vs. the cost of a redundant Condition is a
reviewer judgement worth deciding deliberately rather than leaving
implicit.

**Out of scope.** The rule above is for *resource* policies and
covers the two `Principal` shapes that account for everything in
`terraform/modules/` today. Things it does *not* extend to without
further analysis:

- **IAM trust policies** (`aws_iam_role.assume_role_policy`). The
  cross-account analogue here is `sts:ExternalId`, not
  `aws:SourceAccount` — the latter isn't populated on `sts:AssumeRole`
  in the trust direction. This repo has three cross-account
  `Principal.AWS` trust policies — `grafana_cloudwatch` in
  `terraform/modules/grafana-dashboards/main.tf`,
  `grafana_sns_publisher` in
  `terraform/modules/grafana-dashboards/alerts.tf`, and
  `grafana_athena` in `terraform/modules/cost-analytics/main.tf` — and
  all three pin `sts:ExternalId` *when
  `local.grafana_cloud_external_id` is set*. They share a known
  caveat: the Condition is wrapped `local.grafana_cloud_external_id !=
  "" ? {...} : {}`, so in environments where the external ID is unset
  the trust policy degrades to permitting any principal in
  `var.grafana_cloud_aws_account_id`. That's an explicit design
  choice already documented in the `external_id` comment block on
  `grafana_contact_point.qurl_aws_sns` in
  `terraform/modules/grafana-dashboards/alerts.tf`; tightening it is
  out of scope for this audit and tracked in
  [#1462](https://github.com/layervai/nhp/issues/1462).
- `Principal.Federated` (OIDC, SAML), `Principal.CanonicalUser`, and
  mixed-principal statements.
- KMS key policies. KMS evaluates resource policies against IAM in a
  way distinct from generic resource policies, and several of this
  repo's KMS keys use `Principal.AWS` without `Source*` Conditions on
  purpose — see the `EnableRootAccount` statement in
  `terraform/modules/kms/main.tf` (`Principal.AWS = ...:root` on the
  local account, no Condition) for an example.

If a future PR adds `aws:SourceAccount` to any of those shapes, treat
the rule above as silent on the case and verify empirically.

## Audit: every `aws:SourceAccount` / `aws:SourceArn` use in `terraform/modules/`

Generated by `grep -rn -E 'aws:SourceAccount|aws:SourceArn' terraform/`
(the comment block in `terraform/modules/ecr/main.tf` documenting the
removed Condition is the only `aws:SourceArn` mention and is not
itself a Condition; no `aws:SourceArn` Condition is in use anywhere in
the tree). The lint's `BANNED_CONDITIONS` proactively guards both
`aws:SourceAccount` and `aws:SourceArn` on `aws_ecr_registry_policy`
even though only the former was the 2026-04-24 incident's exact
trigger — both keys share the same root cause (ECR's cross-account
replication SLR populates neither in the destination-side auth
context), so a future copy-paste reaching for either would hit the
same trap.

The grep is scoped to `terraform/`. The same reviewer rule below
applies to *any* policy-authoring surface (CloudFormation/SAM
templates, inline policies set via SDK calls in app code, ad-hoc
`aws iam` CLI invocations) — those just live outside the grep's
search root. Extending the audit to a non-terraform surface means
reproducing the rule there, not assuming `terraform/`-clean implies
fleet-wide-clean.

| Module | Resource | Service integration | Principal shape | AWS populates the key? | Verdict | Citation |
|---|---|---|---|---|---|---|
| `ecr/` | `aws_ecr_registry_policy.replication` in `terraform/modules/ecr/main.tf` (Condition itself was removed in #1316; the surviving comment block above the resource documents the removed pattern) | ECR cross-account replication | `Principal.AWS = arn:aws:iam::<primary>:root` | **No** — empirically verified during the 2026-04-24 incident; AWS reference policy omits the key for the same reason | ✅ Removed in [#1316](https://github.com/layervai/nhp/pull/1316); fenced by `check-terraform-policy-conditions.py` | [AWS — cross-account ECR replication policy examples](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions-cross-account-examples.html) |
| `monitoring/` | `aws_iam_policy_document.alerts_policy` statement `AllowCloudWatchAlarms` in `terraform/modules/monitoring/main.tf` | CloudWatch Alarms → SNS publish | `Principal.Service = cloudwatch.amazonaws.com` | Yes — CloudWatch is on AWS's list of `aws:SourceAccount`-supporting services for SNS | ✅ Correct — same-account confused-deputy guard | [AWS — SNS access policy use cases (services supporting `aws:SourceAccount`)](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html) |
| `monitoring/` | `aws_iam_policy_document.alerts_policy` statement `AllowEventBridge` in `terraform/modules/monitoring/main.tf` | EventBridge → SNS publish | `Principal.Service = events.amazonaws.com` | Yes — EventBridge is on AWS's list of `aws:SourceAccount`-supporting services for SNS | ✅ Correct — same as above | [AWS — SNS access policy use cases (services supporting `aws:SourceAccount`)](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html) |
| `security/` | `aws_iam_policy_document.guardduty_email_policy` statement `AllowEventBridgePublish` in `terraform/modules/security/main.tf` | EventBridge (GuardDuty findings rule) → SNS publish | `Principal.Service = events.amazonaws.com` | Yes — same as above | ✅ Correct — same as above | [AWS — SNS access policy use cases](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html) |
| `cost-analytics/` | `aws_s3_bucket_policy.cost_data` statement `AllowBCMDataExports` in `terraform/modules/cost-analytics/main.tf` | BCM Data Exports / Billing Reports → S3 PutObject | `Principal.Service = bcm-data-exports.amazonaws.com` + `billingreports.amazonaws.com` | Yes — both service principals share the same Condition block and both populate `aws:SourceAccount`, per the AWS Data Exports doc | ✅ Correct — AWS-documented bucket policy for CUR 2.0 / Data Exports | [AWS — Billing and Cost Management Data Exports bucket policy](https://docs.aws.amazon.com/cur/latest/userguide/dataexports-s3-bucket.html) |

### Negative finding (acceptance criterion 3 in #1319)

No additional ECR-trap-style usages exist. The only `Principal.AWS`
*resource* policy in the audit was the one fixed in #1316; every
remaining `aws:SourceAccount` use is on a `Principal.Service` policy
where AWS populates the key per the confused-deputy pattern and the
Condition is load-bearing-correct. **No per-module fix PRs are
needed.**

## Why review didn't catch this in April

The four `Principal.Service` rows in the audit table above are exactly
why "looks like the others" was a reasonable conclusion at staff
review — the ECR row is the only *resource* policy in the tree where a
cross-account `Principal.AWS` also carried an `aws:SourceAccount`
Condition. The overlap is what made it a one-of-a-kind anti-pattern,
not either property alone, and there was no written rule for
distinguishing the cases.

Three axes had to fail for the bug to ship and persist:

1. **PR-time** — `terraform validate` doesn't evaluate resource-policy
   Conditions, and there was no lint enforcing this anti-pattern.
2. **Review-time** — no written reviewer rule distinguishing
   `Principal.Service` (where the key is populated) from
   `Principal.AWS` (where it isn't).
3. **Deploy/empirical-time** — for the reasons given above under "How
   the Condition got added", no environment ever observed a real ECR
   replication attempt under the policy until prod.

This artifact + #1324 close axes (1) and (2): the lint blocks
recurrence at PR time, and the reviewer rule blocks the review-time
"looks like the others" misjudgement. The empirical-verification axis
(3) is still open — closing it would mean a sandbox or smoke-time
probe that actually exercises the policy from the destination side
before a prod release relies on it. Tracked in
[#1466](https://github.com/layervai/nhp/issues/1466).

The lint's denylist is intentionally narrow:
`(aws_ecr_registry_policy, aws:SourceAccount)` and
`(aws_ecr_registry_policy, aws:SourceArn)` only. If the same
unpopulated-key trap recurs on a *different* resource type — i.e., a
new service-linked-role-driven cross-account flow ships and someone
copies the confused-deputy pattern onto its resource policy — the
lint will not catch it at PR time. The reviewer rule above is the
primary defense for those cases until an empirical recurrence creates
the verified failure case the lint requires before extending its
denylist.

## Maintenance

The audit is a snapshot, not a live check. The lint fences ECR-shaped
recurrence; everything else relies on this artifact being re-run when
its grounding assumptions change. To re-run the audit, use the grep
documented in the preamble (`grep -rn -E 'aws:SourceAccount|aws:SourceArn' terraform/`)
and reconcile the hits against the audit table below. Re-run and
update this document when:

- A new cross-account `Principal.AWS` resource policy is added to
  `terraform/modules/`, or an existing one gains a `Condition` block.
- A new `Principal.Service` resource policy adds an
  `aws:SourceAccount` / `aws:SourceArn` Condition that wasn't here
  before — confirm it lands in the audit table with the correct
  verdict and AWS-doc citation.
- A *new* resource type is added to the lint's `BANNED_CONDITIONS`
  (i.e., a new ECR-shaped trap is empirically verified somewhere else
  in AWS), in which case the distinguishing-rule prose may need to
  expand and the audit's negative finding may need to be re-run
  against the new key/resource pair.
- The audit moves to a non-`terraform/` policy-authoring surface
  (CloudFormation, SAM, inline SDK calls). The grep in the preamble
  doesn't cover those paths; the rule does.

## Cross-references

- [#1319](https://github.com/layervai/nhp/issues/1319) — this artifact + audit.
- [#1316](https://github.com/layervai/nhp/pull/1316) — the live fix.
- [#1324](https://github.com/layervai/nhp/issues/1324) — the detector.
- [`docs/incidents/2026-04-24-prod-terraform-drift.md`](2026-04-24-prod-terraform-drift.md) — broader incident artifact.
- [`docs/runbooks/ecr-replication-failure.md`](../runbooks/ecr-replication-failure.md) — operator runbook with the gotcha section.
- PR [#869](https://github.com/layervai/nhp/pull/869) — the original ECR cross-account replication PR; the Condition was added during staff review on its feature branch and squash-merged to `main` as `be98f82b`.
- [#1462](https://github.com/layervai/nhp/issues/1462) — follow-up surfaced by this audit: harden Grafana cross-account trust policies so `sts:ExternalId` doesn't degrade to a permissive trust when the external ID is unset.
- [#1465](https://github.com/layervai/nhp/issues/1465) — follow-up surfaced by this audit: the explicit decision on whether to layer `aws:PrincipalAccount` on `aws_ecr_registry_policy.replication` as defense-in-depth alongside the existing principal pin.
- [#1466](https://github.com/layervai/nhp/issues/1466) — follow-up surfaced by this audit: close the third "Why review didn't catch this" axis with a smoke-time / pre-deploy probe that exercises ECR cross-account replication from the destination side before prod relies on it.
