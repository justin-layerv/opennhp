# Terraform Prod-Drift Detector

Tracks: [#1324](https://github.com/layervai/nhp/issues/1324). Regression
fence for [#1316](https://github.com/layervai/nhp/pull/1316) (ECR
`aws:SourceAccount` Condition) and
[#1323](https://github.com/layervai/nhp/issues/1323) (CFN data source
without IAM grant).

## Problem

The 2026-04-24 prod release hit two terraform failures that both PR-time
CI and the sandbox promote workflow reported green on:

1. **#1316 — ECR registry policy `aws:SourceAccount` Condition.** A
   defense-in-depth Condition silently failed because ECR's cross-account
   replication service does not populate `aws:SourceAccount` in the
   destination-side authorization context. Sandbox validation passed
   because sandbox's primary-account ECR module has `count = 0` and
   never exercises the policy. The break was caught at promote-time
   preflight, after a multi-week window of zero replicated images.

2. **#1323 — `data "aws_cloudformation_stack" "website_api"` IAM gap.**
   The data source was added in #1212, gated on
   `local.website_api_dns_enabled`. Prod tfvars set
   `deploy_website_api_dns = true`; sandbox does not. Sandbox `terraform
   plan` never refreshed the data source (`count = 0`), so the missing
   `cloudformation:DescribeStacks` + `cloudformation:GetTemplate` grants
   on the `nhp-prod-github-actions` role only surfaced when prod
   `terraform plan` actually tried to refresh.

Both broke at prod-apply time. Both were invisible to every PR-time
`terraform validate` and every sandbox `terraform plan`.

## Failure classes

The two cases above are **distinct classes**, and the detector should
treat them as such — papering them together obscures both:

- **Class A (IAM gap).** A consumer (data source or resource) is added
  that requires an IAM action the apply role does not have. Sandbox
  may skip it entirely via `count`/feature flag; prod hits it on every
  plan. #1323 is the canonical case. Generalizes to any future data
  source whose required actions aren't grant-checked at PR time.

- **Class B (resource-policy Condition that doesn't populate).** An
  account-scoped resource policy (ECR registry policy, KMS key policy,
  S3 bucket policy used cross-account, etc.) carries a Condition
  evaluated by an AWS service-linked role in a context where AWS does
  not populate the Condition key. The policy validates fine offline
  and even passes sandbox apply (where sandbox's source-account
  matches by accident); it denies in prod. #1316 is the canonical case
  for `aws:SourceAccount` on `aws_ecr_registry_policy`. Generalizes to
  a small denylist of (resource type, condition key) pairs that have
  bitten us or have documented AWS gotchas.

## Candidate detectors

The issue proposed four candidates. Below: cost, coverage, FP rate,
and verdict for each.

### Candidate 1 — Prod-identical plan in CI

Run `terraform plan` against prod credentials (read-only) on every infra
PR using prod tfvars.

- **Coverage.** Catches both classes; the data source actually
  refreshes against prod, the resource policies are evaluated against
  prod-side authz where applicable.
- **FP rate.** Low. Plans are deterministic given pinned providers and
  state.
- **Cost.** High, and not just runner minutes. **Blocked by [#1121](https://github.com/layervai/nhp/issues/1121)**:
  PR-time AWS credentials were removed from `terraform-validate`
  because PR authors can run arbitrary code during `terraform plan`
  (external data sources, provider hooks) — minting prod creds at PR
  time, even read-only, hands every contributor a one-step IAM
  fingerprinting + state-exfil vector against prod. The open follow-up
  [#1221](https://github.com/layervai/nhp/issues/1221) is reintroducing
  this *for sandbox* with a tightly-scoped readonly role; doing the
  same for prod multiplies the blast radius of any privesc found in
  the plan-role definition. The day the readonly-prod-plan role
  forgets to deny one IAM verb, this becomes how prod gets pillaged.

  Verdict: **rejected for now.** Worth revisiting only after #1221
  ships and produces enough operational evidence to scope a prod twin.
  If we eventually do this, it's an *additional* layer on top of the
  static checks below — not a replacement.

### Candidate 2 — Data-source proof-of-life test against prod

A CI step that enumerates `data` blocks and executes a minimal API
call for each against prod creds.

- **Coverage.** Catches Class A. Doesn't catch Class B (registry/KMS
  policy issues are evaluated by a *service-linked role*, not the
  PR-time test caller — the test would happily succeed against prod
  ECR with the test caller's permissions while replication remains
  broken).
- **FP rate.** Low.
- **Cost.** Same #1121 problem as Candidate 1 — needs prod creds at
  PR time. Narrower than a full plan but the privesc vector is the
  same shape. A `data "external"` block in a PR that runs `aws iam
  *` during the proof-of-life step is the textbook bypass.

  Verdict: **rejected.** Same risk profile as Candidate 1, less coverage.

### Candidate 3 — Per-merge sandbox promote fidelity audit

Emit a manifest after each successful sandbox apply: which `data`
blocks would have refreshed in prod, which tfvars differ between
sandbox and prod, which IAM grants differ between the sandbox and
prod apply roles. Human-reviewed diff on major changes.

- **Coverage.** Catches Class A *eventually* (post-merge, before
  prod-promote — better than catching it at promote-time, worse than
  catching it at PR-time). Doesn't catch Class B on its own.
- **FP rate.** N/A — informational only.
- **Cost.** Low (post-merge job, no PR-time creds).

  Verdict: **complementary, not primary.** Useful as belt-and-braces
  alongside Candidate 4, but doesn't shift detection left. Skipped in
  this PR, tracked separately if the static checks below ever miss a
  case they should have caught.

### Candidate 4 — Static analysis at PR time

Two separate lints, both runnable without AWS credentials:

- **4A — IAM gap lint.** Enumerate every `data "aws_*"` block in
  `terraform/`. For each, look up the required IAM actions in a
  small per-data-source map (`<data_source>.json` allowlist, e.g.
  `aws_cloudformation_stack` → `cloudformation:DescribeStacks` +
  `cloudformation:GetTemplate`). Parse the apply-role policies in
  `terraform/modules/ecr/main.tf` (the role's policies are all
  `jsonencode({...})` blocks; the lint runs `terraform plan
  -backend=false -json` for the `nhp` module against a synthetic
  empty state to render the policy documents reliably). For each
  data source's gating predicate (`count = local.<flag> ? 1 : 0`
  pattern), determine which env(s) instantiate it by reading
  `terraform/environments/<env>/terraform.tfvars`. For each env that
  instantiates the data source, assert the rendered policy bound to
  `nhp-<env>-github-actions` allows the required actions. **Fail
  closed** on unmapped data sources — a new `data "aws_<unknown>"`
  block requires a one-line addition to the map, not silent passthrough.

- **4B — Resource-policy Condition denylist lint.** For each
  account-scoped resource policy in the listed set
  (`aws_ecr_registry_policy`, `aws_kms_key.policy`,
  `aws_s3_bucket_policy` with cross-account replication grants,
  initially), assert the rendered policy document does not contain
  any (resource type, condition key) pair from the denylist. Initial
  denylist seed: `(aws_ecr_registry_policy, aws:SourceAccount)` —
  the #1316 anti-pattern. Each entry carries a comment with the
  AWS-doc citation and the incident reference.

- **Coverage.** 4A catches Class A (#1323). 4B catches Class B
  (#1316). Together they cover both prod-only failure modes the
  issue calls out.
- **FP rate.** Low for 4A — the data-source map is a closed set we
  control. Higher false-negative risk if the map drifts; the
  fail-closed behavior on unmapped data sources is the mitigation. 4B
  is essentially an explicit denylist; FPs are limited to lookalike
  patterns we deliberately add. There is *no* per-line escape hatch
  by design: a finding either reflects a real gap (fix it) or the
  lint's rule is wrong (push back on the lint). Bypass-by-comment
  would re-create the silent-failure mode the lint exists to close.
- **Cost.** Low. No AWS creds needed. Single job, ~10s on a small repo.

  Verdict: **chosen.** Closes the regression class without re-opening
  the #1121 vector. Cheap to extend (each new data-source map entry
  is ~5 lines).

## Chosen detector

**Candidate 4 (4A + 4B).** Two scripts under `.github/scripts/`:

- `check-terraform-iam-coverage.py` — Class A lint (4A).
- `check-terraform-policy-conditions.py` — Class B lint (4B).

Both run as steps in a dedicated non-matrix job
`terraform-prod-drift-lint` (named "Terraform Prod-Drift Lint (PR)"
in the GitHub UI) in `.github/workflows/build-and-push.yml`. The job
sits outside `terraform-validate` so a future matrix change there
can't silently disable the fences; it runs once per PR
(environment-agnostic, no work duplication).

Python over Bash for these two specifically because:

1. The IAM lint needs to parse JSON-encoded policy documents nested
   inside HCL — bash + grep would miss every wildcard
   (`cloudformation:*`, `*:Get*`) and every multi-line `Action`
   array. The existing `check-qurl-slo-lockstep.sh` works in bash
   because it reads two scalar values; this script is structurally
   different.
2. `python-hcl2` is on every Linux runner via pip and is the tooling
   baseline used by `terraform-aws-iam-actions` and similar
   community linters.

The maintainability cost of "another language in
`.github/scripts/`" is real but bounded — Python is already used in
this repo (see `scripts/` and `tests/`), and the alternative
(rendering `terraform plan -json` then `jq`-ing it) trades parsing
complexity for a 30s init+plan cost on every PR.

Both scripts ship with regression fixtures in
`tests/lints/terraform-prod-drift/`:

- `fixtures/iam-gap-1323/` — reproduces the #1323 condition and
  asserts 4A flags it.
- `fixtures/policy-condition-1316/` — reproduces the #1316 anti-pattern
  and asserts 4B flags it.
- `fixtures/clean/` — green case, asserts both pass.

The fixtures are exercised by a `make lint-terraform-drift` target
that runs both scripts against each fixture and asserts the
expected exit codes; the same suite runs in CI under
`terraform-prod-drift-lint` so the fixtures are gated on every PR.

## Out of scope for this PR

- **Candidate 1 / 2.** Tracked under #1221 (sandbox readonly plan)
  and a new follow-up if/when we're ready to extend to prod.
- **Candidate 3.** Tracked separately. Useful as second-line defense
  but doesn't shift detection left.
- **Resource-policy denylist beyond the `aws_ecr_registry_policy`
  pair.** The denylist seed is the one empirically-verified
  resource type with two condition keys (`aws:SourceAccount`,
  `aws:SourceArn`). Add entries when we encounter (or document) a
  new pattern; review-required.
- **Data-source map beyond what `terraform/` uses today.** The map
  ships seeded with the 15 data source types currently in the repo.
  Adding a new `data "aws_*"` block requires a map entry in the
  same PR — fail-closed enforces this.
- **AWS-managed policy ARN action lookup.** The lint can't statically
  resolve the contents of `arn:aws:iam::aws:policy/*` attachments.
  Today no AWS-managed policies are attached to the canonical
  `github_actions` role; if one is added, the lint emits a
  `::warning` so the gap is visible. Curating a small (ARN → action
  set) map for the AWS-managed policies actually used is a follow-up.
- **Per-environment role-attachment differences.** The lint takes the
  union of role policies regardless of `count` predicates. A grant
  attached only in sandbox would pass even though prod doesn't get
  it. The fix needs gate-predicate walking per env.
- **Resource-ARN scope.** The lint checks action names, not whether
  the Resource glob covers the data source's target.
- **`Deny` narrowing on managed-policy attachments.** `statement_actions`
  drops `Deny` statements (the lint checks "can the role perform an
  action?", and a `Deny` doesn't grant). The mixed-Allow/Deny warn
  fires only on inline `aws_iam_role_policy` bodies — not on
  `aws_iam_policy` declarations attached via
  `aws_iam_role_policy_attachment`, because shared managed policies
  (permission boundaries, etc.) legitimately mix effects and the
  warn would be noise. This means a managed policy whose effective
  grant is `Allow X then Deny X under conditions` is counted as
  `Allow X` in the coverage union — the lint may report a clean
  pass when the role's *effective* permission is narrower. Acceptable
  for the targeted regression class (#1323 is "no grant anywhere",
  not "Deny narrows the grant"); flagging for completeness. (cr
  round 15.)
- **Cross-module IAM coverage.** The lint scopes role attribution by
  module path (canonical = `terraform/modules/ecr/`). A future role
  identity that lives in a different module would need a small lint
  change. The collision case is fixture-fenced
  (`colliding-role-namespaces`).
- **Cross-module role identity through variables.** The lint resolves
  cross-module role references by literal-substring match
  (`module.ecr.github_actions_role_name`) and same-module
  `aws_iam_role.X.{id,name}` references. A parent module that wires
  `role_name = module.ecr.github_actions_role_name` into a child
  module variable (`role = var.role_name`) would not credit the
  child's policies to the canonical role — those grants would
  silently miss the coverage union. The repo doesn't use this shape
  today; if a future refactor adopts it, extend the lint to walk
  module-input variables, or move the policy declaration up to the
  canonical module's caller. (cr round 10.)
- **Class C (IAM grants for prod-only features).** A specialization
  of Class A — the union check catches the "no grant anywhere"
  failure mode that #1323 hit. True per-env grant differences are
  not covered (see "Per-environment role-attachment differences"
  above).
- **Branch-protection wiring** is operational, not in-tree. The
  `terraform-prod-drift-lint` job runs on every PR but only blocks
  merge once `Terraform Prod-Drift Lint (PR)` is listed in the
  `main` branch protection required-checks. Tracked as #1425.

## Update: resource-create coverage (#2996)

Class A was always defined as "a consumer — data source **or resource** —
that requires an IAM action the apply role does not have" (see *Failure
classes*), but the original detector only walked `data` blocks. #2996 hit
the resource half: `aws_cloudwatch_composite_alarm` needs
`cloudwatch:PutCompositeAlarm`, a distinct action from the
`cloudwatch:PutMetricAlarm` the apply role already granted. PR-time
`terraform plan` runs under the read-only plan role and never calls the
write API, so the gap was invisible until the post-merge `terraform apply`
turned `main` red — the same "green at PR, red at apply" signature as
#1323, one step later in the lifecycle.

`check-terraform-iam-coverage.py` now walks `resource "aws_*"` blocks too,
against `RESOURCE_ACTIONS`. The design deliberately differs from the
data-source half in one respect: the resource map is **not** seeded
exhaustively. The tree has ~130 resource types vs. ~17 data-source types,
and hand-deriving provider-accurate create/update/delete action sets for
all 130 up front would be error-prone and mostly redundant (every type is
already exercised by a passing apply). So:

- `RESOURCE_ACTIONS` maps the types we choose to action-check — seeded
  with the CloudWatch alarm/dashboard family (the #2996 incident domain
  and its siblings).
- `RESOURCE_UNCHECKED_ACK` grandfathers every other resource type present
  when the half shipped: an explicit, reviewed allowlist that is skipped,
  with a standing burn-down to migrate entries into `RESOURCE_ACTIONS`.
- A resource type in **neither** set is **fail-closed** (exit 2),
  preserving the "no silent passthrough" posture for genuinely new types.
  A new resource type in a PR forces a map-or-grandfather decision — the
  #2996 catch, one merge earlier.

This trades the data-source half's complete-coverage guarantee for
tractability. The resource half catches (a) regressions on mapped types
and (b) any brand-new resource type; it does **not** catch a new action
requirement on an already-grandfathered type until that type is burned
down into `RESOURCE_ACTIONS`. That residual is the acknowledged cost of
not hand-mapping 130 types on day one. Regression fixtures:
`resource-iam-gap-2996` (mapped type, missing action → exit 1),
`unmapped-resource` (type in neither set → exit 2), `resource-alarm-covered`
(mapped + fully granted → exit 0).

## Acceptance / done criteria (from #1324)

- [x] Design doc in `docs/design/` comparing the four candidates.
- [x] Detector implemented in CI catching #1316 and #1323
      regression classes (`.github/scripts/check-terraform-iam-coverage.py`,
      `.github/scripts/check-terraform-policy-conditions.py`).
- [x] Regression fixtures referencing both #1316 and #1323
      (`tests/lints/terraform-prod-drift/fixtures/`).
- [x] Runbook update — `docs/runbooks/terraform-prod-drift.md`.
- [x] Post-incident review — `docs/incidents/2026-04-24-prod-terraform-drift.md`.
