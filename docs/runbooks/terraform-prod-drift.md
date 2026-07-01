# Runbook: terraform-prod-drift detector findings

> ⚠️ **Branch-protection wiring tracked separately as #1425.** Until
> `Terraform Prod-Drift Lint (PR)` is in `main`'s required-checks
> list, this lint reports status but cannot **block** a merge — its
> regression-fence guarantee is advisory until #1425 ships. A reviewer
> who waves through a red lint is overriding the fence by hand.

## What fired

The `Terraform Prod-Drift Lint (PR)` job in build-and-push.yml failed
at one of the prod-drift detectors:

- **Check terraform IAM coverage** — `.github/scripts/check-terraform-iam-coverage.py`
- **Check terraform policy-condition denylist** — `.github/scripts/check-terraform-policy-conditions.py`

These are the static fences for #1324 — the regression class behind
the 2026-04-24 prod release incident.

The fixture suite (`tests/lints/terraform-prod-drift/`) can also fail
if either lint script changes shape — that's a hint that the lint
itself, not the terraform under review, needs review.

## What it means

The PR added (or modified) something that, by static analysis, looks
like one of the failure modes that previously broke a prod terraform
apply with no PR-time signal. The lint preserves PR-time CI's
no-AWS-creds posture (#1121); it can't simulate AWS and it doesn't try.

## IAM coverage finding

Format:

```
data source `aws_<type>.<name>` requires IAM action(s) not granted
to `aws_iam_role.github_actions`: <action>, <action>...
```

### What the lint is asserting

For every `data "aws_*"` block in `terraform/`, the lint looks up the
required IAM actions in `DATA_SOURCE_ACTIONS` (a curated map in
`.github/scripts/check-terraform-iam-coverage.py`) and asserts the
union of policies attached to `aws_iam_role.github_actions` allows
each action via direct match or wildcard.

For every `resource "aws_*"` block it does the same against
`RESOURCE_ACTIONS`, but only for the resource types mapped there.
Types in `RESOURCE_UNCHECKED_ACK` are grandfathered (skipped); a type
in neither map is fail-closed (see "Unmapped resource" below). This
half exists because #2996's `aws_cloudwatch_composite_alarm` needed
`cloudwatch:PutCompositeAlarm` — a write action the read-only PR plan
never exercises, so the gap only surfaced at the post-merge apply.

### Action

1. **Add the missing grant.** Most github_actions role policies live
   in `terraform/modules/ecr/main.tf` — add a new `aws_iam_role_policy`
   block scoped to the smallest resource ARN that covers the data
   source. PR #1414's `cloudformation_website_api` is a worked
   example.
2. **If the data source is gated** (`count = local.<flag> ? 1 : 0`),
   gate the IAM grant on the same predicate or its driving variable.
   The lint does *not* enforce gate-symmetry — that's tracked
   separately — but mismatched gates were the root of #1322's IAM
   drift, so the design intent stands.
3. **If you intentionally grant the action via a wildcard** (e.g., an
   existing policy already has `cloudformation:*`), the lint should
   already pass. If it's still firing, the wildcard isn't matching;
   read the role's policies via the JSON output and confirm.

### Discovering IAM actions for a new data source

When `DATA_SOURCE_ACTIONS` doesn't have an entry and the
terraform-aws-provider source isn't obvious (or you want a sanity
check before adding the entry), the empirical path is fastest:

1. **Provision the data source against a sandbox account** with a
   minimal grant (just `sts:GetCallerIdentity`).
2. **Run `terraform plan`** — provider refresh will fail with
   `AccessDenied: User: arn:aws:sts::... is not authorized to perform: <iam:Action>`.
3. **Capture each `AccessDenied` action**, add to the map, re-run plan.
4. Repeat until plan is clean. The list of IAM actions you collected
   is the entry's value.

Cross-check with the provider source under
`https://github.com/hashicorp/terraform-provider-aws/tree/main/internal/service/<service>/`
to make sure no edge-case branches (e.g. tag-filter, name-filter)
need different actions — those become body-aware
`Callable[[dict], list[str]]` entries (cr round 15; see
`_route53_zone_actions` for a worked example).

### Unmapped data source ("not in DATA_SOURCE_ACTIONS")

The lint fails closed when a `data "aws_<type>"` block has no entry
in the map. Add one in the same PR:

1. Open `.github/scripts/check-terraform-iam-coverage.py`.
2. Find the terraform-aws-provider source for the data source —
   `https://github.com/hashicorp/terraform-provider-aws/tree/main/internal/service/<service>/`.
3. Read the data source's `read` function (usually `*_data_source.go`).
   List every AWS API call it makes.
4. Translate to IAM action names (the API name is usually the IAM
   action, with edge cases — Route 53 `ListHostedZones` is one such).
5. Add an entry with a comment citing the provider source file the
   actions came from. Update the README's "Adding a fixture" note if
   the new entry needs a fixture.

### Why fail-closed

The whole point of the lint is "no new data source slips into prod
without an IAM grant". If the map silently passed unknown data sources,
the next #1323-class slip would land. The added one-line cost on every
new data source is the price.

## Resource coverage finding

Format:

```
resource `aws_<type>.<name>` requires IAM action(s) not granted to
`aws_iam_role.github_actions`: <action>...
```

### What it means

The apply role can't create/update/destroy the resource. The read-only
PR-time `terraform plan` never calls the write API, so this gap is
invisible until the post-merge `terraform apply` — exactly what turned
`main` red in #2996 (`aws_cloudwatch_composite_alarm` needs
`cloudwatch:PutCompositeAlarm`, a distinct action from the
`cloudwatch:PutMetricAlarm` the role already had).

### Action

1. **Add the missing grant** to the relevant `terraform_apply_*` policy
   in `terraform/modules/ecr/main.tf`. The least-privilege apply
   policies enumerate actions explicitly, so a new resource subtype
   often needs a new verb even when a sibling verb is already granted
   (`PutCompositeAlarm` ≠ `PutMetricAlarm`). #2996 is the worked
   example.
2. **Watch the IAM-propagation race.** When the same apply both grants
   the action and creates the resource, the IAM evaluator can lag ~60s
   and the fresh resource hits `AccessDenied` anyway — see the
   `time_sleep` shim pattern in `terraform/CLAUDE.md`.

To discover a new type's required actions, use the same empirical loop
as for data sources (minimal-grant apply, collect each `AccessDenied`),
or read the terraform-aws-provider service package's create/update/
delete functions. Cite the provider source in the `RESOURCE_ACTIONS`
comment.

### Unmapped resource ("neither RESOURCE_ACTIONS nor RESOURCE_UNCHECKED_ACK")

The resource half is fail-closed on genuinely new resource types. When
a PR adds a `resource "aws_<type>"` the lint has never seen, decide in
the same PR:

1. **Map it** — add `aws_<type>` to `RESOURCE_ACTIONS` with the IAM
   actions its create/update/delete calls make. Strongest option: the
   type is action-checked from then on.
2. **Grandfather it** — add `aws_<type>` to `RESOURCE_UNCHECKED_ACK`
   when the apply role already covers its CRUD (a passing apply proves
   this) and deriving its full action set is more than the PR warrants.
   This is an explicit, reviewed acknowledgement — not silent
   passthrough — with a standing invitation to burn it down into
   `RESOURCE_ACTIONS` later.

`RESOURCE_UNCHECKED_ACK` is seeded from every resource type present when
the resource half shipped, so this only fires on a type new to the
tree. Stale entries (a type later removed) are harmless — they're just
never iterated.

### Exit code 3 — `CANONICAL_ROLE_MODULE_PATH may have moved`

```
::error::collect_role_actions returned an empty action set, but the
terraform tree contains data sources or resources that require IAM
grants. The canonical role's module path may have moved from
`terraform/modules/ecr/` — update `CANONICAL_ROLE_MODULE_PATH` in
.github/scripts/check-terraform-iam-coverage.py.
```

The lint scopes role-attached resource detection by module path
(`terraform/modules/ecr/` for the canonical
`nhp-${env}-github-actions` role). When the empty-attribution case
fires, it usually means a refactor relocated the role declaration —
e.g., extracted into `modules/iam/` or `modules/github-actions/`. Fix:

1. Identify the new home of `aws_iam_role.github_actions` (`grep -rn
   'resource "aws_iam_role" "github_actions"' terraform/`).
2. Update `CANONICAL_ROLE_MODULE_PATH` in
   `.github/scripts/check-terraform-iam-coverage.py` to the new
   `("modules", "<new-home>")` tuple.
3. Re-run `make lint-terraform-drift` and confirm the diagnostic clears.

### Why is the lint passing when I expected it to fail?

A handful of policy shapes pass the lint by design even though they
might surprise a reviewer expecting a finding:

- **Wildcard actions.** A statement granting `Action = "*"` or
  `cloudformation:*` covers every action in that namespace via the
  IAM glob match (`fnmatch.fnmatchcase` — see `action-wildcard-grant`
  fixture). The lint reports clean. If the wildcard is overly broad
  for the role's actual needs, the *coverage* lint won't catch it —
  this is the IAM coverage lint's job, not least-privilege auditing.
  IAM Access Analyzer / `iamlive` cover the latter.
- **Managed-policy `Deny` narrowing.** `statement_actions` ignores
  `Effect = Deny` (the lints check whether the role *can* perform an
  action; a Deny doesn't grant). For a managed policy whose
  effective permission is `Allow X then Deny X under conditions`,
  the lint counts the Allow and reports the role as covered. The
  mixed-Allow/Deny warn fires only on inline `aws_iam_role_policy`
  bodies (shared managed policies legitimately mix effects). See the
  design doc's "Out of scope" entry for the rationale.
- **`aws_iam_role_policies_exclusive`.** The resource declares the
  exhaustive set of inline-policy NAMES on a role, but doesn't carry
  the policy body — the bodies still come from `aws_iam_role_policy`
  blocks, which the lint already walks. The exclusive resource is
  silently skipped.
- **`count = false` or `for_each = {}` gating.** The lint takes a
  union view of policies regardless of `count`/`for_each` predicates
  (a grant attached only in sandbox would still pass even when prod
  doesn't get it). True per-environment grant differences are
  out of scope; tracked separately in the design doc.

If the lint passes and you believe a finding is warranted, the
question is which of the above shapes applies — extend the
appropriate lint rule (or a new one) rather than working around
the existing posture.

### Unrecognized `policy_arn` warning

```
::warning::aws_iam_role_policy_attachment references a policy_arn
(<arn>) the lint can't recognize. Expected forms: ...
```

Fired when an `aws_iam_role_policy_attachment.policy_arn` matches
neither the in-tree HCL reference (`aws_iam_policy.X.arn` with
optional index) nor the well-formed external ARN
(`arn:aws*:iam::(<12-digit account>|aws|${...}):policy/<name>`).
Almost always a typo or placeholder — e.g.
`arn:aws:iam::ACCOUNT_PLACEHOLDER:policy/foo`. Fix the ARN to a
recognized shape; the lint then resolves the actions (or warns
out-of-tree, which is also actionable).

### Cross-module module-output managed-policy ARN warning

```
::warning::aws_iam_role_policy_attachment binds a cross-module
module-output managed policy (module.X.Y) to
`aws_iam_role.github_actions`; the lint doesn't walk module outputs
and will exclude its actions from the coverage union. ...
```

Fired when an attachment's `policy_arn` is a `module.X.Y`
module-output reference (third recognized shape, alongside in-tree
`aws_iam_policy.X.arn` and external literal ARNs). The lint doesn't
walk module outputs to resolve the underlying policy, so the
actions are excluded from the coverage union. Fix:

1. **Hoist the policy declaration into the canonical role's
   module.** If the policy is logically owned by the github_actions
   coverage surface, declare it directly in
   `terraform/modules/ecr/` so the lint's same-module
   `aws_iam_policy.X.arn` resolution succeeds.
2. **Inline the grant.** Replace the attachment with an
   `aws_iam_role_policy` block listing the actions inline. Loses
   the encapsulation but keeps the lint enumeration intact.
3. **Accept the warning.** If the action set is genuinely owned by
   another module and the coverage gap is tolerable, the warning
   stays — but be aware a future data source that needs the actions
   will trip the IAM-coverage check, requiring options 1 or 2 then.

### Out-of-tree managed-policy ARN warning

```
::warning::aws_iam_role_policy_attachment.<name> binds an out-of-tree
managed policy (<arn>) to `aws_iam_role.github_actions`; the lint
can't enumerate its actions and will exclude them from the coverage
union. ...
```

The lint can resolve `aws_iam_role_policy_attachment.policy_arn` only
when the referenced `aws_iam_policy` is declared in the same module
*and* in the canonical role module path. References to a managed
policy declared elsewhere — or a hand-written ARN of an AWS-managed
policy — can't be enumerated statically, so the actions don't reach
the coverage union and an IAM gap may be falsely reported (or
silently missed). Fix:

1. **Inline the grant.** If the ARN points to a small AWS-managed
   policy whose actions are well-understood, replace the attachment
   with an `aws_iam_role_policy` block that lists the actions
   inline. The lint then enumerates them.
2. **Move the declaration into the canonical module path.** If a
   sibling module declares the policy, hoist the declaration into
   `terraform/modules/ecr/` (or whatever
   `CANONICAL_ROLE_MODULE_PATH` points at) so the lint's
   same-module-only resolution succeeds.
3. **Accept the warning** when the action set is genuinely
   out-of-scope for the lint (e.g., a `ReadOnlyAccess` AWS-managed
   policy whose actions are too broad to enumerate). The fail-closed
   posture means the lint won't credit those actions; if the
   coverage check then fires falsely, take action 1 or 2.

This warning is paired by design with the IAM-coverage finding
itself — the warning explains why a coverage gap might be reported
even though a managed-policy attachment looks like it should grant
the action.

### Mixed `Allow`/`Deny` inline role-policy warning

```
::warning::aws_iam_role_policy.<name>: policy mixes `Allow` and
`Deny` effects — the lint counts only the Allow grants and ignores
the Deny narrowing ...
```

Fired when an `aws_iam_role_policy` attached to the canonical
`github_actions` role has both `Effect = Allow` and `Effect = Deny`
statements in the same body. The lint's coverage union takes only
the Allow grants — a Deny narrowing is invisible to the lint. The
warning is scoped to inline role policies only; shared managed
policies (e.g. permission boundaries) legitimately mix effects by
design, and warning on those would be noise. Fix:

1. **Split the Allow and Deny into separate `aws_iam_role_policy`
   blocks.** This makes the intent explicit in source and removes
   the lint's blind spot.
2. **Convert to a permission boundary.** If the Deny is meant to
   subtract from many policies (rather than narrow a single grant),
   it likely belongs in
   `terraform/modules/security/main.tf` (`permission_boundary`).
3. **Accept the warning** if the mixed shape is intentional and
   contained — the lint still passes (warnings don't fail). The
   tradeoff: a future addition of a sensitive Allow under the same
   Deny shape won't get flagged, since the warn is one-time per
   policy. Prefer 1 or 2.

### Interpolation-with-parens warning

```
::warning::found `${fn(...)}` interpolation inside a string literal
in a policy body — `_iter_jsonencode_args` may miscount parens and
truncate the decoded body. ...
```

The balanced-paren scanner that walks `jsonencode(...)` calls treats
HCL string literals as opaque, but a `${fn(arg)}` interpolation
inside a string carries an extra `(` and `)` that the scanner can't
distinguish from policy-body parens. The decoded body would then be
truncated and actions silently dropped. The repo doesn't use this
shape today; the warn fires if a refactor introduces it. Fix:

1. **Hoist the interpolation into a `local` or `variable`.** Compute
   the value outside the policy body and reference it as a bare
   string interpolation (`${local.x}` with no inner parens).
2. **Extend `_iter_jsonencode_args`** to recognize `${...}` inside
   string literals and walk past the inner parens. The current scanner
   is intentionally simple; adding interpolation-awareness is a
   30-line change once you accept the complexity tradeoff.

### Heredoc-form `jsonencode(<<EOF ...)` warning

```
::warning::found heredoc-form `jsonencode(<<EOF ...)` policy body —
the lint can't decode actions inside heredocs. Convert to an inline
`jsonencode({...})` call or extend .github/scripts/_tf_lint_lib.py.
```

The balanced-paren scanner in `_tf_lint_lib.py` understands string
literals but not HCL heredocs — actions inside a `<<EOF ... EOF`
payload aren't extracted. The repo doesn't use this shape today; the
warning fires if a refactor introduces it. Fix:

1. Convert the heredoc to an inline `jsonencode({...})` block (the
   common shape across the rest of the codebase). The lint then
   decodes the actions normally; or
2. If a heredoc is genuinely required, extend `_iter_jsonencode_args`
   in `.github/scripts/_tf_lint_lib.py` to recognize and skip
   heredoc payloads.

## Policy-condition denylist finding

Format:

```
resource `aws_<type>.<name>` contains banned Condition key `<key>`
— AWS does not populate this key in the auth path for this resource
type and the Condition will silently deny in prod.
```

### What the lint is asserting

For each `(resource_type, condition_key)` pair in `BANNED_CONDITIONS`
in `.github/scripts/check-terraform-policy-conditions.py`, the lint
flags any policy body containing that key.

### Action

1. **Remove the Condition.** The fix in #1316 was a single-line
   removal of `Condition.StringEquals.aws:SourceAccount`. The
   surrounding `Principal` restriction was load-bearing and stayed.
2. **If you believe the denylist entry is wrong** — i.e., AWS does
   populate the condition key in this auth path now, or the resource
   type is wired differently than the entry assumes — open a PR
   removing the entry from `BANNED_CONDITIONS`, with proof:
   - AWS documentation citation showing the key populates here.
   - A successful sandbox apply + observation that the service
     actually performs the action under the Condition (the original
     #1316 case had a green sandbox apply too — that's not enough).
   - Reviewer sign-off from someone who's debugged AWS service-linked
     role auth before.

   The bar is high because every entry on the denylist costs
   approximately one "you can't do that" PR review per year. The
   value is in *not* paying for an entry's removal that will cost a
   prod incident to put back.

### Adding a new denylist entry

When you encounter (or document) a new "AWS doesn't populate this
key here" gotcha, extend `BANNED_CONDITIONS` with `(resource_type,
condition_key, AWS_doc_url, incident_ref)`. Add a fixture under
`tests/lints/terraform-prod-drift/fixtures/` that exercises it, and
add a row to the fixture suite in `run-fixtures.sh`.

### Known false-positive shape: Deny statements

The lint flags any statement containing the banned condition key,
regardless of `Effect`. A `Deny` statement keyed on an
unpopulated condition fails *open* (the deny doesn't fire when AWS
doesn't populate the key) — i.e., functionally inert, not the same
failure mode as a load-bearing Allow with the same key. We flag it
anyway because:

1. It signals confusion about how the key actually evaluates
   (someone wrote it expecting it to *do* something).
2. Future copy-paste of the same shape into an Allow position would
   then carry the bug. Catching it on the Deny costs little; catching
   it post-flip costs an incident.

If you have a load-bearing reason for a Deny that intentionally
no-ops on the unpopulated key (rare), refactor to make the intent
explicit (e.g., a different condition operator like `BoolIfExists`)
rather than relying on AWS's omission.

## KMS wildcard-decrypt finding

Format:

```
resource `aws_<type>.<name>` statement `<Sid>` grants a decrypt-capable
KMS action on a broad resource (`Resource = "*"`, an account-wildcard
ARN, or `NotResource`) with no same-account-resource condition.
```

### What the lint is asserting

The Class-C guard added for #1523 (regression-prevention for #1125 /
PR #1520). In an **identity** policy, an `Allow` statement granting a
decrypt-capable KMS action (`kms:Decrypt` / `kms:ReEncryptFrom`,
IAM-glob-aware so `kms:*`/`*` count) on a broad resource lets a
same-account principal decrypt across account boundaries unless the
statement is scoped to same-account resources. A resource is "broad" when
it is `Resource = "*"`, an ARN whose account-id field is `*`
(`arn:aws:kms:*:*:key/*`, reaches every account) or empty
(`arn:aws:kms:us-east-1::key/*`, denotes no real key — flagged
conservatively as malformed), or any `NotResource`.

### Action

1. **Scope `Resource` to explicit same-account key ARNs** (e.g.
   `[var.kms_key_arn]`), or
2. **Add a same-account condition**: `aws:ResourceAccount`
   (`= data.aws_caller_identity.current.account_id`) — or, for AWS-managed
   keys whose ARN isn't known at plan time (SecretsManager/SSM),
   `kms:ViaService` — in a positive `StringEquals`/`StringLike` condition.
   `kms:CallerAccount` does **not** count: in an identity policy it
   resolves to the principal's own account, so it never constrains the
   *resource's* account (the #1125 trap). `*IfExists`, negated operators,
   and a pure-`*` value don't count either.

### What this lint does and does not prove

- It proves the **presence** of same-account-scoping *syntax*, not the
  **correctness** of the bound account value. The real account is usually
  `data.aws_caller_identity.current.account_id`, resolved at apply, so a
  hardcoded *foreign* concrete account
  (`StringEquals aws:ResourceAccount = "<foreign-acct>"`) passes the lint
  clean. A reviewer must still confirm the account literal — a green check
  is not "the account value is verified."
- Only `aws:ResourceAccount` and `kms:ViaService` are recognized as scope.
  Tag conditions (`aws:ResourceTag/...`) and `aws:ResourceOrgID` are
  **not** same-account bounds (a foreign key can carry a matching tag;
  same-org spans accounts), so such grants are flagged and must refactor
  to explicit ARNs or `aws:ResourceAccount`.
- `kms:ViaService` pins the call to a service endpoint, not strictly to an
  account; a same-account secret referencing a foreign KMS key is a
  documented residual gap (accepted per #1523 as the AWS-managed-key
  pattern).

### Full-admin grants

A legitimate break-glass / admin role with `Action = "*"` (or a broad
`NotAction`) on `Resource = "*"` **will** trip this finding, because it
*can* decrypt cross-account. There is intentionally **no exception
mechanism** today (the tree is clean). The first real admin-shaped grant
needs a deliberate decision, not a reflexive scoping edit: either narrow
the grant, or add an explicit, reviewed exception path to
`kms_wildcard_decrypt_findings` (e.g. an allowlist of `(type, name, Sid)`
with a rationale, mirroring how `BANNED_CONDITIONS` is documented) plus a
fixture. Don't bolt `aws:ResourceAccount` onto a grant that genuinely
needs admin breadth.

### Adding coverage

New shapes get a fixture under
`tests/lints/terraform-prod-drift/fixtures/` (one dir, `terraform/` tree)
plus a row in `run-fixtures.sh`'s `FIXTURES` array and the README table,
kept in lockstep (the suite asserts dir/row parity).

## Diagnostic — how to see what the lint actually saw

Both scripts support `--json` for machine-readable output:

```bash
python3 .github/scripts/check-terraform-iam-coverage.py --json | jq
python3 .github/scripts/check-terraform-policy-conditions.py --json | jq
```

The IAM coverage JSON includes the full union of action globs the
lint resolved from the role's policies — useful when a finding
seems wrong (the union is what the lint compared against).

## Running locally before pushing

```bash
make lint-terraform-drift
```

Requires `python-hcl2`. The make target prints the install command on
miss.

## After resolving

The lint will pass on the next CI run. No manual unblock — there's
no escape hatch. If you need one, you should push back on the lint
itself, not the finding.

## Related

- `docs/design/TERRAFORM_PROD_DRIFT_DETECTOR.md` — design doc with
  the candidate-detector tradeoffs and why this approach was chosen.
- `docs/incidents/2026-04-24-prod-terraform-drift.md` — the incident
  that motivated the lint.
- `docs/runbooks/ecr-replication-failure.md` — runtime runbook for
  the #1316 condition (the in-prod failure path); this runbook
  covers the at-PR-time prevention path.
- `docs/runbooks/promote-to-prod-partial-deploy.md` — sibling
  incident from the same release window (#1322).
- #1425 — operational follow-up: ensure
  `Terraform Prod-Drift Lint (PR)` is in the `main` branch
  protection required-checks list (the lint runs on every PR but
  blocks merge only when listed there).
