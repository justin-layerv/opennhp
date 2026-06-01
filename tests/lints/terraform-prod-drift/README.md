# terraform-prod-drift lint fixtures

Regression fixtures for the two PR-time terraform drift detectors:

- `.github/scripts/check-terraform-iam-coverage.py` — Class A (#1323).
- `.github/scripts/check-terraform-policy-conditions.py` — Class B (#1316).

Each fixture is a minimal terraform tree that the lints run against. The
test harness (`run-fixtures.sh`) asserts each lint produces the expected
exit code on each fixture. It also has a small alignment sentinel for
nhp#1146's Route53 normalized-record-name exact-name rule, which is
intentionally duplicated in the Python condition lint and
`terraform/modules/ecr` variable validation.

## Fixtures

| Fixture | Class | Expected `iam-coverage` | Expected `policy-conditions` |
|---|---|---|---|
| `clean` | green path | exit 0 | exit 0 |
| `iam-gap-1323` | A — #1323 regression | exit 1 (gap) | exit 0 |
| `policy-condition-1316` | B — #1316 regression (`aws:SourceAccount`) | exit 0 | exit 1 (banned condition) |
| `policy-condition-1316-sourcearn` | B — #1316 sibling (`aws:SourceArn`) | exit 0 | exit 1 (banned condition) |
| `unmapped-data-source` | A — fail-closed on unmapped | exit 2 (unmapped) | exit 0 |
| `indexed-managed-policy` | A — count-gated `aws_iam_policy.X[0].arn` (cr round 1) | exit 0 | exit 0 |
| `single-statement-dict` | A — IAM shorthand `Statement = {...}` (cr round 1) | exit 0 | exit 0 |
| `ternary-policy` | A — union of both `jsonencode` legs (cr round 1) | exit 0 | exit 0 |
| `colliding-role-namespaces` | A — module-scoped role attribution (cr round 2) | exit 1 (gap) | exit 0 |
| `warn-undecodable-policy` | A — warn-path: undecodable role-policy body (cr round 3) | exit 0 + stderr warning | exit 0 |
| `warn-external-managed-arn` | A — warn-path: out-of-tree managed-policy ARN (cr round 3) | exit 0 + stderr warning | exit 0 |
| `warn-undecodable-condition` | B — warn-path: undecodable condition body (cr round 3) | exit 0 | exit 0 + stderr warning |
| `empty-role-attribution` | A — `CANONICAL_ROLE_MODULE_PATH` drift diagnostic (cr round 6) | exit 3 + stderr error | exit 0 |
| `deny-banned-condition` | B — `Deny` + banned key flagged-by-design (cr round 6) | exit 0 | exit 1 (banned condition) |
| `managed-policy-name-collision` | A — bare-name collision warn (cr round 6) | exit 0 + stderr warning | exit 0 |
| `condition-ifexists-allowlist` | B — `*IfExists` operators NOT flagged (cr round 7) | exit 0 | exit 0 |
| `action-wildcard-grant` | A — IAM glob match (`cloudformation:*` covers required actions) (cr round 9) | exit 0 | exit 0 |
| `empty-statement-policy` | A — `Statement = []` decoded-but-empty (cr round 10) | exit 0 + no misleading warn | exit 0 |
| `mixed-allow-deny-warn` | A — mixed `Allow`/`Deny` warn (cr round 10) | exit 0 + stderr warning | exit 0 |
| `legacy-multi-target-attachment` | A — `aws_iam_policy_attachment` multi-target shape (cr round 11) | exit 0 | exit 0 |
| `attachments-exclusive` | A — `aws_iam_role_policy_attachments_exclusive` shape (cr round 12) | exit 0 | exit 0 |
| `interpolation-with-parens-warn` | A — `${fn(arg)}` interpolation inside string warn (cr round 12) | exit 0 + stderr warning | exit 0 |
| `cross-module-attachment` | A — `module.ecr.github_actions_role_name` cross-module ref positive case (cr round 12) | exit 0 | exit 0 |
| `cross-module-policy-arn` | A — `module.X.Y` cross-module policy_arn shape warn (cr round 13) | exit 0 + stderr warning | exit 0 |
| `literal-role-name-attachment` | A — literal role-name suffix match (cr round 14) | exit 0 | exit 0 |
| `literal-role-name-sibling-prefix` | A — sibling-module role with same suffix doesn't false-positive (cr round 15) | exit 1 (gap) | exit 0 |
| `role-policies-exclusive-noop` | A — `aws_iam_role_policies_exclusive` no-op contract (cr round 16) | exit 0 | exit 0 |
| `heredoc-jsonencode-error` | A/B — `jsonencode(<<EOF ...)` hard-fail (cr round 17) | exit 2 + ::error | exit 2 + ::error |
| `multi-leg-with-bad-paren` | A — multi-leg ternary with interpolation warn (cr round 14) | exit 0 + interpolation warn | exit 0 |
| `github-actions-permission-boundary` | B — nhp#1146 ACME-only permission boundary must not cap terraform CI | exit 0 | exit 1 (`permissions_boundary` on canonical CI role) |
| `route53-tag-filter-gap` | A — `aws_route53_zone` tags-filter drift detection (cr round 14) | exit 1 (gap) | exit 0 |
| `route53-recordset-wildcard` | B — nhp#1146 wildcard Route53 record mutation | exit 0 | exit 1 (missing normalized-record-name condition) |
| `route53-recordset-partial-wildcard` | B — nhp#1146 partial hosted-zone wildcard | exit 0 | exit 1 (missing normalized-record-name condition) |
| `route53-recordset-partial-interpolation-condition` | B — nhp#1146 wildcard zone with an unresolved partial interpolation in the name condition | exit 0 | exit 1 (partial interpolation is not a reviewed variable ref) |
| `route53-recordset-notaction` | B — nhp#1146 Allow + NotAction wildcard mutation | exit 0 | exit 1 (missing normalized-record-name condition) |
| `route53-recordset-action-change-glob` | B — nhp#1146 `route53:Change*` action glob wildcard mutation | exit 0 | exit 1 (action glob matches record mutation) |
| `route53-recordset-action-service-glob` | B — nhp#1146 `route53:*` action glob wildcard mutation | exit 0 | exit 1 (service glob matches record mutation) |
| `route53-recordset-notresource` | B — nhp#1146 Allow + NotResource wildcard mutation | exit 0 | exit 1 (NotResource is wildcard-equivalent) |
| `route53-recordset-notresource-condition` | B — nhp#1146 Allow + NotResource remains banned even with a narrow name condition | exit 0 | exit 1 (NotResource is a broad complement) |
| `route53-recordset-broad-condition` | B — nhp#1146 broad `NormalizedRecordNames = ["*"]` | exit 0 | exit 1 (condition is present but not narrow) |
| `route53-recordset-plain-condition` | B — nhp#1146 non-`ForAllValues` normalized-name condition | exit 0 | exit 1 (condition does not validate every record) |
| `route53-recordset-service-case` | B — nhp#1146 mixed-case Route53 service ARN wildcard | exit 0 | exit 1 (case-insensitive wildcard resource detection) |
| `route53-recordset-service-wildcard` | B — nhp#1146 service-level Route53 ARN wildcard | exit 0 | exit 1 (Route53 ARN wildcard resource detection) |
| `route53-recordset-gov-partition` | B — nhp#1146 non-`aws` partition hosted-zone wildcard | exit 0 | exit 1 (partition-agnostic Route53 ARN detection) |
| `route53-recordset-change-resource` | B — nhp#1146 `arn:aws:route53:::change/*` is not a hosted-zone wildcard | exit 0 | exit 0 |
| `route53-recordset-missing-null` | B — nhp#1146 narrow condition without `Null=false` | exit 0 | exit 1 (absent-key guard is required) |
| `route53-recordset-negated-condition` | B — nhp#1146 negated normalized-name condition | exit 0 | exit 1 (`StringNotLike` does not narrow access) |
| `route53-recordset-role-inline-policy` | B — nhp#1146 `aws_iam_role.inline_policy` wildcard mutation | exit 0 | exit 1 (inline role policies are scanned) |
| `route53-recordset-user-policy` | B — nhp#1146 `aws_iam_user_policy` wildcard mutation | exit 0 | exit 1 (user policies are scanned) |
| `route53-recordset-group-policy` | B — nhp#1146 `aws_iam_group_policy` wildcard mutation | exit 0 | exit 1 (group policies are scanned) |
| `route53-recordset-managed-policy` | B — nhp#1146 `aws_iam_policy` wildcard mutation | exit 0 | exit 1 (managed policies are scanned) |
| `route53-recordset-broad-suffix-condition` | B — nhp#1146 broad suffix wildcard such as `*.com` | exit 0 | exit 1 (condition suffix is too broad) |
| `route53-recordset-prefix-wildcard-condition` | B — nhp#1146 wildcard such as `*x` | exit 0 | exit 1 (condition wildcard shape is too broad) |
| `route53-recordset-acme-missing-null` | B — nhp#1146 ACME boundary missing action/type `Null=false` guards | exit 0 | exit 1 (all ACME multi-valued keys require absent-key guards) |
| `route53-recordset-acme-boundary-condition` | B — nhp#1146 valid ACME TXT-only boundary condition shape | exit 0 | exit 0 |
| `route53-recordset-left-label-wildcard-condition` | B — nhp#1146 left-label wildcard requires code review before use | exit 0 | exit 1 (computed-zone patterns are exact-name-only) |
| `route53-recordset-narrow-condition` | B — nhp#1146 valid computed-zone wildcard with narrow name condition | exit 0 | exit 0 |
| `route53-recordset-unreviewed-variable-condition` | B — nhp#1146 wildcard zone with an unreviewed variable-sourced name condition | exit 0 | exit 1 (only reviewed variable refs may defer to Terraform validation) |
| `route53-recordset-variable-condition` | B — nhp#1146 valid computed-zone wildcard with variable-sourced name condition | exit 0 | exit 0 |

The `clean` fixture additionally exercises `count`-gated `aws_iam_role_policy` (the `cloudformation_website_api` grant is gated on `var.deploy_website_api_dns`, mirroring the real `terraform/modules/ecr/main.tf` shape that landed in #1414). `indexed-managed-policy` covers the same gating shape for `aws_iam_policy`.

Each fixture is the minimum terraform that exercises the relevant code
path — enough for the lint to find a `data` block, a role, and a policy,
but not so much that the fixture turns into a maintenance burden when
the production terraform changes.

## Running

```bash
make lint-terraform-drift          # run from repo root
./run-fixtures.sh                  # run from this directory
```

## Adding a fixture

When extending `DATA_SOURCE_ACTIONS` or `BANNED_CONDITIONS`, add a
fixture for the new case here and a row in `run-fixtures.sh`. The
fixture should be small enough to read in one screen.
