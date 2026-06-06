# cis-metric-filter-patterns lint

Freezes the CIS v1.4.0 CloudWatch Logs metric-filter `pattern` strings in
[`terraform/modules/security/cloudtrail_metric_filters.tf`](../../../terraform/modules/security/cloudtrail_metric_filters.tf)
against a golden reference
([`golden.json`](golden.json)).

## Why

AWS Security Hub matches each `CloudWatch.N` control against the **exact**
CIS-prescribed filter term set and fails the control on any divergence
("Additional fields or terms cannot be added"). A one-character edit to a
`pattern` therefore silently reverts a CIS control (CloudWatch.1/4/5/6/7/8/9/
10/11/12/13/14) to FAILED. Because sandbox sets `enable_cloudtrail = false`
(no trail to validate against) and `terraform validate` doesn't check pattern
fidelity, the only place that surfaces today is the Security Hub re-evaluation
~18h **after the prod apply**. This lint converts that slow, post-apply failure
into a red check on the PR that touched the pattern.

See [`.github/scripts/check-cis-metric-filter-patterns.py`](../../../.github/scripts/check-cis-metric-filter-patterns.py)
for the checker and the #1140 / PR #2344 context.

## Updating a pattern (deliberately)

These patterns are frozen. The lint catches *accidental* drift; it cannot
vouch for a *deliberate* edit, so the golden must stay independently
re-validatable. `golden.json` carries a `_controls` map (filter key →
`CloudWatch.N` control) precisely so a reviewer can re-check each pattern
against its named AWS page without trusting the .tf.

To change a pattern:

1. **Re-validate** the new pattern verbatim against the AWS Security Hub
   `CloudWatch.N` remediation page named for that key in `_controls`. This
   is the load-bearing step — `--dump` does NOT validate, it only reflects
   whatever the .tf currently says.
2. Edit it in `cloudtrail_metric_filters.tf`.
3. Regenerate the golden (carries `_controls` + `patterns`):
   `python3 .github/scripts/check-cis-metric-filter-patterns.py --dump > /tmp/p.json`
   then merge `_controls` + `patterns` into `golden.json` (keep the `_comment`).
4. Both files change in the same PR. A reviewer must treat any `golden.json`
   diff as a security-control change and re-verify it against the AWS page —
   the two-file, reviewed edit is the point.

## Fixtures

Each `fixtures/<name>/` holds a minimal `filters.tf` + `golden.json` pair:

| fixture | expects | exercises |
|---------|---------|-----------|
| `clean` | exit 0 | tf matches golden (incl. escaped-quote + brace-in-pattern parsing) |
| `changed` | exit 1 | a pattern diverges from the golden |
| `missing` | exit 1 | a golden key absent from the tf (would FAIL a control) |
| `extra` | exit 1 | a tf key absent from the golden (un-vetted addition) |

Run locally: `./tests/lints/cis-metric-filter-patterns/run-fixtures.sh`
(or `make lint-cis-metric-filter-patterns`).
