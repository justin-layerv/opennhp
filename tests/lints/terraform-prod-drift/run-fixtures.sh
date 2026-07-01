#!/bin/bash
# run-fixtures.sh — exercise the terraform-prod-drift lints against the
# regression fixtures and assert each lint's exit code (and, for warning
# fixtures, an stderr substring) matches expectation.
#
# Run by `make lint-terraform-drift` and by the CI step in
# `.github/workflows/build-and-push.yml`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/tests/lints/terraform-prod-drift/fixtures"
IAM_LINT="$REPO_ROOT/.github/scripts/check-terraform-iam-coverage.py"
COND_LINT="$REPO_ROOT/.github/scripts/check-terraform-policy-conditions.py"

# (fixture, expected-iam-exit, expected-condition-exit, optional-iam-warn-grep, optional-cond-warn-grep)
# Update README.md's table in lockstep when adding a row.
# An empty grep field means "no warning content asserted"; a non-empty
# one asserts the lint's stderr contains the literal substring. Prefix
# with `not:` to invert — `not:foo` asserts stderr does NOT contain
# `foo` (used to fence regressions where a misleading warning
# previously fired against valid input — cr round 10).
FIXTURES=(
  "clean|0|0||"
  "iam-gap-1323|1|0||"
  "policy-condition-1316|0|1||"
  "policy-condition-1316-sourcearn|0|1||"
  "unmapped-data-source|2|0||"
  "resource-iam-gap-2996|1|0||"
  "unmapped-resource|2|0||"
  "resource-alarm-covered|0|0||"
  "resource-metric-alarm-tag-gap|1|0||"
  "indexed-managed-policy|0|0||"
  "single-statement-dict|0|0||"
  "ternary-policy|0|0||"
  "colliding-role-namespaces|1|0||"
  "warn-undecodable-policy|0|0|policy attribute couldn't be decoded|"
  "warn-external-managed-arn|0|0|out-of-tree managed policy|"
  "warn-undecodable-condition|0|0||policy attribute couldn't be decoded"
  "empty-role-attribution|3|0|CANONICAL_ROLE_MODULE_PATH|"
  "deny-banned-condition|0|1||"
  "managed-policy-name-collision|0|0|declared in multiple modules|"
  "condition-ifexists-allowlist|0|0||"
  "action-wildcard-grant|0|0||"
  "empty-statement-policy|0|0|not:policy attribute couldn't be decoded|"
  "mixed-allow-deny-warn|0|0|policy mixes \`Allow\` and \`Deny\`|"
  "legacy-multi-target-attachment|0|0||"
  "attachments-exclusive|0|0||"
  "interpolation-with-parens-warn|0|0|interpolation inside a string|"
  "cross-module-attachment|0|0||"
  "cross-module-policy-arn|0|0|cross-module module-output managed policy|"
  "literal-role-name-attachment|0|0||"
  "literal-role-name-sibling-prefix|1|0||"
  "role-policies-exclusive-noop|0|0||"
  "heredoc-jsonencode-error|2|2|heredoc-form \`jsonencode(<<EOF|heredoc-form \`jsonencode(<<EOF"
  "multi-leg-with-bad-paren|0|0|interpolation inside a string|"
  "github-actions-permission-boundary|0|1||permissions_boundary"
  "route53-tag-filter-gap|1|0||"
  "route53-recordset-wildcard|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-partial-wildcard|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-partial-interpolation-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-notaction|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-action-change-glob|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-action-service-glob|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-notresource|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-notresource-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-broad-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-plain-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-service-case|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-service-wildcard|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-gov-partition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-change-resource|0|0||"
  "route53-recordset-missing-null|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-negated-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-role-inline-policy|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-user-policy|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-group-policy|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-managed-policy|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-broad-suffix-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-prefix-wildcard-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-acme-missing-null|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-acme-boundary-condition|0|0||"
  "route53-recordset-left-label-wildcard-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-narrow-condition|0|0||"
  "route53-recordset-unreviewed-variable-condition|0|1||route53:ChangeResourceRecordSets"
  "route53-recordset-variable-condition|0|0||"
  "kms-wildcard-decrypt-unconditioned|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-calleraccount|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-resourceaccount|0|0||"
  "kms-wildcard-decrypt-viaservice|0|0||"
  "kms-wildcard-decrypt-scoped-resource|0|0||"
  "kms-wildcard-decrypt-deny|0|0||"
  "kms-wildcard-decrypt-key-policy|0|0||"
  "kms-wildcard-decrypt-ifexists|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-action-glob|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-role-inline|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-reencrypt|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-managed-policy|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-negated-condition|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-stringlike-wildcard|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-viaservice-stringlike|0|0||"
  "kms-wildcard-decrypt-identity-principal|0|0||"
  "kms-wildcard-decrypt-notresource|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-stringlike-mixed|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-stringequals-deadwildcard|0|0||"
  "kms-wildcard-decrypt-account-wildcard-arn|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-notaction|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-forallvalues-scope|0|0||"
  "kms-wildcard-decrypt-user-policy|0|1||decrypt-capable KMS action"
  "kms-wildcard-decrypt-group-policy|0|1||decrypt-capable KMS action"
)

# Consistency check (cr round 3 nit, tightened in round 6): the FIXTURES
# array and the on-disk fixture directories must be in lockstep —
# otherwise a fixture added/renamed in one but not the other drifts
# silently. Assert the *names* match, not just the count, so a rename
# can't slip through.
declared_names=$(for spec in "${FIXTURES[@]}"; do echo "${spec%%|*}"; done | sort)
on_disk_names=$(find "$FIXTURES_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)
if [[ "$declared_names" != "$on_disk_names" ]]; then
  echo "::error::fixture name mismatch between FIXTURES array and fixtures/ directory. Update both in lockstep." >&2
  diff <(echo "$declared_names") <(echo "$on_disk_names") >&2 || true
  exit 1
fi

# The Route53 normalized-record-name exact-name rule is enforced in both the
# Python condition lint and the terraform/modules/ecr variable validation. Keep
# a small sentinel here so wildcard support cannot be added in one language
# without touching this check.
python3 - "$REPO_ROOT" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
py_lint = (root / ".github/scripts/check-terraform-policy-conditions.py").read_text()
ecr_hcl = (root / "terraform/modules/ecr/main.tf").read_text()
# These are literal source needles by design: if the validation is rewritten
# but stays semantically equivalent, update both implementations and these
# sentinel strings in the same change so reviewers see the lockstep edit.
needles = {
    "python wildcard rejection": 'any(char in pattern for char in "*?")' in py_lint,
    "hcl wildcard rejection": 'length(regexall("[*?]", name)) == 0' in ecr_hcl,
}
missing = [name for name, ok in needles.items() if not ok]
if missing:
    for name in missing:
        print(f"::error::Route53 exact-name rule alignment check missing {name}", file=sys.stderr)
    sys.exit(1)
print("Route53 exact-name rule alignment check: OK")
PY

PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for spec in "${FIXTURES[@]}"; do
  IFS='|' read -r name want_iam want_cond want_iam_grep want_cond_grep <<<"$spec"
  fixture="$FIXTURES_DIR/$name/terraform"
  if [[ ! -d "$fixture" ]]; then
    echo "::error::fixture not found: $fixture" >&2
    FAIL=$((FAIL + 1))
    continue
  fi

  iam_log="$TMP/$name.iam.log"
  cond_log="$TMP/$name.cond.log"
  set +e
  python3 "$IAM_LINT" --terraform-root "$fixture" >"$iam_log" 2>&1
  got_iam=$?
  python3 "$COND_LINT" --terraform-root "$fixture" >"$cond_log" 2>&1
  got_cond=$?
  set -e

  status="PASS"
  if [[ "$got_iam" != "$want_iam" ]]; then
    status="FAIL"
    echo "::error::fixture $name: iam-coverage exit was $got_iam, expected $want_iam" >&2
    sed 's/^/    iam-coverage: /' "$iam_log" >&2
  fi
  if [[ "$got_cond" != "$want_cond" ]]; then
    status="FAIL"
    echo "::error::fixture $name: policy-conditions exit was $got_cond, expected $want_cond" >&2
    sed 's/^/    policy-conditions: /' "$cond_log" >&2
  fi
  # Substring assertions support both "must contain" and "must NOT
  # contain" (the latter via a `not:` prefix). The negative case fences
  # regressions where a misleading warning previously fired against
  # valid input — cr round 10's empty-Statement bug.
  check_grep() {
    local lint_name="$1" pattern="$2" log="$3"
    [[ -z "$pattern" ]] && return 0
    if [[ "$pattern" == not:* ]]; then
      local needle="${pattern#not:}"
      if grep -qF "$needle" "$log"; then
        echo "::error::fixture $name: $lint_name stderr unexpectedly contains '$needle'" >&2
        sed "s/^/    $lint_name: /" "$log" >&2
        return 1
      fi
    else
      if ! grep -qF "$pattern" "$log"; then
        echo "::error::fixture $name: $lint_name stderr missing expected substring '$pattern'" >&2
        sed "s/^/    $lint_name: /" "$log" >&2
        return 1
      fi
    fi
    return 0
  }
  check_grep "iam-coverage" "$want_iam_grep" "$iam_log" || status="FAIL"
  check_grep "policy-conditions" "$want_cond_grep" "$cond_log" || status="FAIL"
  echo "  $status fixture=$name iam=$got_iam(want $want_iam) cond=$got_cond(want $want_cond)"
  if [[ "$status" == "PASS" ]]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo
echo "terraform-prod-drift fixture suite: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
