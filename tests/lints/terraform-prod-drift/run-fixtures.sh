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
  "route53-tag-filter-gap|1|0||"
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
