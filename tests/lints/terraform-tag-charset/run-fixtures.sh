#!/bin/bash
# run-fixtures.sh — exercise check-terraform-tag-charset.py against the
# fixtures and assert the exit code matches expectation. Mirrors the
# pattern in tests/lints/terraform-prod-drift/run-fixtures.sh.
#
# Run by `make lint-terraform-drift` and by the CI step in
# `.github/workflows/build-and-push.yml`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/tests/lints/terraform-tag-charset/fixtures"
LINT="$REPO_ROOT/.github/scripts/check-terraform-tag-charset.py"

# (fixture, expected-exit, optional-stderr-substring-grep)
# A non-empty grep field asserts the lint's stderr contains the literal
# substring — keeps the bad-charset fixture honest by checking the
# annotation actually names the offending char class. The substring
# matches both "tag key contains…" and "tag value contains…" so a
# refactor that drops the `key`-side message still fails.
FIXTURES=(
  "clean|0|"
  "bad-charset|1|contains chars outside AWS's allowed set"
)

# Per-regression-class assertion: the bad-charset fixture encodes one
# distinct regression class per resource, each crafted with a unique
# offender substring that the annotation echoes. Every substring below
# must appear in the lint's stderr — if a future refactor silently
# breaks N-1 of N detections, the FIXTURES single-grep above would
# still pass (any one `→` in stderr matches), but this list fails
# loud. Update in lockstep with `fixtures/bad-charset/terraform/main.tf`
# when adding a new class.
BAD_CHARSET_CLASS_OFFENDERS=(
  "(bootstrap → knock)"        # unicode_arrow
  "(bootstrap -> knock)"       # ascii_arrow_and_parens
  "Has (Parens)"               # literal_form_bad_key (offending KEY)
  "bad arrow → here"           # single_line_map
  "bad → on opener line"       # opener_line_first_kv
  "bad → with comment"         # trailing_comment
  "ASG with bad → in value"    # asg_singular_tag (offending VALUE)
  "Bad>Key"                    # asg_singular_tag_key (offending KEY)
  "Ticket #1234"               # hash_in_string (# inside string)
  "locals → tag map"           # locals_tag_map
)

# Lockstep check: FIXTURES array and on-disk fixture dirs must match.
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
  IFS='|' read -r name want_exit want_grep <<<"$spec"
  fixture="$FIXTURES_DIR/$name/terraform"
  if [[ ! -d "$fixture" ]]; then
    echo "::error::fixture not found: $fixture" >&2
    FAIL=$((FAIL + 1))
    continue
  fi

  err_log="$TMP/$name.err"
  set +e
  python3 "$LINT" "$fixture" 2>"$err_log"
  got_exit=$?
  set -e

  if [[ "$got_exit" -ne "$want_exit" ]]; then
    echo "::error::fixture $name: expected exit $want_exit, got $got_exit" >&2
    echo "----- stderr -----" >&2
    cat "$err_log" >&2
    echo "------------------" >&2
    FAIL=$((FAIL + 1))
    continue
  fi

  if [[ -n "$want_grep" ]]; then
    if ! grep -qF -- "$want_grep" "$err_log"; then
      echo "::error::fixture $name: expected stderr to contain '$want_grep'" >&2
      echo "----- stderr -----" >&2
      cat "$err_log" >&2
      echo "------------------" >&2
      FAIL=$((FAIL + 1))
      continue
    fi
  fi

  if [[ "$name" == "bad-charset" ]]; then
    missing=0
    for offender in "${BAD_CHARSET_CLASS_OFFENDERS[@]}"; do
      if ! grep -qF -- "$offender" "$err_log"; then
        echo "::error::fixture bad-charset: expected stderr to mention regression-class offender '$offender'" >&2
        missing=$((missing + 1))
      fi
    done
    if (( missing > 0 )); then
      echo "----- stderr -----" >&2
      cat "$err_log" >&2
      echo "------------------" >&2
      FAIL=$((FAIL + 1))
      continue
    fi
  fi

  PASS=$((PASS + 1))
done

echo "terraform-tag-charset fixtures: $PASS pass / $FAIL fail"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
