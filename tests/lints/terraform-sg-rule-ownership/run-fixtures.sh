#!/bin/bash
# run-fixtures.sh — exercise check-terraform-sg-rule-ownership.py against
# the fixtures and assert the exit code matches expectation. Mirrors the
# pattern in tests/lints/terraform-tag-charset/run-fixtures.sh.
#
# Run by the CI step in `.github/workflows/build-and-push.yml`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/tests/lints/terraform-sg-rule-ownership/fixtures"
LINT="$REPO_ROOT/.github/scripts/check-terraform-sg-rule-ownership.py"

# (fixture, expected-exit, optional-stderr-substring-grep)
FIXTURES=(
  "clean|0|"
  "mixed-ownership|1|is authoritative for the whole"
)

# Per-regression-class assertion: the mixed-ownership fixture encodes one
# distinct class per security group, each named so the annotation echoes a
# unique substring. Every substring below must appear in the lint's stderr
# — if a future refactor silently breaks N-1 of N detections, the single
# grep above would still pass (any one error matches), but this list fails
# loud. Update in lockstep with
# `fixtures/mixed-ownership/terraform/modules/sg-owner/main.tf`.
MIXED_CLASS_OFFENDERS=(
  "aws_security_group.bad_same_module_ingress"  # same-module inline vs standalone
  "aws_security_group.bad_cross_module_redis"   # the #3281 cross-module shape
  "aws_security_group.bad_unfrozen_egress"      # `egress = []` without ignore_changes
)

# The clean fixture must be clean for the RIGHT reason. A resolver that
# silently fails to follow a reference also "passes" — it just never
# attaches the rule to its group. Assert the summary proves the resolver
# reached every group, and that no `::warning` (the resolver's own
# could-not-resolve signal) was emitted.
CLEAN_EXPECTED_SUMMARY="PASS: 5 aws_security_group resource(s) checked; 5 group(s) have standalone rule owners"

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
  out_log="$TMP/$name.out"
  set +e
  python3 "$LINT" "$fixture" >"$out_log" 2>"$err_log"
  got_exit=$?
  set -e

  if [[ "$got_exit" -ne "$want_exit" ]]; then
    echo "::error::fixture $name: expected exit $want_exit, got $got_exit" >&2
    echo "----- stdout -----" >&2
    cat "$out_log" >&2
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

  if [[ "$name" == "clean" ]]; then
    problem=0
    if ! grep -qF -- "$CLEAN_EXPECTED_SUMMARY" "$out_log"; then
      echo "::error::fixture clean: expected stdout to contain '$CLEAN_EXPECTED_SUMMARY'" >&2
      echo "  (a resolver that stopped following references would also exit 0 —" >&2
      echo "   this assertion is what proves it still reaches every group)" >&2
      problem=1
    fi
    if grep -q '::warning' "$err_log"; then
      echo "::error::fixture clean: lint emitted an unresolved-reference warning; every reference in the clean fixture must resolve" >&2
      problem=1
    fi
    if (( problem > 0 )); then
      echo "----- stdout -----" >&2
      cat "$out_log" >&2
      echo "----- stderr -----" >&2
      cat "$err_log" >&2
      echo "------------------" >&2
      FAIL=$((FAIL + 1))
      continue
    fi
  fi

  if [[ "$name" == "mixed-ownership" ]]; then
    missing=0
    for offender in "${MIXED_CLASS_OFFENDERS[@]}"; do
      if ! grep -qF -- "$offender" "$err_log"; then
        echo "::error::fixture mixed-ownership: expected stderr to mention regression-class offender '$offender'" >&2
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

echo "terraform-sg-rule-ownership fixtures: $PASS pass / $FAIL fail"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
