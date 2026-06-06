#!/bin/bash
# run-fixtures.sh — exercise check-cis-metric-filter-patterns.py against the
# fixtures and assert the exit code (and a stderr substring) matches
# expectation. Mirrors tests/lints/terraform-tag-charset/run-fixtures.sh.
#
# Run by `make lint-cis-metric-filter-patterns` and by the CI step in
# `.github/workflows/build-and-push.yml` (terraform-prod-drift-lint job).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FIXTURES_DIR="$REPO_ROOT/tests/lints/cis-metric-filter-patterns/fixtures"
LINT="$REPO_ROOT/.github/scripts/check-cis-metric-filter-patterns.py"

# (fixture, expected-exit, optional-stderr-substring-grep)
# The grep field keeps each drift class honest: it asserts the annotation
# actually names the right divergence kind, so a refactor that collapses
# the three messages into one generic string fails loud here.
FIXTURES=(
  "clean|0|"
  "changed|1|diverges from the"
  "missing|1|missing from"
  "extra|1|not in the golden set"
  "malformed|2|cannot read golden"
)

# Lockstep check: FIXTURES array and on-disk fixture dirs must match, so a
# new fixture dir can't be added without an assertion (or vice versa).
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
  tf="$FIXTURES_DIR/$name/filters.tf"
  golden="$FIXTURES_DIR/$name/golden.json"
  if [[ ! -f "$tf" || ! -f "$golden" ]]; then
    echo "::error::fixture incomplete: $name (need filters.tf + golden.json)" >&2
    FAIL=$((FAIL + 1))
    continue
  fi

  err_log="$TMP/$name.err"
  set +e
  python3 "$LINT" --tf "$tf" --golden "$golden" 2>"$err_log" >/dev/null
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

  PASS=$((PASS + 1))
done

# --dump smoke: it must emit valid JSON carrying both `patterns` and the
# `_controls` provenance, so the golden-regeneration path stays working.
dump_out="$TMP/dump.json"
if python3 "$LINT" --tf "$FIXTURES_DIR/clean/filters.tf" --dump >"$dump_out" 2>/dev/null \
  && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "patterns" in d and "_controls" in d and d["patterns"], d' "$dump_out"; then
  PASS=$((PASS + 1))
else
  echo "::error::--dump did not emit valid JSON with patterns + _controls" >&2
  cat "$dump_out" >&2 || true
  FAIL=$((FAIL + 1))
fi

echo "cis-metric-filter-patterns fixtures: $PASS pass / $FAIL fail"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
