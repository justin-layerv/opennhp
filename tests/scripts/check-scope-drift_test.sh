#!/usr/bin/env bash
# check-scope-drift_test.sh — fixture tests for scripts/check-scope-drift.sh
# ----------------------------------------------------------------------------
# Write fixture bug_report.yml + CLAUDE.md files into a tempdir that
# mimics the real repo layout, invoke the script against that tempdir,
# and assert exit code + output lines. Catches regressions in the
# two extractors the next time the real files get reformatted.
#
# The script resolves paths relative to its own location via
# `dirname "${BASH_SOURCE[0]}"/..`, so the fixture dir must contain
# a `scripts/` symlink back to the real script. Run from any
# directory; $REPO_ROOT is derived from this test file.
#
# Usage: bash tests/scripts/check-scope-drift_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-scope-drift.sh"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# Build a fake repo layout in a tempdir. The script expects its sibling
# `scripts/` and a repo-root `CLAUDE.md` + `.github/ISSUE_TEMPLATE/
# bug_report.yml`. Symlink the script in so we're testing the real
# code, not a copy.
_make_fixture_repo() {
  local dir="$1" form_body="$2" claude_body="$3"
  mkdir -p "$dir/scripts" "$dir/.github/ISSUE_TEMPLATE"
  ln -sf "$SCRIPT" "$dir/scripts/check-scope-drift.sh"
  printf '%s' "$form_body" > "$dir/.github/ISSUE_TEMPLATE/bug_report.yml"
  printf '%s' "$claude_body" > "$dir/CLAUDE.md"
}

# Fixture: form YAML with a parameterized option list.
_make_form_yaml() {
  local options="$1"
  cat <<EOF
name: Bug Report
description: Test fixture
body:
  - type: dropdown
    id: component
    attributes:
      label: Component
      options:
$options
    validations:
      required: true
EOF
}

# Fixture: CLAUDE.md with a parameterized Scopes table.
_make_claude_md() {
  local rows="$1"
  cat <<EOF
# CLAUDE.md

## Commit Convention

### Scopes

| Scope | Component |
|-------|-----------|
$rows

## Other Stuff
EOF
}

# ---- test: in-sync ----------------------------------------------------------

test_in_sync() {
  local name="in-sync form and CLAUDE scopes"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - server
        - ac
        - other"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `server` | NHP Server |
| `ac` | Access Controller |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  if ! grep -q "OK: bug_report.yml Component dropdown matches" <<<"$out"; then
    report_fail "$name" "expected OK message, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: form has extra scope ---------------------------------------------

test_form_only_drift() {
  local name="form-only drift (extra scope in form)"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - server
        - bonus-scope
        - other"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `server` | NHP Server |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "In bug_report.yml but NOT in CLAUDE.md" <<<"$out"; then
    report_fail "$name" "expected form-only-drift message, got: $out"
    return
  fi
  if ! grep -q "bonus-scope" <<<"$out"; then
    report_fail "$name" "expected 'bonus-scope' in output, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: CLAUDE.md has extra scope ----------------------------------------

test_claude_only_drift() {
  local name="CLAUDE-only drift (extra scope in CLAUDE.md)"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - other"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `server` | NHP Server |
| `missing` | Missing from form |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "In CLAUDE.md Scopes table but NOT in bug_report.yml" <<<"$out"; then
    report_fail "$name" "expected claude-only-drift message, got: $out"
    return
  fi
  # Assert EACH missing scope is reported, not just one or the other.
  # A partial-output regression that only emits one side of the diff
  # would previously slip past a combined 'missing|server' match.
  if ! grep -q "missing" <<<"$out"; then
    report_fail "$name" "expected 'missing' scope in output, got: $out"
    return
  fi
  if ! grep -q "server" <<<"$out"; then
    report_fail "$name" "expected 'server' scope in output, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: dict-shaped options are tolerated --------------------------------

test_dict_option_shape() {
  local name="dict-shaped dropdown options are tolerated"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # Mix plain strings and {label, value} dicts — valid GH issue-form
  # shape that the original regex/extractor didn't handle.
  local form_body
  form_body=$(cat <<'EOF'
name: Bug Report
body:
  - type: dropdown
    id: component
    attributes:
      label: Component
      options:
        - agent
        - label: "Server (NHP)"
          value: server
        - other
    validations:
      required: true
EOF
)
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `server` | NHP Server |'
  _make_fixture_repo "$tmp" "$form_body" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0 with dict-shaped option, got $rc. Output: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: intro sentence between heading and table -------------------------

test_intro_sentence_before_table() {
  local name="intro sentence between heading and table (loose regex)"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - other"
  local claude_body
  claude_body=$(cat <<'EOF'
# CLAUDE.md

## Commit Convention

### Scopes

These are the valid commit scopes for this repo:

| Scope | Component |
|-------|-----------|
| `agent` | NHP Agent |

## Other Stuff
EOF
)
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$claude_body"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "loose regex should tolerate intro text. got $rc. Output: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: form missing the component dropdown ------------------------------

test_form_missing_component_dropdown() {
  local name="form missing 'id: component' dropdown — clear error"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # Form has no `id: component` section at all.
  local form_body
  form_body=$(cat <<'EOF'
name: Bug Report
body:
  - type: dropdown
    id: something-else
    attributes:
      label: Different
      options:
        - one
    validations:
      required: true
EOF
)
  local claude_rows='| `agent` | NHP Agent |'
  _make_fixture_repo "$tmp" "$form_body" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "no .id: component. dropdown" <<<"$out"; then
    report_fail "$name" "expected actionable error about missing dropdown, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: CLAUDE.md missing ### Scopes heading -----------------------------

test_claude_missing_scopes_heading() {
  local name="CLAUDE.md missing '### Scopes' heading — clear error"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - other"
  local claude_body
  claude_body=$(cat <<'EOF'
# CLAUDE.md

## Commit Convention

No Scopes section here at all.
EOF
)
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$claude_body"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "could not find .### Scopes. heading" <<<"$out"; then
    report_fail "$name" "expected actionable error, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: CLAUDE.md Scopes table parses to zero rows -----------------------

test_claude_scopes_heading_but_empty_table() {
  local name="### Scopes heading with no table rows — clear error"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - other"
  # Heading exists but no pipe-lines follow (just prose, then next heading).
  local claude_body
  claude_body=$(cat <<'EOF'
# CLAUDE.md

## Commit Convention

### Scopes

Scopes table moved elsewhere, sorry.

## Other Stuff
EOF
)
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$claude_body"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "parsed to zero rows" <<<"$out"; then
    report_fail "$name" "expected zero-rows error, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: duplicate component in the form is caught -----------------------

test_duplicate_component_in_form() {
  local name="duplicate component in form → clear error"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # `sort -u` would silently dedupe; without the explicit dup check
  # in the extractor, this fixture would compare equal to a clean
  # CLAUDE.md and exit 0.
  local form_opts="        - agent
        - server
        - server
        - other"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `server` | NHP Server |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "duplicate component" <<<"$out"; then
    report_fail "$name" "expected 'duplicate component' error, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: 'other' in CLAUDE.md yields targeted advice ----------------------

test_other_leak_into_claude_md() {
  local name="'other' in CLAUDE.md → targeted 'remove from CLAUDE.md' advice"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent
        - other"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |
| `other` | Generic escape hatch |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "form-only sentinel" <<<"$out"; then
    report_fail "$name" "expected 'form-only sentinel' targeted advice, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- runner -----------------------------------------------------------------

# ---- test: dict-shaped `other` is recognized as the sentinel ----------------

test_dict_shaped_other_recognized() {
  local name="dict-shaped {value: other} is filtered + marks has_other"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_body
  form_body=$(cat <<'EOF'
name: Bug Report
body:
  - type: dropdown
    id: component
    attributes:
      label: Component
      options:
        - agent
        - label: "Other (misc)"
          value: other
    validations:
      required: true
EOF
)
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |'
  _make_fixture_repo "$tmp" "$form_body" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  # Success path should acknowledge `other` is present even when it
  # came in via dict-shape, not the simpler "NOT present" warning.
  if ! grep -q "plus 'other' in the form" <<<"$out"; then
    report_fail "$name" "expected success message to confirm 'other' present, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: form without 'other' emits the NOT-present hint ------------------

test_form_without_other_warns() {
  local name="form missing 'other' → success message flags it"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local form_opts="        - agent"
  # shellcheck disable=SC2016 # backticks are literal Markdown, not shell
  local claude_rows='| `agent` | NHP Agent |'
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$(_make_claude_md "$claude_rows")"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  if ! grep -q "NOT present" <<<"$out"; then
    report_fail "$name" "expected 'NOT present' warning, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: form with ONLY 'other' doesn't trip set -e ----------------------

test_form_with_only_other() {
  local name="form with only 'other' doesn't silently trip set -e"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # Pathological but valid: a form whose only Component option is the
  # sentinel. Python emits `__OTHER__` as the sole line; the
  # subsequent `grep -vx '__OTHER__'` matches zero lines and exits 1.
  # Without the `|| true` guard, `set -e` + pipefail would kill the
  # script silently (no output, exit 1) — hard to diagnose.
  local form_opts="        - other"
  local claude_body
  claude_body=$(cat <<'EOF'
# CLAUDE.md

## Commit Convention

### Scopes

No scopes yet (placeholder).

## Other Stuff
EOF
)
  _make_fixture_repo "$tmp" "$(_make_form_yaml "$form_opts")" "$claude_body"
  local out rc=0
  out=$(cd "$tmp" && bash scripts/check-scope-drift.sh 2>&1) || rc=$?
  # Expected: the CLAUDE.md zero-rows error fires before any
  # comparison. What matters is a CLEAR error, not a silent exit-1.
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit on empty Scopes table, got 0. Output: $out"
    return
  fi
  if [ -z "$out" ]; then
    report_fail "$name" "silent failure — grep -vx likely tripped set -e"
    return
  fi
  if ! grep -q "parsed to zero rows" <<<"$out"; then
    report_fail "$name" "expected zero-rows error, got: $out"
    return
  fi
  report_pass "$name"
}

echo "Running check-scope-drift_test.sh"
test_in_sync
test_form_only_drift
test_claude_only_drift
test_dict_option_shape
test_intro_sentence_before_table
test_form_missing_component_dropdown
test_claude_missing_scopes_heading
test_claude_scopes_heading_but_empty_table
test_duplicate_component_in_form
test_other_leak_into_claude_md
test_dict_shaped_other_recognized
test_form_without_other_warns
test_form_with_only_other

printf '\n[check-scope-drift_test.sh] %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'Failures:\n'
  printf '%b' "$failures"
  exit 1
fi
