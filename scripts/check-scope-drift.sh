#!/usr/bin/env bash
# check-scope-drift.sh
# ----------------------------------------------------------------------------
# Fail if the Component dropdown in .github/ISSUE_TEMPLATE/bug_report.yml
# drifts from the Scopes table in CLAUDE.md. These two are the only
# places in the repo that list valid commit scopes; drift between them
# means either:
#   - A new scope was added to CLAUDE.md but not to the bug form —
#     reporters can't pick it, triagers re-label forever.
#   - A new scope was added to the form but not to CLAUDE.md —
#     reporters pick a scope that the commit-convention enforcement
#     won't accept, and release-please can't categorize.
#
# `other` is the one legitimate form-only entry: a reporter-UX escape
# hatch that is NOT a valid commit scope. It's subtracted from the
# form set before diffing.
#
# Usage:
#   ./scripts/check-scope-drift.sh         # exit 0 in sync, 1 on drift
#   make lint-workflows                    # wired into the workflow-lint target
#
# Dependencies: python3 with PyYAML. CI installs PyYAML explicitly in
# `.github/workflows/validate-workflows.yml`; for local dev install via
# `python3 -m pip install pyyaml` or `apt install python3-yaml`. Prefer
# `python3 -m pip` over bare `pip` — on macOS `pip` may be missing or
# point at Python 2. A missing PyYAML surfaces as "ModuleNotFoundError:
# yaml" — no magic fallback.
# ============================================================================

set -euo pipefail
# NOTE on error propagation: bash's `set -e` does NOT trip when a
# non-zero exit is swallowed by `$(...)` command substitution. `shopt
# -s inherit_errexit` fixes this, but requires bash 4.4+ — macOS
# default bash is 3.2. We guard each extractor's output explicitly
# below instead of relying on inherit_errexit so the script runs
# consistently on both the CI runners (bash 5.x) and local macOS
# dev boxes (bash 3.2). A failed extractor with no stdout is caught
# by the emptiness check that follows each assignment.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORM="${REPO_ROOT}/.github/ISSUE_TEMPLATE/bug_report.yml"
CLAUDE_MD="${REPO_ROOT}/CLAUDE.md"

if [ ! -f "$FORM" ]; then
  echo "ERROR: missing $FORM" >&2
  exit 1
fi
if [ ! -f "$CLAUDE_MD" ]; then
  echo "ERROR: missing $CLAUDE_MD" >&2
  exit 1
fi

# Extract the Component dropdown's options. The form guarantees the id is
# `component` and options are indented list items beneath its `options:`
# key. Python walks the YAML so we don't hand-parse — failure to find
# the block is itself an error (comment was removed or schema drift).
#
# `|| exit $?` propagates the python exit code through the command
# substitution — without it, a python failure would be swallowed per
# the NOTE above.
form_scopes=$(python3 - "$FORM" <<'PY'
import sys, yaml
from collections import Counter
# Explicit utf-8 — CLAUDE.md contains em dashes / arrows / box chars,
# and the form descriptions may contain non-ASCII too. Relying on
# locale.getpreferredencoding() is a UnicodeDecodeError waiting for
# a dev box with a non-UTF-8 default.
with open(sys.argv[1], encoding="utf-8") as f:
    doc = yaml.safe_load(f)
for section in doc.get("body", []):
    if section.get("id") == "component":
        opts = section.get("attributes", {}).get("options", [])
        values = []
        has_other = False
        for o in opts:
            # GitHub issue-form dropdown options can be strings OR
            # {label, value} dicts (the latter is added when a form
            # wants display labels to differ from the recorded value).
            # Take the value first, fall back to label; skip anything
            # unrecognized rather than printing Python's dict repr.
            if isinstance(o, str):
                v = o
            elif isinstance(o, dict):
                v = o.get("value") or o.get("label") or ""
            else:
                continue
            if v == "other":
                has_other = True
                continue
            if v:
                values.append(v)
        # Duplicate detection: `sort -u` downstream silently dedupes, so
        # `[server, server, agent]` in the form would compare equal to
        # `[server, agent]` in CLAUDE.md. Emit an explicit error instead.
        # `Counter` is O(n) vs the O(n²) of `list.count()` per element;
        # it also reads cleaner for a small list.
        dupes = sorted(v for v, c in Counter(values).items() if c > 1)
        if dupes:
            print(
                "ERROR: duplicate component(s) in bug_report.yml dropdown: "
                + ", ".join(dupes),
                file=sys.stderr,
            )
            sys.exit(1)
        for v in values:
            print(v)
        # Trailing marker so bash can tell whether `other` was present
        # without re-parsing the YAML. Stripped before the diff.
        if has_other:
            print("__OTHER__")
        sys.exit(0)
print("ERROR: no `id: component` dropdown in bug_report.yml", file=sys.stderr)
sys.exit(1)
PY
) || exit $?

# Split off the `other` marker so the real scope list doesn't diff
# against CLAUDE.md with an __OTHER__ ghost.
#
# `|| true` on the `grep -vx` — if the form happens to have ONLY
# `other` (form_scopes == "__OTHER__"), grep matches zero lines and
# exits 1, which combined with `pipefail` would trip `set -e` silently.
# Pathological today but a zero-cost guard.
if echo "$form_scopes" | grep -qx '__OTHER__'; then
  form_has_other=1
  form_scopes=$(echo "$form_scopes" | grep -vx '__OTHER__' || true)
else
  form_has_other=0
fi

# Extract the Scopes table from CLAUDE.md. The table is identified by
# its "### Scopes" heading; we pull rows until the blank line that
# terminates the table and take the first backtick-delimited cell.
# `|| exit $?` — same propagation trick as above.
claude_scopes=$(python3 - "$CLAUDE_MD" <<'PY'
import re, sys
with open(sys.argv[1], encoding="utf-8") as f:
    body = f.read()
# Find the heading, then scan forward to the first `|`-line. This is
# looser than requiring the table to immediately follow the heading,
# which tolerates future edits that insert an intro sentence or extra
# whitespace between heading and table without breaking CI.
hm = re.search(r"^### Scopes\s*$", body, re.MULTILINE)
if not hm:
    print("ERROR: could not find '### Scopes' heading in CLAUDE.md", file=sys.stderr)
    sys.exit(1)
lines = body[hm.end():].splitlines()
# Skip ahead to the first pipe-line (table start). Stop at the next
# heading or the end of the section.
table_lines = []
in_table = False
for line in lines:
    if line.startswith("#"):
        break
    if line.startswith("|"):
        in_table = True
        table_lines.append(line)
    elif in_table and not line.strip():
        break
rows = [line for line in table_lines if line.startswith("| `")]
scopes = []
for row in rows:
    mm = re.match(r"^\| `([^`]+)` \|", row)
    if mm:
        scopes.append(mm.group(1))
if not scopes:
    print("ERROR: '### Scopes' table in CLAUDE.md parsed to zero rows", file=sys.stderr)
    sys.exit(1)
for s in scopes:
    print(s)
PY
) || exit $?

# Sort both so the diff is stable regardless of declaration order.
form_sorted=$(echo "$form_scopes" | sort -u)
claude_sorted=$(echo "$claude_scopes" | sort -u)

if [ "$form_sorted" = "$claude_sorted" ]; then
  # `wc -l` of an empty string returns 1, not 0. Guard explicitly so
  # the message is accurate if we ever hit the degenerate case of
  # both sides being empty (the script would still be "in sync").
  if [ -z "$form_sorted" ]; then
    count=0
  else
    count=$(echo "$form_sorted" | wc -l | tr -d ' ')
  fi
  echo "OK: bug_report.yml Component dropdown matches CLAUDE.md Scopes table"
  if [ "$form_has_other" = "1" ]; then
    echo "    ($count scopes, plus 'other' in the form)"
  else
    echo "    ($count scopes; 'other' sentinel is NOT present in the form — consider adding it back for reporter UX)"
  fi
  exit 0
fi

# Drift — emit an actionable diff showing which side has what the other
# doesn't. `comm` needs sorted input (already). Keep an unindented copy
# so the `other`-sentinel detection below is a simple `grep -qxF` on
# raw scope names rather than a whitespace-exact regex.
only_in_form_raw=$(comm -23 <(echo "$form_sorted") <(echo "$claude_sorted"))
only_in_claude_raw=$(comm -13 <(echo "$form_sorted") <(echo "$claude_sorted"))
only_in_form=$(echo "$only_in_form_raw" | sed 's/^/    /')
only_in_claude=$(echo "$only_in_claude_raw" | sed 's/^/    /')

echo "DRIFT: bug_report.yml Component dropdown and CLAUDE.md Scopes disagree."
echo ""
if [ -n "$only_in_form_raw" ]; then
  echo "  In bug_report.yml but NOT in CLAUDE.md Scopes table:"
  echo "$only_in_form"
  echo ""
  echo "  → Either add these to CLAUDE.md's Scopes table, or remove from the form."
  echo ""
fi
if [ -n "$only_in_claude_raw" ]; then
  echo "  In CLAUDE.md Scopes table but NOT in bug_report.yml:"
  echo "$only_in_claude"
  echo ""
  # `other` is a form-only reporter-UX sentinel. If it shows up in
  # CLAUDE.md's Scopes table, the fix is to remove it from CLAUDE.md,
  # not add it to the form (it's already there, subtracted before
  # this comparison). Call that case out explicitly to avoid the
  # misleading default "add to form" suggestion.
  if echo "$only_in_claude_raw" | grep -qxF other; then
    echo "  → NOTE: 'other' is a form-only sentinel, not a commit scope."
    echo "         Remove it from CLAUDE.md's Scopes table."
    echo "         (For any non-'other' entries above: add to the form.)"
  else
    echo "  → Add these as options in .github/ISSUE_TEMPLATE/bug_report.yml."
  fi
  echo ""
fi
exit 1
