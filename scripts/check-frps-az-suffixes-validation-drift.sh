#!/usr/bin/env bash
# check-frps-az-suffixes-validation-drift.sh
# ----------------------------------------------------------------------------
# Fail if the `frps_az_suffixes` validation blocks in the root variable
# (`terraform/variables.tf`) drift from the module variable
# (`terraform/modules/qurl-reverse-tunnel-server/variables.tf`).
#
# Why this exists: the same variable is declared twice — once at the
# module so module-direct consumers (smoke fixtures, isolated tests)
# get plan-time validation, and once at the root so a typo fails plan
# even when `deploy_frps = false` keeps the module out of the graph.
# The two `validation { condition = ... ; error_message = ... }` blocks
# are intentionally duplicated and explicitly documented as "keep in
# lockstep" — this script is the lint that enforces the lockstep so
# the duplication can't silently rot.
#
# What this script enforces:
#   - `type` and `default` lines match (cr round 6 — silent default-value
#     drift would produce two different runtime contracts depending on
#     which caller instantiated the variable).
#   - Each `condition` / `error_message` pair from every `validation`
#     block matches between the two files.
#
# What this script handles (cr round 7 hardening):
#   - **Multi-line `default` and `type` values.** A `default = [` opening
#     bracket on its own line is collected with all subsequent lines
#     until the closing `]` on the matching column. The original
#     single-line awk extractor only captured `default = [` and silently
#     dropped the actual list contents.
#   - **Validation block ordering.** Each `validation { condition;
#     error_message }` pair is normalised to a single line and the
#     resulting set is sorted before comparison, so reordering the two
#     validation blocks in just one of the two files is not flagged as
#     drift (the logic is what matters; ordering is incidental).
#
# What this script does NOT enforce (intentional):
#   - Comments inside the variable block. Each side comments its own
#     context (root: "fences when deploy_frps = false"; module: "covers
#     module-direct consumers"). Comment drift is fine.
#   - Description text. The two descriptions intentionally differ — the
#     module description references the cross-repo contract, the root
#     description is shorter.
#
# Usage:
#   ./scripts/check-frps-az-suffixes-validation-drift.sh
#   make lint-workflows                    # wired into the workflow-lint target
#
# Exit codes:
#   0 — type, default, and the (unordered) set of validation pairs match
#       between the two declarations.
#   1 — drift detected (script prints a diff). Either update both files
#       in lockstep, or update the inline "keep both in lockstep" note
#       to explain why divergence is intentional and update this script
#       to allow it.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_VARS="${REPO_ROOT}/terraform/variables.tf"
MODULE_VARS="${REPO_ROOT}/terraform/modules/qurl-reverse-tunnel-server/variables.tf"

if [ ! -f "$ROOT_VARS" ]; then
  echo "ERROR: missing $ROOT_VARS" >&2
  exit 1
fi
if [ ! -f "$MODULE_VARS" ]; then
  echo "ERROR: missing $MODULE_VARS" >&2
  exit 1
fi

# Extract the load-bearing lines from the `frps_az_suffixes` variable
# block. The awk script:
#   1. Scopes matching to the variable block bounded by
#      `variable "frps_az_suffixes" {` and the next top-level `}` at
#      column zero.
#   2. For `type` and `default` lines, joins continuation lines (e.g.,
#      a multi-line `default = [\n  "a",\n  "b",\n]` formatted by
#      `terraform fmt`) by tracking bracket depth until balanced.
#   3. For each `validation { ... }` block, collects the `condition`
#      and `error_message` lines and emits them as a single normalised
#      line per block (so the set of validation pairs can be sorted
#      regardless of source ordering).
#   4. Strips leading whitespace and collapses inner whitespace runs
#      to a single space so cosmetic formatting differences (e.g.,
#      alignment spaces around `=`) don't trigger drift.
extract_validation() {
  local file="$1"
  awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      gsub(/[[:space:]]+/, " ", s)
      return s
    }
    function bracket_delta(s,    i, ch, depth) {
      depth = 0
      for (i = 1; i <= length(s); i++) {
        ch = substr(s, i, 1)
        if (ch == "[" || ch == "{" || ch == "(") depth++
        else if (ch == "]" || ch == "}" || ch == ")") depth--
      }
      return depth
    }
    /^variable "frps_az_suffixes"/ { in_var = 1; next }
    in_var && /^}/                 { in_var = 0; next }

    # Multi-line `type` / `default` collector. Start when the line
    # opens a bracketed value and the brackets are not balanced on the
    # same line; continue collecting until the depth returns to 0.
    in_var && /^[[:space:]]*(type|default)[[:space:]]*=/ {
      buf = $0
      depth = bracket_delta(buf)
      while (depth != 0 && (getline next_line) > 0) {
        buf = buf " " next_line
        depth += bracket_delta(next_line)
      }
      print trim(buf)
      next
    }

    # Validation block collector. Normalise each `validation { ... }`
    # block into one canonical line `condition=...|error_message=...`
    # so the set of validations can be compared regardless of source
    # ordering.
    in_var && /^[[:space:]]*validation[[:space:]]*{/ {
      vc = ""; vm = ""
      while ((getline next_line) > 0) {
        if (next_line ~ /^[[:space:]]*}/) break
        if (next_line ~ /^[[:space:]]*condition[[:space:]]*=/) {
          vc = trim(next_line)
        } else if (next_line ~ /^[[:space:]]*error_message[[:space:]]*=/) {
          vm = trim(next_line)
        }
      }
      print "validation: " vc " || " vm
      next
    }
  ' "$file"
}

# Split the extractor output into:
#   - A header (type + default — order-stable, exactly one of each)
#   - A sorted list of validation lines (order-independent)
# So reordering the two validation blocks is not flagged as drift.
canonicalize() {
  local raw="$1"
  local header validations
  header=$(printf '%s\n' "$raw" | grep -E '^(type|default)[[:space:]]*=' || true)
  validations=$(printf '%s\n' "$raw" | grep -E '^validation: ' | LC_ALL=C sort || true)
  printf '%s\n%s\n' "$header" "$validations"
}

root_extract=$(extract_validation "$ROOT_VARS")
module_extract=$(extract_validation "$MODULE_VARS")

if [ -z "$root_extract" ]; then
  echo "ERROR: could not extract frps_az_suffixes validation from $ROOT_VARS" >&2
  exit 1
fi
if [ -z "$module_extract" ]; then
  echo "ERROR: could not extract frps_az_suffixes validation from $MODULE_VARS" >&2
  exit 1
fi

root_canonical=$(canonicalize "$root_extract")
module_canonical=$(canonicalize "$module_extract")

if [ "$root_canonical" != "$module_canonical" ]; then
  echo "ERROR: frps_az_suffixes validation has drifted between the root and module declarations." >&2
  echo "" >&2
  echo "  diff (< $ROOT_VARS vs > $MODULE_VARS):" >&2
  diff <(printf '%s\n' "$root_canonical") <(printf '%s\n' "$module_canonical") >&2 || true
  echo "" >&2
  echo "  Update both files in lockstep, or change the inline 'keep both" >&2
  echo "  in lockstep' note to explain the intentional divergence and" >&2
  echo "  update this script to allow it." >&2
  exit 1
fi

echo "frps_az_suffixes validation: root and module declarations are in sync."
