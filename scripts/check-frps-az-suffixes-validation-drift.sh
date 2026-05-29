#!/usr/bin/env bash
# check-frps-az-suffixes-validation-drift.sh
# ----------------------------------------------------------------------------
# Fail if the `frps_az_suffixes` validation blocks drift between the four
# declarations of the variable:
#   - `terraform/variables.tf`                                        (root)
#   - `terraform/modules/qurl-reverse-tunnel-server/variables.tf`     (module)
#   - `terraform/environments/sandbox/variables.tf`                   (env-root, added by PR #2035)
#   - `terraform/environments/prod/variables.tf`                      (env-root, added by the prod FRPS-behind-AC activation PR)
#
# Why this exists: the same variable is declared in all four places —
# once at the module so module-direct consumers (smoke fixtures, isolated
# tests) get plan-time validation, once at the root so a typo fails plan
# even when `deploy_frps = false` keeps the module out of the graph, and
# once at each env root (sandbox + prod) so a tfvars typo attributes to
# the env root rather than bubbling up to the parent module. All four
# `validation { condition = ... ; error_message = ... }` blocks are
# intentionally duplicated and explicitly documented as "keep in
# lockstep" — this script is the lint that enforces the lockstep so
# the duplication can't silently rot.
#
# #2037 tracks extending this lint to cover the other four FRPS
# variable families with mirrored env-root copies (`connect_layerv_host`,
# `frps_min_size`, `frps_max_size`, `frps_desired_capacity`); this
# script intentionally covers only `frps_az_suffixes` until then.
#
# What this script enforces:
#   - `type` and `default` lines match (cr round 6 — silent default-value
#     drift would produce two different runtime contracts depending on
#     which caller instantiated the variable).
#   - Each `condition` / `error_message` pair from every `validation`
#     block matches between root and each mirrored copy.
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
#     validation blocks in just one copy is not flagged as
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
#       between root and every mirrored copy.
#   1 — drift detected (script prints a diff). Either update all copies
#       in lockstep, or update the inline "keep in lockstep" note
#       to explain why divergence is intentional and update this script
#       to allow it.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_VARS="${REPO_ROOT}/terraform/variables.tf"
MODULE_VARS="${REPO_ROOT}/terraform/modules/qurl-reverse-tunnel-server/variables.tf"
# Sandbox env-root copy (added by PR #2035 — closes the
# "Value for undeclared variable" gap that left #1977's
# FRPS-behind-AC topology unapplied). #2037 tracks extending this
# lint to cover the other four variable families this PR mirrored
# (`connect_layerv_host`, `frps_min_size`/`max_size`/`desired_capacity`);
# this script covers `frps_az_suffixes` only.
SANDBOX_ENV_VARS="${REPO_ROOT}/terraform/environments/sandbox/variables.tf"
# Prod env-root copy (added by the prod FRPS-behind-AC activation PR —
# closes the same "Value for undeclared variable" gap for prod that
# #2035 closed for sandbox). Covered here so the prod copy can't
# silently drift from root after activation. #2037 still tracks
# extending coverage to the other mirrored variable families.
PROD_ENV_VARS="${REPO_ROOT}/terraform/environments/prod/variables.tf"

for _f in "$ROOT_VARS" "$MODULE_VARS" "$SANDBOX_ENV_VARS" "$PROD_ENV_VARS"; do
  if [ ! -f "$_f" ]; then
    echo "ERROR: missing $_f" >&2
    exit 1
  fi
done

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

# The root copy is the source of truth; every mirrored copy below must
# match it. Add a new declaration site (e.g. a future env-root) to this
# list as one `"<label>|<path>"` entry to bring it under lockstep
# enforcement — no new compare block needed.
MIRRORED=(
  "module|$MODULE_VARS"
  "sandbox-env-root|$SANDBOX_ENV_VARS"
  "prod-env-root|$PROD_ENV_VARS"
)

root_extract=$(extract_validation "$ROOT_VARS")
if [ -z "$root_extract" ]; then
  echo "ERROR: could not extract frps_az_suffixes validation from $ROOT_VARS" >&2
  exit 1
fi
root_canonical=$(canonicalize "$root_extract")

# Compare each mirrored copy against root. Pairwise so a drift attributes
# to the specific file that drifted rather than failing with confusion.
drift_detected=0
for entry in "${MIRRORED[@]}"; do
  label="${entry%%|*}"
  file="${entry#*|}"

  extract=$(extract_validation "$file")
  if [ -z "$extract" ]; then
    echo "ERROR: could not extract frps_az_suffixes validation from $file" >&2
    exit 1
  fi
  canonical=$(canonicalize "$extract")

  if [ "$root_canonical" != "$canonical" ]; then
    echo "ERROR: frps_az_suffixes validation has drifted between the root and $label declarations." >&2
    echo "" >&2
    echo "  diff (< $ROOT_VARS vs > $file):" >&2
    diff <(printf '%s\n' "$root_canonical") <(printf '%s\n' "$canonical") >&2 || true
    echo "" >&2
    drift_detected=1
  fi
done

if [ "$drift_detected" -ne 0 ]; then
  echo "  Update all copies in lockstep, or change the inline 'keep" >&2
  echo "  in lockstep' notes to explain the intentional divergence and" >&2
  echo "  update this script to allow it." >&2
  exit 1
fi

# Derive the label list from MIRRORED so adding a future env-root stays a
# one-line array edit (no other lines to update).
labels=$(printf '%s, ' "${MIRRORED[@]%%|*}")
echo "frps_az_suffixes validation: root + ${#MIRRORED[@]} mirrored declarations (${labels%, }) are in sync."
