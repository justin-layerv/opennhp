#!/usr/bin/env bash
# lint-issue-templates.sh
# ----------------------------------------------------------------------------
# Validate every file under .github/ISSUE_TEMPLATE/ against the right
# GitHub-published schema:
#   - config.{yml,yaml} → vendor.github-issue-config
#   - everything else .{yml,yaml} → vendor.github-issue-forms
#
# Both extensions are accepted by GitHub, so we glob both here; validating
# only `*.yml` would silently skip a contributor's `*.yaml` file — the
# exact silent-skip class this lint is designed to catch.
#
# Called by both `make lint-workflows` (local) and
# `.github/workflows/validate-workflows.yml` (CI) so the two stay in
# lockstep by construction. Requires `check-jsonschema` on PATH.
# ============================================================================

set -euo pipefail

# Resolve template dir relative to this script, not CWD. A dev running
# `bash scripts/lint-issue-templates.sh` from `scripts/` would otherwise
# see an empty $TEMPLATE_DIR and exit 0 — a silent false-green.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/.github/ISSUE_TEMPLATE"

# Fail fast with an actionable message if the script is run directly
# without check-jsonschema installed. `make lint-workflows` has its own
# guard, but a dev running the script standalone would otherwise get
# "command not found" mid-execution with no install hint.
if ! command -v check-jsonschema >/dev/null 2>&1; then
  echo "ERROR: check-jsonschema not found on PATH." >&2
  echo "  Install (local):  pipx install check-jsonschema" >&2
  echo "  Install (CI):     see .github/workflows/validate-workflows.yml" >&2
  exit 1
fi

# A missing template dir in THIS repo is a regression, not a valid
# state — the issue-priority rollout depends on `blank_issues_enabled:
# false`, which is only coherent if at least one form exists. Fail
# loud rather than reporting "nothing to validate".
if [[ ! -d "$TEMPLATE_DIR" ]]; then
  echo "ERROR: $TEMPLATE_DIR not found." >&2
  echo "  At least one issue form must exist — blank_issues_enabled: false" >&2
  echo "  (config.yml) requires it. If you deliberately removed every form," >&2
  echo "  also flip that setting back." >&2
  exit 1
fi

shopt -s nullglob

forms=()
configs=()
for f in "$TEMPLATE_DIR"/*.yml "$TEMPLATE_DIR"/*.yaml; do
  case "$(basename "$f")" in
    config.yml|config.yaml)
      # GitHub picks one config file per directory; if both are
      # present, validate both so the misconfiguration surfaces here
      # instead of at issue-creation time where the fallback is silent.
      configs+=("$f")
      ;;
    *)
      forms+=("$f")
      ;;
  esac
done

# Same "at least one form" rule as the dir existence check above:
# an empty template dir (all forms deleted) would pass the dir check
# but still defeat `blank_issues_enabled: false`. Require at least
# one non-config file.
if (( ${#forms[@]} == 0 )); then
  echo "ERROR: no issue-form YAMLs found in $TEMPLATE_DIR." >&2
  echo "  At least one bug_report / feature_request form is required" >&2
  echo "  for the issue-priority flow; see config.yml's blank_issues_enabled." >&2
  exit 1
fi

check-jsonschema --builtin-schema vendor.github-issue-forms "${forms[@]}"

if (( ${#configs[@]} > 0 )); then
  check-jsonschema --builtin-schema vendor.github-issue-config "${configs[@]}"
fi
