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
# LOCAL use only. CI runs the equivalent check via the
# `layervai/ops-routines-workflows/.github/workflows/validate-issue-templates.yml`
# reusable (shimmed from `.github/workflows/validate-issue-templates.yml`),
# which is the canonical fleet-wide source. This script exists solely so
# `make lint-workflows` gives fast local feedback without spinning up a
# GitHub Actions runner. Keep the two in behavioural lockstep; bump the
# reusable SHA in the shim when logic changes here, or vice versa.
#
# Drift guard: enforces the local `check-jsonschema` version matches the
# version pinned in the reusable (see `CHECK_JSONSCHEMA_VERSION` below).
# Bump both in lockstep with the reusable. Catches the common local↔CI
# tool-version drift that would otherwise mask a version-sensitive fail.
# Requires `check-jsonschema` on PATH.
# ============================================================================

set -euo pipefail

# Pinned to match the reusable's `check-jsonschema-version` default at
# layervai/ops-routines-workflows/.github/workflows/validate-issue-templates.yml.
# Bump BOTH in lockstep. Mismatch here means a version that passes locally
# could fail CI (or vice versa) — the drift class the shim was meant to
# eliminate. If you bump the reusable's default, bump this, update the
# SHA pin in `.github/workflows/validate-issue-templates.yml`, and confirm
# in that PR's test plan.
CHECK_JSONSCHEMA_VERSION="0.37.1"

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
  echo "  Install (local):  pipx install 'check-jsonschema==${CHECK_JSONSCHEMA_VERSION}'" >&2
  echo "  Install (CI):     see .github/workflows/validate-issue-templates.yml" >&2
  exit 1
fi

# Version drift guard — see header comment. `check-jsonschema --version`
# prints `check-jsonschema, version <x.y.z>` on stdout. Discard stderr
# so a pipx/pip deprecation warning (which interleaves ahead of the
# version line when `2>&1`-merged) can't corrupt $NF extraction. Pin
# to line 1 for belt-and-suspenders in case the tool ever emits a
# multi-line version block.
ACTUAL_VERSION="$(check-jsonschema --version 2>/dev/null | awk 'NR==1 {print $NF; exit}')"
if [[ "$ACTUAL_VERSION" != "$CHECK_JSONSCHEMA_VERSION" ]]; then
  echo "ERROR: check-jsonschema version mismatch." >&2
  echo "  Found:    $ACTUAL_VERSION" >&2
  echo "  Required: $CHECK_JSONSCHEMA_VERSION (matches the ops-routines reusable)" >&2
  echo "  Fix:      pipx install --force 'check-jsonschema==${CHECK_JSONSCHEMA_VERSION}'" >&2
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
