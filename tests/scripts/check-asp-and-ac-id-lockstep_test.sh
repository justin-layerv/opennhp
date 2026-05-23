#!/usr/bin/env bash
# check-asp-and-ac-id-lockstep_test.sh — fixture tests for
# scripts/check-asp-and-ac-id-lockstep.sh
# ----------------------------------------------------------------------------
# Build fake repo layouts in tempdirs that mimic the real file
# structure, invoke the script against each, and assert exit code +
# output substring. Catches regressions in the extractors and in the
# pairwise equality logic the next time the real files get
# reformatted (HCL `default = "..."` style change, tfvars assignment
# layout, etc.).
#
# The script under test resolves repo root via
# `dirname "${BASH_SOURCE[0]}"/..`, so each fixture dir must contain
# a `scripts/check-asp-and-ac-id-lockstep.sh` that points back at
# the real script (symlinked) plus the seven files the real script
# reads.
#
# Usage: bash tests/scripts/check-asp-and-ac-id-lockstep_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-asp-and-ac-id-lockstep.sh"

pass=0
fail=0

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# Build a fake repo at $dir with the seven files the lint reads.
# Each arg is the literal value to put at the corresponding site;
# pass "" for a value to omit that line (used by tests that need
# to simulate a missing-key extractor case).
_make_fixture() {
  local dir="$1"
  local plugin_id="$2"
  local root_var_default="$3"
  local ac_module_var_default="$4"
  local sandbox_env_var_default="$5"
  local prod_env_var_default="$6"
  local sandbox_tfvars_value="$7"
  local prod_tfvars_value="$8"
  local ac_module_ac_id_default="$9"
  local sandbox_qurl_default_ac_id="${10}"
  local prod_qurl_default_ac_id="${11}"
  # Optional 12th/13th args for the customer-id contract; default
  # to matching values so legacy 11-arg callers continue to pass.
  local go_customer_id="${12:-00000000000000000000000000}"
  local tf_customer_id="${13:-00000000000000000000000000}"

  mkdir -p \
    "$dir/scripts" \
    "$dir/endpoints/server/staticplugins/agent" \
    "$dir/terraform/environments/sandbox" \
    "$dir/terraform/environments/prod" \
    "$dir/terraform/modules/ac"
  ln -sf "$SCRIPT" "$dir/scripts/check-asp-and-ac-id-lockstep.sh"

  cat > "$dir/endpoints/server/staticplugins/agent/plugin.go" <<EOF
package agent
const PluginID = "$plugin_id"
EOF

  # Go-side resource_lookup.go fixture — needs to carry the
  # nhpSystemCustomerID const. The script's extract_go_const matches
  # both bare-const and const-group forms; we use the const-group
  # form (`const ( ... )`) here because that's the shape the real
  # file uses, so this exercises the harder match path.
  cat > "$dir/endpoints/server/resource_lookup.go" <<EOF
package server
const (
	nhpSystemCustomerID = "$go_customer_id"
)
EOF

  cat > "$dir/terraform/variables.tf" <<EOF
variable "ac_auth_service_id" {
  type    = string
  default = "$root_var_default"
}
EOF

  # TF resources.tf fixture — needs to carry the matching local. The
  # script extracts via extract_locals_value scanning the locals
  # block for the named key.
  cat > "$dir/terraform/resources.tf" <<EOF
locals {
  nhp_system_customer_id = "$tf_customer_id"
}
EOF

  cat > "$dir/terraform/modules/ac/variables.tf" <<EOF
variable "auth_service_id" {
  type    = string
  default = "$ac_module_var_default"
}

variable "ac_id" {
  type    = string
  default = "$ac_module_ac_id_default"
}
EOF

  cat > "$dir/terraform/environments/sandbox/variables.tf" <<EOF
variable "ac_auth_service_id" {
  type    = string
  default = "$sandbox_env_var_default"
}
EOF

  cat > "$dir/terraform/environments/prod/variables.tf" <<EOF
variable "ac_auth_service_id" {
  type    = string
  default = "$prod_env_var_default"
}
EOF

  {
    [ -n "$sandbox_tfvars_value" ] && echo "ac_auth_service_id = \"$sandbox_tfvars_value\""
    [ -n "$sandbox_qurl_default_ac_id" ] && echo "qurl_default_ac_id = \"$sandbox_qurl_default_ac_id\""
  } > "$dir/terraform/environments/sandbox/terraform.tfvars"

  {
    [ -n "$prod_tfvars_value" ] && echo "ac_auth_service_id = \"$prod_tfvars_value\""
    [ -n "$prod_qurl_default_ac_id" ] && echo "qurl_default_ac_id = \"$prod_qurl_default_ac_id\""
  } > "$dir/terraform/environments/prod/terraform.tfvars"
}

# Assert script exits 0 against a fixture where every value agrees.
test_all_in_sync() {
  local name="all-in-sync"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    if [[ "$out" == *"lockstep OK"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "exit 0 but output missing 'lockstep OK': $out"
    fi
  else
    report_fail "$name" "expected exit 0, got non-zero. Output:\n$out"
  fi
}

# Assert script fails when one of the aspId TF surfaces drifts.
test_aspid_tfvars_drift_fails() {
  local name="aspid-tfvars-drift-fails"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "layerv" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0. Output:\n$out"
  else
    if [[ "$out" == *"DRIFT (aspId)"* ]] && [[ "$out" == *"sandbox/terraform.tfvars"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "expected aspId DRIFT message naming sandbox tfvars, got:\n$out"
    fi
  fi
}

# Assert script fails when the Go PluginID drifts from TF.
test_go_pluginid_drift_fails() {
  local name="go-pluginid-drift-fails"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "layerv" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0. Output:\n$out"
  else
    # When Go side says "layerv" and TF says "agent", every TF surface
    # mismatches. Just check the contract name is in the output.
    if [[ "$out" == *"DRIFT (aspId)"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "expected aspId DRIFT, got:\n$out"
    fi
  fi
}

# Assert script fails when sandbox's qurl_default_ac_id disagrees
# with the AC module's var.ac_id default.
test_ac_id_drift_fails() {
  local name="ac-id-drift-fails"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-old" "layerv-ac-tf"

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0. Output:\n$out"
  else
    if [[ "$out" == *"DRIFT (ac_id)"* ]] && [[ "$out" == *"layerv-ac-old"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "expected ac_id DRIFT message naming layerv-ac-old, got:\n$out"
    fi
  fi
}

# Assert script PASSES when an env legitimately doesn't set
# qurl_default_ac_id (deploy_frps = false in that env). Empty
# value should skip the check rather than fail.
test_unset_qurl_default_ac_id_skips() {
  local name="unset-qurl-default-ac-id-skips"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" ""

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    if [[ "$out" == *"lockstep OK"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "exit 0 but output missing 'lockstep OK': $out"
    fi
  else
    report_fail "$name" "expected exit 0 (unset env qurl_default_ac_id is valid); got non-zero. Output:\n$out"
  fi
}

# Assert script fails loud when the Go file is missing the PluginID
# constant entirely — guards against an extractor that returns empty
# being silently treated as "matches everything."
test_missing_pluginid_constant_fails_loud() {
  local name="missing-pluginid-fails-loud"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  # Overwrite plugin.go with a file that has no `const PluginID`.
  cat > "$tmp/endpoints/server/staticplugins/agent/plugin.go" <<EOF
package agent
// PluginID was renamed; extractor must surface this as a hard error.
var pluginIDRenamed = "agent"
EOF

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit (missing PluginID), got 0. Output:\n$out"
  else
    if [[ "$out" == *"could not extract"* ]] && [[ "$out" == *"PluginID"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "expected 'could not extract … PluginID' diagnostic, got:\n$out"
    fi
  fi
}

# Assert the extractor doesn't false-match a nested `default = "..."`
# inside a validation block of a different variable.
test_nested_validation_default_does_not_false_match() {
  local name="nested-validation-default-no-false-match"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  # Replace root variables.tf with a version where another variable's
  # validation message contains a literal `default = "stale"` token —
  # the extractor must NOT pick that up as ac_auth_service_id's default.
  cat > "$tmp/terraform/variables.tf" <<'EOF'
variable "other_var" {
  type = string
  validation {
    condition     = length(var.other_var) > 0
    error_message = "If unset the default = \"stale\" is used."
  }
}

variable "ac_auth_service_id" {
  type    = string
  default = "agent"
}
EOF

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    if [[ "$out" == *"lockstep OK"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "exit 0 but output missing 'lockstep OK': $out"
    fi
  else
    report_fail "$name" "expected exit 0 (the 'default = stale' token is inside another variable's validation block, not the target); got non-zero. Output:\n$out"
  fi
}

# Assert the awk depth guard refuses to false-match an actual nested
# `default = "<wrong>"` line inside the TARGET variable's validation
# block — the scenario the depth-check defends against. Today HCL only
# permits `condition` and `error_message` inside validation{}, so a
# real nested `default =` is non-grammatical, but the depth guard is
# the only fence between this lint and a future HCL grammar
# extension OR a stub file produced by a tool that doesn't validate
# the schema. Without the `depth == 1` guard, this fixture would print
# "WRONG" and the equality check below would fire DRIFT.
test_nested_default_inside_target_var_validation_skipped() {
  local name="nested-default-inside-target-var-skipped"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf"

  # Replace root variables.tf with a synthetic variable that has BOTH
  # a nested `default = "WRONG"` (illegal HCL today, but the lint
  # must defend against it) AND a legitimate top-level
  # `default = "agent"`. Extractor must skip the nested line and
  # return "agent".
  cat > "$tmp/terraform/variables.tf" <<'EOF'
variable "ac_auth_service_id" {
  type = string
  validation {
    default = "WRONG"
  }
  default = "agent"
}
EOF

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    if [[ "$out" == *"lockstep OK"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "exit 0 but output missing 'lockstep OK': $out"
    fi
  else
    report_fail "$name" "expected exit 0 (nested 'default = WRONG' inside validation{} must be skipped by depth guard, legitimate 'default = agent' must win); got non-zero. Output:\n$out"
  fi
}

echo "Running check-asp-and-ac-id-lockstep.sh fixture tests..."
test_all_in_sync
test_aspid_tfvars_drift_fails
test_go_pluginid_drift_fails
test_ac_id_drift_fails
test_unset_qurl_default_ac_id_skips
test_missing_pluginid_constant_fails_loud
test_nested_validation_default_does_not_false_match
test_nested_default_inside_target_var_validation_skipped

# Workflow trigger coverage: every path the lint reads must be covered
# by the trigger paths in validate-workflows.yml, otherwise an edit to
# (e.g.) terraform/modules/ac/variables.tf wouldn't re-fire the lint.
# Runs against the REAL repo tree (not a fixture); fences the static-
# paths-vs-script-source-list drift the cr review surfaced. Covered by
# wildcards in the trigger list count — checking literal match OR
# wildcard match is sufficient for this lint's source list (no
# inotify-style negative patterns to deal with).
test_workflow_trigger_paths_cover_lint_sources() {
  local name="workflow-trigger-paths-cover-lint-sources"
  local workflow="$REPO_ROOT/.github/workflows/validate-workflows.yml"
  if [ ! -f "$workflow" ]; then
    report_fail "$name" "workflow missing: $workflow"
    return
  fi

  local missing=""
  local src
  while IFS= read -r src; do
    [ -z "$src" ] && continue
    # An entry is covered if the workflow has a literal path entry
    # equal to it, OR any wildcard entry whose `**`-stripped prefix
    # is a directory prefix of the source. Cheap matcher: check
    # literal first, then wildcard prefixes.
    if grep -qE "^[[:space:]]*-[[:space:]]+\"${src}\"" "$workflow"; then
      continue
    fi
    # Wildcard match: strip the trailing `**` from each wildcard
    # entry, see if any is a prefix of the source. Bash 3.2-safe.
    local covered=0
    local pattern
    while IFS= read -r pattern; do
      # Strip leading dash+whitespace + quotes from the YAML line.
      pattern=$(printf '%s' "$pattern" | sed -E 's/^[[:space:]]*-[[:space:]]+"//;s/"$//')
      # Only wildcard patterns are relevant for this branch.
      case "$pattern" in
        *'**')
          local prefix="${pattern%/**}"
          if [[ "$src" == "$prefix"/* ]] || [[ "$src" == "$prefix" ]]; then
            covered=1; break
          fi
          ;;
      esac
    done < <(grep -E '^[[:space:]]*-[[:space:]]+".*\*\*"' "$workflow")
    if [ "$covered" -ne 1 ]; then
      missing+="$src\n"
    fi
  done < <(bash "$SCRIPT" --list-sources)

  if [ -z "$missing" ]; then
    report_pass "$name"
  else
    report_fail "$name" "workflow trigger paths missing coverage for these lint sources:\n$missing → add literal entries or covering wildcards to .github/workflows/validate-workflows.yml so an edit to these files re-fires the lockstep lint"
  fi
}

test_workflow_trigger_paths_cover_lint_sources

# Assert the customer-id contract fires when Go and TF disagree.
test_customer_id_drift_fails() {
  local name="customer-id-drift-fails"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  _make_fixture "$tmp" \
    "agent" "agent" "agent" "agent" "agent" "agent" "agent" \
    "layerv-ac-tf" "layerv-ac-tf" "layerv-ac-tf" \
    "00000000000000000000000000" "11111111111111111111111111"

  local out
  if out=$(bash "$tmp/scripts/check-asp-and-ac-id-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0. Output:\n$out"
  else
    if [[ "$out" == *"DRIFT (nhp_system_customer_id)"* ]] && [[ "$out" == *"11111"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "expected customer_id DRIFT message naming the mismatched 1...1 value, got:\n$out"
    fi
  fi
}

test_customer_id_drift_fails

echo
echo "Passed: $pass    Failed: $fail"
[ "$fail" -eq 0 ] || exit 1
