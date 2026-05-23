#!/usr/bin/env bash
# check-asp-and-ac-id-lockstep.sh
# ----------------------------------------------------------------------------
# Fence two TF↔Go lockstep contracts whose runtime failure modes are
# silent until first knock:
#
#   1. aspId lockstep — the value the AC announces in its registry
#      entry (`var.ac_auth_service_id`), the value the DDB bridge
#      writes into the seed row's `auth_service_id` (same), and the
#      PluginID the server-side static plugin registers
#      (`staticplugins/agent.PluginID`) MUST all agree. A drift
#      produces `ErrAuthServiceProviderNotFound (52002)` on every
#      agent knock — the bridge's FilterExpression matches no rows
#      because the row's `auth_service_id` value disagrees with the
#      aspId the agent stamped. The Go side carries
#      `TestPluginID_IsAgent` as a literal-match anchor; nothing
#      else pins the TF side without this script.
#
#   2. ac_id lockstep — the AC module's `var.ac_id` default (= what
#      the AC announces in its registry entry) MUST agree with
#      `var.qurl_default_ac_id` in every env that consumes it. The
#      DDB bridge writes `var.qurl_default_ac_id` into the seed
#      row's `ac_id` field; the server uses that value at knock-time
#      to look up the live AC connection. Drift → every knock returns
#      `ErrACConnectionNotFound`. The TF `validation {}` regex on
#      `qurl_default_ac_id` only fences shape, not cross-module
#      equality.
#
# Both contracts surfaced as #1976 cutover follow-ups (PR #2141);
# filed as #2142 / #2143 and folded back into the cutover PR so the
# lockstep ships with the rename.
#
# Detection: string-based grep+sed extractors over the targeted files
# (TF + Go). Parser-based would need an HCL parser AND a Go AST
# parser; the values here are simple `"..."` literals on
# greppable single-line patterns, so the parser overhead has no
# benefit. The fixture-test alongside (`tests/scripts/
# check-asp-and-ac-id-lockstep_test.sh`) covers the extractor
# regressions.
#
# Usage:
#   ./scripts/check-asp-and-ac-id-lockstep.sh
#     → exit 0 on lockstep, 1 on drift (with a diagnostic message)
# ============================================================================

set -euo pipefail

# Resolve repo root relative to this script so the check runs the same
# under `bash scripts/...` and `cd scripts && bash check-...sh`.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --list-sources mode: emit one source path per line, then exit. Used
# by the workflow-trigger-coverage fence below and by any caller that
# wants to assert paths-filter coverage against this lint's read set
# without re-parsing the script. Keep this list as the single source
# of truth — every entry added to `aspid_sources` / `ac_id_envs`
# below MUST also appear here so the trigger-coverage fence catches
# drift between "what the lint reads" and "what re-triggers the
# workflow on edit."
if [ "${1:-}" = "--list-sources" ]; then
  cat <<EOF
endpoints/server/staticplugins/agent/plugin.go
endpoints/server/resource_lookup.go
terraform/variables.tf
terraform/resources.tf
terraform/modules/ac/variables.tf
terraform/environments/sandbox/variables.tf
terraform/environments/prod/variables.tf
terraform/environments/sandbox/terraform.tfvars
terraform/environments/prod/terraform.tfvars
EOF
  exit 0
fi

# Each function below extracts a single string value from a single
# file. Empty stdout means "key not found" (the caller emptiness-
# checks). All extractors emit on stdout only; diagnostic chatter
# goes to stderr.
#
# `head -1` everywhere defends against a future regression that
# accidentally duplicates a key (e.g. copy-paste). The downstream
# equality check still catches drift; `head -1` keeps the extractor
# itself deterministic.

# Pull a Go `const NAME = "VALUE"` literal from a .go source file.
# Matches BOTH the bare top-level form (`const NAME = "..."`) and the
# parenthesized const-group form (`\tNAME = "..."` inside `const (...)`).
# Greedy-anchored on the constant name to avoid matching `// NAME`
# comments or `var NAME = "..."`.
extract_go_const() {
  local file="$1" name="$2"
  # Try bare-const form first (`const NAME = "..."` at start of line).
  local v
  v=$(grep -oE "^const ${name} = \"[^\"]+\"" "$file" 2>/dev/null \
    | head -1 \
    | sed -E "s/^const ${name} = \"([^\"]+)\"/\1/")
  if [ -n "${v:-}" ]; then
    printf '%s\n' "$v"
    return 0
  fi
  # Fall back to const-group form (`\tNAME = "..."` indented inside
  # a `const (...)` block). Whitespace-leading, no `const` prefix.
  grep -oE "^[[:space:]]+${name} = \"[^\"]+\"" "$file" 2>/dev/null \
    | head -1 \
    | sed -E "s/^[[:space:]]+${name} = \"([^\"]+)\"/\1/"
}

# Pull a `name = "VALUE"` assignment from a `locals { ... }` block.
# Same depth-tracking shape as extract_variable_default; matches at
# depth==1 (i.e. directly inside the locals body, not nested in any
# sub-block). The locals block can appear multiple times in a .tf
# file, so we scan all of them and return the first matching key.
extract_locals_value() {
  local file="$1" name="$2"
  awk -v name="$name" '
    /^locals[[:space:]]*\{/ { inblock = 1; depth = 1; next }
    inblock {
      n = gsub(/\{/, "{")
      m = gsub(/\}/, "}")
      depth += n - m
      if (depth == 1 && match($0, "^[[:space:]]*" name "[[:space:]]*=[[:space:]]*\"[^\"]*\"")) {
        s = substr($0, RSTART, RLENGTH)
        sub("^[[:space:]]*" name "[[:space:]]*=[[:space:]]*\"", "", s)
        sub(/"$/, "", s)
        print s
        exit
      }
      if (depth <= 0) { inblock = 0 }
    }
  ' "$file" 2>/dev/null
}

# Pull a top-level tfvars value (`name = "VALUE"`, not nested in any
# block). Anchor to start-of-line so a `default = "..."` inside a
# nested `variable {}` block doesn't match.
extract_tfvars_value() {
  local file="$1" name="$2"
  grep -oE "^${name}[[:space:]]*=[[:space:]]*\"[^\"]+\"" "$file" 2>/dev/null \
    | head -1 \
    | sed -E "s/^${name}[[:space:]]*=[[:space:]]*\"([^\"]+)\"/\1/"
}

# Pull a `default = "VALUE"` from the `variable "NAME" { ... }`
# block in a .tf file. Uses awk to scope the search to the matching
# variable block — a bare `grep "default"` would false-match against
# another variable's default a few lines below the target.
extract_variable_default() {
  local file="$1" name="$2"
  awk -v name="$name" '
    $0 ~ "^variable[[:space:]]+\"" name "\"[[:space:]]*\\{" { inblock = 1; depth = 1; next }
    inblock {
      # Track brace depth so we only match defaults at depth == 1
      # (i.e., directly inside this variable body, NOT inside a
      # nested block like validation{}). Counting BEFORE the match
      # gives depth-of-this-line; opening { on the current line
      # already counted as a nested block so a default on the SAME
      # line as a `validation {` opener would be depth==2 and
      # correctly skipped.
      n = gsub(/\{/, "{")
      m = gsub(/\}/, "}")
      depth += n - m
      if (depth == 1 && match($0, /^[[:space:]]*default[[:space:]]*=[[:space:]]*"[^"]*"/)) {
        s = substr($0, RSTART, RLENGTH)
        sub(/^[[:space:]]*default[[:space:]]*=[[:space:]]*"/, "", s)
        sub(/"$/, "", s)
        print s
        exit
      }
      if (depth <= 0) { exit }
    }
  ' "$file" 2>/dev/null
}

# -----------------------------------------------------------------------------
# Contract 1: aspId — staticplugins/agent.PluginID == every TF surface
#                     setting `ac_auth_service_id`.
# -----------------------------------------------------------------------------

# Source of truth on the Go side: the plugin's registered identifier.
PLUGIN_GO="${REPO_ROOT}/endpoints/server/staticplugins/agent/plugin.go"
go_plugin_id=$(extract_go_const "$PLUGIN_GO" PluginID || true)
if [ -z "${go_plugin_id:-}" ]; then
  echo "ERROR: could not extract \`const PluginID = \"...\"\` from $PLUGIN_GO" >&2
  echo "       Either the file moved, the constant renamed, or the extractor regressed." >&2
  exit 1
fi

# Each entry: "<label-for-diagnostics>|<file>|<extractor>|<var-name>"
# Order matters only for output stability — the equality check is
# pairwise against go_plugin_id.
aspid_sources=(
  "terraform/variables.tf::var.ac_auth_service_id|terraform/variables.tf|extract_variable_default|ac_auth_service_id"
  "terraform/modules/ac/variables.tf::var.auth_service_id|terraform/modules/ac/variables.tf|extract_variable_default|auth_service_id"
  "terraform/environments/sandbox/variables.tf::var.ac_auth_service_id|terraform/environments/sandbox/variables.tf|extract_variable_default|ac_auth_service_id"
  "terraform/environments/prod/variables.tf::var.ac_auth_service_id|terraform/environments/prod/variables.tf|extract_variable_default|ac_auth_service_id"
  "terraform/environments/sandbox/terraform.tfvars::ac_auth_service_id|terraform/environments/sandbox/terraform.tfvars|extract_tfvars_value|ac_auth_service_id"
  "terraform/environments/prod/terraform.tfvars::ac_auth_service_id|terraform/environments/prod/terraform.tfvars|extract_tfvars_value|ac_auth_service_id"
)

aspid_drift=0
for entry in "${aspid_sources[@]}"; do
  IFS='|' read -r label rel_path extractor var_name <<<"$entry"
  abs_path="${REPO_ROOT}/${rel_path}"
  if [ ! -f "$abs_path" ]; then
    echo "ERROR: aspId-lockstep source missing: $rel_path" >&2
    echo "       Either the file moved or the lint's source list is stale." >&2
    aspid_drift=1
    continue
  fi
  value=$("$extractor" "$abs_path" "$var_name" || true)
  if [ -z "${value:-}" ]; then
    echo "ERROR: aspId-lockstep extractor returned empty for $label" >&2
    echo "       File exists but the value at \`$var_name\` couldn't be found — extractor regression or variable removed." >&2
    aspid_drift=1
    continue
  fi
  if [ "$value" != "$go_plugin_id" ]; then
    echo "DRIFT (aspId): $label = \"$value\" but staticplugins/agent.PluginID = \"$go_plugin_id\"" >&2
    aspid_drift=1
  fi
done

if [ "$aspid_drift" -ne 0 ]; then
  cat >&2 <<EOF

aspId lockstep FAILED. The Go-side static plugin (staticplugins/agent)
registers under PluginID="$go_plugin_id"; every TF surface that sets
\`ac_auth_service_id\` (or its AC-module alias \`auth_service_id\`) must
match. A drift here produces ErrAuthServiceProviderNotFound (52002) on
every agent knock — the bridge's FilterExpression matches no rows.

To fix: update either side so all values agree. Then re-run this
script locally to confirm.
EOF
fi

# -----------------------------------------------------------------------------
# Contract 2: ac_id — terraform/modules/ac/variables.tf::var.ac_id default
#                     (= what the AC announces) == var.qurl_default_ac_id
#                     in every env whose tfvars sets it.
# -----------------------------------------------------------------------------

AC_VARS_TF="${REPO_ROOT}/terraform/modules/ac/variables.tf"
if [ ! -f "$AC_VARS_TF" ]; then
  echo "ERROR: ac_id-lockstep source missing: terraform/modules/ac/variables.tf" >&2
  exit 1
fi
ac_module_id=$(extract_variable_default "$AC_VARS_TF" ac_id || true)
if [ -z "${ac_module_id:-}" ]; then
  echo "ERROR: could not extract \`var.ac_id\` default from $AC_VARS_TF" >&2
  echo "       Either the variable was renamed or its default became dynamic (no literal)." >&2
  exit 1
fi

# Each entry: "<label>|<tfvars-relative-path>"
# An env that doesn't set `qurl_default_ac_id` (e.g. because
# `deploy_frps = false`) passes silently — the empty-extractor case
# below skips the check rather than failing.
ac_id_envs=(
  "terraform/environments/sandbox/terraform.tfvars|terraform/environments/sandbox/terraform.tfvars"
  "terraform/environments/prod/terraform.tfvars|terraform/environments/prod/terraform.tfvars"
)

ac_id_drift=0
for entry in "${ac_id_envs[@]}"; do
  IFS='|' read -r label rel_path <<<"$entry"
  abs_path="${REPO_ROOT}/${rel_path}"
  if [ ! -f "$abs_path" ]; then
    # Env tfvars genuinely missing is a different kind of regression
    # (probably an env was added without all the standard files);
    # treat as a hard error so the lint surfaces it rather than
    # silently passing because the file didn't exist.
    echo "ERROR: ac_id-lockstep source missing: $rel_path" >&2
    ac_id_drift=1
    continue
  fi
  value=$(extract_tfvars_value "$abs_path" qurl_default_ac_id || true)
  if [ -z "${value:-}" ]; then
    # Env didn't set qurl_default_ac_id — valid for envs without
    # `deploy_frps = true`. Skip rather than fail.
    continue
  fi
  if [ "$value" != "$ac_module_id" ]; then
    echo "DRIFT (ac_id): $label::qurl_default_ac_id = \"$value\" but terraform/modules/ac/variables.tf::var.ac_id default = \"$ac_module_id\"" >&2
    ac_id_drift=1
  fi
done

if [ "$ac_id_drift" -ne 0 ]; then
  cat >&2 <<EOF

ac_id lockstep FAILED. The AC module's \`var.ac_id\` default
("$ac_module_id") is the identifier the deployed AC announces in its
registry entry; the server keys live AC connections by this value at
knock time. The DDB bridge writes \`var.qurl_default_ac_id\` into the
seed row's \`ac_id\` field, which becomes \`ResourceInfo.ACId\` and is
used for the same lookup. A drift here produces ErrACConnectionNotFound
on every agent knock — the server thinks the resource's AC isn't
connected.

To fix: align the env tfvars' \`qurl_default_ac_id\` with the AC
module's \`var.ac_id\` default, or update the AC module default if
the deployed ID legitimately changed. Then re-run this script.
EOF
fi

# -----------------------------------------------------------------------------
# Contract 3: nhpSystemCustomerID — Go-side const must agree with TF-side
#                                   local for the partition the bridge reads
#                                   and the seed-row writes both target.
# -----------------------------------------------------------------------------

LOOKUP_GO="${REPO_ROOT}/endpoints/server/resource_lookup.go"
RESOURCES_TF="${REPO_ROOT}/terraform/resources.tf"
customer_id_drift=0
if [ ! -f "$LOOKUP_GO" ]; then
  echo "ERROR: customer-id-lockstep source missing: endpoints/server/resource_lookup.go" >&2
  customer_id_drift=1
elif [ ! -f "$RESOURCES_TF" ]; then
  echo "ERROR: customer-id-lockstep source missing: terraform/resources.tf" >&2
  customer_id_drift=1
else
  go_customer_id=$(extract_go_const "$LOOKUP_GO" nhpSystemCustomerID || true)
  tf_customer_id=$(extract_locals_value "$RESOURCES_TF" nhp_system_customer_id || true)
  if [ -z "${go_customer_id:-}" ]; then
    echo "ERROR: could not extract \`nhpSystemCustomerID = \"...\"\` from $LOOKUP_GO" >&2
    echo "       Either the const was renamed, moved, or the extractor regressed." >&2
    customer_id_drift=1
  elif [ -z "${tf_customer_id:-}" ]; then
    echo "ERROR: could not extract \`nhp_system_customer_id = \"...\"\` from $RESOURCES_TF" >&2
    echo "       Either the local was renamed, moved out of the locals{} block, or the extractor regressed." >&2
    customer_id_drift=1
  elif [ "$go_customer_id" != "$tf_customer_id" ]; then
    echo "DRIFT (nhp_system_customer_id): terraform/resources.tf::local.nhp_system_customer_id = \"$tf_customer_id\" but endpoints/server/resource_lookup.go::nhpSystemCustomerID = \"$go_customer_id\"" >&2
    customer_id_drift=1
  fi
fi

if [ "$customer_id_drift" -ne 0 ]; then
  cat >&2 <<EOF

nhp_system_customer_id lockstep FAILED. The Go-side bridge queries DDB
under the partition key from \`nhpSystemCustomerID\` (resource_lookup.go);
the TF seed-row writer puts the row under \`local.nhp_system_customer_id\`
(resources.tf). A drift means the writer puts the row in one partition
and the reader queries another — the resolver returns
ErrResourceUnknownASP on every knock (empty partition, no rows match
the FilterExpression).

To fix: align both values. Then re-run this script.
EOF
fi

if [ "$aspid_drift" -ne 0 ] || [ "$ac_id_drift" -ne 0 ] || [ "$customer_id_drift" -ne 0 ]; then
  exit 1
fi

echo "asp+ac_id+customer_id lockstep OK: PluginID=\"$go_plugin_id\", ac_id=\"$ac_module_id\", customer_id=\"$go_customer_id\""
