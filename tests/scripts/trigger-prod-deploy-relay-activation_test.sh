#!/usr/bin/env bash
# trigger-prod-deploy-relay-activation_test.sh — fixture tests for the relay
# activation branch of scripts/trigger-prod-deploy.sh
# ----------------------------------------------------------------------------
# WHY THIS EXISTS
#
# The relay's prod SSM tag does not exist until the activation apply creates
# it. Deciding from the live parameter alone therefore cannot distinguish:
#
#   deploy_relay = false in prod tfvars -> relay genuinely dark, skip is right
#   deploy_relay = true  in prod tfvars -> THIS promote's terraform-apply
#                                          creates the parameter and
#                                          deploy-relay runs after it
#
# The script used to print `[SKIP] relay is dark in prod` for both, so the
# command it hands the operator carried `-f deploy_relay=false` on the very
# release that activates the relay. Copy-pasting it would have created the
# parameter and never advanced it — shipping the activation release with the
# relay dark, silently, with a green promote.
#
# The whole script cannot run offline (it reads SSM, ECR and STS), so this
# extracts the decision block verbatim from the real file and drives it with
# controlled inputs. Extraction is self-tested below: if the block is renamed
# or restructured so the markers stop matching, the canary fails loudly rather
# than the suite passing on zero assertions.
#
# Usage: bash tests/scripts/trigger-prod-deploy-relay-activation_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/trigger-prod-deploy.sh"

FAILURES=0
pass() { echo "  ok   — $1"; }
fail() { echo "  FAIL — $1"; FAILURES=$((FAILURES + 1)); }

# Pull the relay decision out of the real script: from the tfvars read through
# the end of the if/elif chain that sets deploy_relay.
extract_block() {
    # Two `fi`s live in this region: one closes the tfvars read, one closes the
    # relay if/elif chain. Only stop at the second -- i.e. after the relay
    # branch itself has been seen.
    awk '
        /^[[:space:]]*prod_tfvars="\$SCRIPT_DIR/ { capture = 1 }
        capture { print }
        capture && /SANDBOX_RELAY_TAG.*PROD_RELAY_TAG/ { in_relay = 1 }
        capture && in_relay && /^    fi[[:space:]]*$/ { exit }
    ' "$SCRIPT"
}

# --- canary: the extraction must actually find the block -------------------
BLOCK=$(extract_block)
if [[ -z "$BLOCK" ]]; then
    fail "CANARY: extracted an empty relay block — markers no longer match the script"
elif ! grep -q 'terraform.tfvars' <<<"$BLOCK"; then
    fail "CANARY: extracted block does not read terraform.tfvars — wrong block or the tfvars check was removed"
elif ! grep -q 'deploy_relay=true' <<<"$BLOCK"; then
    fail "CANARY: extracted block never sets deploy_relay=true — the activation path is gone"
else
    pass "CANARY: extracted the relay decision block from the real script"
fi

# Run the extracted block against a fixture tfvars.
#   $1 = the deploy_relay line to write into terraform.tfvars ("" = omit file)
# Echoes "<deploy_relay>|<RELAY_REASON>".
run_case() {
    local tfvars_line="$1"
    local tmp
    tmp=$(mktemp -d)
    mkdir -p "$tmp/scripts" "$tmp/terraform/environments/prod"
    if [[ -n "$tfvars_line" ]]; then
        printf '%s\n' "$tfvars_line" >"$tmp/terraform/environments/prod/terraform.tfvars"
    fi
    {
        echo 'SCRIPT_DIR="'"$tmp"'/scripts"'
        echo 'SANDBOX_RELAY_TAG="abc123"'
        echo 'PROD_RELAY_TAG="(not set)"'
        echo 'deploy_relay=false'
        echo 'RELAY_REASON=""'
        printf '%s\n' "$BLOCK"
        # shellcheck disable=SC2016  # deliberate: these expand in the generated
        # script, which is where the extracted block has actually run.
        printf '%s\n' 'printf "%s|%s\\n" "$deploy_relay" "$RELAY_REASON"'
    } >"$tmp/run.sh"
    bash "$tmp/run.sh" 2>/dev/null
    rm -rf "$tmp"
}

# --- the regression this file exists for -----------------------------------
result=$(run_case 'deploy_relay                = true')
if [[ "${result%%|*}" == "true" ]]; then
    pass "tfvars deploy_relay=true + unset prod tag -> deploy_relay=true (activation ships the relay)"
else
    fail "tfvars deploy_relay=true + unset prod tag -> got '${result%%|*}', want 'true'. The activation release would ship with the relay dark."
fi

# --- the case the original skip was written for, which must still skip -----
result=$(run_case 'deploy_relay                = false')
if [[ "${result%%|*}" == "false" ]] && grep -q 'SKIP' <<<"${result#*|}"; then
    pass "tfvars deploy_relay=false + unset prod tag -> skip (relay genuinely dark)"
else
    fail "tfvars deploy_relay=false -> got '$result', want deploy_relay=false and a SKIP reason"
fi

# --- unresolvable must not silently pick a side ----------------------------
result=$(run_case '')
if [[ "${result%%|*}" == "false" ]] && grep -qE 'not resolvable|explicitly' <<<"${result#*|}"; then
    pass "tfvars unreadable -> skips AND says to set -f deploy_relay explicitly"
else
    fail "tfvars unreadable -> got '$result', want a skip that tells the operator to decide"
fi

# ===========================================================================
# The run_terraform coupling guard
# ---------------------------------------------------------------------------
# The activation is only coherent WITH terraform: the parameter and the relay
# ASG do not exist until terraform-apply creates them, and deploy-relay fires
# an instance refresh against that ASG. run_terraform comes from independent
# change detection, so nothing else couples them -- emitting
# deploy_relay=true with run_terraform=false would refresh an ASG Terraform
# never created. Reachable in practice: a prior promote can advance
# deployed-commit past the activating commit while its terraform-apply failed,
# and prod state 'failed' only warns.
# ===========================================================================

extract_force_block() {
    awk '
        /^if \[\[ "\$RELAY_FIRST_ACTIVATION" == "true"/ { capture = 1 }
        capture { print }
        capture && /^fi[[:space:]]*$/ { exit }
    ' "$SCRIPT"
}

FORCE_BLOCK=$(extract_force_block)
if [[ -z "$FORCE_BLOCK" ]]; then
    fail "CANARY: extracted an empty run_terraform force block — the coupling guard is gone or was renamed"
elif ! grep -q 'run_terraform=true' <<<"$FORCE_BLOCK"; then
    fail "CANARY: force block never sets run_terraform=true"
else
    pass "CANARY: extracted the run_terraform coupling guard from the real script"
fi

#   $1 = RELAY_FIRST_ACTIVATION, $2 = starting run_terraform. Echoes run_terraform.
run_force_case() {
    local tmp
    tmp=$(mktemp -d)
    {
        echo "RELAY_FIRST_ACTIVATION=$1"
        echo "run_terraform=$2"
        echo 'TF_REASON=""'
        echo 'WARNINGS=()'
        echo 'warn() { :; }'
        printf '%s\n' "$FORCE_BLOCK"
        # shellcheck disable=SC2016  # expands in the generated script, not here
        printf '%s\n' 'printf "%s\\n" "$run_terraform"'
    } >"$tmp/force.sh"
    bash "$tmp/force.sh" 2>/dev/null
    rm -rf "$tmp"
}

if [[ "$(run_force_case true false)" == "true" ]]; then
    pass "first activation + run_terraform=false -> forced true (deploy-relay cannot refresh an ASG terraform never created)"
else
    fail "first activation + run_terraform=false -> got '$(run_force_case true false)', want 'true'"
fi

if [[ "$(run_force_case false false)" == "false" ]]; then
    pass "no activation -> run_terraform left alone (the guard does not widen unrelated promotes)"
else
    fail "no activation -> got '$(run_force_case false false)', want 'false'"
fi

echo
if [[ $FAILURES -gt 0 ]]; then
    echo "FAILED: $FAILURES assertion(s)"
    exit 1
fi
echo "All relay-activation assertions passed."
