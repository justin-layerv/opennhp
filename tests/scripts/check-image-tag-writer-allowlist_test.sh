#!/usr/bin/env bash
# check-image-tag-writer-allowlist_test.sh — fixture tests for
# scripts/check-image-tag-writer-allowlist.py
# ----------------------------------------------------------------------------
# Build small tempdir repos that exercise the detector's
# literal-slot-path, variable-indirected, and edge-case shapes,
# invoke the script with --repo-root pointing at the fixture, and
# assert exit code. The final case scans the real repo, so this
# file is both the lint's unit test AND its enforcement against
# the actual tree (one invocation does both jobs — `Makefile`'s
# lint-workflows target and validate-workflows.yml's
# `Test + enforce image-tag writer allowlist` step rely on that).
#
# Usage: bash tests/scripts/check-image-tag-writer-allowlist_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-image-tag-writer-allowlist.py"

pass=0
fail=0
failures=""

report_pass() {
  pass=$((pass + 1))
  printf '  \033[32m✓\033[0m %s\n' "$1"
}
report_fail() {
  fail=$((fail + 1))
  failures+="  ✗ $1: $2\n"
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

_run_in_fixture() {
  python3 "$SCRIPT" --repo-root "$1"
}

# _assert_run <name> <expected: pass|fail> <dir>
# Runs the detector against <dir> and reports pass/fail. Shared by
# _assert_case (heredoc fixtures) and the open-coded tests that need
# custom setup (empty-repo, real-repo).
_assert_run() {
  local name="$1" expected="$2" dir="$3"
  if _run_in_fixture "$dir" >/dev/null 2>&1; then
    if [ "$expected" = "pass" ]; then
      report_pass "$name"
    else
      report_fail "$name" "detector exited 0, expected non-zero"
    fi
  else
    if [ "$expected" = "fail" ]; then
      report_pass "$name"
    else
      report_fail "$name" "detector exited non-zero, expected 0"
    fi
  fi
}

# _assert_case <name> <expected: pass|fail> <fixture-yaml-rel-path>
# Reads the fixture YAML body from stdin (heredoc), drops it at the
# given path inside a fresh tempdir, runs the detector, and asserts.
_assert_case() {
  local name="$1" expected="$2" rel="$3"
  local dir
  dir=$(mktemp -d)
  # Eager-expand $dir into the trap body (double-quote on the outside,
  # single-quote around the path). Bash 3.2 (macOS default) inherits
  # the RETURN trap into the calling function, so the trap fires a
  # second time when the caller returns. Lazy expansion would re-read
  # $dir at trap-fire time, by which point the local is gone and
  # `set -u` aborts. Eager expansion bakes the value in; the second
  # fire is a harmless rm of an already-removed path.
  # shellcheck disable=SC2064
  trap "rm -rf '$dir'" RETURN
  mkdir -p "$dir/$(dirname "$rel")"
  cat > "$dir/$rel"
  _assert_run "$name" "$expected" "$dir"
}

# Empty repo with the script's expected directory shape — must pass.
_test_empty_passes() {
  local dir
  dir=$(mktemp -d)
  # See the eager-expand comment in _assert_case.
  # shellcheck disable=SC2064
  trap "rm -rf '$dir'" RETURN
  mkdir -p "$dir/.github/workflows" "$dir/.github/scripts" "$dir/scripts"
  _assert_run "empty repo: exit 0" pass "$dir"
}

_test_literal_write_fails() {
  _assert_case "literal write outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          aws ssm put-parameter \
            --name "/sandbox/nhp/server/image-tag" \
            --value "abc123" --type String --overwrite
EOF
}

_test_variable_write_fails() {
  _assert_case "variable-indirected write outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SSM_PARAM="/sandbox/nhp/ac/green-image-tag"
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value "abc123" --type String --overwrite
EOF
}

# Mirrors the deleted shape from build-and-push.yml — slot segment was
# `${SSM_COMPONENT}`, not a literal. A regex restricted to (server|ac)
# would silently miss a re-introduction of the exact pattern this guard
# exists to prevent.
_test_templated_component_write_fails() {
  _assert_case "templated-component write outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SSM_PARAM="/${ENVIRONMENT}/nhp/${SSM_COMPONENT}/image-tag"
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value "$IMAGE_TAG" --type String --overwrite
EOF
}

_test_single_quoted_name_fails() {
  _assert_case "single-quoted --name outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          aws ssm put-parameter --name '/sandbox/nhp/server/image-tag' --value abc --type String --overwrite
EOF
}

_test_name_equals_form_fails() {
  _assert_case "--name= form outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          aws ssm put-parameter --name="/sandbox/nhp/ac/image-tag" --value abc --type String --overwrite
EOF
}

_test_lowercase_variable_fails() {
  _assert_case "lowercase variable outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          slot="/sandbox/nhp/server/green-image-tag"
          aws ssm put-parameter \
            --name "$slot" \
            --value abc --type String --overwrite
EOF
}

# Single-quoted RHS on the variable assignment: VAR='/path'. The
# detector should resolve the variable to the literal slot inside
# the quotes (not include the surrounding ' in the captured value).
_test_single_quoted_assignment_fails() {
  _assert_case "single-quoted RHS assignment outside allowlist" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SSM_PARAM='/sandbox/nhp/server/image-tag'
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value abc --type String --overwrite
EOF
}

# `--name "${VAR:-/sandbox/nhp/server/image-tag}"` — parameter
# expansion with a literal slot path as the default. SLOT_PATH_RE
# is searched against the raw NAME_VALUE before variable resolution
# runs, so an embedded literal slot path is caught regardless of
# the surrounding `${VAR:-…}` shape. This fixture pins that.
_test_parameter_expansion_default_fails() {
  _assert_case "parameter-expansion default with embedded slot path" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - run: |
          aws ssm put-parameter \
            --name "${SLOT:-/sandbox/nhp/server/image-tag}" \
            --value abc --type String --overwrite
EOF
}

# YAML step-level `env:` assignment of $SSM_PARAM to a slot path,
# sibling to `run:`. The shell-level backward walk stops at the
# `run:` boundary and would miss this; resolve_yaml_env_var catches
# it. This is the exact shape cr7 flagged as smugglable past the
# detector.
_test_yaml_env_block_assignment_fails() {
  _assert_case "YAML step-level env: assignment with slot path" fail .github/workflows/rogue.yml <<'EOF'
name: rogue
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - name: smuggle via env
        env:
          SSM_PARAM: /sandbox/nhp/server/image-tag
        run: |
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value abc --type String --overwrite
EOF
}

# A variable assigned to a slot path in an EARLIER step must NOT be
# resolved across the step boundary. If the put-parameter's enclosing
# run: block doesn't itself assign the variable, the use is undefined
# (a runtime bug), and the lint must not synthesise a false positive
# from the unrelated earlier assignment.
_test_cross_step_no_resolution_passes() {
  _assert_case "cross-step variable scope (with names): no false positive" pass .github/workflows/two-step.yml <<'EOF'
name: two-step
jobs:
  innocent:
    runs-on: ubuntu-latest
    steps:
      - name: First (sets the slot var)
        run: |
          SSM_PARAM="/sandbox/nhp/server/image-tag"
          echo "tag is at $SSM_PARAM"
      - name: Second (writes an unrelated param)
        run: |
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value abc --type String --overwrite
EOF
}

# Same scope-boundary contract as above, but with the dashed
# list-item `- run: |` form and no explicit `- name:` per step.
# Catches a real gap in an earlier BLOCK_BOUNDARY_RES that only
# matched `run: |` at attribute position.
_test_cross_step_dashed_run_no_resolution_passes() {
  _assert_case "cross-step variable scope (dashed run): no false positive" pass .github/workflows/two-step-dashed.yml <<'EOF'
name: two-step-dashed
jobs:
  innocent:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SSM_PARAM="/sandbox/nhp/server/image-tag"
          echo "tag is at $SSM_PARAM"
      - run: |
          aws ssm put-parameter \
            --name "$SSM_PARAM" \
            --value abc --type String --overwrite
EOF
}

_test_allowlisted_write_passes() {
  _assert_case "allowlisted file writes slot" pass .github/workflows/blue-green-deploy.yml <<'EOF'
name: Blue/Green Deploy
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          SSM_PARAM="/sandbox/nhp/server/green-image-tag"
          aws ssm put-parameter \
            --name "$SSM_PARAM" --value "$IMAGE_TAG" --type String --overwrite
EOF
}

# The shape promote-to-prod.yml uses: direct GET reads of slot paths
# alongside unrelated PUTs to /deploy/* params.
_test_get_with_unrelated_put_passes() {
  _assert_case "get-on-slot + unrelated put: no false positive" pass .github/workflows/innocent.yml <<'EOF'
name: innocent
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: |
          aws ssm get-parameter \
            --name "/prod/nhp/server/image-tag" \
            --query "Parameter.Value" --output text
          aws ssm put-parameter \
            --name "/prod/nhp/deploy/deployed-commit" \
            --value "abc" --type String --overwrite
EOF
}

# Real repo scan — also enforces the allowlist on the actual tree.
_test_real_repo_passes() {
  _assert_run "real repo: exit 0" pass "$REPO_ROOT"
}

echo "Running check-image-tag-writer-allowlist tests..."
_test_empty_passes
_test_literal_write_fails
_test_variable_write_fails
_test_templated_component_write_fails
_test_single_quoted_name_fails
_test_name_equals_form_fails
_test_lowercase_variable_fails
_test_single_quoted_assignment_fails
_test_parameter_expansion_default_fails
_test_yaml_env_block_assignment_fails
_test_cross_step_no_resolution_passes
_test_cross_step_dashed_run_no_resolution_passes
_test_allowlisted_write_passes
_test_get_with_unrelated_put_passes
_test_real_repo_passes

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
