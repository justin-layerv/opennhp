#!/usr/bin/env bash
# check-dispatch-concurrency-isolation_test.sh — fixture tests for
# scripts/check-dispatch-concurrency-isolation.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint at
# each via BUILD_AND_PUSH_WF, and asserts exit code. The key fixture is the
# pre-fix expression that actually shipped: it must fail, or this lint would not
# have caught the outage it exists to prevent. The final case runs against the
# real repo tree, so one invocation both unit-tests the detector and enforces the
# wiring on the actual workflow.
#
# Usage: bash tests/scripts/check-dispatch-concurrency-isolation_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-dispatch-concurrency-isolation.sh"

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# assert_exit <label> <fixture-file-or-empty-for-real-tree> <expected-exit>
assert_exit() {
  local label="$1" wf="$2" want="$3" got
  if [ -n "$wf" ]; then
    BUILD_AND_PUSH_WF="$wf" bash "$SCRIPT" >/dev/null 2>&1
  else
    bash "$SCRIPT" >/dev/null 2>&1
  fi
  got=$?
  if [ "$got" -eq "$want" ]; then
    report_pass "$label"
  else
    report_fail "$label" "exit $got, want $want"
  fi
}

# The expression as it stands after the fix.
cat > "$TMP/good.yml" <<'EOF'
name: Build and Deploy NHP
on:
  workflow_dispatch:
concurrency:
  group: ${{ github.event_name == 'push' && format('nhp-push-{0}', github.run_id) || (github.event_name == 'workflow_dispatch' && inputs.correlation_id != '' && format('nhp-corr-{0}', inputs.correlation_id)) || format('nhp-{0}-{1}-{2}', github.event.inputs.environment || 'sandbox', github.ref_name, github.event_name) }}
  cancel-in-progress: ${{ github.event_name == 'workflow_dispatch' && inputs.correlation_id == '' }}

jobs:
  build:
    runs-on: ubuntu-latest
EOF

# The expression that actually shipped and caused the outage.
cat > "$TMP/pre-fix.yml" <<'EOF'
name: Build and Deploy NHP
on:
  workflow_dispatch:
concurrency:
  group: ${{ github.event_name == 'push' && format('nhp-push-{0}', github.run_id) || format('nhp-{0}-{1}-{2}', github.event.inputs.environment || 'sandbox', github.ref_name, github.event_name) }}
  cancel-in-progress: ${{ github.event_name == 'workflow_dispatch' }}

jobs:
  build:
    runs-on: ubuntu-latest
EOF

# Group discriminates but cancellation does not — a correlation run gets its own
# lane yet is still cancellable, which is the half-fix worth catching.
cat > "$TMP/group-only.yml" <<'EOF'
name: Build and Deploy NHP
on:
  workflow_dispatch:
concurrency:
  group: ${{ (github.event_name == 'workflow_dispatch' && inputs.correlation_id != '' && format('nhp-corr-{0}', inputs.correlation_id)) || 'nhp-fallback' }}
  cancel-in-progress: ${{ github.event_name == 'workflow_dispatch' }}

jobs:
  build:
    runs-on: ubuntu-latest
EOF

cat > "$TMP/no-concurrency.yml" <<'EOF'
name: Build and Deploy NHP
on:
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
EOF

# A job-level concurrency block must not be mistaken for the top-level one.
cat > "$TMP/job-level-only.yml" <<'EOF'
name: Build and Deploy NHP
on:
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    concurrency:
      group: ${{ inputs.correlation_id }}
      cancel-in-progress: ${{ inputs.correlation_id == '' }}
EOF

echo "check-dispatch-concurrency-isolation.sh"
assert_exit "fixed expression passes"                      "$TMP/good.yml"          0
assert_exit "pre-fix expression is rejected"               "$TMP/pre-fix.yml"       1
assert_exit "isolated group but cancellable is rejected"   "$TMP/group-only.yml"    1
assert_exit "missing concurrency block is rejected"        "$TMP/no-concurrency.yml" 1
assert_exit "job-level block is not read as top-level"     "$TMP/job-level-only.yml" 1
assert_exit "real build-and-push.yml satisfies the lint"   ""                       0

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
