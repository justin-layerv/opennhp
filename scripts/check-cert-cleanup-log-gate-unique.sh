#!/usr/bin/env bash
# Asserts the cert lambda emits the smoke-gate prefix "Domain cleanup
# complete for" exactly ONCE in non-comment Python source.
#
# Why: tests/smoke/18_custom_domain_cleanup_test.go polls the cert
# lambda's log group via FilterLogEvents with substring match on
# `cleanupLogLinePrefix + " " + domain`. If a future refactor reuses
# the same prefix at an earlier lifecycle point (e.g., an "about to
# clean up domain" debug log), the smoke filter would match the early
# emit and assertSSMParamsAbsent would race the actual SSM deletes —
# a false-positive pass.
#
# Comments referencing the gate string are stripped: only code emits
# should count. The lambda's own back-pointer comment at the emit site
# explicitly forbids reuse — this script is the CI safety net.
#
# Wired into `make lint-workflows`.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
LAMBDA="${REPO_ROOT}/terraform/modules/custom-domain-cert/lambda/custom_domain_cert_manager.py"
NEEDLE="Domain cleanup complete for"

if [ ! -f "$LAMBDA" ]; then
  echo "ERROR: $LAMBDA not found" >&2
  exit 1
fi

# Strip BOTH whole-line and trailing inline Python comments before
# counting code-side occurrences. Two known limitations are documented:
#   - The naive `s/#.*//` also strips `#` inside string literals.
#   - Triple-quoted docstrings are NOT stripped — putting the gate
#     string inside a `"""..."""` block will spuriously trip this lint.
# Both are far enough from any realistic content position to leave
# the cheap strip in place rather than wire a Python AST tool into the
# lint chain. `grep -o | wc -l` counts every occurrence (including
# multiple on one line); `grep -c` would undercount a single-line
# double-emit. Guard with `|| true` so an unmatched grep doesn't fail
# the pipeline before we report the diagnostic.
count=$(sed 's/[[:space:]]*#.*$//' "$LAMBDA" | grep -o "$NEEDLE" | wc -l | tr -d ' ' || true)

if [ "$count" != "1" ]; then
  cat <<EOF >&2
ERROR: $(basename "$LAMBDA") must emit the smoke-gate prefix
       "$NEEDLE" exactly ONCE in non-comment Python source
       (found $count occurrences).

       tests/smoke/18_custom_domain_cleanup_test.go::cleanupLogLinePrefix
       polls for this substring via FilterLogEvents. Reusing the same
       prefix at a different lifecycle point would let the smoke test
       pass before the SSM deletes complete (false-positive pass).

       If you genuinely need to log a similar message elsewhere, choose
       a distinct phrasing — and update this lint's NEEDLE if the
       canonical emit prefix itself changes (keep the test constant in
       lockstep).
EOF
  exit 1
fi

echo "OK: cert lambda emits smoke-gate prefix exactly once (count=$count)"
