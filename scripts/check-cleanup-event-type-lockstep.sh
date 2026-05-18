#!/usr/bin/env bash
# Asserts the cleanup event-type wire-string is in lockstep between
# the Go smoke test and the Python cert lambda. The third site (the
# publisher in the qurl-service repo) cannot be checked here — drift
# there still trips the 90s smoke timeout, not this lint.
#
# Sites compared:
#   - tests/smoke/18_custom_domain_cleanup_test.go::cleanupEventType
#   - terraform/modules/custom-domain-cert/lambda/custom_domain_cert_manager.py::EVENT_DOMAIN_CLEANUP
#
# Both must resolve to the literal "domain.cleanup". If either drifts,
# the SNS MessageAttribute routing in the lambda dispatcher would no
# longer match what the test publishes (or vice versa), and the smoke
# test would fail at the 90s poll timeout with no specific signal that
# the wire-string drifted. This lint surfaces the drift at PR time.
#
# Wired into `make lint-workflows`.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GO_TEST="${REPO_ROOT}/tests/smoke/18_custom_domain_cleanup_test.go"
LAMBDA="${REPO_ROOT}/terraform/modules/custom-domain-cert/lambda/custom_domain_cert_manager.py"

if [ ! -f "$GO_TEST" ]; then
  echo "ERROR: $GO_TEST not found" >&2
  exit 1
fi
if [ ! -f "$LAMBDA" ]; then
  echo "ERROR: $LAMBDA not found" >&2
  exit 1
fi

# Match: `const cleanupEventType = "domain.cleanup"` (single-line Go const).
# A refactor to a `const (...)` block would fail loud here (the extract
# returns empty and the script exits with a clear error) rather than
# silently accept a stale value — so a future Go-side reformat is
# tolerable; just update the regex to match the new shape.
go_value=$(grep -E '^const cleanupEventType[[:space:]]*=[[:space:]]*"' "$GO_TEST" | sed -E 's/^.*=[[:space:]]*"([^"]*)".*$/\1/' | head -n1)

# Match: `EVENT_DOMAIN_CLEANUP = 'domain.cleanup'` (single-line Python module const).
# Python accepts either single or double quotes; allow both.
py_value=$(grep -E "^EVENT_DOMAIN_CLEANUP[[:space:]]*=[[:space:]]*['\"]" "$LAMBDA" | sed -E "s/^.*=[[:space:]]*['\"]([^'\"]*)['\"].*$/\1/" | head -n1)

if [ -z "$go_value" ]; then
  echo "ERROR: could not extract cleanupEventType value from $GO_TEST" >&2
  echo "       (expected: const cleanupEventType = \"...\")" >&2
  exit 1
fi
if [ -z "$py_value" ]; then
  echo "ERROR: could not extract EVENT_DOMAIN_CLEANUP value from $LAMBDA" >&2
  echo "       (expected: EVENT_DOMAIN_CLEANUP = '...')" >&2
  exit 1
fi

if [ "$go_value" != "$py_value" ]; then
  cat <<EOF >&2
ERROR: cleanup event-type wire-string drift between Go test and Python lambda.

       $GO_TEST::cleanupEventType
         = "$go_value"

       $LAMBDA::EVENT_DOMAIN_CLEANUP
         = "$py_value"

       The lambda dispatcher routes on this SNS MessageAttribute value,
       so a mismatch means published events never reach handle_domain_cleanup
       and the smoke test would fail at the 90s poll timeout. Update both
       sites (and the qurl-service publisher) in lockstep.
EOF
  exit 1
fi

echo "OK: cleanup event-type wire-string is lockstep across Go test + Python lambda (value=$go_value)"
