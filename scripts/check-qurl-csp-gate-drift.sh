#!/usr/bin/env bash
# check-qurl-csp-gate-drift.sh
# ----------------------------------------------------------------------------
# Fence drift between the qurl.link CSP propagation gate in build-and-push.yml
# and the smoke test that asserts the same script-src posture on the wire.
#
# The workflow cannot import the Go smoke regex, and the smoke module cannot
# import workflow YAML. This lint keeps the duplicated contract honest:
#   - workflow EXPECTED_SCRIPT_SRC_RE and scriptSrcInlineAndSelfRE must agree
#     on realistic CSP inputs;
#   - sandbox qurl_link_js_agent_enabled must stay true while the sandbox-only
#     gate expects the js-agent posture; prod posture is intentionally out of
#     scope for this lint because the propagation wait does not run in prod;
#   - the workflow fallback origin must match the smoke sandbox default.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_FILE="${1:-${REPO_ROOT}/.github/workflows/build-and-push.yml}"
SMOKE_FILE="${2:-${REPO_ROOT}/tests/smoke/16_qurl_link_frontend_test.go}"
DNS_FILE="${3:-${REPO_ROOT}/tests/smoke/dns.go}"
SANDBOX_TFVARS="${4:-${REPO_ROOT}/terraform/environments/sandbox/terraform.tfvars}"

require_file() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "ERROR: missing $file" >&2
    exit 1
  fi
}

single_match() {
  local label="$1" matches="$2"
  local non_empty count
  non_empty=$(printf '%s\n' "$matches" | sed '/^$/d')
  if [ -z "$non_empty" ]; then
    count=0
  else
    count=$(printf '%s\n' "$non_empty" | wc -l | tr -d ' ')
  fi
  if [ "$count" -ne 1 ]; then
    echo "ERROR: $label: expected exactly one match, found $count" >&2
    [ -z "$non_empty" ] || printf '%s\n' "$non_empty" >&2
    exit 1
  fi
  printf '%s\n' "$non_empty"
}

for file in "$WORKFLOW_FILE" "$SMOKE_FILE" "$DNS_FILE" "$SANDBOX_TFVARS"; do
  require_file "$file"
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for CSP regex equivalence checks." >&2
  exit 1
fi

workflow_re="$(
  single_match "workflow EXPECTED_SCRIPT_SRC_RE" "$(
    sed -nE 's/^[[:space:]]*EXPECTED_SCRIPT_SRC_RE:[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$WORKFLOW_FILE"
  )"
)"
smoke_re="$(
  single_match "smoke scriptSrcInlineAndSelfRE" "$(
    # shellcheck disable=SC2016 # backticks are literal Go raw-string delimiters
    sed -nE 's/^[[:space:]]*scriptSrcInlineAndSelfRE[[:space:]]*=[[:space:]]*regexp\.MustCompile\(`([^`]+)`\).*$/\1/p' "$SMOKE_FILE"
  )"
)"

python3 - "$workflow_re" "$smoke_re" <<'PY'
import re
import sys

raw_workflow_re = sys.argv[1]
workflow_re = raw_workflow_re.replace("[[:space:]]", r"\s")
smoke_re = sys.argv[2]

# This is a corpus-based drift fence for the duplicated contract, not a full
# proof of grep ERE and Go RE2 engine equivalence. Keep the patterns simple.
if "[[:" in workflow_re or ":]]" in workflow_re:
    print(
        "ERROR: workflow regex contains a POSIX class this lint does not translate; "
        "extend check-qurl-csp-gate-drift.sh before changing EXPECTED_SCRIPT_SRC_RE.",
        file=sys.stderr,
    )
    sys.exit(1)

cases = [
    ("script-src 'unsafe-inline' 'self'", True),
    ("script-src   'unsafe-inline'   'self'   ", True),
    ("default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline'", True),
    ("style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self';", True),
    ("script-src 'unsafe-inline'", False),
    ("script-src 'self' 'unsafe-inline'", False),
    ("x-script-src 'unsafe-inline' 'self'", False),
    ("default-src 'self'; script-src 'unsafe-inline' 'selfish'", False),
]

def matches(pattern: str, value: str) -> bool:
    return re.search(pattern, value, re.IGNORECASE) is not None

failures = []
for value, expected in cases:
    workflow_match = matches(workflow_re, value)
    smoke_match = matches(smoke_re, value)
    if workflow_match != smoke_match:
        failures.append(
            f"regex drift for {value!r}: workflow={workflow_match} smoke={smoke_match}"
        )
    if workflow_match != expected:
        failures.append(
            f"unexpected contract result for {value!r}: got={workflow_match} want={expected}"
        )

if failures:
    print("ERROR: qurl.link CSP gate drift:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    sys.exit(1)
PY

sandbox_tf_enabled="$(
  single_match "sandbox terraform qurl_link_js_agent_enabled" "$(
    sed -nE 's/^[[:space:]]*qurl_link_js_agent_enabled[[:space:]]*=[[:space:]]*(true|false)[[:space:]]*$/\1/p' "$SANDBOX_TFVARS"
  )"
)"
smoke_map_enabled="$(
  single_match "smoke qurlLinkJSAgentEnabledEnvs sandbox entry" "$(
    awk '
      index($0, "var qurlLinkJSAgentEnabledEnvs = map[string]bool{") { in_map = 1; next }
      in_map && /^[[:space:]]*}/ { in_map = 0 }
      in_map {
        line = $0
        if (line ~ /^[[:space:]]*"sandbox":[[:space:]]*(true|false),[[:space:]]*$/) {
          sub(/^[[:space:]]*"sandbox":[[:space:]]*/, "", line)
          sub(/,.*/, "", line)
          print line
        }
      }
    ' "$SMOKE_FILE"
  )"
)"
if [ "$sandbox_tf_enabled" != "$smoke_map_enabled" ]; then
  echo "ERROR: sandbox qurl_link_js_agent_enabled drift:" >&2
  echo "  terraform: $sandbox_tf_enabled ($SANDBOX_TFVARS)" >&2
  echo "  smoke:     $smoke_map_enabled ($SMOKE_FILE)" >&2
  exit 1
fi
if [ "$sandbox_tf_enabled" != "true" ]; then
  echo "ERROR: qurl.link CSP gate expects sandbox js-agent posture, but sandbox tfvars disables it." >&2
  echo "       Update the workflow gate and smoke map in the same PR as any tfvar flip." >&2
  exit 1
fi

workflow_fallback="$(
  single_match "workflow QURL_LINK_URL fallback" "$(
    sed -nE 's/^[[:space:]]*QURL_LINK_URL="([^"]+)"[[:space:]]*$/\1/p' "$WORKFLOW_FILE"
  )"
)"
smoke_sandbox_origin="$(
  single_match "smoke sandbox QURLLinkOrigin" "$(
    awk '
      /case "sandbox":/ { in_sandbox = 1 }
      /case "prod":/ { in_sandbox = 0 }
      in_sandbox && /QURLLinkOrigin:/ {
        line = $0
        sub(/.*QURLLinkOrigin:[[:space:]]*"/, "", line)
        sub(/".*/, "", line)
        print line
      }
    ' "$DNS_FILE"
  )"
)"
if [ "$workflow_fallback" != "$smoke_sandbox_origin" ]; then
  echo "ERROR: qurl.link fallback origin drift:" >&2
  echo "  workflow fallback: $workflow_fallback ($WORKFLOW_FILE)" >&2
  echo "  smoke sandbox:     $smoke_sandbox_origin ($DNS_FILE)" >&2
  exit 1
fi

echo "qurl.link CSP gate drift check passed"
