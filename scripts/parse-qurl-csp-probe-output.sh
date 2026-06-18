#!/usr/bin/env bash
# parse-qurl-csp-probe-output.sh
# ----------------------------------------------------------------------------
# Parse the bounded curl probe output used by the sandbox qurl.link CSP wait.
# Input is curl's response headers plus the synthetic __nhp_http_status__ marker.

set -euo pipefail

probe_output="$(cat)"

http_status="$(
  printf '%s\n' "$probe_output" \
    | awk -F: 'tolower($1) == "__nhp_http_status__" { sub(/^[[:space:]]*/, "", $2); print $2; found = 1 } END { if (!found) print "000" }'
)"
csp="$(
  printf '%s\n' "$probe_output" \
    | tr -d '\r' \
    | awk 'tolower($0) ~ /^content-security-policy:/ { sub(/^[^:]+:[[:space:]]*/, ""); print; exit }'
)"

printf 'http_status=%s\n' "$http_status"
printf 'csp=%s\n' "$csp"
