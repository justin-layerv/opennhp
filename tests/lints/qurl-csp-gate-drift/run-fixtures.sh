#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/check-qurl-csp-gate-drift.sh.
#
# The production lint checks real repo files. These fixtures exercise the
# parser and equivalence checks against synthetic workflow/smoke/dns/tfvars
# files so extractor regressions fail before they can mask real drift.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-qurl-csp-gate-drift.sh"
PROBE_PARSE_SCRIPT="${REPO_ROOT}/scripts/parse-qurl-csp-probe-output.sh"

if [ ! -x "$LINT_SCRIPT" ]; then
  echo "ERROR: lint script not executable: $LINT_SCRIPT" >&2
  exit 1
fi
if [ ! -x "$PROBE_PARSE_SCRIPT" ]; then
  echo "ERROR: probe parser script not executable: $PROBE_PARSE_SCRIPT" >&2
  exit 1
fi

GOOD_WORKFLOW_RE="(^|;[[:space:]]*)script-src[[:space:]]+'unsafe-inline'[[:space:]]+'self'([[:space:]]*;|[[:space:]]*$)"
INLINE_ONLY_WORKFLOW_RE="(^|;[[:space:]]*)script-src[[:space:]]+'unsafe-inline'([[:space:]]*;|[[:space:]]*$)"
UNTRANSLATED_POSIX_RE="(^|;[[:blank:]]*)script-src[[:blank:]]+'unsafe-inline'[[:blank:]]+'self'([[:blank:]]*;|[[:blank:]]*$)"
GOOD_SMOKE_RE="(?i)(?:^|;\s*)script-src\s+'unsafe-inline'\s+'self'\s*(?:;|$)"
ORIGIN="https://qurl.link.layerv.xyz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

write_fixture() {
  local dir="$1"
  local workflow_re="$2"
  local smoke_re="$3"
  local tf_enabled="$4"
  local smoke_enabled="$5"
  local workflow_origin="$6"
  local smoke_origin="$7"
  local extra_map="$8"

  mkdir -p "$dir"

  {
    printf 'jobs:\n'
    printf '  fixture:\n'
    printf '    steps:\n'
    printf '      - run: |\n'
    printf '          QURL_LINK_URL="%s"\n' "$workflow_origin"
    printf '        env:\n'
    printf '          EXPECTED_SCRIPT_SRC_RE: "%s"\n' "$workflow_re"
  } > "$dir/workflow.yml"

  {
    printf 'package smoke\n\n'
    printf 'var (\n'
    # shellcheck disable=SC2016 # backticks are literal Go raw-string delimiters
    printf '\tscriptSrcInlineAndSelfRE = regexp.MustCompile(`%s`)\n' "$smoke_re"
    printf ')\n\n'
    if [ "$extra_map" = "true" ]; then
      printf 'var unrelatedSandboxFlags = map[string]bool{\n'
      printf '\t"sandbox": false,\n'
      printf '}\n\n'
    fi
    printf 'var qurlLinkJSAgentEnabledEnvs = map[string]bool{\n'
    printf '\t"sandbox": %s,\n' "$smoke_enabled"
    printf '}\n'
  } > "$dir/smoke.go"

  {
    printf 'package smoke\n\n'
    printf 'func derivedEndpointsForEnv(env string) derivedEndpoints {\n'
    printf '\tswitch env {\n'
    printf '\tcase "sandbox":\n'
    printf '\t\treturn derivedEndpoints{\n'
    printf '\t\t\tQURLLinkOrigin: "%s",\n' "$smoke_origin"
    printf '\t\t}\n'
    printf '\tcase "prod":\n'
    printf '\t\treturn derivedEndpoints{\n'
    printf '\t\t\tQURLLinkOrigin: "https://qurl.link",\n'
    printf '\t\t}\n'
    printf '\t}\n'
    printf '\treturn derivedEndpoints{}\n'
    printf '}\n'
  } > "$dir/dns.go"

  printf 'qurl_link_js_agent_enabled = %s\n' "$tf_enabled" > "$dir/sandbox.tfvars"
}

run_case() {
  local name="$1"
  local expected="$2"
  local workflow_re="$3"
  local smoke_re="$4"
  local tf_enabled="$5"
  local smoke_enabled="$6"
  local workflow_origin="$7"
  local smoke_origin="$8"
  local extra_map="$9"
  local dir="${TMP}/${name}"
  local out="${TMP}/${name}.log"
  local actual=0

  write_fixture "$dir" "$workflow_re" "$smoke_re" "$tf_enabled" "$smoke_enabled" "$workflow_origin" "$smoke_origin" "$extra_map"
  "$LINT_SCRIPT" "$dir/workflow.yml" "$dir/smoke.go" "$dir/dns.go" "$dir/sandbox.tfvars" >"$out" 2>&1 || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    echo "  FAIL: $name - expected exit $expected, got $actual" >&2
    sed 's/^/        /' "$out" >&2
    FAIL=$((FAIL + 1))
    return
  fi

  printf '  PASS: %-25s (exit %d as expected)\n' "$name" "$actual"
  PASS=$((PASS + 1))
}

run_probe_case() {
  local name="$1"
  local input="$2"
  local expected_status="$3"
  local expected_csp="$4"
  local out="${TMP}/probe-${name}.out"
  local status csp

  printf '%b' "$input" | "$PROBE_PARSE_SCRIPT" >"$out"
  status=$(sed -n 's/^http_status=//p' "$out")
  csp=$(sed -n 's/^csp=//p' "$out")

  if [ "$status" != "$expected_status" ] || [ "$csp" != "$expected_csp" ]; then
    echo "  FAIL: probe-$name" >&2
    echo "        expected status=$expected_status csp=$expected_csp" >&2
    echo "        got      status=$status csp=$csp" >&2
    FAIL=$((FAIL + 1))
    return
  fi

  printf '  PASS: %-25s (status %s)\n' "probe-$name" "$status"
  PASS=$((PASS + 1))
}

echo "Running qurl-csp-gate-drift fixtures..."

PASS=0
FAIL=0
run_case "in-sync" 0 "$GOOD_WORKFLOW_RE" "$GOOD_SMOKE_RE" true true "$ORIGIN" "$ORIGIN" false
run_case "extra-sandbox-map" 0 "$GOOD_WORKFLOW_RE" "$GOOD_SMOKE_RE" true true "$ORIGIN" "$ORIGIN" true
run_case "regex-drift" 1 "$INLINE_ONLY_WORKFLOW_RE" "$GOOD_SMOKE_RE" true true "$ORIGIN" "$ORIGIN" false
run_case "tfvar-drift" 1 "$GOOD_WORKFLOW_RE" "$GOOD_SMOKE_RE" false true "$ORIGIN" "$ORIGIN" false
run_case "smoke-map-drift" 1 "$GOOD_WORKFLOW_RE" "$GOOD_SMOKE_RE" true false "$ORIGIN" "$ORIGIN" false
run_case "fallback-origin-drift" 1 "$GOOD_WORKFLOW_RE" "$GOOD_SMOKE_RE" true true "https://other.example" "$ORIGIN" false
run_case "untranslated-posix-class" 1 "$UNTRANSLATED_POSIX_RE" "$GOOD_SMOKE_RE" true true "$ORIGIN" "$ORIGIN" false

run_probe_case "crlf-success" \
  "HTTP/2 200\r\ncontent-type: text/html\r\nContent-Security-Policy: default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline'\r\n\r\n__nhp_http_status__:200\n" \
  "200" \
  "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline'"
run_probe_case "missing-csp" \
  "HTTP/2 200\r\ncontent-type: text/html\r\n\r\n__nhp_http_status__:200\n" \
  "200" \
  ""
run_probe_case "curl-error-no-marker" \
  "curl: (28) Operation timed out after 5001 milliseconds\n" \
  "000" \
  ""

echo "qurl-csp-gate-drift fixtures: ${PASS} passed, ${FAIL} failed."
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
