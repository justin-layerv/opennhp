#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/check-disable-agent-validation.sh
# (#1157 F9).
#
# Each fixture is a synthetic config tree under a tempdir with a
# specific shape. The runner invokes the lint script with
# DISABLE_AGENT_VALIDATION_SCAN_PATHS=... overriding the default
# prod-paths list, and asserts the expected exit code.
#
# Why fixtures: the production lint runs against the real repo and
# is self-validating in the happy path — but a regression in the
# regex (e.g., an accidental relaxation that would miss a real
# violation) wouldn't surface until a real PR introduced a
# violation. Fixtures pre-flush every failure mode the lint claims
# to catch on every CI run.
#
# Mirrors the pattern of tests/lints/redirect-url-drift/run-fixtures.sh.
#
# Usage:
#   ./tests/lints/disable-agent-validation/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-disable-agent-validation.sh"

if [[ ! -x "${LINT_SCRIPT}" ]]; then
	echo "ERROR: lint script not executable: ${LINT_SCRIPT}" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

PASS=0
FAIL=0

# Helper to run the lint script with an overridden scan-paths list
# scoped to a per-fixture tempdir. Each fixture gets a fresh tree.
run_fixture() {
	local name="$1"
	local fixture_dir="$2"
	local scan_paths="$3"
	local expected="$4"
	local out="${TMP}/${name}.log"
	local actual=0

	(
		cd "${fixture_dir}"
		DISABLE_AGENT_VALIDATION_SCAN_PATHS="${scan_paths}" "${LINT_SCRIPT}" >"${out}" 2>&1
	) || actual=$?

	if [[ "${actual}" -ne "${expected}" ]]; then
		echo "  FAIL: ${name} — expected exit ${expected}, got ${actual}" >&2
		echo "        fixture: ${fixture_dir}" >&2
		echo "        scan_paths: ${scan_paths}" >&2
		echo "        lint output:" >&2
		sed 's/^/          /' "${out}" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	printf '  PASS: %-45s (exit %d as expected)\n' "${name}" "${actual}"
	PASS=$((PASS + 1))
}

# ---------------------------------------------------------------------------
# Fixture 1: clean fixture with all configs at false
# ---------------------------------------------------------------------------
fix_clean="${TMP}/clean"
mkdir -p "${fix_clean}/cfg"
cat > "${fix_clean}/cfg/server.toml" <<'EOF'
# nhp-server config
DisableAgentValidation = false
ListenAddr = "0.0.0.0:62206"
EOF
run_fixture "clean-all-false" "${fix_clean}" "cfg/server.toml" 0

# ---------------------------------------------------------------------------
# Fixture 2: violation — DisableAgentValidation = true
# ---------------------------------------------------------------------------
fix_violation="${TMP}/violation"
mkdir -p "${fix_violation}/cfg"
cat > "${fix_violation}/cfg/server.toml" <<'EOF'
# nhp-server config — BAD: should be false
DisableAgentValidation = true
ListenAddr = "0.0.0.0:62206"
EOF
run_fixture "violation-true-rejected" "${fix_violation}" "cfg/server.toml" 1

# ---------------------------------------------------------------------------
# Fixture 3: comment-only mention (the documentation line in the
# real config.toml — should NOT trip the lint)
# ---------------------------------------------------------------------------
fix_comment="${TMP}/comment"
mkdir -p "${fix_comment}/cfg"
cat > "${fix_comment}/cfg/server.toml" <<'EOF'
# DisableAgentValidation: whether to skip agent validation. Default false.
# Setting DisableAgentValidation = true is a SECURITY REGRESSION.
DisableAgentValidation = false
EOF
run_fixture "comment-only-mention-not-violation" "${fix_comment}" "cfg/server.toml" 0

# ---------------------------------------------------------------------------
# Fixture 4: HCL-style true (// comment grammar)
# ---------------------------------------------------------------------------
fix_hcl="${TMP}/hcl"
mkdir -p "${fix_hcl}/tf"
cat > "${fix_hcl}/tf/main.tf" <<'EOF'
// Terraform module wiring nhp-server config
locals {
  DisableAgentValidation = true
}
EOF
run_fixture "hcl-style-true-rejected" "${fix_hcl}" "tf" 1

# ---------------------------------------------------------------------------
# Fixture 5: shell heredoc embedding TOML (mirrors user_data.sh.tpl)
# ---------------------------------------------------------------------------
fix_heredoc="${TMP}/heredoc"
mkdir -p "${fix_heredoc}/tf"
cat > "${fix_heredoc}/tf/user_data.sh.tpl" <<'EOF'
#!/bin/bash
cat > /etc/nhp-server/config.toml <<'CONFIG'
DisableAgentValidation = true
ListenAddr = "0.0.0.0:62206"
CONFIG
EOF
run_fixture "heredoc-embedded-true-rejected" "${fix_heredoc}" "tf/user_data.sh.tpl" 1

# ---------------------------------------------------------------------------
# Fixture 6: extra whitespace + tab — must still match
# ---------------------------------------------------------------------------
fix_whitespace="${TMP}/whitespace"
mkdir -p "${fix_whitespace}/cfg"
printf 'DisableAgentValidation\t=\ttrue\n' > "${fix_whitespace}/cfg/server.toml"
run_fixture "whitespace-tabs-still-rejected" "${fix_whitespace}" "cfg/server.toml" 1

# ---------------------------------------------------------------------------
# Fixture 7: case-insensitive match REQUIRED — pelletier/go-toml/v2
# matches keys to Go struct fields case-insensitively when the field
# has no `toml:` tag. Config.DisableAgentValidation has only a `json`
# tag (no `toml:` tag), so all three lowercase/upper/camel typos
# below WOULD be parsed at runtime and set the bool — a case-sensitive
# lint would miss those silent bypasses. The fixture asserts the lint
# rejects all three case variants.
# ---------------------------------------------------------------------------
fix_case_lower="${TMP}/case_lower"
mkdir -p "${fix_case_lower}/cfg"
cat > "${fix_case_lower}/cfg/server.toml" <<'EOF'
disableagentvalidation = true
EOF
run_fixture "case-lower-rejected" "${fix_case_lower}" "cfg/server.toml" 1

fix_case_upper="${TMP}/case_upper"
mkdir -p "${fix_case_upper}/cfg"
cat > "${fix_case_upper}/cfg/server.toml" <<'EOF'
DISABLEAGENTVALIDATION = true
EOF
run_fixture "case-upper-rejected" "${fix_case_upper}" "cfg/server.toml" 1

fix_case_camel="${TMP}/case_camel"
mkdir -p "${fix_case_camel}/cfg"
cat > "${fix_case_camel}/cfg/server.toml" <<'EOF'
disableAgentValidation = true
EOF
run_fixture "case-camel-rejected" "${fix_case_camel}" "cfg/server.toml" 1

# ---------------------------------------------------------------------------
# Fixture 8: empty / nonexistent paths fail loud (prevents silent skip)
# ---------------------------------------------------------------------------
fix_empty="${TMP}/empty"
mkdir -p "${fix_empty}"
run_fixture "no-files-found-fails-loud" "${fix_empty}" "does-not-exist" 1

# ---------------------------------------------------------------------------
# Fixture 9: multiple paths, one violation among many — must surface
# ---------------------------------------------------------------------------
fix_multi="${TMP}/multi"
mkdir -p "${fix_multi}/dev" "${fix_multi}/prod"
cat > "${fix_multi}/dev/server.toml" <<'EOF'
DisableAgentValidation = false
EOF
cat > "${fix_multi}/prod/server.toml" <<'EOF'
DisableAgentValidation = true
EOF
run_fixture "multi-path-mixed-violation-detected" "${fix_multi}" "dev:prod" 1

# ---------------------------------------------------------------------------
# Fixture 10: false-with-trailing-comment edge — must still pass
# ---------------------------------------------------------------------------
fix_inline="${TMP}/inline"
mkdir -p "${fix_inline}/cfg"
cat > "${fix_inline}/cfg/server.toml" <<'EOF'
DisableAgentValidation = false # default for prod
EOF
run_fixture "false-with-inline-comment-passes" "${fix_inline}" "cfg/server.toml" 0

# ---------------------------------------------------------------------------
# Fixture 11: single-line nested HCL (e.g. `bar = { DisableAgentValidation
# = true }`) is INTENTIONALLY NOT detected by the lint. The regex
# requires the key to start the (whitespace-trimmed) line to keep the
# pattern tractable; a single-line nested structure puts the key after
# `{` or `,`. This shape is unusual in practice (no current prod
# config uses it) and the lint stays naive on purpose. Pinning the
# gap here so a future tightening of the regex (broader leading
# anchor) surfaces a trade-off discussion at PR time rather than
# silently changing behavior. cr round 8 concern #3.
# ---------------------------------------------------------------------------
fix_inline_hcl="${TMP}/inline_hcl"
mkdir -p "${fix_inline_hcl}/tf"
cat > "${fix_inline_hcl}/tf/main.tf" <<'EOF'
locals {
  bar = { DisableAgentValidation = true }
}
EOF
run_fixture "single-line-nested-hcl-NOT-detected-acceptable-gap" "${fix_inline_hcl}" "tf" 0

if [[ "${FAIL}" -gt 0 ]]; then
	echo "" >&2
	echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
	exit 1
fi
echo "All ${PASS} disable-agent-validation fixtures passed."
