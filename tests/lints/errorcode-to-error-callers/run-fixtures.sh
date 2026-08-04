#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/check-errorcode-to-error-callers.sh (PR #3643).
#
# The production lint runs against the real repo and is self-validating in the
# happy path — but a regression in the matching (an accidental relaxation that
# would miss a real violation, or a tightening that flags prose) would not
# surface until a real PR tripped it. These fixtures exercise every case the
# lint claims to handle on every CI run.
#
# Mirrors the pattern of the other tests/lints/*/run-fixtures.sh suites.
#
# Usage:
#   ./tests/lints/errorcode-to-error-callers/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-errorcode-to-error-callers.sh"

if [[ ! -x "${LINT_SCRIPT}" ]]; then
	echo "ERROR: lint script not executable: ${LINT_SCRIPT}" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

PASS=0
FAIL=0

# run_fixture <name> <expected_exit> <setup_fn>
run_fixture() {
	local name="$1" expected="$2" setup="$3"
	local dir="${TMP}/${name}"
	rm -rf "${dir}"
	mkdir -p "${dir}/nhp/common" "${dir}/endpoints/agent"
	"${setup}" "${dir}"

	local actual=0
	ERRORCODE_CALLERS_SCAN_ROOT="${dir}" "${LINT_SCRIPT}" >/dev/null 2>&1 || actual=$?

	if [[ "${actual}" -eq "${expected}" ]]; then
		echo "  PASS: ${name}"
		PASS=$((PASS + 1))
	else
		echo "  FAIL: ${name} (expected exit ${expected}, got ${actual})"
		FAIL=$((FAIL + 1))
	fi
}

# The definition and its in-package caller are always allowed.
seed_allowed() {
	cat >"$1/nhp/common/errors.go" <<'GO'
package common

func ErrorCodeToError(code string) *Error { return errorMap[code] }

func ErrorFromResponse(code, message string) *Error {
	if e := ErrorCodeToError(code); e != nil {
		return e
	}
	return &Error{code: code, msg: message}
}
GO
}

fx_clean() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

func knock() error { return common.ErrorFromResponse(code, msg) }
GO
}

fx_external_call() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

func knock() error {
	var err error = common.ErrorCodeToError(code)
	return err
}
GO
}

fx_line_comment_only() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

// This path used to call common.ErrorCodeToError(code) directly, which
// returned a nil *Error for extension codes. Do not go back.
func knock() error { return common.ErrorFromResponse(code, msg) }
GO
}

fx_block_comment_only() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

/*
Historical note: common.ErrorCodeToError(code) was called here and produced a
typed-nil error interface.
*/
func knock() error { return common.ErrorFromResponse(code, msg) }
GO
}

fx_trailing_comment_on_real_call() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

func knock() error {
	var err error = common.ErrorCodeToError(code) // looks intentional, still wrong
	return err
}
GO
}

fx_call_after_block_comment_ends() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

func knock() error {
	/* explanatory
	   block */ var err error = common.ErrorCodeToError(code)
	return err
}
GO
}

fx_similarly_named_identifier_passes() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

// An identifier that merely ENDS in the guarded name is a different symbol and
// must not trip the lint. Only a real ErrorCodeToError call is a violation.
func wrapErrorCodeToError(code string) error { return common.ErrorFromResponse(code, "") }

func knock() error { return wrapErrorCodeToError(code) }
GO
}

fx_qualified_call_fails() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/knock.go" <<'GO'
package agent

func knock() error {
	var err error = common.ErrorCodeToError(code)
	return err
}
GO
}

fx_non_go_file_ignored() {
	seed_allowed "$1"
	cat >"$1/endpoints/agent/notes.md" <<'MD'
Call common.ErrorCodeToError(code) here — this is documentation, not Go.
MD
}

echo "errorcode-to-error-callers fixtures:"
run_fixture "clean-tree-passes" 0 fx_clean
run_fixture "external-call-fails" 1 fx_external_call
run_fixture "line-comment-mention-passes" 0 fx_line_comment_only
run_fixture "block-comment-mention-passes" 0 fx_block_comment_only
run_fixture "trailing-comment-on-real-call-fails" 1 fx_trailing_comment_on_real_call
run_fixture "call-after-block-comment-ends-fails" 1 fx_call_after_block_comment_ends
run_fixture "similarly-named-identifier-passes" 0 fx_similarly_named_identifier_passes
run_fixture "qualified-call-fails" 1 fx_qualified_call_fails
run_fixture "non-go-file-ignored" 0 fx_non_go_file_ignored

echo "errorcode-to-error-callers fixtures: ${PASS} pass / ${FAIL} fail"
if [[ "${FAIL}" -gt 0 ]]; then
	exit 1
fi
