#!/usr/bin/env bash
# check-errorcode-to-error-callers.sh
# ----------------------------------------------------------------------------
# Fail if any Go code outside `nhp/common/` calls `ErrorCodeToError(`.
#
# Why this exists (PR #3643):
#
#   `common.ErrorCodeToError` returns a bare `nil *Error` for any code it does
#   not recognize — every extension code emitted by an auth service or AC.
#   Assigning that nil `*Error` into an `error`-typed variable produces the Go
#   typed-nil trap: a non-nil interface wrapping a nil pointer. `err != nil` is
#   then TRUE, and the `err.Error()` that follows dereferences `e.msg` on a nil
#   receiver and panics.
#
#   That is not hypothetical — it is what the five agent call sites in
#   `endpoints/agent/{knock.go,request.go}` did before #3643 converted them to
#   `common.ErrorFromResponse`, which never returns nil. `docs/UPSTREAM_SYNC.md`
#   records that `ErrorCodeToError` is now reachable only from inside
#   `ErrorFromResponse`. This script is what MAKES that true instead of merely
#   asserting it: nothing else stops the next caller from reaching for the raw
#   lookup and reintroducing the same panic.
#
# Why a shell lint and not a Go test:
#
#   This started as a Go test in `nhp/common`. That was wrong, and silently so.
#   Go caches test results keyed on the package's own inputs, and a test that
#   walks the repo reads files the cache does not attribute to it — so adding a
#   fresh offending file and running `go test ./...` returned a CACHED PASS.
#   A fence that passes precisely when it should fail is worse than no fence,
#   and `actions/setup-go` restores the build cache in CI too, so this was not
#   a local-only artifact. A lint script has no such semantics.
#
# Scope:
#
#   `nhp/common/` is exempt: that is where the function is defined, where
#   `ErrorFromResponse` legitimately calls it, and where
#   `errors_assignment_test.go` pins its nil-return behavior (the very property
#   that makes the trap possible).
#
#   `ErrorCodeToError` stays EXPORTED. It is upstream OpenNHP's API and
#   unexporting it would create a fork divergence for no safety this fence does
#   not already provide — the dangerous pattern is an external caller taking the
#   raw lookup, which is exactly what this blocks.
#
# Detection:
#
#   String-based, matching `ErrorCodeToError(` on the call form only. Comments
#   are stripped first (`//` line comments and `/* */` blocks, including blocks
#   spanning lines) because several files now carry prose explaining this trap
#   and a doc mention must not fail the lint. A trailing comment on a real call
#   still trips — that is a real call.
#
# Usage:
#   ./scripts/check-errorcode-to-error-callers.sh
#
# Override the scan root for fixtures:
#   ERRORCODE_CALLERS_SCAN_ROOT=/tmp/fixture ./scripts/check-errorcode-to-error-callers.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_ROOT="${ERRORCODE_CALLERS_SCAN_ROOT:-${REPO_ROOT}}"

# Directory prefixes (relative to SCAN_ROOT) allowed to call the function.
ALLOWED_PREFIX="nhp/common/"

if [[ ! -d "${SCAN_ROOT}" ]]; then
	echo "ERROR: scan root does not exist: ${SCAN_ROOT}" >&2
	exit 2
fi

# Strip Go comments so a doc mention of the symbol is not a violation.
# Handles /* */ blocks that span lines, then // to end of line.
strip_comments() {
	awk '
		BEGIN { inblock = 0 }
		{
			line = $0
			out = ""
			while (length(line) > 0) {
				if (inblock) {
					pos = index(line, "*/")
					if (pos == 0) { line = ""; break }
					line = substr(line, pos + 2)
					inblock = 0
					continue
				}
				bpos = index(line, "/*")
				lpos = index(line, "//")
				if (lpos > 0 && (bpos == 0 || lpos < bpos)) {
					out = out substr(line, 1, lpos - 1)
					line = ""
					break
				}
				if (bpos > 0) {
					out = out substr(line, 1, bpos - 1)
					line = substr(line, bpos + 2)
					inblock = 1
					continue
				}
				out = out line
				line = ""
			}
			print out
		}
	' "$1"
}

violations=0
report=""

while IFS= read -r file; do
	rel="${file#"${SCAN_ROOT}"/}"
	case "${rel}" in
	"${ALLOWED_PREFIX}"*) continue ;;
	esac

	# Report the ORIGINAL line for readability, but decide on the stripped one.
	stripped="$(strip_comments "${file}")"
	lineno=0
	while IFS= read -r code_line; do
		lineno=$((lineno + 1))
		# Word-anchored so an identifier merely ENDING in the name (a
		# hypothetical wrapErrorCodeToError) is not flagged. Matches the
		# qualified call (common.ErrorCodeToError() from another package) and
		# the bare call, and nothing in between.
		if [[ "${code_line}" =~ (^|[^A-Za-z0-9_])ErrorCodeToError\( ]]; then
			original="$(sed -n "${lineno}p" "${file}")"
			# Strip leading indentation with native expansion (shellcheck SC2001).
			trimmed="${original#"${original%%[![:space:]]*}"}"
			report="${report}  ${rel}:${lineno}: ${trimmed}"$'\n'
			violations=$((violations + 1))
		fi
	done <<<"${stripped}"
done < <(find "${SCAN_ROOT}" \
	-type d \( -name .git -o -name release -o -name vendor -o -name node_modules \) -prune -o \
	-type f -name '*.go' -print)

if [[ ${violations} -gt 0 ]]; then
	cat >&2 <<EOF
ERROR: ErrorCodeToError() called outside ${ALLOWED_PREFIX}

${report}
ErrorCodeToError returns a nil *Error for unregistered (extension) codes.
Assigned into an 'error' variable that becomes a non-nil interface wrapping a
nil pointer, so 'err != nil' is true and the following err.Error() panics on a
nil receiver.

Call common.ErrorFromResponse(code, message) instead. It returns the canonical
error for known codes and a populated, non-nil *Error for extension codes, so
the result is always safe to assign into an 'error'.
EOF
	exit 1
fi

echo "OK: ErrorCodeToError has no callers outside ${ALLOWED_PREFIX}"
