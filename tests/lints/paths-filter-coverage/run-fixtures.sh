#!/usr/bin/env bash
# Regression fixtures for scripts/check-paths-filter-coverage.py.
#
# Each fixture exercises one branch of the lint's contract:
#   exit 0 — every inner-filter pattern covered (or lint inapplicable)
#   exit 1 — at least one inner-filter pattern uncovered
#   exit 2 — malformed input or unsupported glob syntax
#
# The two `fail-*-gap.yml` fixtures retroactively reconstruct the
# real-world failures that motivated this lint:
#   .trivyignore (#1775/#1776) — pre-fix state had the path in the
#     inner filter but missing from on.push.paths, so a path-only
#     merge silently skipped the workflow.
#   packer/** (#252/#980) — same shape, fixed years earlier per the
#     in-file comment in build-and-push.yml.
# Either fixture passing here means the lint regressed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-paths-filter-coverage.py"
FIXTURE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "${LINT_SCRIPT}" ]]; then
	echo "ERROR: lint script not executable: ${LINT_SCRIPT}" >&2
	exit 1
fi

OUT_FILE="$(mktemp)"
trap 'rm -f "${OUT_FILE}"' EXIT

PASS=0
FAIL=0

run_fixture() {
	local name="$1" fixture="$2" expected="$3"
	local actual=0
	"${LINT_SCRIPT}" "${FIXTURE_DIR}/${fixture}" >"${OUT_FILE}" 2>&1 || actual=$?
	if [[ "${actual}" -ne "${expected}" ]]; then
		echo "  FAIL: ${name} — expected exit ${expected}, got ${actual}" >&2
		echo "        fixture: ${fixture}" >&2
		echo "        lint output:" >&2
		sed 's/^/          /' "${OUT_FILE}" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	printf '  PASS: %-50s (exit %d as expected)\n' "${name}" "${actual}"
	PASS=$((PASS + 1))
}

run_fixture "representative-shape-passes"          "pass-representative-shape.yml"     0

# Retroactive coverage of the two historical gaps.
run_fixture "trivyignore-gap-flagged-pre-1776"     "fail-trivyignore-gap.yml"          1
run_fixture "packer-gap-flagged-pre-252"           "fail-packer-gap.yml"               1

# Allowlist mechanism — pass/fail pair proves the annotation is
# load-bearing (a regression would either fail both or pass both).
run_fixture "annotation-exempts-meta-filter"       "pass-allowlisted-code-group.yml"   0
run_fixture "missing-annotation-still-flags"       "fail-annotation-removed.yml"       1
run_fixture "trailing-same-line-annotation-works"  "pass-trailing-allow.yml"           0
run_fixture "annotation-spans-blank-and-comment-lines" "pass-allowlist-spans-blank-lines.yml" 0
run_fixture "annotation-doesnt-leak-to-next-group" "fail-annotation-doesnt-leak.yml"   1
run_fixture "prose-mention-not-allowlist"          "fail-prose-mention-not-allowlist.yml" 1
run_fixture "allowlist-prefix-not-exact"           "fail-allowlist-prefix-not-exact.yml" 1

# Coverage semantics + skip path + bad-input.
run_fixture "ancestor-glob-covers-nested"          "pass-ancestor-glob.yml"            0
run_fixture "bare-dir-not-covered-by-dir-glob"     "fail-bare-dir-not-covered.yml"     1
run_fixture "no-push-paths-universal-coverage"     "pass-no-push-paths.yml"            0
run_fixture "bare-on-pyyaml-quirk-handled"         "pass-bare-on-pyyaml-quirk.yml"     0
run_fixture "no-paths-filter-step-skipped-silently" "skip-no-paths-filter.yml"         0
run_fixture "unsupported-glob-rejects-with-2"       "badinput-unsupported-glob.yml"    2
run_fixture "single-star-glob-rejected-with-2"      "badinput-single-star-glob.yml"    2
run_fixture "leading-doublestar-glob-rejected-2"    "badinput-leading-doublestar-glob.yml" 2
run_fixture "non-string-filter-value-rejected-2"    "badinput-non-string-filter-value.yml" 2
run_fixture "filters-from-source-file-rejected-2"   "badinput-filters-from-source-file.yml" 2
run_fixture "malformed-inner-yaml-rejected-2"       "badinput-malformed-inner-yaml.yml" 2
run_fixture "string-shorthand-value-rejected-2"     "badinput-string-shorthand-value.yml" 2
run_fixture "paths-ignore-not-modeled-rejected-2"   "badinput-paths-ignore-not-modeled.yml" 2

# Multiple `dorny/paths-filter` steps — every step must be checked,
# not just the first. Pair: passing case + second-step-uncovered.
run_fixture "multiple-paths-filter-steps-all-checked" "pass-multiple-paths-filter-steps.yml"        0
run_fixture "multiple-steps-second-uncovered-flagged" "fail-multiple-steps-second-uncovered.yml"    1

# pull_request.paths shares the failure class with push.paths —
# inner-filter pattern absent from the PR trigger silently skips
# validation jobs at PR time. Pin it.
run_fixture "pull-request-paths-gap-flagged"       "fail-pull-request-paths-gap.yml"   1

if [[ "${FAIL}" -gt 0 ]]; then
	echo "" >&2
	echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
	exit 1
fi
echo "All ${PASS} paths-filter-coverage fixtures passed."
