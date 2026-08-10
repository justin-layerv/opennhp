#!/usr/bin/env bash
# Regression fixtures for scripts/check-golangci-config-schema.py.
#
# The point of that script is to catch config mistakes that `golangci-lint
# run` does NOT catch — unknown top-level keys and unknown nested keys are
# both silently ignored by the linter itself, so a typo reads as an enabled
# setting doing nothing. These fixtures pin that it actually does, plus every
# condition that keeps the vendored copy honest: version lockstep, the sidecar
# digest, self-containment (a remote $ref would refetch at check time), and
# that `verify:` cannot be satisfied by a different step.
#
# Fixtures run before the real check in `make lint-workflows` so a regex or
# validator regression surfaces against known inputs first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-golangci-config-schema.py"
REAL_SCHEMA_DIR="${REPO_ROOT}/.github/schemas"

PASS=0
FAILED=0

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# A minimal stand-in for the real ubuntu-build.yml lint step. Indentation
# matches the real file so the step regex is exercised as deployed.
write_workflow() {
  local dest="$1" version="$2" verify="$3"
  {
    printf 'jobs:\n  lint:\n'
    printf '    strategy:\n      matrix:\n        module: [nhp, internalauth, endpoints, tests/e2e]\n'
    printf '    steps:\n'
    printf '    - name: Run golangci-lint\n'
    printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
    printf '      with:\n'
    printf '        version: %s\n' "${version}"
    if [[ -n "${verify}" ]]; then
      printf '        verify: %s\n' "${verify}"
    fi
    printf '        working-directory: nhp\n'
  } >"${dest}"
}

run_case() {
  local name="$1" want_exit="$2" workflow="$3" config="$4" schema_dir="$5" want_text="${6:-}"
  local out rc=0
  out="$(python3 "${LINT_SCRIPT}" \
    --workflow "${workflow}" --config "${config}" --schema-dir "${schema_dir}" 2>&1)" || rc=$?
  if [[ "${rc}" -ne "${want_exit}" ]]; then
    printf '  FAIL: %-46s (exit %s, wanted %s)\n' "${name}" "${rc}" "${want_exit}"
    printf '        %s\n' "${out}"
    FAILED=$((FAILED + 1))
    return
  fi
  if [[ -n "${want_text}" ]] && ! grep -qF "${want_text}" <<<"${out}"; then
    printf '  FAIL: %-46s (exit ok, but message lacked %q)\n' "${name}" "${want_text}"
    printf '        %s\n' "${out}"
    FAILED=$((FAILED + 1))
    return
  fi
  printf '  PASS: %-46s (exit %s as expected)\n' "${name}" "${rc}"
  PASS=$((PASS + 1))
}

GOOD_WF="${WORK}/good-workflow.yml"
write_workflow "${GOOD_WF}" "v2.11.4" "false"

# The real config is the valid fixture: if it ever stops validating, the
# suite says so here rather than only in the live check.
run_case "real config validates" 0 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# --- the two cases `golangci-lint run` silently ignores -------------------
UNKNOWN_TOP="${WORK}/unknown-top.yml"
cp "${REPO_ROOT}/.golangci.yml" "${UNKNOWN_TOP}"
printf 'bogus_top_level_key: true\n' >>"${UNKNOWN_TOP}"
run_case "unknown top-level key rejected" 1 \
  "${GOOD_WF}" "${UNKNOWN_TOP}" "${REAL_SCHEMA_DIR}" "bogus_top_level_key"

UNKNOWN_NESTED="${WORK}/unknown-nested.yml"
python3 - "${REPO_ROOT}/.golangci.yml" "${UNKNOWN_NESTED}" <<'PY'
import sys
src, dest = sys.argv[1], sys.argv[2]
text = open(src).read()
assert "    govet:\n" in text, "fixture assumes a linters.settings.govet block"
open(dest, "w").write(text.replace("    govet:\n", "    govet:\n      bogus_nested_key: 42\n", 1))
PY
run_case "unknown nested key rejected" 1 \
  "${GOOD_WF}" "${UNKNOWN_NESTED}" "${REAL_SCHEMA_DIR}" "bogus_nested_key"

# --- lockstep: the vendored copy must track the pin ----------------------
BUMPED_WF="${WORK}/bumped-workflow.yml"
write_workflow "${BUMPED_WF}" "v2.99.0" "false"
run_case "version bump without a vendored schema" 1 \
  "${BUMPED_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "is not vendored"

# A patch bump inside the same minor reuses the vendored file: upstream
# publishes per major.minor, so v2.11.4 -> v2.11.9 must NOT demand a refresh.
PATCH_WF="${WORK}/patch-workflow.yml"
write_workflow "${PATCH_WF}" "v2.11.9" "false"
run_case "patch bump reuses the same-minor schema" 0 \
  "${PATCH_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# --- lockstep: the flake must not be able to come back -------------------
VERIFY_ON="${WORK}/verify-on.yml"
write_workflow "${VERIFY_ON}" "v2.11.4" "true"
run_case "verify: true flagged (network fetch returns)" 1 \
  "${VERIFY_ON}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "must set \`verify: false\`"

VERIFY_ABSENT="${WORK}/verify-absent.yml"
write_workflow "${VERIFY_ABSENT}" "v2.11.4" ""
run_case "verify omitted flagged (defaults to true)" 1 \
  "${VERIFY_ABSENT}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "must set \`verify: false\`"

# --- the vendored bytes must be upstream's -------------------------------
# A hand-edited schema could be used to make an invalid config "pass", so the
# sidecar digest is enforced, not merely recorded.
TAMPERED_DIR="${WORK}/tampered-schema"
mkdir -p "${TAMPERED_DIR}"
cp "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json.sha256" "${TAMPERED_DIR}/"
python3 - "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" \
  "${TAMPERED_DIR}/golangci.v2.11.jsonschema.json" <<'PY'
import json, sys
schema = json.load(open(sys.argv[1]))
# The edit a bad actor (or a frustrated maintainer) would actually make.
schema["additionalProperties"] = True
json.dump(schema, open(sys.argv[2], "w"))
PY
run_case "hand-edited schema rejected by its digest" 1 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${TAMPERED_DIR}" "does not match"

NO_DIGEST_DIR="${WORK}/no-digest"
mkdir -p "${NO_DIGEST_DIR}"
cp "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" "${NO_DIGEST_DIR}/"
run_case "vendored schema with no sidecar digest" 1 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${NO_DIGEST_DIR}" "no golangci.v2.11.jsonschema.json.sha256"

# --- a later step must not satisfy the golangci step's `verify:` ---------
# The with-block capture stops at the next step start. Without that, this
# workflow would read as compliant: the golangci step has no `verify:` at all,
# and the `verify: false` belongs to an unrelated step below it.
LATER_STEP_WF="${WORK}/later-step-verify.yml"
{
  printf 'jobs:\n  lint:\n    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n'
  printf '        version: v2.11.4\n'
  printf '        working-directory: nhp\n'
  printf '    - name: Some later step\n'
  printf '      uses: example/other-action@abc123\n'
  printf '      with:\n'
  printf '        verify: false\n'
} >"${LATER_STEP_WF}"
run_case "later step's verify: false does not count" 1 \
  "${LATER_STEP_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "must set \`verify: false\`"

# --- offline-ness depends on the schema being self-contained -------------
REMOTE_REF_DIR="${WORK}/remote-ref"
mkdir -p "${REMOTE_REF_DIR}"
python3 - "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" \
  "${REMOTE_REF_DIR}/golangci.v2.11.jsonschema.json" <<'PY'
import json, sys
schema = json.load(open(sys.argv[1]))
# What an upstream refresh could plausibly reintroduce.
schema["properties"]["run"] = {"$ref": "https://json.schemastore.org/partial.json"}
json.dump(schema, open(sys.argv[2], "w"))
PY
shasum -a 256 "${REMOTE_REF_DIR}/golangci.v2.11.jsonschema.json" | awk '{print $1}' \
  >"${REMOTE_REF_DIR}/golangci.v2.11.jsonschema.json.sha256"
run_case "remote \$ref rejected (would refetch at check time)" 1 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${REMOTE_REF_DIR}" "external \$ref"

# --- a per-module config would win for that module and go unvalidated ----
# Scoped to the lint matrix's modules, so this is drivable from a temp tree
# (the earlier repo-wide rglob version was untestable, and would have
# false-positived on any vendored dependency shipping its own config).
STRAY_ROOT="${WORK}/stray-root"
mkdir -p "${STRAY_ROOT}/endpoints"
cp "${REPO_ROOT}/.golangci.yml" "${STRAY_ROOT}/.golangci.yml"
cp "${REPO_ROOT}/.golangci.yml" "${STRAY_ROOT}/endpoints/.golangci.yml"
run_case "per-module config in a matrix module is flagged" 1 \
  "${GOOD_WF}" "${STRAY_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "endpoints/.golangci.yml"

# A config outside the matrix modules (a vendored dependency's own, say) does
# not govern this repo's lint and must NOT trip the fence.
VENDOR_ROOT="${WORK}/vendor-root"
mkdir -p "${VENDOR_ROOT}/vendor/github.com/someone/lib"
cp "${REPO_ROOT}/.golangci.yml" "${VENDOR_ROOT}/.golangci.yml"
cp "${REPO_ROOT}/.golangci.yml" "${VENDOR_ROOT}/vendor/github.com/someone/lib/.golangci.yml"
run_case "a vendored dependency's own config is ignored" 0 \
  "${GOOD_WF}" "${VENDOR_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# --- value anchoring: `falsely` is not `false` ---------------------------
VERIFY_FALSELY_WF="${WORK}/verify-falsely.yml"
write_workflow "${VERIFY_FALSELY_WF}" "v2.11.4" "falsely"
run_case "verify: falsely does not read as disabled" 1 \
  "${VERIFY_FALSELY_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "must set \`verify: false\`"

# A trailing comment after the value is legal YAML and must still match.
VERIFY_COMMENT_WF="${WORK}/verify-comment.yml"
write_workflow "${VERIFY_COMMENT_WF}" "v2.11.4" "false  # offline check owns this"
run_case "verify: false with a trailing comment still matches" 0 \
  "${VERIFY_COMMENT_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# --- a shape change must fail closed, not scan nothing --------------------
# A block-style matrix used to return an empty module list, which made the
# stray check silently examine nothing — deleting the guarantee without
# turning anything red.
BLOCK_MATRIX_WF="${WORK}/block-matrix.yml"
{
  printf 'jobs:\n  lint:\n'
  printf '    strategy:\n      matrix:\n        module:\n          - nhp\n          - endpoints\n'
  printf '    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n        version: v2.11.4\n        verify: false\n'
} >"${BLOCK_MATRIX_WF}"
run_case "block-style matrix fails closed, not silently empty" 2 \
  "${BLOCK_MATRIX_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "matrix.module"

# --- two golangci steps make "which pin?" ambiguous ----------------------
# The ACTION_PREFIX comment always claimed this was worth failing on; the
# first-match search quietly picked one instead.
TWO_STEPS_WF="${WORK}/two-steps.yml"
{
  printf 'jobs:\n  lint:\n'
  printf '    strategy:\n      matrix:\n        module: [nhp]\n'
  printf '    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n        version: v2.11.4\n        verify: false\n'
  printf '    - name: Run golangci-lint again\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n        version: v2.99.0\n        verify: true\n'
} >"${TWO_STEPS_WF}"
run_case "two golangci-lint steps are ambiguous, not first-wins" 2 \
  "${TWO_STEPS_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "ambiguous"

# --- a nested block sequence in `with:` must not truncate the mapping ----
# The regex this replaced stopped at any `- ` line, so a block-list value
# before version:/verify: hid them and produced a bogus complaint about a
# config that was correct.
BLOCK_SEQ_WF="${WORK}/block-seq.yml"
{
  printf 'jobs:\n  lint:\n'
  printf '    strategy:\n      matrix:\n        module: [nhp]\n'
  printf '    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n'
  printf '        args:\n          - --foo\n          - --bar\n'
  printf '        version: v2.11.4\n'
  printf '        verify: false\n'
} >"${BLOCK_SEQ_WF}"
run_case "block sequence before version/verify still parses" 0 \
  "${BLOCK_SEQ_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# Same for a blank line inside the mapping, which also used to truncate it.
BLANK_LINE_WF="${WORK}/blank-line.yml"
{
  printf 'jobs:\n  lint:\n'
  printf '    strategy:\n      matrix:\n        module: [nhp]\n'
  printf '    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n'
  printf '        version: v2.11.4\n'
  printf '\n'
  printf '        verify: false\n'
} >"${BLANK_LINE_WF}"
run_case "blank line inside with: no longer truncates it" 0 \
  "${BLANK_LINE_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

# --- bad input is distinguished from drift -------------------------------
MALFORMED_DIR="${WORK}/malformed-schema"
mkdir -p "${MALFORMED_DIR}"
printf '{"type": "object",\n' >"${MALFORMED_DIR}/golangci.v2.11.jsonschema.json"
shasum -a 256 "${MALFORMED_DIR}/golangci.v2.11.jsonschema.json" | awk '{print $1}' \
  >"${MALFORMED_DIR}/golangci.v2.11.jsonschema.json.sha256"
run_case "malformed schema JSON is bad input, not drift" 2 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${MALFORMED_DIR}" "not valid JSON"

# A step key between `uses:` and `with:` is legal YAML that the pre-parser
# regex could not handle; structural parsing takes it in stride.
STEP_KEY_WF="${WORK}/step-key.yml"
{
  printf 'jobs:\n  lint:\n'
  printf '    strategy:\n      matrix:\n        module: [nhp]\n'
  printf '    steps:\n'
  printf '    - name: Run golangci-lint\n'
  printf '      uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      id: golangci\n'
  printf '      with:\n'
  printf '        version: v2.11.4\n'
  printf '        verify: false\n'
} >"${STEP_KEY_WF}"
# Structural parsing handles this; the old regex demanded `with:` follow
# `uses:` with only comments between, and reported a bogus verify complaint.
run_case "a step key between uses: and with: parses fine" 0 \
  "${STEP_KEY_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

EMPTY_DIGEST_DIR="${WORK}/empty-digest"
mkdir -p "${EMPTY_DIGEST_DIR}"
cp "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" "${EMPTY_DIGEST_DIR}/"
: >"${EMPTY_DIGEST_DIR}/golangci.v2.11.jsonschema.json.sha256"
run_case "empty sidecar digest is bad input, not a traceback" 2 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${EMPTY_DIGEST_DIR}" "is empty"

# Parseable JSON that is not a valid schema: exit 2, matching the JSON branch.
BAD_SCHEMA_DIR="${WORK}/bad-schema"
mkdir -p "${BAD_SCHEMA_DIR}"
python3 - "${BAD_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" <<'PY'
import json, sys
# Parseable JSON, but `type` must be a string or array — not a valid schema.
json.dump({"$schema": "http://json-schema.org/draft-07/schema#", "type": 42},
          open(sys.argv[1], "w"))
PY
shasum -a 256 "${BAD_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" | awk '{print $1}' \
  >"${BAD_SCHEMA_DIR}/golangci.v2.11.jsonschema.json.sha256"
run_case "structurally invalid schema is bad input, not drift" 2 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${BAD_SCHEMA_DIR}" "not a valid JSON Schema"

# A sibling-file ref resolves off disk, so it counts as external too.
FILE_REF_DIR="${WORK}/file-ref"
mkdir -p "${FILE_REF_DIR}"
python3 - "${REAL_SCHEMA_DIR}/golangci.v2.11.jsonschema.json" \
  "${FILE_REF_DIR}/golangci.v2.11.jsonschema.json" <<'PY'
import json, sys
schema = json.load(open(sys.argv[1]))
schema["properties"]["run"] = {"$ref": "sibling.json#/definitions/run"}
json.dump(schema, open(sys.argv[2], "w"))
PY
shasum -a 256 "${FILE_REF_DIR}/golangci.v2.11.jsonschema.json" | awk '{print $1}' \
  >"${FILE_REF_DIR}/golangci.v2.11.jsonschema.json.sha256"
run_case "relative-file \$ref also rejected" 1 \
  "${GOOD_WF}" "${REPO_ROOT}/.golangci.yml" "${FILE_REF_DIR}" "external \$ref"

MAJOR_ONLY_WF="${WORK}/major-only.yml"
write_workflow "${MAJOR_ONLY_WF}" "v2" "false"
run_case "version pin without a minor is bad input" 2 \
  "${MAJOR_ONLY_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "could not read"

# The dependency guard: `make lint-workflows` is documented as mirroring CI, so
# a missing local jsonschema must be an actionable message, not a traceback.
NO_DEP_DIR="${WORK}/no-jsonschema"
mkdir -p "${NO_DEP_DIR}"
printf 'raise ModuleNotFoundError("No module named %s", name=%s)\n' "'jsonschema'" "'jsonschema'" \
  >"${NO_DEP_DIR}/jsonschema.py"
dep_out="$(PYTHONPATH="${NO_DEP_DIR}" python3 "${LINT_SCRIPT}" 2>&1 || true)"
dep_rc=0
PYTHONPATH="${NO_DEP_DIR}" python3 "${LINT_SCRIPT}" >/dev/null 2>&1 || dep_rc=$?
if [[ "${dep_rc}" -eq 2 ]] && grep -qF "validate-workflows-requirements.txt" <<<"${dep_out}"; then
  printf '  PASS: %-46s (exit 2 as expected)\n' "missing jsonschema is actionable, not a traceback"
  PASS=$((PASS + 1))
else
  printf '  FAIL: %-46s (exit %s)\n' "missing jsonschema is actionable, not a traceback" "${dep_rc}"
  printf '        %s\n' "${dep_out}"
  FAILED=$((FAILED + 1))
fi

NO_PIN_WF="${WORK}/no-pin.yml"
{
  printf 'jobs:\n  lint:\n    steps:\n'
  printf '    - uses: golangci/golangci-lint-action@ba0d7d2 # v9.3.0\n'
  printf '      with:\n        verify: false\n        working-directory: nhp\n'
} >"${NO_PIN_WF}"
run_case "unreadable version pin is bad input, not drift" 2 \
  "${NO_PIN_WF}" "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "could not read"

BAD_YAML="${WORK}/bad.yml"
printf 'version: "2"\nlinters: [unclosed\n' >"${BAD_YAML}"
run_case "unparseable config is bad input, not drift" 2 \
  "${GOOD_WF}" "${BAD_YAML}" "${REAL_SCHEMA_DIR}" "not valid YAML"

# ubuntu-build.yml carries a comment block INSIDE the with: mapping (between
# `version:` and `verify:`), so parse the real file, not just the stand-ins.
run_case "real ubuntu-build.yml step parses" 0 \
  "${REPO_ROOT}/.github/workflows/ubuntu-build.yml" \
  "${REPO_ROOT}/.golangci.yml" "${REAL_SCHEMA_DIR}" "OK:"

if [[ "${FAILED}" -ne 0 ]]; then
  echo "${FAILED} golangci-config-schema fixture(s) failed." >&2
  exit 1
fi
echo "All ${PASS} golangci-config-schema fixtures passed."
