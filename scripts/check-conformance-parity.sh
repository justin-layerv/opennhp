#!/usr/bin/env bash
# check-conformance-parity.sh
# ----------------------------------------------------------------------------
# Fail if the two NHP legs that BOTH consume the qURL issuer-signature golden
# vectors end up pinning byte-DIFFERENT copies of that file.
#
# Two legs, two ecosystems, two independent pins:
#   - the Go server reads github.com/layervai/qurl-conformance, pinned in
#     endpoints/go.mod (go:embed of its vectors/, fed to the qurlv2 tests).
#   - the browser js-agent reads npm @layervai/qurl-conformance, pinned in
#     endpoints/js-agent/package.json.
# Today both pins resolve to a byte-identical issuer_signature_vectors.json,
# but nothing stops a future one-sided bump (e.g. bumping only the Go pin) from
# shipping two DIFFERENT signature contracts to the two halves of the same wire
# protocol. That split would let the browser and the server disagree on what a
# valid issuer signature is — exactly the kind of silent cross-ecosystem drift
# the conformance package exists to prevent. This check compares the ACTUAL
# bytes each side resolves and fails the build if they differ.
#
# SCOPE — issuer_signature_vectors.json is the ONLY vectors file BOTH legs
# consume, so it is the only cross-ecosystem parity that matters here. The Go
# server also embeds qv2_conformance_vectors.json (strict_base64 / claims
# classes), but the js-agent does not read that file, so there is no second
# party to drift against and nothing to cross-check for it.
#
# Each side's own toolchain already asserts its implementation against its own
# copy (the Go qurlv2 tests; the js-agent vitest suite) — this is the missing
# cross-check that those two copies are the SAME bytes, which neither side can
# see on its own.
#
# Usage:
#   ./scripts/check-conformance-parity.sh   # exit 0 if equal, 1 on drift
# It is self-contained: it runs `go mod download` and `npm ci` itself so the
# local invocation resolves the exact same bytes CI does. The Go module cache
# is read-only (0444) — this script only reads it.
#
# TEST SEAM — set GO_VECTOR and/or NPM_VECTOR in the environment to a path and
# that side's network resolution (`go mod download` / `npm ci`) is skipped and
# the given path is compared directly. The fixture test
# (tests/scripts/check-conformance-parity_test.sh) sets BOTH to synthetic files
# to exercise the compare/guard/exit-code logic with no toolchain. With both
# unset (the real CI run) resolution and behavior are unchanged.
#
# REPO_ROOT is derived from this script's own location (not git) so it works
# from any cwd and in a fixture/temp checkout.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODULE_PATH="github.com/layervai/qurl-conformance"
NPM_PACKAGE="@layervai/qurl-conformance"
VECTOR_FILE="issuer_signature_vectors.json"

ENDPOINTS_DIR="${REPO_ROOT}/endpoints"
JS_AGENT_DIR="${ENDPOINTS_DIR}/js-agent"

# TEST SEAM — the two resolve blocks below are each skipped when their
# resolved-path var (GO_VECTOR / NPM_VECTOR) is ALREADY set in the environment.
# That lets the fixture test (tests/scripts/check-conformance-parity_test.sh)
# inject two synthetic paths and exercise the compare/guard/exit-code logic with
# NO network (no `go mod download`, no `npm ci`). When BOTH vars are unset — the
# real CI run — every line below executes exactly as before, so behavior is
# unchanged for the production path. Only resolution is bypassable; the
# missing-file guard and the cmp/sha compare downstream always run.

# --- Go side -----------------------------------------------------------------
# Resolve the version from endpoints/go.mod (the require block is tab-indented,
# so match on the first field) and read the embedded vector out of the module
# cache. Fetch it first so a cold cache resolves the same bytes CI would.
if [ -z "${GO_VECTOR:-}" ]; then
  GO_VERSION="$(awk -v mod="$MODULE_PATH" '$1 == mod { print $2; exit }' "${ENDPOINTS_DIR}/go.mod")"
  if [ -z "${GO_VERSION}" ]; then
    echo "ERROR: could not resolve ${MODULE_PATH} version from ${ENDPOINTS_DIR}/go.mod" >&2
    exit 1
  fi

  ( cd "${ENDPOINTS_DIR}" && go mod download "${MODULE_PATH}" )
  GOMODCACHE="$(cd "${ENDPOINTS_DIR}" && go env GOMODCACHE)"
  GO_VECTOR="${GOMODCACHE}/${MODULE_PATH}@${GO_VERSION}/vectors/${VECTOR_FILE}"
fi
# When GO_VECTOR was injected, no version was resolved; keep the log lines below
# safe under `set -u` without claiming a pin we did not read.
GO_VERSION="${GO_VERSION:-<injected>}"

# --- npm side ----------------------------------------------------------------
# Read the version package.json pins for the log, and install so the file lands
# in node_modules. `npm ci` honours package-lock.json exactly. Read the version
# via fs (not require of a relative path) so it is independent of this script's
# cwd and of the js-agent package's "type": "module".
if [ -z "${NPM_VECTOR:-}" ]; then
  NPM_VERSION="$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).devDependencies["'"${NPM_PACKAGE}"'"] ?? ""' "${JS_AGENT_DIR}/package.json" 2>/dev/null \
    || true)"
  ( cd "${JS_AGENT_DIR}" && npm ci )
  NPM_VECTOR="${JS_AGENT_DIR}/node_modules/${NPM_PACKAGE}/vectors/${VECTOR_FILE}"
fi
NPM_VERSION="${NPM_VERSION:-<injected>}"

# --- both files must actually exist (a missing path is the classic false-green)
for f in "${GO_VECTOR}" "${NPM_VECTOR}"; do
  if [ ! -f "${f}" ]; then
    echo "ERROR: expected vector file does not exist: ${f}" >&2
    echo "       (a missing path must FAIL, not silently compare empty strings)" >&2
    exit 1
  fi
done

# --- sha256 both (portable: prefer sha256sum, fall back to shasum on macOS) ---
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
GO_SHA="$(sha256_of "${GO_VECTOR}")"
NPM_SHA="$(sha256_of "${NPM_VECTOR}")"

echo "Go pin  (endpoints/go.mod):            ${MODULE_PATH} ${GO_VERSION}"
echo "npm pin (js-agent/package.json):       ${NPM_PACKAGE} ${NPM_VERSION:-<unresolved>}"
echo "Go  ${VECTOR_FILE}: ${GO_SHA}"
echo "npm ${VECTOR_FILE}: ${NPM_SHA}"

# Exact-bytes compare. cmp is the authority (sha is for the log); both agree.
if cmp -s "${GO_VECTOR}" "${NPM_VECTOR}"; then
  echo "OK: Go and npm resolve byte-identical ${VECTOR_FILE} (sha256 ${GO_SHA})."
  exit 0
fi

{
  echo "DRIFT: the Go server and the js-agent resolve DIFFERENT ${VECTOR_FILE}."
  echo "  Go pin : ${MODULE_PATH} ${GO_VERSION}  (sha256 ${GO_SHA})"
  echo "  npm pin: ${NPM_PACKAGE} ${NPM_VERSION:-<unresolved>}  (sha256 ${NPM_SHA})"
  echo "  Both legs share one wire contract and MUST consume the same bytes."
  echo "  Re-align the two pins (endpoints/go.mod vs endpoints/js-agent/package.json)"
  echo "  to versions of qurl-conformance whose ${VECTOR_FILE} is identical."
} >&2
exit 1
