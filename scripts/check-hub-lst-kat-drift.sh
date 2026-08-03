#!/usr/bin/env bash
# check-hub-lst-kat-drift.sh
# ----------------------------------------------------------------------------
# Fail if the Hub LST cookie-proof digest KAT in this repo has drifted from the
# CANONICAL copy published by layervai/qurl-conformance.
#
# nhp/core/hub_lst_cookie_test.go's TestHubLSTCookieProofDigestKAT and
# qurl-conformance's vectors/connector_hub_lst_cookie_v1_vectors.json
# (`proof_digest_kat`) are the SAME known-answer test written down twice: the
# same server static public key, the same 208-byte header prefix, the same raw
# cookie, and the same expected BLAKE2s digest. The Go copy is hand-typed.
#
# THE GAP THIS CLOSES — the Go test only proves this repo's implementation agrees
# with this repo's own copy of the answer. If someone regenerates the vectors
# upstream (or edits the Go literal to make a failing test pass), both sides stay
# internally consistent and every suite stays green while the two repos silently
# disagree about the wire. That is exactly what happened at the 1.0 -> 1.1 header
# binding: the header prefix carries the version bytes, so ANY change to the
# HeaderCommon transcript moves this KAT in both repos at once. Nothing compared
# them. This check does.
#
# WHY NOT scripts/check-golden-vectors.sh — that fence pairs a Go file with a
# TypeScript file INSIDE this repo, and adding markers alone cannot cover this
# KAT: the js-agent implements no Hub LST cookie proof, so there is no in-repo
# second copy to compare against. The drift here is cross-REPO, not
# cross-language, which is the shape scripts/check-agent-reg-vector-drift.sh
# already handles — this script follows it deliberately, including its skip
# semantics. The `nhp-golden-vector:` markers are still the extraction
# convention, shared with check-golden-vectors.sh so there is one marker syntax
# to learn; only the far side of the comparison differs.
#
# SOURCE REF — the canonical vectors are fetched from qurl-conformance at the ref
# named below, a single knob. It points at `main`, which has carried the protocol
# 1.1 vectors since layervai/qurl-conformance#71 merged. WHEN qurl-conformance
# cuts a release carrying them (the tags at v0.11.0 and earlier still hold the 1.0
# KAT), re-point to that `vX.Y.Z` tag so the compare is against a frozen artifact
# rather than a moving branch head — and bump endpoints/go.mod to the same
# release in the same change.
#
# NETWORK / ABSENCE TOLERANCE — a drift detector must fail LOUD on real drift but
# must NOT redden CI for unrelated reasons:
#   * FETCH FAILURE (network, GitHub 5xx, auth/rate-limit) => SKIP, exit 0. An
#     outage is not drift, and the Go test still pins the local copy meanwhile.
#   * FILE ABSENT AT THE SOURCE REF (HTTP 404) => FAILURE, exit 1. This differs
#     from scripts/check-agent-reg-vector-drift.sh, whose canonical is not on its
#     source ref yet and so tolerates a 404 as a pre-publication state. Ours IS
#     published on `main`, so a 404 can only mean the file was moved or removed
#     upstream — silently skipping would turn this fence off exactly when the
#     contract it guards has changed.
#   * PRESENT + VALUES DIFFER => DRIFT. Exit 1 with remediation.
#   * PRESENT + VALUES EQUAL => OK. Exit 0.
#
# Usage:
#   ./scripts/check-hub-lst-kat-drift.sh   # 0 ok/skip, 1 on real drift
#
# TEST SEAM — set REMOTE_VECTOR to a path (or the literal `__ABSENT__` /
# `__FETCHFAIL__`) and the network fetch is skipped; the given path (or the
# simulated 404 / fetch failure) drives the compare/skip/exit logic directly. The
# fixture test (tests/scripts/check-hub-lst-kat-drift_test.sh) uses this to
# exercise every branch with NO network and NO gh. Unset (the real run), fetch
# and behavior are unchanged. LOCAL_KAT_FILE overrides the local Go file for the
# same reason.
#
# REPO_ROOT is derived from this script's own location (not git) so it works from
# any cwd and in a fixture/temp checkout.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Remove the fetched canonical body on EVERY exit path (OK, DRIFT, each SKIP) so
# a repeated local run does not litter TMPDIR. Written as an INLINE trap rather
# than a named function so a linter cannot flag the body as never-invoked. The
# trailing `|| true` keeps the trap's own status 0 so it never overrides an
# `exit N` set upstream.
_tmpfile=""
trap 'rm -f "${_tmpfile}" 2>/dev/null || true' EXIT

# --- what we compare ---------------------------------------------------------
CANONICAL_REPO="layervai/qurl-conformance"
CANONICAL_PATH="vectors/connector_hub_lst_cookie_v1_vectors.json"
# See "SOURCE REF" above. Re-point to the release tag once one carries the 1.1
# vectors; v0.11.0 and earlier still hold the 1.0 KAT.
CANONICAL_REF="main"

LOCAL_KAT_FILE="${LOCAL_KAT_FILE:-${REPO_ROOT}/nhp/core/hub_lst_cookie_test.go}"

MARKER="nhp-golden-vector:"

# Marked label in the Go file -> jq path under the canonical's proof_digest_kat.
# Both sides of every row are the same value written down in two repos; adding a
# row is how you extend this fence.
KAT_FIELDS=(
  "hub-lst-proof-server-static-pubkey|hub_server_static_public_key_hex"
  "hub-lst-proof-header-prefix|header_prefix_hex"
  "hub-lst-proof-raw-cookie|raw_cookie_hex"
  "hub-lst-proof-expected-digest|expected_digest_hex"
)

# --- the local copy must exist (its absence is a repo defect, not a skip) -----
if [ ! -f "${LOCAL_KAT_FILE}" ]; then
  echo "ERROR: local KAT file not found: ${LOCAL_KAT_FILE}" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: 'jq' not available to read ${CANONICAL_PATH}." >&2
  exit 0
fi

# --- extract one marked value from the local Go file -------------------------
# Same pattern as scripts/check-golden-vectors.sh: a quoted value immediately
# followed by the trailing `//` marker comment. Anchoring on the `//` AFTER the
# quote is what keeps prose that merely mentions a label from matching.
local_value() {
  local label="$1"
  sed -nE "s/^.*\"([^\"]*)\"[,;[:space:]]*\/\/.*${MARKER}[[:space:]]*${label}([[:space:]]|$).*/\1/p" \
    "${LOCAL_KAT_FILE}"
}

# --- fetch the canonical bytes into REMOTE_FILE, or SKIP ---------------------
# TEST SEAM: REMOTE_VECTOR=__FETCHFAIL__ | __ABSENT__ | <path>
REMOTE_FILE=""
fetch_canonical() {
  if [ -n "${REMOTE_VECTOR:-}" ]; then
    case "${REMOTE_VECTOR}" in
      __FETCHFAIL__)
        echo "SKIP: could not fetch ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} (simulated fetch failure)." >&2
        echo "      A fetch failure is not KAT drift; the Go test still pins the local copy." >&2
        exit 0
        ;;
      __ABSENT__)
        echo "ERROR: ${CANONICAL_PATH} does not exist at ${CANONICAL_REPO}@${CANONICAL_REF} (simulated HTTP 404)." >&2
        echo "       It is published on that ref, so a 404 means it moved or was removed upstream." >&2
        exit 1
        ;;
      *)
        if [ ! -f "${REMOTE_VECTOR}" ]; then
          echo "ERROR: injected REMOTE_VECTOR path does not exist: ${REMOTE_VECTOR}" >&2
          exit 1
        fi
        REMOTE_FILE="${REMOTE_VECTOR}"
        return 0
        ;;
    esac
  fi

  if ! command -v gh >/dev/null 2>&1; then
    echo "SKIP: 'gh' CLI not available to fetch the canonical ${CANONICAL_PATH}." >&2
    echo "      Install/authenticate the GitHub CLI to run the upstream drift check." >&2
    exit 0
  fi

  # Two-phase, matching check-agent-reg-vector-drift.sh: a `-i` request to read
  # the status line for classification, then on 200 a plain `gh api` whose stdout
  # is the raw body with no header block to strip. `gh` exits non-zero on non-2xx,
  # so we ignore its status and classify on the parsed status line; an empty
  # status (request never reached GitHub) falls through to the generic skip.
  local http
  http="$(gh api \
    "repos/${CANONICAL_REPO}/contents/${CANONICAL_PATH}?ref=${CANONICAL_REF}" \
    -H "Accept: application/vnd.github.raw" \
    -i --cache 0 2>/dev/null | awk 'NR==1{print $2; exit}')" || true

  case "${http}" in
    200)
      _tmpfile="$(mktemp)"
      if ! gh api \
        "repos/${CANONICAL_REPO}/contents/${CANONICAL_PATH}?ref=${CANONICAL_REF}" \
        -H "Accept: application/vnd.github.raw" \
        --cache 0 > "${_tmpfile}" 2>/dev/null; then
        echo "SKIP: body fetch for ${CANONICAL_PATH} failed after a 200 status (transient)." >&2
        exit 0
      fi
      if [ ! -s "${_tmpfile}" ]; then
        echo "SKIP: fetched an EMPTY ${CANONICAL_PATH} (fetch anomaly); refusing to compare against empty bytes." >&2
        exit 0
      fi
      REMOTE_FILE="${_tmpfile}"
      return 0
      ;;
    404)
      # Not a skip: the canonical IS published on CANONICAL_REF, so a 404 means
      # it was moved or removed upstream — the fence must alarm, not go quiet.
      echo "ERROR: ${CANONICAL_PATH} does not exist at ${CANONICAL_REPO}@${CANONICAL_REF} (HTTP 404)." >&2
      echo "       It was moved or removed upstream; re-point CANONICAL_PATH/CANONICAL_REF." >&2
      exit 1
      ;;
    *)
      echo "SKIP: could not fetch ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} (status '${http:-none}')." >&2
      echo "      A fetch failure is not KAT drift; the Go test still pins the local copy." >&2
      exit 0
      ;;
  esac
}

fetch_canonical

if ! jq -e '.proof_digest_kat' "${REMOTE_FILE}" >/dev/null 2>&1; then
  echo "ERROR: ${CANONICAL_PATH} at ${CANONICAL_REPO}@${CANONICAL_REF} has no 'proof_digest_kat' object." >&2
  echo "       The canonical layout changed; update KAT_FIELDS in this script." >&2
  exit 1
fi

status=0
compared=0
for row in "${KAT_FIELDS[@]}"; do
  label="${row%%|*}"
  field="${row##*|}"

  got="$(local_value "${label}")"
  if [ -z "${got}" ]; then
    echo "ERROR: no '${MARKER} ${label}' vector found in ${LOCAL_KAT_FILE}" >&2
    echo "       expected a line like: name = \"<hex>\" // ${MARKER} ${label}" >&2
    status=1
    continue
  fi
  # More than one match means a duplicated marker; comparing a concatenation
  # would be nonsense, so report it instead (mirrors check-golden-vectors.sh).
  if [ "$(printf '%s\n' "${got}" | wc -l | tr -d ' ')" != "1" ]; then
    echo "ERROR: duplicate '${MARKER} ${label}' marker in ${LOCAL_KAT_FILE}; each label must be unique." >&2
    status=1
    continue
  fi

  want="$(jq -r --arg f "${field}" '.proof_digest_kat[$f] // empty' "${REMOTE_FILE}")"
  if [ -z "${want}" ]; then
    echo "ERROR: canonical proof_digest_kat has no '${field}' (mapped from ${label})." >&2
    status=1
    continue
  fi

  if [ "${got}" != "${want}" ]; then
    {
      echo "DRIFT: Hub LST proof KAT '${label}' disagrees across repos."
      echo "  local  (${LOCAL_KAT_FILE#"${REPO_ROOT}"/}): ${got}"
      echo "  canonical (${CANONICAL_REPO}@${CANONICAL_REF} ${CANONICAL_PATH} .proof_digest_kat.${field}): ${want}"
    } >&2
    status=1
    continue
  fi
  compared=$((compared + 1))
done

if [ "${status}" -ne 0 ]; then
  {
    echo ""
    echo "  This KAT is one value written down in two repos and they MUST agree."
    echo "  The header prefix carries the protocol version bytes, so any change to"
    echo "  the HeaderCommon transcript moves it on BOTH sides at once. Regenerate"
    echo "  the qurl-conformance vectors and re-copy all four literals together —"
    echo "  do not edit one side to make a red test green."
  } >&2
  exit 1
fi

echo "OK: Hub LST proof KAT lockstep with ${CANONICAL_REPO}@${CANONICAL_REF} (${compared} values)."
