#!/usr/bin/env bash
# check-agent-reg-vector-drift.sh
# ----------------------------------------------------------------------------
# Fail if the LOCAL vendored NHP agent-registration golden vectors have drifted
# from the CANONICAL copy published by layervai/qurl-conformance.
#
# nhp/core/testdata/agent_registration_golden.json is a byte-for-byte re-host of
# qurl-conformance's vectors/agent_registration_golden.json (nhp stays
# dependency-free — the js-agent knock.json precedent). nhp/core's roundtrip
# fence (agent_registration_roundtrip_test.go) pins the local copy with a
# hardcoded agentRegFixtureSHA256 constant.
#
# THE GAP THIS CLOSES (nhp#3138) — that SHA pin compares the LOCAL copy against a
# LOCAL constant, both in this repo. It catches an accidental local edit or a
# partial re-sync (JSON touched without the constant, or vice versa). It does
# NOT catch a silent UPSTREAM drift: if the canonical qurl-conformance artifact
# changes and nobody re-syncs this repo, the local bytes and the local constant
# stay mutually consistent, so the fence stays green against stale bytes. This
# check is the missing cross-repo half: it FETCHES the canonical artifact and
# byte-compares it against the vendored copy, failing the build on drift.
#
# SOURCE REF — the canonical file is fetched from qurl-conformance at the ref
# named below. It is set here as a single easy-to-re-point knob:
#   * TODAY it points at the branch that first introduces the file
#     (layervai/qurl-conformance#20, `justin/agent-registration-vectors`),
#     because the vectors are not yet on that repo's default branch.
#   * WHEN #20 MERGES, re-point CANONICAL_REF to `main`.
#   * WHEN qurl-conformance cuts a release that carries the file (a `vX.Y.Z`
#     git tag — the repo already tags releases, e.g. v0.1.2), re-point
#     CANONICAL_REF to that tag so the compare is against a frozen published
#     artifact rather than a moving branch head. (This is the git-tag analog of
#     migrating to the published Go/npm conformance accessor — the eventual end
#     state tracked by nhp#3138 / qurl-typescript#176. Until the canonical is a
#     consumable Go module, fetch from the repo directly.)
#
# NETWORK / ABSENCE TOLERANCE (robustness) — a drift-detector must fail LOUD on
# real drift but must NOT redden CI for reasons unrelated to the vectors:
#   * FETCH FAILURE (network down, GitHub 5xx, auth/rate-limit) => SKIP with a
#     clear message and exit 0. A transient GitHub outage is not vector drift;
#     failing here would flap the build and the scheduled run. The local SHA pin
#     still guards local edits in the meantime.
#   * FILE ABSENT AT THE SOURCE REF (HTTP 404) => SKIP with a clear message and
#     exit 0. Until #20 lands on the ref we point at, the canonical simply does
#     not exist there yet; that is an expected pre-merge state, not drift. (Once
#     CANONICAL_REF points at a ref that is guaranteed to carry the file, a 404
#     would instead mean the file was moved/removed upstream — revisit this skip
#     then; for now, pre-publication absence is the common case.)
#   * FILE PRESENT + BYTES DIFFER => DRIFT. Exit 1 with remediation. This is the
#     one failure the local SHA pin cannot see.
#   * FILE PRESENT + BYTES IDENTICAL => OK. Exit 0.
#
# Usage:
#   ./scripts/check-agent-reg-vector-drift.sh   # 0 ok/skip, 1 on real drift
# It is self-contained: it fetches the canonical bytes itself (via `gh api`, so
# it uses the caller's / the runner's GITHUB_TOKEN and gets clean HTTP status
# codes) and byte-compares. Same command run locally and in CI.
#
# TEST SEAM — set REMOTE_VECTOR in the environment to a path (or to the literal
# `__ABSENT__` / `__FETCHFAIL__`) and the network fetch is skipped; the given
# path (or simulated 404 / fetch-failure) drives the compare/skip/exit logic
# directly. The fixture test (tests/scripts/check-agent-reg-vector-drift_test.sh)
# uses this to exercise every branch with NO network and NO gh. With it unset
# (the real CI/local run) the fetch and behavior are unchanged.
#
# REPO_ROOT is derived from this script's own location (not git) so it works
# from any cwd and in a fixture/temp checkout.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Remove any temp file we create (the fetched canonical body) on EVERY exit path
# — OK, DRIFT, and each SKIP — so a repeated local run does not litter TMPDIR.
# Populated by fetch_canonical; a single EXIT trap covers all the mid-function
# `exit`s without a cleanup call at each one. Written as an INLINE trap (not a
# named cleanup function) so the linter does not flag the body as unreachable or
# never-invoked — it cannot see that the EXIT trap runs it, and that diagnostic
# code differs across linter versions. `rm -f` on an empty/absent path is a
# harmless no-op, and the trailing `|| true` guarantees the trap's own status is
# 0 so a would-be non-zero never overrides the exit code an `exit N` set.
_tmpfile=""
trap 'rm -f "${_tmpfile}" 2>/dev/null || true' EXIT

# --- what we compare ---------------------------------------------------------
CANONICAL_REPO="layervai/qurl-conformance"
CANONICAL_PATH="vectors/agent_registration_golden.json"
# See "SOURCE REF" above. Re-point to `main` after qurl-conformance#20 merges,
# then to a `vX.Y.Z` release tag once one carries the file.
# TRACKED: nhp#3144 forces this re-point (+ the 404 SKIP->FAIL flip below) so it
# is not lost while the detector runs dormant-and-green against the feature branch.
CANONICAL_REF="justin/agent-registration-vectors"

LOCAL_VECTOR="${REPO_ROOT}/nhp/core/testdata/agent_registration_golden.json"

# --- the local copy must exist (its absence is a real repo defect, not a skip)
if [ ! -f "${LOCAL_VECTOR}" ]; then
  echo "ERROR: local vendored vector not found: ${LOCAL_VECTOR}" >&2
  echo "       (this repo must carry the re-hosted copy; a missing local file" >&2
  echo "        is a defect, not an upstream-absence skip)" >&2
  exit 1
fi

# --- portable sha256 (prefer sha256sum, fall back to shasum on macOS) --------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# --- fetch the canonical bytes into $REMOTE_FILE, or SKIP -------------------
# Sets REMOTE_FILE to a readable path on success. On any tolerated condition
# (fetch failure or 404) it prints a clear SKIP line and exits 0 — a
# drift-detector must never redden CI for a transient/absence reason.
#
# TEST SEAM: when REMOTE_VECTOR is set we do not touch the network:
#   REMOTE_VECTOR=__FETCHFAIL__  -> simulate a fetch failure (skip 0)
#   REMOTE_VECTOR=__ABSENT__     -> simulate a 404 at the source ref (skip 0)
#   REMOTE_VECTOR=<path>         -> compare against that file directly
REMOTE_FILE=""
fetch_canonical() {
  if [ -n "${REMOTE_VECTOR:-}" ]; then
    case "${REMOTE_VECTOR}" in
      __FETCHFAIL__)
        echo "SKIP: could not fetch ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} (simulated fetch failure)." >&2
        echo "      A fetch failure is not vector drift; the local SHA pin still guards local edits." >&2
        exit 0
        ;;
      __ABSENT__)
        echo "SKIP: ${CANONICAL_PATH} does not exist at ${CANONICAL_REPO}@${CANONICAL_REF} (simulated HTTP 404)." >&2
        echo "      The canonical is not published at this ref yet; re-point CANONICAL_REF once it lands." >&2
        exit 0
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

  # Two-phase so the byte capture is EXACT and the control flow is robust:
  #  (1) a `-i` request to read the HTTP status line only (for classification);
  #  (2) on 200, a second plain `gh api` (no `-i`) whose stdout is the RAW file
  #      body with no header block to strip — redirected straight to a temp file
  #      for a byte-for-byte capture (no `tr`/`awk` munging that could add a
  #      trailing newline or drop a legitimate CR and cause a false DRIFT).
  # The extra call happens only on the success path, so no error path rides a
  # pipefail. `gh api` uses GH_TOKEN / GITHUB_TOKEN, so CI is not rate-limited on
  # the public qurl-conformance repo. `gh` exits non-zero on a non-2xx status, so
  # we ignore its exit code and classify on the parsed status line — an empty
  # status (request never reached GitHub: DNS/connection failure) => generic skip.
  local http
  http="$(gh api \
    "repos/${CANONICAL_REPO}/contents/${CANONICAL_PATH}?ref=${CANONICAL_REF}" \
    -H "Accept: application/vnd.github.raw" \
    -i --cache 0 2>/dev/null | awk 'NR==1{print $2; exit}')" || true

  case "${http}" in
    200)
      # Track the temp file so the EXIT trap removes it on every downstream path.
      _tmpfile="$(mktemp)"
      # Byte-exact body capture: no -i, stdout is the file bytes verbatim.
      if ! gh api \
        "repos/${CANONICAL_REPO}/contents/${CANONICAL_PATH}?ref=${CANONICAL_REF}" \
        -H "Accept: application/vnd.github.raw" \
        --cache 0 > "${_tmpfile}" 2>/dev/null; then
        # Status said 200 a moment ago but the body fetch failed — transient.
        echo "SKIP: body fetch for ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} failed after a 200 status (transient)." >&2
        echo "      Not treating an incomplete fetch as drift; re-run once connectivity is restored." >&2
        exit 0
      fi
      if [ ! -s "${_tmpfile}" ]; then
        # 200 with an empty body is a fetch anomaly — refuse a false-green match.
        echo "SKIP: fetched an EMPTY ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} (fetch anomaly)." >&2
        echo "      Refusing to compare against empty bytes; treating as a transient failure." >&2
        exit 0
      fi
      REMOTE_FILE="${_tmpfile}"
      return 0
      ;;
    404)
      # SEMANTICS NOTE (tracked: nhp#3144) — a 404 skips today because the
      # canonical is not published at CANONICAL_REF yet (pre-merge). Once
      # CANONICAL_REF points at a ref that is GUARANTEED to carry the file (main
      # after #20, or a release tag), a 404 instead means the file was
      # moved/removed upstream — a real problem, not an absence. When you re-point
      # CANONICAL_REF (nhp#3144), revisit this branch: turn it into a FAILURE
      # (exit 1) there, so a vanished canonical alarms instead of silently
      # no-op'ing the detector.
      echo "SKIP: ${CANONICAL_PATH} does not exist at ${CANONICAL_REPO}@${CANONICAL_REF} (HTTP 404)." >&2
      echo "      The canonical is not published at this ref yet (expected pre-merge state)." >&2
      echo "      Re-point CANONICAL_REF in this script once qurl-conformance#20 lands (main, then a release tag)." >&2
      exit 0
      ;;
    *)
      echo "SKIP: could not fetch ${CANONICAL_PATH} from ${CANONICAL_REPO}@${CANONICAL_REF} (HTTP ${http:-unknown})." >&2
      echo "      A transient fetch failure (network / GitHub outage / rate-limit) is not vector drift;" >&2
      echo "      the local SHA pin still guards local edits. Re-run once connectivity is restored." >&2
      exit 0
      ;;
  esac
}

fetch_canonical

# --- compare (cmp is the authority; sha is for the human-readable log) --------
LOCAL_SHA="$(sha256_of "${LOCAL_VECTOR}")"
REMOTE_SHA="$(sha256_of "${REMOTE_FILE}")"

echo "canonical : ${CANONICAL_REPO}@${CANONICAL_REF}:${CANONICAL_PATH}"
echo "local     : nhp/core/testdata/agent_registration_golden.json"
echo "canonical sha256: ${REMOTE_SHA}"
echo "local     sha256: ${LOCAL_SHA}"

if cmp -s "${REMOTE_FILE}" "${LOCAL_VECTOR}"; then
  echo "OK: local vendored copy is byte-identical to the canonical (sha256 ${LOCAL_SHA})."
  exit 0
fi

{
  echo "DRIFT: the local vendored ${CANONICAL_PATH} differs from the canonical."
  echo "  canonical: ${CANONICAL_REPO}@${CANONICAL_REF}  (sha256 ${REMOTE_SHA})"
  echo "  local    : nhp/core/testdata/agent_registration_golden.json  (sha256 ${LOCAL_SHA})"
  echo "  The vendored copy must stay byte-identical to the qurl-conformance canonical."
  echo "  To re-sync: copy the canonical over the local file AND update"
  echo "  agentRegFixtureSHA256 in nhp/core/agent_registration_roundtrip_test.go to:"
  echo "    ${REMOTE_SHA}"
  echo "  then re-run the nhp/core suite so the roundtrip fence validates the new bytes."
} >&2
exit 1
