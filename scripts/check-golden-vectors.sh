#!/usr/bin/env bash
# check-golden-vectors.sh
# ----------------------------------------------------------------------------
# Fail if a cross-language golden vector drifts between a Go test and its
# TypeScript js-agent counterpart. These vectors pin the wire contract between
# the browser agent and the Go server/relay: the browser and Go MUST derive the
# same routing id / handshake material, so a one-sided algorithm change (hash,
# prefix length, base64 variant, KDF tag, ...) must fail the build instead of
# silently shipping a split.
#
# Each side marks its shared constants with a trailing
# `// nhp-golden-vector: <label>` comment; this script extracts the labelled
# (label, value) pairs from BOTH files of each pair and fails if they disagree.
# Each suite still asserts its own implementation against its own copy in its
# own toolchain (the Go test never runs the TS code; the js-agent vitest job
# never runs Go) — this is the missing cross-check between those two copies.
#
# INCLUSION CRITERION — only NHP-*custom* constructions whose "correct" value is
# defined by this repo and copied by hand into both languages belong here:
#   - PubKeyFingerprint (truncated-SHA-256 routing id)
#   - the NHP HKDF / NoiseFactory KeyGen transcript
# The other js-agent crypto tests (dh/aead/hash) are fenced against EXTERNAL
# published KATs (RFC 7748 / RFC 7693 / FIPS 180-4 / a standard AES-256-GCM KAT).
# Those need no cross-check: the standard is the shared oracle, and each side's
# own test already fails if it drifts from it. Add a pair below only when both
# files hand-copy a repo-defined value.
#
# Usage:
#   ./scripts/check-golden-vectors.sh   # exit 0 in sync, 1 on drift
#   make lint-workflows                 # wired into the workflow-lint target
#
# REPO_ROOT is derived from this script's own location (not git) so the fixture
# test (tests/scripts/check-golden-vectors_test.sh) can symlink the script into
# a tempdir and exercise it against synthetic files.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MARKER="nhp-golden-vector:"

# "<go file>|<ts file>" pairs, relative to REPO_ROOT. See the inclusion
# criterion above before adding a pair. WHEN YOU ADD A PAIR: also add both files
# to the `paths:` trigger in .github/workflows/validate-workflows.yml
# (validate_paths). This fence only runs when a listed file changes, so an
# unlisted new pair would silently skip CI on a one-sided edit — defeating the
# whole point of the check.
PAIRS=(
  "nhp/utils/crypto_fingerprint_test.go|endpoints/js-agent/test/fingerprint.test.ts"
  "nhp/core/kdf_test.go|endpoints/js-agent/test/kdf.test.ts"
)

# --list-sources mode: print every file this lint reads (both sides of each
# PAIRS entry), one per line, then exit. PAIRS is the single source of truth, so
# this derives the list with no second copy to maintain. The fixture test's
# trigger-coverage case feeds this into a check that every source is in
# validate-workflows.yml's paths — turning the "remember to add both files to
# the workflow paths" rule (above) from prose discipline into a CI failure.
if [ "${1:-}" = "--list-sources" ]; then
  for pair in "${PAIRS[@]}"; do
    printf '%s\n' "${pair%%|*}" "${pair##*|}"
  done
  exit 0
fi

# Emit a sorted "<label>=<value>" line for every real vector line. The pattern
# matches only a quoted value immediately followed by the trailing `//` marker
# comment (modulo a `,`/`;` and whitespace): `"<value>" // ... <marker> <label>`.
# Anchoring on the trailing `//` after the value excludes BOTH prose with no
# quoted value AND prose that merely mentions the marker after some quoted word
# (there the `//` precedes the quote, so the pattern cannot match). Assumes one
# quoted value per marked line — true for every vector line; a marked line with
# more than one quoted string would capture the last one before the `//`. A
# single sed pass filters and transforms: `-n` prints only matched lines; sed
# exits 0 even on no match, so an empty result is reported by the caller, not
# swallowed.
extract_pairs() {
  local file="$1"
  sed -nE "s/^.*\"([^\"]*)\"[,;[:space:]]*\/\/.*${MARKER}[[:space:]]*([A-Za-z0-9._-]+).*/\2=\1/p" "$file" \
    | sort
}

status=0
total=0
for pair in "${PAIRS[@]}"; do
  go_rel="${pair%%|*}"
  ts_rel="${pair##*|}"
  go_file="${REPO_ROOT}/${go_rel}"
  ts_file="${REPO_ROOT}/${ts_rel}"

  if [ ! -f "$go_file" ]; then
    echo "ERROR: missing $go_file" >&2
    status=1
    continue
  fi
  if [ ! -f "$ts_file" ]; then
    echo "ERROR: missing $ts_file" >&2
    status=1
    continue
  fi

  go_pairs="$(extract_pairs "$go_file")"
  ts_pairs="$(extract_pairs "$ts_file")"

  if [ -z "$go_pairs" ]; then
    echo "ERROR: no '${MARKER} <label>' vectors found in $go_file" >&2
    echo "       expected lines like: dst0 = \"...\" // ${MARKER} <label>" >&2
    status=1
    continue
  fi
  if [ -z "$ts_pairs" ]; then
    echo "ERROR: no '${MARKER} <label>' vectors found in $ts_file" >&2
    echo "       expected lines like: dst0: \"...\", // ${MARKER} <label>" >&2
    status=1
    continue
  fi

  # Each label must be unique within a file — a typo'd duplicate marker would
  # otherwise be silently compared/diffed instead of reported (mirrors the
  # explicit dup detection in check-scope-drift.sh). Values never contain '='
  # (base64url-nopad / hex), so cut on '=' isolates the label.
  go_dups="$(printf '%s\n' "$go_pairs" | cut -d= -f1 | sort | uniq -d)"
  ts_dups="$(printf '%s\n' "$ts_pairs" | cut -d= -f1 | sort | uniq -d)"
  if [ -n "$go_dups" ] || [ -n "$ts_dups" ]; then
    {
      echo "ERROR: duplicate ${MARKER} label(s) in pair:"
      echo "  Go: $go_rel"
      echo "  TS: $ts_rel"
      [ -n "$go_dups" ] && {
        echo "  duplicated in the Go file:"
        printf '%s\n' "$go_dups" | sed 's/^/    /'
      }
      [ -n "$ts_dups" ] && {
        echo "  duplicated in the TS file:"
        printf '%s\n' "$ts_dups" | sed 's/^/    /'
      }
      echo "  Each marked vector needs a unique label; rename or remove the dup."
    } >&2
    status=1
    continue
  fi

  if [ "$go_pairs" = "$ts_pairs" ]; then
    n="$(printf '%s\n' "$go_pairs" | wc -l | tr -d ' ')"
    echo "OK: $go_rel <-> $ts_rel ($n vectors)"
    total=$((total + n))
    continue
  fi

  # Drift — show which labelled vectors are present on only one side.
  only_go="$(comm -23 <(printf '%s\n' "$go_pairs") <(printf '%s\n' "$ts_pairs"))"
  only_ts="$(comm -13 <(printf '%s\n' "$go_pairs") <(printf '%s\n' "$ts_pairs"))"
  {
    echo "DRIFT: golden vectors disagree between:"
    echo "  Go: $go_rel"
    echo "  TS: $ts_rel"
    if [ -n "$only_go" ]; then
      echo "  Only in the Go file (label=value):"
      printf '%s\n' "$only_go" | sed 's/^/    /'
    fi
    if [ -n "$only_ts" ]; then
      echo "  Only in the TS file (label=value):"
      printf '%s\n' "$only_ts" | sed 's/^/    /'
    fi
    echo "  Both files hand-copy the same repo-defined value and MUST agree."
    echo "  Update both marked vectors together (and re-run the per-language tests)."
    echo ""
  } >&2
  status=1
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "OK: all cross-language golden vectors lockstep (${#PAIRS[@]} pairs, $total vectors)"
