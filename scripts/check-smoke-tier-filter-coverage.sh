#!/usr/bin/env bash
# Validate that every Test<Prefix>_ declared in tests/smoke/0X_*_test.go
# is reachable by the corresponding tier in scripts/run-smoke.sh's
# RUN_FILTER, and conversely that every alternation token in each
# RUN_FILTER corresponds to at least one real Test<Token>_ declaration.
#
# RUN_FILTER is the SINGLE SOURCE OF TRUTH in scripts/run-smoke.sh (the
# shared entrypoint that local pre-PR, PR CI, and post-deploy CI all call).
# It used to live inline in .github/workflows/nhp-smoke-tests.yml; this
# checker moved with it.
#
# Catches both directions of the silent-skip class:
# - token-without-test (a filter token without a matching
#   `^func Test<Token>_` declaration silently matches nothing —
#   e.g., a token `SSMProbe` would not match
#   `TestSSMProbeRejectList` because the regex's trailing `_`
#   requires the next character after the token to be `_`)
# - test-without-token (a Test<Prefix>_ declaration in a
#   tiered file with no matching token in that tier's filter
#   silently skips during CI runs)
#
# Wired into `make lint-workflows` so the regression fence runs on every
# CI workflow validation and on every local lint pass.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SMOKE_DIR="${REPO_ROOT}/tests/smoke"
FILTER_SRC="${REPO_ROOT}/scripts/run-smoke.sh"

if [ ! -d "$SMOKE_DIR" ]; then
  echo "ERROR: $SMOKE_DIR not found" >&2
  exit 1
fi
if [ ! -f "$FILTER_SRC" ]; then
  echo "ERROR: $FILTER_SRC not found" >&2
  exit 1
fi

# Tier 1 = files 01_-09_ per CLAUDE.md smoke-rule prefix mapping.
# Tier 2 = files 10_-19_. Tier 3 = files 20_-29_. The function below
# returns the tier number (1/2/3) for a numbered prefix; non-numbered
# helper files (assertions.go, ssm_probe.go) return 0 (no tier).
file_tier() {
  case "$(basename "$1")" in
    0[1-9]_*_test.go) echo 1 ;;
    1[0-9]_*_test.go) echo 2 ;;
    2[0-9]_*_test.go) echo 3 ;;
    *) echo 0 ;;
  esac
}

# Collect prefixes from real Test declarations grouped by tier.
declare -a tier1_prefixes=() tier2_prefixes=() tier3_prefixes=()
for f in "$SMOKE_DIR"/[0-9][0-9]_*_test.go; do
  [ -f "$f" ] || continue
  tier=$(file_tier "$f")
  [ "$tier" = 0 ] && continue
  # Pull prefixes: ^func Test<Prefix>_ where Prefix = [A-Z][A-Za-z0-9]*
  while IFS= read -r prefix; do
    case "$tier" in
      1) tier1_prefixes+=("$prefix") ;;
      2) tier2_prefixes+=("$prefix") ;;
      3) tier3_prefixes+=("$prefix") ;;
    esac
  done < <(grep -hE '^func Test[A-Z][A-Za-z0-9]*_' "$f" | sed -E 's/^func Test([A-Z][A-Za-z0-9]*)_.*/\1/')
done

# Dedupe.
dedupe_array() {
  # Read a newline-separated unique list into a named variable.
  # Avoids word-splitting of $() in array context (shellcheck SC2207)
  # and works on bash 3.2 without mapfile.
  #
  # The `eval` here is intentional and bounded by macOS-bash-3.2
  # portability — bash 4.3+ namerefs (`local -n`) are the cleaner
  # primitive but unavailable on stock macOS. All callers in this
  # script pass HARDCODED LITERAL variable names (e.g.,
  # `dedupe_array tier1_prefixes "${tier1_prefixes[@]:-}"`), and
  # the values are sed-extracted alphanumeric prefixes matching
  # `[A-Z][A-Za-z0-9]*`, so injection is not a vector. Do NOT
  # extend this helper to take user-supplied target names.
  local target="$1"
  shift
  local sorted
  sorted=$(printf '%s\n' "$@" | sort -u | sed '/^$/d')
  eval "$target=()"
  while IFS= read -r line; do
    [ -n "$line" ] && eval "$target+=(\"\$line\")"
  done <<< "$sorted"
}

dedupe_array tier1_prefixes "${tier1_prefixes[@]:-}"
dedupe_array tier2_prefixes "${tier2_prefixes[@]:-}"
dedupe_array tier3_prefixes "${tier3_prefixes[@]:-}"

# Extract a tier's RUN_FILTER alternation tokens. Pulls the first
# `^Test(...)_` regex on the line whose case label matches the tier.
extract_filter_tokens() {
  local label="$1"
  # Pull the RUN_FILTER line that follows the case label exactly,
  # then split its alternation into one token per line. Uses awk
  # with an exact-string match (==) for the label so embedded
  # regex metachars (the `+` in `tier1+tier2`) need no escaping.
  awk -v label="$label" '
    {
      stripped = $0
      sub(/^[[:space:]]+/, "", stripped)
      sub(/[[:space:]]+$/, "", stripped)
    }
    stripped == label")" { in_block=1; next }
    in_block && /^[[:space:]]*RUN_FILTER=/ {
      sub(/.*\^Test\(/, "")
      sub(/\)_.*/, "")
      gsub(/\|/, "\n")
      print
      exit
    }
    in_block && stripped == ";;" { in_block=0 }
  ' "$FILTER_SRC" | sed '/^$/d' | sort -u
}

# Exact-match membership test: return 0 iff $1 equals one of the
# remaining args. Pure bash — no subprocess, no pipe.
#
# This replaced a `printf '%s\n' "${arr[@]}" | grep -qx "$needle"`
# membership idiom that raced SIGPIPE under `set -o pipefail`: grep
# closes the pipe on its first match, printf then hits EPIPE and exits
# non-zero, and pipefail propagates that non-zero status even though
# grep MATCHED — flipping a hit into a spurious "no matching
# declaration" flake. Full mechanism + the regression fence live in
# tests/lints/smoke-tier-filter-coverage/run-fixtures.sh.
#
# Tokens and prefixes are alphanumeric ([A-Z][A-Za-z0-9]*), so exact
# string equality is identical to the old `grep -qx` whole-line match,
# with no regex-metacharacter caveat.
#
# Keep this subprocess-free: do NOT reintroduce a `printf … | grep -q`
# membership test (fenced by the fixture above).
array_contains() {
  local needle="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [ "$candidate" = "$needle" ] && return 0
  done
  return 1
}

# Run two-way consistency check for a single tier label against its
# expected real-test prefixes.
check_tier() {
  local label="$1"
  shift
  local -a real=("$@")
  # Read filter tokens portably (mapfile is bash 4+, macOS ships
  # bash 3.2 by default).
  local -a tokens=()
  while IFS= read -r tok; do
    [ -n "$tok" ] && tokens+=("$tok")
  done < <(extract_filter_tokens "$label")

  # Structural-drift fence: if the awk extractor returned zero
  # tokens, run-smoke.sh's RUN_FILTER assumption (single-line single-
  # quoted `^Test(...)_` after the case label) has broken — likely
  # because someone reformatted the case block to a multi-line string
  # or switched quote style. Without this guard the script silently
  # reports OK when in fact it parsed nothing, defeating the
  # regression class it exists to prevent.
  if [ "${#tokens[@]}" -eq 0 ]; then
    echo "ERROR [$label]: extracted zero tokens from RUN_FILTER — likely a run-smoke.sh reformat (multi-line string, quote-style change, or case-label rename) broke the awk parser. Re-check $FILTER_SRC or update extract_filter_tokens()." >&2
    return 1
  fi

  local errs=0
  # token-without-test: filter token has no matching Test<token>_
  for t in "${tokens[@]:-}"; do
    [ -z "$t" ] && continue
    if ! array_contains "$t" "${real[@]:-}"; then
      echo "ERROR [$label]: filter token '$t' has no matching ^func Test${t}_ declaration in any file routing to this tier — silent no-op"
      errs=$((errs+1))
    fi
  done

  # test-without-token: real prefix not in filter alternation
  # (skip for label=all, which has an empty filter, and label=local,
  # which is a curated allow-list of the wire-contract subset that runs
  # against the self-contained local stack — most tests are AWS-infra or
  # qURL and legitimately absent from it)
  #
  # `tier3_no_ssm_expected_omissions` is the single source of truth
  # for prefixes that are intentionally omitted from tier3-no-ssm
  # because their tests have a hard SSM RunShellScript dependency
  # (calls into the `probe*` / `sendShellScript` helpers defined in
  # tests/smoke/ssm_probe.go). Those are gated by the 30-day
  # `allow_ssm_probes` burn-in and so can't run in tier3-no-ssm by
  # design.
  #
  # Defined at top-level (above) so the structural fence at the end
  # of the script and the in-tier check below share one list. A
  # duplicate per-callsite copy is the same silent-drift class this
  # lint exists to prevent.
  is_expected_omission() {
    # `:-`: uniform with the callsites above, and safe if this list is
    # ever emptied (bare "${arr[@]}" trips nounset on bash 3.2).
    array_contains "$1" "${tier3_no_ssm_expected_omissions[@]:-}"
  }
  if [ "$label" != "all" ] && [ "$label" != "local" ]; then
    for r in "${real[@]:-}"; do
      [ -z "$r" ] && continue
      if ! array_contains "$r" "${tokens[@]:-}"; then
        # tier1+tier2 should also include tier1 prefixes; tier3-no-ssm
        # is allowed to omit SSM-needing prefixes. We split the
        # tier3-no-ssm omission into two cases: expected (in the
        # exemption list above — silent) and unexpected (WARN — a
        # real signal something new landed without a routing
        # decision).
        if [ "$label" = "tier3-no-ssm" ]; then
          if ! is_expected_omission "$r"; then
            echo "WARN [$label]: real prefix 'Test${r}_' not in filter (intentional only if it requires SSM — if so, add to tier3_no_ssm_expected_omissions in scripts/check-smoke-tier-filter-coverage.sh)"
          fi
        else
          echo "ERROR [$label]: real prefix 'Test${r}_' is missing from filter — silent skip"
          errs=$((errs+1))
        fi
      fi
    done
  fi
  # Clamp the per-tier exit code to bash's 0-255 return range so a
  # large drift event surfaces a non-zero return rather than wrapping
  # to 0 mod 256.
  if [ "$errs" -gt 255 ]; then
    return 255
  fi
  return "$errs"
}

# Structural fence on tier3_no_ssm_expected_omissions: each entry
# must correspond to a test file that actually calls into a helper
# defined in tests/smoke/ssm_probe.go. Closes the "exemption list
# rots silently when a test drops its SSM dependency" class — the
# same silent-skip shape this script's RUN_FILTER lint already
# fences (token-without-test).
#
# Strategy: extract the exact function names from ssm_probe.go (so
# the lint stays correct if helpers are added/renamed), build a
# regex matching `\b<name>(` for each, and grep every test file
# declaring `^func Test<Prefix>_` for any of those names. A bare
# `probe[A-Z]*\(` grep would false-positive on local variables
# named `probeCtx`, `probeCancel`, etc. (real example in
# 09_public_alb_internal_lockdown_test.go).
#
# The fence runs even when the previous tier checks already failed,
# so a stale exemption surfaces alongside the routing errors.
ssm_dep_errs=0
# Extract package-level function names from ssm_probe.go. The
# `^func <Name>(` shape excludes method receivers and matches both
# `sendShellScript` and the `probe*` family. If a future helper is
# added that doesn't start at column 0 (e.g., a closure or a
# generic), widen the extractor.
SSM_PROBE_FILE="$SMOKE_DIR/ssm_probe.go"
if [ ! -f "$SSM_PROBE_FILE" ]; then
  echo "ERROR [tier3-no-ssm-exemption]: $SSM_PROBE_FILE not found — the structural fence on the exemption list depends on extracting helper names from it. Either the file was renamed/removed (update this script's SSM_PROBE_FILE path) or the smoke suite moved its SSM helpers elsewhere." >&2
  exit 1
fi
ssm_helper_names=$(grep -hE '^func [a-zA-Z][a-zA-Z0-9]*\(' "$SSM_PROBE_FILE" | sed -E 's/^func ([a-zA-Z][a-zA-Z0-9]*)\(.*/\1/' | sort -u)
if [ -z "$ssm_helper_names" ]; then
  echo "ERROR [tier3-no-ssm-exemption]: extracted zero helper names from $SSM_PROBE_FILE — the awk extractor's '^func <Name>(' assumption may have broken." >&2
  exit 1
fi
# Build alternation: `(name1|name2|...)\(` anchored with a non-word
# char on the left (or start-of-line) to prevent local-variable
# false positives like `probeCancel(` matching `probe[A-Z]*`.
ssm_helper_alt=$(printf '%s\n' "$ssm_helper_names" | tr '\n' '|' | sed 's/|$//')
ssm_helper_regex="(^|[^A-Za-z0-9_])(${ssm_helper_alt})\\("
tier3_no_ssm_expected_omissions=(
  ACEBPFObjects
  DockerImage
  SSMRunbook
  ServerDeployStability
)
for prefix in "${tier3_no_ssm_expected_omissions[@]}"; do
  matching_files=()
  for f in "$SMOKE_DIR"/[0-9][0-9]_*_test.go; do
    [ -f "$f" ] || continue
    if grep -qE "^func Test${prefix}_" "$f"; then
      matching_files+=("$f")
    fi
  done
  if [ "${#matching_files[@]}" -eq 0 ]; then
    echo "ERROR [tier3-no-ssm-exemption]: prefix '${prefix}' is in tier3_no_ssm_expected_omissions but no 0X_*_test.go file declares ^func Test${prefix}_. Either the test was renamed/removed (drop the entry) or the prefix is a typo."
    ssm_dep_errs=$((ssm_dep_errs+1))
    continue
  fi
  if ! grep -qE "$ssm_helper_regex" "${matching_files[@]}"; then
    echo "ERROR [tier3-no-ssm-exemption]: prefix '${prefix}' is in tier3_no_ssm_expected_omissions but its test file(s) (${matching_files[*]}) contain NO calls to helpers defined in $SSM_PROBE_FILE (sendShellScript / probe* family). Either (a) the test no longer needs SSM RunShellScript — remove from the exemption list AND add '${prefix}' to tier3-no-ssm RUN_FILTER in scripts/run-smoke.sh, OR (b) the test uses a different SSM mechanism (e.g., CloudWatch Logs Insights via the AWS SDK, SSM Parameter Store via getSSMParameter) — those are not gated by the 30-day allow_ssm_probes burn-in, so they belong in tier3-no-ssm and the entry should be removed from this exemption list."
    ssm_dep_errs=$((ssm_dep_errs+1))
  fi
done

errs=0
check_tier "tier1" "${tier1_prefixes[@]:-}" || errs=$((errs+$?))
# tier1+tier2: combine tier1 + tier2 prefixes
combined=()
dedupe_array combined "${tier1_prefixes[@]:-}" "${tier2_prefixes[@]:-}"
check_tier "tier1+tier2" "${combined[@]:-}" || errs=$((errs+$?))
# tier3-no-ssm is curated (excludes SSM-needing tests); we still want
# to flag tokens that don't match any test (no-op).
all_real=()
dedupe_array all_real "${tier1_prefixes[@]:-}" "${tier2_prefixes[@]:-}" "${tier3_prefixes[@]:-}"
check_tier "tier3-no-ssm" "${all_real[@]:-}" || errs=$((errs+$?))
# local is a curated allow-list (like `all`): validate its tokens are real
# (token-without-test) but do not require every test to appear in it.
check_tier "local" "${all_real[@]:-}" || errs=$((errs+$?))

total_errs=$((errs + ssm_dep_errs))
if [ "$total_errs" -gt 0 ]; then
  echo ""
  if [ "$errs" -gt 0 ]; then
    echo "FAIL: $errs RUN_FILTER coverage error(s) in $FILTER_SRC"
    echo "      Each token in a RUN_FILTER must have a matching ^func Test<Token>_ declaration"
    echo "      in some 0X_*_test.go file routing to that tier, and conversely."
  fi
  if [ "$ssm_dep_errs" -gt 0 ]; then
    echo "FAIL: $ssm_dep_errs tier3_no_ssm_expected_omissions structural drift error(s)"
    echo "      Each entry in the exemption list must correspond to a test file"
    echo "      that actually calls into probe* / sendShellScript helpers."
  fi
  exit 1
fi

echo "OK: smoke RUN_FILTER tokens and Test<Prefix>_ declarations are consistent across tier1, tier1+tier2, tier3-no-ssm; all tier3_no_ssm_expected_omissions entries still depend on SSM."
