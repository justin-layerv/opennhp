#!/usr/bin/env bash
# Behaviour fixture for .github/scripts/scan-attestation-soak.sh — the parser
# half of the Attestation Verify Watchdog (.github/workflows/attestation-verify-
# watchdog.yml), which automates the manual "grep deploy logs for ATTEST_RESULT"
# soak check (docs/SECURITY.md) into a paging tracker issue. Pre-enforce-flip
# item on #1334.
#
# The classification is safety-relevant: a miss on the `error` case means the
# watchdog stays silent while the #1334 gate is failing OPEN (verifying nothing)
# under enforce — the exact "wait to be eyeballed" gap the watchdog closes. So
# this fixture pins the per-lane verdict against the REAL captured marker
# wording, the same non-tautological discipline the verify-image-attestation
# fixture uses. Wired into `make lint-workflows` and validate-workflows.yml.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/scan-attestation-soak.sh"
[[ -f "$SCRIPT" ]] || { echo "missing script: $SCRIPT"; exit 1; }

# Lint the script too. make lint-workflows / CI run shellcheck on it separately,
# but keep the fixture self-checking when run standalone (skip with a note when
# the linter is absent — CI provides it).
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s bash "$SCRIPT" || { echo "FAIL  scan-attestation-soak.sh failed shellcheck"; exit 1; }
  echo "PASS  scan-attestation-soak.sh shellcheck"
else
  echo "NOTE  shellcheck not on PATH; skipping script lint (CI/make lint-workflows provide it)"
fi

# REAL marker lines, captured verbatim from a live blue-green-deploy run
# (layervai/nhp run 27516737204, 2026-06-15) via `gh run view --log`. Using the
# observed wording — including the `<job>\t<step>\t<ISO-ts> ##[notice]` prefix gh
# renders around the action's `::notice::` — makes these fixtures non-tautological.
# These are FROZEN captures: they pin parser BEHAVIOUR against known wording. The
# emit()-lockstep block below is what catches the emitter drifting away from them
# — re-capture these lines (and the parser regex) if verify-image-attestation's
# emit() format ever changes.
TAB="$(printf '\t')"
REAL_SERVER_PASS="Deploy to Standby${TAB}[Server] Verify Image Attestation${TAB}2026-06-15T00:18:17.9943095Z ##[notice]ATTEST_RESULT=pass repo=layerv/nhp-server tag=c0f17b152f87708b9db17ebf07b282c0aed1008d digest=sha256:14aff5919595b2ef6495f4701c204ef033c90d16c4e1d4a7d58f1516d51d4cad mode=audit"
REAL_AC_PASS="Deploy to Standby${TAB}[AC] Verify Image Attestation${TAB}2026-06-15T00:18:29.4423511Z ##[notice]ATTEST_RESULT=pass repo=layerv/nhp-ac tag=c0f17b152f87708b9db17ebf07b282c0aed1008d digest=sha256:9db80333b97d33906ad7029e2bf7a725cf36d4c67141995ee3a8a6b6f6b9cca0 mode=audit"
# The action's `emit()` DEFINITION line, echoed verbatim by the step's command
# listing (note the literal `$1`/`${MODE}` and the ANSI escapes gh emits). The
# parser must NOT treat this as a marker — the `pass|fail|error` anchor excludes
# it because `$1` is not a result token. Captured from the same run.
REAL_EMIT_DEF=$'Deploy to Standby\t[Server] Verify Image Attestation\t2026-06-15T00:18:10.0359583Z \x1b[36;1memit() { echo "::notice::ATTEST_RESULT=$1 repo=${REPOSITORY} tag=${IMAGE_TAG} digest=${DIGEST:-none} mode=${MODE}"; }\x1b[0m'

# Derive a marker by swapping ONLY the two fields the action itself varies —
# the result token (emit's $1) and mode (${MODE}). Faithful because emit() prints
# all of pass/fail/error through one identical printf; tag/digest are irrelevant
# to the parser and kept as the captured values.
marker() { # marker <result> <repo> <mode>
  printf '%s\n' "$REAL_SERVER_PASS" \
    | sed -E "s/ATTEST_RESULT=pass/ATTEST_RESULT=$1/; s#repo=layerv/nhp-server#repo=$2#; s/mode=audit/mode=$3/"
}

PASS=0; FAIL=0
# assert_eq <name> <expected-stdout> <actual-stdout>
assert_eq() {
  local name="$1" exp="$2" act="$3"
  if [[ "$exp" == "$act" ]]; then
    printf 'PASS  %s\n' "$name"; PASS=$((PASS+1))
  else
    printf 'FAIL  %s\n' "$name"; FAIL=$((FAIL+1))
    printf '      --- expected ---\n%s\n      --- actual -----\n%s\n' "$exp" "$act" | sed 's/^/      /'
  fi
}
# assert_rc <name> <expected-rc> <actual-rc>
assert_rc() {
  local name="$1" exp="$2" act="$3"
  if [[ "$exp" == "$act" ]]; then
    printf 'PASS  %s (exit=%s)\n' "$name" "$act"; PASS=$((PASS+1))
  else
    printf 'FAIL  %s (exit=%s want %s)\n' "$name" "$act" "$exp"; FAIL=$((FAIL+1))
  fi
}

# ---- Case: real PASS markers parse; emit() definition line is ignored --------
D="$(mktemp -d)"
{ printf '%s\n%s\n%s\n' "$REAL_SERVER_PASS" "$REAL_AC_PASS" "$REAL_EMIT_DEF"; } \
  > "$D/blue-green-deploy__1750000000__900.log"
got="$(bash "$SCRIPT" "$D")"
want="pass${TAB}blue-green-deploy${TAB}layerv/nhp-ac${TAB}audit${TAB}900${TAB}1750000000${TAB}0
pass${TAB}blue-green-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}900${TAB}1750000000${TAB}0"
assert_eq "real pass markers parse; emit() def line ignored" "$want" "$got"
rm -rf "$D"

# ---- Case: error fires under audit (THE acceptance criterion: a persistent ----
#           infra/permission error must page even though the gate is in audit) --
D="$(mktemp -d)"
marker error layerv/nhp-server audit > "$D/canary-deploy__1750000100__111.log"
got="$(bash "$SCRIPT" "$D")"
want="error${TAB}canary-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}111${TAB}1750000100${TAB}1"
assert_eq "error under audit -> fire=1 (silent fail-open detector)" "$want" "$got"
rm -rf "$D"

# ---- Case: error fires under enforce -----------------------------------------
D="$(mktemp -d)"
marker error layerv/nhp-ac enforce > "$D/canary-deploy__1750000100__112.log"
got="$(bash "$SCRIPT" "$D")"
want="error${TAB}canary-deploy${TAB}layerv/nhp-ac${TAB}enforce${TAB}112${TAB}1750000100${TAB}1"
assert_eq "error under enforce -> fire=1" "$want" "$got"
rm -rf "$D"

# ---- Case: fail fires ONLY under enforce -------------------------------------
D="$(mktemp -d)"
marker fail layerv/nhp-server enforce > "$D/promote-to-prod__1750000200__300.log"
got="$(bash "$SCRIPT" "$D")"
want="fail${TAB}promote-to-prod${TAB}layerv/nhp-server${TAB}enforce${TAB}300${TAB}1750000200${TAB}1"
assert_eq "fail under enforce -> fire=1 (verdict blocked / under-matched INFRA_RE)" "$want" "$got"
rm -rf "$D"

# ---- Case: fail under audit must NOT page (expected legacy/pre-#2339 soak) ----
D="$(mktemp -d)"
marker fail layerv/nhp-server audit > "$D/blue-green-deploy__1750000050__400.log"
got="$(bash "$SCRIPT" "$D")"
want="fail${TAB}blue-green-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}400${TAB}1750000050${TAB}0"
assert_eq "fail under audit -> fire=0 (no page during audit soak)" "$want" "$got"
rm -rf "$D"

# ---- Case: latest run per lane wins (an older error superseded by a newer pass
#           on the SAME lane reports the recovery, not the stale error) ---------
D="$(mktemp -d)"
marker error layerv/nhp-server audit > "$D/blue-green-deploy__1750000000__900.log"
marker pass  layerv/nhp-server audit > "$D/blue-green-deploy__1750009999__901.log"
got="$(bash "$SCRIPT" "$D")"
want="pass${TAB}blue-green-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}901${TAB}1750009999${TAB}0"
assert_eq "latest-per-lane: newer pass supersedes older error" "$want" "$got"
rm -rf "$D"

# ---- Case: stale error persists until a newer run proves recovery ------------
#      (older pass + newer error on one lane -> the error is current -> fire) ---
D="$(mktemp -d)"
marker pass  layerv/nhp-ac audit > "$D/canary-deploy__1750000000__500.log"
marker error layerv/nhp-ac audit > "$D/canary-deploy__1750009999__501.log"
got="$(bash "$SCRIPT" "$D")"
want="error${TAB}canary-deploy${TAB}layerv/nhp-ac${TAB}audit${TAB}501${TAB}1750009999${TAB}1"
assert_eq "latest-per-lane: newer error supersedes older pass" "$want" "$got"
rm -rf "$D"

# ---- Case: mixed multi-lane corpus, stable workflow-then-repo ordering --------
D="$(mktemp -d)"
{ printf '%s\n%s\n' "$REAL_SERVER_PASS" "$REAL_AC_PASS"; } > "$D/blue-green-deploy__1750000300__700.log"
marker error layerv/nhp-server audit   > "$D/canary-deploy__1750000300__710.log"
marker fail  layerv/nhp-ac     enforce > "$D/canary-deploy__1750000300__711.log"
marker fail  layerv/nhp-server audit   > "$D/promote-to-prod__1750000300__720.log"
got="$(bash "$SCRIPT" "$D")"
# Output is sorted by workflow then repo (ascending), so within canary-deploy the
# nhp-ac lane precedes nhp-server regardless of run id / which error is which.
want="pass${TAB}blue-green-deploy${TAB}layerv/nhp-ac${TAB}audit${TAB}700${TAB}1750000300${TAB}0
pass${TAB}blue-green-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}700${TAB}1750000300${TAB}0
fail${TAB}canary-deploy${TAB}layerv/nhp-ac${TAB}enforce${TAB}711${TAB}1750000300${TAB}1
error${TAB}canary-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}710${TAB}1750000300${TAB}1
fail${TAB}promote-to-prod${TAB}layerv/nhp-server${TAB}audit${TAB}720${TAB}1750000300${TAB}0"
assert_eq "mixed lanes classify + sort stably" "$want" "$got"
rm -rf "$D"

# ---- Case: empty dir -> no output, exit 0 ------------------------------------
D="$(mktemp -d)"
got="$(bash "$SCRIPT" "$D")"; rc=$?
assert_eq "empty dir -> empty report" "" "$got"
assert_rc "empty dir -> exit 0" 0 "$rc"
rm -rf "$D"

# ---- Case: missing dir -> usage error exit 2 ---------------------------------
bash "$SCRIPT" /no/such/dir >/dev/null 2>&1; rc=$?
assert_rc "missing dir -> exit 2" 2 "$rc"

# ---- Case: no args -> usage error exit 2 -------------------------------------
bash "$SCRIPT" >/dev/null 2>&1; rc=$?
assert_rc "no args -> exit 2" 2 "$rc"

# ---- Case: malformed log filename (no '__' metadata) is ignored, not parsed ---
D="$(mktemp -d)"
marker error layerv/nhp-server audit > "$D/notavalidname.log"
got="$(bash "$SCRIPT" "$D" 2>/dev/null)"; rc=$?
assert_eq "malformed filename -> no lane emitted" "" "$got"
assert_rc "malformed filename -> exit 0" 0 "$rc"
rm -rf "$D"

# ---- Case: a run whose log has NO marker (gate step never reached) is a no-op -
D="$(mktemp -d)"
printf 'some unrelated deploy log line\nDeploy\t[Server] Something Else\tno marker here\n' \
  > "$D/promote-to-prod__1750000400__800.log"
got="$(bash "$SCRIPT" "$D")"
assert_eq "marker-less run -> no lane emitted" "" "$got"
rm -rf "$D"

# ---- Case: CRLF line ending (gh logs can carry a trailing \r) parses cleanly --
#      `mode` is the LAST field, so a stray \r would otherwise leak into it
#      ('audit\r'). The parser strips it today; this locks CR-robustness so a
#      future field reorder that moves repo/mode off line-end can't regress it.
D="$(mktemp -d)"
printf '%s\r\n' "$(marker error layerv/nhp-server audit)" > "$D/canary-deploy__1750000600__601.log"
got="$(bash "$SCRIPT" "$D")"
want="error${TAB}canary-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}601${TAB}1750000600${TAB}1"
assert_eq "CRLF marker -> fields parsed without trailing CR" "$want" "$got"
rm -rf "$D"

# ---- Case: same-second epoch tie is broken deterministically by run_id --------
#      Two markers for one lane at the identical epoch; the higher (newer) run_id
#      must win regardless of input order (locks the `-k6,6nr` sort tiebreaker).
D="$(mktemp -d)"
marker error layerv/nhp-server audit > "$D/canary-deploy__1750000700__700.log"
marker pass  layerv/nhp-server audit > "$D/canary-deploy__1750000700__701.log"
got="$(bash "$SCRIPT" "$D")"
want="pass${TAB}canary-deploy${TAB}layerv/nhp-server${TAB}audit${TAB}701${TAB}1750000700${TAB}0"
assert_eq "same-epoch tie -> higher run_id wins" "$want" "$got"
rm -rf "$D"

# ---- Lockstep: the parser is coupled to verify-image-attestation's emit() ----
#      wording. If emit() drifts (renames ATTEST_RESULT / repo= / mode=, drops the
#      ::notice:: prefix), the parser silently matches ZERO markers, the report
#      goes empty, and the watchdog's auto-close path could close a real tracker.
#      Pin the emitter's tokens here so that drift fails CI — forcing a parser +
#      fixture update — instead of going silent. Literal substring checks (no
#      rendering) keyed on the action's actual emit() line.
ACTION="$ROOT/.github/actions/verify-image-attestation/action.yml"
# The single-quoted tokens below are LITERAL emitter source ($1/${REPOSITORY}/
# ${MODE} are shell expansions inside the action, matched verbatim here) — not
# meant to expand, so SC2016 is expected.
# shellcheck disable=SC2016
if [[ -f "$ACTION" ]]; then
  emit_def="$(grep -F 'ATTEST_RESULT=$1' "$ACTION" || true)"
  miss=0
  for tok in '::notice::ATTEST_RESULT=$1' 'repo=${REPOSITORY}' 'mode=${MODE}'; do
    case "$emit_def" in
      *"$tok"*) ;;
      *) printf 'FAIL  emit() drift: token %q absent from action emit() — update scan-attestation-soak.sh regex + re-capture the REAL_* fixtures\n' "$tok"; FAIL=$((FAIL+1)); miss=1 ;;
    esac
  done
  [[ "$miss" -eq 0 ]] && { echo "PASS  emit() lockstep (parser anchor tokens present in verify-image-attestation)"; PASS=$((PASS+1)); }
else
  echo "NOTE  verify-image-attestation/action.yml not found; skipping emit() lockstep"
fi

echo "-----"
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
