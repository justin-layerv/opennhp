#!/usr/bin/env bash
# check-lambda-boto-pin-lockstep.sh
# ----------------------------------------------------------------------------
# Fail if the boto3/botocore version pins across the Lambda requirement files
# under terraform/modules/*/lambda/requirements*.txt fall out of lockstep.
#
# Why this lint exists (#3320/#3323): build-and-push.yml's "Test Lambdas" job
# installs THREE requirement files into ONE shared Python 3.12 env —
#     terraform/modules/acme-cert/lambda/requirements-dev.txt
#     terraform/modules/custom-domain-cert/lambda/requirements-test.txt
#     terraform/modules/status-page/lambda/requirements-dev.txt
# — each pinning boto3== and botocore==. Those three `pip install -r` commands run
# in sequence into the same env, so a pin split has TWO failure modes, and this
# lint exists to catch both before merge:
#   - WITHIN a file, boto3 pinned ahead of botocore fails that file's own install
#     LOUDLY: boto3 X.Y.Z requires botocore>=X.Y.Z, so the pinned older botocore
#     is unsatisfiable → pip ResolutionImpossible. #3320 was exactly this — a lone
#     Dependabot boto3 bump outran botocore in one file.
#   - ACROSS files, each internally consistent but pinning DIFFERENT versions, the
#     installs do not conflict — the LAST `-r` silently wins and every suite then
#     runs against that one version. No install error; CI stays green while some
#     tests exercise an unintended boto3/botocore. This silent last-write-wins case
#     (spelled out in acme-cert/lambda/requirements-dev.txt's own comment) is the
#     more dangerous one.
# #3323 unified the pins to boto3==botocore==1.43.51 and added a boto3+botocore
# Dependabot group (.github/dependabot.yml `aws-sdk` / `aws-sdk-security`) so
# version + security bumps move the pair together. That group stops Dependabot
# from re-splitting the pair, but a hand-edit — or a NEW terraform/modules/*/lambda
# module added with a mismatched pin — is still only convention-enforced (comments
# in the three files). This lint IS that enforcement: a divergent pin fails here at
# lint/PR time instead of loudly (within-file) or silently (cross-file) later.
#
# Invariant (two checks, matching the one-shared-env reality):
#   (a) within any single file that pins both, boto3 == botocore.
#   (b) every boto3==/botocore== pin across ALL the files is the identical
#       version — the sequential installs share one env, so a disagreement can
#       only ever resolve to a single last-write-wins version anyway.
# Equivalently: the set of all pinned versions, across both packages and all
# files, collapses to exactly one version.
#
# Strict equality (rather than pip's weaker `botocore>=boto3` within a series) is
# deliberate: boto3 and botocore currently ship in lockstep at IDENTICAL version
# numbers — the "Test Lambdas" job resolves boto3==botocore==<ver> green, proving
# the equal pins install — and equality is the simpler, safer bias for a shared
# env. If a future release pair ever legitimately ships at DIFFERENT version
# strings again (boto3 and botocore carried a fixed minor-version offset in years
# past), the reconciliation is to RELAX (a)/(b) to pip's real constraint
# (botocore >= boto3 within the same series) — NOT to bump one pin to a version the
# other never shipped, which would pin an untested, possibly-uninstallable combo.
#
# Discovery is terraform/modules/*/lambda/requirements*.txt (one module level).
# The "Test Lambdas" job's actual install list is a hardcoded three-file set in
# build-and-push.yml, maintained INDEPENDENTLY of this glob; the glob is the
# superset SHAPE of it, not a mirror. That biases fail-safe: a new module's pinned
# test file is enforced here even before it is wired into the job (harmless
# over-enforcement — boto3/botocore are a matched pair regardless), while a file
# wired into the job that does NOT match requirements*.txt (e.g.
# test-requirements.txt) would escape — widen the glob if the install list ever
# grows such a file (auto-verifying that coupling is tracked in #3330). A file
# that pins NEITHER package — the deployed runtime
# requirements.txt, or a pytest-only dev file — contributes nothing and is
# skipped. Only exact `==` pins are read; the repo convention pins boto3/botocore
# exactly for reproducible CI installs, so a `>=`/`~=`/`<`/`===` specifier, an
# extras-annotated `boto3[crt]==`, or a boto pulled in transitively via a nested
# `-r other.txt` is invisible here and fails OPEN (a divergence it can't see).
# That is acceptable under the exact-pin convention; a module that deviates must
# extend this parser. If discovery finds NO boto3/botocore `==` pin anywhere, that
# is a hard error (the glob or the pin regex has drifted and the lint would pass
# vacuously) — the same fail-closed checked==0 guard the sibling drift lints carry.
#
# Wired into `make lint-workflows` and .github/workflows/validate-workflows.yml.
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

failures=""
# `checked` counts every boto3/botocore pin the lint actually compared. A final
# checked==0 guard fails closed if discovery matched nothing (glob/regex drift),
# so this lint can never pass vacuously on zero inputs.
checked=0
# `all_versions` is the newline-joined multiset of every pinned version seen; the
# cross-file (b) check collapses it to a distinct set. `pin_summary` accumulates
# one preformatted line per pinning file — the same newline-string idiom as
# `failures` — for the final actionable "Pinned in each …" dump; `file_count` is
# the pinning-file tally for the OK line. Plain strings, no arrays: bash 3.2 on
# macOS dev boxes has no associative arrays, and a string also sidesteps the
# `set -u` empty-array expansion hazard.
all_versions=""
pin_summary=""
file_count=0

fail() {
  failures="${failures}ERROR: $1"$'\n'
}

# Print the pinned version(s) of package $2 (boto3|botocore) in requirements file
# $1, sorted-unique, one per line (empty if unpinned). A top-level `==` pin only:
# leading whitespace tolerated, optional spaces around `==`, version captured up
# to the first whitespace / `;` env-marker / `#` inline comment / `,` / `=` — the
# comma stops the capture at the version proper, so a compound `boto3==1.43.51,<2`
# reads as `1.43.51` (its exact pin) rather than false-drifting on the literal
# `1.43.51,<2`; excluding `=` means the extra `=` of an arbitrary-equality
# `boto3===1.0` can't leak into the version (that non-simple form just fails open,
# below). A trailing CR from a CRLF file is whitespace too (POSIX [:space:] includes \r), so
# it is excluded from the captured version — CRLF files parse identically to LF, no
# invisible-CR false drift (both boundaries locked by fixtures). The package name is anchored at
# ^ so `boto3-stubs==` / `botocore-stubs==` and commented-out
# `# boto3==` lines never match, and `boto3` cannot be read off a `botocore==`
# line (or vice versa). A `-r requirements.txt` include carries no `==` and is
# ignored. An extras-annotated pin (`boto3[crt]==…`) is NOT parsed — the `[`
# breaks the name anchor, so it is skipped (fails open); the repo pins
# boto3/botocore without extras, and adding one should extend this regex + a
# fixture. This runs in a command substitution — it only echoes, never mutates
# globals — so the bash `set -e` + `$(...)` swallow does not hide a failed fail().
uniq_pins() {
  local file="$1" pkg="$2"
  sed -nE "s/^[[:space:]]*${pkg}[[:space:]]*==[[:space:]]*([^[:space:];#,=]+).*/\1/p" "$file" \
    | sort -u
}

# True when the sort -u'd version list $1 holds MORE THAN ONE distinct value.
# Every caller passes a `sort -u` result (non-empty lines, no trailing newline),
# so ">1 value" is exactly "contains a newline" — a subshell-free, bash-3.2-safe
# test with no wc/tr/empty-string bookkeeping.
multiple_versions() {
  [[ "$1" == *$'\n'* ]]
}

# Record a non-empty pinned version into the cross-file multiset and bump the
# compared-pin count. A direct call (not $(...)) so it mutates the globals
# in-shell — bash-3.2-safe, and there is no fail()/subshell contract to preserve
# here (this never calls fail()).
record_pin() {
  [ -n "$1" ] || return 0
  all_versions="${all_versions}$1"$'\n'
  checked=$((checked + 1))
}

shopt -s nullglob
for file in "$REPO_ROOT"/terraform/modules/*/lambda/requirements*.txt; do
  path=${file#"$REPO_ROOT"/}

  b3=""
  bc=""
  b3_list=$(uniq_pins "$file" boto3)
  bc_list=$(uniq_pins "$file" botocore)

  # No boto3/botocore pin at all — runtime requirements.txt or a pytest-only dev
  # file. Nothing to compare; skip so it never appears in drift output.
  if [ -z "$b3_list" ] && [ -z "$bc_list" ]; then
    continue
  fi

  # A single requirements file must pin each package at most once. Two differing
  # boto3 (or botocore) `==` lines are self-contradictory — flag and treat the
  # package as unusable rather than silently picking one.
  if multiple_versions "$b3_list"; then
    fail "$path: multiple differing boto3 pins ($(printf '%s' "$b3_list" | tr '\n' ' ')) — pin boto3 exactly once."
  else
    b3="$b3_list"
  fi
  if multiple_versions "$bc_list"; then
    fail "$path: multiple differing botocore pins ($(printf '%s' "$bc_list" | tr '\n' ' ')) — pin botocore exactly once."
  else
    bc="$bc_list"
  fi

  pin_summary="${pin_summary}    ${path}: boto3==${b3:-<none>} botocore==${bc:-<none>}"$'\n'
  file_count=$((file_count + 1))
  record_pin "$b3"
  record_pin "$bc"

  # (a) within-file: boto3 and botocore must pin the SAME version. Either
  # direction is wrong, for different reasons: boto3 ahead of botocore fails this
  # file's own `pip install -r` outright (the #3320 shape), while botocore ahead
  # installs today but is a mismatched pair — the message spells out both.
  if [ -n "$b3" ] && [ -n "$bc" ] && [ "$b3" != "$bc" ]; then
    fail "$path: boto3==$b3 does not match botocore==$bc — pin the SAME version (boto3 and botocore ship in lockstep at matching versions). boto3 ahead of botocore fails this file's install outright (boto3 X requires botocore>=X → pip ResolutionImpossible, the #3320 shape); botocore ahead installs today but is a mismatched pair one lone boto3 bump from the same break."
  fi
done

# (b) cross-file: with more than one pinning file, every pin across both packages
# and all files must be one version. The file_count>1 gate keeps a lone file's
# within-file split from ALSO tripping this "across the files" message (which
# reads oddly for a single file) — the (a) check already reports that case with a
# one-file-appropriate message. It loses no coverage: with a single pinning file
# any disagreement is within it (caught by (a)) or a duplicate pin (caught by the
# multiplicity check). Safe when nothing was pinned — file_count==0 falls through
# to the fail-closed checked==0 guard below.
distinct=$(printf '%s' "$all_versions" | sort -u)
if [ "$file_count" -gt 1 ] && multiple_versions "$distinct"; then
  fail "boto3/botocore pins are not identical across the shared-env lambda requirement files (found: $(printf '%s' "$distinct" | tr '\n' ' ')) — the sequential 'Test Lambdas' installs share one env, so a disagreement silently resolves last-write-wins and runs some suites against an unintended version."
fi

if [ -n "$failures" ]; then
  echo "DRIFT: lambda boto3/botocore pin lockstep check failed." >&2
  echo "" >&2
  printf '%s' "$failures" >&2
  echo "" >&2
  echo "Pinned in each shared-env lambda requirements file:" >&2
  printf '%s' "$pin_summary" >&2
  echo "" >&2
  echo "build-and-push.yml's 'Test Lambdas' job installs all of these into ONE Python env, so every boto3==/botocore== pin must be the identical version (boto3 and botocore ship in lockstep at matching versions). Bump the pair together — Dependabot's aws-sdk group keeps them aligned; see .github/dependabot.yml and the header of this script." >&2
  exit 1
fi

# Fail-closed: no failures above, yet discovery compared no pins at all — the glob
# no longer reaches the lambda requirement files, or the `==` regex stopped
# matching them. Without this the lint would report false-green on zero inputs.
# Checked AFTER the failures block on purpose: a file whose only boto content is
# self-contradictory duplicate pins leaves checked==0 too, and it must report that
# specific "multiple differing … pins" error rather than this generic one.
if [ "$checked" -eq 0 ]; then
  echo "ERROR: no boto3/botocore == pins found under terraform/modules/*/lambda/requirements*.txt — the discovery glob or the pin regex has drifted; this lint would otherwise pass vacuously on nothing." >&2
  exit 1
fi

echo "OK: lambda boto3/botocore pins in lockstep ($checked pin(s) at $distinct across $file_count file(s))"
