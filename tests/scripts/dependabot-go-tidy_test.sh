#!/usr/bin/env bash
# dependabot-go-tidy_test.sh — structural regression fence for the
# dependabot-go-tidy workflow's bot-identity preflight.
# ----------------------------------------------------------------------------
# PR #1384 introduced `gh api /user` as a preflight to assert the App
# token resolved to `ops-routines-reader[bot]` before pushing. The bug:
# `/user` is unsupported on GitHub App installation tokens — it returns
# HTTP 403 "Resource not accessible by integration". The bug stayed
# latent because every prior tidy run on nhp was either a no-op (commit
# step skipped via `if: changed == 'true'`) or 404'd at the upstream
# App-token mint (App not yet installed on nhp). PR #1409's commit
# step finally exercised the path on 2026-05-07 and surfaced the 403.
#
# PR #1777 swapped the call for the action's `app-slug` output, which
# the action computes from the resolved App ID — preserving the
# swap-defense (a swapped OPS_ROUTINES_APP_ID still surfaces as a slug
# mismatch) without hitting an unsupported endpoint.
#
# Assertions (5 total — must stay in lockstep with the matchers below):
#   1. The workflow does NOT contain `gh api /user` (or quoted variants)
#      in executable code. Comments mentioning the endpoint are fine.
#   2. The workflow references `steps.app_token.outputs.app-slug`.
#   2w. The `APP_SLUG` env var binds to `steps.app_token.outputs.app-slug`
#       specifically (not just any output reference somewhere).
#   3. AUTH_USER is constructed from APP_SLUG (not from a `gh api` call).
#   4. EXPECTED_BOT_USER is pinned to `ops-routines-reader[bot]` so an
#      App rename surfaces at lint time, not at next runtime push.
#
# Each assertion's matching logic is factored into a function that runs
# against both the real workflow file AND inline self-test fixtures, so
# a future regex weakening (e.g., losing the right-boundary, dropping
# the inline-comment strip) is caught even if the real file happens to
# stay clean — the fixtures encode known-bad patterns the fence MUST
# trip on.
#
# Usage: bash tests/scripts/dependabot-go-tidy_test.sh
# ============================================================================

# No `-e`: every assertion must run so the operator sees all failures
# in one run. Exit status comes from the `fail` counter at the bottom.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
WORKFLOW="$REPO_ROOT/.github/workflows/dependabot-go-tidy.yml"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# ----------------------------------------------------------------------------
# Matchers (each returns 0 for "pattern present", 1 for "absent")
#
# When adding a matcher, grep the herestring: `grep -qE 'pat' <<<"$1"`, NOT
# `printf '%s\n' "$1" | grep -qE 'pat'`. `grep -q` exits on first match and
# SIGPIPEs the upstream writer; under `set -o pipefail` (set above) that becomes
# a spurious exit 141 on a job that actually matched — a timing-dependent flake
# (#2256). The herestring has no upstream writer to race.
# ----------------------------------------------------------------------------

# Pipeline:
#   1. Collapse `\<newline><ws>` line continuations so multi-line
#      `gh api \\<NL>  /user` invocations match the line-level
#      conjunction below. Without this, the two greps see the `\`
#      and `/user` on different lines and miss the call.
#      Sed compatibility: `\n` in the LHS of `s///` matches the
#      embedded newline characters that the `:a;$!{N;ba}` loop
#      builds into the pattern space. Verified empirically on both
#      macOS BSD sed (`/usr/bin/sed`) and GNU sed (Linux CI). If a
#      future runner uses a strict-POSIX sed where `\n` in LHS is
#      literal `n`, the multi-line continuation fixture will fail
#      loudly — switch to an awk- or perl-based join at that point.
#   2. Strip inline comments (`<ws>#...$`) so bash `${VAR#suffix}`
#      and YAML key suffixes are preserved.
#   3. Drop full-line comments.
#   4+5. Line-level conjunction — line contains `gh api` AND line
#      contains `/user(boundary)`. So `gh api -X GET /user`, `gh api
#      --method GET /user`, quoted forms (`"/user"` / `'/user'`),
#      `gh api https://api.github.com/user`, and the multi-line
#      continuation shape all trip.
# Right-boundary `($|[^a-zA-Z0-9_/])` keeps the assertion scoped to
# the literal `GET /user` endpoint and excludes `/users/{name}` and
# `/user/repos`. Kept narrow because `/user` is the only auth-
# context-derived endpoint that 403s on installation tokens —
# `/users/*` and `/user/repos` are properly scoped (resolve a path
# arg or repo collection, not the auth identity) and work fine on
# installation tokens. Don't widen without a documented case.
matches_gh_api_user() {
  # Capture the filtered text, then grep -q the herestring. A `grep -q` at the
  # end of a pipe early-exits on first match and SIGPIPEs the upstream stages;
  # under `set -o pipefail` that surfaces as a spurious exit 141 ("write error:
  # Broken pipe") on a job that actually matched — a timing-dependent CI flake
  # (#2256). The capture pipeline has no early-exit consumer, so it can't race.
  local filtered
  filtered=$(printf '%s\n' "$1" \
    | sed -e ':a' -e '$!{N;ba' -e '}' -e 's/\\\n[[:space:]]*/ /g' \
    | sed 's/[[:space:]]\{1,\}#.*$//' \
    | grep -vE '^[[:space:]]*#' \
    | grep -E 'gh[[:space:]]+api[[:space:]]+')
  grep -qE '/user($|[^a-zA-Z0-9_/])' <<<"$filtered"
}

matches_app_slug_output_ref() {
  grep -qE 'steps\.app_token\.outputs\.app-slug' <<<"$1"
}

# Closes a wiring gap: `matches_app_slug_output_ref` and
# `matches_auth_user_from_app_slug` each assert one side of the
# binding, but neither asserts the env var named `APP_SLUG` is bound
# to that specific output. A future refactor could rename the env on
# one side and not the other and pass both checks. This matcher
# fences the literal `APP_SLUG: ${{ steps.app_token.outputs.app-slug }}`
# binding.
#
# Don't delete `matches_app_slug_output_ref` as "subsumed by this":
# the split gives a more precise error message when the output isn't
# referenced anywhere vs when it's referenced but not bound to
# `APP_SLUG`. Operator hitting a fence failure benefits from the
# distinction.
#
# Step-id constraint: this matcher hard-codes `steps.app_token.` —
# a semantically-equivalent rename of the step id (e.g.,
# `gh_app_token`) trips the fence as a false-positive. If the step
# id is renamed, update this matcher in lockstep with the workflow.
# Relaxing to `steps\.[a-z_]+\.` would weaken the wiring assertion
# (the fence wouldn't catch an output bound to a different step
# entirely), which is a worse tradeoff for the rename frequency
# (~zero in this workflow's history).
#
# Parser-vs-grep tradeoff: this is line-level grep over YAML, not
# real YAML parsing. A literal block-scalar containing
# `APP_SLUG: ${{ ... }}` would false-positive (matches in a string)
# and a folded scalar splitting `APP_SLUG:` from its value would
# false-negative (matches across lines). Real-world workflow YAML
# doesn't take either shape; widening to PyYAML-based parsing (per
# `test_promote_to_prod_gating.py`) would be the upgrade path if
# the YAML structure ever gets clever enough to warrant it.
matches_app_slug_env_wiring() {
  # shellcheck disable=SC2016 # literal `${{ ... }}` is GitHub Actions expression syntax.
  grep -qE 'APP_SLUG:[[:space:]]*\$\{\{[[:space:]]*steps\.app_token\.outputs\.app-slug[[:space:]]*\}\}' <<<"$1"
}

# Explicit alternation — `${APP_SLUG}` OR `$APP_SLUG`, no malformed
# half-braced forms. Both are bash-semantic equivalents:
# `${APP_SLUG}[bot]` and `$APP_SLUG[bot]` parse identically because
# `[bot]` outside of `[[ ]]` / arithmetic / array contexts is a
# literal string. The braced form is unambiguous and stylistically
# preferred (and is what the workflow uses today); the unbraced form
# is accepted so a semantically-equivalent reformat doesn't trip the
# fence as a false-positive. If you want to require the braced form
# only, drop the unbraced alternative.
matches_auth_user_from_app_slug() {
  # shellcheck disable=SC2016 # literal `$` and braces are regex content, not parameter expansion.
  grep -qE 'AUTH_USER="(\$\{APP_SLUG\}|\$APP_SLUG)\[bot\]"' <<<"$1"
}

# Pin the `EXPECTED_BOT_USER` constant. The header comment at the env
# block says "If the App is renamed or swapped, update here and the
# header comment in lockstep" — but a one-sided change would still
# satisfy assertions 2/2w/3 because they fence the binding shape, not
# the expected slug. This matcher fences the literal value so a
# rename gets caught at lint time, not at the next runtime push.
# When the App is genuinely renamed, update both this matcher's
# pattern AND the workflow env in the same PR.
matches_expected_bot_user_pinned() {
  grep -qE 'EXPECTED_BOT_USER:[[:space:]]+ops-routines-reader\[bot\]' <<<"$1"
}

# ----------------------------------------------------------------------------
# Self-test: run matchers against known-good and known-bad fixtures.
# Catches regex regressions that would otherwise let the real-file
# assertions silently pass after a refactor weakened the matcher.
# ----------------------------------------------------------------------------

selftest() {
  local name="$1" matcher="$2" expected="$3" fixture="$4" actual
  if "$matcher" "$fixture"; then
    actual="match"
  else
    actual="no-match"
  fi
  if [ "$actual" = "$expected" ]; then
    report_pass "selftest: $name"
  else
    report_fail "selftest: $name" "expected $expected, got $actual on fixture: $(printf '%s' "$fixture" | head -c 60)"
  fi
}

printf '\nDependabot Go Mod Tidy preflight (PR #1777 fence)\n'
printf '\n  -- matcher self-tests --\n'

# Fixtures use literal `${...}` and `$(...)` strings as regex inputs;
# shell expansion is exactly what we want suppressed here.
# shellcheck disable=SC2016
{
  selftest "1. catches bare call"          matches_gh_api_user "match"    'AUTH_USER=$(gh api /user --jq .login)'
  selftest "1. catches -X GET form"        matches_gh_api_user "match"    'gh api -X GET /user --jq .login'
  selftest "1. catches --method form"      matches_gh_api_user "match"    'gh api --method GET /user'
  selftest "1. catches https URL form"     matches_gh_api_user "match"    'gh api -X GET https://api.github.com/user --jq .login'
  selftest "1. catches double-quoted"      matches_gh_api_user "match"    'gh api "/user" >> log'
  selftest "1. catches single-quoted"      matches_gh_api_user "match"    "gh api '/user' >> log"
  selftest "1. catches multi-line cont"    matches_gh_api_user "match"    $'AUTH_USER=$(gh api \\\n  /user \\\n  --jq .login)'
  selftest "1. ignores full-line comment"  matches_gh_api_user "no-match" '# documentation: gh api /user is unsupported'
  selftest "1. ignores inline comment"     matches_gh_api_user "no-match" 'echo hi  # gh api /user — note'
  selftest "1. ignores /users plural"      matches_gh_api_user "no-match" 'gh api /users/posey/repos'
  selftest "1. ignores /user/repos"        matches_gh_api_user "no-match" 'gh api /user/repos'
  # Lock the design boundary: the legitimate `gh api repos/...`
  # calls in the same workflow MUST NOT trip the fence. If a future
  # widening (e.g., relaxing the right-boundary to also match `/user`
  # at start-of-string) breaks this, the fence flips red on the
  # workflow's own correct calls.
  selftest "1. ignores legitimate repos call" matches_gh_api_user "no-match" 'gh api "repos/$REPO/git/refs/heads/$BRANCH"'
  # `gh api user` (no leading slash) is the same endpoint as `/user`
  # and equally broken on installation tokens, but the matcher
  # requires a leading `/` by design. Widening to optional slash
  # would false-positive on `--user` flags, `my-user` substrings,
  # and `gh api repos/$user/...`. Rare in practice; if a future
  # contributor writes `gh api user`, runtime will still 403 with
  # the same operator-readable error and the trap surfaces it.
  selftest "1. ignores no-slash (by design)" matches_gh_api_user "no-match" 'gh api user --jq .login'

  selftest "2. catches output ref"         matches_app_slug_output_ref "match"    'APP_SLUG: ${{ steps.app_token.outputs.app-slug }}'
  selftest "2. ignores absent"             matches_app_slug_output_ref "no-match" 'APP_SLUG: ${{ secrets.SOMETHING }}'

  selftest "2w. catches env binding"       matches_app_slug_env_wiring "match"    'APP_SLUG: ${{ steps.app_token.outputs.app-slug }}'
  selftest "2w. catches no-spaces form"    matches_app_slug_env_wiring "match"    'APP_SLUG: ${{steps.app_token.outputs.app-slug}}'
  selftest "2w. rejects renamed env"       matches_app_slug_env_wiring "no-match" 'OTHER_VAR: ${{ steps.app_token.outputs.app-slug }}'
  selftest "2w. rejects wrong output"      matches_app_slug_env_wiring "no-match" 'APP_SLUG: ${{ steps.app_token.outputs.token }}'

  selftest "3. catches braced"             matches_auth_user_from_app_slug "match"    'AUTH_USER="${APP_SLUG}[bot]"'
  selftest "3. catches unbraced"           matches_auth_user_from_app_slug "match"    'AUTH_USER="$APP_SLUG[bot]"'
  selftest "3. rejects gh-api form"        matches_auth_user_from_app_slug "no-match" 'AUTH_USER=$(gh api /user --jq .login)'
  selftest "3. rejects malformed braces"   matches_auth_user_from_app_slug "no-match" 'AUTH_USER="${APP_SLUG[bot]"'

  selftest "4. catches expected pin"       matches_expected_bot_user_pinned "match"    'EXPECTED_BOT_USER: ops-routines-reader[bot]'
  selftest "4. rejects different slug"     matches_expected_bot_user_pinned "no-match" 'EXPECTED_BOT_USER: some-other-app[bot]'
  selftest "4. rejects missing [bot]"      matches_expected_bot_user_pinned "no-match" 'EXPECTED_BOT_USER: ops-routines-reader'
}

# ----------------------------------------------------------------------------
# Real-file assertions
# ----------------------------------------------------------------------------

if [ ! -f "$WORKFLOW" ]; then
  printf '\033[31mFAIL\033[0m: workflow not found at %s\n' "$WORKFLOW"
  exit 1
fi

printf '\n  -- workflow file assertions --\n'
WORKFLOW_TEXT=$(cat "$WORKFLOW")

if matches_gh_api_user "$WORKFLOW_TEXT"; then
  report_fail "no gh api /user" "workflow re-introduced unsupported endpoint in executable code; see PR #1777"
else
  report_pass "no gh api /user (executable code)"
fi

if matches_app_slug_output_ref "$WORKFLOW_TEXT"; then
  report_pass "uses steps.app_token.outputs.app-slug"
else
  report_fail "uses steps.app_token.outputs.app-slug" "bot-identity invariant must read app-slug from create-github-app-token's outputs"
fi

if matches_app_slug_env_wiring "$WORKFLOW_TEXT"; then
  report_pass "APP_SLUG env wired to app-slug output"
else
  # shellcheck disable=SC2016 # literal `${{ ... }}` is GitHub Actions expression syntax.
  report_fail "APP_SLUG env wired to app-slug output" 'expected `APP_SLUG: ${{ steps.app_token.outputs.app-slug }}` — env var must bind to the action output, not just reference it elsewhere'
fi

if matches_auth_user_from_app_slug "$WORKFLOW_TEXT"; then
  report_pass "AUTH_USER constructed from APP_SLUG"
else
  # shellcheck disable=SC2016 # literal ${APP_SLUG} is the intent — it's workflow-syntax, not a shell variable to expand here.
  report_fail "AUTH_USER constructed from APP_SLUG" 'expected AUTH_USER="${APP_SLUG}[bot]" or AUTH_USER="$APP_SLUG[bot]"'
fi

if matches_expected_bot_user_pinned "$WORKFLOW_TEXT"; then
  report_pass "EXPECTED_BOT_USER pinned to ops-routines-reader[bot]"
else
  report_fail "EXPECTED_BOT_USER pinned to ops-routines-reader[bot]" "EXPECTED_BOT_USER constant must equal 'ops-routines-reader[bot]' — App rename requires updating the matcher in lockstep with the workflow env"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"

if [ "$fail" -gt 0 ]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
