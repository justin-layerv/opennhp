#!/usr/bin/env bash
# check-redirect-url-drift.sh
# ----------------------------------------------------------------------------
# Fence drift between the `redirectURLField` constants in:
#
#   - endpoints/server/staticplugins/qurl/main.go
#       (handler: emits this JSON field on the Accept: application/json branch)
#   - tests/smoke/15_resolve_accept_negotiation_test.go
#       (smoke: verifies the field on the wire against the deployed server)
#
# The duplication is intentional. The smoke suite is a separate Go module
# with no `replace` line back to endpoints/, so the smoke test can't import
# the plugin's package. Both files document the mirror in their source
# comments. The risk this lint addresses: if the plugin's literal is
# renamed, the smoke test would silently keep checking the old field name
# and pass against a deployed server that no longer emits it — a missed
# wire-contract regression.
#
# Strategy: extract the right-hand side of `redirectURLField = "<value>"`
# from each file and compare. Anchoring on the constant *name* (rather
# than grepping for the bare `"redirect_url"` literal) means a deliberate
# lockstep rename to a different value is correctly accepted as in-sync,
# while one-sided edits — to either the value or the name — are caught.
#
# Usage:
#   ./scripts/check-redirect-url-drift.sh                    # production paths
#   ./scripts/check-redirect-url-drift.sh PLUGIN SMOKE       # override paths
#                                                            # (used by the
#                                                            # fixture suite)
#   make lint-redirect-url-drift                             # wired into lint
# ============================================================================

set -euo pipefail

# Two optional positional args allow the fixture suite at
# tests/lints/redirect-url-drift/ to point this script at synthetic Go
# files without symlink gymnastics. With no args, defaults are the
# canonical production paths so the public CLI stays a no-arg call.
# Reject exactly one arg — asymmetric calls would silently mix a
# custom plugin path with the default smoke path, comparing apples
# and oranges.
if [ $# -ne 0 ] && [ $# -ne 2 ]; then
  echo "usage: $0 [PLUGIN_FILE SMOKE_FILE]" >&2
  echo "  with no args: check the canonical production paths" >&2
  echo "  with two args: check the supplied paths (used by the fixture suite)" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_FILE="${1:-${REPO_ROOT}/endpoints/server/staticplugins/qurl/main.go}"
SMOKE_FILE="${2:-${REPO_ROOT}/tests/smoke/15_resolve_accept_negotiation_test.go}"

# extract_field <file> — print the string content of the first
# `redirectURLField = "..."` (or backtick raw-string) assignment in
# <file>, or fail loud.
#
# The regex tolerates:
#   - a leading `const ` keyword (smoke uses `const redirectURLField = "..."`;
#     plugin declares it inside a `const ( ... )` block with no per-line keyword)
#   - either Go string-literal form: double-quoted ("redirect_url") or
#     backtick raw ( `redirect_url` ). Both are valid Go and either could
#     appear after a refactor; ignoring backticks would be silent-fail-prone.
#
# What does NOT match (and surfaces via the "could not find" error
# path, fail-closed):
#   - typed declaration: `redirectURLField string = "..."` — the regex
#     requires whitespace-then-equals immediately after the identifier.
#   - renamed identifier: any name other than `redirectURLField`.
#
# Soft spot: an embedded escaped quote in a double-quoted literal
# (`redirectURLField = "foo\"bar"`) would be matched as `"foo\"`,
# yielding a truncated RHS rather than an error. JSON field names with
# embedded quotes aren't a real concern in practice; if that ever
# changes, harden the alternation to `"([^"\\]|\\.)*"`.
extract_field() {
  local file="$1"
  if [ ! -e "$file" ]; then
    echo "ERROR: missing $file" >&2
    exit 1
  fi
  if [ -d "$file" ]; then
    echo "ERROR: $file is a directory, expected a file" >&2
    exit 1
  fi
  # `^[[:space:]]*` anchors the match to start-of-line (modulo leading
  # whitespace, since main.go indents the const inside a `const ( ... )`
  # block). Without the anchor, a `// previously redirectURLField = "..."`
  # comment line ahead of the real declaration would match — `//` is
  # not whitespace, so the anchor cleanly rejects `//`-prefixed lines.
  # This is the defense for line-comment hazards.
  #
  # Two patterns ORed for the RHS: double-quoted then backtick raw.
  # SC2016 disabled on the grep line below: the backticks inside the
  # single-quoted regex are literal Go raw-string delimiters, not
  # command substitution.
  #
  # The process-substitution feed (`done < <(grep ...)`) doesn't
  # propagate the inner pipeline's exit code, so a no-match is harmless
  # here — no `|| true` needed. The `${#matches[@]}` count below decides
  # what to surface.
  #
  # `grep -v '^[[:space:]]*\*'` pre-filter is defense-in-depth against
  # Go-convention block-comment continuation lines (` * redirectURLField
  # = "old"` inside a `/* ... */` block). Strictly speaking the regex
  # anchor below already rejects these — `^[[:space:]]*` consumes the
  # leading whitespace and the next required token is `(const )?
  # redirectURLField`, but the actual next char is `*`, so the match
  # fails. Keeping the pre-filter belt-and-suspenders so a future regex
  # relaxation (e.g., loosening the anchor) doesn't silently lose
  # block-comment rejection. The `block-comment-go-style` fixture
  # exercises the path. Block comments that DON'T use the `*`
  # continuation convention (e.g. `/*\n redirectURLField = "old"\n*/`)
  # are a remaining soft spot — production const declarations rarely
  # carry block comments, and a full block-comment-aware filter would
  # require a per-file state machine.
  #
  # CRLF: the regex captures only up to the closing `"` or `` ` ``, so
  # a trailing `\r` from a CRLF-edited file is naturally outside the
  # match. The `crlf-line-ending` synth fixture verifies this and would
  # surface as a fixture failure if a future regex relaxation allowed
  # trailing characters past the closing delimiter.
  # Collect all matches (post-filter) into an array. `head -n1` would
  # silently mask a second declaration with a different value — possible
  # if a build-tag-gated alternate or a half-finished rename leaves two
  # `redirectURLField = "..."` lines in the same file. Fail loud on
  # >1 matches; the lint exists precisely to catch silent drift.
  local matches=()
  local m
  # shellcheck disable=SC2016 # backticks are literal Go raw-string delimiters
  while IFS= read -r m; do
    [ -n "$m" ] && matches+=("$m")
  done < <(grep -v -E '^[[:space:]]*\*' "$file" | grep -E -o '^[[:space:]]*(const[[:space:]]+)?redirectURLField[[:space:]]*=[[:space:]]*("[^"]*"|`[^`]*`)')
  if [ "${#matches[@]}" -eq 0 ]; then
    echo "ERROR: could not find \`redirectURLField = \"...\"\` in $file" >&2
    echo "       Either the constant was renamed, the literal was removed," >&2
    echo "       or a typed declaration (\`redirectURLField string = \"...\"\`)" >&2
    echo "       was introduced. This lint guards against drift between the" >&2
    echo "       plugin handler and the smoke test that verifies the wire" >&2
    echo "       contract." >&2
    exit 1
  fi
  if [ "${#matches[@]}" -gt 1 ]; then
    echo "ERROR: multiple \`redirectURLField = \"...\"\` declarations in $file:" >&2
    for m in "${matches[@]}"; do
      echo "    $m" >&2
    done
    echo "  This lint compares a single declaration per file. Two on one" >&2
    echo "  side (build-tag drift, half-finished rename, etc.) could let" >&2
    echo "  a divergent value slip past — exactly the failure mode the" >&2
    echo "  lint exists to catch." >&2
    exit 1
  fi
  local line="${matches[0]}"
  # Strip up to and including the opening delimiter (" or `), then the
  # trailing delimiter. Bash's `##` is greedy and would eat the inner
  # value, so `#` (non-greedy from the front) is required.
  local rhs="${line#*[\"\`]}"
  rhs="${rhs%[\"\`]}"
  printf '%s\n' "$rhs"
}

plugin_value="$(extract_field "$PLUGIN_FILE")"
smoke_value="$(extract_field "$SMOKE_FILE")"

# Guard against the both-sides-empty silent-pass: `redirectURLField = ""`
# is a valid Go declaration the regex cleanly extracts, but emitting an
# empty JSON field name would break the wire contract. If both sides
# happened to be empty, the equality check below would silently green.
# Fail loud here instead — the smoke test would catch this elsewhere
# but the lint should not be the thing that hid it.
if [ -z "$plugin_value" ] || [ -z "$smoke_value" ]; then
  echo "ERROR: redirectURLField extracted to an empty string." >&2
  echo "  plugin: \"$plugin_value\" ($PLUGIN_FILE)" >&2
  echo "  smoke:  \"$smoke_value\" ($SMOKE_FILE)" >&2
  echo "  An empty JSON field name would break the wire contract." >&2
  exit 1
fi

if [ "$plugin_value" != "$smoke_value" ]; then
  # Render extracted values without quotes — the source could be a
  # double-quoted or backtick-raw literal, and showing one form when
  # the source used the other would be misleading. Use `→` to
  # disambiguate display from source syntax.
  echo "ERROR: redirectURLField drift between plugin and smoke test." >&2
  echo "  $PLUGIN_FILE:" >&2
  echo "    redirectURLField → $plugin_value" >&2
  echo "  $SMOKE_FILE:" >&2
  echo "    redirectURLField → $smoke_value" >&2
  echo "" >&2
  echo "These two values must match. The smoke test verifies the JSON" >&2
  echo "field name the plugin emits on the wire; if they diverge, the" >&2
  echo "smoke test passes against a server that no longer emits the" >&2
  echo "field it's checking. See issue #1325." >&2
  exit 1
fi

echo "redirectURLField in sync: $plugin_value"
