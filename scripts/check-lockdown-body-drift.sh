#!/usr/bin/env bash
# check-lockdown-body-drift.sh
# ----------------------------------------------------------------------------
# Fence drift between the lockdown fixed-response body shape declared in:
#
#   - terraform/modules/qurl-service/main.tf
#       (aws_lb_listener_rule.public_internal_block — emits this body
#        to the wire on /internal/* on the public ALB)
#   - tests/smoke/09_public_alb_internal_lockdown_test.go
#       (publicALBLockdownExpectedBody — smoke asserts the same shape
#        on the wire against the deployed ALB)
#
# The duplication is intentional (the smoke suite cannot import a
# Terraform-rendered string). Both files have "COORDINATED CHANGE"
# comments naming each other. The risk this lint addresses: a one-
# sided edit to the body shape — e.g., switching to gin's text/plain
# to close the body-shape fingerprint leak documented at the TF
# header — would leave the smoke fence asserting against the prior
# JSON shape and silently false-positive.
#
# Strategy: extract a canonical normalized body shape from each file
# and compare. The normalized form strips whitespace and quote-style
# differences so a refactor that switches single → double quotes (Go
# isn't a JSON file, but the map literal can be rewritten) doesn't
# trip a false drift.
#
# Soft spot: the extractor's regex (`jsonencode\(\{[^}]+\}\)`) is
# single-level brace matching. NESTED jsonencode bodies — e.g.,
# `jsonencode({ error = "not found", details = { code = 1 } })` —
# truncate at the inner `}` and produce a malformed match that the
# downstream `normalize_tf` would fail to parse. Additive flat
# keys (e.g., `{ error = "not found", request_id = "" }`) are
# unaffected: that body has exactly one closing brace before the
# closing paren so the regex matches it fully.
#
# Acceptable trade because the structural risk is one-sided
# removal/rename (caught), not nested-evolution; if a future
# response body grows nested structure, harden the extractor to
# bracket-count or scope it tighter inside the `fixed_response`
# sub-block.
#
# Usage:
#   ./scripts/check-lockdown-body-drift.sh                    # production paths
#   ./scripts/check-lockdown-body-drift.sh TF_FILE GO_FILE    # override paths
#                                                             # (used by the
#                                                             # fixture suite,
#                                                             # if added later)
# ============================================================================

set -euo pipefail

if [ $# -ne 0 ] && [ $# -ne 2 ]; then
  echo "usage: $0 [TF_FILE GO_FILE]" >&2
  echo "  with no args: check the canonical production paths" >&2
  echo "  with two args: check the supplied paths" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_FILE="${1:-${REPO_ROOT}/terraform/modules/qurl-service/main.tf}"
GO_FILE="${2:-${REPO_ROOT}/tests/smoke/09_public_alb_internal_lockdown_test.go}"

for f in "$TF_FILE" "$GO_FILE"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: missing $f" >&2
    exit 1
  fi
done

# Extract the TF body from `jsonencode({ error = "not found" })`,
# anchored on the `aws_lb_listener_rule.public_internal_block` block.
#
# The narrow anchor matters because the file has multiple other
# `jsonencode({...})` calls (qurl-link static + canary lambdas, etc.).
# Today they happen to be multi-line so a single-line `[^}]+` regex
# misses them by coincidence — fragile. The awk range-pattern below
# scopes the grep to only the lockdown rule, so a future single-line
# `jsonencode({...})` added elsewhere in the file (or a `terraform
# fmt` rule change that collapses an existing one) does not trip
# this lint.
#
# Range delimiters:
#   - Start: `resource "aws_lb_listener_rule" "public_internal_block"`
#     line.
#   - End: the first line that is exactly `}` at column 0. Terraform's
#     formatter writes top-level resources this way; any deviation
#     would surface as a "could not find" error below rather than a
#     silent narrow-extract.
#
# `-E -o` returns the matched substring per line. We further narrow
# from the resource block to its `fixed_response { ... }` sub-block,
# which is the only place the lockdown wire body lives. The inner
# anchor means a future refactor that adds a sibling `jsonencode({...})`
# inside the same rule (e.g., a tags helper, an action precondition)
# does not trip this lint. We accept exactly one match within the
# sub-block; multiple is suspicious (two body assignments inside one
# fixed_response — invalid HCL today, but the lint fails loud if a
# future Terraform language change ever allows it).
block_extract=$(awk '
  /^resource "aws_lb_listener_rule" "public_internal_block"/ { in_block=1 }
  in_block { print }
  in_block && /^}/ { in_block=0 }
' "$TF_FILE")

if [ -z "$block_extract" ]; then
  echo "ERROR: could not locate the \`aws_lb_listener_rule.public_internal_block\` block in $TF_FILE" >&2
  echo "       The lockdown rule resource was either renamed, removed, or its" >&2
  echo "       opening line no longer matches the canonical \`resource \"aws_lb_listener_rule\" \"public_internal_block\"\` form." >&2
  echo "       If the rename is intentional, update this script's awk range pattern." >&2
  exit 1
fi

# Narrow further to the `fixed_response { ... }` sub-block. The
# sub-block delimiter is a closing `}` indented by exactly 4 spaces
# (Terraform fmt's canonical 2-space indent times 2 levels: rule → action).
# An inner brace at a different indent would surface as a missing
# match downstream, not a silent narrow-extract.
fixed_response_extract=$(printf '%s\n' "$block_extract" | awk '
  /^    fixed_response \{/ { in_fr=1; next }
  in_fr && /^    \}/ { in_fr=0; next }
  in_fr { print }
')

if [ -z "$fixed_response_extract" ]; then
  echo "ERROR: could not locate the \`fixed_response { ... }\` sub-block inside the lockdown rule in $TF_FILE" >&2
  echo "       Either the action type changed (away from fixed-response), the" >&2
  echo "       sub-block indentation changed, or the rule was restructured." >&2
  echo "       If intentional, update this script's awk sub-block extractor." >&2
  exit 1
fi

tf_matches=()
while IFS= read -r line; do
  [ -n "$line" ] && tf_matches+=("$line")
done < <(printf '%s\n' "$fixed_response_extract" | grep -E -o 'jsonencode\(\{[^}]+\}\)' || true)

if [ "${#tf_matches[@]}" -eq 0 ]; then
  echo "ERROR: could not find \`jsonencode({...})\` in $TF_FILE" >&2
  echo "       The lockdown rule's fixed-response body is expected to use" >&2
  echo "       jsonencode() — either it was rewritten to a literal JSON string" >&2
  echo "       or the resource was removed. This lint exists to catch drift" >&2
  echo "       between the TF body and the smoke fence; please confirm both" >&2
  echo "       sides intentionally and update this script if so." >&2
  exit 1
fi
if [ "${#tf_matches[@]}" -gt 1 ]; then
  echo "ERROR: multiple \`jsonencode({...})\` inside the \`aws_lb_listener_rule.public_internal_block\` block in $TF_FILE:" >&2
  for m in "${tf_matches[@]}"; do
    echo "    $m" >&2
  done
  echo "  The block scope is already in place (awk range pattern above)." >&2
  echo "  A second jsonencode here likely means a second fixed-response" >&2
  echo "  sub-action or a sibling header/audit-trail addition was made" >&2
  echo "  inside the same rule. Sharpen further to anchor on the" >&2
  echo "  \`message_body =\` assignment (or scope to the \`fixed_response\`" >&2
  echo "  sub-block) so the lint compares the exact wire body, not a" >&2
  echo "  collateral jsonencode call." >&2
  exit 1
fi
tf_body="${tf_matches[0]}"

# Extract the Go body from `map[string]string{"error": "not found"}`
# (the publicALBLockdownExpectedBody declaration). Anchor on the
# `map[string]string{` prefix to avoid matching other maps in the
# file; capture through the closing `}`.
go_matches=()
while IFS= read -r line; do
  [ -n "$line" ] && go_matches+=("$line")
done < <(grep -E -o 'publicALBLockdownExpectedBody[[:space:]]*=[[:space:]]*map\[string\]string\{[^}]+\}' "$GO_FILE" || true)

if [ "${#go_matches[@]}" -eq 0 ]; then
  echo "ERROR: could not find \`publicALBLockdownExpectedBody = map[string]string{...}\` in $GO_FILE" >&2
  echo "       Either the constant was renamed, its type was widened to" >&2
  echo "       map[string]any, or the declaration moved out of this file." >&2
  echo "       Update this lint if that change is intentional." >&2
  exit 1
fi
if [ "${#go_matches[@]}" -gt 1 ]; then
  echo "ERROR: multiple \`publicALBLockdownExpectedBody = map[string]string{...}\` in $GO_FILE" >&2
  exit 1
fi
go_body="${go_matches[0]}"

# Normalize each side to a comparable shape: extract the {key, value}
# pairs and re-render as `key=value` lines, lowercased. This collapses
# whitespace, key-order, and TF-HCL-vs-Go-map syntax differences.
#
# TF normalize: pull `key = "value"` pairs out of `jsonencode({...})`.
# Go normalize: pull `"key": "value"` pairs out of `map[string]string{...}`.
normalize_tf() {
  local s="$1"
  s="${s#jsonencode\(\{}"
  s="${s%\}\)}"
  # `sort` makes the comparison key-order-insensitive — a deliberate
  # reorder of the body keys must not trip drift.
  printf '%s\n' "$s" | grep -E -o '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*"[^"]*"' \
    | sed -E 's/[[:space:]]*=[[:space:]]*"/=/' \
    | sed -E 's/"$//' \
    | sort
}
normalize_go() {
  local s="$1"
  s="${s#*map\[string\]string\{}"
  s="${s%\}}"
  printf '%s\n' "$s" | grep -E -o '"[^"]*"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed -E 's/^"//; s/"[[:space:]]*:[[:space:]]*"/=/; s/"$//' \
    | sort
}

tf_normalized="$(normalize_tf "$tf_body")"
go_normalized="$(normalize_go "$go_body")"

if [ -z "$tf_normalized" ] || [ -z "$go_normalized" ]; then
  echo "ERROR: extracted lockdown body normalized to an empty pair set." >&2
  echo "  TF   ($TF_FILE): \"$tf_body\" → normalized: \"$tf_normalized\"" >&2
  echo "  Go   ($GO_FILE): \"$go_body\" → normalized: \"$go_normalized\"" >&2
  echo "  An empty body would break the smoke fence's assertion contract." >&2
  exit 1
fi

if [ "$tf_normalized" != "$go_normalized" ]; then
  echo "ERROR: lockdown body shape drift between TF and smoke test." >&2
  echo "  $TF_FILE:" >&2
  echo "    $tf_body" >&2
  echo "    normalized → $(echo "$tf_normalized" | tr '\n' '|')" >&2
  echo "  $GO_FILE:" >&2
  echo "    $go_body" >&2
  echo "    normalized → $(echo "$go_normalized" | tr '\n' '|')" >&2
  echo "" >&2
  echo "The two body shapes must match. The smoke test asserts the ALB" >&2
  echo "listener rule emits a body matching publicALBLockdownExpectedBody;" >&2
  echo "if they diverge, the smoke test passes against a rule that no" >&2
  echo "longer emits that shape. See PR #1635 and the COORDINATED CHANGE" >&2
  echo "comments at both call sites." >&2
  exit 1
fi

echo "lockdown body shape in sync: $(echo "$tf_normalized" | tr '\n' '|')"
