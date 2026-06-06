#!/usr/bin/env bash
# check-lockdown-body-drift.sh
# ----------------------------------------------------------------------------
# Fence drift in the qurl-service /internal/* public-ALB lockdown body
# contract across:
#
#   - terraform/modules/qurl-service/main.tf
#       * local.public_internal_lockdown_body — the SINGLE source of truth
#         for the lockdown fixed-response body shape.
#       * aws_lb_listener_rule.public_internal_block — emits that body to
#         the wire on /internal/* on the public ALB
#         (fixed_response.message_body).
#       * aws_ssm_parameter.public_internal_lockdown_body — publishes that
#         body to SSM so the smoke fence can read it.
#   - tests/smoke/aws_helpers.go
#       (resolvePublicALBLockdownExpectedBody — reads the SSM parameter at
#        /{env}/nhp/qurl/internal-lockdown-body and parses it).
#   - tests/smoke/09_public_alb_internal_lockdown_test.go
#       (publicALBLockdownExpectedBody — the resolved value the wire
#        assertions compare against).
#
# Architecture (#1645, Path B). Before #1645 the body shape was duplicated
# as a Go literal that mirrored the TF rule with no compile-time link, and
# this lint compared the two literals. That coupling is gone: the smoke
# fence now sources its expected body from the SSM parameter, and Terraform
# authors BOTH the rule's message_body AND that SSM parameter from one
# shared local. So the served body and the fence's expected body provably
# share a source and cannot drift across an apply — PROVIDED both keep
# referencing the local, and PROVIDED Terraform and smoke agree on the SSM
# parameter name. Those two are exactly what this lint now fences:
#
#   1. local.public_internal_lockdown_body is defined as jsonencode({...}).
#      (The smoke resolver json.Unmarshal-s the value into map[string]string;
#      a switch to a non-JSON body — e.g. gin's text/plain per #1642 — must
#      trip this lint so the resolver and the Go type get updated too.)
#   2. The rule's fixed_response.message_body references that local
#      (not a re-inlined literal that would diverge from the SSM value).
#   3. The SSM parameter's value references that same local.
#   4. The smoke side carries NO compile-time body literal anymore, and
#      Terraform + the smoke resolver name the SAME SSM parameter.
#
# If 2 and 3 both reference the one local, the wire body and the SSM-sourced
# expected body are identical by construction; if 4 holds, the fence reads
# the parameter Terraform actually publishes. A one-sided edit to any of
# these is what reopens silent drift, and is what fails here at PR time.
#
# Usage:
#   ./scripts/check-lockdown-body-drift.sh
#       # canonical production paths
#   ./scripts/check-lockdown-body-drift.sh TF_FILE GO_RESOLVER_FILE GO_FENCE_FILE
#       # override all three (for a future fixture suite)
# ============================================================================

set -euo pipefail

if [ "$#" -ne 0 ] && [ "$#" -ne 3 ]; then
  echo "usage: $0 [TF_FILE GO_RESOLVER_FILE GO_FENCE_FILE]" >&2
  echo "  with no args: check the canonical production paths" >&2
  echo "  with three args: check the supplied paths" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_FILE="${1:-${REPO_ROOT}/terraform/modules/qurl-service/main.tf}"
GO_RESOLVER_FILE="${2:-${REPO_ROOT}/tests/smoke/aws_helpers.go}"
GO_FENCE_FILE="${3:-${REPO_ROOT}/tests/smoke/09_public_alb_internal_lockdown_test.go}"

for f in "$TF_FILE" "$GO_RESOLVER_FILE" "$GO_FENCE_FILE"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: missing $f" >&2
    exit 1
  fi
done

# The SSM parameter name (minus the per-env "/{env}" prefix) that Terraform
# publishes and the smoke resolver reads. Both sides must contain this exact
# substring or the fence reads a parameter that does not exist.
PARAM_NAME_SUFFIX="/nhp/qurl/internal-lockdown-body"

# ---- 1. local.public_internal_lockdown_body = jsonencode({...}) ------------
# Match the single-level flat jsonencode form (additive flat keys like
# `{ error = "not found", request_id = "" }` are fine; nested objects would
# need the extractor hardened to brace-count — same soft spot the original
# lint documented). A switch to a non-jsonencode value (raw string for
# text/plain) does not match and trips the "missing local" error below — by
# design, so #1642 also updates the resolver + Go type.
local_matches=()
while IFS= read -r line; do
  [ -n "$line" ] && local_matches+=("$line")
done < <(grep -E -o 'public_internal_lockdown_body[[:space:]]*=[[:space:]]*jsonencode\(\{[^}]+\}\)' "$TF_FILE" || true)

if [ "${#local_matches[@]}" -eq 0 ]; then
  echo "ERROR: could not find \`local.public_internal_lockdown_body = jsonencode({...})\` in $TF_FILE" >&2
  echo "       This local is the single source of truth for the lockdown body" >&2
  echo "       (#1645). If it was renamed, removed, or switched to a non-JSON" >&2
  echo "       value (e.g. text/plain per #1642), update both this lint AND" >&2
  echo "       tests/smoke/aws_helpers.go::resolvePublicALBLockdownExpectedBody" >&2
  echo "       (which json.Unmarshal-s the value) in the same PR." >&2
  exit 1
fi
if [ "${#local_matches[@]}" -gt 1 ]; then
  echo "ERROR: multiple \`public_internal_lockdown_body = jsonencode({...})\` in $TF_FILE" >&2
  exit 1
fi
local_body="${local_matches[0]}"

# ---- 2 & 3. rule message_body AND SSM param value both reference the local --
# Both attributes must be assigned from local.public_internal_lockdown_body
# (not a re-inlined literal) so the served body and the SSM-published expected
# body share one source (#1645). $1 = attribute, $2 = human-readable site.
#
# The match is file-wide, NOT scoped to a single resource block — intentionally.
# A future priority-2 lockdown rule (the slot-budget expansion the TF resource
# header describes) would legitimately add a SECOND
# `message_body = local.public_internal_lockdown_body` line, which a block-scoped
# or exactly-once assertion would wrongly reject. The accepted gap: if a second
# resource referenced the local AND the real rule's reference were swapped to an
# inline literal in the same edit, this check could be masked. The block-scoped
# rule<=>param guard is check 5 (resource_count_expr); together they keep the
# single-consumer case (today) tight. Revisit if a real second consumer lands.
#
# The two attributes' guarantees differ: a priority-2 rule is a real, documented
# future second `message_body` consumer; `value` has NO analogous second
# consumer (only aws_ssm_parameter assigns it), so its file-wide match is merely
# "no unrelated resource happens to also carry `value = local.<this>`" — weaker
# in theory but unconditional today. If a second `value` consumer ever appears,
# scope the `value` check to the SSM resource block rather than relaxing it.
require_local_ref() {
  local attr="$1" site="$2"
  if ! grep -E -q "^[[:space:]]*${attr}[[:space:]]*=[[:space:]]*local\.public_internal_lockdown_body[[:space:]]*\$" "$TF_FILE"; then
    echo "ERROR: ${site} does not reference local.public_internal_lockdown_body in $TF_FILE." >&2
    echo "       It MUST stay \`${attr} = local.public_internal_lockdown_body\` so the served" >&2
    echo "       body and the SSM-published expected body share one source (#1645); a" >&2
    echo "       re-inlined literal here would diverge and silently false-positive the fence." >&2
    exit 1
  fi
}

require_local_ref "message_body" "the lockdown rule's fixed_response.message_body"
require_local_ref "value" "aws_ssm_parameter.public_internal_lockdown_body's value"

# ---- 4a. no re-introduced Go body literal ----------------------------------
# publicALBLockdownExpectedBody is runtime-resolved from SSM now; a `= map[
# string]string{...}` literal would resurrect the exact drift class #1645
# eliminated.
if grep -E -q 'publicALBLockdownExpectedBody[[:space:]]*=[[:space:]]*map\[string\]string\{' "$GO_FENCE_FILE"; then
  echo "ERROR: $GO_FENCE_FILE re-introduces a compile-time literal" >&2
  echo "       \`publicALBLockdownExpectedBody = map[string]string{...}\`." >&2
  echo "       Under #1645 (Path B) this value is resolved at startup from the" >&2
  echo "       SSM parameter Terraform publishes; a hardcoded literal here would" >&2
  echo "       re-couple the fence to a value that can go stale against the rule." >&2
  exit 1
fi

# ---- 4b. Terraform and smoke name the same SSM parameter -------------------
# Anchor on the suffix followed by a closing double-quote. The suffix is always
# the TAIL of the param-name string literal — `"/${var.environment}/nhp/qurl/
# internal-lockdown-body"` in TF and `"/" + env + "/nhp/qurl/internal-lockdown-body"`
# in the resolver — so it is immediately followed by `"` in both. A free-floating
# substring match would also be satisfied by a DOC-COMMENT mention of the path
# (the resolver's comment spells it out), so renaming only the load-bearing code
# string would slip past — the gap the `resolver-comment-only` fixture pins.
for f in "$TF_FILE" "$GO_RESOLVER_FILE"; do
  if ! grep -F -q "${PARAM_NAME_SUFFIX}\"" "$f"; then
    echo "ERROR: SSM parameter name drift — \`${PARAM_NAME_SUFFIX}\"\` (the param-name" >&2
    echo "       string literal) not found in $f." >&2
    echo "       Terraform (aws_ssm_parameter.public_internal_lockdown_body) and the" >&2
    echo "       smoke resolver (resolvePublicALBLockdownExpectedBody) must name the" >&2
    echo "       SAME parameter in code (a doc-comment mention does not count), or the" >&2
    echo "       fence reads one that does not exist (#1645)." >&2
    exit 1
  fi
done

# ---- 5. rule and SSM param share the same count gate -----------------------
# The parameter must exist iff the rule exists (param-exists <=> rule-exists),
# which holds only while both `count` on the SAME expression. A one-sided count
# edit would otherwise surface as a confusing runtime red (rule deployed, param
# absent -> resolver hard-errors) or a silent gap (param present, rule absent).
# Both resources happen to put `count` first today, but the awk doesn't rely on
# that: it grabs the first `count =` line ANYWHERE within each resource block
# (interposed comments don't match `^count`, so they're skipped). If the target
# block ends (next top-level `resource "` line) before a `count` is seen, it
# stops with no output rather than grabbing a LATER resource's count — the
# caller's empty guard then fails loud instead of silently comparing the wrong
# resource.
resource_count_expr() {
  awk -v hdr="resource \"$1\" \"$2\"" '
    index($0, hdr) { in_block = 1; next }
    in_block && /^resource "/ { exit }
    in_block && /^[[:space:]]*count[[:space:]]*=/ {
      sub(/^[[:space:]]*count[[:space:]]*=[[:space:]]*/, "")
      print
      exit
    }
  ' "$TF_FILE"
}

rule_count="$(resource_count_expr "aws_lb_listener_rule" "public_internal_block")"
param_count="$(resource_count_expr "aws_ssm_parameter" "public_internal_lockdown_body")"

if [ -z "$rule_count" ] || [ -z "$param_count" ]; then
  echo "ERROR: could not extract a \`count = ...\` gate from the lockdown rule and/or the" >&2
  echo "       SSM parameter in $TF_FILE (rule=\"$rule_count\" param=\"$param_count\")." >&2
  echo "       If one lost its count, the param-exists <=> rule-exists invariant broke (#1645)." >&2
  exit 1
fi
if [ "$rule_count" != "$param_count" ]; then
  echo "ERROR: count-gate drift between the lockdown rule and its SSM parameter in $TF_FILE:" >&2
  echo "         rule  count = $rule_count" >&2
  echo "         param count = $param_count" >&2
  echo "       They MUST share the same count so the parameter exists iff the rule does" >&2
  echo "       (#1645); a mismatch yields a deployed rule with no parameter (resolver" >&2
  echo "       hard-errors) or a parameter with no rule (silent gap)." >&2
  exit 1
fi

# ---- 6. content_type matches between the TF rule and the Go fence literal ---
# Unlike the body (now SSM-sourced), content_type is still a duplicated TF<->Go
# literal: the rule's `content_type = "..."` and the fence's
# publicALBLockdownExpectedCT. The message_body comment requires they move in
# lockstep (until #1642's text/plain switch can fold CT into the SSM source);
# fence that here so a one-sided CT edit can't silently false-positive.
#
# Extract content_type from WITHIN the lockdown rule's block only — NOT
# file-wide. qurl-service/main.tf is a large module; an unrelated future
# content_type (a CDN/header/other fixed_response block) must not trip this lint
# with an off-topic error. Anchor on the rule header, stop at the next
# top-level `resource "`, and match the first `content_type = "..."` (the
# `= "..."` form skips the prose "content_type" mentions in the rule comment).
rule_content_type() {
  awk '
    index($0, "resource \"aws_lb_listener_rule\" \"public_internal_block\"") { in_rule = 1; next }
    in_rule && /^resource "/ { exit }
    in_rule && match($0, /content_type[[:space:]]*=[[:space:]]*"[^"]*"/) {
      ct = substr($0, RSTART, RLENGTH)
      sub(/^content_type[[:space:]]*=[[:space:]]*"/, "", ct)
      sub(/"$/, "", ct)
      print ct
      exit
    }
  ' "$TF_FILE"
}
tf_ct="$(rule_content_type)"
if [ -z "$tf_ct" ]; then
  echo "ERROR: could not extract \`content_type = \"...\"\` from the lockdown rule" >&2
  echo "       (aws_lb_listener_rule.public_internal_block) in $TF_FILE — was the" >&2
  echo "       fixed_response content_type removed or the rule renamed? (#1645)." >&2
  exit 1
fi

go_ct="$(grep -E -o 'publicALBLockdownExpectedCT[[:space:]]*=[[:space:]]*"[^"]*"' "$GO_FENCE_FILE" | head -1 | sed -E 's/.*"([^"]*)"/\1/')"
if [ -z "$go_ct" ]; then
  echo "ERROR: could not find \`publicALBLockdownExpectedCT = \"...\"\` in $GO_FENCE_FILE (#1645)." >&2
  exit 1
fi
if [ "$tf_ct" != "$go_ct" ]; then
  echo "ERROR: content_type drift — TF rule content_type=\"$tf_ct\" but the fence's" >&2
  echo "       publicALBLockdownExpectedCT=\"$go_ct\". They must match (update both in the" >&2
  echo "       same PR); #1642's text/plain switch must change both in lockstep (#1645)." >&2
  exit 1
fi

echo "lockdown body contract in sync (#1645): rule + SSM param both source local.public_internal_lockdown_body = ${local_body}, share count gate (${rule_count}); content_type=\"${tf_ct}\" matches the fence; smoke reads ${PARAM_NAME_SUFFIX}, no Go literal."
