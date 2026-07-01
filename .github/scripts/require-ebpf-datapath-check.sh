#!/usr/bin/env bash
# Manage the GitHub repository ruleset that makes the eBPF datapath/object
# freshness proof a REQUIRED status check on the protected branch(es).
#
# Issue #2861 governance step for PR #2860: the conditional-job workflow
# (.github/workflows/ebpf-datapath-test.yml) is required-check ready, this
# applies/verifies the branch ruleset that actually requires it.
#
# The desired state lives in .github/rulesets/ebpf-datapath-proof-required.json
# (config-as-code, reviewed in PR). This script applies that file to the live
# repo, verifies compliance, or rolls it back. It is idempotent: re-running
# --apply on an already-compliant repo makes no change.
#
# Check identity (acceptance criteria): the required `context` is the job name
# `eBPF datapath and object freshness proof`, bound to integration_id 15368
# (the GitHub Actions app on github.com — github.com-specific; GHES differs) so
# only the Actions-produced check can satisfy the rule. The
# old `eBPF Datapath Test (#2779 surgical-kill)` identity is scanned for and
# reported so a stale binding cannot linger.
#
# Modes:
#   --check    (default) read-only; exits non-zero if the live ruleset does not
#              match the desired file, a stale #2779 binding is present, or the
#              stale-binding scan cannot complete. Never mutates.
#   --apply    create or update the ruleset to match the desired file. Refuses to
#              create an unsatisfiable required check (workflow absent on target)
#              unless --force.
#   --remove   delete the managed ruleset (rollback).
#
# Env overrides (testing): REQUIRE_EBPF_GH (gh binary), REQUIRE_EBPF_REPO
# (owner/repo), REQUIRE_EBPF_RULESET_JSON (desired-state file path).

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)

GH="${REQUIRE_EBPF_GH:-gh}"
RULESET_JSON="${REQUIRE_EBPF_RULESET_JSON:-$REPO_ROOT/.github/rulesets/ebpf-datapath-proof-required.json}"

# Old, superseded check identity from #2779; the managed ruleset must never carry
# it and we flag it if it lingers anywhere else (classic branch protection or
# another ruleset). The match is intentionally broad (a substring like "eBPF
# Datapath Test" could in principle touch a future legitimately-named context),
# which is acceptable because this scan only WARNS/flags — it never auto-removes —
# and the managed context name ("...object freshness proof") does not collide.
STALE_CONTEXT_REGEX='eBPF Datapath Test|#2779|surgical-kill'

# Workflow file that must exist on a target branch for the required context to be
# satisfiable; without it every PR to that branch hangs on a check that never
# reports.
WORKFLOW_PATH=".github/workflows/ebpf-datapath-test.yml"

mode="check"
repo="${REQUIRE_EBPF_REPO:-}"
force=0

log() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; }

usage() {
  cat <<EOF
usage: $(basename "$0") [--check|--apply|--remove] [--repo OWNER/REPO] [--force]

  --check    read-only compliance check (default); non-zero exit on drift
  --apply    create/update the ruleset to match $RULESET_JSON (idempotent)
  --remove   delete the managed ruleset (rollback)
  --repo     target repository (default: REQUIRE_EBPF_REPO or \`gh repo view\`)
  --force    with --apply, create the rule even if the workflow is absent on a
             target branch (normally refused to avoid an unsatisfiable check)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) mode="check" ;;
    --apply) mode="apply" ;;
    --remove) mode="remove" ;;
    --force) force=1 ;;
    --repo) shift; repo="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) err "unknown argument: $1"; usage >&2; exit 2 ;;
  esac
  shift
done

gh_api() { "$GH" api "$@"; }

if [ ! -f "$RULESET_JSON" ]; then
  err "desired-state file not found: $RULESET_JSON"
  exit 2
fi
if ! jq -e . "$RULESET_JSON" >/dev/null 2>&1; then
  err "desired-state file is not valid JSON: $RULESET_JSON"
  exit 2
fi

if [ -z "$repo" ]; then
  repo=$("$GH" repo view --json nameWithOwner --jq .nameWithOwner)
fi

desired_name=$(jq -r '.name' "$RULESET_JSON")

# Comparable projection of the governance posture this ruleset asserts:
# enforcement, target, the ref condition (BOTH include and exclude — exclude
# takes precedence in GitHub rulesets, so an added exclude can neuter the rule
# while include/enforcement still look intact), the required contexts (context +
# integration_id), bypass_actors (a fail-closed control must catch an *added*
# bypass), the set of rule types (so an extra rule added live is caught), and the
# strict / do-not-enforce-on-create rule params. Server-added fields (id,
# timestamps, _links, source) are ignored so idempotency is not defeated by
# echo-back; absent strict/do_not_enforce normalize to GitHub's `false` default
# so they never drift spuriously; arrays are sorted for stable comparison.
# Deliberate scope: params of non-required_status_checks rule types are not
# deep-compared (the desired ruleset has none; rule_types still flags an added type).
projection_filter='{
  enforcement: .enforcement,
  target: .target,
  refs: {
    include: (.conditions.ref_name.include | sort),
    exclude: (.conditions.ref_name.exclude // [] | sort)
  },
  bypass_actors: ([.bypass_actors[]? | {actor_id, actor_type, bypass_mode}]
    | sort_by([.actor_type, (.actor_id | tostring), .bypass_mode])),
  rule_types: ([.rules[].type] | sort),
  checks: ([.rules[]
      | select(.type == "required_status_checks")
      | .parameters
      | {
          strict: (.strict_required_status_checks_policy // false),
          do_not_enforce_on_create: (.do_not_enforce_on_create // false),
          contexts: ([.required_status_checks[] | {context, integration_id}]
            | sort_by(.context))
        }] | sort)
}'

desired_projection=$(jq -c "$projection_filter" "$RULESET_JSON")

# The required context(s) this ruleset binds, used by the --apply satisfiability
# precondition below (the workflow must actually declare them before the rule is
# made required). Drift state is carried separately by desired_projection.
required_contexts=$(jq -r '.rules[]?.parameters.required_status_checks[]?.context' "$RULESET_JSON")

# Branches named by the desired refs (refs/heads/NAME -> NAME), skipping glob
# patterns we cannot resolve to a single branch for the precondition check.
desired_branches() {
  jq -r '.conditions.ref_name.include[]' "$RULESET_JSON" \
    | sed -n 's#^refs/heads/##p' \
    | grep -v '[*]' || true
}

# Fetch the repo's rulesets once per run; callers thread the result down so a
# single --check/--apply lists rulesets only once.
#
# per_page=100 in one request rather than `--paginate`: for a top-level-array
# endpoint `gh --paginate` emits one JSON array PER PAGE (a concatenated stream),
# which the single-array `jq` consumers below would mis-handle past page 1. A repo
# has far fewer than 100 rulesets, so one max-size page is both correct and
# complete.
#
# Fail closed on a FULL page rather than silently truncate: if the single page
# comes back with the max 100 entries there may be a second page we did not fetch,
# so both the managed-ruleset lookup and the #2779 stale sweep could miss entries
# and falsely report clean — the exact silent-failure mode the rest of this script
# guards against. If this ever trips, switch to real pagination
# (`--paginate --slurp | jq 'add'`).
#
# NOTE: the list endpoint returns SUMMARY objects (id / name / target /
# enforcement); rules, conditions, and bypass_actors are NOT included, so reading
# rule details still requires a GET by id (see ruleset_projection /
# scan_stale_bindings). Do not "optimize" those per-id GETs away by reading the
# list element — it has no rules.
list_rulesets() {
  local out
  out=$(gh_api "repos/$repo/rulesets?per_page=100")
  # Guard before emitting, so we never hand callers a list we're about to reject.
  if [ "$(printf '%s' "$out" | jq 'length')" -ge 100 ]; then
    err "$repo has >= 100 rulesets; the single-page list may be truncated — refusing to trust an incomplete scan (add pagination)."
    return 1
  fi
  printf '%s' "$out"
}

# Print (stdout) the first ruleset id whose name matches the desired ruleset, from
# a cached list ($1). Returns 2 (after a loud warning) if the name is AMBIGUOUS
# (>1 match) so callers can treat an unreviewed duplicate as drift / refuse to act;
# returns 0 otherwise. The id is written to stdout regardless, so a caller that
# tolerates ambiguity still gets the first match.
find_ruleset_id() {
  # First match inside jq rather than piping to `head -n1`: under pipefail,
  # `head` closing the pipe can SIGPIPE jq (exit 141) and abort under set -e.
  local matches
  matches=$(printf '%s' "$1" | jq -c --arg n "$desired_name" '[.[] | select(.name == $n) | .id]')
  printf '%s' "$matches" | jq -r '.[0] // empty'
  if [ "$(printf '%s' "$matches" | jq 'length')" -gt 1 ]; then
    err "multiple rulesets named '$desired_name' on $repo; managing the first. Remove the duplicate(s)."
    return 2
  fi
}

ruleset_projection() {
  gh_api "repos/$repo/rulesets/$1" | jq -c "$projection_filter"
}

# --apply satisfiability precondition for branch $1: the workflow must exist AND
# still declare every required context (job name), so the rule cannot be required
# before the context can report. Fetches the raw file and substring-checks each
# context — this catches an absent workflow AND a renamed job. (A reintroduced
# `pull_request.paths` filter or a dropped `main` trigger would also strand PRs;
# detecting those needs trigger-structure parsing, so they remain guarded by the
# workflow's own "keep unfiltered by paths" comment + the runbook's documented
# dependency, verified live on #2877 — not double-checked here to avoid coupling
# this script to the workflow's internal YAML shape.)
workflow_present_on() {
  local branch="$1" content namelines ctx
  content=$(gh_api -H "Accept: application/vnd.github.raw" \
    "repos/$repo/contents/$WORKFLOW_PATH?ref=$branch" 2>/dev/null) || return 1
  [ -n "$content" ] || return 1
  # Match the context only on a `name:`-declaring line, with comments stripped, so
  # a context that survives merely in a comment (this very file's header mentions
  # it) cannot satisfy the check — otherwise a renamed job would pass undetected.
  # Caveat: `sed 's/#.*//'` also strips a literal `#` inside a quoted job name
  # (e.g. `name: "a # b"`); harmless for the current context (no `#`), but a future
  # `#`-bearing job name would need a YAML-aware check here.
  namelines=$(printf '%s' "$content" | sed 's/#.*//' | grep 'name:' || true)
  while IFS= read -r ctx; do
    [ -n "$ctx" ] || continue
    grep -qF "$ctx" <<< "$namelines" || return 1
  done <<< "$required_contexts"
}

# Pretty-print a JSON value ($1) for human-readable output.
show_json() { printf '%s\n' "$1" | jq .; }

# Render the desired-vs-actual projection diff (actual passed as $1).
print_drift() {
  log "--- desired ---"; show_json "$desired_projection"
  log "--- actual  ---"; show_json "$1"
}

# Emit a stale-#2779 warning if any newline-separated value in $2 matches the
# legacy identity; $1 is a human label for where it was found. Returns 1 if a
# stale value was found, 0 otherwise.
report_if_stale() {
  local label="$1" values="$2"
  printf '%s\n' "$values" | grep -Eq "$STALE_CONTEXT_REGEX" || return 0
  err "stale #2779 binding $label:"
  printf '%s\n' "$values" | grep -E "$STALE_CONTEXT_REGEX" | sed 's/^/    /' >&2
  return 1
}

# Echo classic-branch-protection required-status-check contexts for branch $1.
# A 404 (no branch protection) is expected -> empty output, success. Any other
# gh failure (e.g. 403 from insufficient admin scope) is surfaced loudly and
# returns 1, so the secondary #2779 sweep cannot silently disarm itself on a
# permissions gap (repo stance: no silent failures).
classic_bp_contexts() {
  local branch="$1" out rc=0 errf
  errf=$(mktemp)
  out=$(gh_api "repos/$repo/branches/$branch/protection/required_status_checks" 2>"$errf") || rc=$?
  if [ "$rc" -eq 0 ]; then
    rm -f "$errf"
    printf '%s' "$out" | jq -r '.contexts[]?'
    return 0
  fi
  if grep -qiE 'not found|not protected' "$errf"; then
    rm -f "$errf"  # no classic branch protection on this branch — expected
    return 0
  fi
  err "could not read classic branch protection on '$branch' (gh exit $rc):"
  sed 's/^/    /' "$errf" >&2
  rm -f "$errf"
  return 1
}

# Flag any stale (#2779) context in classic branch protection or in any ruleset
# other than the managed one ($2), scanning the cached ruleset list ($1).
# Returns 0 if nothing stale and every source was read; 1 if a stale binding was
# found OR a source could not be read (so the caller never treats a partial scan
# as clean). Scope note: the classic-BP arm only checks `desired_branches` (the
# branches this ruleset governs, i.e. `main`) — a legacy binding on some other
# branch's classic protection is out of scope by design; rulesets are scanned
# repo-wide.
scan_stale_bindings() {
  local rulesets="$1" managed_id="${2:-}" found=0 branch contexts id names
  for branch in $(desired_branches); do
    if contexts=$(classic_bp_contexts "$branch"); then
      report_if_stale "in classic branch protection on '$branch'" "$contexts" || found=1
    else
      found=1  # read error already reported loudly; do not pass it off as clean
    fi
  done
  while read -r id; do
    [ -n "$id" ] || continue
    if [ "$id" = "$managed_id" ]; then continue; fi
    # A per-id GET here uses the same scope that just listed the rulesets, so
    # (unlike classic branch protection above) a perms gap is not a realistic
    # silent-failure vector; tolerate a transient miss rather than fail the scan —
    # but warn so a flake is visible instead of silently skipping a ruleset.
    if ! names=$(gh_api "repos/$repo/rulesets/$id" \
        --jq '.rules[]?.parameters.required_status_checks[]?.context' 2>/dev/null); then
      err "warning: could not read ruleset $id during stale scan (transient?); skipping it"
      names=""
    fi
    report_if_stale "in ruleset id $id" "$names" || found=1
  done < <(printf '%s' "$rulesets" | jq -r '.[].id' 2>/dev/null || true)
  return "$found"
}

cmd_check() {
  local rulesets id actual rc=0 dup=0
  rulesets=$(list_rulesets)
  id=$(find_ruleset_id "$rulesets") || dup=$?
  # An ambiguous (duplicate) name is itself unreviewed drift -> fail the check.
  if [ "$dup" -ne 0 ]; then rc=1; fi
  if [ -z "$id" ]; then
    err "ruleset '$desired_name' not found on $repo"
    log "desired:"
    show_json "$desired_projection"
    rc=1
  else
    actual=$(ruleset_projection "$id")
    if [ "$actual" != "$desired_projection" ]; then
      err "ruleset '$desired_name' (id $id) on $repo drifted from desired state"
      print_drift "$actual"
      rc=1
    elif [ "$dup" -ne 0 ]; then
      # Projection matches, but the name is ambiguous (warned above) -> still drift.
      err "ruleset '$desired_name' (id $id) matches desired state, but the name is ambiguous on $repo — treated as drift"
    else
      log "OK: ruleset '$desired_name' (id $id) on $repo matches desired state"
      show_json "$desired_projection"
    fi
  fi
  if ! scan_stale_bindings "$rulesets" "$id"; then
    rc=1
  fi
  return "$rc"
}

cmd_apply() {
  local branch rulesets id actual changed=0 bound dup=0
  # Fail closed: do not require a check the target branch cannot report.
  if [ "$force" -ne 1 ]; then
    for branch in $(desired_branches); do
      if ! workflow_present_on "$branch"; then
        err "$WORKFLOW_PATH on '$branch' of $repo is absent or does not declare the required context;"
        err "requiring the check now would hang every PR. Land/fix the workflow first, or pass --force."
        return 1
      fi
    done
  fi

  rulesets=$(list_rulesets)
  id=$(find_ruleset_id "$rulesets") || dup=$?
  if [ "$dup" -ne 0 ]; then
    err "refusing to apply: ruleset name '$desired_name' is ambiguous on $repo; remove the duplicate(s) first."
    return 1
  fi
  if [ -z "$id" ]; then
    log "creating ruleset '$desired_name' on $repo ..."
    id=$(gh_api -X POST "repos/$repo/rulesets" --input "$RULESET_JSON" --jq '.id')
    changed=1
    log "created ruleset id $id"
  else
    actual=$(ruleset_projection "$id")
    if [ "$actual" = "$desired_projection" ]; then
      log "no change: ruleset '$desired_name' (id $id) already matches desired state"
    else
      log "updating ruleset '$desired_name' (id $id) on $repo ..."
      gh_api -X PUT "repos/$repo/rulesets/$id" --input "$RULESET_JSON" --jq '.id' >/dev/null
      changed=1
      log "updated ruleset id $id"
    fi
  fi

  # Re-fetch to verify only after a mutation; the no-op path already compared
  # live state to desired above. (scan_stale_bindings below runs against the
  # pre-mutation list; that is fine — it only sweeps OTHER rulesets / classic BP
  # for legacy #2779 contexts, which this apply did not touch, and the managed
  # ruleset is excluded from the sweep anyway.)
  bound=$(printf '%s' "$desired_projection" | jq -c '[.checks[].contexts[]]')
  if [ "$changed" -eq 1 ]; then
    actual=$(ruleset_projection "$id")
    if [ "$actual" != "$desired_projection" ]; then
      err "post-apply verification failed: live ruleset does not match desired state"
      print_drift "$actual"
      return 1
    fi
    log "verified post-apply: required context bound -> $bound"
  else
    log "required context bound -> $bound"
  fi
  # Surface any stale binding elsewhere (non-fatal: the managed ruleset is
  # correct; classic-BP cleanup is a separate, manual step).
  if ! scan_stale_bindings "$rulesets" "$id"; then
    err "stale-binding scan reported a problem (see warnings above); resolve before relying on the #2779 sweep."
  fi
}

cmd_remove() {
  local id dup=0 rulesets
  # Assign list_rulesets to its own var (not nested in $(find_ruleset_id ...)) so
  # its fail-closed full-page guard's non-zero exit is not masked by the outer
  # command substitution.
  rulesets=$(list_rulesets)
  id=$(find_ruleset_id "$rulesets") || dup=$?
  if [ "$dup" -ne 0 ]; then
    err "refusing to remove: ruleset name '$desired_name' is ambiguous on $repo; remove the intended one manually."
    return 1
  fi
  if [ -z "$id" ]; then
    log "nothing to remove: ruleset '$desired_name' not found on $repo"
    return 0
  fi
  log "deleting ruleset '$desired_name' (id $id) on $repo ..."
  gh_api -X DELETE "repos/$repo/rulesets/$id"
  log "deleted ruleset id $id"
}

case "$mode" in
  check) cmd_check ;;
  apply) cmd_apply ;;
  remove) cmd_remove ;;
  *) err "unknown mode: $mode"; exit 2 ;;
esac
