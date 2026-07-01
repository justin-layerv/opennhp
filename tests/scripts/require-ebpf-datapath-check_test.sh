#!/usr/bin/env bash
# Fixture tests for .github/scripts/require-ebpf-datapath-check.sh.
#
# A stateful mock `gh` (injected via REQUIRE_EBPF_GH) emulates just the rulesets
# / branch-protection / contents endpoints the script touches, persisting its
# "server" state in a temp dir so create/update/delete are observable across the
# script's separate gh invocations. The desired state is the real config-as-code
# file under .github/rulesets/, so these tests also guard that file's shape.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/require-ebpf-datapath-check.sh"
DESIRED="$REPO_ROOT/.github/rulesets/ebpf-datapath-proof-required.json"

pass=0
fail=0
LAST_OUTPUT=""
LAST_RC=0

TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done; }
trap cleanup EXIT
new_tmpdir() {
  local __resultvar="$1" tmpdir_path
  tmpdir_path=$(mktemp -d)
  TMPDIRS+=("$tmpdir_path")
  printf -v "$__resultvar" '%s' "$tmpdir_path"
}

report_pass() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  FAIL %s\n      %s\n' "$1" "$2"; }

assert_rc() {
  local want="$1" name="$2"
  if [ "$LAST_RC" -eq "$want" ]; then report_pass "$name (rc=$want)"; else
    report_fail "$name" "expected rc $want, got $LAST_RC; output: $LAST_OUTPUT"; fi
}
assert_contains() {
  local needle="$1" name="$2"
  if printf '%s' "$LAST_OUTPUT" | grep -qF "$needle"; then report_pass "$name"; else
    report_fail "$name" "expected output to contain: $needle; got: $LAST_OUTPUT"; fi
}
assert_no_mutations() {
  local statedir="$1" name="$2"
  if grep -Eq '^(POST|PUT|DELETE) ' "$statedir/calls.log" 2>/dev/null; then
    report_fail "$name" "mutating call(s) found: $(grep -E '^(POST|PUT|DELETE) ' "$statedir/calls.log")"
  else report_pass "$name"; fi
}

# Build the mock gh into $1/bin/gh and seed empty state.
make_mock() {
  local statedir="$1"
  mkdir -p "$statedir/bin"
  printf '[]' >"$statedir/rulesets.json"
  : >"$statedir/calls.log"
  : >"$statedir/workflow_present"
  printf '1000' >"$statedir/nextid"
  cat >"$statedir/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
STATE="$MOCK_GH_STATE"
[ "${1:-}" = "api" ] || { echo "mock gh: only 'api' supported: $*" >&2; exit 99; }
shift
method=GET; endpoint=""; jqexpr=""; input=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -X) shift; method="$1" ;;
    --jq) shift; jqexpr="$1" ;;
    --input) shift; input="$1" ;;
    -H) shift ;;
    -*) ;;
    *) [ -z "$endpoint" ] && endpoint="$1" ;;
  esac
  shift
done
printf '%s %s\n' "$method" "$endpoint" >>"$STATE/calls.log"
ep="${endpoint%%\?*}"; query="${endpoint#"$ep"}"
emit() { if [ -n "$jqexpr" ]; then printf '%s' "$1" | jq -r "$jqexpr"; else printf '%s' "$1"; fi; }
case "$method:$ep" in
  GET:repos/*/rulesets/*)
    id="${ep##*/}"
    if [ -f "$STATE/ruleset_${id}.fail" ]; then echo "Server Error" >&2; exit 1; fi
    obj=$(jq -c --argjson id "$id" '.[] | select(.id==$id)' "$STATE/rulesets.json")
    [ -n "$obj" ] || { echo "Not Found" >&2; exit 1; }
    emit "$obj" ;;
  GET:repos/*/rulesets)
    # Mirror the real API: the LIST endpoint returns summary objects only —
    # rules/conditions/bypass_actors are omitted (only GET-by-id has them). This
    # keeps the per-id GET path honest so a regression that reads rule details
    # from the list would fail here.
    emit "$(jq -c 'map(del(.rules, .conditions, .bypass_actors))' "$STATE/rulesets.json")" ;;
  GET:repos/*/contents/*)
    # Raw workflow content (script requests Accept: raw). "Present" returns YAML
    # declaring the required context; the workflow_missing_ctx sentinel returns a
    # present-but-renamed-job workflow to exercise the satisfiability precondition.
    branch="${query#*ref=}"
    if grep -qxF "$branch" "$STATE/workflow_present" 2>/dev/null; then
      # Realistic: like the real file, the context also appears in a COMMENT, so a
      # whole-file match would false-pass. The renamed variant keeps that comment
      # but renames the job, so only a name:-line match catches it.
      if [ -f "$STATE/workflow_missing_ctx" ]; then
        emit $'# mentions eBPF datapath and object freshness proof here\n    name: some other job'
      else
        emit $'# mentions eBPF datapath and object freshness proof here\n    name: eBPF datapath and object freshness proof'
      fi
    else echo "Not Found" >&2; exit 1; fi ;;
  GET:repos/*/branches/*/protection/required_status_checks)
    rest="${ep#repos/*/branches/}"; branch="${rest%%/*}"
    if [ -f "$STATE/bp_${branch}.forbidden" ]; then
      echo "Resource not accessible by integration" >&2; exit 1
    fi
    f="$STATE/bp_${branch}.json"
    if [ -f "$f" ]; then emit "$(cat "$f")"; else echo "Not Found" >&2; exit 1; fi ;;
  POST:repos/*/rulesets)
    newid=$(cat "$STATE/nextid"); printf '%s' "$((newid + 1))" >"$STATE/nextid"
    obj=$(jq -c --argjson id "$newid" '. + {id:$id}' "$input")
    jq -c --argjson o "$obj" '. + [$o]' "$STATE/rulesets.json" >"$STATE/rulesets.json.tmp"
    mv "$STATE/rulesets.json.tmp" "$STATE/rulesets.json"
    emit "$obj" ;;
  PUT:repos/*/rulesets/*)
    id="${ep##*/}"
    obj=$(jq -c --argjson id "$id" '. + {id:$id}' "$input")
    # Optionally store a divergent object (simulate a PUT that did not take) so the
    # caller's post-apply verification re-fetch sees drift.
    stored="$obj"
    if [ -f "$STATE/corrupt_on_put" ]; then
      stored=$(printf '%s' "$obj" | jq -c '.rules[].parameters.required_status_checks[].integration_id = 1')
    fi
    jq -c --argjson id "$id" --argjson o "$stored" 'map(if .id==$id then $o else . end)' \
      "$STATE/rulesets.json" >"$STATE/rulesets.json.tmp"
    mv "$STATE/rulesets.json.tmp" "$STATE/rulesets.json"
    emit "$obj" ;;
  DELETE:repos/*/rulesets/*)
    id="${ep##*/}"
    jq -c --argjson id "$id" 'map(select(.id != $id))' "$STATE/rulesets.json" \
      >"$STATE/rulesets.json.tmp"
    mv "$STATE/rulesets.json.tmp" "$STATE/rulesets.json" ;;
  *) echo "mock gh: unhandled $method $ep" >&2; exit 98 ;;
esac
EOF
  chmod +x "$statedir/bin/gh"
}

# Seed a ruleset matching the real desired file (server-assigned id 1000).
seed_compliant() {
  local statedir="$1"
  jq -c '[{id:1000} + .]' "$DESIRED" >"$statedir/rulesets.json"
}
# Seed a same-name ruleset whose context is bound to the WRONG integration_id.
seed_wrong_identity() {
  local statedir="$1"
  jq -c '[{id:1000} + (.rules[].parameters.required_status_checks[].integration_id = 99999)]' \
    "$DESIRED" >"$statedir/rulesets.json"
}
# Seed a same-name ruleset that adds a bypass actor (governance drift a
# fail-closed control must catch).
seed_bypass_actor() {
  local statedir="$1"
  jq -c '[{id:1000} + (.bypass_actors = [{actor_id:5, actor_type:"Team", bypass_mode:"always"}])]' \
    "$DESIRED" >"$statedir/rulesets.json"
}
# Seed a same-name ruleset with strict-required-status-checks flipped on.
seed_strict_flip() {
  local statedir="$1"
  jq -c '[{id:1000} + (.rules[].parameters.strict_required_status_checks_policy = true)]' \
    "$DESIRED" >"$statedir/rulesets.json"
}
# Seed a same-name ruleset that excludes the protected branch (neuters the rule:
# exclude takes precedence over include in GitHub rulesets).
seed_excluded_ref() {
  local statedir="$1"
  jq -c '[{id:1000} + (.conditions.ref_name.exclude = ["refs/heads/main"])]' \
    "$DESIRED" >"$statedir/rulesets.json"
}
# Seed a same-name ruleset with an extra rule of a different type appended.
seed_extra_rule() {
  local statedir="$1"
  jq -c '[{id:1000} + (.rules += [{"type":"deletion"}])]' "$DESIRED" >"$statedir/rulesets.json"
}
# Seed two rulesets sharing the desired name (ambiguous).
seed_duplicate_named() {
  local statedir="$1"
  jq -c '[({id:1000} + .), ({id:1001} + .)]' "$DESIRED" >"$statedir/rulesets.json"
}
mark_workflow_present() { printf 'main\n' >"$1/workflow_present"; }
# Workflow file exists but the job was renamed (no longer declares the context).
mark_workflow_present_but_renamed() { printf 'main\n' >"$1/workflow_present"; : >"$1/workflow_missing_ctx"; }
seed_stale_classic_bp() {
  printf '%s' '{"contexts":["Test","eBPF Datapath Test (#2779 surgical-kill)"]}' \
    >"$1/bp_main.json"
}
# Simulate a 403 reading classic branch protection for `main`.
seed_classic_bp_forbidden() { : >"$1/bp_main.forbidden"; }
# Seed the compliant managed ruleset PLUS a second, differently-named ruleset
# carrying the legacy #2779 context (exercises the stale-scan's other-ruleset arm).
seed_compliant_plus_stale_other() {
  local statedir="$1"
  jq -c '[ ({id:1000} + .),
           { id:1001, name:"legacy surgical-kill", target:"branch",
             conditions:.conditions, bypass_actors:[],
             rules:[{ type:"required_status_checks",
                      parameters:{ required_status_checks:[
                        {context:"eBPF Datapath Test (#2779 surgical-kill)", integration_id:15368} ] } }] } ]' \
    "$DESIRED" >"$statedir/rulesets.json"
}
# Make the mock corrupt the stored object on PUT (live state diverges from what
# was sent) to exercise cmd_apply's post-apply verification-failure branch.
seed_corrupt_on_put() { : >"$1/corrupt_on_put"; }
# Seed a FULL page (100) of rulesets so list_rulesets' truncation guard fires.
seed_many_rulesets() {
  jq -nc '[range(100) | {id:(2000+.), name:"filler-\(.)", target:"branch",
           conditions:{ref_name:{include:[],exclude:[]}}, bypass_actors:[], rules:[]}]' \
    >"$1/rulesets.json"
}
# Seed the compliant managed ruleset PLUS a second ruleset whose per-id GET fails
# (transient error), to exercise the non-fatal stale-scan warning.
seed_compliant_plus_unreadable_other() {
  local statedir="$1"
  jq -c '[ ({id:1000} + .),
           {id:1001, name:"other", target:"branch", conditions:.conditions,
            bypass_actors:[], rules:[]} ]' "$DESIRED" >"$statedir/rulesets.json"
  : >"$statedir/ruleset_1001.fail"
}

run() { # mode... ; uses $STATE
  local out
  out=$(MOCK_GH_STATE="$STATE" REQUIRE_EBPF_GH="$STATE/bin/gh" REQUIRE_EBPF_REPO="test/repo" \
    REQUIRE_EBPF_RULESET_JSON="$DESIRED" bash "$SCRIPT" "$@" 2>&1)
  LAST_RC=$?
  LAST_OUTPUT="$out"
}

echo "require-ebpf-datapath-check.sh fixture tests"

# 1. desired file is valid and projects to the expected identity
ctx=$(jq -r '.rules[].parameters.required_status_checks[].context' "$DESIRED")
iid=$(jq -r '.rules[].parameters.required_status_checks[].integration_id' "$DESIRED")
if [ "$ctx" = "eBPF datapath and object freshness proof" ]; then
  report_pass "desired context is the proof job name"
else
  report_fail "desired context" "got: $ctx"
fi
if [ "$iid" = "15368" ]; then
  report_pass "desired binds GitHub Actions integration_id 15368"
else
  report_fail "desired integration_id" "got: $iid"
fi

# 2. check: ruleset missing -> non-zero, no mutation
new_tmpdir STATE; make_mock "$STATE"
run --check
assert_rc 1 "check: missing ruleset fails"
assert_contains "not found" "check: reports not found"
assert_no_mutations "$STATE" "check: missing ruleset performs no mutation"

# 3. check: compliant -> zero
new_tmpdir STATE; make_mock "$STATE"; seed_compliant "$STATE"
run --check
assert_rc 0 "check: compliant passes"
assert_contains "matches desired state" "check: reports match"
assert_no_mutations "$STATE" "check: compliant performs no mutation"

# 4. check: wrong integration_id (identity not bound) -> drift
new_tmpdir STATE; make_mock "$STATE"; seed_wrong_identity "$STATE"
run --check
assert_rc 1 "check: wrong integration_id fails"
assert_contains "drifted" "check: reports drift on wrong identity"

# 4b. check: added bypass actor (fail-closed governance drift) -> drift
new_tmpdir STATE; make_mock "$STATE"; seed_bypass_actor "$STATE"
run --check
assert_rc 1 "check: added bypass actor fails"
assert_contains "drifted" "check: reports drift on added bypass actor"

# 4c. check: strict-required-status-checks flipped on -> drift
new_tmpdir STATE; make_mock "$STATE"; seed_strict_flip "$STATE"
run --check
assert_rc 1 "check: strict-policy flip fails"
assert_contains "drifted" "check: reports drift on strict-policy flip"

# 5. check: stale #2779 binding in classic branch protection -> fails
new_tmpdir STATE; make_mock "$STATE"; seed_compliant "$STATE"; seed_stale_classic_bp "$STATE"
run --check
assert_rc 1 "check: stale #2779 binding fails"
assert_contains "stale #2779 binding in classic branch protection" "check: reports stale binding"

# 5a. check: an added exclude that neuters the rule -> drift (exclude precedence)
new_tmpdir STATE; make_mock "$STATE"; seed_excluded_ref "$STATE"
run --check
assert_rc 1 "check: added exclude fails"
assert_contains "drifted" "check: reports drift on neutering exclude"

# 5b. check: an extra rule type added live -> drift (projection catches it)
new_tmpdir STATE; make_mock "$STATE"; seed_extra_rule "$STATE"
run --check
assert_rc 1 "check: extra rule type fails"
assert_contains "drifted" "check: reports drift on extra rule type"

# 5c. check: duplicate-named rulesets -> loud warning AND failure (unreviewed drift)
new_tmpdir STATE; make_mock "$STATE"; seed_duplicate_named "$STATE"
run --check
assert_rc 1 "check: duplicate-named rulesets fail"
assert_contains "multiple rulesets named" "check: warns on duplicate-named rulesets"
assert_contains "name is ambiguous" "check: ambiguity message instead of OK on compliant duplicate"

# 5d. check: classic-BP read error (403) -> loud, not silently "clean"
new_tmpdir STATE; make_mock "$STATE"; seed_compliant "$STATE"; seed_classic_bp_forbidden "$STATE"
run --check
assert_rc 1 "check: classic-BP read error fails (not silent)"
assert_contains "could not read classic branch protection" "check: surfaces the read error"

# 5e. check: stale #2779 binding in ANOTHER ruleset -> fails (other-ruleset scan arm)
new_tmpdir STATE; make_mock "$STATE"; seed_compliant_plus_stale_other "$STATE"
run --check
assert_rc 1 "check: stale #2779 in another ruleset fails"
assert_contains "stale #2779 binding in ruleset id" "check: reports stale binding in another ruleset"

# 5f. check: a full (100-item) ruleset page -> fail loud, no silent truncation
new_tmpdir STATE; make_mock "$STATE"; seed_many_rulesets "$STATE"
run --check
assert_rc 1 "check: full ruleset page fails (no silent truncation)"
assert_contains "refusing to trust an incomplete scan" "check: surfaces the truncation guard"

# 5g. check: a transient per-id GET failure in the stale scan -> visible warning, non-fatal
new_tmpdir STATE; make_mock "$STATE"; seed_compliant_plus_unreadable_other "$STATE"
run --check
assert_rc 0 "check: transient stale-scan GET failure is non-fatal"
assert_contains "could not read ruleset 1001 during stale scan" "check: warns on transient stale-scan GET failure"

# 6. apply: refuses to create when workflow absent on target branch
new_tmpdir STATE; make_mock "$STATE"
run --apply
assert_rc 1 "apply: refuses when workflow absent"
assert_contains "would hang every PR" "apply: explains the refusal"
assert_no_mutations "$STATE" "apply: no mutation when refused"

# 6b. apply: refuses on an ambiguous (duplicate) name rather than guessing
new_tmpdir STATE; make_mock "$STATE"; seed_duplicate_named "$STATE"; mark_workflow_present "$STATE"
run --apply
assert_rc 1 "apply: refuses on ambiguous name"
assert_contains "refusing to apply" "apply: explains ambiguity refusal"
assert_no_mutations "$STATE" "apply: no mutation on ambiguous name"

# 6c. apply: refuses when the workflow exists but no longer declares the context
new_tmpdir STATE; make_mock "$STATE"; mark_workflow_present_but_renamed "$STATE"
run --apply
assert_rc 1 "apply: refuses when workflow lacks the required context"
assert_contains "does not declare the required context" "apply: explains missing-context refusal"
assert_no_mutations "$STATE" "apply: no mutation when context absent"

# 7. apply: --force creates even when workflow absent
new_tmpdir STATE; make_mock "$STATE"
run --apply --force
assert_rc 0 "apply --force: creates despite absent workflow"
assert_contains "created ruleset" "apply --force: reports creation"

# 8. apply: creates when workflow present, then check passes
new_tmpdir STATE; make_mock "$STATE"; mark_workflow_present "$STATE"
run --apply
assert_rc 0 "apply: creates when workflow present"
assert_contains "created ruleset" "apply: reports creation"
run --check
assert_rc 0 "apply then check: compliant"

# 9. apply: idempotent no-op on already-compliant repo (no POST/PUT)
new_tmpdir STATE; make_mock "$STATE"; seed_compliant "$STATE"; mark_workflow_present "$STATE"
run --apply
assert_rc 0 "apply: idempotent succeeds"
assert_contains "no change" "apply: reports no change"
assert_no_mutations "$STATE" "apply: idempotent performs no mutation"

# 10. apply: updates a drifted same-name ruleset (PUT), then compliant
new_tmpdir STATE; make_mock "$STATE"; seed_wrong_identity "$STATE"; mark_workflow_present "$STATE"
run --apply
assert_rc 0 "apply: updates drifted ruleset"
assert_contains "updated ruleset" "apply: reports update"
if grep -q '^PUT ' "$STATE/calls.log"; then report_pass "apply: issued PUT to fix drift"; else
  report_fail "apply: PUT" "no PUT recorded"; fi
run --check
assert_rc 0 "apply update then check: compliant"

# 10b. apply: post-apply verification failure (live != desired after PUT) -> non-zero
new_tmpdir STATE; make_mock "$STATE"; seed_wrong_identity "$STATE"; mark_workflow_present "$STATE"; seed_corrupt_on_put "$STATE"
run --apply
assert_rc 1 "apply: post-apply verification failure fails"
assert_contains "post-apply verification failed" "apply: reports post-apply verification failure"

# 11. remove: deletes the managed ruleset
new_tmpdir STATE; make_mock "$STATE"; seed_compliant "$STATE"
run --remove
assert_rc 0 "remove: succeeds"
assert_contains "deleted ruleset" "remove: reports deletion"
run --check
assert_rc 1 "remove then check: ruleset gone"

# 11b. remove: refuses on an ambiguous (duplicate) name
new_tmpdir STATE; make_mock "$STATE"; seed_duplicate_named "$STATE"
run --remove
assert_rc 1 "remove: refuses on ambiguous name"
assert_contains "refusing to remove" "remove: explains ambiguity refusal"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
