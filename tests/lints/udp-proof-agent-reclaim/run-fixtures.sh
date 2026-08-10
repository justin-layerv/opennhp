#!/usr/bin/env bash
# Proves reclaim_udp_proof_agents.sh, with a stubbed aws CLI.
#
# The assertion that matters is the COUNTER one. Deleting AGENT# rows without
# reconciling META.assignment_count looks like a successful reclaim and changes
# nothing: the Authority reads the counter, not the rows. That exact mistake
# left the proof denied at enrollment for hours on 2026-08-10.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/reclaim_udp_proof_agents.sh"
fails=0

run_case() {
  local name="$1" sks="$2" count="$3" update_rc="$4" update_err="$5" fail_query="${6:-}"
  local tmp; tmp="$(mktemp -d)"
  mkdir -p "$tmp/bin"
  [ -n "$fail_query" ] && : > "$tmp/fail_query"
  cat > "$tmp/bin/aws" <<EOF
#!/usr/bin/env bash
# Record every mutating call so the test can assert on them.
echo "\$@" >> "$tmp/calls.log"
case "\$2" in
  query)
    if [ -f "$tmp/fail_query" ]; then echo "throttled" >&2; exit 255; fi
    if [ -f "$tmp/deleted_all" ]; then printf '%s' ""; else printf '%s' '$sks'; fi
    ;;
  get-item)   printf '%s' '$count' ;;
  delete-item) : > "$tmp/deleted_all" ;;
  update-item)
    if [ "$update_rc" != "0" ]; then echo '$update_err' >&2; exit $update_rc; fi
    ;;
esac
exit 0
EOF
  chmod +x "$tmp/bin/aws"
  set +e
  out="$(PATH="$tmp/bin:$PATH" AWS_REGION=us-east-2 \
    PROOF_AUTHORITY_TABLE=t PROOF_AGENT_OWNER_PK='OWNER#abc' \
    bash "$SCRIPT" 2>&1)"
  rc=$?
  set -e
  echo "--- $name (rc=$rc) ---"
  printf '%s\n' "$out" | sed 's/^/    /'
  case_out="$out"; case_rc="$rc"; case_calls="$(cat "$tmp/calls.log" 2>/dev/null || true)"
  rm -rf "$tmp"
}

# Explicit values rather than eval over globals: shellcheck cannot see through
# eval, and a suppression would hide real unused-variable findings later.
pass_or_fail() {
  local what="$1" ok="$2"
  if [ "$ok" = "yes" ]; then echo "  ok: $what"; else echo "  FAIL: $what"; fails=$((fails+1)); fi
}
expect_contains() {
  local what="$1" hay="$2" needle="$3" ok=no
  case "$hay" in *"$needle"*) ok=yes ;; esac
  pass_or_fail "$what" "$ok"
}
expect_not_contains() {
  local what="$1" hay="$2" needle="$3" ok=yes
  case "$hay" in *"$needle"*) ok=no ;; esac
  pass_or_fail "$what" "$ok"
}
expect_rc() {
  local what="$1" got="$2" want="$3" ok=no
  [ "$got" = "$want" ] && ok=yes
  pass_or_fail "$what" "$ok"
}
# get-item and update-item legitimately key on META -- only DELETES are
# forbidden, so filter to delete-item lines before looking for it.
expect_no_meta_delete() {
  local what="$1" calls="$2" ok=yes
  if printf '%s\n' "$calls" | grep '^dynamodb delete-item' | grep -q '"sk":{"S":"META"}'; then
    ok=no
  fi
  pass_or_fail "$what" "$ok"
}
expect_rc_nonzero() {
  local what="$1" got="$2" ok=yes
  [ "$got" = "0" ] && ok=no
  pass_or_fail "$what" "$ok"
}

# 1. Rows are deleted AND the counter is reconciled down.
run_case "reclaims rows and reconciles the counter" \
  'AGENT#a
DEVICE_CREDENTIAL#b
COMPLETION#c
META' '25' 0 ''
expect_contains "reconciles 25 -> 0" "$case_out" "reconciled 25 -> 0"
expect_rc "exits 0" "$case_rc" 0
expect_contains "issues an update-item on the counter" "$case_calls" "update-item"
expect_contains "deletes the AGENT# row" "$case_calls" '"sk":{"S":"AGENT#a"}'
expect_contains "deletes the DEVICE_CREDENTIAL# row" "$case_calls" '"sk":{"S":"DEVICE_CREDENTIAL#b"}'
expect_contains "deletes the COMPLETION# row" "$case_calls" '"sk":{"S":"COMPLETION#c"}'
# Paired with the positive assertions above so this cannot pass merely because
# nothing was deleted at all.
expect_no_meta_delete "never deletes META" "$case_calls"

# 2. A concurrent activation must NOT be clobbered, and must not fail the run.
run_case "tolerates a concurrent activation" \
  'AGENT#a
META' '9' 255 'An error occurred (ConditionalCheckFailedException) when calling UpdateItem'
expect_contains "warns instead of failing" "$case_out" "::warning::"
expect_rc "exits 0" "$case_rc" 0

# 3. Any other counter failure must fail LOUDLY -- silence here is how the
#    counter drifted up forever in the first place.
run_case "fails loudly on a real counter error" \
  'AGENT#a
META' '9' 255 'An error occurred (AccessDeniedException) when calling UpdateItem'
expect_contains "emits ::error::" "$case_out" "::error::"
expect_rc_nonzero "exits non-zero" "$case_rc"

# 4. No META row at all: nothing to reconcile, and NOT an error.
run_case "exits cleanly when there is no counter row" \
  'AGENT#a
META' 'None' 0 ''
expect_contains "says there is nothing to reconcile" "$case_out" "nothing to reconcile"
expect_rc "exits 0" "$case_rc" 0
expect_not_contains "never writes the counter" "$case_calls" "update-item"

# 5. Counter already equals the surviving agent count: no write at all.
#    Guards against a needless write on every run, which would also make the
#    conditional-update contention window fire for no reason.
run_case "skips the write when already reconciled" \
  'META' '0' 0 ''
expect_contains "reports already reconciled" "$case_out" "already reconciled"
expect_rc "exits 0" "$case_rc" 0
expect_not_contains "never writes the counter" "$case_calls" "update-item"

# 6. A FAILED listing must be fatal, never mistaken for an empty partition.
#    Without this, a transient throttle yields remaining_agents=0 against a
#    live observed count and drives a confident SET assignment_count = 0 while
#    the agents still exist. The condition-expression cannot catch that: it
#    guards a concurrent WRITER, not a wrong input.
run_case "refuses to reconcile from a failed listing" \
  'AGENT#a
META' '25' 0 '' fail
expect_contains "emits ::error::" "$case_out" "::error::"
expect_rc_nonzero "exits non-zero" "$case_rc"
expect_not_contains "never issues the counter write" "$case_calls" "update-item"

if [ "$fails" != "0" ]; then echo "FAILED: $fails assertion(s)"; exit 1; fi
echo "all reclaim fixtures passed"
