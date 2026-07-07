#!/usr/bin/env bash
# blue-green-switch_test.sh — fixture tests for .github/scripts/blue-green-switch.sh
# ----------------------------------------------------------------------------
# #2628 takes nhp-server private: the public UDP NLB and its
# /<env>/nhp/server/udp-listener-arn SSM param are removed, so the blue/green
# switch must flip the internal relay UDP listener instead. This fences that
# contract:
#   - server + MISSING udp-listener-arn + private marker -> flip internal-udp, record active-color, rc=0
#   - server + present listener + TGs                    -> normal flip still happens (regression guard)
#   - ac     + MISSING tcp-listener-arn                  -> still a hard error (the server fallback is not global)
#
# Each case puts a fake `aws` on PATH and runs the REAL switch script. The fake
# records modify-listener / put-parameter calls so we can assert what happened.
#
# Usage: bash tests/scripts/blue-green-switch_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/blue-green-switch.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  FAIL $1: $2\n"; printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"; }

# Build a fake `aws` on PATH. Param values come from a TAB-separated file
# ($FAKE_PARAMS: "<name>\t<value>"); a name absent from the file (or with an
# empty value) makes `aws ssm get-parameter` exit non-zero — exactly how the
# real CLI behaves for a missing parameter, which the script's get_ssm_param
# turns into "". modify-listener / put-parameter calls are appended to marker
# files so tests can assert on them.
make_fake_aws() {
  local dir="$1"
  cat > "$dir/aws" <<'AWS'
#!/usr/bin/env bash
set -uo pipefail
svc="${1:-}"; sub="${2:-}"; shift 2 || true

opt_val() { # opt_val <flag> <args...> -> prints value after <flag>
  local want="$1" prev=""; shift
  for a in "$@"; do
    [[ "$prev" == "$want" ]] && { printf '%s' "$a"; return 0; }
    prev="$a"
  done
  return 1
}
name=$(opt_val --name "$@" || true)

case "$svc/$sub" in
  ssm/get-parameter)
    val=$(awk -F'\t' -v n="$name" '$1==n{print $2; f=1} END{exit !f}' "$FAKE_PARAMS") || exit 255
    [[ -z "$val" ]] && exit 255
    printf '%s\n' "$val"
    ;;
  ssm/put-parameter)
    printf '%s\t%s\n' "$name" "$(opt_val --value "$@" || true)" >> "$FAKE_PUTS"
    ;;
  elbv2/modify-listener)
    listener=$(opt_val --listener-arn "$@" || true)
    actions=$(opt_val --default-actions "$@" || true)
    printf 'listener=%s actions=%s\n' \
      "$listener" \
      "$actions" >> "$FAKE_MODIFY"
    if [[ -n "${FAKE_FAIL_MODIFY_LISTENER:-}" && "$listener" == "$FAKE_FAIL_MODIFY_LISTENER" ]]; then
      exit 77
    fi
    ;;
  *)
    echo "fake-aws: unhandled $svc $sub" >&2; exit 64
    ;;
esac
exit 0
AWS
  chmod +x "$dir/aws"
}

# _run <component> <target_color> — runs the real script with the fake aws on
# PATH. Sets RC, OUT (combined stdout+stderr), and the marker-file paths.
RC=0; OUT=""
_run() {
  local component="$1" target_color="$2"
  local bindir; bindir=$(mktemp -d)
  make_fake_aws "$bindir"
  export FAKE_PARAMS FAKE_PUTS FAKE_MODIFY FAKE_FAIL_MODIFY_LISTENER
  : > "$FAKE_PUTS"
  : > "$FAKE_MODIFY"
  OUT=$(PATH="$bindir:$PATH" DRY_RUN=false AWS_REGION=us-east-2 \
        bash "$SCRIPT" sandbox "$target_color" "$component" 2>&1)
  RC=$?
  rm -rf "$bindir"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAKE_PARAMS="$WORK/params"
FAKE_PUTS="$WORK/puts"
FAKE_MODIFY="$WORK/modify"
FAKE_FAIL_MODIFY_LISTENER=""

echo "Running blue-green-switch tests..."

# --- Case 1: private server — no public udp listener BUT take-server-private=true ->
# flip the internal relay UDP listener, then record color. Also asserts the
# SECONDARY (HTTPS) block runs as a safe no-op after the primary switch: https is
# likewise absent when private, so it must log "No https listener configured".
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/take-server-private\ttrue\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
  printf '/sandbox/nhp/server/green-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -eq 0 ]] && [[ "$OUT" == *"Switching the internal relay UDP listener instead"* ]] \
   && [[ "$OUT" == *"No https listener configured"* ]] \
   && grep -q "listener/internal-udp" "$FAKE_MODIFY" \
   && grep -q "tg/internal-green" "$FAKE_MODIFY" \
   && grep -qE "active-color[[:space:]]+green" "$FAKE_PUTS"; then
  report_pass "private server (marker=true) flips internal relay UDP listener, HTTPS no-ops, records active-color=green"
else
  report_fail "private server flips internal relay listener" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 2: normal server switch (listener + TGs present) -> flip to green TG
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -eq 0 ]] && grep -q "tg/green" "$FAKE_MODIFY" && grep -q "active-color" "$FAKE_PUTS"; then
  report_pass "normal server switch still flips the public UDP listener"
else
  report_fail "normal server switch flips UDP listener" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 3: migration state with public UDP + internal relay UDP -> flip both
# before active-color is written.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
  printf '/sandbox/nhp/server/green-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -eq 0 ]] \
   && grep -q "listener/udp" "$FAKE_MODIFY" \
   && grep -q "tg/green" "$FAKE_MODIFY" \
   && grep -q "listener/internal-udp" "$FAKE_MODIFY" \
   && grep -q "tg/internal-green" "$FAKE_MODIFY" \
   && grep -qE "active-color[[:space:]]+green" "$FAKE_PUTS"; then
  report_pass "server switch flips both public UDP and internal relay UDP listeners"
else
  report_fail "server switch flips both public and internal UDP listeners" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 4: AC with no tcp listener -> hard error (skip is server-only)
printf '/sandbox/nhp/ac/active-color\tblue\n' > "$FAKE_PARAMS"
_run ac green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]]; then
  report_pass "AC missing primary listener is still a hard error"
else
  report_fail "AC missing primary listener errors" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 5: server with NO udp listener AND NO take-server-private marker -> HARD FAIL.
# Guards the silent-skip-widening risk: a botched public apply / SSM drift / accidental
# param deletion on a PUBLIC server must fail loudly, not skip the switch and report green.
printf '/sandbox/nhp/server/active-color\tblue\n' > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ "$OUT" == *"take-server-private is not 'true'"* ]]; then
  report_pass "server missing listener WITHOUT private marker hard-fails (no silent skip)"
else
  report_fail "server missing listener without marker hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 6: private marker true but the internal listener SSM contract is absent
# -> HARD FAIL before active-color is updated. This catches the exact dangerous
# drift where a private server deploy reports green without an active relay switch
# point.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/take-server-private\ttrue\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"relay path has no active-color switch point"* ]]; then
  report_pass "private server missing internal listener hard-fails before active-color update"
else
  report_fail "private server missing internal listener hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 7: migration state with public UDP + internal relay UDP, but the
# target internal TG is missing -> roll back the already-switched public listener
# and do not record active-color.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
} > "$FAKE_PARAMS"
_run server green
modify_lines=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
first_modify=$(sed -n '1p' "$FAKE_MODIFY")
second_modify=$(sed -n '2p' "$FAKE_MODIFY")
if [[ "$RC" -ne 0 ]] && [[ "$modify_lines" == "2" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$first_modify" == *"listener/udp"* && "$first_modify" == *"tg/green"* ]] \
   && [[ "$second_modify" == *"listener/udp"* && "$second_modify" == *"tg/blue"* ]] \
   && [[ "$OUT" == *"Internal relay listener exists but one or more internal UDP target group ARNs are missing"* ]]; then
  report_pass "missing internal relay target TG rolls back public UDP and skips active-color"
else
  report_fail "missing internal relay target TG rolls back public UDP" "rc=$RC lines=$modify_lines modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 8: migration state with public UDP + internal relay UDP, but the
# internal relay listener switch fails -> roll back public UDP and do not record
# active-color.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
  printf '/sandbox/nhp/server/green-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-green\n'
} > "$FAKE_PARAMS"
FAKE_FAIL_MODIFY_LISTENER="arn:aws:elbv2:::listener/internal-udp"
_run server green
FAKE_FAIL_MODIFY_LISTENER=""
modify_lines=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
first_modify=$(sed -n '1p' "$FAKE_MODIFY")
second_modify=$(sed -n '2p' "$FAKE_MODIFY")
third_modify=$(sed -n '3p' "$FAKE_MODIFY")
if [[ "$RC" -ne 0 ]] && [[ "$modify_lines" == "3" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$first_modify" == *"listener/udp"* && "$first_modify" == *"tg/green"* ]] \
   && [[ "$second_modify" == *"listener/internal-udp"* && "$second_modify" == *"tg/internal-green"* ]] \
   && [[ "$third_modify" == *"listener/udp"* && "$third_modify" == *"tg/blue"* ]] \
   && [[ "$OUT" == *"internal relay UDP listener switch failed"* ]]; then
  report_pass "failed internal relay switch rolls back public UDP and skips active-color"
else
  report_fail "failed internal relay switch rolls back public UDP" "rc=$RC lines=$modify_lines modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 9: private marker true and internal listener exists, but the target
# internal TG is missing -> HARD FAIL before any listener switch or active-color
# write. This keeps the private-only error message explicit about the relay
# active-color switch point.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/take-server-private\ttrue\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"relay path has no active-color switch point"* ]]; then
  report_pass "private server missing target internal TG hard-fails before active-color update"
else
  report_fail "private server missing target internal TG hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 10: public switch has the target TG but the current-color rollback TG
# is missing -> HARD FAIL before the first listener switch. A later internal or
# HTTPS listener failure would otherwise roll back primary to an empty TG ARN.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"rollback target group ARN"* ]]; then
  report_pass "missing current-color primary rollback TG hard-fails before listener switch"
else
  report_fail "missing current-color rollback TG hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

echo
if [[ "$fail" -gt 0 ]]; then
  printf '\033[31m%d passed, %d failed\033[0m\n' "$pass" "$fail"
  printf '%b' "$failures"
  exit 1
fi
printf '\033[32mAll %d tests passed\033[0m\n' "$pass"
