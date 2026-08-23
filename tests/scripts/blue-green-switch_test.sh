#!/usr/bin/env bash
# blue-green-switch_test.sh — fixture tests for .github/scripts/blue-green-switch.sh
# ----------------------------------------------------------------------------
# Direct-cell UDP SDKs require the public server NLB on UDP 62206. This fences
# the listener-switch contract:
#   - server always requires udp-listener-arn and its color target groups
#   - a deployed relay makes its internal listener/TGs mandatory
#   - every present listener and rollback TG is preflighted before mutation
#   - any switch or active-color failure rolls all changed listeners back
#   - AC still requires its TCP listener independently
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
    val=$(awk -F'\t' -v n="$name" '$1==n{print $2; f=1} END{exit !f}' "$FAKE_PARAMS") || {
      echo "An error occurred (ParameterNotFound) when calling GetParameter" >&2
      exit 255
    }
    if [[ -z "$val" ]]; then
      echo "An error occurred (ParameterNotFound) when calling GetParameter" >&2
      exit 255
    fi
    printf '%s\n' "$val"
    ;;
  ssm/put-parameter)
    printf '%s\t%s\n' "$name" "$(opt_val --value "$@" || true)" >> "$FAKE_PUTS"
    if [[ -n "${FAKE_FAIL_PUT_NAME:-}" && "$name" == "$FAKE_FAIL_PUT_NAME" ]]; then
      exit 78
    fi
    ;;
  elbv2/modify-listener)
    listener=$(opt_val --listener-arn "$@" || true)
    actions=$(opt_val --default-actions "$@" || true)
    printf 'listener=%s actions=%s\n' \
      "$listener" \
      "$actions" >> "$FAKE_MODIFY"
    call_no=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
    if [[ ",${FAKE_FAIL_MODIFY_CALLS:-}," == *",${call_no},"* ]]; then
      exit 79
    fi
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

# _run <component> <target_color> [reconcile_current] — runs the real script with the fake aws on
# PATH. Sets RC, OUT (combined stdout+stderr), and the marker-file paths.
RC=0; OUT=""
_run() {
  local component="$1" target_color="$2" reconcile_current="${3:-false}"
  local bindir; bindir=$(mktemp -d)
  make_fake_aws "$bindir"
  export FAKE_PARAMS FAKE_PUTS FAKE_MODIFY FAKE_FAIL_MODIFY_LISTENER
  export FAKE_FAIL_MODIFY_CALLS FAKE_FAIL_PUT_NAME
  : > "$FAKE_PUTS"
  : > "$FAKE_MODIFY"
  OUT=$(PATH="$bindir:$PATH" DRY_RUN=false RECONCILE_CURRENT="$reconcile_current" AWS_REGION=us-east-2 \
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
FAKE_FAIL_MODIFY_CALLS=""
FAKE_FAIL_PUT_NAME=""

echo "Running blue-green-switch tests..."

# --- Case 1: an HTTPS listener without both target and rollback TGs fails the
# complete preflight before any listener or authoritative state mutation.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/server/https-listener-arn\tarn:aws:elbv2:::listener/https\n'
  printf '/sandbox/nhp/server/green-https-tg-arn\tarn:aws:elbv2:::tg/https-green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"https target group ARNs are missing"* ]]; then
  report_pass "missing HTTPS rollback TG fails before any traffic mutation"
else
  report_fail "HTTPS TGs are fully preflighted" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
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

# --- Case 5: a server with no UDP listener hard-fails; the required public edge
# can never disappear.
printf '/sandbox/nhp/server/active-color\tblue\n' > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ "$OUT" == *"required udp listener ARN"* ]]; then
  report_pass "server missing public UDP listener hard-fails"
else
  report_fail "server missing public listener hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 6: a deployed relay requires the internal listener before any public
# listener mutation.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/relay/asg-name\tlayerv-nhp-sandbox-relay-dmz\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"required internal UDP listener ARN"* ]]; then
  report_pass "deployed relay requires internal listener before public switch"
else
  report_fail "deployed relay missing internal listener hard-fails" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 7: public UDP + internal relay UDP, but the target internal TG is
# missing -> fail preflight before either listener or active-color moves.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/relay/asg-name\tlayerv-nhp-sandbox-relay-dmz\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 ]] && [[ ! -s "$FAKE_MODIFY" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$OUT" == *"Internal relay listener exists but one or more internal UDP target group ARNs are missing"* ]]; then
  report_pass "missing internal relay target TG fails before public UDP switch"
else
  report_fail "missing internal relay target TG preflight" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 8: migration state with public UDP + internal relay UDP, but the
# internal relay listener switch fails -> roll back public UDP and do not record
# active-color.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/relay/asg-name\tlayerv-nhp-sandbox-relay-dmz\n'
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

# --- Case 9: failure to write the non-authoritative timestamp does not undo a
# completed listener switch and authoritative active-color update.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
FAKE_FAIL_PUT_NAME="/sandbox/nhp/server/last-switch-timestamp"
_run server green
FAKE_FAIL_PUT_NAME=""
if [[ "$RC" -eq 0 ]] && grep -q 'tg/green' "$FAKE_MODIFY" \
   && grep -qE 'active-color[[:space:]]+green' "$FAKE_PUTS" \
   && [[ "$OUT" == *"Failed to record non-authoritative switch timestamp"* ]]; then
  report_pass "timestamp failure remains non-authoritative after active-color succeeds"
else
  report_fail "timestamp write is non-authoritative" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
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

# --- Case 11: all three listeners switch, but authoritative active-color write
# fails. Roll back HTTPS, internal UDP, and public UDP in exact reverse order.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
  printf '/sandbox/nhp/server/green-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-green\n'
  printf '/sandbox/nhp/server/https-listener-arn\tarn:aws:elbv2:::listener/https\n'
  printf '/sandbox/nhp/server/blue-https-tg-arn\tarn:aws:elbv2:::tg/https-blue\n'
  printf '/sandbox/nhp/server/green-https-tg-arn\tarn:aws:elbv2:::tg/https-green\n'
} > "$FAKE_PARAMS"
FAKE_FAIL_PUT_NAME="/sandbox/nhp/server/active-color"
_run server green
FAKE_FAIL_PUT_NAME=""
modify_lines=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
call1=$(sed -n '1p' "$FAKE_MODIFY"); call2=$(sed -n '2p' "$FAKE_MODIFY")
call3=$(sed -n '3p' "$FAKE_MODIFY"); call4=$(sed -n '4p' "$FAKE_MODIFY")
call5=$(sed -n '5p' "$FAKE_MODIFY"); call6=$(sed -n '6p' "$FAKE_MODIFY")
if [[ "$RC" -ne 0 ]] && [[ "$modify_lines" == "6" ]] \
   && [[ "$call1" == *'listener/udp'* && "$call1" == *'tg/green'* ]] \
   && [[ "$call2" == *'listener/internal-udp'* && "$call2" == *'tg/internal-green'* ]] \
   && [[ "$call3" == *'listener/https'* && "$call3" == *'tg/https-green'* ]] \
   && [[ "$call4" == *'listener/https'* && "$call4" == *'tg/https-blue'* ]] \
   && [[ "$call5" == *'listener/internal-udp'* && "$call5" == *'tg/internal-blue'* ]] \
   && [[ "$call6" == *'listener/udp'* && "$call6" == *'tg/blue'* ]]; then
  report_pass "active-color failure rolls every switched listener back in reverse order"
else
  report_fail "active-color failure is transactionally rolled back" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 12: the secondary HTTPS forward switch fails after public and internal
# UDP move. Both prior listeners are restored and active-color is not written.
FAKE_FAIL_MODIFY_LISTENER="arn:aws:elbv2:::listener/https"
_run server green
FAKE_FAIL_MODIFY_LISTENER=""
modify_lines=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
call3=$(sed -n '3p' "$FAKE_MODIFY"); call4=$(sed -n '4p' "$FAKE_MODIFY")
call5=$(sed -n '5p' "$FAKE_MODIFY")
if [[ "$RC" -ne 0 ]] && [[ "$modify_lines" == "5" ]] && [[ ! -s "$FAKE_PUTS" ]] \
   && [[ "$call3" == *'listener/https'* && "$call3" == *'tg/https-green'* ]] \
   && [[ "$call4" == *'listener/internal-udp'* && "$call4" == *'tg/internal-blue'* ]] \
   && [[ "$call5" == *'listener/udp'* && "$call5" == *'tg/blue'* ]]; then
  report_pass "failed HTTPS switch restores both earlier UDP listeners"
else
  report_fail "failed HTTPS switch rolls back prior listeners" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 13: one rollback call fails after the active-color write fails. The
# rollback routine still attempts every remaining listener repair.
FAKE_FAIL_PUT_NAME="/sandbox/nhp/server/active-color"
FAKE_FAIL_MODIFY_CALLS="4"
_run server green
FAKE_FAIL_MODIFY_CALLS=""
FAKE_FAIL_PUT_NAME=""
modify_lines=$(wc -l < "$FAKE_MODIFY" | tr -d ' ')
call4=$(sed -n '4p' "$FAKE_MODIFY"); call5=$(sed -n '5p' "$FAKE_MODIFY")
call6=$(sed -n '6p' "$FAKE_MODIFY")
if [[ "$RC" -ne 0 ]] && [[ "$modify_lines" == "6" ]] \
   && [[ "$call4" == *'listener/https'* ]] \
   && [[ "$call5" == *'listener/internal-udp'* ]] \
   && [[ "$call6" == *'listener/udp'* ]] \
   && [[ "$OUT" == *"One or more listener rollbacks failed"* ]]; then
  report_pass "rollback failure does not prevent remaining listener repairs"
else
  report_fail "rollback remains best effort across all listeners" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 14: a newly created listener can default to blue while the existing
# active-color marker is green. Explicit reconciliation must not take the normal
# current==target no-op; it re-applies green to both public and internal UDP.
{
  printf '/sandbox/nhp/server/active-color\tgreen\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
  printf '/sandbox/nhp/relay/asg-name\tlayerv-nhp-sandbox-relay-dmz\n'
  printf '/sandbox/nhp/server/internal-udp-listener-arn\tarn:aws:elbv2:::listener/internal-udp\n'
  printf '/sandbox/nhp/server/blue-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-blue\n'
  printf '/sandbox/nhp/server/green-internal-udp-tg-arn\tarn:aws:elbv2:::tg/internal-green\n'
} > "$FAKE_PARAMS"
_run server green true
if [[ "$RC" -eq 0 ]] \
   && grep -q 'listener/udp.*tg/green' "$FAKE_MODIFY" \
   && grep -q 'listener/internal-udp.*tg/internal-green' "$FAKE_MODIFY" \
   && grep -qE 'active-color[[:space:]]+green' "$FAKE_PUTS" \
   && [[ "$OUT" == *"Reconciling every listener"* ]]; then
  report_pass "explicit reconciliation re-applies the current color to every server listener"
else
  report_fail "current-color listener reconciliation" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 15: once the durable floor is installed, an unrecorded legacy slot
# is permanently ineligible even for switch-only/reconcile callers.
{
  printf '/sandbox/nhp/minimum-protocol-profile\tdurable-aop-v1\n'
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 && ! -s "$FAKE_MODIFY" && ! -s "$FAKE_PUTS" && "$OUT" == *"below minimum"* ]]; then
  report_pass "durable minimum rejects an unrecorded legacy target slot"
else
  report_fail "durable minimum blocks legacy target" "rc=$RC modify=$(cat "$FAKE_MODIFY") puts=$(cat "$FAKE_PUTS") out=<<<$OUT>>>"
fi

# --- Case 16: the exact profile record binds both profile and image.
{
  printf '/sandbox/nhp/minimum-protocol-profile\tdurable-aop-v1\n'
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/green-image-tag\t0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/server/green-protocol-profile\tv1|durable-aop-v1|0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -eq 0 && "$OUT" == *"target=durable-aop-v1 minimum=durable-aop-v1"* ]]; then
  report_pass "exact durable slot record remains switchable at the floor"
else
  report_fail "exact durable record accepted" "rc=$RC out=<<<$OUT>>>"
fi

# --- Case 17: changing only the image tag invalidates the record before any
# listener mutation.
sed -i.bak 's/green-image-tag\t0123456789012345678901234567890123456789/green-image-tag\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 && ! -s "$FAKE_MODIFY" && ! -s "$FAKE_PUTS" && "$OUT" == *"does not bind its current image"* ]]; then
  report_pass "stale profile record cannot authorize a different image"
else
  report_fail "slot record binds exact image" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 18: before the floor advances, an ordinary helper invocation cannot
# activate a prepared durable slot without the dedicated cutover ledger.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/green-image-tag\t0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/server/green-protocol-profile\tv1|durable-aop-v1|0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -ne 0 && ! -s "$FAKE_MODIFY" && ! -s "$FAKE_PUTS" && "$OUT" == *"without the dedicated cutover ledger"* ]]; then
  report_pass "durable standby cannot be activated outside the dedicated cutover"
else
  report_fail "upward profile activation requires cutover ledger" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

# --- Case 19: the exact image-bound ledger authorizes cell0 only after the AC
# switch phase. This is the retry-safe path the dedicated cutover uses.
{
  printf '/sandbox/nhp/server/active-color\tblue\n'
  printf '/sandbox/nhp/server/green-image-tag\t0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/server/green-protocol-profile\tv1|durable-aop-v1|0123456789012345678901234567890123456789\n'
  printf '/sandbox/nhp/cutovers/durable-aop-v1/state\t%s\n' \
    '{"schema":2,"image":"0123456789012345678901234567890123456789","orchestrator_sha":"0123456789012345678901234567890123456789","lock_owner":"nhp:123:durable-aop-cutover:0123456789012345678901234567890123456789","phase":"ac_switched"}'
  printf '/sandbox/nhp/server/udp-listener-arn\tarn:aws:elbv2:::listener/udp\n'
  printf '/sandbox/nhp/server/blue-udp-tg-arn\tarn:aws:elbv2:::tg/blue\n'
  printf '/sandbox/nhp/server/green-udp-tg-arn\tarn:aws:elbv2:::tg/green\n'
} > "$FAKE_PARAMS"
_run server green
if [[ "$RC" -eq 0 && -s "$FAKE_MODIFY" && "$OUT" == *"target=durable-aop-v1 minimum=legacy-aop-v1"* ]]; then
  report_pass "exact post-AC cutover ledger authorizes cell0 durable activation"
else
  report_fail "dedicated ledger authorizes ordered upward activation" "rc=$RC modify=$(cat "$FAKE_MODIFY") out=<<<$OUT>>>"
fi

echo
if [[ "$fail" -gt 0 ]]; then
  printf '\033[31m%d passed, %d failed\033[0m\n' "$pass" "$fail"
  printf '%b' "$failures"
  exit 1
fi
printf '\033[32mAll %d tests passed\033[0m\n' "$pass"
