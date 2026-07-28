#!/usr/bin/env bash
# soak-period_test.sh — fixture tests for .github/scripts/soak-period.sh
# ----------------------------------------------------------------------------
# The soak runs strictly AFTER blue-green-deploy.yml's switch-traffic job, so it
# must watch the color that is actually serving traffic. This fences that:
#   - the fleet is resolved from active-color -> <color>-asg-name
#   - /<env>/nhp/server/asg-name (the color-BLIND base/blue group) is NEVER read
#   - an absent/unknown/padded color fails closed, with no fallback
#   - a missing per-color ASG parameter fails closed, with no fallback
#   - a genuinely degraded ACTIVE fleet still fails the soak
#
# Each case puts a fake `aws` (and a no-op `sleep`) on PATH and runs the REAL
# script. The fake dispatches by parameter/ASG/target-group NAME, never by call
# order, so a script that asks for the wrong fleet cannot accidentally pass.
#
# Response shapes are captured verbatim from the live sandbox account
# (767397897469 / us-east-2) for the exact --query/--output pairs the script
# uses:
#   ssm get-parameter --query Parameter.Value --output text  -> "green\n"
#     (a missing parameter exits 254 with ParameterNotFound on stderr)
#   autoscaling describe-auto-scaling-groups
#     --query '...{Desired:...,Healthy:...}' --output json   -> pretty JSON
#     --query 'AutoScalingGroups[0].TargetGroupARNs[0]' --output text -> ARN
#   elbv2 describe-target-health --query 'length(...)' --output text  -> integer
#
# Usage: bash tests/scripts/soak-period_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/soak-period.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  FAIL $1: $2\n"; printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"; }

# Live ARNs and names, so the fixtures are the real topology rather than
# invented placeholders. Blue's first target group is the INTERNAL udp group —
# TargetGroupARNs order is the live order, which is what the script indexes.
BLUE_ASG="layerv-nhp-sandbox-server"
GREEN_ASG="layerv-nhp-sandbox-server-green"
BLUE_TG="arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-srv-int-udp/b565d1e52500c695"
GREEN_TG="arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-srv-int-grn/ba51122c7e9420e4"
CELL1_BLUE_ASG="layerv-nhp-sandbox-cell1-server"
CELL1_GREEN_ASG="layerv-nhp-sandbox-cell1-server-green"
CELL1_GREEN_TG="arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-cell1-udp-grn/5977903c7d055294"

# Build a fake `aws` plus a no-op `sleep` on PATH.
#
# $FAKE_PARAMS  "<name>\t<value>"          — absent/empty name => exit 254 (ParameterNotFound)
# $FAKE_ASGS    "<asg>\t<desired>\t<healthy>\t<tg-arn>"
# $FAKE_TGH     "<tg-arn>\t<total>\t<unhealthy>"
# $FAKE_CALLS   every resolved lookup, one per line, for order-independent asserts
make_fake_bin() {
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

case "$svc/$sub" in
  ssm/get-parameter)
    name=$(opt_val --name "$@" || true)
    printf 'ssm:%s\n' "$name" >> "$FAKE_CALLS"
    val=$(awk -F'\t' -v n="$name" '$1==n{print $2; f=1} END{exit !f}' "$FAKE_PARAMS") || {
      # Verbatim shape of a real miss: stderr + exit 254.
      echo "aws: [ERROR]: An error occurred (ParameterNotFound) when calling the GetParameter operation:" >&2
      exit 254
    }
    [[ -z "$val" ]] && {
      echo "aws: [ERROR]: An error occurred (ParameterNotFound) when calling the GetParameter operation:" >&2
      exit 254
    }
    printf '%s\n' "$val"
    ;;
  autoscaling/describe-auto-scaling-groups)
    asg=$(opt_val --auto-scaling-group-names "$@" || true)
    query=$(opt_val --query "$@" || true)
    read -r desired healthy tg < <(
      awk -F'\t' -v n="$asg" '$1==n{print $2"\t"$3"\t"$4; f=1} END{exit !f}' "$FAKE_ASGS"
    ) || { echo "fake-aws: unknown ASG $asg" >&2; exit 254; }
    if [[ "$query" == *TargetGroupARNs* ]]; then
      printf 'asg-tg:%s\n' "$asg" >> "$FAKE_CALLS"
      printf '%s\n' "$tg"
    else
      printf 'asg-health:%s\n' "$asg" >> "$FAKE_CALLS"
      # Real --output json is pretty-printed; jq reads it either way.
      printf '{\n    "Desired": %s,\n    "Healthy": %s\n}\n' "$desired" "$healthy"
    fi
    ;;
  elbv2/describe-target-health)
    tg=$(opt_val --target-group-arn "$@" || true)
    query=$(opt_val --query "$@" || true)
    printf 'tgh:%s\n' "$tg" >> "$FAKE_CALLS"
    read -r total unhealthy < <(
      awk -F'\t' -v n="$tg" '$1==n{print $2"\t"$3; f=1} END{exit !f}' "$FAKE_TGH"
    ) || { echo "fake-aws: unknown target group $tg" >&2; exit 254; }
    # The script asks for the unhealthy count and the total in separate calls.
    if [[ "$query" == *'TargetHealth.State'* ]]; then
      printf '%s\n' "$unhealthy"
    else
      printf '%s\n' "$total"
    fi
    ;;
  *)
    echo "fake-aws: unhandled $svc $sub" >&2; exit 64
    ;;
esac
exit 0
AWS
  chmod +x "$dir/aws"
  # The soak sleeps between checks; a no-op keeps the suite instant while
  # leaving the real loop arithmetic (and therefore the real check count) intact.
  printf '#!/usr/bin/env bash\nexit 0\n' > "$dir/sleep"
  chmod +x "$dir/sleep"
}

# _run <environment> [soak_minutes] [skip_soak] — runs the real script with the
# fakes on PATH. Sets RC and OUT (combined stdout+stderr).
RC=0; OUT=""
_run() {
  local environment="$1" soak_minutes="${2:-1}" skip_soak="${3:-false}"
  local bindir; bindir=$(mktemp -d)
  make_fake_bin "$bindir"
  export FAKE_PARAMS FAKE_ASGS FAKE_TGH FAKE_CALLS
  : > "$FAKE_CALLS"
  OUT=$(PATH="$bindir:$PATH" \
        ENVIRONMENT="$environment" SOAK_MINUTES="$soak_minutes" \
        SKIP_SOAK="$skip_soak" AWS_REGION=us-east-2 \
        bash "$SCRIPT" 2>&1)
  RC=$?
  rm -rf "$bindir"
}

called() { grep -qxF "$1" "$FAKE_CALLS"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAKE_PARAMS="$WORK/params"
FAKE_ASGS="$WORK/asgs"
FAKE_TGH="$WORK/tgh"
FAKE_CALLS="$WORK/calls"

# Live sandbox topology, captured 2026-07-28. Blue and green ASGs are BOTH
# 3/3 healthy — the ASG check alone cannot tell them apart, which is exactly why
# the color must be resolved rather than assumed. Blue's target group carries
# three "unused" (Target.NotInUse) targets because no listener forwards to it
# while green is active; green's carries three healthy ones.
write_live_sandbox_fixture() {
  local active="$1"
  {
    printf '/sandbox/nhp/server/active-color\t%s\n' "$active"
    printf '/sandbox/nhp/server/asg-name\t%s\n' "$BLUE_ASG"
    printf '/sandbox/nhp/server/blue-asg-name\t%s\n' "$BLUE_ASG"
    printf '/sandbox/nhp/server/green-asg-name\t%s\n' "$GREEN_ASG"
  } > "$FAKE_PARAMS"
  {
    printf '%s\t3\t3\t%s\n' "$BLUE_ASG" "$BLUE_TG"
    printf '%s\t3\t3\t%s\n' "$GREEN_ASG" "$GREEN_TG"
  } > "$FAKE_ASGS"
  {
    printf '%s\t3\t3\n' "$BLUE_TG"   # three "unused" targets => 3 unhealthy
    printf '%s\t3\t0\n' "$GREEN_TG"  # three healthy targets
  } > "$FAKE_TGH"
}

echo "Running soak-period tests..."

# --- Case 1: green active -> soak the GREEN fleet, never blue.
# This is the regression fence. Under the old color-blind resolution the script
# read blue, whose live target group is entirely "unused", and exited 1 on a
# perfectly healthy deployment.
write_live_sandbox_fixture green
_run sandbox
if [[ "$RC" -eq 0 ]] \
   && called "ssm:/sandbox/nhp/server/active-color" \
   && called "ssm:/sandbox/nhp/server/green-asg-name" \
   && called "asg-health:$GREEN_ASG" \
   && called "tgh:$GREEN_TG" \
   && ! called "asg-health:$BLUE_ASG" \
   && ! called "tgh:$BLUE_TG" \
   && ! called "ssm:/sandbox/nhp/server/asg-name" \
   && [[ "$OUT" == *"Active color: green"* ]]; then
  report_pass "green active soaks the green fleet and never touches blue or asg-name"
else
  report_fail "green active soaks green" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 2: blue active -> soak the BLUE fleet (not hardcoded to green).
# Blue's target group is healthy here because blue is the color being served.
write_live_sandbox_fixture blue
printf '%s\t3\t0\n' "$BLUE_TG" > "$FAKE_TGH"
printf '%s\t3\t3\n' "$GREEN_TG" >> "$FAKE_TGH"
_run sandbox
if [[ "$RC" -eq 0 ]] \
   && called "ssm:/sandbox/nhp/server/blue-asg-name" \
   && called "asg-health:$BLUE_ASG" \
   && ! called "asg-health:$GREEN_ASG" \
   && ! called "ssm:/sandbox/nhp/server/asg-name" \
   && [[ "$OUT" == *"Active color: blue"* ]]; then
  report_pass "blue active soaks the blue fleet via blue-asg-name, not asg-name"
else
  report_fail "blue active soaks blue" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 3: cell1 is blue/green-capable on its own /sandbox-cell1 path.
# Live today it is active-color=blue with asg-name == blue-asg-name, so it is
# only COINCIDENTALLY correct; its first switch to green must follow the color.
{
  printf '/sandbox-cell1/nhp/server/active-color\tgreen\n'
  printf '/sandbox-cell1/nhp/server/asg-name\t%s\n' "$CELL1_BLUE_ASG"
  printf '/sandbox-cell1/nhp/server/blue-asg-name\t%s\n' "$CELL1_BLUE_ASG"
  printf '/sandbox-cell1/nhp/server/green-asg-name\t%s\n' "$CELL1_GREEN_ASG"
} > "$FAKE_PARAMS"
printf '%s\t1\t1\t%s\n' "$CELL1_GREEN_ASG" "$CELL1_GREEN_TG" > "$FAKE_ASGS"
printf '%s\t1\t0\n' "$CELL1_GREEN_TG" > "$FAKE_TGH"
_run sandbox-cell1
if [[ "$RC" -eq 0 ]] \
   && called "ssm:/sandbox-cell1/nhp/server/green-asg-name" \
   && called "asg-health:$CELL1_GREEN_ASG" \
   && ! called "ssm:/sandbox-cell1/nhp/server/asg-name"; then
  report_pass "cell1 switched to green soaks the cell1 green fleet"
else
  report_fail "cell1 follows active color" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 4: absent active-color -> hard error, no fallback of any kind.
# The old code degraded a missing parameter into a blind `sleep` and exit 0.
write_live_sandbox_fixture green
grep -v 'active-color' "$FAKE_PARAMS" > "$WORK/tmp" && mv "$WORK/tmp" "$FAKE_PARAMS"
_run sandbox
if [[ "$RC" -ne 0 ]] \
   && ! called "ssm:/sandbox/nhp/server/asg-name" \
   && ! grep -q '^asg-health:' "$FAKE_CALLS" \
   && [[ "$OUT" == *"Could not resolve a known active color"* ]] \
   && [[ "$OUT" != *"time-based"* ]]; then
  report_pass "absent active-color fails closed instead of a blind time-based soak"
else
  report_fail "absent active-color fails closed" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 5-8: a color that is not exactly blue/green is rejected, never
# defaulted. Padded and cased values must not be normalized into a color.
for bad in "purple" " green " "Green" "" "blue green"; do
  write_live_sandbox_fixture green
  {
    grep -v '/active-color' "$FAKE_PARAMS"
    printf '/sandbox/nhp/server/active-color\t%s\n' "$bad"
  } > "$WORK/tmp" && mv "$WORK/tmp" "$FAKE_PARAMS"
  _run sandbox
  if [[ "$RC" -ne 0 ]] \
     && ! grep -q '^asg-health:' "$FAKE_CALLS" \
     && ! called "ssm:/sandbox/nhp/server/asg-name"; then
    report_pass "active-color '${bad}' is rejected, not defaulted to a color"
  else
    report_fail "reject active-color '${bad}'" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
  fi
done

# --- Case 9: color resolves but its per-color ASG parameter is missing ->
# hard error, and specifically NO fallback to the color-blind asg-name.
write_live_sandbox_fixture green
grep -v 'green-asg-name' "$FAKE_PARAMS" > "$WORK/tmp" && mv "$WORK/tmp" "$FAKE_PARAMS"
_run sandbox
if [[ "$RC" -ne 0 ]] \
   && ! called "ssm:/sandbox/nhp/server/asg-name" \
   && ! grep -q '^asg-health:' "$FAKE_CALLS" \
   && [[ "$OUT" == *"green-asg-name is missing or empty"* ]]; then
  report_pass "missing green-asg-name fails closed without falling back to asg-name"
else
  report_fail "missing per-color ASG fails closed" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 10: an empty per-color ASG value is rejected too (an existing but
# blank parameter must not resolve to an empty --auto-scaling-group-names).
write_live_sandbox_fixture green
{
  grep -v 'green-asg-name' "$FAKE_PARAMS"
  printf '/sandbox/nhp/server/green-asg-name\t\n'
} > "$WORK/tmp" && mv "$WORK/tmp" "$FAKE_PARAMS"
_run sandbox
if [[ "$RC" -ne 0 ]] && ! grep -q '^asg-health:' "$FAKE_CALLS"; then
  report_pass "empty green-asg-name is rejected"
else
  report_fail "empty per-color ASG rejected" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

# --- Case 11: the soak must still FAIL on a genuinely degraded ACTIVE fleet.
# Following the active color must not turn the soak into a rubber stamp.
write_live_sandbox_fixture green
printf '%s\t3\t3\t%s\n' "$BLUE_ASG" "$BLUE_TG" > "$FAKE_ASGS"
printf '%s\t3\t2\t%s\n' "$GREEN_ASG" "$GREEN_TG" >> "$FAKE_ASGS"
_run sandbox
if [[ "$RC" -ne 0 ]] && [[ "$OUT" == *"ASG has unhealthy instances (2/3)"* ]]; then
  report_pass "a degraded active fleet still fails the soak"
else
  report_fail "degraded active fleet fails" "rc=$RC out=<<<$OUT>>>"
fi

# --- Case 12: unhealthy targets in the ACTIVE color's target group still fail.
write_live_sandbox_fixture green
printf '%s\t3\t1\n' "$GREEN_TG" > "$FAKE_TGH"
_run sandbox
if [[ "$RC" -ne 0 ]] && [[ "$OUT" == *"NLB target group has 1 unhealthy targets"* ]]; then
  report_pass "unhealthy targets in the active target group still fail the soak"
else
  report_fail "active TG unhealthy fails" "rc=$RC out=<<<$OUT>>>"
fi

# --- Case 13: SKIP_SOAK short-circuits before any AWS call at all.
write_live_sandbox_fixture green
_run sandbox 1 true
if [[ "$RC" -eq 0 ]] && [[ ! -s "$FAKE_CALLS" ]] && [[ "$OUT" == *"Soak period skipped"* ]]; then
  report_pass "SKIP_SOAK exits cleanly without resolving any fleet"
else
  report_fail "SKIP_SOAK short-circuits" "rc=$RC calls=$(tr '\n' ' ' < "$FAKE_CALLS") out=<<<$OUT>>>"
fi

echo
if [[ "$fail" -gt 0 ]]; then
  printf '\033[31m%d passed, %d failed\033[0m\n' "$pass" "$fail"
  printf '%b' "$failures"
  exit 1
fi
printf '\033[32mAll %d tests passed\033[0m\n' "$pass"
