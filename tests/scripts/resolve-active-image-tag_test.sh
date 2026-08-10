#!/usr/bin/env bash
# resolve-active-image-tag_test.sh — fixture tests for
# .github/scripts/resolve-active-image-tag.sh
# ----------------------------------------------------------------------------
# The canonical active-color -> logical slot resolver is load-bearing for four callers
# (build-and-push.yml, promote-to-prod.yml, blue-green-deploy.yml,
# trigger-prod-deploy.sh) and previously had no unit coverage. This fences its
# contract: active green -> green-image-tag, active blue -> image-tag, standby
# to the opposite slot, and fail-closed on a read error, an unexpected/corrupt
# active-color, an unsupported environment, or invalid inputs.
#
# Each case puts a fake `aws` on PATH returning canned SSM values from a fixture
# file (one "<param> <value>" per line; a missing param errors + exit 255,
# mirroring real `aws ssm get-parameter` on a nonexistent name), invokes the
# REAL resolver, and asserts stdout + exit code.
#
# Usage: bash tests/scripts/resolve-active-image-tag_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/resolve-active-image-tag.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# _make_aws_shim <dir> <fixture> — fake `aws` resolving
# `ssm get-parameter --name <p>` from the fixture; missing param -> exit 255.
_make_aws_shim() {
  local dir="$1" fixture="$2"
  cat > "$dir/aws" <<EOF
#!/usr/bin/env bash
name=""; prev=""
for a in "\$@"; do
  [[ "\$prev" == "--name" ]] && name="\$a"
  prev="\$a"
done
val=\$(grep -E "^\${name} " "$fixture" 2>/dev/null | head -1 | cut -d' ' -f2-)
if [[ -z "\$val" ]]; then echo "An error occurred (ParameterNotFound) when calling GetParameter on \$name" >&2; exit 255; fi
# A real AWS CLI can write to stderr on an otherwise-successful call
# (deprecation notice, credential-source warning). Emitted here when the case
# asks for it, so the resolver's stdout/stderr split stays fenced.
[[ -n "\${AWS_SHIM_STDERR_NOISE:-}" ]] && echo "\$AWS_SHIM_STDERR_NOISE" >&2
printf '%s\n' "\$val"
EOF
  chmod +x "$dir/aws"
}

# _run <env> <comp> <slot-or-default> <fixture-body> -> sets GOT and RC.
# Pass "-" for slot-or-default to exercise the resolver's default active mode.
GOT=""; RC=0
_run() {
  local env="$1" comp="$2" slot="$3" body="$4" dir
  dir=$(mktemp -d)
  printf '%s\n' "$body" > "$dir/fixture.txt"
  _make_aws_shim "$dir" "$dir/fixture.txt"
  if [[ "$slot" == "-" ]]; then
    GOT=$(PATH="$dir:$PATH" AWS_PROFILE=test bash "$SCRIPT" "$env" "$comp" 2>/dev/null); RC=$?
  else
    GOT=$(PATH="$dir:$PATH" AWS_PROFILE=test bash "$SCRIPT" "$env" "$comp" "$slot" 2>/dev/null); RC=$?
  fi
  rm -rf "$dir"
}

# _assert_tag <name> <env> <comp> <slot-or-default> <expected-stdout> <body>
_assert_tag() {
  local name="$1" env="$2" comp="$3" slot="$4" want="$5" body="$6"
  _run "$env" "$comp" "$slot" "$body"
  if [[ "$RC" -eq 0 && "$GOT" == "$want" ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC out='$GOT' (want rc=0 out='$want')"; fi
}

# _assert_tag_noisy <name> <env> <comp> <slot-or-default> <expected-stdout> <body>
#
# As _assert_tag, but the fake AWS CLI also writes a warning to stderr on every
# *successful* read. The resolver used to capture its reads with 2>&1, which
# spliced that warning into the value: a polluted colour then failed the
# blue/green check and hard-failed the deploy over a perfectly healthy
# parameter, and a polluted tag propagated an image tag that does not exist.
# Fenced here rather than only through trigger-prod-deploy.sh's fixtures,
# because this resolver is the shared source of truth for four callers.
_assert_tag_noisy() {
  local name="$1" env="$2" comp="$3" slot="$4" want="$5" body="$6"
  export AWS_SHIM_STDERR_NOISE="urllib3 v2 only supports OpenSSL 1.1.1+, currently the ssl module is compiled with LibreSSL 2.8.3"
  _run "$env" "$comp" "$slot" "$body"
  unset AWS_SHIM_STDERR_NOISE
  if [[ "$RC" -eq 0 && "$GOT" == "$want" ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC out='$GOT' (want rc=0 out='$want')"; fi
}

# _assert_fail <name> <env> <comp> <slot-or-default> <body>
_assert_fail() {
  local name="$1" env="$2" comp="$3" slot="$4" body="$5"
  _run "$env" "$comp" "$slot" "$body"
  if [[ "$RC" -ne 0 ]]; then report_pass "$name"
  else report_fail "$name" "rc=0 out='$GOT' (want non-zero)"; fi
}

echo "Running resolve-active-image-tag tests..."

# Core: the live tag follows active-color, NOT a fixed slot. The omitted slot
# argument preserves backward compatibility with existing active-tag callers.
_assert_tag "active=green default -> green-image-tag" sandbox server - "GREENTAG" \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "active=blue explicit -> image-tag" sandbox server active "BLUETAG" \
"/sandbox/nhp/server/active-color blue
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "standby with active=green -> image-tag" sandbox server standby "BLUETAG" \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "standby with active=blue -> green-image-tag" sandbox server standby "GREENTAG" \
"/sandbox/nhp/server/active-color blue
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "ac component honours active=green" sandbox ac active "ACGREEN" \
"/sandbox/nhp/ac/active-color green
/sandbox/nhp/ac/image-tag ACBLUE
/sandbox/nhp/ac/green-image-tag ACGREEN"

# A CLI warning on a successful read must not reach the value. Both reads are
# covered: active-color (a polluted colour fails the blue/green check and takes
# the deploy down with it) and the resolved slot (a polluted tag is returned to
# the caller as a real image tag).
_assert_tag_noisy "stderr warning does not pollute the resolved tag" sandbox server - "GREENTAG" \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag_noisy "stderr warning does not pollute a blue active-color" sandbox server active "BLUETAG" \
"/sandbox/nhp/server/active-color blue
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

# Fail-closed: unexpected/corrupt active-color is rejected, never guessed.
_assert_fail "unexpected active-color rejected" sandbox server active \
"/sandbox/nhp/server/active-color magenta
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

# Fail-closed: active-color read failure (e.g. missing / transient) -> exit 1.
_assert_fail "active-color read failure -> non-zero" sandbox server active \
"/sandbox/nhp/server/image-tag BLUETAG"

# Fail-closed: slot read failure (active=green but green slot missing) -> exit 1.
_assert_fail "missing active resolved slot -> non-zero" sandbox server active \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG"

_assert_fail "missing standby resolved slot -> non-zero" sandbox server standby \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/green-image-tag GREENTAG"

# cell1 is a second infrastructure namespace on the same blue/green shape.
# Its SSM paths are /sandbox-cell1/nhp/server/* — keyed on terraform's
# `environment` ("sandbox-cell1"), not on the protocol environment (both
# sandbox cells are protocol environment "sandbox").
_assert_tag "cell1 active=blue -> image-tag" sandbox-cell1 server active "C1BLUE" \
"/sandbox-cell1/nhp/server/active-color blue
/sandbox-cell1/nhp/server/image-tag C1BLUE
/sandbox-cell1/nhp/server/green-image-tag C1GREEN"

_assert_tag "cell1 standby with active=blue -> green-image-tag" sandbox-cell1 server standby "C1GREEN" \
"/sandbox-cell1/nhp/server/active-color blue
/sandbox-cell1/nhp/server/image-tag C1BLUE
/sandbox-cell1/nhp/server/green-image-tag C1GREEN"

# cell1 must never resolve cell0's parameters: with only /sandbox/... populated,
# a cell1 lookup has to fail rather than silently return cell0's tag. This is
# the exact confusion that left cell1 with no deploy lane.
_assert_fail "cell1 does not fall back to cell0 parameters" sandbox-cell1 server active \
"/sandbox/nhp/server/active-color blue
/sandbox/nhp/server/image-tag CELL0TAG"

# cell1 is server-only — it has no /sandbox-cell1/nhp/ac/* parameters.
_assert_fail "cell1 ac component rejected" sandbox-cell1 ac active \
"/sandbox-cell1/nhp/ac/active-color blue
/sandbox-cell1/nhp/ac/image-tag C1AC"

# Input validation: only the blue/green infra namespaces are supported
# (prod is canary, read directly).
_assert_fail "non-sandbox environment rejected" prod server active \
"/prod/nhp/server/active-color blue
/prod/nhp/server/image-tag PRODTAG"

# Input validation: invalid component.
_assert_fail "invalid component rejected" sandbox database active \
"/sandbox/nhp/database/active-color blue"

_assert_fail "invalid slot rejected" sandbox server passive \
"/sandbox/nhp/server/active-color blue"

# Input validation: missing args (exits before any SSM read).
if "$SCRIPT" sandbox >/dev/null 2>&1; then
  report_fail "missing component arg rejected" "rc=0 (want non-zero)"
else
  report_pass "missing component arg rejected"
fi

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
