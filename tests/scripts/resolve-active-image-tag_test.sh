#!/usr/bin/env bash
# resolve-active-image-tag_test.sh — fixture tests for
# .github/scripts/resolve-active-image-tag.sh
# ----------------------------------------------------------------------------
# The canonical active-color → slot resolver is load-bearing for four callers
# (build-and-push.yml, promote-to-prod.yml, blue-green-deploy.yml,
# trigger-prod-deploy.sh) and previously had no unit coverage. This fences its
# contract: green → green-image-tag, blue → image-tag, and fail-closed on a
# read error, an unexpected/corrupt active-color, an unsupported environment,
# or an invalid component.
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
printf '%s\n' "\$val"
EOF
  chmod +x "$dir/aws"
}

# _run <env> <comp> <fixture-body> -> sets GOT (stdout) and RC (exit code)
GOT=""; RC=0
_run() {
  local env="$1" comp="$2" body="$3" dir
  dir=$(mktemp -d)
  printf '%s\n' "$body" > "$dir/fixture.txt"
  _make_aws_shim "$dir" "$dir/fixture.txt"
  GOT=$(PATH="$dir:$PATH" AWS_PROFILE=test bash "$SCRIPT" "$env" "$comp" 2>/dev/null); RC=$?
  rm -rf "$dir"
}

# _assert_tag <name> <env> <comp> <expected-stdout> <body>
_assert_tag() {
  local name="$1" env="$2" comp="$3" want="$4" body="$5"
  _run "$env" "$comp" "$body"
  if [[ "$RC" -eq 0 && "$GOT" == "$want" ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC out='$GOT' (want rc=0 out='$want')"; fi
}

# _assert_fail <name> <env> <comp> <body>
_assert_fail() {
  local name="$1" env="$2" comp="$3" body="$4"
  _run "$env" "$comp" "$body"
  if [[ "$RC" -ne 0 ]]; then report_pass "$name"
  else report_fail "$name" "rc=0 out='$GOT' (want non-zero)"; fi
}

echo "Running resolve-active-image-tag tests..."

# Core: the live tag follows active-color, NOT a fixed slot.
_assert_tag "active=green -> green-image-tag" sandbox server "GREENTAG" \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "active=blue -> image-tag" sandbox server "BLUETAG" \
"/sandbox/nhp/server/active-color blue
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

_assert_tag "ac component honours active=green" sandbox ac "ACGREEN" \
"/sandbox/nhp/ac/active-color green
/sandbox/nhp/ac/image-tag ACBLUE
/sandbox/nhp/ac/green-image-tag ACGREEN"

# Fail-closed: unexpected/corrupt active-color is rejected, never guessed.
_assert_fail "unexpected active-color rejected" sandbox server \
"/sandbox/nhp/server/active-color magenta
/sandbox/nhp/server/image-tag BLUETAG
/sandbox/nhp/server/green-image-tag GREENTAG"

# Fail-closed: active-color read failure (e.g. missing / transient) -> exit 1.
_assert_fail "active-color read failure -> non-zero" sandbox server \
"/sandbox/nhp/server/image-tag BLUETAG"

# Fail-closed: slot read failure (active=green but green slot missing) -> exit 1.
_assert_fail "missing resolved slot -> non-zero" sandbox server \
"/sandbox/nhp/server/active-color green
/sandbox/nhp/server/image-tag BLUETAG"

# Input validation: only sandbox is supported (prod is canary, read directly).
_assert_fail "non-sandbox environment rejected" prod server \
"/prod/nhp/server/active-color blue
/prod/nhp/server/image-tag PRODTAG"

# Input validation: invalid component.
_assert_fail "invalid component rejected" sandbox database \
"/sandbox/nhp/database/active-color blue"

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
