#!/usr/bin/env bash
# Fixture tests for .github/scripts/resolve-live-app-image-required.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/resolve-live-app-image-required.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

git -C "$tmpdir" init -q
git -C "$tmpdir" config user.email test@example.com
git -C "$tmpdir" config user.name "Test User"

mkdir -p "$tmpdir/endpoints/relay" "$tmpdir/nhp" "$tmpdir/internalauth" "$tmpdir/endpoints/internal"
printf 'old\n' > "$tmpdir/endpoints/relay/relay.go"
printf 'module old\n' > "$tmpdir/endpoints/go.mod"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m base
base=$(git -C "$tmpdir" rev-parse HEAD)

printf 'new\n' > "$tmpdir/endpoints/relay/relay.go"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m relay-change
head=$(git -C "$tmpdir" rev-parse HEAD)

stubbin="$tmpdir/bin"
mkdir -p "$stubbin"

write_aws_stub() {
  local relay_mode="$1"
  local fail_read="${2:-}"
  cat > "$stubbin/aws" <<EOF
#!/usr/bin/env bash
set -euo pipefail
name=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --name)
      name="\$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
case "\$name" in
  /sandbox/nhp/server/active-color)
    if [[ '$fail_read' == 'server-active-color' ]]; then
      echo 'ThrottlingException: server active-color read failed' >&2
      exit 255
    fi
    printf 'green'
    ;;
  /sandbox/nhp/server/green-image-tag) printf '$base' ;;
  /sandbox/nhp/ac/active-color) printf 'blue' ;;
  /sandbox/nhp/ac/image-tag) printf '$base' ;;
  /sandbox/nhp/relay/image-tag)
    case '$relay_mode' in
      present) printf '$base' ;;
      absent) echo 'An error occurred (ParameterNotFound) when calling GetParameter for /sandbox/nhp/relay/image-tag' >&2; exit 254 ;;
      error) echo 'ThrottlingException: nope' >&2; exit 255 ;;
      mentions) echo 'An error occurred (AccessDeniedException) when calling GetParameter: message mentions ParameterNotFound but is not that error code' >&2; exit 255 ;;
    esac
    ;;
  *) echo "unexpected parameter: \$name" >&2; exit 99 ;;
esac
EOF
  chmod +x "$stubbin/aws"
}

run_case() {
  local name="$1" relay_mode="$2" want_rc="$3" want="$4"
  local fail_read="${5:-}"
  local out rc out_file github_output
  write_aws_stub "$relay_mode" "$fail_read"
  out_file=$(mktemp)
  out=$(cd "$tmpdir" && PATH="$stubbin:$PATH" GITHUB_OUTPUT="$out_file" "$SCRIPT" sandbox "$head" 2>&1)
  rc=$?
  github_output=$(cat "$out_file")
  if [[ "$want_rc" == "0" ]]; then
    if [[ "$rc" -eq 0 && "$out" == *"app_image_required=$want"* && "$github_output" == *"server_tag=$base"* ]]; then
      report_pass "$name"
    else
      report_fail "$name" "rc=$rc output='$out' github_output='$github_output' want app_image_required=$want"
    fi
  elif [[ "$rc" -ne 0 && "$out" == *"$want"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want non-zero containing '$want'"
  fi
  rm -f "$out_file"
}

echo "Running resolve-live-app-image-required tests..."

run_case "relay present participates in live drift detection" present 0 true
run_case "relay ParameterNotFound is ignored as dark relay" absent 0 true
run_case "non-ParameterNotFound relay SSM error fails loud" error 1 ThrottlingException
run_case "relay SSM error merely mentioning ParameterNotFound fails loud" mentions 1 AccessDeniedException
run_case "server/AC active tag read failure fails loud" present 1 "server active-color read failed" server-active-color

write_aws_stub present
out=$(cd "$tmpdir" && PATH="$stubbin:$PATH" "$SCRIPT" prod "$head" 2>&1)
rc=$?
if [[ "$rc" -ne 0 && "$out" == *"only supports sandbox"* ]]; then
  report_pass "non-sandbox environment rejected"
else
  report_fail "non-sandbox environment rejected" "rc=$rc output='$out'"
fi

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
