#!/usr/bin/env bash
# Fixture tests for .github/scripts/verify-asg-instances-healthy.sh.
#
# Usage: bash tests/scripts/verify-asg-instances-healthy_test.sh

set -uo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: verify-asg-instances-healthy tests require jq for JSON fixture parsing" >&2
  exit 2
fi

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/verify-asg-instances-healthy.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0
failures=""
LAST_OUT=""
LAST_RC=0

report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  failures+="  FAIL $1: $2\n"
  printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"
}

make_fake_commands() {
  local dir="$1"
  local fixture_mode="${2:-}"
  mkdir -p "$dir"

  cat > "$dir/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_SCENARIO:-failed-static}"
state_dir="${FAKE_STATE_DIR:?}"

next_count() {
  local name="$1" file count
  file="$state_dir/$name-count"
  count=0
  [[ -f "$file" ]] && count=$(cat "$file")
  count=$((count + 1))
  printf '%s' "$count" > "$file"
  printf '%s\n' "$count"
}

case "$1 $2" in
  "autoscaling describe-auto-scaling-groups")
    case "$scenario" in
      success) printf 'i-ok\n' ;;
      empty) printf '\n' ;;
      *) printf 'i-fail\n' ;;
    esac
    ;;
  "ssm send-command")
    case "$scenario" in
      send-fails) exit 255 ;;
      *) printf 'cmd-%s\n' "$(next_count send)" ;;
    esac
    ;;
  "ssm get-command-invocation")
    query=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "--query" ]]; then
        shift
        query="${1:-}"
        break
      fi
      shift
    done
    case "$query" in
      Status)
        case "$scenario" in
          success) printf 'Success\n' ;;
          pending) printf 'Pending\n' ;;
          *) printf 'Failed\n' ;;
        esac
        ;;
      *ResponseCode*StandardOutputContent*StandardErrorContent*)
        case "$scenario" in
          failed-changing-output)
            detail_count=$(next_count detail)
            if [[ "$detail_count" -eq 1 ]]; then
              printf '{"ResponseCode":7,"StandardOutputContent":"probe stdout first\\n","StandardErrorContent":"curl: (7) first failure\\n"}\n'
            else
              printf '{"ResponseCode":8,"StandardOutputContent":"probe stdout second\\n","StandardErrorContent":"curl: (7) second failure\\n"}\n'
            fi
            ;;
          *)
            printf '{"ResponseCode":7,"StandardOutputContent":"probe stdout line\\n","StandardErrorContent":"curl: (7) failed to connect\\n"}\n'
            ;;
        esac
        ;;
      *) printf 'unexpected query: %s\n' "$query" >&2; exit 2 ;;
    esac
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "$*" >&2
    exit 2
    ;;
esac
AWS
  chmod +x "$dir/aws"

  cat > "$dir/date" <<'DATE'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${FAKE_STATE_DIR:?}"
count_file="$STATE_DIR/date-count"
count=0
[[ -f "$count_file" ]] && count=$(cat "$count_file")
count=$((count + 1))
printf '%s' "$count" > "$count_file"

case "$count" in
  1|2|3|4|5) printf '100\n' ;;
  *) printf '200\n' ;;
esac
DATE
  chmod +x "$dir/date"

  cat > "$dir/sleep" <<'SLEEP'
#!/usr/bin/env bash
exit 0
SLEEP
  chmod +x "$dir/sleep"

  if [[ "$fixture_mode" == "jq-fails" ]]; then
    cat > "$dir/jq" <<'JQ'
#!/usr/bin/env bash
exit 127
JQ
    chmod +x "$dir/jq"
  elif [[ "$fixture_mode" == "cut-fails" ]]; then
    cat > "$dir/cut" <<'CUT'
#!/usr/bin/env bash
exit 1
CUT
    chmod +x "$dir/cut"
  elif [[ "$fixture_mode" == "jq-absent" ]]; then
    local tool resolved
    for tool in awk bash cat cut grep sed sort tr; do
      resolved=$(command -v "$tool") || {
        echo "ERROR: jq-absent fixture requires $tool in the parent PATH" >&2
        exit 2
      }
      ln -s "$resolved" "$dir/$tool"
    done
    for tool in sha256sum shasum cksum; do
      if resolved=$(command -v "$tool"); then
        ln -s "$resolved" "$dir/$tool"
      fi
    done
  fi
}

run_case() {
  local name="$1"
  local scenario="$2"
  local fixture_mode=""
  shift
  shift
  case "${1:-}" in
  cut-fails|jq-*)
    fixture_mode="$1"
    shift
    ;;
  esac
  local case_dir="$TMP_ROOT/$name"
  local bin_dir="$case_dir/bin"
  local path_value="$bin_dir:$PATH"
  mkdir -p "$case_dir"
  make_fake_commands "$bin_dir" "$fixture_mode"
  if [[ "$fixture_mode" == "jq-absent" ]]; then
    path_value="$bin_dir"
  fi

  LAST_OUT="$case_dir/out"
  PATH="$path_value" FAKE_SCENARIO="$scenario" FAKE_STATE_DIR="$case_dir" "$@" >"$LAST_OUT" 2>&1
  LAST_RC=$?
}

assert_rc() {
  local label="$1" want="$2"
  if [[ "$LAST_RC" -eq "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "got exit $LAST_RC, want $want; output: $(cat "$LAST_OUT")"
  fi
}

assert_contains() {
  local label="$1" needle="$2"
  if grep -Fq -- "$needle" "$LAST_OUT"; then
    report_pass "$label"
  else
    report_fail "$label" "missing '$needle'; output: $(cat "$LAST_OUT")"
  fi
}

assert_count() {
  local label="$1" needle="$2" want="$3"
  local got
  got=$(grep -F -c -- "$needle" "$LAST_OUT")
  if [[ "$got" == "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "got count $got, want $want for '$needle'; output: $(cat "$LAST_OUT")"
  fi
}

echo "Running verify-asg-instances-healthy tests..."

run_case success success bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "successful health probe exits zero" 0
assert_contains "successful health probe logs ok instance" "i-ok: ok"
assert_contains "successful health probe logs completion" "All 1 instance(s) passed health check"
assert_count "successful health probe skips failure details" "health command stdout" 0

run_case empty-asg empty bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "ASG with no InService instances fails closed" 1
assert_contains "empty ASG failure names the missing runtime" "No InService instances found"

run_case failed-health-probe failed-static bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "failed health probe exits non-zero" 1
assert_contains "failed probe logs status and response code" "[AC-Standby] i-fail health command status=Failed response_code=7"
assert_contains "failed probe logs stdout" "probe stdout line"
assert_contains "failed probe logs stderr" "curl: (7) failed to connect"
assert_contains "outer loop still logs unhealthy instance" "i-fail: unhealthy (exit non-zero)"
assert_count "failed probe keeps per-iteration status breadcrumb" "health command status=Failed response_code=7" 2
assert_count "failed probe dedupes stdout details" "health command stdout" 1
assert_count "failed probe dedupes stderr details" "health command stderr" 1

run_case diagnostic-cut-fails failed-static cut-fails bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "diagnostic cut failure exits non-zero" 1
assert_contains "diagnostic cut failure logs status" "[AC-Standby] i-fail health command status=Failed response_code=7"
assert_contains "diagnostic cut failure still marks unhealthy" "i-fail: unhealthy (exit non-zero)"

run_case changed-health-probe failed-changing-output bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "changed failed health probe exits non-zero" 1
assert_contains "changed failed probe logs first stdout" "probe stdout first"
assert_contains "changed failed probe logs second stdout" "probe stdout second"
assert_contains "changed failed probe logs first stderr" "curl: (7) first failure"
assert_contains "changed failed probe logs second stderr" "curl: (7) second failure"
assert_count "changed failed probe re-dumps changed stdout details" "health command stdout" 2
assert_count "changed failed probe re-dumps changed stderr details" "health command stderr" 2

run_case pending-ssm pending bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "pending SSM probe exits non-zero" 1
assert_count "pending SSM probe retries unreachable instance" "SSM unreachable, retrying" 2
assert_count "pending SSM probe skips failure details" "health command stdout" 0

run_case send-command-fails send-fails bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "send-command failure exits non-zero" 1
assert_count "send-command failure retries unreachable instance" "SSM unreachable, retrying" 2
assert_count "send-command failure skips failure details" "health command stdout" 0

run_case jq-failed-fallback failed-static jq-fails bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "jq failed fallback exits non-zero" 1
assert_contains "jq failed fallback logs unknown response code" "health command status=Failed response_code=unknown"
assert_contains "jq failed fallback dumps raw invocation json" '"StandardOutputContent":"probe stdout line\n"'
assert_count "jq failed fallback dedupes raw json details" "health command stdout" 1

run_case jq-absent-fallback failed-static jq-absent bash "$SCRIPT" layerv-nhp-sandbox-ac AC-Standby 1 'curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
assert_rc "jq absent fallback exits non-zero" 1
assert_contains "jq absent fallback logs unknown response code" "health command status=Failed response_code=unknown"
assert_contains "jq absent fallback dumps raw invocation json" '"StandardOutputContent":"probe stdout line\n"'
assert_count "jq absent fallback dedupes raw json details" "health command stdout" 1

if [[ "$fail" -ne 0 ]]; then
  printf '\n%b' "$failures"
  exit 1
fi

printf 'verify-asg-instances-healthy tests passed (%d assertions).\n' "$pass"
