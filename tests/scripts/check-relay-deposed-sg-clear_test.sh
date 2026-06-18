#!/usr/bin/env bash
# Fixture tests for .github/scripts/check-relay-deposed-sg-clear.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRIPT="$REPO_ROOT/.github/scripts/check-relay-deposed-sg-clear.sh"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

PASS=0
FAIL=0

report_pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

report_fail() {
  echo "FAIL: $1 - $2" >&2
  FAIL=$((FAIL + 1))
}

make_stubs() {
  local dir="$1"
  mkdir -p "$dir/bin"
  cat > "$dir/bin/aws" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$AWS_LOG"

if [[ "${AWS_FAIL:-0}" == "1" ]]; then
  echo "An error occurred (ThrottlingException) when calling the DescribeNetworkInterfaces operation: throttled" >&2
  exit 42
fi

if [[ -n "${AWS_FAIL_SEQUENCE:-}" ]]; then
  fail_count_file="${AWS_LOG}.fail_count"
  fail_index=0
  [[ -f "$fail_count_file" ]] && fail_index=$(cat "$fail_count_file")
  IFS=',' read -r -a fail_sequence <<< "$AWS_FAIL_SEQUENCE"
  if (( fail_index >= ${#fail_sequence[@]} )); then
    fail_value="${fail_sequence[$((${#fail_sequence[@]} - 1))]}"
  else
    fail_value="${fail_sequence[$fail_index]}"
  fi
  printf '%s' "$((fail_index + 1))" > "$fail_count_file"
  if [[ "$fail_value" == "fail" || "$fail_value" == "1" ]]; then
    echo "An error occurred (ThrottlingException) when calling the DescribeNetworkInterfaces operation: throttled" >&2
    exit 42
  fi
fi

if [[ -n "${AWS_ENI_SEQUENCE:-}" ]]; then
  count_file="${AWS_LOG}.count"
  index=0
  [[ -f "$count_file" ]] && index=$(cat "$count_file")
  IFS=',' read -r -a eni_sequence <<< "$AWS_ENI_SEQUENCE"
  if (( index >= ${#eni_sequence[@]} )); then
    printf '%s\n' "${eni_sequence[$((${#eni_sequence[@]} - 1))]}"
  else
    printf '%s\n' "${eni_sequence[$index]}"
  fi
  printf '%s' "$((index + 1))" > "$count_file"
  exit 0
fi

sg_id=""
for arg in "$@"; do
  case "$arg" in
    Name=group-id,Values=*) sg_id="${arg#Name=group-id,Values=}" ;;
  esac
done

if [[ -n "${AWS_ATTACHED_SG:-}" && "$sg_id" == "$AWS_ATTACHED_SG" ]]; then
  printf '%s\n' "${AWS_ATTACHED_ENIS:-eni-attached}"
  exit 0
fi

printf '%s\n' "${AWS_DEFAULT_ENIS:-None}"
STUB
  chmod +x "$dir/bin/aws"
}

write_no_deposed_plan() {
  local path="$1"
  cat > "$path" <<'EOF'
Terraform will perform the following actions:

  # module.nhp.module.server.aws_security_group.server will be destroyed
  - resource "aws_security_group" "server" {
      - id = "sg-01111111111111111" -> null
    }
EOF
}

write_deposed_plan() {
  local path="$1"
  local sg_id="$2"
  cat > "$path" <<EOF
Terraform will perform the following actions:

  # module.nhp.module.relay[0].aws_security_group.relay (deposed object eb253654) will be destroyed
  - resource "aws_security_group" "relay" {
      - description = "old relay node security group" -> null
      - id          = "$sg_id" -> null
    }

  # module.nhp.module.relay[0].aws_security_group.relay will be updated in-place
  ~ resource "aws_security_group" "relay" {
      id = "sg-02222222222222222"
    }
EOF
}

write_two_deposed_plan() {
  local path="$1"
  cat > "$path" <<'EOF'
Terraform will perform the following actions:

  # module.nhp.module.relay[0].aws_security_group.relay (deposed object oldaaaaa) will be destroyed
  - resource "aws_security_group" "relay" {
      - id = "sg-0aaaaaaaaaaaaaaaa" -> null
    }

  # module.nhp.module.relay[0].aws_security_group.relay (deposed object oldbbbbb) will be destroyed
  - resource "aws_security_group" "relay" {
      - id = "sg-0bbbbbbbbbbbbbbbb" -> null
    }
EOF
}

write_missing_id_plan() {
  local path="$1"
  cat > "$path" <<'EOF'
Terraform will perform the following actions:

  # module.nhp.module.relay[0].aws_security_group.relay (deposed object eb253654) will be destroyed
  - resource "aws_security_group" "relay" {
      - description = "old relay node security group" -> null
    }
EOF
}

write_custom_addr_deposed_plan() {
  local path="$1"
  local sg_id="$2"
  cat > "$path" <<EOF
Terraform will perform the following actions:

  # module.nhp.module.relay_blue.aws_security_group.relay (deposed object eb253654) will be destroyed
  - resource "aws_security_group" "relay" {
      - id = "$sg_id" -> null
    }
EOF
}

write_json_no_deposed_plan() {
  local path="$1"
  cat > "$path" <<'EOF'
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "module.nhp.module.server.aws_security_group.server",
      "type": "aws_security_group",
      "change": {
        "actions": ["delete"],
        "before": {
          "id": "sg-01111111111111111"
        }
      }
    }
  ]
}
EOF
}

write_json_deposed_plan() {
  local path="$1"
  local sg_id="$2"
  cat > "$path" <<EOF
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "module.nhp.module.relay[0].aws_security_group.relay",
      "type": "aws_security_group",
      "deposed": "eb253654",
      "change": {
        "actions": ["delete"],
        "before": {
          "id": "$sg_id",
          "description": "old relay node security group"
        }
      }
    },
    {
      "address": "module.nhp.module.relay[0].aws_security_group.relay",
      "type": "aws_security_group",
      "change": {
        "actions": ["update"],
        "before": {
          "id": "sg-02222222222222222"
        }
      }
    }
  ]
}
EOF
}

write_json_missing_id_plan() {
  local path="$1"
  cat > "$path" <<'EOF'
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "module.nhp.module.relay[0].aws_security_group.relay",
      "type": "aws_security_group",
      "deposed": "eb253654",
      "change": {
        "actions": ["delete"],
        "before": {
          "description": "old relay node security group"
        }
      }
    }
  ]
}
EOF
}

write_json_custom_addr_deposed_plan() {
  local path="$1"
  local sg_id="$2"
  cat > "$path" <<EOF
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "module.nhp.module.relay_blue.aws_security_group.relay",
      "type": "aws_security_group",
      "deposed": "eb253654",
      "change": {
        "actions": ["delete"],
        "before": {
          "id": "$sg_id"
        }
      }
    }
  ]
}
EOF
}

run_checker() {
  local name="$1" mode="$2" plan_writer="$3" sg_arg="${4:-}" attached_sg="${5:-}" attached_enis="${6:-}" aws_fail="${7:-0}"
  local eni_sequence="${8:-}" check_max="${9:-1}" check_interval="${10:-0}" aws_fail_sequence="${11:-}"
  local dir="$TMP_ROOT/$name"
  local args=()
  mkdir -p "$dir"
  make_stubs "$dir"
  if [[ -n "$sg_arg" ]]; then
    "$plan_writer" "$dir/plan-show.txt" "$sg_arg"
  else
    "$plan_writer" "$dir/plan-show.txt"
  fi
  if [[ -n "$mode" ]]; then
    args+=("$mode")
  fi
  args+=("$dir/plan-show.txt")

  AWS_LOG="$dir/aws.log" \
  AWS_FAIL="$aws_fail" \
  AWS_ATTACHED_SG="$attached_sg" \
  AWS_ATTACHED_ENIS="$attached_enis" \
  AWS_ENI_SEQUENCE="$eni_sequence" \
  AWS_FAIL_SEQUENCE="$aws_fail_sequence" \
  AWS_REGION="us-east-2" \
  RELAY_DEPOSED_SG_CHECK_MAX_ITERATIONS="$check_max" \
  RELAY_DEPOSED_SG_CHECK_INTERVAL_SECS="$check_interval" \
  RELAY_DEPOSED_SG_RESOURCE_ADDR="${CHECK_RESOURCE_ADDR:-}" \
  CHECK_RELAY_DEPOSED_SG_AWS_BIN="$dir/bin/aws" \
    "$SCRIPT" "${args[@]}" > "$dir/out.log" 2> "$dir/err.log"
}

assert_success() {
  local name="$1" mode="$2" plan_writer="$3" sg_arg="${4:-}" attached_sg="${5:-}" attached_enis="${6:-}" aws_fail="${7:-0}"
  local eni_sequence="${8:-}" check_max="${9:-1}" check_interval="${10:-0}" aws_fail_sequence="${11:-}"
  if run_checker "$name" "$mode" "$plan_writer" "$sg_arg" "$attached_sg" "$attached_enis" "$aws_fail" "$eni_sequence" "$check_max" "$check_interval" "$aws_fail_sequence"; then
    report_pass "$name exits 0"
  else
    report_fail "$name exits 0" "script failed"
  fi
}

assert_failure() {
  local name="$1" mode="$2" plan_writer="$3" sg_arg="${4:-}" attached_sg="${5:-}" attached_enis="${6:-}" aws_fail="${7:-0}"
  local eni_sequence="${8:-}" check_max="${9:-1}" check_interval="${10:-0}" aws_fail_sequence="${11:-}"
  if run_checker "$name" "$mode" "$plan_writer" "$sg_arg" "$attached_sg" "$attached_enis" "$aws_fail" "$eni_sequence" "$check_max" "$check_interval" "$aws_fail_sequence"; then
    report_fail "$name exits nonzero" "script unexpectedly succeeded"
  else
    report_pass "$name exits nonzero"
  fi
}

assert_file_contains() {
  local name="$1" path="$2" needle="$3"
  if [[ ! -f "$path" ]]; then
    report_fail "$name" "missing file $path"
    return
  fi
  if grep -Fq "$needle" "$path"; then
    report_pass "$name"
  else
    report_fail "$name" "expected '$needle' in $path; got: $(cat "$path")"
  fi
}

assert_file_absent() {
  local name="$1" path="$2"
  if [[ -e "$path" ]]; then
    report_fail "$name" "unexpected file $path with: $(cat "$path")"
  else
    report_pass "$name"
  fi
}

RELAY_SG="sg-0f9032cf4cc6eee7a"

assert_success "no-deposed-check" "" write_no_deposed_plan
assert_file_absent "no deposed check does not call AWS" "$TMP_ROOT/no-deposed-check/aws.log"

assert_failure "no-deposed-detect-only" "--detect-only" write_no_deposed_plan
assert_file_absent "detect-only absent does not call AWS" "$TMP_ROOT/no-deposed-detect-only/aws.log"

assert_success "deposed-detect-only" "--detect-only" write_deposed_plan "$RELAY_SG"
assert_file_absent "detect-only present does not call AWS" "$TMP_ROOT/deposed-detect-only/aws.log"

CHECK_RESOURCE_ADDR="module.nhp.module.relay_blue.aws_security_group.relay" \
  assert_success "custom-resource-address" "--detect-only" write_custom_addr_deposed_plan "$RELAY_SG"

assert_failure "json-no-deposed-detect-only" "--detect-only" write_json_no_deposed_plan
assert_file_absent "json detect-only absent does not call AWS" "$TMP_ROOT/json-no-deposed-detect-only/aws.log"

assert_success "json-deposed-detect-only" "--detect-only" write_json_deposed_plan "$RELAY_SG"
assert_file_absent "json detect-only present does not call AWS" "$TMP_ROOT/json-deposed-detect-only/aws.log"

CHECK_RESOURCE_ADDR="module.nhp.module.relay_blue.aws_security_group.relay" \
  assert_success "json-custom-resource-address" "--detect-only" write_json_custom_addr_deposed_plan "$RELAY_SG"

assert_success "json-deposed-attached-needs-recovery" "--needs-recovery" write_json_deposed_plan "$RELAY_SG" "$RELAY_SG" "eni-json"
assert_file_contains "json needs-recovery attached path reports refresh required" "$TMP_ROOT/json-deposed-attached-needs-recovery/err.log" "recovery refresh is required"

assert_failure "json-deposed-missing-id" "" write_json_missing_id_plan
assert_file_contains "json missing id reports parser drift" "$TMP_ROOT/json-deposed-missing-id/err.log" "could not extract its security group id"
assert_file_absent "json missing id does not call AWS" "$TMP_ROOT/json-deposed-missing-id/aws.log"

assert_failure "deposed-clear-needs-no-recovery" "--needs-recovery" write_deposed_plan "$RELAY_SG"
assert_file_contains "needs-recovery clear path inspects deposed SG" "$TMP_ROOT/deposed-clear-needs-no-recovery/aws.log" "Name=group-id,Values=$RELAY_SG"
assert_file_contains "needs-recovery clear path explains skip" "$TMP_ROOT/deposed-clear-needs-no-recovery/err.log" "::notice::Deposed relay node security group cleanup is already ENI-clear"

assert_success "deposed-attached-needs-recovery" "--needs-recovery" write_deposed_plan "$RELAY_SG" "$RELAY_SG" "eni-aaa"
assert_file_contains "needs-recovery attached path reports refresh required" "$TMP_ROOT/deposed-attached-needs-recovery/err.log" "recovery refresh is required"

assert_success "deposed-clear" "" write_deposed_plan "$RELAY_SG"
assert_file_contains "clear check inspects deposed SG" "$TMP_ROOT/deposed-clear/aws.log" "Name=group-id,Values=$RELAY_SG"

assert_success "deposed-eventual-clear" "" write_deposed_plan "$RELAY_SG" "" "" 0 "eni-stale,None" 3 0
assert_file_contains "eventual clear retries stale ENI" "$TMP_ROOT/deposed-eventual-clear/err.log" "retrying attachment check"

assert_failure "deposed-attached-enis" "" write_deposed_plan "$RELAY_SG" "$RELAY_SG" "eni-aaa eni-bbb"
assert_file_contains "attached ENIs fail closed" "$TMP_ROOT/deposed-attached-enis/err.log" "did not clear all deposed SG ENI attachments"

assert_failure "deposed-missing-id" "" write_missing_id_plan
assert_file_contains "missing id reports parser drift" "$TMP_ROOT/deposed-missing-id/err.log" "could not extract its security group id"
assert_file_absent "missing id does not call AWS" "$TMP_ROOT/deposed-missing-id/aws.log"

assert_failure "aws-describe-failure" "" write_deposed_plan "$RELAY_SG" "" "" 1
assert_file_contains "AWS failure reports inspect error" "$TMP_ROOT/aws-describe-failure/err.log" "Failed to inspect ENI attachments"

assert_failure "needs-recovery-retries-aws-failure-then-clear" "--needs-recovery" write_deposed_plan "$RELAY_SG" "" "" 0 "None" 3 0 "fail,pass"
assert_file_contains "needs-recovery retries AWS inspection failure" "$TMP_ROOT/needs-recovery-retries-aws-failure-then-clear/err.log" "retrying attachment check"
assert_file_contains "needs-recovery clear after retry explains skip" "$TMP_ROOT/needs-recovery-retries-aws-failure-then-clear/err.log" "::notice::Deposed relay node security group cleanup is already ENI-clear"

assert_failure "multiple-deposed-one-attached" "" write_two_deposed_plan "" "sg-0bbbbbbbbbbbbbbbb" "eni-bbb"
assert_file_contains "multiple deposed checks first SG" "$TMP_ROOT/multiple-deposed-one-attached/aws.log" "Name=group-id,Values=sg-0aaaaaaaaaaaaaaaa"
assert_file_contains "multiple deposed checks second SG" "$TMP_ROOT/multiple-deposed-one-attached/aws.log" "Name=group-id,Values=sg-0bbbbbbbbbbbbbbbb"
assert_file_contains "multiple deposed attached SG fails" "$TMP_ROOT/multiple-deposed-one-attached/err.log" "sg-0bbbbbbbbbbbbbbbb"

if [[ "$FAIL" -gt 0 ]]; then
  echo "$FAIL failure(s), $PASS pass(es)" >&2
  exit 1
fi

echo "$PASS pass(es)"
