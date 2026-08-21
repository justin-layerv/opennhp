#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
UNDER_TEST="${ROOT}/.github/scripts/verify-authority-cell-alias-convergence.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

PASS=0
FAIL=0

report_pass() {
  PASS=$((PASS + 1))
  echo "PASS: $1"
}

report_fail() {
  FAIL=$((FAIL + 1))
  echo "FAIL: $1" >&2
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" >&2
  fi
}

write_config() {
  local path="$1"
  local cell="$2"
  local color="$3"
  cat >"$path" <<EOF
NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-iro-${cell}:${color}
NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ar-${cell}:${color}
NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-cr-${cell}:${color}
NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ccr-${cell}:${color}
NHP_CONNECTOR_RESOURCE_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-creso-${cell}:${color}
EOF
}

make_case() {
  local name="$1"
  local case_dir="${TEST_ROOT}/${name}"
  mkdir -p "${case_dir}/bin" "${case_dir}/fixtures"
  write_config "${case_dir}/fixtures/cell0" cell0 "${POINTER_COLOR:-blue}"
  write_config "${case_dir}/fixtures/cell1" cell1 "${POINTER_COLOR:-blue}"

  cat >"${case_dir}/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "ssm get-parameter" ]]; then
  name=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--name" ]]; then
      name="$2"
      break
    fi
    shift
  done
  case "$name" in
    /sandbox/nhp/control/authority/active-color)
      pointer_reads=0
      if [[ -f "$POINTER_READ_COUNT" ]]; then
        pointer_reads=$(<"$POINTER_READ_COUNT")
      fi
      printf '%s\n' "$((pointer_reads + 1))" >"$POINTER_READ_COUNT"
      if [[ "$pointer_reads" -gt 0 && -n "${FINAL_POINTER_COLOR:-}" ]]; then
        printf '%s\n' "$FINAL_POINTER_COLOR"
      else
        printf '%s\n' "${POINTER_COLOR:-blue}"
      fi
      ;;
    /sandbox/nhp/server/active-color) printf '%s\n' "${CELL0_SERVER_COLOR:-green}" ;;
    /sandbox-cell1/nhp/server/active-color) printf '%s\n' "${CELL1_SERVER_COLOR:-blue}" ;;
    /sandbox/nhp/server/green-asg-name) printf '%s\n' 'cell0-green-asg' ;;
    /sandbox/nhp/server/blue-asg-name) printf '%s\n' 'cell0-blue-asg' ;;
    /sandbox-cell1/nhp/server/green-asg-name) printf '%s\n' 'cell1-green-asg' ;;
    /sandbox-cell1/nhp/server/blue-asg-name) printf '%s\n' 'cell1-blue-asg' ;;
    *) echo "unexpected SSM parameter: $name" >&2; exit 1 ;;
  esac
  exit 0
fi
if [[ "$1 $2" == "s3 cp" ]]; then
  source_uri="$3"
  destination="$4"
  case "$source_uri" in
    s3://layerv-nhp-sandbox-plugins/*) cp "${FIXTURE_DIR}/cell0" "$destination" ;;
    s3://layerv-nhp-sandbox-cell1-plugins/*) cp "${FIXTURE_DIR}/cell1" "$destination" ;;
    *) echo "unexpected S3 URI: $source_uri" >&2; exit 1 ;;
  esac
  exit 0
fi
echo "unexpected aws call: $*" >&2
exit 1
EOF
  chmod +x "${case_dir}/bin/aws"

  cat >"${case_dir}/verify-asg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$VERIFY_LOG"
if [[ "${FAIL_ASG:-}" == "$1" ]]; then
  exit 1
fi
EOF
  chmod +x "${case_dir}/verify-asg"
  printf '%s' "$case_dir"
}

run_case() {
  local case_dir="$1"
  shift
  PATH="${case_dir}/bin:${PATH}" \
    FIXTURE_DIR="${case_dir}/fixtures" \
    VERIFY_LOG="${case_dir}/verify.log" \
    POINTER_READ_COUNT="${case_dir}/pointer-reads" \
    VERIFY_ASG_INSTANCES_HEALTHY="${case_dir}/verify-asg" \
    "$@" "$UNDER_TEST" sandbox 767397897469 us-east-2
}

case_dir=$(make_case success)
if output=$(run_case "$case_dir" env 2>&1); then
  if [[ $(wc -l <"${case_dir}/verify.log") -eq 2 ]] \
    && [[ $(<"${case_dir}/pointer-reads") -eq 2 ]] \
    && grep -Fq $'cell0-green-asg\tAuthorityAlias-cell0\t4\t' "${case_dir}/verify.log" \
    && grep -Fq $'cell1-blue-asg\tAuthorityAlias-cell1\t4\t' "${case_dir}/verify.log" \
    && grep -Fq "docker exec nhp-server env" "${case_dir}/verify.log" \
    && grep -Fq "grep -Ec '^NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN='" "${case_dir}/verify.log" \
    && grep -Fq "ca-iro-cell0:blue" "${case_dir}/verify.log" \
    && grep -Fq "ca-ccr-cell1:blue" "${case_dir}/verify.log" \
    && grep -Fq "ca-creso-cell1:blue" "${case_dir}/verify.log" \
    && grep -Fq "pointer=blue, cells=2" <<<"$output"; then
    report_pass "selected aliases are proved in both bootstrap and active runtimes"
  else
    report_fail "success case emitted the full exact contract" "$output"
  fi
else
  report_fail "success case passes" "$output"
fi

case_dir=$(make_case missing-resource-operation)
sed -i.bak '/NHP_CONNECTOR_RESOURCE_ALIAS_ARN/d' "${case_dir}/fixtures/cell0"
if output=$(run_case "$case_dir" env 2>&1); then
  report_fail "missing connector-resource alias is rejected" "$output"
else
  if [[ "$output" == *"NHP_CONNECTOR_RESOURCE_ALIAS_ARN"* ]]; then
    report_pass "missing connector-resource alias is rejected"
  else
    report_fail "connector-resource alias failure names the operation" "$output"
  fi
fi

case_dir=$(POINTER_COLOR=purple make_case invalid-pointer)
if output=$(POINTER_COLOR=purple run_case "$case_dir" env 2>&1); then
  report_fail "invalid Authority pointer fails closed" "$output"
else
  if [[ "$output" == *"expected blue or green"* ]]; then
    report_pass "invalid Authority pointer fails closed"
  else
    report_fail "invalid pointer names its contract" "$output"
  fi
fi

case_dir=$(make_case stale-bootstrap)
write_config "${case_dir}/fixtures/cell0" cell0 green
if output=$(run_case "$case_dir" env 2>&1); then
  report_fail "stale bootstrap color is rejected" "$output"
else
  if [[ "$output" == *"cell0 bootstrap does not select blue"* ]]; then
    report_pass "stale bootstrap color is rejected"
  else
    report_fail "stale bootstrap failure is actionable" "$output"
  fi
fi

case_dir=$(make_case wrong-cell)
write_config "${case_dir}/fixtures/cell1" cell0 blue
if output=$(run_case "$case_dir" env 2>&1); then
  report_fail "wrong-cell alias graph is rejected" "$output"
else
  if [[ "$output" == *"cell1 bootstrap does not select blue"* ]]; then
    report_pass "wrong-cell alias graph is rejected"
  else
    report_fail "wrong-cell failure is actionable" "$output"
  fi
fi

case_dir=$(make_case missing-operation)
sed -i.bak '/CREDENTIAL_RECOVERY/d' "${case_dir}/fixtures/cell1"
if output=$(run_case "$case_dir" env 2>&1); then
  report_fail "partial alias graph is rejected" "$output"
else
  if [[ "$output" == *"NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN"* ]]; then
    report_pass "partial alias graph is rejected"
  else
    report_fail "partial graph failure names the missing operation" "$output"
  fi
fi

case_dir=$(make_case duplicate-bootstrap)
printf '%s\n' \
  'NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN=arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-iro-cell0:green' \
  >>"${case_dir}/fixtures/cell0"
if output=$(run_case "$case_dir" env 2>&1); then
  report_fail "duplicate conflicting bootstrap assignment is rejected" "$output"
else
  if [[ "$output" == *"has 2 assignments"* && "$output" == *"expected exactly one selecting blue"* ]]; then
    report_pass "duplicate conflicting bootstrap assignment is rejected"
  else
    report_fail "duplicate assignment failure names count and selected color" "$output"
  fi
fi

case_dir=$(make_case invalid-server-color)
if output=$(run_case "$case_dir" env CELL0_SERVER_COLOR=red 2>&1); then
  report_fail "invalid server active color is rejected" "$output"
else
  if [[ "$output" == *"cell0 server active-color is 'red'"* ]]; then
    report_pass "invalid server active color is rejected"
  else
    report_fail "invalid server color failure is actionable" "$output"
  fi
fi

case_dir=$(make_case runtime-failure)
if output=$(run_case "$case_dir" env FAIL_ASG=cell1-blue-asg 2>&1); then
  report_fail "active runtime mismatch propagates" "$output"
else
  report_pass "active runtime mismatch propagates"
fi

case_dir=$(make_case pointer-moved)
if output=$(run_case "$case_dir" env FINAL_POINTER_COLOR=green 2>&1); then
  report_fail "selector movement during readback fails closed" "$output"
else
  if [[ "$output" == *"changed from blue to green"* ]]; then
    report_pass "selector movement during readback fails closed"
  else
    report_fail "selector movement failure names both colors" "$output"
  fi
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
