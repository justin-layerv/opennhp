#!/usr/bin/env bash

set -euo pipefail

action="${1:-}"
github_run_id="${2:-}"
github_run_attempt="${3:-}"

if [[ "$action" != "start" && "$action" != "stop" ]]; then
  echo "::error::broker action must be start or stop"
  exit 2
fi
if [[ ! "$github_run_id" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::GitHub run ID must be a positive integer"
  exit 2
fi
if [[ ! "$github_run_attempt" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::GitHub run attempt must be a positive integer"
  exit 2
fi
: "${BROKER_FUNCTION:?BROKER_FUNCTION is required}"
: "${AWS_REGION:?AWS_REGION is required}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
response_file="$work_dir/response.json"
invoke_file="$work_dir/invoke.json"
payload="$(
  jq -cn \
    --arg action "$action" \
    --arg run_id "$github_run_id" \
    --arg run_attempt "$github_run_attempt" \
    '{
      action: $action,
      github_run_id: $run_id,
      github_run_attempt: $run_attempt
    }'
)"

# On stop, false means the secret was already absent. The broker raises instead
# of returning if deletion fails, so either boolean is terminal cleanup
# confirmation rather than permission to leave a secret behind.
for attempt in 1 2 3 4 5; do
  if aws lambda invoke \
    --function-name "$BROKER_FUNCTION" \
    --cli-binary-format raw-in-base64-out \
    --payload "$payload" \
    --region "$AWS_REGION" \
    "$response_file" >"$invoke_file" &&
    jq -e '.StatusCode == 200 and (has("FunctionError") | not)' \
      "$invoke_file" >/dev/null &&
    jq -e --arg action "$action" '
      if $action == "start" then
        (keys | sort) == ["action", "instance_id", "status"] and
        .action == "start" and
        (.status == "launched" or .status == "existing") and
        (.instance_id | type == "string" and test("^i-[0-9a-f]+$"))
      else
        (keys | sort) == ["account_credential_secret_deleted", "action", "instances", "secret_deleted", "status"] and
        .action == "stop" and
        (.status == "terminated" or .status == "absent") and
        (.instances | type == "array") and
        (.instances | all(.[]; type == "string" and test("^i-[0-9a-f]+$"))) and
        (.instances | unique | length) == (.instances | length) and
        (if .status == "terminated" then
          (.instances | length) >= 1
        else
          (.instances | length) == 0
        end) and
        (.secret_deleted | type == "boolean") and
        (.account_credential_secret_deleted | type == "boolean")
      end
    ' "$response_file" >/dev/null; then
    exit 0
  fi

  rm -f "$response_file" "$invoke_file"
  if (( attempt < 5 )); then
    sleep "$((attempt * 10))"
  fi
done

if [[ "$action" == "start" ]]; then
  echo "::error::broker did not confirm an exact ready runner"
else
  echo "::error::broker did not confirm exact runner/run-bound secret cleanup"
fi
exit 1
