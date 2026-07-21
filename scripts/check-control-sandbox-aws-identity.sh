#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]] || [[ ! "$1" =~ ^[A-Za-z0-9+=,.@_-]{2,64}$ ]]; then
  echo "usage: $0 <expected-role-session-name>" >&2
  exit 2
fi

expected_session="$1"
expected_account="767397897469"
expected_arn="arn:aws:sts::${expected_account}:assumed-role/nhp-sandbox-github-actions/${expected_session}"
identity="$(aws sts get-caller-identity --output json)"
account="$(jq -er '.Account | select(type == "string")' <<<"$identity")"
arn="$(jq -er '.Arn | select(type == "string")' <<<"$identity")"

if [[ "$account" != "$expected_account" || "$arn" != "$expected_arn" ]]; then
  echo "ERROR: sandbox Control AWS identity is not the exact reviewed role/session" >&2
  exit 1
fi
