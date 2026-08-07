#!/usr/bin/env bash

# Prove the caller is the exact reviewed Control apply role/session for one
# environment. The environment is an explicit required argument with no default:
# a silent default is how a prod dispatch ends up validated against a sandbox
# identity and passes.
set -euo pipefail

if [[ "$#" -ne 2 ]] || [[ ! "$2" =~ ^[A-Za-z0-9+=,.@_-]{2,64}$ ]]; then
  echo "usage: $0 <sandbox|prod> <expected-role-session-name>" >&2
  exit 2
fi

environment="$1"
expected_session="$2"

case "$environment" in
  sandbox)
    expected_account="767397897469"
    expected_role="nhp-sandbox-github-actions"
    ;;
  prod)
    expected_account="235500187906"
    expected_role="nhp-prod-github-actions"
    ;;
  *)
    echo "ERROR: unknown Control environment: ${environment}" >&2
    exit 2
    ;;
esac

expected_arn="arn:aws:sts::${expected_account}:assumed-role/${expected_role}/${expected_session}"
identity="$(aws sts get-caller-identity --output json)"
account="$(jq -er '.Account | select(type == "string")' <<<"$identity")"
arn="$(jq -er '.Arn | select(type == "string")' <<<"$identity")"

if [[ "$account" != "$expected_account" || "$arn" != "$expected_arn" ]]; then
  echo "ERROR: ${environment} Control AWS identity is not the exact reviewed role/session" >&2
  exit 1
fi
