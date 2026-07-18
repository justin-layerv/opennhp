#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${repo_root}/scripts/check-control-global-routing.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

fake_bin="${fixture_root}/bin"
mkdir -p "$fake_bin"
ln -s "${repo_root}/tests/fixtures/control-vpc-cidr-overlap/aws" "${fake_bin}/aws"

run_checker() {
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 767397897469 10.102.0.0/16
}

expect_failure() {
  local expected="$1"
  shift
  local output
  if output=$("$@" 2>&1); then
    echo "ERROR: command unexpectedly passed: $*" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "ERROR: failure did not contain '$expected':" >&2
    echo "$output" >&2
    exit 1
  fi
}

FAKE_ENABLED_REGIONS='us-east-1 us-east-2' run_checker >/dev/null

expect_failure 'expected 767397897469' env \
  FAKE_ACCOUNT_ID=000000000000 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'home region us-east-2 is not enabled' env \
  FAKE_ENABLED_REGIONS=us-east-1 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'Direct Connect gateway' env \
  FAKE_DX_GATEWAY_STATE=available PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'Direct Connect gateway' env \
  FAKE_DX_GATEWAY_STATE=available FAKE_DX_ASSOCIATION_STATE=associating \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'Direct Connect gateway' env \
  FAKE_DX_GATEWAY_STATE=available FAKE_DX_PROPOSAL_STATE=requested \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

FAKE_DX_GATEWAY_STATE=deleted \
  FAKE_DX_ASSOCIATION_STATE=deleted \
  FAKE_DX_PROPOSAL_STATE=accepted \
  run_checker >/dev/null

echo "Control global routing fixtures passed"
