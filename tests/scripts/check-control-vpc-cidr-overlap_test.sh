#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${repo_root}/scripts/check-control-vpc-cidr-overlap.sh"
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

FAKE_IPAM_STATE=delete-complete FAKE_TGW_STATE=deleted run_checker >/dev/null

expect_failure 'expected 767397897469' env \
  FAKE_ACCOUNT_ID=000000000000 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'overlaps routed/account CIDRs: 10.102.0.0/24' env \
  FAKE_VPC_CIDR=10.102.0.0/24 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'overlaps routed/account CIDRs: 10.102.1.0/24' env \
  FAKE_PEERING_CIDR=10.102.1.0/24 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'overlaps routed/account CIDRs: 10.102.2.0/24' env \
  FAKE_ROUTE_CIDR=10.102.2.0/24 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure "invalid active route destination CIDR '10.102.2.1/24'" env \
  FAKE_ROUTE_CIDR=10.102.2.1/24 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'Transit Gateway attachments' env \
  FAKE_TGW_STATE=deleting PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

expect_failure 'VPC IPAM resources' env \
  FAKE_IPAM_STATE=delete-in-progress PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 767397897469 10.102.0.0/16

echo "Control VPC CIDR overlap state fixtures passed"
