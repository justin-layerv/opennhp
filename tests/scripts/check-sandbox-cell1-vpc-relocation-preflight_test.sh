#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${repo_root}/scripts/check-sandbox-cell1-vpc-relocation-preflight.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

fake_bin="${fixture_root}/bin"
mkdir -p "$fake_bin"
ln -s \
  "${repo_root}/tests/fixtures/sandbox-cell1-vpc-relocation/aws" \
  "${fake_bin}/aws"

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

PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 drained >/dev/null
PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.104.0.0/16 drained >/dev/null

expect_failure 'expected 767397897469' env \
  FAKE_ACCOUNT_ID=000000000000 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'pinned to us-east-2' env \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-west-2 10.102.0.0/16 drained

expect_failure 'source VPC CIDR must be' env \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.105.0.0/16 drained

expect_failure 'not fully drained' env \
  FAKE_BLUE_MIN=1 FAKE_BLUE_MAX=2 FAKE_BLUE_DESIRED=1 \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'server-green is not fully drained' env \
  FAKE_GREEN_MIN=1 FAKE_GREEN_MAX=2 FAKE_GREEN_DESIRED=1 \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'still has instances' env \
  'FAKE_BLUE_INSTANCES=[{"InstanceId":"i-old"}]' \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'server-green still has instances' env \
  'FAKE_GREEN_INSTANCES=[{"InstanceId":"i-old-green"}]' \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'required suspended processes missing' env \
  'FAKE_BLUE_SUSPENDED=[{"ProcessName":"Launch"}]' \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'server-green can still repopulate' env \
  'FAKE_GREEN_SUSPENDED=[{"ProcessName":"Launch"}]' \
  PATH="${fake_bin}:${PATH}" "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'could not identify the sole tagged cell1' env \
  FAKE_LEGACY_VPC_COUNT=0 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 drained

expect_failure 'still has EC2 instance ENIs' env \
  FAKE_INSTANCE_ENI=1 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 drained

PATH="${fake_bin}:${PATH}" \
  FAKE_BLUE_MIN=1 FAKE_BLUE_MAX=2 FAKE_BLUE_DESIRED=1 FAKE_BLUE_SUSPENDED='[]' \
  "$checker" fake us-east-2 10.102.0.0/16 pre-drain >/dev/null

expect_failure 'restoration would deadlock' env \
  FAKE_BLUE_MIN=0 FAKE_BLUE_MAX=2 FAKE_BLUE_DESIRED=1 \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 pre-drain

expect_failure 'restoration would deadlock' env \
  FAKE_BLUE_MIN=1 FAKE_BLUE_MAX=2 FAKE_BLUE_DESIRED=0 \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 pre-drain

expect_failure 'server-green has min/desired capacity' env \
  FAKE_GREEN_MIN=0 FAKE_GREEN_MAX=2 FAKE_GREEN_DESIRED=1 \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 pre-drain

expect_failure 'malformed min/desired capacity' env \
  FAKE_BLUE_MIN=null FAKE_BLUE_MAX=2 FAKE_BLUE_DESIRED=0 \
  PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 pre-drain

expect_failure 'found 3 groups' env \
  FAKE_DUPLICATE_BLUE=1 PATH="${fake_bin}:${PATH}" \
  "$checker" fake us-east-2 10.102.0.0/16 drained

echo "Sandbox cell1 VPC relocation preflight fixtures passed"
