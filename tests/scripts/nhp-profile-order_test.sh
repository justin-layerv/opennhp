#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/nhp-profile-order.sh"
IMAGE=0123456789012345678901234567890123456789

[[ "$($SCRIPT order legacy-aop-v1)" == 10 ]]
[[ "$($SCRIPT order durable-aop-v1)" == 20 ]]
$SCRIPT assert-at-least durable-aop-v1 legacy-aop-v1
$SCRIPT assert-at-least durable-aop-v1 durable-aop-v1
if $SCRIPT assert-at-least legacy-aop-v1 durable-aop-v1 >/dev/null 2>&1; then exit 1; fi
if $SCRIPT order future-unknown >/dev/null 2>&1; then exit 1; fi

record=$($SCRIPT record durable-aop-v1 "$IMAGE")
[[ "$record" == "v1|durable-aop-v1|$IMAGE" ]]
$SCRIPT assert-record "$record" durable-aop-v1 "$IMAGE"
if $SCRIPT assert-record "$record" durable-aop-v1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then exit 1; fi
if $SCRIPT assert-record 'v1|legacy-aop-v1|0123456789012345678901234567890123456789' durable-aop-v1 "$IMAGE" >/dev/null 2>&1; then exit 1; fi

echo "nhp-profile-order: all tests passed"
