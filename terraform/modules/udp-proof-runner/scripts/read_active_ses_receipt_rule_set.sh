#!/usr/bin/env bash
set -euo pipefail

query="$(< /dev/stdin)"
region="$(jq -er '.region | select(type == "string" and test("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$"))' <<<"$query")"
name="$(
  aws ses describe-active-receipt-rule-set \
    --region "$region" \
    --query 'Metadata.Name' \
    --output text
)"
if [[ "$name" == "None" || "$name" == "null" ]]; then
  name=""
fi
jq -cn --arg name "$name" '{name:$name}'
