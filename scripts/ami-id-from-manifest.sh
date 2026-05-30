#!/usr/bin/env bash
# Extract the AMI ID for a region from a Packer manifest.
#
# amazon-ebs writes artifact_id as "region:ami-xxx" or, for multi-region
# builds, "region1:ami-a,region2:ami-b". Terraform SSM parameters must receive
# only the bare ami-* value for the region being deployed.

set -euo pipefail

usage() {
  echo "Usage: $0 <manifest.json> <aws-region>" >&2
}

dump_manifest() {
  local manifest="$1"
  echo "--- $manifest contents ---" >&2
  cat "$manifest" >&2 || true
}

if [ "$#" -ne 2 ]; then
  usage
  exit 64
fi

manifest="$1"
region="$2"

if [ ! -f "$manifest" ]; then
  echo "ERROR: AMI manifest $manifest not found" >&2
  exit 1
fi

ami_line=$(jq -r '.builds[-1].artifact_id // empty' "$manifest")
if [ -z "$ami_line" ]; then
  echo "ERROR: no artifact_id in $manifest" >&2
  dump_manifest "$manifest"
  exit 1
fi

ami_id=$(printf '%s\n' "$ami_line" | tr ',' '\n' | awk -F: -v r="$region" '$1 == r { print $2; exit }')
if [ -z "$ami_id" ]; then
  echo "ERROR: manifest $manifest has no AMI for region $region (artifact_id: $ami_line)" >&2
  dump_manifest "$manifest"
  exit 1
fi

if ! echo "$ami_id" | grep -Eq '^ami-[0-9a-f]+$'; then
  echo "ERROR: parsed AMI ID '$ami_id' from manifest is not a valid ami-* identifier (artifact_id: $ami_line)" >&2
  dump_manifest "$manifest"
  exit 1
fi

printf '%s\n' "$ami_id"
