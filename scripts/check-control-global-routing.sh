#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <aws-profile> <home-region> <expected-account-id> <candidate-cidr>" >&2
  exit 2
fi

profile="$1"
home_region="$2"
expected_account="$3"
candidate_cidr="$4"
profile_args=()
if [[ "$profile" != "-" ]]; then
  profile_args=(--profile "$profile")
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
regional_checker="${repo_root}/scripts/check-control-vpc-cidr-overlap.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

account_id="$(aws sts get-caller-identity \
  "${profile_args[@]}" \
  --query Account \
  --output text)"
if [[ "$account_id" != "$expected_account" ]]; then
  echo "ERROR: profile $profile resolved account $account_id, expected $expected_account" >&2
  exit 1
fi

aws ec2 describe-regions \
  "${profile_args[@]}" \
  --region "$home_region" \
  --all-regions \
  --output json >"$tmp_dir/regions.json"

python3 - "$tmp_dir/regions.json" "$home_region" >"$tmp_dir/enabled-regions.txt" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
home_region = sys.argv[2]
regions = payload.get("Regions")
if not isinstance(regions, list):
    print("ERROR: describe-regions did not return a Regions array", file=sys.stderr)
    raise SystemExit(1)
enabled = sorted(
    item.get("RegionName")
    for item in regions
    if item.get("OptInStatus") in {"opt-in-not-required", "opted-in"}
    and isinstance(item.get("RegionName"), str)
)
if home_region not in enabled:
    print(f"ERROR: home region {home_region} is not enabled", file=sys.stderr)
    raise SystemExit(1)
if len(enabled) != len(set(enabled)):
    print("ERROR: enabled region inventory contains duplicates", file=sys.stderr)
    raise SystemExit(1)
print("\n".join(enabled))
PY

region_count=0
while IFS= read -r region; do
  [[ -n "$region" ]] || continue
  region_count=$((region_count + 1))
  "$regional_checker" "$profile" "$region" "$expected_account" "$candidate_cidr"
done <"$tmp_dir/enabled-regions.txt"
if [[ "$region_count" -eq 0 ]]; then
  echo "ERROR: no enabled AWS regions were audited" >&2
  exit 1
fi

# Direct Connect gateways and their cross-account/TGW/VGW associations are not
# covered by the per-region connection/virtual-interface calls above. The dark
# Control VPC has no legitimate Direct Connect dependency, so any nondeleted
# global gateway/association/proposal is a fail-closed manual-audit boundary.
aws directconnect describe-direct-connect-gateways \
  "${profile_args[@]}" \
  --region "$home_region" \
  --output json >"$tmp_dir/direct-connect-gateways.json"

# These two APIs do not support account-wide enumeration: AWS requires a
# Direct Connect gateway ID (or another specific association selector). Walk
# every nondeleted gateway returned by the account-wide gateway API instead.
python3 - "$tmp_dir/direct-connect-gateways.json" >"$tmp_dir/direct-connect-gateway-ids.txt" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
gateways = payload.get("directConnectGateways")
if not isinstance(gateways, list):
    print("ERROR: Direct Connect gateway inventory is malformed", file=sys.stderr)
    raise SystemExit(1)
for gateway in gateways:
    if gateway.get("directConnectGatewayState") == "deleted":
        continue
    gateway_id = gateway.get("directConnectGatewayId")
    if not isinstance(gateway_id, str) or not gateway_id:
        print("ERROR: nondeleted Direct Connect gateway has no ID", file=sys.stderr)
        raise SystemExit(1)
    print(gateway_id)
PY

gateway_index=0
while IFS= read -r gateway_id; do
  [[ -n "$gateway_id" ]] || continue
  aws directconnect describe-direct-connect-gateway-associations \
    "${profile_args[@]}" \
    --region "$home_region" \
    --direct-connect-gateway-id "$gateway_id" \
    --output json >"$tmp_dir/direct-connect-gateway-associations-${gateway_index}.json"
  aws directconnect describe-direct-connect-gateway-association-proposals \
    "${profile_args[@]}" \
    --region "$home_region" \
    --direct-connect-gateway-id "$gateway_id" \
    --output json >"$tmp_dir/direct-connect-gateway-association-proposals-${gateway_index}.json"
  gateway_index=$((gateway_index + 1))
done <"$tmp_dir/direct-connect-gateway-ids.txt"

python3 - "$tmp_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])


def load(name, key):
    payload = json.loads((root / name).read_text(encoding="utf-8"))
    value = payload.get(key)
    if not isinstance(value, list):
        print(f"ERROR: {name} did not return {key} as an array", file=sys.stderr)
        raise SystemExit(1)
    return value


def load_many(pattern, key):
    values = []
    for path in sorted(root.glob(pattern)):
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get(key)
        if not isinstance(items, list):
            print(f"ERROR: {path.name} did not return {key} as an array", file=sys.stderr)
            raise SystemExit(1)
        values.extend(items)
    return values


gateways = [
    item
    for item in load("direct-connect-gateways.json", "directConnectGateways")
    if item.get("directConnectGatewayState") != "deleted"
]
associations = [
    item
    for item in load_many(
        "direct-connect-gateway-associations-*.json",
        "directConnectGatewayAssociations",
    )
    if item.get("associationState") != "deleted"
]
proposals = [
    item
    for item in load_many(
        "direct-connect-gateway-association-proposals-*.json",
        "directConnectGatewayAssociationProposals",
    )
    if item.get("proposalState") not in {"deleted", "accepted"}
]
if gateways or associations or proposals:
    print(
        "ERROR: account has nondeleted Direct Connect gateway, association, "
        "or proposal resources; audit every remote CIDR before accepting the "
        "Control VPC candidate",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY

echo "PASS: ${candidate_cidr} passed regional routing audits in ${region_count} enabled regions and the global Direct Connect gateway audit"
