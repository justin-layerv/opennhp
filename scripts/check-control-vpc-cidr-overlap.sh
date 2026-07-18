#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <aws-profile> <region> <expected-account-id> <candidate-cidr>" >&2
  exit 2
fi

profile="$1"
region="$2"
expected_account="$3"
candidate_cidr="$4"
profile_args=()
if [[ "$profile" != "-" ]]; then
  profile_args=(--profile "$profile")
fi
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

# Correctness requires AWS CLI v2 default API auto-pagination. Callers must not
# inject --no-paginate or otherwise truncate any describe response below.
aws ec2 describe-vpcs \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/vpcs.json"
aws ec2 describe-ipams \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/ipams.json"
aws ec2 describe-vpc-peering-connections \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/peerings.json"
aws ec2 describe-transit-gateway-attachments \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/tgw-attachments.json"
aws ec2 describe-route-tables \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/route-tables.json"
aws ec2 describe-vpn-gateways \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/vpn-gateways.json"
aws ec2 describe-vpn-connections \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/vpn-connections.json"
aws ec2 describe-client-vpn-endpoints \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/client-vpn-endpoints.json"
aws directconnect describe-connections \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/direct-connect-connections.json"
aws directconnect describe-virtual-interfaces \
  "${profile_args[@]}" \
  --region "$region" \
  --output json >"$tmp_dir/direct-connect-virtual-interfaces.json"

python3 - "$candidate_cidr" "$tmp_dir" <<'PY'
import ipaddress
import json
import pathlib
import sys


def parse_ipv4_network(raw: str, source: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        print(f"ERROR: invalid {source} CIDR {raw!r}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if not isinstance(network, ipaddress.IPv4Network):
        print(f"ERROR: {source} CIDR {raw!r} is not IPv4", file=sys.stderr)
        raise SystemExit(1)
    return network


candidate = parse_ipv4_network(sys.argv[1], "candidate")
tmp_dir = pathlib.Path(sys.argv[2])

with (tmp_dir / "vpcs.json").open(encoding="utf-8") as source:
    vpcs = json.load(source)["Vpcs"]
with (tmp_dir / "ipams.json").open(encoding="utf-8") as source:
    ipams = json.load(source)["Ipams"]
with (tmp_dir / "peerings.json").open(encoding="utf-8") as source:
    peerings = json.load(source)["VpcPeeringConnections"]
with (tmp_dir / "tgw-attachments.json").open(encoding="utf-8") as source:
    tgw_attachments = json.load(source)["TransitGatewayAttachments"]
with (tmp_dir / "route-tables.json").open(encoding="utf-8") as source:
    route_tables = json.load(source)["RouteTables"]
with (tmp_dir / "vpn-gateways.json").open(encoding="utf-8") as source:
    vpn_gateways = json.load(source)["VpnGateways"]
with (tmp_dir / "vpn-connections.json").open(encoding="utf-8") as source:
    vpn_connections = json.load(source)["VpnConnections"]
with (tmp_dir / "client-vpn-endpoints.json").open(encoding="utf-8") as source:
    client_vpn_endpoints = json.load(source)["ClientVpnEndpoints"]
with (tmp_dir / "direct-connect-connections.json").open(encoding="utf-8") as source:
    direct_connect_connections = json.load(source)["connections"]
with (tmp_dir / "direct-connect-virtual-interfaces.json").open(
    encoding="utf-8"
) as source:
    direct_connect_virtual_interfaces = json.load(source)["virtualInterfaces"]

terminal_deletion_states = {"deleted", "delete-complete"}
active_ipams = [
    item for item in ipams if item.get("State") not in terminal_deletion_states
]
active_tgw_attachments = [
    item
    for item in tgw_attachments
    if item.get("State") not in terminal_deletion_states
]

if active_ipams:
    print(
        "ERROR: account has VPC IPAM resources; audit every pool allocation "
        "before accepting this candidate",
        file=sys.stderr,
    )
    raise SystemExit(1)
if active_tgw_attachments:
    print(
        "ERROR: account has Transit Gateway attachments; audit routed remote "
        "CIDRs before accepting this candidate",
        file=sys.stderr,
    )
    raise SystemExit(1)

nondeleted_vpn_gateways = [
    item for item in vpn_gateways if item.get("State") != "deleted"
]
nondeleted_vpn_connections = [
    item for item in vpn_connections if item.get("State") != "deleted"
]
nondeleted_client_vpn_endpoints = [
    item
    for item in client_vpn_endpoints
    if item.get("Status", {}).get("Code") != "deleted"
]
nondeleted_direct_connect_connections = [
    item for item in direct_connect_connections if item.get("connectionState") != "deleted"
]
nondeleted_direct_connect_virtual_interfaces = [
    item
    for item in direct_connect_virtual_interfaces
    if item.get("virtualInterfaceState") != "deleted"
]
if any(
    (
        nondeleted_vpn_gateways,
        nondeleted_vpn_connections,
        nondeleted_client_vpn_endpoints,
        nondeleted_direct_connect_connections,
        nondeleted_direct_connect_virtual_interfaces,
    )
):
    print(
        "ERROR: account has a VPN or Direct Connect path; audit its routed "
        "remote CIDRs before accepting this candidate",
        file=sys.stderr,
    )
    raise SystemExit(1)

networks: set[ipaddress.IPv4Network] = set()
for vpc in vpcs:
    for association in vpc.get("CidrBlockAssociationSet", []):
        if association.get("CidrBlockState", {}).get("State") == "associated":
            networks.add(parse_ipv4_network(association["CidrBlock"], "associated VPC"))

for peering in peerings:
    if peering.get("Status", {}).get("Code") != "active":
        continue
    for side in ("AccepterVpcInfo", "RequesterVpcInfo"):
        for item in peering.get(side, {}).get("CidrBlockSet", []):
            networks.add(parse_ipv4_network(item["CidrBlock"], "active peering"))

# The reviewed candidate contract is IPv4. IPv6 routes cannot overlap an IPv4
# network; prefix-list routes do not expose CIDRs in DescribeRouteTables and are
# not treated as address allocations by this preflight.
for route_table in route_tables:
    for route in route_table.get("Routes", []):
        destination = route.get("DestinationCidrBlock")
        if (
            destination
            and destination != "0.0.0.0/0"
            and route.get("State") == "active"
        ):
            networks.add(parse_ipv4_network(destination, "active route destination"))

overlaps = sorted(str(network) for network in networks if candidate.overlaps(network))
if overlaps:
    print(
        f"ERROR: candidate {candidate} overlaps routed/account CIDRs: "
        + ", ".join(overlaps),
        file=sys.stderr,
    )
    raise SystemExit(1)

print(
    f"PASS: {candidate} does not overlap {len(networks)} account/active-peering "
    "and active-route CIDRs; the regional query found no IPAM, Transit Gateway "
    "attachment, VPN resource, Direct Connect connection, or Direct Connect "
    "virtual interface; audit global and cross-region gateways separately"
)
PY
