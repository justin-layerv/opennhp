#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <aws-profile-or--> <region> <source-vpc-cidr> <pre-drain|drained>" >&2
  exit 2
fi

profile="$1"
region="$2"
source_cidr="$3"
phase="$4"
expected_account="767397897469"
if [[ "$region" != "us-east-2" ]]; then
  echo "ERROR: sandbox cell1 is pinned to us-east-2, not $region" >&2
  exit 1
fi
if [[ "$source_cidr" != "10.102.0.0/16" && "$source_cidr" != "10.104.0.0/16" ]]; then
  echo "ERROR: source VPC CIDR must be 10.102.0.0/16 or 10.104.0.0/16" >&2
  exit 1
fi
if [[ "$phase" != "pre-drain" && "$phase" != "drained" ]]; then
  echo "ERROR: phase must be pre-drain or drained" >&2
  exit 1
fi
required_suspended_processes=(
  AlarmNotification
  AZRebalance
  InstanceRefresh
  Launch
  ReplaceUnhealthy
  ScheduledActions
)
asg_names=(
  layerv-nhp-sandbox-cell1-server
  layerv-nhp-sandbox-cell1-server-green
)
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

aws autoscaling describe-auto-scaling-groups \
  "${profile_args[@]}" \
  --region "$region" \
  --auto-scaling-group-names "${asg_names[@]}" \
  --output json >"$tmp_dir/asgs.json"

aws ec2 describe-vpcs \
  "${profile_args[@]}" \
  --region "$region" \
  --filters \
    "Name=cidr-block-association.cidr-block,Values=${source_cidr}" \
    "Name=tag:Environment,Values=sandbox-cell1" \
    "Name=tag:Cell,Values=cell1" \
  --output json >"$tmp_dir/legacy-vpcs.json"

legacy_vpc_id="$(jq -er '
  .Vpcs
  | select(length == 1)
  | .[0].VpcId
' "$tmp_dir/legacy-vpcs.json")" || {
  echo "ERROR: could not identify the sole tagged cell1 ${source_cidr} VPC" >&2
  exit 1
}

aws ec2 describe-network-interfaces \
  "${profile_args[@]}" \
  --region "$region" \
  --filters "Name=vpc-id,Values=${legacy_vpc_id}" \
  --output json >"$tmp_dir/legacy-enis.json"

python3 - \
  "$tmp_dir/asgs.json" \
  "$tmp_dir/legacy-enis.json" \
  "$legacy_vpc_id" \
  "$phase" \
  "${asg_names[@]}" \
  -- "${required_suspended_processes[@]}" <<'PY'
import json
import pathlib
import sys


args = sys.argv[1:]
separator = args.index("--")
asgs_path, enis_path, legacy_vpc_id, phase, *expected_names = args[:separator]
required_suspended = set(args[separator + 1 :])

with pathlib.Path(asgs_path).open(encoding="utf-8") as source:
    groups = json.load(source).get("AutoScalingGroups", [])
with pathlib.Path(enis_path).open(encoding="utf-8") as source:
    enis = json.load(source).get("NetworkInterfaces", [])

expected = set(expected_names)
observed = {group.get("AutoScalingGroupName") for group in groups}
if len(groups) != 2 or observed != expected:
    print(
        "ERROR: expected exact cell1 ASGs "
        f"{sorted(expected)!r}, found {len(groups)} groups "
        f"{sorted(observed)!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)

for group in groups:
    name = group["AutoScalingGroupName"]
    suspended = {
        item.get("ProcessName") for item in group.get("SuspendedProcesses", [])
    }
    minimum = group.get("MinSize")
    desired = group.get("DesiredCapacity")
    if (
        type(minimum) is not int
        or type(desired) is not int
        or minimum < 0
        or desired < 0
    ):
        print(
            f"ERROR: {name} has malformed min/desired capacity "
            f"{minimum!r}/{desired!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if (
        phase == "pre-drain"
        and (minimum > 0 or desired > 0)
        and "Launch" in suspended
    ):
        print(
            f"ERROR: {name} has min/desired capacity {minimum}/{desired} "
            "while Launch was already "
            "suspended; restoration would deadlock",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if phase == "pre-drain":
        continue

    capacities = {
        key: group.get(key)
        for key in ("MinSize", "MaxSize", "DesiredCapacity")
    }
    if capacities != {"MinSize": 0, "MaxSize": 0, "DesiredCapacity": 0}:
        print(
            f"ERROR: {name} is not fully drained; expected min/max/desired "
            f"0/0/0, found {capacities!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if group.get("Instances"):
        instance_ids = [
            item.get("InstanceId", "<unknown>") for item in group["Instances"]
        ]
        print(
            f"ERROR: {name} still has instances: {instance_ids!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    missing = sorted(required_suspended - suspended)
    if missing:
        print(
            f"ERROR: {name} can still repopulate the legacy VPC; required "
            f"suspended processes missing: {missing!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)

instance_enis = [
    eni
    for eni in enis
    if isinstance(eni.get("Attachment"), dict)
    and eni["Attachment"].get("InstanceId")
]
if phase == "drained" and instance_enis:
    details = [
        {
            "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
            "InstanceId": eni["Attachment"].get("InstanceId"),
            "Status": eni.get("Status"),
        }
        for eni in instance_enis
    ]
    print(
        f"ERROR: legacy VPC {legacy_vpc_id} still has EC2 instance ENIs: "
        f"{details!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)

if phase == "pre-drain":
    print(
        "PASS: both cell1 ASGs are uniquely identified and can be restored "
        "without a pre-existing Launch suspension deadlock"
    )
else:
    print(
        "PASS: both cell1 ASGs are min/max/desired 0/0/0, have no instances, "
        "cannot launch or policy-scale, and the legacy VPC has no EC2 instance ENIs"
    )
PY
