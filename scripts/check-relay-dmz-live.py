#!/usr/bin/env python3
"""Fail-closed inventory check for the singleton NHP relay DMZ.

The normal mode reads AWS through the CLI and validates the live boundary.  The
``--snapshot`` mode consumes the normalized document emitted by this module's
collector, which keeps the policy checks deterministic and unit-testable.

The sibling plan checker stays under ``.github/scripts`` because it is a
PR-workflow helper. This live detector stays under top-level ``scripts`` because
deployment workflows and operators invoke it after apply and fleet refresh.

This checker intentionally targets the commercial ``aws`` partition. Its ARN
contracts require the exact ``arn:aws:`` prefix and its DNS contracts use
``amazonaws.com`` service names. Its region grammar allowlists reviewed
commercial prefixes; isolated, sovereign, GovCloud, and China partitions need
separate contracts rather than being accepted by a permissive region regex.

Repository CI for this detector layer executes the deterministic unit/snapshot
suite only; it does not contact AWS. The stacked integration layer is where the
structural and functional live invocations become deployment gates.

Structural collection deliberately uses whole-account, auto-paginated load
balancer, target-group, and coverage listings before applying exact ownership
and name filters. That makes duplicate/stale resources visible. Large-account
page cost is bounded by the CLI timeout and classified as retryable rather than
silently accepting a partial inventory.

The 30-second bound is per AWS CLI call, not per structural pass. The integrated
deployment jobs therefore own the aggregate ceiling: their documented 55-minute
infrastructure and 35-minute functional timeouts include convergence, plan, and
fresh-collection budgets. A slow-but-successful call sequence remains bounded by
those caller timeouts rather than by an implicit partial-inventory cutoff here.

Functional mode uses SSM SendCommand. The integration IAM is currently scoped
to sandbox relay tags while the prod relay remains dark. Enabling this command
path in prod requires separately reviewed prod IAM enablement and explicit
security acceptance; support in this detector is not that authorization.

Exit codes:
  0: every requested invariant passed
  1: live state was read successfully but violated one or more invariants
  2: inventory collection or snapshot parsing failed
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any


# The first committed live snapshot contract started at v2. Version 3 adds the
# relay-owned native UDP edge. Version 6 removes that edge; version 7 binds the
# replacement public UDP/62206 proof to the assigned-cell compute NLB. Version 8
# adds the active-color internal relay NLB target/ASG/SG proof and inventories
# every public main-VPC NLB to detect a second NHP-owned edge. Version 9 resolves
# IP targets and expands NHP ownership evidence to canonical server ASG, SG, and
# private-IP identity. Increment for incompatible snapshot changes.
SCHEMA_VERSION = 9
EXPECTED_INTERFACE_SERVICES = {
    "ecr.api",
    "ecr.dkr",
    "guardduty-data",
    "logs",
    "monitoring",
    "secretsmanager",
    "ssm",
    "ssmmessages",
}
EXPECTED_ENDPOINT_ACTIONS = {
    "ecr.api": {
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    },
    "ecr.dkr": {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    },
    "secretsmanager": {"secretsmanager:GetSecretValue"},
    "ssm": {
        "ssm:GetParameter",
        "ssm:DescribeAssociation",
        "ssm:DescribeDocument",
        "ssm:GetDocument",
        "ssm:GetManifest",
        "ssm:ListAssociations",
        "ssm:ListInstanceAssociations",
        "ssm:PutComplianceItems",
        "ssm:PutConfigurePackageResult",
        "ssm:PutInventory",
        "ssm:UpdateAssociationStatus",
        "ssm:UpdateInstanceAssociationStatus",
        "ssm:UpdateInstanceInformation",
    },
    "ssmmessages": {
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
    },
    "logs": {
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
    },
    "monitoring": {"cloudwatch:PutMetricData"},
    "guardduty-data": {"*"},
}
ADVANCED_DNS_PROTECTION_PRIORITIES = {
    "DGA": 100,
    "DICTIONARY_DGA": 110,
    "DNS_TUNNELING": 120,
}
ADVANCED_DNS_PROTECTIONS = set(ADVANCED_DNS_PROTECTION_PRIORITIES)
# Mirrored by Terraform and the plan checker's explicit drift alarm. NODATA is
# required because the functional example.com probe expects resolution failure.
DNS_BLOCK_RESPONSE = "NODATA"
MIN_SSM_AGENT_VERSION = (3, 3, 40, 0)
AWS_CLI_TIMEOUT_SECONDS = 30
RETRY_BASE_SECONDS = 5
RETRY_MAX_SECONDS = 30
# SendCommand delivery timeout, not a shell execution ceiling. Individual TCP
# socket canaries self-bound to four seconds; SSM_PROBE_DEADLINE_SECONDS bounds
# detector polling, not remote shell execution.
SSM_COMMAND_TIMEOUT_SECONDS = 30
SSM_PROBE_POLL_INTERVAL_SECONDS = 2
SSM_PROBE_DEADLINE_SECONDS = 90
SSM_RUN_SHELL_DOCUMENT_NAME = "AWS-RunShellScript"
SSM_RUN_SHELL_DOCUMENT_OWNER = "Amazon"
PUBLIC_EGRESS_CANARY_IPS = ("1.1.1.1", "8.8.8.8")
EXPECTED_FLOW_LOG_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} "
    "${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} "
    "${action} ${log-status} ${pkt-srcaddr} ${pkt-dstaddr} "
    "${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} "
    "${traffic-path}"
)
# Prod functional mode intentionally remains code-dark as well as IAM-dark.
# A reviewed integration change must flip this fence together with prod IAM and
# security acceptance; CLI and direct callers both fail before any AWS request.
PROD_FUNCTIONAL_MODE_ENABLED = False
EXPECTED_ENVIRONMENT_REGIONS = {
    "sandbox": "us-east-2",
    "prod": "us-east-2",
}
RELAY_HTTPS_PORT = 443
RELAY_BACKEND_PORT = 8080
RELAY_SERVER_UDP_PORT = 62206
RELAY_ACK_UDP_PORT = 62207
RELAY_HEALTH_PATH = "/health/live"
RELAY_TLS_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"
RELAY_TG_NAME_PREFIX = "rlytls"

# Sandbox and prod deliberately use the same reviewed address plan today. Keep
# separate entries: a future prod-only CIDR change must update the explicit prod
# contract and its tests rather than inheriting a sandbox edit accidentally.
RELAY_DMZ_NETWORK_CONTRACTS = {
    "sandbox": {
        "vpc": "10.101.0.0/16",
        "public-alb": {"10.101.0.0/24", "10.101.1.0/24", "10.101.2.0/24"},
        "isolated-relay": {
            "10.101.10.0/24",
            "10.101.11.0/24",
            "10.101.12.0/24",
        },
        "isolated-endpoint": {
            "10.101.20.0/24",
            "10.101.21.0/24",
            "10.101.22.0/24",
        },
    },
    "prod": {
        "vpc": "10.101.0.0/16",
        "public-alb": {"10.101.0.0/24", "10.101.1.0/24", "10.101.2.0/24"},
        "isolated-relay": {
            "10.101.10.0/24",
            "10.101.11.0/24",
            "10.101.12.0/24",
        },
        "isolated-endpoint": {
            "10.101.20.0/24",
            "10.101.21.0/24",
            "10.101.22.0/24",
        },
    },
}

# Existing non-US commercial region families accept their reviewed prefix
# grammar; US remains explicitly east/west. Any future family or US subdivision
# fails closed here until its CLI/endpoint semantics receive review.
COMMERCIAL_REGION_RE = re.compile(
    r"(?:(?:af|ap|ca|eu|il|me|mx|sa)(?:-[a-z]+)+|us-(?:east|west))-\d+"
)
PROBE_OUTPUT_FORMAT = (
    "NHP_DMZ_PROBE allowed_dns=%s blocked_public_dns=%s "
    "public_tcp_unreachable=%s relay_active=%s"
)


def _compile_probe_output_re(format_string: str) -> re.Pattern[str]:
    # Split on the format token before escaping so this does not depend on
    # Python-version-specific re.escape("%s") behavior. Exactly four probe
    # fields are part of the wire contract below.
    parts = format_string.split("%s")
    if len(parts) != 5:
        raise ValueError("probe output format must contain exactly four %s tokens")
    return re.compile(r"(\d)".join(re.escape(part) for part in parts))


PROBE_OUTPUT_RE = _compile_probe_output_re(PROBE_OUTPUT_FORMAT)
SSM_AGENT_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


NEGATIVE_DNS_PROBE_PY = """import socket, sys
try:
    socket.getaddrinfo("example.com", None)
except socket.gaierror as exc:
    blocked = {socket.EAI_NONAME}
    nodata = getattr(socket, "EAI_NODATA", None)
    if nodata is not None:
        blocked.add(nodata)
    sys.exit(0 if exc.errno in blocked else 2)
except OSError:
    sys.exit(2)
sys.exit(1)
"""

PUBLIC_TCP_PROBE_PY = """import errno, socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(4)
try:
    result = sock.connect_ex((sys.argv[1], int(sys.argv[2])))
except TimeoutError:
    result = errno.ETIMEDOUT
except OSError as exc:
    result = exc.errno
finally:
    sock.close()
if result in (0, errno.ECONNREFUSED):
    sys.exit(1)
if result in (errno.ETIMEDOUT, errno.EAGAIN, errno.ENETUNREACH, errno.EHOSTUNREACH):
    sys.exit(0)
sys.exit(2)
"""


class InventoryError(RuntimeError):
    """AWS inventory could not be completed safely."""


class RetryableInventoryError(InventoryError):
    """AWS inventory is incomplete because live resources are still converging."""


def _tags(value: list[dict[str, str]] | None) -> dict[str, str]:
    # Key is required by every AWS tag shape consumed here. Index deliberately:
    # silently skipping a malformed tag could hide a missing ownership marker,
    # while KeyError is caught at the collector boundary and exits fail-closed.
    return {tag["Key"]: tag.get("Value", "") for tag in value or []}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _service_suffix(service_name: str) -> str:
    parts = service_name.split(".")
    return ".".join(parts[3:]) if len(parts) > 3 else service_name


def _decode_policy(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    for candidate in (str(value), urllib.parse.unquote(str(value))):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _flatten_permissions(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for permission in permissions:
        base = {
            "protocol": permission.get("IpProtocol"),
            "from": permission.get("FromPort"),
            "to": permission.get("ToPort"),
        }
        source_fields = (
            ("IpRanges", "CidrIp", "cidr_ipv4"),
            ("Ipv6Ranges", "CidrIpv6", "cidr_ipv6"),
            ("PrefixListIds", "PrefixListId", "prefix_list"),
            ("UserIdGroupPairs", "GroupId", "security_group"),
        )
        emitted = False
        for collection, field, kind in source_fields:
            for source in permission.get(collection, []):
                emitted = True
                rule = dict(base)
                rule.update({"source_type": kind, "source": source.get(field)})
                rules.append(rule)
        if not emitted:
            rule = dict(base)
            rule.update({"source_type": "none", "source": None})
            rules.append(rule)
    return sorted(rules, key=_rule_key)


def _rule_key(rule: dict[str, Any]) -> tuple[str, int, int, str, str]:
    return (
        str(rule.get("protocol")),
        -1 if rule.get("from") is None else int(rule["from"]),
        -1 if rule.get("to") is None else int(rule["to"]),
        str(rule.get("source_type")),
        str(rule.get("source")),
    )


def _route(route: dict[str, Any]) -> dict[str, Any]:
    destination = (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
    )
    target_fields = (
        ("NatGatewayId", "nat"),
        ("GatewayId", "gateway"),
        ("VpcPeeringConnectionId", "peering"),
        ("TransitGatewayId", "transit_gateway"),
        ("NetworkInterfaceId", "network_interface"),
        ("InstanceId", "instance"),
        ("EgressOnlyInternetGatewayId", "egress_only_igw"),
    )
    target = None
    target_type = None
    for field, kind in target_fields:
        if route.get(field):
            target = route[field]
            target_type = kind
            break
    return {
        "destination": destination,
        "target_type": target_type,
        "target": target,
        "state": route.get("State"),
    }


def _require_commercial_region(value: str) -> str:
    region = value.strip()
    if not COMMERCIAL_REGION_RE.fullmatch(region):
        raise InventoryError(
            f"AWS region {value!r} is not a valid commercial partition region"
        )
    return region


def _require_account_id(value: Any) -> str:
    account_id = str(value or "").strip()
    if not re.fullmatch(r"\d{12}", account_id):
        raise InventoryError(f"AWS account ID {value!r} is not a 12-digit identifier")
    return account_id


def _exact_nonnegative_int(value: Any) -> int | None:
    """Accept an integer or its canonical decimal string, never truncating."""
    if type(value) is int:
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"0|[1-9]\d*", value):
        return int(value)
    return None


def _valid_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _require_expected_environment_region(environment: str, region: str) -> None:
    expected_region = EXPECTED_ENVIRONMENT_REGIONS.get(environment)
    if expected_region is None:
        raise InventoryError(
            f"relay DMZ has no reviewed AWS region for environment {environment!r}"
        )
    if region != expected_region:
        raise InventoryError(
            f"relay DMZ environment {environment!r} requires AWS region "
            f"{expected_region!r}, not {region!r}"
        )


def _require_live_functional_authorized(environment: str) -> None:
    if environment == "sandbox":
        return
    if environment == "prod" and PROD_FUNCTIONAL_MODE_ENABLED:
        return
    if environment == "prod":
        raise InventoryError(
            "prod relay DMZ functional mode is IAM-dark; enable the explicit "
            "code fence only with reviewed prod IAM and security acceptance"
        )
    raise InventoryError(
        f"live relay DMZ functional mode is not authorized for environment {environment!r}"
    )


class AwsCli:
    def __init__(self, region: str | None = None) -> None:
        self.region = next(
            (
                value.strip()
                for value in (
                    region,
                    os.environ.get("AWS_REGION"),
                    os.environ.get("AWS_DEFAULT_REGION"),
                )
                if value and value.strip()
            ),
            None,
        )
        if not self.region:
            try:
                result = subprocess.run(
                    ["aws", "configure", "get", "region"],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=AWS_CLI_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise InventoryError(
                    "AWS region is not configured and the AWS CLI configuration "
                    f"could not be read: {exc}"
                ) from exc
            configured_region = result.stdout.strip() if result.returncode == 0 else ""
            if not configured_region:
                detail = result.stderr.strip().splitlines()
                suffix = f": {detail[-1]}" if detail else ""
                raise InventoryError(
                    "AWS region is not configured; set AWS_REGION/AWS_DEFAULT_REGION "
                    f"or configure the active AWS profile{suffix}"
                )
            self.region = configured_region
        self.region = _require_commercial_region(str(self.region))

    def call(self, service: str, operation: str, *args: str) -> dict[str, Any]:
        # AWS CLI v1 and v2 auto-paginate paginated list/describe operations.
        # Keep that default: --no-cli-pager below only disables terminal paging
        # and must not be replaced or supplemented with --no-paginate. The 30s
        # subprocess bound intentionally also covers account-wide auto-paginated
        # calls; a timeout is classified as retryable by the bounded caller.
        command = [
            "aws",
            service,
            operation,
            "--region",
            self.region,
            *args,
            "--output",
            "json",
            "--no-cli-pager",
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=AWS_CLI_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise InventoryError(
                f"AWS CLI timed out after {AWS_CLI_TIMEOUT_SECONDS}s "
                f"({service} {operation})"
            ) from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            detail = stderr.splitlines()[-1] if stderr else "unknown error"
            raise InventoryError(f"AWS CLI failed ({service} {operation}): {detail}")
        try:
            parsed = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise InventoryError(
                f"AWS CLI returned invalid JSON ({service} {operation})"
            ) from exc
        if not isinstance(parsed, dict):
            raise InventoryError(
                f"AWS CLI returned a non-object ({service} {operation})"
            )
        return parsed


def _pin_ssm_run_shell_document(aws: AwsCli) -> tuple[str, str]:
    """Return the exact active Amazon document version and SHA-256 hash."""
    description = aws.call(
        "ssm", "describe-document", "--name", SSM_RUN_SHELL_DOCUMENT_NAME
    ).get("Document")
    if not isinstance(description, dict):
        raise InventoryError("SSM RunShellScript document metadata is missing")

    expected_fields = {
        "Name": SSM_RUN_SHELL_DOCUMENT_NAME,
        "Owner": SSM_RUN_SHELL_DOCUMENT_OWNER,
        "DocumentType": "Command",
        "Status": "Active",
        "HashType": "Sha256",
    }
    for field, expected in expected_fields.items():
        if description.get(field) != expected:
            raise InventoryError(
                f"SSM RunShellScript document {field} is not {expected!r}"
            )

    version = str(description.get("DocumentVersion") or "")
    document_hash = str(description.get("Hash") or "")
    if not re.fullmatch(r"[1-9]\d*", version):
        raise InventoryError("SSM RunShellScript document version is not numeric")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", document_hash):
        raise InventoryError("SSM RunShellScript document SHA-256 hash is invalid")
    return version, document_hash


def _find_route_table(
    subnet_id: str, route_tables: list[dict[str, Any]]
) -> dict[str, Any] | None:
    # AWS implicitly associates an otherwise-unassociated subnet with the VPC
    # main table. Preserve that live behavior here; the validator still requires
    # three distinct dedicated tables with exact per-subnet routes, so inheriting
    # the main table fails closed with the topology/route contract violations.
    for table in route_tables:
        if any(
            association.get("SubnetId") == subnet_id
            for association in table.get("Associations", [])
        ):
            return table
    for table in route_tables:
        if any(
            association.get("Main") for association in table.get("Associations", [])
        ):
            return table
    return None


def _normalize_sg(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": group.get("GroupId"),
        "vpc_id": group.get("VpcId"),
        "name": group.get("GroupName"),
        "tags": _tags(group.get("Tags")),
        "inbound": _flatten_permissions(group.get("IpPermissions", [])),
        "outbound": _flatten_permissions(group.get("IpPermissionsEgress", [])),
    }


def _normalize_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": endpoint.get("VpcEndpointId"),
        "service": _service_suffix(endpoint.get("ServiceName", "")),
        "type": endpoint.get("VpcEndpointType"),
        "state": endpoint.get("State"),
        "private_dns_enabled": bool(endpoint.get("PrivateDnsEnabled")),
        "subnet_ids": sorted(endpoint.get("SubnetIds", [])),
        "route_table_ids": sorted(endpoint.get("RouteTableIds", [])),
        "security_group_ids": sorted(
            group.get("GroupId")
            for group in endpoint.get("Groups", [])
            if group.get("GroupId")
        ),
        "policy": _decode_policy(endpoint.get("PolicyDocument")),
    }


def _collect_udp_target_group(
    aws: AwsCli, target_group_arn: str
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    target_group_rows = aws.call(
        "elbv2",
        "describe-target-groups",
        "--target-group-arns",
        target_group_arn,
    ).get("TargetGroups", [])
    target_group = None
    if len(target_group_rows) == 1:
        row = target_group_rows[0]
        target_group_attributes = {
            item.get("Key"): item.get("Value")
            for item in aws.call(
                "elbv2",
                "describe-target-group-attributes",
                "--target-group-arn",
                target_group_arn,
            ).get("Attributes", [])
        }
        target_group_tags = aws.call(
            "elbv2", "describe-tags", "--resource-arns", target_group_arn
        ).get("TagDescriptions", [])
        target_group = {
            "arn": row.get("TargetGroupArn"),
            "name": row.get("TargetGroupName"),
            "tags": (
                _tags(target_group_tags[0].get("Tags"))
                if len(target_group_tags) == 1
                else {}
            ),
            "vpc_id": row.get("VpcId"),
            "protocol": row.get("Protocol"),
            "port": row.get("Port"),
            "target_type": row.get("TargetType"),
            "preserve_client_ip": (
                target_group_attributes.get("preserve_client_ip.enabled") == "true"
            ),
            "health_check_enabled": row.get("HealthCheckEnabled"),
            "health_check_protocol": row.get("HealthCheckProtocol"),
            "health_check_port": row.get("HealthCheckPort"),
            "health_check_path": row.get("HealthCheckPath"),
            "health_check_matcher": row.get("Matcher", {}).get("HttpCode"),
        }

    targets = [
        {
            "id": row.get("Target", {}).get("Id"),
            "port": row.get("Target", {}).get("Port"),
            "state": row.get("TargetHealth", {}).get("State"),
            "reason": row.get("TargetHealth", {}).get("Reason"),
        }
        for row in aws.call(
            "elbv2",
            "describe-target-health",
            "--target-group-arn",
            target_group_arn,
        ).get("TargetHealthDescriptions", [])
    ]
    target_to_instance_id = {
        str(row["id"]): str(row["id"])
        for row in targets
        if str(row.get("id", "")).startswith("i-")
    }
    if isinstance(target_group, dict) and target_group.get("target_type") == "ip":
        ip_target_ids = sorted(
            {
                str(row["id"])
                for row in targets
                if isinstance(row.get("id"), str) and _valid_ip_address(str(row["id"]))
            }
        )
        target_vpc_id = target_group.get("vpc_id")
        if ip_target_ids and isinstance(target_vpc_id, str) and target_vpc_id:
            ip_reservations = aws.call(
                "ec2",
                "describe-instances",
                "--filters",
                f"Name=vpc-id,Values={target_vpc_id}",
                "Name=network-interface.addresses.private-ip-address,Values="
                + ",".join(ip_target_ids),
            ).get("Reservations", [])
            for reservation in ip_reservations:
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    if not isinstance(instance_id, str) or not instance_id:
                        continue
                    private_ips = {
                        str(address.get("PrivateIpAddress"))
                        for interface in instance.get("NetworkInterfaces", [])
                        for address in interface.get("PrivateIpAddresses", [])
                        if address.get("PrivateIpAddress")
                    }
                    if instance.get("PrivateIpAddress"):
                        private_ips.add(str(instance["PrivateIpAddress"]))
                    for private_ip in private_ips & set(ip_target_ids):
                        target_to_instance_id[private_ip] = instance_id

    instance_ids = sorted(set(target_to_instance_id.values()))
    if instance_ids:
        asg_rows = aws.call(
            "autoscaling",
            "describe-auto-scaling-instances",
            "--instance-ids",
            *instance_ids,
        ).get("AutoScalingInstances", [])
        by_instance = {
            str(row.get("InstanceId")): row for row in asg_rows if row.get("InstanceId")
        }
        reservations = aws.call(
            "ec2", "describe-instances", "--instance-ids", *instance_ids
        ).get("Reservations", [])
        target_instance_sgs = {
            str(instance.get("InstanceId")): sorted(
                group.get("GroupId")
                for group in instance.get("SecurityGroups", [])
                if group.get("GroupId")
            )
            for reservation in reservations
            for instance in reservation.get("Instances", [])
            if instance.get("InstanceId")
        }
        target_instance_private_ips = {
            str(instance.get("InstanceId")): sorted(
                {
                    str(private_ip)
                    for private_ip in [
                        instance.get("PrivateIpAddress"),
                        *(
                            address.get("PrivateIpAddress")
                            for interface in instance.get("NetworkInterfaces", [])
                            for address in interface.get("PrivateIpAddresses", [])
                        ),
                    ]
                    if private_ip
                }
            )
            for reservation in reservations
            for instance in reservation.get("Instances", [])
            if instance.get("InstanceId")
        }
        for target in targets:
            instance_id = target_to_instance_id.get(str(target.get("id")))
            asg_row = by_instance.get(str(instance_id), {})
            target.update(
                {
                    "instance_id": instance_id,
                    "asg_name": asg_row.get("AutoScalingGroupName"),
                    "lifecycle_state": asg_row.get("LifecycleState"),
                    "health_status": asg_row.get("HealthStatus"),
                    "security_group_ids": target_instance_sgs.get(str(instance_id), []),
                    "private_ip_addresses": target_instance_private_ips.get(
                        str(instance_id), []
                    ),
                }
            )
    return target_group, targets


def collect_structural(environment: str, aws: AwsCli) -> dict[str, Any]:
    if environment not in EXPECTED_ENVIRONMENT_REGIONS:
        raise InventoryError(f"unsupported relay DMZ environment {environment!r}")
    parameter_name = f"/{environment}/nhp/relay/asg-name"
    parameter = aws.call("ssm", "get-parameter", "--name", parameter_name)
    asg_name = parameter.get("Parameter", {}).get("Value")
    if not asg_name:
        raise InventoryError(f"canonical ASG parameter {parameter_name} is empty")

    # Sandbox and prod occupy separate AWS accounts, with exactly one relay
    # environment per account. The account-wide ASG/LB/target-group scans below
    # are narrowed by canonical name, ownership tags, and exact DMZ VPC identity.
    legacy_asg_name = f"layerv-nhp-{environment}-relay"
    all_groups = aws.call("autoscaling", "describe-auto-scaling-groups").get(
        "AutoScalingGroups", []
    )
    candidate_groups = [
        row
        for row in all_groups
        if row.get("AutoScalingGroupName") in {asg_name, legacy_asg_name}
        or (
            (tags := _tags(row.get("Tags"))).get("Service") == "nhp-relay"
            and tags.get("Environment") == environment
        )
    ]
    groups = [
        row for row in candidate_groups if row.get("AutoScalingGroupName") == asg_name
    ]
    if len(groups) != 1:
        error_type = RetryableInventoryError if not groups else InventoryError
        raise error_type(f"canonical ASG {asg_name!r} resolved to {len(groups)} groups")
    group = groups[0]
    asg_members = sorted(
        (
            {
                "instance_id": item.get("InstanceId"),
                "lifecycle_state": item.get("LifecycleState"),
                "health_status": item.get("HealthStatus"),
            }
            for item in group.get("Instances", [])
            if item.get("InstanceId")
        ),
        key=lambda item: str(item["instance_id"]),
    )
    instance_ids = sorted(str(item["instance_id"]) for item in asg_members)
    subnet_ids = sorted(
        filter(None, str(group.get("VPCZoneIdentifier", "")).split(","))
    )
    if not subnet_ids:
        raise InventoryError(f"canonical ASG {asg_name!r} has no VPC subnets")

    raw_subnets = aws.call("ec2", "describe-subnets", "--subnet-ids", *subnet_ids).get(
        "Subnets", []
    )
    vpc_ids = {subnet.get("VpcId") for subnet in raw_subnets}
    if len(vpc_ids) != 1:
        raise InventoryError("canonical ASG subnets do not belong to exactly one VPC")
    vpc_id = next(iter(vpc_ids))

    all_subnets = aws.call(
        "ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}"
    ).get("Subnets", [])
    route_tables = aws.call(
        "ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={vpc_id}"
    ).get("RouteTables", [])
    subnets: list[dict[str, Any]] = []
    for subnet in all_subnets:
        tags = _tags(subnet.get("Tags"))
        table = _find_route_table(subnet["SubnetId"], route_tables)
        subnets.append(
            {
                "id": subnet["SubnetId"],
                "vpc_id": subnet.get("VpcId"),
                "cidr": subnet.get("CidrBlock"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "map_public_ip_on_launch": bool(subnet.get("MapPublicIpOnLaunch")),
                "tier": tags.get("Tier"),
                "route_table_id": table.get("RouteTableId") if table else None,
                "routes": sorted(
                    (_route(route) for route in (table or {}).get("Routes", [])),
                    key=lambda item: str(item.get("destination")),
                ),
            }
        )

    instance_rows: list[dict[str, Any]] = []
    relay_sg_ids: set[str] = set()
    if instance_ids:
        # The reviewed relay capacity contract caps this at root max_capacity
        # (10 in sandbox), well below the EC2 API limit. Batch if that cap grows.
        reservations = aws.call(
            "ec2", "describe-instances", "--instance-ids", *instance_ids
        ).get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                sg_ids = sorted(
                    sg["GroupId"]
                    for sg in instance.get("SecurityGroups", [])
                    if sg.get("GroupId")
                )
                relay_sg_ids.update(sg_ids)
                ipv6 = sorted(
                    address.get("Ipv6Address")
                    for interface in instance.get("NetworkInterfaces", [])
                    for address in interface.get("Ipv6Addresses", [])
                    if address.get("Ipv6Address")
                )
                instance_rows.append(
                    {
                        "id": instance.get("InstanceId"),
                        "state": instance.get("State", {}).get("Name"),
                        "vpc_id": instance.get("VpcId"),
                        "subnet_id": instance.get("SubnetId"),
                        "private_ip": instance.get("PrivateIpAddress"),
                        "public_ip": instance.get("PublicIpAddress"),
                        "ipv6": ipv6,
                        "security_group_ids": sg_ids,
                    }
                )

    endpoints_raw = aws.call(
        "ec2", "describe-vpc-endpoints", "--filters", f"Name=vpc-id,Values={vpc_id}"
    ).get("VpcEndpoints", [])
    endpoints = sorted(
        (_normalize_endpoint(endpoint) for endpoint in endpoints_raw),
        key=lambda item: (item["service"], item["id"]),
    )
    endpoint_sg_ids = {
        sg_id
        for endpoint in endpoints
        if endpoint["type"] == "Interface"
        for sg_id in endpoint["security_group_ids"]
    }

    lbs = aws.call("elbv2", "describe-load-balancers").get("LoadBalancers", [])
    dmz_lbs = [candidate for candidate in lbs if candidate.get("VpcId") == vpc_id]
    dmz_lb_arns = [
        str(candidate["LoadBalancerArn"])
        for candidate in dmz_lbs
        if candidate.get("LoadBalancerArn")
    ]
    dmz_lb_tags: dict[str, dict[str, str]] = {}
    for offset in range(0, len(dmz_lb_arns), 20):
        tag_descriptions = aws.call(
            "elbv2",
            "describe-tags",
            "--resource-arns",
            *dmz_lb_arns[offset : offset + 20],
        ).get("TagDescriptions", [])
        dmz_lb_tags.update(
            {
                str(row.get("ResourceArn")): _tags(row.get("Tags"))
                for row in tag_descriptions
                if row.get("ResourceArn")
            }
        )
    # Intentional naming asymmetry: the replacement fleet's root module passes
    # an explicit *-relay-dmz ASG name, while modules/relay keeps its reviewed
    # public ALB contract at *-relay. The recorded collector fixture exercises
    # both names so this live lookup cannot drift silently from Terraform.
    relay_lbs = [
        lb
        for lb in lbs
        if lb.get("VpcId") == vpc_id
        and lb.get("Type") == "application"
        and lb.get("LoadBalancerName") == f"layerv-nhp-{environment}-relay"
    ]
    if len(relay_lbs) != 1:
        error_type = RetryableInventoryError if not relay_lbs else InventoryError
        raise error_type(f"relay DMZ VPC has {len(relay_lbs)} canonical ALBs")
    lb = relay_lbs[0]
    if len(dmz_lbs) != 1 or dmz_lbs[0].get("LoadBalancerArn") != lb.get(
        "LoadBalancerArn"
    ):
        raise InventoryError(
            "relay DMZ load-balancer inventory must contain exactly the canonical HTTPS ALB"
        )
    alb_sg_ids = set(lb.get("SecurityGroups", []))
    alb_attributes = {
        item.get("Key"): item.get("Value")
        for item in aws.call(
            "elbv2",
            "describe-load-balancer-attributes",
            "--load-balancer-arn",
            lb["LoadBalancerArn"],
        ).get("Attributes", [])
    }
    alb_tags = dmz_lb_tags.get(str(lb.get("LoadBalancerArn")), {})
    expected_relay_lb_arns = {str(lb.get("LoadBalancerArn"))}
    tagged_relay_lb_arns = {
        arn
        for arn, tags in dmz_lb_tags.items()
        if tags.get("Service") == "nhp-relay" and tags.get("Environment") == environment
    }
    if tagged_relay_lb_arns != expected_relay_lb_arns:
        raise InventoryError(
            "relay DMZ load-balancer inventory is not exactly the tagged HTTPS ALB"
        )
    # Exact VPC inventory plus ownership tags exclude every second public or
    # private LB, including an untagged NLB with unrelated security groups.

    all_dmz_sg_ids = sorted(relay_sg_ids | endpoint_sg_ids | alb_sg_ids)
    if not all_dmz_sg_ids:
        raise InventoryError("relay DMZ inventory resolved to no security group IDs")
    # The exact DMZ topology contains only its relay, endpoint, and ALB groups.
    # Batch this call if the reviewed singleton topology expands.
    raw_groups = aws.call(
        "ec2", "describe-security-groups", "--group-ids", *all_dmz_sg_ids
    ).get("SecurityGroups", [])
    normalized_groups = {group["GroupId"]: _normalize_sg(group) for group in raw_groups}

    requester_peers = aws.call(
        "ec2",
        "describe-vpc-peering-connections",
        "--filters",
        f"Name=requester-vpc-info.vpc-id,Values={vpc_id}",
    ).get("VpcPeeringConnections", [])
    accepter_peers = aws.call(
        "ec2",
        "describe-vpc-peering-connections",
        "--filters",
        f"Name=accepter-vpc-info.vpc-id,Values={vpc_id}",
    ).get("VpcPeeringConnections", [])
    peering_rows = list(
        {
            row.get("VpcPeeringConnectionId"): row
            for row in [*requester_peers, *accepter_peers]
            if row.get("VpcPeeringConnectionId")
        }.values()
    )
    active_peers = [
        peer for peer in peering_rows if peer.get("Status", {}).get("Code") == "active"
    ]
    if len(active_peers) != 1:
        error_type = RetryableInventoryError if not active_peers else InventoryError
        raise error_type(f"relay DMZ VPC has {len(active_peers)} active peers")
    peer = active_peers[0]
    requester = peer.get("RequesterVpcInfo", {})
    accepter = peer.get("AccepterVpcInfo", {})
    main_vpc_id = (
        accepter.get("VpcId")
        if requester.get("VpcId") == vpc_id
        else requester.get("VpcId")
    )
    if not isinstance(main_vpc_id, str) or not main_vpc_id.startswith("vpc-"):
        raise InventoryError("active relay VPC peer lacks a valid main VPC ID")
    main_vpcs = aws.call("ec2", "describe-vpcs", "--vpc-ids", main_vpc_id).get(
        "Vpcs", []
    )
    if not main_vpcs:
        raise RetryableInventoryError(f"main VPC {main_vpc_id!r} resolved to 0 VPCs")
    if len(main_vpcs) != 1:
        raise InventoryError(
            f"main VPC {main_vpc_id!r} resolved to {len(main_vpcs)} VPCs"
        )
    main_vpc = main_vpcs[0]
    cell_id = str(
        aws.call(
            "ssm",
            "get-parameter",
            "--name",
            f"/{environment}/nhp/deploy/cell-id",
        )
        .get("Parameter", {})
        .get("Value", "")
    ).strip()
    if not cell_id:
        raise RetryableInventoryError("assigned-cell deployment marker is missing")
    deploy_mode = str(
        aws.call(
            "ssm",
            "get-parameter",
            "--name",
            f"/{environment}/nhp/deploy/mode",
        )
        .get("Parameter", {})
        .get("Value", "")
    ).strip()
    if deploy_mode == "blue_green":
        active_color = str(
            aws.call(
                "ssm",
                "get-parameter",
                "--name",
                f"/{environment}/nhp/server/active-color",
            )
            .get("Parameter", {})
            .get("Value", "")
        ).strip()
    elif deploy_mode == "canary":
        # Canary/static deployments have only the canonical blue ASG/TGs and do
        # not create the blue-green active-color parameter.
        active_color = "blue"
    else:
        raise RetryableInventoryError(
            f"server deployment-mode marker is invalid: {deploy_mode!r}"
        )
    if active_color not in {"blue", "green"}:
        raise RetryableInventoryError(
            f"server active-color marker is invalid: {active_color!r}"
        )

    # Upcoming UDP SDKs connect directly to the NHP server NLB of their assigned
    # cell. Inventory every public NLB in the peered main VPC, but classify only
    # canonical or NHP-owned edges so an unrelated product NLB remains out of
    # scope while a second compute/cell NHP edge fails closed.
    expected_server_lb_name = f"layerv-nhp-{environment}-nlb"
    canonical_server_lbs = [
        candidate
        for candidate in lbs
        if candidate.get("VpcId") == main_vpc_id
        and candidate.get("Scheme") == "internet-facing"
        and candidate.get("Type") == "network"
        and candidate.get("LoadBalancerName") == expected_server_lb_name
    ]
    if len(canonical_server_lbs) != 1:
        error_type = (
            RetryableInventoryError if not canonical_server_lbs else InventoryError
        )
        raise error_type(
            f"main VPC has {len(canonical_server_lbs)} canonical assigned-cell NHP NLBs"
        )
    canonical_server_lb_arn = str(canonical_server_lbs[0]["LoadBalancerArn"])
    expected_internal_lb_name = f"layerv-nhp-{environment}-srv-int"
    internal_server_lbs = [
        candidate
        for candidate in lbs
        if candidate.get("VpcId") == main_vpc_id
        and candidate.get("Scheme") == "internal"
        and candidate.get("Type") == "network"
        and candidate.get("LoadBalancerName") == expected_internal_lb_name
    ]
    if len(internal_server_lbs) != 1:
        error_type = (
            RetryableInventoryError if not internal_server_lbs else InventoryError
        )
        raise error_type(
            f"main VPC has {len(internal_server_lbs)} canonical internal relay NHP NLBs"
        )
    internal_server_lb_arn = str(internal_server_lbs[0]["LoadBalancerArn"])
    public_main_nlbs = [
        candidate
        for candidate in lbs
        if candidate.get("VpcId") == main_vpc_id
        and candidate.get("Scheme") == "internet-facing"
        and candidate.get("Type") == "network"
    ]
    inventoried_main_nlb_arns = [
        str(candidate["LoadBalancerArn"])
        for candidate in [*public_main_nlbs, *internal_server_lbs]
        if candidate.get("LoadBalancerArn")
    ]
    main_nlb_tags: dict[str, dict[str, str]] = {}
    if inventoried_main_nlb_arns:
        for offset in range(0, len(inventoried_main_nlb_arns), 20):
            tag_descriptions = aws.call(
                "elbv2",
                "describe-tags",
                "--resource-arns",
                *inventoried_main_nlb_arns[offset : offset + 20],
            ).get("TagDescriptions", [])
            main_nlb_tags.update(
                {
                    str(row.get("ResourceArn")): _tags(row.get("Tags"))
                    for row in tag_descriptions
                    if row.get("ResourceArn")
                }
            )
    # Listener wiring is part of NHP ownership. An untagged/arbitrarily named
    # public NLB forwarding to the canonical server TG is still an NHP edge and
    # must not evade the one-port contract. Inventory listeners on every public
    # main-VPC NLB before classifying unrelated product edges.
    public_listener_rows_by_lb: dict[str, list[dict[str, Any]]] = {}
    for candidate in public_main_nlbs:
        candidate_arn = candidate.get("LoadBalancerArn")
        if not isinstance(candidate_arn, str) or not candidate_arn:
            raise InventoryError(
                "internet-facing main-VPC network load balancer lacks an ARN"
            )
        public_listener_rows_by_lb[candidate_arn] = aws.call(
            "elbv2", "describe-listeners", "--load-balancer-arn", candidate_arn
        ).get("Listeners", [])
    public_udp_target_groups: dict[
        str, tuple[dict[str, Any] | None, list[dict[str, Any]]]
    ] = {}
    for public_listener_rows in public_listener_rows_by_lb.values():
        for listener in public_listener_rows:
            if str(listener.get("Protocol") or "").upper() not in {
                "UDP",
                "TCP_UDP",
            }:
                continue
            for action in listener.get("DefaultActions", []):
                target_group_arn = action.get("TargetGroupArn")
                if action.get("Type") != "forward" or not isinstance(
                    target_group_arn, str
                ):
                    continue
                if target_group_arn not in public_udp_target_groups:
                    public_udp_target_groups[target_group_arn] = (
                        _collect_udp_target_group(aws, target_group_arn)
                    )
    canonical_target_group_arns = {
        str(action.get("TargetGroupArn"))
        for listener in public_listener_rows_by_lb.get(canonical_server_lb_arn, [])
        if str(listener.get("Protocol") or "").upper() in {"UDP", "TCP_UDP"}
        for action in listener.get("DefaultActions", [])
        if action.get("Type") == "forward" and action.get("TargetGroupArn")
    }
    expected_server_asg_names = {
        f"layerv-nhp-{environment}-server",
        f"layerv-nhp-{environment}-server-green",
    }
    canonical_server_targets = [
        target
        for target_group_arn in canonical_target_group_arns
        for target in public_udp_target_groups.get(target_group_arn, (None, []))[1]
    ]
    canonical_server_security_group_ids = {
        str(security_group_id)
        for target in canonical_server_targets
        for security_group_id in target.get("security_group_ids", [])
        if security_group_id
    }
    canonical_server_private_ips = {
        str(private_ip)
        for target in canonical_server_targets
        for private_ip in [
            *target.get("private_ip_addresses", []),
            target.get("id") if _valid_ip_address(str(target.get("id", ""))) else None,
        ]
        if private_ip
    }

    def has_assigned_cell_target_ownership(target_group_arn: str) -> bool:
        target_group, targets = public_udp_target_groups.get(
            target_group_arn, (None, [])
        )
        tags = target_group.get("tags", {}) if isinstance(target_group, dict) else {}
        tagged_for_cell = (
            tags.get("Environment") == environment
            and tags.get("Component") == "compute"
            and tags.get("Cell") == cell_id
        )
        has_canonical_target = any(
            target.get("asg_name") in expected_server_asg_names
            or bool(
                set(target.get("security_group_ids", []))
                & canonical_server_security_group_ids
            )
            or str(target.get("id")) in canonical_server_private_ips
            for target in targets
        )
        return tagged_for_cell or has_canonical_target

    assigned_cell_nhp_listeners: list[dict[str, Any]] = []
    for candidate in public_main_nlbs:
        load_balancer_arn = candidate.get("LoadBalancerArn")
        if not isinstance(load_balancer_arn, str) or not load_balancer_arn:
            raise InventoryError(
                "internet-facing main-VPC network load balancer lacks an ARN"
            )
        load_balancer_tags = main_nlb_tags.get(str(load_balancer_arn), {})
        public_listener_rows = public_listener_rows_by_lb[load_balancer_arn]
        shares_canonical_target = any(
            str(action.get("TargetGroupArn")) in canonical_target_group_arns
            for listener in public_listener_rows
            if str(listener.get("Protocol") or "").upper() in {"UDP", "TCP_UDP"}
            for action in listener.get("DefaultActions", [])
            if action.get("Type") == "forward" and action.get("TargetGroupArn")
        )
        owns_distinct_server_target = any(
            has_assigned_cell_target_ownership(str(action.get("TargetGroupArn")))
            for listener in public_listener_rows
            if str(listener.get("Protocol") or "").upper() in {"UDP", "TCP_UDP"}
            for action in listener.get("DefaultActions", [])
            if action.get("Type") == "forward" and action.get("TargetGroupArn")
        )
        nhp_owned = (
            load_balancer_arn == canonical_server_lb_arn
            or (
                load_balancer_tags.get("Environment") == environment
                and (
                    load_balancer_tags.get("Component") == "compute"
                    or load_balancer_tags.get("Cell") == cell_id
                )
            )
            or str(candidate.get("LoadBalancerName", "")).startswith(
                f"layerv-nhp-{environment}-"
            )
            or shares_canonical_target
            or owns_distinct_server_target
        )
        if not nhp_owned:
            continue
        for listener in public_listener_rows:
            port = _exact_nonnegative_int(listener.get("Port"))
            protocol = str(listener.get("Protocol") or "").upper()
            if protocol in {"UDP", "TCP_UDP"}:
                actions = listener.get("DefaultActions", [])
                forward_actions = [
                    action
                    for action in actions
                    if action.get("Type") == "forward" and action.get("TargetGroupArn")
                ]
                target_group_arn = (
                    str(forward_actions[0]["TargetGroupArn"])
                    if len(forward_actions) == 1
                    else None
                )
                target_group = None
                targets: list[dict[str, Any]] = []
                if target_group_arn:
                    target_group, targets = public_udp_target_groups.get(
                        target_group_arn, (None, [])
                    )
                assigned_cell_nhp_listeners.append(
                    {
                        "load_balancer_arn": load_balancer_arn,
                        "load_balancer_name": candidate.get("LoadBalancerName"),
                        "load_balancer_tags": load_balancer_tags,
                        "canonical": load_balancer_arn == canonical_server_lb_arn,
                        "listener_arn": listener.get("ListenerArn"),
                        "protocol": protocol,
                        "port": port,
                        "target_group_arn": target_group_arn,
                        "target_group": target_group,
                        "targets": targets,
                    }
                )

    internal_cell_nhp_listeners: list[dict[str, Any]] = []
    internal_candidate = internal_server_lbs[0]
    internal_listener_rows = aws.call(
        "elbv2",
        "describe-listeners",
        "--load-balancer-arn",
        internal_server_lb_arn,
    ).get("Listeners", [])
    for listener in internal_listener_rows:
        actions = listener.get("DefaultActions", [])
        forward_actions = [
            action
            for action in actions
            if action.get("Type") == "forward" and action.get("TargetGroupArn")
        ]
        target_group_arn = (
            str(forward_actions[0]["TargetGroupArn"])
            if len(forward_actions) == 1
            else None
        )
        target_group = None
        targets: list[dict[str, Any]] = []
        if target_group_arn:
            target_group, targets = _collect_udp_target_group(aws, target_group_arn)
        internal_cell_nhp_listeners.append(
            {
                "load_balancer_arn": internal_server_lb_arn,
                "load_balancer_name": internal_candidate.get("LoadBalancerName"),
                "load_balancer_tags": main_nlb_tags.get(internal_server_lb_arn, {}),
                "canonical": True,
                "listener_arn": listener.get("ListenerArn"),
                "protocol": str(listener.get("Protocol") or "").upper(),
                "port": _exact_nonnegative_int(listener.get("Port")),
                "target_group_arn": target_group_arn,
                "target_group": target_group,
                "targets": targets,
            }
        )
    dmz_peer_info = requester if requester.get("VpcId") == vpc_id else accepter
    main_peer_info = accepter if requester.get("VpcId") == vpc_id else requester

    main_subnets = aws.call(
        "ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={main_vpc_id}"
    ).get("Subnets", [])
    main_route_tables_raw = aws.call(
        "ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={main_vpc_id}"
    ).get("RouteTables", [])
    main_private_routes: list[dict[str, Any]] = []
    for subnet in main_subnets:
        if _tags(subnet.get("Tags")).get("Type") != "private":
            continue
        table = _find_route_table(subnet["SubnetId"], main_route_tables_raw)
        main_private_routes.append(
            {
                "subnet_id": subnet.get("SubnetId"),
                "cidr": subnet.get("CidrBlock"),
                "route_table_id": table.get("RouteTableId") if table else None,
                "route_table_tags": _tags((table or {}).get("Tags")),
                "routes": sorted(
                    (_route(route) for route in (table or {}).get("Routes", [])),
                    key=lambda item: str(item.get("destination")),
                ),
            }
        )

    # Informational stale-resource inventory only: these are intentionally found
    # by the legacy operator tag because they have no canonical identity to join.
    # Boundary decisions use the exact canonical SG IDs collected separately.
    legacy_main_vpc_security_groups = aws.call(
        "ec2",
        "describe-security-groups",
        "--filters",
        f"Name=vpc-id,Values={main_vpc_id}",
        "Name=tag:Service,Values=nhp-relay",
    ).get("SecurityGroups", [])

    relay_network_interfaces: list[dict[str, Any]] = []
    if subnet_ids:
        eni_rows = aws.call(
            "ec2",
            "describe-network-interfaces",
            "--filters",
            f"Name=subnet-id,Values={','.join(subnet_ids)}",
        ).get("NetworkInterfaces", [])
        relay_network_interfaces = [
            {
                "id": interface.get("NetworkInterfaceId"),
                "subnet_id": interface.get("SubnetId"),
                "private_ip": interface.get("PrivateIpAddress"),
                "public_ip": interface.get("Association", {}).get("PublicIp"),
                "ipv6": sorted(
                    address.get("Ipv6Address")
                    for address in interface.get("Ipv6Addresses", [])
                    if address.get("Ipv6Address")
                ),
                "security_group_ids": sorted(
                    group.get("GroupId")
                    for group in interface.get("Groups", [])
                    if group.get("GroupId")
                ),
                "status": interface.get("Status"),
            }
            for interface in eni_rows
        ]

    server_sg_ids: set[str] = set()
    for sg_id in relay_sg_ids:
        for rule in normalized_groups.get(sg_id, {}).get("inbound", []):
            if (
                rule.get("protocol") == "udp"
                and rule.get("from") == RELAY_ACK_UDP_PORT
                and rule.get("to") == RELAY_ACK_UDP_PORT
                and rule.get("source_type") == "security_group"
            ):
                source = rule.get("source")
                if source:
                    server_sg_ids.add(source)
    if server_sg_ids:
        server_groups = aws.call(
            "ec2", "describe-security-groups", "--group-ids", *sorted(server_sg_ids)
        ).get("SecurityGroups", [])
        normalized_groups.update(
            {group["GroupId"]: _normalize_sg(group) for group in server_groups}
        )

    listeners_raw = aws.call(
        "elbv2", "describe-listeners", "--load-balancer-arn", lb["LoadBalancerArn"]
    ).get("Listeners", [])
    listeners: list[dict[str, Any]] = []
    target_group_arns: set[str] = set()
    for listener in listeners_raw:
        rules_raw = aws.call(
            "elbv2", "describe-rules", "--listener-arn", listener["ListenerArn"]
        ).get("Rules", [])
        rules: list[dict[str, Any]] = []
        for rule in rules_raw:
            actions = rule.get("Actions", [])
            for action in actions:
                if action.get("TargetGroupArn"):
                    target_group_arns.add(action["TargetGroupArn"])
                for target in action.get("ForwardConfig", {}).get("TargetGroups", []):
                    if target.get("TargetGroupArn"):
                        target_group_arns.add(target["TargetGroupArn"])
            rules.append(
                {
                    "is_default": bool(rule.get("IsDefault")),
                    "priority": rule.get("Priority"),
                    "conditions": rule.get("Conditions", []),
                    "actions": actions,
                }
            )
        listeners.append(
            {
                "arn": listener.get("ListenerArn"),
                "port": listener.get("Port"),
                "protocol": listener.get("Protocol"),
                "ssl_policy": listener.get("SslPolicy"),
                "rules": rules,
            }
        )
    target_groups: list[dict[str, Any]] = []
    if target_group_arns:
        # The passing listener contract has one browser target group; over-limit
        # drift fails collection closed. Batch if the supported contract expands.
        target_group_rows = aws.call(
            "elbv2",
            "describe-target-groups",
            "--target-group-arns",
            *sorted(target_group_arns),
        ).get("TargetGroups", [])
        target_groups = [
            {
                "arn": row.get("TargetGroupArn"),
                "vpc_id": row.get("VpcId"),
                "protocol": row.get("Protocol"),
                "port": row.get("Port"),
                "target_type": row.get("TargetType"),
                "health_check_enabled": row.get("HealthCheckEnabled"),
                "health_check_protocol": row.get("HealthCheckProtocol"),
                "health_check_port": row.get("HealthCheckPort"),
                "health_check_path": row.get("HealthCheckPath"),
                "health_check_matcher": row.get("Matcher", {}).get("HttpCode"),
                "healthy_threshold": row.get("HealthyThresholdCount"),
                "unhealthy_threshold": row.get("UnhealthyThresholdCount"),
                "health_check_interval": row.get("HealthCheckIntervalSeconds"),
                "health_check_timeout": row.get("HealthCheckTimeoutSeconds"),
            }
            for row in target_group_rows
        ]
    # aws_lb_target_group.relay uses Terraform name_prefix="rlytls" and AWS
    # appends the unique suffix. AWS limits name_prefix to six characters, so it
    # cannot carry the environment. Keep the prefix in lockstep with Terraform;
    # the validator scopes canonical/orphan decisions by exact VPC identity.
    all_relay_target_groups = [
        row
        for row in aws.call("elbv2", "describe-target-groups").get("TargetGroups", [])
        if str(row.get("TargetGroupName", "")).startswith(RELAY_TG_NAME_PREFIX)
    ]
    try:
        waf = aws.call(
            "wafv2", "get-web-acl-for-resource", "--resource-arn", lb["LoadBalancerArn"]
        ).get("WebACL", {})
    except InventoryError as exc:
        # aws wafv2 reports an absent association through stderr; AwsCli wraps
        # that text in InventoryError. This explicit CLI-format dependency is
        # fail-closed: any unrecognized wording remains an operational error.
        # AwsCli includes the final raw stderr line in InventoryError, and this
        # bare re-raise preserves it for the operator when the token changes.
        # Revalidate the token after every AWS CLI major-version upgrade.
        if "WAFNonexistentItemException" not in str(exc):
            raise
        waf = {}

    flow_logs = aws.call(
        "ec2", "describe-flow-logs", "--filter", f"Name=resource-id,Values={vpc_id}"
    ).get("FlowLogs", [])
    expected_log_group_names = _expected_security_log_group_names(environment)
    raw_log_groups = aws.call(
        "logs",
        "describe-log-groups",
        "--log-group-name-prefix",
        f"/layerv/nhp/{environment}/relay-dmz/",
    ).get("logGroups", [])
    security_log_groups: dict[str, dict[str, Any]] = {}
    for purpose, name in expected_log_group_names.items():
        matches = [row for row in raw_log_groups if row.get("logGroupName") == name]
        if len(matches) == 1:
            row = matches[0]
            security_log_groups[purpose] = {
                "name": name,
                "arn": row.get("logGroupArn")
                or str(row.get("arn", "")).removesuffix(":*"),
                "kms_key_id": row.get("kmsKeyId"),
                "retention_in_days": row.get("retentionInDays"),
            }
    log_kms_key_ids = _log_group_kms_key_ids(security_log_groups)
    logs_kms_policy: dict[str, Any] = {}
    if len(log_kms_key_ids) == 1:
        policy_response = aws.call(
            "kms",
            "get-key-policy",
            "--key-id",
            next(iter(log_kms_key_ids)),
            "--policy-name",
            "default",
        )
        logs_kms_policy = _decode_policy(policy_response.get("Policy"))

    firewall_associations = aws.call(
        "route53resolver", "list-firewall-rule-group-associations", "--vpc-id", vpc_id
    ).get("FirewallRuleGroupAssociations", [])
    resolver_associations: list[dict[str, Any]] = []
    for association in firewall_associations:
        rules_raw = aws.call(
            "route53resolver",
            "list-firewall-rules",
            "--firewall-rule-group-id",
            association["FirewallRuleGroupId"],
        ).get("FirewallRules", [])
        rules: list[dict[str, Any]] = []
        for rule in rules_raw:
            domains: list[str] = []
            if rule.get("FirewallDomainListId"):
                domains = aws.call(
                    "route53resolver",
                    "list-firewall-domains",
                    "--firewall-domain-list-id",
                    rule["FirewallDomainListId"],
                ).get("Domains", [])
            rules.append(
                {
                    "action": rule.get("Action"),
                    "priority": rule.get("Priority"),
                    "dns_threat_protection": rule.get("DnsThreatProtection"),
                    "confidence_threshold": rule.get("ConfidenceThreshold"),
                    "block_response": rule.get("BlockResponse"),
                    "redirection_action": rule.get("FirewallDomainRedirectionAction"),
                    "domains": sorted(domains),
                }
            )
        resolver_associations.append(
            {
                "id": association.get("Id"),
                "status": association.get("Status"),
                "mutation_protection": association.get("MutationProtection"),
                "priority": association.get("Priority"),
                "rules": sorted(rules, key=lambda item: int(item.get("priority") or 0)),
            }
        )
    firewall_config = aws.call(
        "route53resolver", "get-firewall-config", "--resource-id", vpc_id
    ).get("FirewallConfig", {})
    query_associations = aws.call(
        "route53resolver",
        "list-resolver-query-log-config-associations",
        "--filters",
        f"Name=ResourceId,Values={vpc_id}",
    ).get("ResolverQueryLogConfigAssociations", [])
    query_configs: list[dict[str, Any]] = []
    for association in query_associations:
        config = aws.call(
            "route53resolver",
            "get-resolver-query-log-config",
            "--resolver-query-log-config-id",
            association["ResolverQueryLogConfigId"],
        ).get("ResolverQueryLogConfig", {})
        query_configs.append(
            {
                "association_status": association.get("Status"),
                "status": config.get("Status"),
                "destination_arn": config.get("DestinationArn"),
                "name": config.get("Name"),
            }
        )

    identity = aws.call("sts", "get-caller-identity")
    vpcs = aws.call("ec2", "describe-vpcs", "--vpc-ids", vpc_id).get("Vpcs", [])
    if not vpcs:
        raise RetryableInventoryError(f"relay DMZ VPC {vpc_id!r} resolved to 0 VPCs")
    if len(vpcs) != 1:
        raise InventoryError(f"relay DMZ VPC {vpc_id!r} resolved to {len(vpcs)} VPCs")
    vpc = vpcs[0]
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": environment,
        "region": aws.region,
        "account_id": identity.get("Account"),
        "cell_id": cell_id,
        "server_deploy_mode": deploy_mode,
        "server_active_color": active_color,
        "canonical_asg": {
            "name": asg_name,
            "vpc_id": vpc_id,
            "subnet_ids": subnet_ids,
            "instance_ids": instance_ids,
            "members": asg_members,
            "min_size": group.get("MinSize"),
            "desired_capacity": group.get("DesiredCapacity"),
            "target_group_arns": sorted(group.get("TargetGroupARNs", [])),
        },
        "orphaned_legacy_resources": {
            "asgs": sorted(
                str(row.get("AutoScalingGroupName"))
                for row in candidate_groups
                if row.get("AutoScalingGroupName") != asg_name
            ),
            "main_vpc_security_groups": sorted(
                str(row.get("GroupId")) for row in legacy_main_vpc_security_groups
            ),
            "target_groups": sorted(
                str(row.get("TargetGroupArn"))
                for row in all_relay_target_groups
                # The reviewed pre-DMZ topology placed relay target groups in
                # the main VPC. Also reject unattached relay-prefixed groups in
                # the DMZ VPC; only the two listener-referenced canonical groups
                # may remain there. Other VPCs are outside this environment's
                # contract.
                if row.get("VpcId") == main_vpc_id
                or (
                    row.get("VpcId") == vpc_id
                    and row.get("TargetGroupArn") not in target_group_arns
                )
            ),
        },
        "assigned_cell_nhp_listeners": sorted(
            assigned_cell_nhp_listeners,
            key=lambda row: (
                str(row.get("load_balancer_arn")),
                str(row.get("listener_arn")),
            ),
        ),
        "internal_cell_nhp_listeners": sorted(
            internal_cell_nhp_listeners,
            key=lambda row: str(row.get("listener_arn")),
        ),
        "vpc": {
            "id": vpc_id,
            "cidr": vpc.get("CidrBlock"),
            "ipv4_cidr_associations": sorted(
                [
                    {
                        "cidr": row.get("CidrBlock"),
                        "state": row.get("CidrBlockState", {}).get("State"),
                    }
                    for row in vpc.get("CidrBlockAssociationSet", [])
                    if row.get("CidrBlockState", {}).get("State") != "failed"
                ],
                key=lambda row: str(row["cidr"]),
            ),
            "ipv6_cidr_associations": sorted(
                [
                    {
                        "cidr": row.get("Ipv6CidrBlock"),
                        "state": row.get("Ipv6CidrBlockState", {}).get("State"),
                    }
                    for row in vpc.get("Ipv6CidrBlockAssociationSet", [])
                    if row.get("Ipv6CidrBlockState", {}).get("State") != "failed"
                ],
                key=lambda row: str(row["cidr"]),
            ),
        },
        "peer": {
            "id": peer.get("VpcPeeringConnectionId"),
            "active_peer_count": len(active_peers),
            "main_vpc_id": main_vpc_id,
            # The reviewed topology places all server private subnets in the
            # VPC primary CIDR. Secondary-CIDR server placement is intentionally
            # unsupported until its routes and SG sources are reviewed together.
            "main_vpc_cidr": main_vpc.get("CidrBlock"),
            "dmz_dns_resolution": bool(
                dmz_peer_info.get("PeeringOptions", {}).get(
                    "AllowDnsResolutionFromRemoteVpc"
                )
            ),
            "main_dns_resolution": bool(
                main_peer_info.get("PeeringOptions", {}).get(
                    "AllowDnsResolutionFromRemoteVpc"
                )
            ),
        },
        "subnets": sorted(subnets, key=lambda item: item["id"]),
        "main_private_routes": sorted(
            main_private_routes, key=lambda item: item["subnet_id"]
        ),
        "instances": sorted(instance_rows, key=lambda item: item["id"]),
        "relay_network_interfaces": sorted(
            relay_network_interfaces, key=lambda item: item["id"]
        ),
        "security_groups": {
            "relay_ids": sorted(relay_sg_ids),
            "endpoint_ids": sorted(endpoint_sg_ids),
            "alb_ids": sorted(alb_sg_ids),
            "server_ids": sorted(server_sg_ids),
            "by_id": normalized_groups,
        },
        "endpoints": endpoints,
        "flow_logs": [
            {
                "id": row.get("FlowLogId"),
                "traffic_type": row.get("TrafficType"),
                "flow_log_status": row.get("FlowLogStatus"),
                "delivery_status": row.get("DeliverLogsStatus"),
                "destination_type": row.get("LogDestinationType"),
                "destination_arn": row.get("LogDestination"),
                "max_aggregation_interval": row.get("MaxAggregationInterval"),
                "log_format": row.get("LogFormat"),
            }
            for row in flow_logs
        ],
        "security_log_groups": security_log_groups,
        "logs_kms_policy": logs_kms_policy,
        "resolver": {
            "firewall_fail_open": firewall_config.get("FirewallFailOpen"),
            "firewall_associations": resolver_associations,
            "query_log_configs": query_configs,
        },
        "alb": {
            "arn": lb.get("LoadBalancerArn"),
            "name": lb.get("LoadBalancerName"),
            "vpc_id": lb.get("VpcId"),
            "scheme": lb.get("Scheme"),
            "type": lb.get("Type"),
            "tags": alb_tags,
            "deletion_protection_enabled": alb_attributes.get(
                "deletion_protection.enabled"
            ),
            "idle_timeout_seconds": alb_attributes.get("idle_timeout.timeout_seconds"),
            "drop_invalid_headers_enabled": alb_attributes.get(
                "routing.http.drop_invalid_header_fields.enabled"
            ),
            "desync_mitigation_mode": alb_attributes.get(
                "routing.http.desync_mitigation_mode"
            ),
            "xff_header_processing_mode": alb_attributes.get(
                "routing.http.xff_header_processing.mode"
            ),
            "xff_client_port_enabled": alb_attributes.get(
                "routing.http.xff_client_port.enabled"
            ),
            "waf_fail_open_enabled": alb_attributes.get("waf.fail_open.enabled"),
            "access_logs_enabled": alb_attributes.get("access_logs.s3.enabled"),
            "access_logs_bucket": alb_attributes.get("access_logs.s3.bucket"),
            "access_logs_prefix": alb_attributes.get("access_logs.s3.prefix"),
            "security_group_ids": sorted(lb.get("SecurityGroups", [])),
            "listeners": listeners,
            "target_group_arns": sorted(target_group_arns),
            "target_groups": sorted(target_groups, key=lambda item: item["arn"]),
            "waf_arn": waf.get("ARN"),
        },
    }


def _statement_actions(statement: dict[str, Any]) -> set[str]:
    return {str(action) for action in _as_list(statement.get("Action"))}


def _statement_resources(statement: dict[str, Any]) -> set[str]:
    return {str(resource) for resource in _as_list(statement.get("Resource"))}


def _resources_for_action(policy: dict[str, Any], action: str) -> set[str]:
    resources: set[str] = set()
    for statement in _as_list(policy.get("Statement")):
        if statement.get("Effect") != "Allow":
            continue
        if action in _statement_actions(statement):
            resources.update(_statement_resources(statement))
    return resources


def _has_cross_account_deny(policy: dict[str, Any], account_id: str) -> bool:
    # VPC endpoint policies retain the authored Principal shape. The Terraform
    # plan checker (`is_cross_account_deny` and endpoint allow checks) also pins
    # the bare string "*" deliberately. Semantically equivalent {"AWS": "*"}
    # is rejected by both layers so an authoring-shape drift is loud and
    # reviewable instead of one checker accepting what the other rejects.
    for statement in _as_list(policy.get("Statement")):
        if (
            statement.get("Effect") == "Deny"
            and statement.get("Principal") == "*"
            and _statement_actions(statement) == {"*"}
            and _statement_resources(statement) == {"*"}
            and statement.get("Condition")
            == {"StringNotEquals": {"aws:PrincipalAccount": account_id}}
        ):
            return True
    return False


def _semantic_statement(statement: dict[str, Any]) -> dict[str, Any]:
    """Drop non-semantic labels while preserving the complete permission shape."""
    return {key: value for key, value in statement.items() if key != "Sid"}


def _expected_s3_resources(region: str) -> set[str]:
    return {
        f"arn:aws:s3:::prod-{region}-starport-layer-bucket/*",
        f"arn:aws:s3:::amazon-ssm-{region}/*",
        f"arn:aws:s3:::aws-ssm-{region}/*",
        f"arn:aws:s3:::{region}-birdwatcher-prod/*",
        f"arn:aws:s3:::aws-ssm-document-attachments-{region}/*",
    }


def _expected_security_log_group_names(environment: str) -> dict[str, str]:
    prefix = f"/layerv/nhp/{environment}/relay-dmz"
    return {"flow": f"{prefix}/flow", "resolver": f"{prefix}/resolver"}


def _log_group_kms_key_ids(
    security_log_groups: dict[str, dict[str, Any]],
) -> set[str]:
    return {
        str(row["kms_key_id"])
        for row in security_log_groups.values()
        if row.get("kms_key_id")
    }


def _expected_dns_domains(region: str) -> set[str]:
    return {
        f"api.ecr.{region}.amazonaws.com",
        f"*.dkr.ecr.{region}.amazonaws.com",
        f"secretsmanager.{region}.amazonaws.com",
        f"ssm.{region}.amazonaws.com",
        f"ssmmessages.{region}.amazonaws.com",
        f"logs.{region}.amazonaws.com",
        f"monitoring.{region}.amazonaws.com",
        f"guardduty-data.{region}.amazonaws.com",
        f"s3.{region}.amazonaws.com",
        f"*.s3.{region}.amazonaws.com",
        f"*.elb.{region}.amazonaws.com",
    }


def _rules_equal(
    actual: Iterable[dict[str, Any]], expected: Iterable[dict[str, Any]]
) -> bool:
    return sorted((_rule_key(rule) for rule in actual)) == sorted(
        (_rule_key(rule) for rule in expected)
    )


def _rule_covers_udp_port(rule: dict[str, Any], port: int) -> bool:
    protocol = str(rule.get("protocol", "")).lower()
    if protocol in {"-1", "all"}:
        return True
    if protocol != "udp":
        return False
    from_port = rule.get("from")
    to_port = rule.get("to")
    if from_port is None or to_port is None:
        return True
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return True


def _route_key(route: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(route.get("destination")),
        str(route.get("target_type")),
        str(route.get("target")),
        str(route.get("state")),
    )


def validate_structural(snapshot: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    environment = snapshot.get("environment")
    region = snapshot.get("region")
    account_id = snapshot.get("account_id")
    # Structural validation uses account_id only in exact ARN/policy string
    # comparisons, which fail closed for malformed values. collect_functional
    # applies _require_account_id because it interpolates the value into an SSM
    # shell command; that stricter check is injection-scoped.
    asg = snapshot.get("canonical_asg", {})
    vpc = snapshot.get("vpc", {})
    peer = snapshot.get("peer", {})
    network_contract = RELAY_DMZ_NETWORK_CONTRACTS.get(str(environment))
    try:
        _require_expected_environment_region(str(environment), str(region))
    except InventoryError as exc:
        errors.append(str(exc))
    if network_contract is None:
        errors.append(f"snapshot environment {environment!r} has no DMZ CIDR contract")
        network_contract = {
            "vpc": None,
            "public-alb": set(),
            "isolated-relay": set(),
            "isolated-endpoint": set(),
        }

    if snapshot.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"snapshot schema_version must be {SCHEMA_VERSION}")
    deploy_mode = snapshot.get("server_deploy_mode")
    active_color = snapshot.get("server_active_color")
    if deploy_mode not in {"blue_green", "canary"}:
        errors.append("server deployment mode must be exactly blue_green or canary")
    elif deploy_mode == "canary" and active_color != "blue":
        errors.append("canary server deployment must use the canonical blue ASG/TGs")
    if asg.get("name") != f"layerv-nhp-{environment}-relay-dmz":
        errors.append(
            "canonical relay ASG parameter does not point to the DMZ-named ASG"
        )
    if asg.get("vpc_id") != vpc.get("id"):
        errors.append("canonical relay ASG is not in the inventoried DMZ VPC")
    expected_vpc_cidr = network_contract["vpc"]
    if vpc.get("cidr") != expected_vpc_cidr:
        errors.append(
            f"relay DMZ VPC does not use the reviewed {environment} "
            f"{expected_vpc_cidr} CIDR"
        )
    if vpc.get("ipv4_cidr_associations") != [
        {"cidr": expected_vpc_cidr, "state": "associated"}
    ]:
        errors.append("relay DMZ VPC has an unexpected secondary IPv4 CIDR")
    if vpc.get("ipv6_cidr_associations"):
        errors.append("relay DMZ VPC has an unexpected IPv6 CIDR")
    main_vpc_cidr = peer.get("main_vpc_cidr")
    main_vpc_cidr_valid = isinstance(main_vpc_cidr, str) and bool(main_vpc_cidr)
    if (
        not peer.get("id")
        or not peer.get("main_vpc_id")
        or peer.get("active_peer_count") != 1
    ):
        errors.append("DMZ does not have exactly one inventoried active main-VPC peer")
    if not main_vpc_cidr_valid:
        errors.append("active main-VPC peer has a missing or invalid main VPC CIDR")
    if not peer.get("dmz_dns_resolution") or not peer.get("main_dns_resolution"):
        errors.append("VPC peering DNS resolution is not enabled in both directions")

    subnets = snapshot.get("subnets", [])
    if len(subnets) != 9:
        errors.append(f"DMZ must contain exactly nine subnets (found {len(subnets)})")
    tiers = {tier: [] for tier in ("public-alb", "isolated-relay", "isolated-endpoint")}
    for subnet in subnets:
        if subnet.get("tier") in tiers:
            tiers[subnet["tier"]].append(subnet)
        else:
            errors.append(
                f"DMZ subnet {subnet.get('id')} has an unrecognized or missing Tier tag"
            )
    for tier, rows in tiers.items():
        if len(rows) != 3:
            errors.append(
                f"DMZ must have exactly three {tier} subnets (found {len(rows)})"
            )
        if any(row.get("map_public_ip_on_launch") for row in rows):
            errors.append(f"{tier} subnets must disable map_public_ip_on_launch")
        if {row.get("cidr") for row in rows} != network_contract[tier]:
            errors.append(f"{tier} subnet CIDRs differ from the reviewed contract")

    relay_subnets = tiers["isolated-relay"]
    endpoint_subnets = tiers["isolated-endpoint"]
    public_subnets = tiers["public-alb"]
    relay_cidrs = {row.get("cidr") for row in relay_subnets}
    endpoint_subnet_ids = {row.get("id") for row in endpoint_subnets}
    public_route_table_ids = {row.get("route_table_id") for row in public_subnets}
    relay_route_table_ids = {row.get("route_table_id") for row in relay_subnets}
    endpoint_route_table_ids = {row.get("route_table_id") for row in endpoint_subnets}
    if len(public_route_table_ids) != 1:
        errors.append("public ALB subnets must share exactly one public route table")
    if len(relay_route_table_ids) != 3:
        errors.append("relay subnets must use three distinct relay route tables")
    if len(endpoint_route_table_ids) != 3:
        errors.append(
            "endpoint subnets must use three distinct local-only route tables"
        )
    if relay_route_table_ids & endpoint_route_table_ids:
        errors.append("relay and endpoint subnets share a route table")
    for tier, rows in (("relay", relay_subnets), ("endpoint", endpoint_subnets)):
        for row in rows:
            for route in row.get("routes", []):
                if route.get("destination") in {"0.0.0.0/0", "::/0"}:
                    errors.append(f"{tier} subnet {row.get('id')} has a default route")
                if route.get("target_type") == "nat":
                    errors.append(f"{tier} subnet {row.get('id')} has a NAT route")

    main_destination_sets = []
    for row in relay_subnets:
        destinations = {
            route.get("destination")
            for route in row.get("routes", [])
            if route.get("target_type") == "peering"
            and route.get("target") == peer.get("id")
        }
        main_destination_sets.append(destinations)
    main_route_destinations = (
        main_destination_sets[0] if main_destination_sets else set()
    )
    main_routes_identical = bool(main_destination_sets) and all(
        destinations == main_destination_sets[0]
        for destinations in main_destination_sets
    )
    if not main_routes_identical:
        errors.append(
            "relay route tables do not have identical exact main-private routes"
        )
    if len(main_route_destinations) != 3:
        errors.append(
            "relay route tables must contain exactly three main-VPC /24 routes"
        )
    if main_routes_identical:
        try:
            main_network = ipaddress.ip_network(str(main_vpc_cidr))
            route_networks = [
                ipaddress.ip_network(str(cidr)) for cidr in main_route_destinations
            ]
            if main_network.version != 4 or any(
                network.version != 4 for network in route_networks
            ):
                errors.append("main VPC and relay peering routes must use IPv4 CIDRs")
            elif not route_networks or any(
                network.prefixlen != 24 or not network.subnet_of(main_network)
                for network in route_networks
            ):
                errors.append("relay peering routes are not exact main-VPC /24 subnets")
        except ValueError:
            errors.append("main VPC or relay peering route contains an invalid CIDR")

    main_private_routes = snapshot.get("main_private_routes", [])
    main_private_route_table_ids = {
        row.get("route_table_id") for row in main_private_routes
    }
    expected_main_table_count = 3 if environment == "prod" else 1
    if (
        None in main_private_route_table_ids
        or len(main_private_route_table_ids) != expected_main_table_count
    ):
        errors.append(
            f"main private subnets must use exactly {expected_main_table_count} active extensible route table(s)"
        )
    expected_main_table_names = {
        f"layerv-nhp-{environment}-rtb-private-extensible-{index}"
        for index in range(expected_main_table_count)
    }
    actual_main_table_names = {
        row.get("route_table_tags", {}).get("Name") for row in main_private_routes
    }
    if actual_main_table_names != expected_main_table_names or any(
        row.get("route_table_tags", {}).get("Component") != "networking"
        for row in main_private_routes
    ):
        errors.append(
            "main private subnets must be associated only with the tagged extensible route tables"
        )

    main_nat_gateway_ids: set[str] = set()
    for row in main_private_routes:
        reverse_destinations = {
            route.get("destination")
            for route in row.get("routes", [])
            if route.get("target_type") == "peering"
            and route.get("target") == peer.get("id")
        }
        if reverse_destinations != relay_cidrs:
            errors.append(
                f"main private subnet {row.get('subnet_id')} lacks the exact relay /24 return routes"
            )
        nat_defaults = [
            route
            for route in row.get("routes", [])
            if route.get("destination") == "0.0.0.0/0"
            and route.get("target_type") == "nat"
            and str(route.get("target", "")).startswith("nat-")
            and route.get("state") == "active"
        ]
        if len(nat_defaults) != 1:
            errors.append(
                f"main private subnet {row.get('subnet_id')} lacks exactly one active NAT default route"
            )
        else:
            main_nat_gateway_ids.add(str(nat_defaults[0]["target"]))
    if len(main_nat_gateway_ids) != expected_main_table_count:
        errors.append(
            f"main private extensible route tables must use exactly {expected_main_table_count} NAT gateway(s)"
        )
    # The reviewed topology always has three private-subnet views. Sandbox may
    # share one route table while prod owns three; table cardinality is checked
    # separately above, so this fixed count is intentionally not parameterized.
    if len(main_private_routes) != 3:
        errors.append(
            "inventory must contain exactly three main private subnet route views"
        )
    for row in public_subnets:
        defaults = [
            route
            for route in row.get("routes", [])
            if route.get("destination") == "0.0.0.0/0"
            and route.get("target_type") == "gateway"
            and str(route.get("target", "")).startswith("igw-")
        ]
        if len(defaults) != 1:
            errors.append(
                f"public subnet {row.get('id')} lacks exactly one IGW default route"
            )
        else:
            expected_public_routes = {
                (str(vpc.get("cidr")), "gateway", "local", "active"),
                (
                    "0.0.0.0/0",
                    "gateway",
                    str(defaults[0].get("target")),
                    "active",
                ),
            }
            if {
                _route_key(route) for route in row.get("routes", [])
            } != expected_public_routes:
                errors.append(
                    f"public subnet {row.get('id')} route table is not exactly local plus IGW default"
                )
    expected_endpoint_routes = {(str(vpc.get("cidr")), "gateway", "local", "active")}
    for row in endpoint_subnets:
        if {
            _route_key(route) for route in row.get("routes", [])
        } != expected_endpoint_routes:
            errors.append(
                f"endpoint subnet {row.get('id')} route table is not local-only"
            )

    orphaned = snapshot.get("orphaned_legacy_resources", {})
    for resource_type in ("asgs", "main_vpc_security_groups"):
        if orphaned.get(resource_type):
            errors.append(
                f"orphaned pre-DMZ relay {resource_type} remain: "
                f"{sorted(orphaned[resource_type])}"
            )
    assigned_cell_nhp_listeners = snapshot.get("assigned_cell_nhp_listeners")
    if not isinstance(assigned_cell_nhp_listeners, list):
        errors.append(
            "assigned-cell public NHP listener inventory is missing or malformed"
        )
    elif len(assigned_cell_nhp_listeners) != 1:
        errors.append(
            "assigned cell must expose exactly one public UDP listener on 62206: "
            f"{assigned_cell_nhp_listeners}"
        )
    else:
        cell_edge = assigned_cell_nhp_listeners[0]
        expected_lb_name = f"layerv-nhp-{environment}-nlb"
        expected_lb_tags = {
            "Environment": str(environment),
            "Component": "compute",
            "Name": expected_lb_name,
            "Cell": snapshot.get("cell_id"),
        }
        target_group = cell_edge.get("target_group")
        targets = cell_edge.get("targets")
        if (
            cell_edge.get("canonical") is not True
            or cell_edge.get("load_balancer_name") != expected_lb_name
            or not cell_edge.get("listener_arn")
            or cell_edge.get("protocol") != "UDP"
            or cell_edge.get("port") != RELAY_SERVER_UDP_PORT
            or any(
                cell_edge.get("load_balancer_tags", {}).get(key) != value
                for key, value in expected_lb_tags.items()
            )
        ):
            errors.append(
                "assigned cell public NHP listener is not the canonical tagged compute NLB UDP 62206 edge"
            )
        expected_target_group = {
            "arn": cell_edge.get("target_group_arn"),
            "vpc_id": snapshot.get("peer", {}).get("main_vpc_id"),
            "protocol": "UDP",
            "port": RELAY_SERVER_UDP_PORT,
            "target_type": "instance",
            "preserve_client_ip": True,
            "health_check_enabled": True,
            "health_check_protocol": "HTTP",
            "health_check_port": "8888",
            "health_check_path": "/health/live",
            "health_check_matcher": "200",
        }
        if not isinstance(target_group, dict) or any(
            target_group.get(key) != value
            for key, value in expected_target_group.items()
        ):
            errors.append(
                "assigned cell public UDP listener does not forward to the canonical UDP 62206 instance target group"
            )
        expected_target_owners = {
            f"layerv-nhp-{environment}-udp": {
                "color": "blue",
                "asg": f"layerv-nhp-{environment}-server",
                "tag_name": f"layerv-nhp-{environment}-tg-udp",
            },
            f"layerv-nhp-{environment}-udp-grn": {
                "color": "green",
                "asg": f"layerv-nhp-{environment}-server-green",
                "tag_name": f"layerv-nhp-{environment}-tg-udp-green",
            },
        }
        target_owner = (
            expected_target_owners.get(str(target_group.get("name")))
            if isinstance(target_group, dict)
            else None
        )
        if (
            target_owner is None
            or target_owner.get("color") != snapshot.get("server_active_color")
            or any(
                target_group.get("tags", {}).get(key) != value
                for key, value in {
                    "Environment": str(environment),
                    "Component": "compute",
                    "Cell": snapshot.get("cell_id"),
                    "Name": (target_owner or {}).get("tag_name"),
                }.items()
            )
        ):
            errors.append(
                "assigned cell public UDP target group lacks canonical cell/color ownership"
            )
        server_sg_ids = snapshot.get("security_groups", {}).get("server_ids", [])
        expected_server_sg_id = server_sg_ids[0] if len(server_sg_ids) == 1 else None
        if (
            not isinstance(targets, list)
            or not targets
            or any(
                row.get("state") != "healthy"
                or row.get("port") != RELAY_SERVER_UDP_PORT
                or not str(row.get("id", "")).startswith("i-")
                or row.get("asg_name") != (target_owner or {}).get("asg")
                or row.get("lifecycle_state") != "InService"
                or row.get("health_status") != "HEALTHY"
                or row.get("security_group_ids") != [expected_server_sg_id]
                for row in targets
            )
        ):
            errors.append(
                "assigned cell public UDP target group must have healthy active-color server-ASG targets on 62206 using the canonical server SG"
            )

    internal_listeners = snapshot.get("internal_cell_nhp_listeners")
    active_color = snapshot.get("server_active_color")
    if not isinstance(internal_listeners, list) or len(internal_listeners) != 1:
        errors.append(
            "relay path must have exactly one canonical internal server UDP 62206 listener"
        )
    elif active_color not in {"blue", "green"}:
        errors.append("server active-color marker must be exactly blue or green")
    else:
        internal_edge = internal_listeners[0]
        expected_internal_lb_name = f"layerv-nhp-{environment}-srv-int"
        expected_internal_lb_tags = {
            "Environment": str(environment),
            "Component": "compute",
            "Cell": snapshot.get("cell_id"),
            "Name": f"layerv-nhp-{environment}-srv-int-nlb",
        }
        internal_tg = internal_edge.get("target_group")
        expected_internal_owners = {
            "blue": {
                "name": f"layerv-nhp-{environment}-srv-int-udp",
                "tag_name": f"layerv-nhp-{environment}-tg-srv-int-udp-blue",
                "asg": f"layerv-nhp-{environment}-server",
            },
            "green": {
                "name": f"layerv-nhp-{environment}-srv-int-grn",
                "tag_name": f"layerv-nhp-{environment}-tg-srv-int-udp-green",
                "asg": f"layerv-nhp-{environment}-server-green",
            },
        }
        internal_owner = expected_internal_owners[str(active_color)]
        if (
            internal_edge.get("canonical") is not True
            or internal_edge.get("load_balancer_name") != expected_internal_lb_name
            or not internal_edge.get("listener_arn")
            or internal_edge.get("protocol") != "UDP"
            or internal_edge.get("port") != RELAY_SERVER_UDP_PORT
            or any(
                internal_edge.get("load_balancer_tags", {}).get(key) != value
                for key, value in expected_internal_lb_tags.items()
            )
        ):
            errors.append(
                "relay path internal server listener is not the canonical tagged UDP 62206 NLB edge"
            )
        expected_internal_tg = {
            "arn": internal_edge.get("target_group_arn"),
            "name": internal_owner["name"],
            "vpc_id": snapshot.get("peer", {}).get("main_vpc_id"),
            "protocol": "UDP",
            "port": RELAY_SERVER_UDP_PORT,
            "target_type": "instance",
            "preserve_client_ip": True,
            "health_check_enabled": True,
            "health_check_protocol": "HTTP",
            "health_check_port": "8888",
            "health_check_path": "/health/live",
            "health_check_matcher": "200",
        }
        if not isinstance(internal_tg, dict) or any(
            internal_tg.get(key) != value for key, value in expected_internal_tg.items()
        ):
            errors.append(
                "relay path internal listener does not forward to the active-color UDP 62206 instance target group"
            )
        if not isinstance(internal_tg, dict) or any(
            internal_tg.get("tags", {}).get(key) != value
            for key, value in {
                "Environment": str(environment),
                "Component": "compute",
                "Cell": snapshot.get("cell_id"),
                "Name": internal_owner["tag_name"],
                "DeployColor": active_color,
            }.items()
        ):
            errors.append(
                "relay path internal target group lacks canonical active-color ownership"
            )
        internal_targets = internal_edge.get("targets")
        server_sg_ids = snapshot.get("security_groups", {}).get("server_ids", [])
        expected_server_sg_id = server_sg_ids[0] if len(server_sg_ids) == 1 else None
        if (
            not isinstance(internal_targets, list)
            or not internal_targets
            or any(
                row.get("state") != "healthy"
                or row.get("port") != RELAY_SERVER_UDP_PORT
                or not str(row.get("id", "")).startswith("i-")
                or row.get("asg_name") != internal_owner["asg"]
                or row.get("lifecycle_state") != "InService"
                or row.get("health_status") != "HEALTHY"
                or row.get("security_group_ids") != [expected_server_sg_id]
                for row in internal_targets
            )
        ):
            errors.append(
                "relay path internal target group must have healthy active-color server-ASG targets on 62206 using the canonical server SG"
            )
    if orphaned.get("target_groups"):
        errors.append(
            f"orphaned relay target groups remain: {sorted(orphaned['target_groups'])}"
        )
    instances = snapshot.get("instances", [])
    desired_capacity = asg.get("desired_capacity")
    asg_members = asg.get("members", [])
    instance_ids = set(asg.get("instance_ids", []))
    # Three is the reviewed one-per-AZ relay floor, not a generic capacity
    # preference. A deliberate capacity-contract change must update Terraform,
    # the plan checker, and this live detector together.
    if asg.get("min_size") != 3:
        errors.append("canonical relay ASG minimum capacity must be exactly three")
    if not isinstance(desired_capacity, int) or desired_capacity < 3:
        errors.append("canonical relay ASG desired capacity must be at least three")
    if isinstance(desired_capacity, int) and (
        len(instance_ids) != desired_capacity
        or len(asg_members) != desired_capacity
        or len(instances) != desired_capacity
    ):
        errors.append(
            "canonical relay ASG has not converged to its desired instance count"
        )
    if {row.get("instance_id") for row in asg_members} != instance_ids:
        errors.append(
            "canonical relay ASG member inventory does not match its instances"
        )
    https_target_group_arns = set(snapshot.get("alb", {}).get("target_group_arns", []))
    if (
        len(https_target_group_arns) != 1
        or set(asg.get("target_group_arns", [])) != https_target_group_arns
    ):
        errors.append(
            "canonical relay ASG is not attached to exactly the HTTPS target group"
        )
    for member in asg_members:
        if (
            member.get("lifecycle_state") != "InService"
            or member.get("health_status") != "Healthy"
        ):
            errors.append(
                f"relay ASG member {member.get('instance_id')} is not InService and Healthy"
            )
    for instance in instances:
        if instance.get("id") not in instance_ids:
            errors.append(
                f"relay EC2 instance {instance.get('id')} is not a canonical ASG member"
            )
        if instance.get("state") != "running":
            errors.append(f"relay instance {instance.get('id')} is not running")
        if instance.get("vpc_id") != vpc.get("id"):
            errors.append(f"relay instance {instance.get('id')} is outside the DMZ VPC")
        if instance.get("subnet_id") not in {row.get("id") for row in relay_subnets}:
            errors.append(
                f"relay instance {instance.get('id')} is outside an isolated relay subnet"
            )
        if instance.get("public_ip") or instance.get("ipv6"):
            errors.append(
                f"relay instance {instance.get('id')} has a public or IPv6 address"
            )

    relay_enis = snapshot.get("relay_network_interfaces", [])
    if not relay_enis:
        errors.append("no relay-subnet network interfaces were inventoried")
    expected_relay_sg_ids = set(
        snapshot.get("security_groups", {}).get("relay_ids", [])
    )
    expected_private_ips = {
        instance.get("private_ip")
        for instance in instances
        if instance.get("private_ip")
    }
    if (
        len(relay_enis) != len(instances)
        or {interface.get("private_ip") for interface in relay_enis}
        != expected_private_ips
    ):
        errors.append(
            "relay-subnet ENIs do not map one-to-one to canonical ASG instances"
        )
    for interface in relay_enis:
        if interface.get("public_ip") or interface.get("ipv6"):
            errors.append(
                f"relay-subnet network interface {interface.get('id')} has a public or IPv6 address"
            )
        if (
            set(interface.get("security_group_ids", [])) != expected_relay_sg_ids
            or interface.get("status") != "in-use"
        ):
            errors.append(
                f"relay-subnet network interface {interface.get('id')} is not an in-use canonical relay ENI"
            )

    endpoints = snapshot.get("endpoints", [])
    interface_endpoints = [row for row in endpoints if row.get("type") == "Interface"]
    gateway = [row for row in endpoints if row.get("type") == "Gateway"]
    services = {row.get("service") for row in interface_endpoints}
    if services != EXPECTED_INTERFACE_SERVICES or len(interface_endpoints) != len(
        EXPECTED_INTERFACE_SERVICES
    ):
        errors.append(
            "interface endpoint set differs from the exact required set: "
            f"{sorted(services)}"
        )
    if any(row.get("service") == "ec2messages" for row in endpoints):
        errors.append("ec2messages endpoint must not exist")
    endpoint_sg_ids = set(snapshot.get("security_groups", {}).get("endpoint_ids", []))
    for endpoint in interface_endpoints:
        endpoint_id = endpoint.get("id")
        service = endpoint.get("service")
        if endpoint.get("state") != "available":
            errors.append(f"interface endpoint {endpoint_id} is not available")
        if not endpoint.get("private_dns_enabled"):
            errors.append(f"interface endpoint {endpoint_id} lacks private DNS")
        if (
            set(endpoint.get("security_group_ids", [])) != endpoint_sg_ids
            or len(endpoint_sg_ids) != 1
        ):
            errors.append(
                f"interface endpoint {endpoint_id} is not in the one endpoint SG"
            )
        if set(endpoint.get("subnet_ids", [])) != endpoint_subnet_ids:
            errors.append(
                f"interface endpoint {endpoint_id} is not in all endpoint subnets"
            )
        policy = endpoint.get("policy", {})
        # Deliberate defense-in-depth: first require the authored bare-string
        # account-boundary deny, then separately require its entire exact shape.
        if not policy or not _has_cross_account_deny(policy, str(account_id)):
            errors.append(
                f"interface endpoint {service} lacks the account-boundary deny"
            )
        statements = _as_list(policy.get("Statement"))
        deny_statements = [
            statement for statement in statements if statement.get("Effect") == "Deny"
        ]
        expected_deny = {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:PrincipalAccount": str(account_id)}},
        }
        if (
            len(deny_statements) != 1
            or _semantic_statement(deny_statements[0]) != expected_deny
        ):
            errors.append(f"interface endpoint {service} deny shape is not exact")
        allow_statements = [
            statement for statement in statements if statement.get("Effect") == "Allow"
        ]
        allow_actions = set().union(
            *(_statement_actions(statement) for statement in allow_statements)
        )
        if allow_actions != EXPECTED_ENDPOINT_ACTIONS.get(str(service), set()):
            errors.append(f"interface endpoint {service} action set is not exact")
        if service == "secretsmanager":
            resources = _resources_for_action(policy, "secretsmanager:GetSecretValue")
            if len(resources) != 1 or not all(
                re.match(
                    rf"^arn:aws:secretsmanager:{re.escape(str(region))}:{re.escape(str(account_id))}:secret:layerv-nhp-{re.escape(str(environment))}-relay(?:-|$)",
                    resource,
                )
                for resource in resources
            ):
                errors.append(
                    "Secrets Manager endpoint is not scoped to the relay identity secret"
                )
        elif service == "logs":
            resources = set().union(
                *(
                    _resources_for_action(policy, action)
                    for action in EXPECTED_ENDPOINT_ACTIONS["logs"]
                )
            )
            expected = (
                f"arn:aws:logs:{region}:{account_id}:"
                f"log-group:/layerv/nhp/{environment}/relay:*"
            )
            if resources != {expected}:
                errors.append("Logs endpoint is not scoped to the relay log group")
        elif service in {"ecr.api", "ecr.dkr"}:
            repository_actions = EXPECTED_ENDPOINT_ACTIONS[service] - {
                "ecr:GetAuthorizationToken"
            }
            repository_resources = set().union(
                *(
                    _resources_for_action(policy, action)
                    for action in repository_actions
                )
            )
            expected_repository = (
                f"arn:aws:ecr:{region}:{account_id}:repository/layerv/nhp-relay"
            )
            if repository_resources != {expected_repository}:
                errors.append(
                    f"{service} endpoint is not scoped to the relay repository"
                )
            if service == "ecr.api" and _resources_for_action(
                policy, "ecr:GetAuthorizationToken"
            ) != {"*"}:
                errors.append("ecr.api authorization-token action must use Resource *")
        elif service == "ssm":
            expected_parameter = (
                f"arn:aws:ssm:{region}:{account_id}:"
                f"parameter/{environment}/nhp/relay/image-tag"
            )
            if _resources_for_action(policy, "ssm:GetParameter") != {
                expected_parameter
            }:
                errors.append(
                    "SSM endpoint GetParameter is not scoped to the relay image pin"
                )
            for action in EXPECTED_ENDPOINT_ACTIONS["ssm"] - {"ssm:GetParameter"}:
                if _resources_for_action(policy, action) != {"*"}:
                    errors.append(
                        f"SSM endpoint {action} has an unexpected resource shape"
                    )
        elif service == "monitoring":
            namespaces = {
                statement.get("Condition", {})
                .get("StringEquals", {})
                .get("cloudwatch:namespace")
                for statement in allow_statements
                if "cloudwatch:PutMetricData" in _statement_actions(statement)
            }
            if namespaces != {"LayerV/NHP"}:
                errors.append(
                    "Monitoring endpoint is not scoped to the LayerV/NHP namespace"
                )
    guardduty = [
        row for row in interface_endpoints if row.get("service") == "guardduty-data"
    ]
    if len(guardduty) != 1:
        errors.append(f"guardduty-data must be a singleton (found {len(guardduty)})")
    else:
        statements = _as_list(guardduty[0].get("policy", {}).get("Statement"))
        expected_guardduty_allow = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "*",
            "Resource": "*",
        }
        expected_guardduty_deny = {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:PrincipalAccount": str(account_id)}},
        }
        if len(statements) != 2 or {
            json.dumps(_semantic_statement(statement), sort_keys=True)
            for statement in statements
        } != {
            json.dumps(expected_guardduty_allow, sort_keys=True),
            json.dumps(expected_guardduty_deny, sort_keys=True),
        }:
            errors.append(
                "guardduty-data policy is not the exact allow plus account-deny shape"
            )

    s3 = [row for row in gateway if row.get("service") == "s3"]
    if len(s3) != 1:
        errors.append(f"S3 gateway endpoint must be a singleton (found {len(s3)})")
    else:
        endpoint = s3[0]
        s3_route_table_ids = set(endpoint.get("route_table_ids", []))
        if s3_route_table_ids != relay_route_table_ids:
            errors.append(
                "S3 endpoint is not associated with exactly the relay route tables"
            )
        statements = _as_list(endpoint.get("policy", {}).get("Statement"))
        allows = [
            statement for statement in statements if statement.get("Effect") == "Allow"
        ]
        actions = set().union(*(_statement_actions(statement) for statement in allows))
        resources = set().union(
            *(_statement_resources(statement) for statement in allows)
        )
        if actions != {"s3:GetObject"} or resources != _expected_s3_resources(
            str(region)
        ):
            errors.append(
                "S3 endpoint policy exceeds or omits the five-resource GetObject contract"
            )
        # The exact route-set comparison needs the reviewed singleton S3
        # endpoint associated with the exact relay route-table set so each
        # table's endpoint prefix-list route is identifiable. A mismatched
        # association already fails above; skip the derived comparison there
        # rather than adding misleading per-subnet cascade errors.
        if s3_route_table_ids == relay_route_table_ids:
            expected_routes_base = {
                (str(vpc.get("cidr")), "gateway", "local", "active"),
                *(
                    (str(cidr), "peering", str(peer.get("id")), "active")
                    for cidr in main_route_destinations
                ),
            }
            for row in relay_subnets:
                expected_routes = set(expected_routes_base)
                s3_routes = [
                    route
                    for route in row.get("routes", [])
                    if route.get("target_type") == "gateway"
                    and route.get("target") == endpoint.get("id")
                    and str(route.get("destination", "")).startswith("pl-")
                ]
                if len(s3_routes) == 1:
                    expected_routes.add(_route_key(s3_routes[0]))
                else:
                    errors.append(
                        f"relay subnet {row.get('id')} lacks exactly one S3 endpoint prefix-list route"
                    )
                if {
                    _route_key(route) for route in row.get("routes", [])
                } != expected_routes:
                    errors.append(
                        f"relay subnet {row.get('id')} route table is not exactly local, three peer /24s, and S3"
                    )

    security = snapshot.get("security_groups", {})
    by_id = security.get("by_id", {})
    relay_ids = security.get("relay_ids", [])
    alb_ids = security.get("alb_ids", [])
    server_ids = security.get("server_ids", [])
    if not (
        len(relay_ids) == len(alb_ids) == len(endpoint_sg_ids) == len(server_ids) == 1
    ):
        errors.append(
            "relay, ALB, endpoint, and server SG identities must each be singular"
        )
    else:
        relay_id, alb_id, endpoint_id, server_id = (
            relay_ids[0],
            alb_ids[0],
            next(iter(endpoint_sg_ids)),
            server_ids[0],
        )
        for instance in instances:
            if set(instance.get("security_group_ids", [])) != {relay_id}:
                errors.append(
                    f"relay instance {instance.get('id')} does not use exactly the relay SG"
                )
        for interface in relay_enis:
            if set(interface.get("security_group_ids", [])) != {relay_id}:
                errors.append(
                    f"relay-subnet network interface {interface.get('id')} does not use exactly the relay SG"
                )
        expected_relay_in = [
            {
                "protocol": "tcp",
                "from": RELAY_BACKEND_PORT,
                "to": RELAY_BACKEND_PORT,
                "source_type": "security_group",
                "source": alb_id,
            },
            {
                "protocol": "udp",
                "from": RELAY_ACK_UDP_PORT,
                "to": RELAY_ACK_UDP_PORT,
                "source_type": "security_group",
                "source": server_id,
            },
        ]
        expected_relay_out = [
            *(
                {
                    "protocol": "udp",
                    "from": RELAY_SERVER_UDP_PORT,
                    "to": RELAY_SERVER_UDP_PORT,
                    "source_type": "cidr_ipv4",
                    "source": cidr,
                }
                for cidr in sorted(main_route_destinations)
            ),
            {
                "protocol": "tcp",
                "from": RELAY_HTTPS_PORT,
                "to": RELAY_HTTPS_PORT,
                "source_type": "security_group",
                "source": endpoint_id,
            },
        ]
        actual_relay_out = by_id.get(relay_id, {}).get("outbound", [])
        s3_prefix_rules = [
            rule
            for rule in actual_relay_out
            if rule.get("protocol") == "tcp"
            and rule.get("from") == RELAY_HTTPS_PORT
            and rule.get("to") == RELAY_HTTPS_PORT
            and rule.get("source_type") == "prefix_list"
        ]
        if len(s3_prefix_rules) != 1:
            errors.append(
                "relay SG must have exactly one TCP 443 S3 prefix-list egress"
            )
        elif len(s3) == 1:
            s3_route_prefixes = {
                route.get("destination")
                for row in relay_subnets
                for route in row.get("routes", [])
                if route.get("target_type") == "gateway"
                and route.get("target") == s3[0].get("id")
            }
            if s3_route_prefixes != {s3_prefix_rules[0].get("source")}:
                errors.append(
                    "relay SG prefix-list egress is not the S3 endpoint prefix list"
                )
        expected_relay_out.extend(s3_prefix_rules)
        if not _rules_equal(
            by_id.get(relay_id, {}).get("inbound", []), expected_relay_in
        ):
            errors.append(
                "relay SG ingress differs from ALB:8080 plus internal server return:62207"
            )
        if not _rules_equal(actual_relay_out, expected_relay_out):
            errors.append(
                "relay SG egress differs from exact UDP, endpoint, and S3 rules"
            )
        expected_alb_in = [
            {
                "protocol": "tcp",
                "from": RELAY_HTTPS_PORT,
                "to": RELAY_HTTPS_PORT,
                "source_type": "cidr_ipv4",
                "source": "0.0.0.0/0",
            }
        ]
        expected_alb_out = [
            {
                "protocol": "tcp",
                "from": RELAY_BACKEND_PORT,
                "to": RELAY_BACKEND_PORT,
                "source_type": "security_group",
                "source": relay_id,
            }
        ]
        alb_sg = by_id.get(alb_id, {})
        if not _rules_equal(alb_sg.get("inbound", []), expected_alb_in):
            errors.append("ALB SG ingress is not exactly public TCP 443")
        if not _rules_equal(alb_sg.get("outbound", []), expected_alb_out):
            errors.append("ALB SG egress is not exactly relay TCP 8080")
        expected_endpoint_in = [
            {
                "protocol": "tcp",
                "from": RELAY_HTTPS_PORT,
                "to": RELAY_HTTPS_PORT,
                "source_type": "security_group",
                "source": relay_id,
            }
        ]
        endpoint_sg = by_id.get(endpoint_id, {})
        if not _rules_equal(endpoint_sg.get("inbound", []), expected_endpoint_in):
            errors.append("endpoint SG ingress is not exactly relay TCP 443")
        if endpoint_sg.get("outbound", []):
            errors.append("endpoint SG must have no egress rules")
        allowed_server_sources = relay_cidrs | {"0.0.0.0/0"}
        expected_server_nhp_rules = [
            {
                "protocol": "udp",
                "from": RELAY_SERVER_UDP_PORT,
                "to": RELAY_SERVER_UDP_PORT,
                "source_type": "cidr_ipv4",
                "source": source,
            }
            for source in sorted(allowed_server_sources)
        ]
        actual_server_nhp_rules = [
            rule
            for rule in by_id.get(server_id, {}).get("inbound", [])
            if _rule_covers_udp_port(rule, RELAY_SERVER_UDP_PORT)
        ]
        if not _rules_equal(actual_server_nhp_rules, expected_server_nhp_rules):
            errors.append(
                "server SG rules covering UDP 62206 are not exactly public internet plus relay /24s"
            )
        public_udp_capable_rules = [
            rule
            for rule in by_id.get(server_id, {}).get("inbound", [])
            if rule.get("source_type") in {"cidr_ipv4", "cidr_ipv6"}
            and rule.get("source") in {"0.0.0.0/0", "::/0"}
            and str(rule.get("protocol", "")).lower() in {"udp", "-1", "all"}
        ]
        expected_public_udp_rule = [
            {
                "protocol": "udp",
                "from": RELAY_SERVER_UDP_PORT,
                "to": RELAY_SERVER_UDP_PORT,
                "source_type": "cidr_ipv4",
                "source": "0.0.0.0/0",
            }
        ]
        if not _rules_equal(public_udp_capable_rules, expected_public_udp_rule):
            errors.append(
                "server SG public UDP-capable ingress must be exactly IPv4 UDP 62206"
            )

    flow_logs = snapshot.get("flow_logs", [])
    security_log_groups = snapshot.get("security_log_groups", {})
    expected_log_group_names = _expected_security_log_group_names(str(environment))
    if set(security_log_groups) != set(expected_log_group_names):
        errors.append(
            "dedicated Flow and Resolver log groups were not both inventoried"
        )
    expected_retention = 365 if environment == "prod" else 30
    for purpose, expected_name in expected_log_group_names.items():
        row = security_log_groups.get(purpose, {})
        if (
            row.get("name") != expected_name
            or row.get("retention_in_days") != expected_retention
        ):
            errors.append(
                f"dedicated {purpose} log group name or retention is incorrect"
            )
    log_kms_key_ids = _log_group_kms_key_ids(security_log_groups)
    if len(log_kms_key_ids) != 1 or len(security_log_groups) != 2:
        errors.append(
            "Flow and Resolver log groups do not use the same customer KMS key"
        )
    logs_kms_policy = snapshot.get("logs_kms_policy", {})
    kms_statements = _as_list(logs_kms_policy.get("Statement"))
    cloudwatch_kms_statements = [
        statement
        for statement in kms_statements
        if statement.get("Principal") == {"Service": f"logs.{region}.amazonaws.com"}
    ]
    admin_kms_statements = [
        statement
        for statement in kms_statements
        if _semantic_statement(statement)
        == {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    expected_kms_actions = {
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
    }
    expected_kms_contexts = {
        f"arn:aws:logs:{region}:{account_id}:log-group:/layerv/nhp/{environment}/relay-dmz/flow",
        f"arn:aws:logs:{region}:{account_id}:log-group:/layerv/nhp/{environment}/relay-dmz/resolver",
    }
    if (
        logs_kms_policy.get("Version") != "2012-10-17"
        or len(kms_statements) != 2
        or len(admin_kms_statements) != 1
    ):
        errors.append(
            "logs KMS key policy is not exactly account admin plus log delivery"
        )
    if len(cloudwatch_kms_statements) != 1:
        errors.append(
            "logs KMS key lacks exactly one regional CloudWatch Logs statement"
        )
    else:
        statement = cloudwatch_kms_statements[0]
        if (
            set(_semantic_statement(statement))
            != {"Effect", "Principal", "Action", "Resource", "Condition"}
            or statement.get("Effect") != "Allow"
            or _statement_actions(statement) != expected_kms_actions
            or _statement_resources(statement) != {"*"}
            or set(
                _as_list(
                    statement.get("Condition", {})
                    .get("ArnEquals", {})
                    .get("kms:EncryptionContext:aws:logs:arn")
                )
            )
            != expected_kms_contexts
            or set(statement.get("Condition", {})) != {"ArnEquals"}
        ):
            errors.append(
                "logs KMS CloudWatch statement conditions or encryption context are not exact"
            )
    healthy_flow_logs = [
        row
        for row in flow_logs
        if row.get("traffic_type") == "ALL"
        and row.get("flow_log_status") == "ACTIVE"
        and row.get("delivery_status") == "SUCCESS"
        and row.get("destination_type") == "cloud-watch-logs"
        and str(row.get("destination_arn", "")).removesuffix(":*")
        == security_log_groups.get("flow", {}).get("arn")
        and row.get("max_aggregation_interval") == 60
        and row.get("log_format") == EXPECTED_FLOW_LOG_FORMAT
    ]
    if not healthy_flow_logs:
        errors.append("DMZ has no healthy ALL-traffic CloudWatch VPC Flow Log")

    resolver = snapshot.get("resolver", {})
    if resolver.get("firewall_fail_open") != "DISABLED":
        errors.append("Resolver DNS Firewall is not fail closed")
    associations = resolver.get("firewall_associations", [])
    if len(associations) != 1 or associations[0].get("status") != "COMPLETE":
        errors.append("DMZ must have one complete Resolver Firewall association")
    else:
        if (
            associations[0].get("mutation_protection") != "DISABLED"
            or associations[0].get("priority") != 101
        ):
            errors.append(
                "Resolver Firewall association must stay rollback-safe at non-reserved priority 101"
            )
        rules = associations[0].get("rules", [])
        if len(rules) != len(ADVANCED_DNS_PROTECTION_PRIORITIES) + 2:
            errors.append(
                "Resolver firewall rule set must contain exactly the reviewed advanced protections, allowlist, and catch-all"
            )
        advanced_rules = [
            rule for rule in rules if rule.get("dns_threat_protection") is not None
        ]
        advanced = {rule.get("dns_threat_protection"): rule for rule in advanced_rules}
        if (
            len(advanced_rules) != len(ADVANCED_DNS_PROTECTION_PRIORITIES)
            or set(advanced) != ADVANCED_DNS_PROTECTIONS
            or any(
                rule.get("action") != "BLOCK"
                or rule.get("block_response") != DNS_BLOCK_RESPONSE
                or rule.get("confidence_threshold") != "HIGH"
                or _exact_nonnegative_int(rule.get("priority"))
                != ADVANCED_DNS_PROTECTION_PRIORITIES[protection]
                for protection, rule in advanced.items()
            )
        ):
            errors.append(
                "Resolver advanced DNS threat protections must be exact HIGH-confidence NODATA blocks"
            )
        allows = [rule for rule in rules if rule.get("action") == "ALLOW"]
        if len(allows) != 1 or _exact_nonnegative_int(allows[0].get("priority")) != 200:
            errors.append("Resolver allowlist rule must be unique at priority 200")
        elif {
            str(domain).removesuffix(".") for domain in allows[0].get("domains", [])
        } != _expected_dns_domains(str(region)):
            errors.append(
                "Resolver allowlist domains differ from the exact regional contract"
            )
        blocks = [
            rule
            for rule in rules
            if rule.get("action") == "BLOCK"
            and {
                str(domain).removesuffix(".") for domain in rule.get("domains", [])
            }
            == {"*"}
        ]
        if (
            len(blocks) != 1
            or _exact_nonnegative_int(blocks[0].get("priority")) != 900
            or blocks[0].get("block_response") != DNS_BLOCK_RESPONSE
        ):
            errors.append(
                "Resolver catch-all must be a unique priority-900 NODATA block after the allowlist"
            )
    query_logs = resolver.get("query_log_configs", [])
    if len(query_logs) != 1 or any(
        row.get("association_status") != "ACTIVE"
        or row.get("status") != "CREATED"
        or str(row.get("destination_arn", "")).removesuffix(":*")
        != security_log_groups.get("resolver", {}).get("arn")
        for row in query_logs
    ):
        errors.append(
            "DMZ must have one healthy CloudWatch Resolver query-log association"
        )

    alb = snapshot.get("alb", {})
    if (
        alb.get("vpc_id") != vpc.get("id")
        or alb.get("scheme") != "internet-facing"
        or alb.get("type") != "application"
    ):
        errors.append(
            "canonical relay ALB is not the internet-facing DMZ application LB"
        )
    expected_alb_attributes = {
        "deletion_protection_enabled": ("true" if environment == "prod" else "false"),
        "idle_timeout_seconds": "30",
        "drop_invalid_headers_enabled": "true",
        "desync_mitigation_mode": "defensive",
        "xff_header_processing_mode": "append",
        "xff_client_port_enabled": "false",
        "waf_fail_open_enabled": "false",
        "access_logs_enabled": "true",
        "access_logs_bucket": (f"layerv-nhp-{environment}-relay-alb-logs-{account_id}"),
        "access_logs_prefix": "",
    }
    if any(alb.get(key) != value for key, value in expected_alb_attributes.items()):
        errors.append(
            "canonical relay ALB deletion protection, WAF/HTTP hardening, or exact access-log destination attributes are incorrect"
        )
    expected_alb_tags = {
        "Environment": str(environment),
        "Service": "nhp-relay",
        "Component": "relay",
        "Name": f"layerv-nhp-{environment}-relay",
    }
    if any(
        alb.get("tags", {}).get(key) != value
        for key, value in expected_alb_tags.items()
    ):
        errors.append("canonical relay ALB ownership tags are incomplete")
    if not alb.get("waf_arn"):
        errors.append("canonical relay ALB has no WAF association")
    listeners = alb.get("listeners", [])
    if (
        len(listeners) != 1
        or listeners[0].get("port") != RELAY_HTTPS_PORT
        or listeners[0].get("protocol") != "HTTPS"
        or listeners[0].get("ssl_policy") != RELAY_TLS_POLICY
    ):
        errors.append("canonical relay ALB listener set is not exactly HTTPS 443")
    else:
        listener_rules = listeners[0].get("rules", [])
        defaults = [rule for rule in listener_rules if rule.get("is_default")]
        forwards = [rule for rule in listener_rules if not rule.get("is_default")]
        if len(defaults) != 1 or [
            action.get("Type") for action in defaults[0].get("actions", [])
        ] != ["fixed-response"]:
            errors.append(
                "canonical relay ALB default action is not one fixed response"
            )
        if len(forwards) != 1 or [
            action.get("Type") for action in forwards[0].get("actions", [])
        ] != ["forward"]:
            errors.append("canonical relay ALB must have exactly one forwarding rule")
        else:
            condition_values: dict[str, set[str]] = {}
            for condition in forwards[0].get("conditions", []):
                values = condition.get("Values")
                if values is None:
                    config = (
                        condition.get("PathPatternConfig")
                        or condition.get("HttpRequestMethodConfig")
                        or {}
                    )
                    values = config.get("Values", [])
                condition_values[condition.get("Field")] = set(values or [])
            if condition_values != {
                "path-pattern": {"/relay/*"},
                "http-request-method": {"POST", "OPTIONS"},
            }:
                errors.append(
                    "canonical relay ALB forwarding rule is not POST/OPTIONS /relay/*"
                )
    target_groups = alb.get("target_groups", [])
    if len(target_groups) != 1 or {row.get("arn") for row in target_groups} != set(
        alb.get("target_group_arns", [])
    ):
        errors.append(
            "canonical relay ALB must have exactly one inventoried target group"
        )
    else:
        target_group = target_groups[0]
        expected_target_group = {
            "vpc_id": vpc.get("id"),
            "protocol": "HTTPS",
            "port": RELAY_BACKEND_PORT,
            "target_type": "instance",
            "health_check_enabled": True,
            "health_check_protocol": "HTTPS",
            "health_check_port": "traffic-port",
            "health_check_path": RELAY_HEALTH_PATH,
            "health_check_matcher": "200",
            "healthy_threshold": 2,
            "unhealthy_threshold": 2,
            "health_check_interval": 15,
            "health_check_timeout": 5,
        }
        if any(
            target_group.get(key) != value
            for key, value in expected_target_group.items()
        ):
            errors.append(
                "relay target group is not HTTPS:8080 with exact HTTPS /health/live checks"
            )
    return errors


def _version(value: str) -> tuple[int, ...]:
    # Require a dotted version so there is enough information to compare the
    # 3.3.40.0 minimum. A bare major such as "3" intentionally returns () and
    # fails closed as below-minimum rather than assuming missing components.
    match = SSM_AGENT_VERSION_RE.fullmatch((value or "").strip())
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def _probe_fully_successful(probe: dict[str, Any]) -> bool:
    return probe.get("status") == "Success" and all(
        probe.get(field) is True
        for field in (
            "allowed_dns",
            "blocked_public_dns",
            "public_tcp_unreachable",
            "relay_active",
        )
    )


def collect_functional(
    snapshot: dict[str, Any],
    aws: AwsCli,
    successful_probe_cache: dict[str, dict[str, Any]] | None = None,
) -> bool:
    # Mutates snapshot["functional"] and returns whether any cached successful
    # probe contributed, which makes the caller require one final fresh pass.
    # Region is interpolated into a remote shell command below. Pin it to the
    # commercial-region grammar before making any AWS call or constructing that
    # command; snapshots/mocks do not get to bypass AwsCli's constructor guard.
    _require_live_functional_authorized(str(snapshot.get("environment", "")))
    region = _require_commercial_region(str(snapshot.get("region", "")))
    account_id = _require_account_id(snapshot.get("account_id"))
    instance_ids = snapshot.get("canonical_asg", {}).get("instance_ids", [])
    target_health: list[dict[str, Any]] = []
    target_group_arns = snapshot.get("alb", {}).get("target_group_arns", [])
    for target_group_arn in target_group_arns:
        rows = aws.call(
            "elbv2", "describe-target-health", "--target-group-arn", target_group_arn
        ).get("TargetHealthDescriptions", [])
        target_health.extend(
            {
                "instance_id": row.get("Target", {}).get("Id"),
                "state": row.get("TargetHealth", {}).get("State"),
                "reason": row.get("TargetHealth", {}).get("Reason"),
                "target_group_arn": target_group_arn,
            }
            for row in rows
        )

    ssm_rows: list[dict[str, Any]] = []
    if instance_ids:
        filters = json.dumps([{"Key": "InstanceIds", "Values": instance_ids}])
        ssm_rows = aws.call(
            "ssm", "describe-instance-information", "--filters", filters
        ).get("InstanceInformationList", [])
    ssm = [
        {
            "instance_id": row.get("InstanceId"),
            "ping_status": row.get("PingStatus"),
            "agent_version": row.get("AgentVersion"),
            "platform": row.get("PlatformName"),
        }
        for row in ssm_rows
    ]

    detectors = aws.call("guardduty", "list-detectors").get("DetectorIds", [])
    coverage: list[dict[str, Any]] = []
    if len(detectors) == 1:
        resources = aws.call(
            "guardduty", "list-coverage", "--detector-id", detectors[0]
        ).get("Resources", [])
        for row in resources:
            details = row.get("ResourceDetails", {}).get("Ec2InstanceDetails", {})
            if details.get("InstanceId") in instance_ids:
                coverage.append(
                    {
                        "instance_id": details.get("InstanceId"),
                        "status": row.get("CoverageStatus"),
                        "issue": row.get("Issue"),
                        "agent_version": details.get("AgentDetails", {}).get("Version"),
                        "management_type": details.get("ManagementType"),
                    }
                )

    probe_cache = successful_probe_cache if successful_probe_cache is not None else {}
    probes = [
        dict(probe_cache[instance_id])
        for instance_id in instance_ids
        if instance_id in probe_cache
        and _probe_fully_successful(probe_cache[instance_id])
    ]
    cached_instance_ids = {probe["instance_id"] for probe in probes}
    used_cached_probes = bool(cached_instance_ids)
    unprobed_instance_ids = [
        instance_id
        for instance_id in instance_ids
        if instance_id not in cached_instance_ids
    ]
    if unprobed_instance_ids:
        hosts = [
            f"api.ecr.{region}.amazonaws.com",
            f"{account_id}.dkr.ecr.{region}.amazonaws.com",
            f"secretsmanager.{region}.amazonaws.com",
            f"ssm.{region}.amazonaws.com",
            f"ssmmessages.{region}.amazonaws.com",
            f"logs.{region}.amazonaws.com",
            f"monitoring.{region}.amazonaws.com",
            f"guardduty-data.{region}.amazonaws.com",
            f"s3.{region}.amazonaws.com",
        ]
        host_words = " ".join(hosts)
        canary_targets = " ".join(PUBLIC_EGRESS_CANARY_IPS)
        negative_dns_probe = shlex.quote(NEGATIVE_DNS_PROBE_PY)
        public_tcp_probe = shlex.quote(PUBLIC_TCP_PROBE_PY)
        probe_output_format = shlex.quote(PROBE_OUTPUT_FORMAT + r"\n")
        # The gate observes DNS and direct-egress behavior from inside each
        # isolated relay node through SSM Run Command. The probe is read-only:
        # name resolution, a TCP connect attempt, and a systemd activity check.
        # python3, getent, and nhp-relayd.service are therefore explicit relay
        # AMI contracts; a missing dependency fails the command/readiness closed.
        # getent proves positive names through the AMI's NSS contract; the Python
        # negative probe distinguishes EAI_NONAME/NODATA from transient resolver
        # errors instead of treating every lookup failure as a successful block.
        # Two independent public HTTPS destinations are representative egress
        # canaries, not exhaustive all-port proof; exact route/SG inventory is
        # authoritative for all protocols. Either being reachable or refusing
        # the connection proves routing and fails the bit. UDP send success is
        # deliberately not used because it cannot prove external reachability.
        # allowed_dns means each Resolver allowlist name resolves, not that each
        # answer is private. S3 may return public addresses whose traffic is
        # still routed through the gateway prefix list.
        # Keep stdout limited to the final printf line consumed below by
        # PROBE_OUTPUT_RE: getent is redirected and both Python probes are
        # intentionally silent. New probe diagnostics must go to stderr so SSM
        # StandardOutputContent cannot bury or truncate the contract line.
        command = (
            f'allowed=1; for host in {host_words}; do getent ahostsv4 "$host" >/dev/null 2>&1 || allowed=0; done; '
            # example.com is intentionally absent from the DNS allowlist.
            # Accept only EAI_NONAME/NODATA as proof of the catch-all; transient
            # resolver errors leave probe_error set and fail the SSM command.
            f'blocked=0; probe_error=0; python3 -c {negative_dns_probe}; dns_rc=$?; if [ "$dns_rc" -eq 0 ]; then blocked=1; elif [ "$dns_rc" -ne 1 ]; then probe_error=1; fi; '
            # connect_ex distinguishes a no-route/timeout isolation result from
            # ECONNREFUSED, which proves the packet reached a public host.
            f'isolated=1; for target in {canary_targets}; do python3 -c {public_tcp_probe} "$target" "{RELAY_HTTPS_PORT}"; tcp_rc=$?; if [ "$tcp_rc" -eq 1 ]; then isolated=0; elif [ "$tcp_rc" -ne 0 ]; then probe_error=1; fi; done; '
            "active=0; systemctl is-active --quiet nhp-relayd.service && active=1 || true; "
            '[ "$probe_error" -eq 0 ] || exit 2; '
            f'printf {probe_output_format} "$allowed" "$blocked" "$isolated" "$active"'
        )
        # Resolve the current Amazon-owned default to an immutable numeric
        # version + service-generated SHA-256 pair, then require SSM to execute
        # exactly that document. Pinning "$DEFAULT" would still follow a moving
        # alias and would not protect this security probe from a version change.
        # SendCommand still supports this hash pair; AWS deprecates Sha1, not
        # the Sha256 hash type used here.
        document_version, document_hash = _pin_ssm_run_shell_document(aws)
        send = aws.call(
            "ssm",
            "send-command",
            "--document-name",
            SSM_RUN_SHELL_DOCUMENT_NAME,
            "--document-version",
            document_version,
            "--document-hash",
            document_hash,
            "--document-hash-type",
            "Sha256",
            "--instance-ids",
            *unprobed_instance_ids,
            "--parameters",
            json.dumps({"commands": [command]}),
            "--timeout-seconds",
            str(SSM_COMMAND_TIMEOUT_SECONDS),
        )
        command_id = send.get("Command", {}).get("CommandId")
        if not command_id:
            raise InventoryError("SSM send-command returned an empty CommandId")
        deadline = time.monotonic() + SSM_PROBE_DEADLINE_SECONDS
        pending = set(unprobed_instance_ids)
        while pending and time.monotonic() < deadline:
            for instance_id in list(pending):
                try:
                    invocation = aws.call(
                        "ssm",
                        "get-command-invocation",
                        "--command-id",
                        command_id,
                        "--instance-id",
                        instance_id,
                    )
                except InventoryError as exc:
                    # SendCommand is eventually consistent with the invocation
                    # read API. Treat only that named transient as pending, and
                    # revalidate the token after AWS CLI major-version upgrades.
                    if "InvocationDoesNotExist" in str(exc):
                        continue
                    raise
                status = invocation.get("Status")
                if status not in {"Pending", "InProgress", "Delayed"}:
                    output = invocation.get("StandardOutputContent", "")
                    match = PROBE_OUTPUT_RE.search(output)
                    probe = {
                        "instance_id": instance_id,
                        "status": status,
                        "allowed_dns": bool(match and match.group(1) == "1"),
                        "blocked_public_dns": bool(match and match.group(2) == "1"),
                        "public_tcp_unreachable": bool(match and match.group(3) == "1"),
                        "relay_active": bool(match and match.group(4) == "1"),
                    }
                    probes.append(probe)
                    if _probe_fully_successful(probe):
                        probe_cache[instance_id] = dict(probe)
                    pending.remove(instance_id)
            if pending:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(SSM_PROBE_POLL_INTERVAL_SECONDS, remaining))
        for instance_id in sorted(pending):
            probes.append({"instance_id": instance_id, "status": "TimedOut"})

    snapshot["functional"] = {
        "target_health": target_health,
        "ssm": ssm,
        "guardduty_detector_count": len(detectors),
        "guardduty_coverage": coverage,
        "probes": probes,
    }
    return used_cached_probes


def validate_functional(snapshot: dict[str, Any]) -> list[str]:
    errors = validate_structural(snapshot)
    functional = snapshot.get("functional", {})
    instance_ids = set(snapshot.get("canonical_asg", {}).get("instance_ids", []))
    if not instance_ids:
        errors.append(
            "functional relay boundary validation requires at least one canonical instance"
        )

    target_health = functional.get("target_health", [])
    expected_target_group_arns = set(
        snapshot.get("alb", {}).get("target_group_arns", [])
    )
    observed_target_group_arns = {row.get("target_group_arn") for row in target_health}
    if instance_ids and observed_target_group_arns != expected_target_group_arns:
        errors.append(
            "functional target health did not inventory the relay HTTPS target group"
        )
    for target_group_arn in sorted(expected_target_group_arns):
        healthy_targets = {
            row.get("instance_id")
            for row in target_health
            if row.get("target_group_arn") == target_group_arn
            and row.get("state") == "healthy"
        }
        if healthy_targets != instance_ids:
            errors.append(
                f"target group {target_group_arn} does not show every canonical relay instance healthy"
            )

    ssm_rows = {row.get("instance_id"): row for row in functional.get("ssm", [])}
    minimum_ssm_version = ".".join(str(part) for part in MIN_SSM_AGENT_VERSION)
    for instance_id in sorted(instance_ids):
        row = ssm_rows.get(instance_id, {})
        version = _version(str(row.get("agent_version", "")))
        padded = version + (0,) * max(0, len(MIN_SSM_AGENT_VERSION) - len(version))
        if row.get("ping_status") != "Online":
            errors.append(f"relay instance {instance_id} is not SSM Online")
        if not version or padded[: len(MIN_SSM_AGENT_VERSION)] < MIN_SSM_AGENT_VERSION:
            errors.append(
                f"relay instance {instance_id} has SSM Agent below {minimum_ssm_version}"
            )

    detector_count = functional.get("guardduty_detector_count")
    if detector_count != 1:
        errors.append(
            "AWS account must have exactly one GuardDuty detector "
            f"(found {detector_count!r})"
        )
    else:
        coverage = {
            row.get("instance_id"): row
            for row in functional.get("guardduty_coverage", [])
        }
        for instance_id in sorted(instance_ids):
            row = coverage.get(instance_id, {})
            if row.get("status") != "HEALTHY" or not row.get("agent_version"):
                errors.append(
                    f"relay instance {instance_id} lacks healthy GuardDuty runtime coverage"
                )

    probes = {row.get("instance_id"): row for row in functional.get("probes", [])}
    for instance_id in sorted(instance_ids):
        row = probes.get(instance_id, {})
        if row.get("status") != "Success":
            errors.append(
                f"relay instance {instance_id} SSM boundary probe did not succeed"
            )
            continue
        for key, label in (
            ("allowed_dns", "cannot resolve every approved AWS endpoint"),
            ("blocked_public_dns", "resolved a non-allowlisted public domain"),
            (
                "public_tcp_unreachable",
                "can reach representative public TCP 443 canary",
            ),
            ("relay_active", "does not have an active relay service"),
        ):
            if not row.get(key):
                errors.append(f"relay instance {instance_id} {label}")
    return errors


def validate_snapshot(snapshot: dict[str, Any], mode: str) -> list[str]:
    return (
        validate_functional(snapshot)
        if mode == "functional"
        else validate_structural(snapshot)
    )


def _validate_snapshot_safely(snapshot: dict[str, Any], mode: str) -> list[str]:
    try:
        return validate_snapshot(snapshot, mode)
    except Exception as exc:
        raise InventoryError(
            f"unexpected validator failure ({type(exc).__name__}): {exc}"
        ) from exc


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, choices=("sandbox", "prod"))
    parser.add_argument("--mode", required=True, choices=("structural", "functional"))
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="read a normalized snapshot instead of calling AWS (fixtures/forensics)",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help=(
            "live-mode convergence deadline for retry sleeps; a collection that "
            "has started is allowed to finish, so wall time may exceed this by "
            "one full collection, plus one fresh functional confirmation when "
            "cached probes were used (recommended: 300 structural, 600 "
            "functional). Snapshot mode is always one-shot"
        ),
    )
    args = parser.parse_args(argv)
    if args.wait_seconds < 0:
        parser.error("--wait-seconds must be non-negative")
    return args


_RETRYABLE_INVENTORY_PATTERNS = (
    # These stderr tokens are deliberate fail-closed AWS CLI wire dependencies.
    # Substring matching is intentional: it changes only retry-vs-terminal
    # classification inside a bounded wait, and either path still exits 2 when
    # inventory cannot be collected. It never converts an error into success.
    # Revalidate them after every AWS CLI major-version upgrade.
    "AWS CLI timed out after",
    "InvalidVpcID.NotFound",
    "InvalidVpcPeeringConnectionID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidNetworkInterfaceID.NotFound",
    "LoadBalancerNotFound",
    "TargetGroupNotFound",
    # Broad not-found responses are deliberately retried only inside the
    # caller's bounded convergence window. A real deletion therefore costs the
    # configured wait before failing closed; one-shot mode still fails at once.
    "ResourceNotFoundException",
    "InvalidInstanceID.NotFound",
    "InvalidInstanceId",
    "InvocationDoesNotExist",
)


def _retryable_inventory_error(error: Exception) -> bool:
    message = str(error)
    return isinstance(error, RetryableInventoryError) or any(
        pattern in message for pattern in _RETRYABLE_INVENTORY_PATTERNS
    )


def _retry_delay_seconds(attempt: int) -> float:
    return float(min(RETRY_BASE_SECONDS * (2 ** min(attempt, 3)), RETRY_MAX_SECONDS))


def _sleep_until_retry(deadline: float, attempt: int = 0) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    # A structural pass performs several account-wide list calls. Exponential
    # backoff (5, 10, 20, then capped at 30 seconds) bounds retry pressure when
    # AWS is throttling while still respecting the caller's absolute deadline.
    time.sleep(min(_retry_delay_seconds(attempt), remaining))
    return True


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    if args.snapshot:
        try:
            snapshot = json.loads(args.snapshot.read_text())
            if not isinstance(snapshot, dict):
                raise InventoryError("snapshot root must be a JSON object")
        except (InventoryError, OSError, json.JSONDecodeError) as exc:
            print(f"relay DMZ inventory error: {exc}", file=sys.stderr)
            return 2
        if snapshot.get("environment") != args.environment:
            print(
                f"relay DMZ inventory error: snapshot environment {snapshot.get('environment')!r} "
                f"does not match --environment {args.environment!r}",
                file=sys.stderr,
            )
            return 2
        # A saved forensic/fixture snapshot is intentionally immutable: never
        # sleep or reread it, even when the caller supplied --wait-seconds.
        # Functional prod snapshots are also intentional: they exercise only
        # captured evidence and never grant the live AWS/SSM access kept dark.
        try:
            errors = _validate_snapshot_safely(snapshot, args.mode)
        except InventoryError as exc:
            print(f"relay DMZ inventory error: {exc}", file=sys.stderr)
            return 2
    else:
        deadline = time.monotonic() + args.wait_seconds
        try:
            # The prod IAM/code-dark fence runs first so it fails before AwsCli
            # constructs or issues any AWS request. Both setup failures share
            # the same non-retryable exit-2 handling.
            if args.mode == "functional":
                _require_live_functional_authorized(args.environment)
            aws = AwsCli()
            # Bind the operator-selected environment to the repository's actual
            # regional deployment before the first AWS inventory request.
            _require_expected_environment_region(args.environment, aws.region)
        except (InventoryError, OSError) as exc:
            print(f"relay DMZ inventory error: {exc}", file=sys.stderr)
            return 2
        successful_probe_cache: dict[str, dict[str, Any]] = {}
        retry_attempt = 0
        expect_uncached_confirmation = False
        while True:
            # A failed confirmation may have cached successes before a later
            # instance/API error. Discard that partial state before every retry
            # so the required confirmation remains fleet-wide and fully fresh.
            if expect_uncached_confirmation:
                successful_probe_cache.clear()
            used_cached_probes = False
            try:
                snapshot = collect_structural(args.environment, aws)
                if args.mode == "functional":
                    used_cached_probes = collect_functional(
                        snapshot, aws, successful_probe_cache
                    )
                    if expect_uncached_confirmation:
                        if used_cached_probes:
                            raise InventoryError(
                                "final fresh functional confirmation unexpectedly reused cached probes"
                            )
                        expect_uncached_confirmation = False
            except Exception as raw_exc:
                # Preserve the public 0/1/2 contract even when AWS returns an
                # unexpected object shape and a normalizer raises IndexError,
                # KeyError, TypeError, etc. Named inventory and OS failures keep
                # their existing retry semantics; programmer/shape errors fail
                # closed as non-retryable collection errors (exit 2), never as a
                # violation-looking traceback (exit 1).
                named_inventory_error = isinstance(raw_exc, (InventoryError, OSError))
                exc = (
                    raw_exc
                    if named_inventory_error
                    else InventoryError(
                        "unexpected collector failure "
                        f"({type(raw_exc).__name__}): {raw_exc}"
                    )
                )
                if (
                    named_inventory_error
                    and args.wait_seconds > 0
                    and _retryable_inventory_error(exc)
                    and _sleep_until_retry(deadline, retry_attempt)
                ):
                    retry_attempt += 1
                    print(
                        f"relay DMZ inventory is still converging: {exc}",
                        file=sys.stderr,
                    )
                    continue
                print(f"relay DMZ inventory error: {exc}", file=sys.stderr)
                return 2
            try:
                errors = _validate_snapshot_safely(snapshot, args.mode)
            except InventoryError as exc:
                print(f"relay DMZ inventory error: {exc}", file=sys.stderr)
                return 2
            if not errors and args.mode == "functional" and used_cached_probes:
                # Cached green probes reduce repeated SSM execution while other
                # invariants converge, but can never authorize final success.
                # Clear them and require one immediate full structural
                # recollection plus a fresh SendCommand round-trip to every relay;
                # a service/egress regression between retries then fails closed.
                # This deliberate, fleet-wide confirmation may run one collection
                # beyond the wait deadline so elapsed time cannot authorize stale
                # data. The extra inventory/SSM cost is paid only after a
                # cache-assisted clean result.
                successful_probe_cache.clear()
                expect_uncached_confirmation = True
                print(
                    "relay DMZ functional state is clean with cached probes; "
                    "running final fresh all-instance confirmation",
                    file=sys.stderr,
                )
                continue
            if (
                errors
                and args.wait_seconds > 0
                and _sleep_until_retry(deadline, retry_attempt)
            ):
                retry_attempt += 1
                print(
                    f"relay DMZ {args.mode} state is still converging "
                    f"({len(errors)} violation(s)); retrying",
                    file=sys.stderr,
                )
                continue
            break
    if errors:
        print(f"relay DMZ {args.mode} check failed ({len(errors)} violation(s)):")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        f"relay DMZ {args.mode} check passed for {args.environment}: "
        f"{snapshot.get('canonical_asg', {}).get('name')} in {snapshot.get('vpc', {}).get('id')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
