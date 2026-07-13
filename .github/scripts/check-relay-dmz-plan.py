#!/usr/bin/env python3
"""Fail closed when a Terraform plan weakens the relay DMZ boundary.

This checker consumes the machine-readable output of ``terraform show -json``.
It intentionally checks both the resolved final values and Terraform's reference
graph: IDs for newly-created resources are unknown during planning, so checking
only ``change.after`` would miss a route or subnet wired to the wrong resource.
The exact ``expression_refs`` sets are part of the toolchain contract: the
sanitized real-plan fixture and PR/apply workflows both pin Terraform 1.14.3.
Any Terraform-version or fixture-provenance change must recapture a real plan
and revalidate those reference shapes before merge.

This contract is intentionally sandbox-specific. It pins account 767397897469,
region us-east-2, sandbox telemetry names, the relay 10.101.0.0/16, and the
10.100.x/24 main-private network shape. Before using it for another environment,
parameterize those expectations together instead of overriding only one of them.
PR #3150 is the tracked integration layer that wires this otherwise-inert checker
into the sandbox PR-plan and final pre-apply gates. The integrated PR-plan
intentionally requires the DMZ to be present; ``--allow-disabled`` is only for
relay-dark/bootstrap callers. Only the final saved-plan pre-apply gate uses
``--require-pr0-applied``. Issue #3154 tracks the all-at-once production variant
required before a future production relay is enabled; implement that variant as
one environment-profile object rather than a second set of parallel constants.
Issue #3164 separately tracks decomposing this sandbox validator into cohesive
helpers; it does not replace #3154's production-profile security prerequisite.

This is an exhaustive validator for the named DMZ security contract, not a
blanket allowlist of every Terraform type/name in the relay modules. New
resources still require HCL review; the checker globally rejects boundary
classes such as NAT/egress gateways across relay-owned scopes and unexpected
security-group rules, then pins the complete inventories whose membership is
itself security-sensitive.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


EXPECTED_SANDBOX_ACCOUNT_ID = "767397897469"
EXPECTED_SANDBOX_REGION = "us-east-2"
EXPECTED_SANDBOX_RELAY_REPO_ARN = (
    f"arn:aws:ecr:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
    "repository/layerv/nhp-relay"
)
EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN = (
    f"arn:aws:ssm:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
    "parameter/sandbox/nhp/relay/image-tag"
)
EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN = (
    # Relay application logs, distinct from the DMZ Flow/Resolver telemetry
    # groups. Keep the trailing :* stream-wildcard form used by IAM; the
    # concrete log-group comparison removes only that suffix below.
    f"arn:aws:logs:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
    "log-group:/layerv/nhp/sandbox/relay:*"
)
EXPECTED_SANDBOX_DMZ_FLOW_LOG_GROUP_ARN = (
    f"arn:aws:logs:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
    "log-group:/layerv/nhp/sandbox/relay-dmz/flow"
)
EXPECTED_SANDBOX_DMZ_RESOLVER_LOG_GROUP_ARN = (
    f"arn:aws:logs:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
    "log-group:/layerv/nhp/sandbox/relay-dmz/resolver"
)
EXPECTED_SANDBOX_MAIN_VPC_CIDR = "10.100.0.0/16"
EXPECTED_SANDBOX_RELAY_VPC_CIDR = "10.101.0.0/16"
EXPECTED_SANDBOX_CELL_ID = "cell0"
EXPECTED_SANDBOX_SERVER_NLB_NAME = "layerv-nhp-sandbox-nlb"
EXPECTED_SANDBOX_SERVER_UDP_TG_NAME = "layerv-nhp-sandbox-udp"
EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME = "layerv-nhp-sandbox-udp-grn"
EXPECTED_SANDBOX_INTERNAL_UDP_TG_NAME = "layerv-nhp-sandbox-srv-int-udp"
EXPECTED_SANDBOX_INTERNAL_UDP_GREEN_TG_NAME = "layerv-nhp-sandbox-srv-int-grn"
EXPECTED_SANDBOX_RELAY_SUBNET_CIDRS = {
    "public": ("10.101.0.0/24", "10.101.1.0/24", "10.101.2.0/24"),
    "relay": ("10.101.10.0/24", "10.101.11.0/24", "10.101.12.0/24"),
    "endpoint": ("10.101.20.0/24", "10.101.21.0/24", "10.101.22.0/24"),
}
EXPECTED_IPV4_DEFAULT_CIDR = "0.0.0.0/0"
EXPECTED_HTTPS_PORT = 443
EXPECTED_RELAY_BACKEND_PORT = 8080
EXPECTED_NHP_SERVER_PORT = 62206
EXPECTED_RELAY_ACK_PORT = 62207
EXPECTED_DEREGISTRATION_DELAY = 30
EXPECTED_METRIC_NAMESPACE = "LayerV/NHP"
EXPECTED_RELAY_HEALTH_PATH = "/health/live"
EXPECTED_DNS_THREAT_CONFIDENCE = "HIGH"


EXPECTED_INTERFACE_ENDPOINTS = {
    "ecr-api": {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetAuthorizationToken",
        "ecr:GetDownloadUrlForLayer",
    },
    "ecr-dkr": {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    },
    "logs": {
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
    },
    "monitoring": {"cloudwatch:PutMetricData"},
    "secretsmanager": {"secretsmanager:GetSecretValue"},
    "ssm": {
        "ssm:DescribeAssociation",
        "ssm:DescribeDocument",
        "ssm:GetDocument",
        "ssm:GetManifest",
        "ssm:GetParameter",
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
    # GuardDuty Runtime Monitoring uses an AWS-internal ingestion API. Its
    # managed endpoint policy deliberately allows Action="*", bounded by the
    # mandatory cross-account deny checked below.
    "guardduty-data": {"*"},
}

EXPECTED_RELAY_IAM_SSM_ACTIONS = {
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
}
EXPECTED_FLOW_LOG_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} "
    "${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} "
    "${log-status} ${pkt-srcaddr} ${pkt-dstaddr} ${pkt-src-aws-service} "
    "${pkt-dst-aws-service} ${flow-direction} ${traffic-path}"
)
EXPECTED_LOGS_KMS_POLICY_REFS = {
    "data.aws_caller_identity.current.account_id",
    "data.aws_caller_identity.current",
    "data.aws_partition.current.dns_suffix",
    "data.aws_partition.current.partition",
    "data.aws_partition.current",
    "data.aws_region.current.region",
    "data.aws_region.current",
    "local.flow_log_group_arn",
    "local.resolver_log_group_arn",
}
EXPECTED_RELAY_IAM_POLICY_REFS = {
    "aws_cloudwatch_log_group.relay.arn",
    "aws_cloudwatch_log_group.relay",
    "data.aws_caller_identity.current.account_id",
    "data.aws_caller_identity.current",
    "data.aws_partition.current.dns_suffix",
    "data.aws_partition.current.partition",
    "data.aws_partition.current",
    "data.aws_region.current.region",
    "data.aws_region.current",
    "var.relay_repo_arn",
    "var.relay_secret_arn",
    "var.secrets_kms_key_arn",
    "var.ssm_image_tag_parameter",
}

EXPECTED_RELAY_IAM_ACTIONS = {
    "cloudwatch:PutMetricData",
    "ecr:BatchCheckLayerAvailability",
    "ecr:BatchGetImage",
    "ecr:GetAuthorizationToken",
    "ecr:GetDownloadUrlForLayer",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "s3:GetObject",
    "secretsmanager:GetSecretValue",
    "ssm:DescribeAssociation",
    "ssm:DescribeDocument",
    "ssm:GetDocument",
    "ssm:GetManifest",
    "ssm:GetParameter",
    "ssm:ListAssociations",
    "ssm:ListInstanceAssociations",
    "ssm:PutComplianceItems",
    "ssm:PutConfigurePackageResult",
    "ssm:PutInventory",
    "ssm:UpdateAssociationStatus",
    "ssm:UpdateInstanceAssociationStatus",
    "ssm:UpdateInstanceInformation",
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
}

EXPECTED_RELAY_IAM_S3_RESOURCES = {
    f"arn:aws:s3:::amazon-ssm-{EXPECTED_SANDBOX_REGION}/*",
    f"arn:aws:s3:::aws-ssm-{EXPECTED_SANDBOX_REGION}/*",
    f"arn:aws:s3:::{EXPECTED_SANDBOX_REGION}-birdwatcher-prod/*",
}

EXPECTED_LOG_KMS_ACTIONS = {
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:Encrypt",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
}

EXPECTED_ALLOW_DOMAINS = {
    f"api.ecr.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"*.dkr.ecr.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"guardduty-data.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"logs.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"monitoring.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"s3.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"*.s3.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"secretsmanager.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"ssm.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"ssmmessages.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
    f"*.elb.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
}

# The gateway-endpoint allowlist is intentionally broader than relay IAM: ECR
# and SSM service flows add starport/document-attachment buckets, while the
# role's direct GetObject grant stays on its three reviewed SSM agent buckets.
EXPECTED_S3_RESOURCES = {
    f"arn:aws:s3:::prod-{EXPECTED_SANDBOX_REGION}-starport-layer-bucket/*",
    f"arn:aws:s3:::amazon-ssm-{EXPECTED_SANDBOX_REGION}/*",
    f"arn:aws:s3:::aws-ssm-{EXPECTED_SANDBOX_REGION}/*",
    f"arn:aws:s3:::{EXPECTED_SANDBOX_REGION}-birdwatcher-prod/*",
    f"arn:aws:s3:::aws-ssm-document-attachments-{EXPECTED_SANDBOX_REGION}/*",
}

# These resources survive the disposable DMZ network/fleet replacement. Their
# values may update in place where noted by Terraform, but a delete or
# replacement would destroy control-plane identity, routing, or retained audit
# evidence and must hard-stop both PR-time and final pre-apply plans.
# That includes a legitimate ForceNew change to either durable Route53 record:
# the replacement workflow is not a bypass, so an operator must split such a
# migration into a separately reviewed plan before attempting the DMZ rollout.
DURABLE_RELAY_ROOT_PARENT = ""
DURABLE_RELAY_IDENTITY_PARENT = "module.relay_identity[0]"
DURABLE_RELAY_FLEET_PARENT = "module.relay[0]"
DURABLE_RELAY_RESOURCES = {
    ("aws_secretsmanager_secret", "relay"): DURABLE_RELAY_IDENTITY_PARENT,
    ("aws_ssm_parameter", "relay_public_key"): DURABLE_RELAY_IDENTITY_PARENT,
    ("aws_acm_certificate", "relay"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_acm_certificate_validation", "relay"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_route53_record", "relay_cert_validation"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_route53_record", "relay_alias"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_ssm_parameter", "relay_image_tag"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_ssm_parameter", "relay_asg_name"): DURABLE_RELAY_ROOT_PARENT,
    ("aws_s3_bucket", "alb_access_logs"): DURABLE_RELAY_FLEET_PARENT,
    (
        "aws_s3_bucket_lifecycle_configuration",
        "alb_access_logs",
    ): DURABLE_RELAY_FLEET_PARENT,
    ("aws_s3_bucket_ownership_controls", "alb_access_logs"): DURABLE_RELAY_FLEET_PARENT,
    ("aws_s3_bucket_policy", "alb_access_logs"): DURABLE_RELAY_FLEET_PARENT,
    ("aws_s3_bucket_public_access_block", "alb_access_logs"): (
        DURABLE_RELAY_FLEET_PARENT
    ),
    (
        "aws_s3_bucket_server_side_encryption_configuration",
        "alb_access_logs",
    ): DURABLE_RELAY_FLEET_PARENT,
    ("aws_s3_bucket_versioning", "alb_access_logs"): DURABLE_RELAY_FLEET_PARENT,
}


# The initial relay-DMZ cutover is complete. These address families comprise the
# steady-state boundary, the singleton
# fleet that inhabits it, the main-VPC route-table cutover, the server return
# hole, the sandbox-only CI IAM grants, and the two durable handoff resources.
# A non-noop action in any family must fail ordinary deployment and require a
# newly reviewed migration mechanism. This intentionally includes the shared
# legacy context_lookups policy: even an unrelated edit to that policy must fail
# the automatic apply path because it shares the IAM document that carries relay
# discovery. Prefix/suffix regexes deliberately support the root, nested-module,
# and counted-parent Terraform JSON shapes.
DMZ_BOUNDARY_ADDRESS_PATTERNS = (
    re.compile(r"(?:^|\.)module\.relay_network(?:\[[^]]+\])?\."),
    re.compile(r"(?:^|\.)module\.relay(?:\[[^]]+\])?\."),
    re.compile(
        r"(?:^|\.)module\.networking(?:\[[^]]+\])?\."
        r"(?:aws_route_table\.private_extensible|"
        r"aws_route\.private_extensible_default|"
        r"terraform_data\.private_extensible_association_ready|"
        r"aws_route_table_association\.private|"
        r"aws_vpc_endpoint\.s3)(?:\[|$)"
    ),
    re.compile(
        r"(?:^|\.)module\.compute(?:\[[^]]+\])?\."
        r"(?:aws_lb\.server|"
        r"aws_lb\.server_internal|"
        r"aws_lb_listener\.(?:udp|udp_internal)|"
        r"aws_lb_target_group\.(?:udp|udp_green|udp_internal|udp_internal_green)|"
        r"aws_autoscaling_attachment\.(?:server|server_internal)|"
        r"aws_autoscaling_group\.server_green|"
        r"aws_vpc_security_group_ingress_rule\.server_nhp_udp(?:_additional)?)"
        r"(?:\[|$)"
    ),
    re.compile(
        r"(?:^|\.)module\.ecr(?:\[[^]]+\])?\."
        r"(?:aws_iam_role_policy\.context_lookups|"
        r"aws_iam_role_policy\.context_lookups_relay_ssm|"
        r"aws_iam_policy\.terraform_apply_relay_dmz|"
        r"aws_iam_role_policy_attachment\.terraform_apply_relay_dmz)(?:\[|$)"
    ),
    re.compile(
        r"(?:^|\.)(?:"
        r"time_sleep\.relay_dmz_iam_propagation|"
        r"terraform_data\.relay_dmz_preconditions|"
        r"terraform_data\.relay_cell_routing|"
        r"terraform_data\.relay_network_ready|"
        r"aws_cloudwatch_metric_alarm\.relay_dmz_dns_blocked|"
        r"aws_route53_record\.relay_alias|"
        r"aws_ssm_parameter\.relay_asg_name)(?:\[|$)"
    ),
)


def is_dmz_boundary_address(address: str) -> bool:
    """Return whether a managed address belongs to the manual DMZ boundary."""
    return any(pattern.search(address) for pattern in DMZ_BOUNDARY_ADDRESS_PATTERNS)


def validate_dmz_boundary_noop(plan: dict[str, Any]) -> list[str]:
    """Reject boundary mutations from the automatic push-to-main apply path."""
    errors: list[str] = []
    for raw in plan.get("resource_changes", []):
        if raw.get("mode", "managed") != "managed":
            continue
        address = str(raw.get("address", ""))
        if not is_dmz_boundary_address(address):
            continue
        actions = tuple((raw.get("change") or {}).get("actions") or ())
        if actions != ("no-op",):
            errors.append(
                "automatic apply refuses relay-DMZ boundary change "
                f"{address} ({', '.join(actions) or 'missing actions'}); "
                "apply the exact reviewed saved plan with "
                "docs/runbooks/sandbox-relay-dmz-replacement.md, then rerun "
                "the workflow against a no-op boundary plan"
            )
    return errors


@dataclass(frozen=True)
class PlannedResource:
    address: str
    resource_type: str
    name: str
    values: dict[str, Any]
    after_unknown: dict[str, Any] | None
    before: dict[str, Any] | None
    actions: tuple[str, ...]


@dataclass(frozen=True)
class RelayTopology:
    vpc: PlannedResource
    network: list[PlannedResource]
    relay: list[PlannedResource]
    parent_prefix: str
    parent_config_suffix: str
    network_config_suffix: str
    relay_config_suffix: str


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)

    def one(
        self, resources: Iterable[PlannedResource], label: str
    ) -> PlannedResource | None:
        found = list(resources)
        self.require(
            len(found) == 1, f"expected exactly one {label}; found {len(found)}"
        )
        return found[0] if len(found) == 1 else None


def active_resources(plan: dict[str, Any]) -> list[PlannedResource]:
    resources: list[PlannedResource] = []
    for raw in plan.get("resource_changes", []):
        if raw.get("mode", "managed") != "managed":
            continue
        change = raw.get("change", {})
        after = change.get("after")
        # Pure deletes intentionally have after=null and are absent from the
        # desired graph checked below. validate_plan's raw resource_changes pass
        # separately rejects delete/replace/forget for every durable relay
        # resource before this final-state projection is built.
        if not isinstance(after, dict):
            continue
        resources.append(
            PlannedResource(
                address=str(raw.get("address", "")),
                resource_type=str(raw.get("type", "")),
                name=str(raw.get("name", "")),
                values=after,
                after_unknown=change.get("after_unknown")
                if isinstance(change.get("after_unknown"), dict)
                else None,
                before=change.get("before")
                if isinstance(change.get("before"), dict)
                else None,
                actions=tuple(change.get("actions", [])),
            )
        )
    return resources


def resources_named(
    resources: Iterable[PlannedResource], resource_type: str, name: str
) -> list[PlannedResource]:
    return [
        resource
        for resource in resources
        if resource.resource_type == resource_type and resource.name == name
    ]


def address_is_scoped_resource(
    address: str, parent_suffix: str, resource_type: str, name: str
) -> bool:
    """Match one reviewed module path, allowing an optional instance key."""
    base_address = (
        f"{parent_suffix}.{resource_type}.{name}"
        if parent_suffix
        else f"{resource_type}.{name}"
    )
    return address == base_address or (
        address.startswith(f"{base_address}[") and address.endswith("]")
    )


def child_module_prefix(parent_prefix: str, child_prefix: str) -> str:
    """Compose an optional topology parent with a reviewed relative child."""
    if parent_prefix and child_prefix:
        return f"{parent_prefix}.{child_prefix}"
    return parent_prefix or child_prefix


def parent_prefix_from_scoped_address(
    address: str, child_prefix: str, resource_type: str, name: str
) -> str | None:
    """Recover a topology parent from an exact identity/fleet resource path."""
    if address_is_scoped_resource(address, child_prefix, resource_type, name):
        return ""
    marker = f".{child_prefix}.{resource_type}.{name}"
    marker_at = address.rfind(marker)
    if marker_at < 0:
        return None
    parent_prefix = address[:marker_at]
    scoped_parent = child_module_prefix(parent_prefix, child_prefix)
    return (
        parent_prefix
        if address_is_scoped_resource(address, scoped_parent, resource_type, name)
        else None
    )


def durable_parent_prefixes(plan: dict[str, Any]) -> set[str]:
    """Infer relay owners even when an allow-disabled plan has no DMZ topology."""
    # Exact root-level durable addresses are unambiguous and safe to protect
    # without an identity anchor; nested/counted owners are inferred below.
    prefixes: set[str] = {""}
    for raw in plan.get("resource_changes", []):
        if raw.get("mode", "managed") != "managed":
            continue
        identity = (str(raw.get("type", "")), str(raw.get("name", "")))
        relative_parent = DURABLE_RELAY_RESOURCES.get(identity)
        # A nested root-relative type/name alone cannot prove relay ownership
        # without globally matching unrelated same-named resources. Complete
        # plans retain a no-op identity/fleet resource as that exact owner
        # anchor; the dark-plan matrix exercises both paths.
        if not relative_parent:
            continue
        parent_prefix = parent_prefix_from_scoped_address(
            str(raw.get("address", "")), relative_parent, *identity
        )
        if parent_prefix is not None:
            prefixes.add(parent_prefix)
    return prefixes


def address_matches_suffix(address: str, suffix: str) -> bool:
    """Match a root-level or nested Terraform module/resource address."""
    return address == suffix or address.endswith(f".{suffix}")


def iter_config_modules(
    module: dict[str, Any], path: str = ""
) -> Iterable[tuple[str, dict[str, Any]]]:
    yield path, module
    for name, call in (module.get("module_calls") or {}).items():
        child = call.get("module")
        if not isinstance(child, dict):
            continue
        child_path = f"{path}.module.{name}" if path else f"module.{name}"
        yield from iter_config_modules(child, child_path)


def config_module(
    v: Validation, plan: dict[str, Any], suffix: str
) -> dict[str, Any] | None:
    root = (plan.get("configuration") or {}).get("root_module")
    if not isinstance(root, dict):
        return None
    matches = [
        module
        for path, module in iter_config_modules(root)
        if path == suffix or path.endswith(f".{suffix}")
    ]
    v.require(
        len(matches) <= 1,
        f"configuration module suffix {suffix!r} is ambiguous; found {len(matches)} matches",
    )
    return matches[0] if len(matches) == 1 else None


def config_resource(
    v: Validation,
    module: dict[str, Any] | None,
    resource_type: str,
    name: str,
) -> dict[str, Any] | None:
    if not module:
        return None
    matches = [
        resource
        for resource in module.get("resources", [])
        if resource.get("type") == resource_type and resource.get("name") == name
    ]
    v.require(
        len(matches) <= 1,
        f"configuration resource {resource_type}.{name} is ambiguous; found {len(matches)} matches",
    )
    return matches[0] if len(matches) == 1 else None


def config_output_refs(module: dict[str, Any] | None, name: str) -> set[str]:
    if not module:
        return set()
    output = (module.get("outputs") or {}).get(name)
    if not isinstance(output, dict):
        return set()
    return references(output.get("expression"))


def references(value: Any) -> set[str]:
    # Terraform 1.14.x serializes a module-output traversal as both the leaf and
    # its enclosing module (for example, module.compute.nlb_dns_name plus
    # module.compute). Exact graph contracts must pin both; a Terraform upgrade
    # that changes this shape requires the documented real-plan recapture.
    found: set[str] = set()
    if isinstance(value, dict):
        raw_refs = value.get("references")
        if isinstance(raw_refs, list):
            found.update(str(ref) for ref in raw_refs)
        for key, child in value.items():
            # A malformed non-list `references` value may still contain valid
            # nested reference lists; recurse so corruption fails closed rather
            # than hiding the usable graph evidence beneath it.
            if key == "references" and isinstance(raw_refs, list):
                continue
            found.update(references(child))
    elif isinstance(value, list):
        for child in value:
            found.update(references(child))
    return found


def matches_exact_int_or_int_string(value: Any, expected: int) -> bool:
    """Accept the canonical decimal string form or an exact JSON integer."""
    # `type(...) is int` intentionally excludes bool (an int subclass), while
    # the explicit type check rejects 30.0, which otherwise compares equal to 30.
    return (type(value) is int and value == expected) or value == str(expected)


def expression_refs(resource: dict[str, Any] | None, attribute: str) -> set[str]:
    if not resource:
        return set()
    return references((resource.get("expressions") or {}).get(attribute))


def call_refs(call: dict[str, Any] | None, argument: str) -> set[str]:
    if not call:
        return set()
    return references((call.get("expressions") or {}).get(argument))


def references_exact_resources(
    refs: set[str],
    expected: set[str],
    *,
    allowed_metadata: frozenset[str] = frozenset(),
) -> bool:
    """Accept exact reviewed resource traversals plus named control metadata."""
    # Any extra traversal can redirect a create-time-unknown boundary field
    # through an unreviewed conditional branch. Metadata is therefore denied
    # by default and admitted only by the one call site that reviews its exact
    # staging-gate variable separately.
    if any(
        not ref.startswith(("aws_", "terraform_data.")) and ref not in allowed_metadata
        for ref in refs
    ):
        return False
    resource_refs = {ref for ref in refs if ref.startswith(("aws_", "terraform_data."))}

    def targets(ref: str, base: str) -> bool:
        return ref == base or ref.startswith(f"{base}.") or ref.startswith(f"{base}[")

    return all(
        any(targets(ref, base) for ref in resource_refs) for base in expected
    ) and all(any(targets(ref, base) for base in expected) for ref in resource_refs)


def refs_match_expected(refs: set[str], expected: str) -> bool:
    """Match an exact variable reference or reviewed resource traversal."""
    if expected.startswith("var."):
        return refs == {expected}
    return references_exact_resources(refs, {expected})


def address_key(address: str) -> str | None:
    """Return a terminal string for_each key; numeric count indexes are invalid."""
    match = re.search(r'(\["(?:[^"\\]|\\.)*"\])$', address)
    if not match:
        return None
    try:
        key = json.loads(match.group(1)[1:-1])
    except json.JSONDecodeError:
        return None
    return key if isinstance(key, str) else None


def index_by_address_key(
    v: Validation, resources: Iterable[PlannedResource], label: str
) -> dict[str, PlannedResource]:
    indexed: dict[str, PlannedResource] = {}
    missing: list[str] = []
    duplicates: set[str] = set()
    for resource in resources:
        key = address_key(resource.address)
        if key is None:
            missing.append(resource.address)
            continue
        if key in indexed:
            duplicates.add(key)
            continue
        indexed[key] = resource
    v.require(
        not missing,
        f"{label} addresses must end in a string for_each key; invalid addresses: {sorted(missing)!r}",
    )
    v.require(
        not duplicates,
        f"{label} address keys must be unique; duplicates: {sorted(duplicates)!r}",
    )
    return indexed


def as_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def string_condition(statement: dict[str, Any], operator: str) -> dict[str, Any] | None:
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return None
    clause = condition.get(operator)
    return clause if isinstance(clause, dict) else None


def endpoint_allow_contracts(
    relay_secret_arn: str | None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Return the exact non-GuardDuty sandbox endpoint Allow statements.

    A missing relay_secret_arn deliberately produces an empty Secrets Manager
    resource set. The durable-secret check emits the primary sequencing error;
    the empty set makes any resolved policy fail closed with a secondary
    endpoint-contract error instead of accepting an unverified ARN.
    """
    return {
        "ecr-api": {
            "RelayAuthorizationToken": {
                "actions": {"ecr:GetAuthorizationToken"},
                "resources": {"*"},
                "condition": None,
            },
            "RelayRepositoryRead": {
                "actions": {
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                },
                "resources": {EXPECTED_SANDBOX_RELAY_REPO_ARN},
                "condition": None,
            },
        },
        "ecr-dkr": {
            "RelayRepositoryRegistryRead": {
                "actions": {
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                },
                "resources": {EXPECTED_SANDBOX_RELAY_REPO_ARN},
                "condition": None,
            }
        },
        "secretsmanager": {
            "RelayIdentityRead": {
                "actions": {"secretsmanager:GetSecretValue"},
                "resources": {relay_secret_arn} if relay_secret_arn else set(),
                "condition": None,
            }
        },
        "ssm": {
            "RelayImageTagRead": {
                "actions": {"ssm:GetParameter"},
                "resources": {EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN},
                "condition": None,
            },
            "RelayManagedInstanceCore": {
                "actions": EXPECTED_RELAY_IAM_SSM_ACTIONS,
                "resources": {"*"},
                "condition": None,
            },
        },
        "ssmmessages": {
            "RelaySessionChannels": {
                "actions": EXPECTED_INTERFACE_ENDPOINTS["ssmmessages"],
                "resources": {"*"},
                "condition": None,
            }
        },
        "logs": {
            "RelayLogWrite": {
                "actions": EXPECTED_INTERFACE_ENDPOINTS["logs"],
                "resources": {EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN},
                "condition": None,
            }
        },
        "monitoring": {
            "RelayMetrics": {
                "actions": {"cloudwatch:PutMetricData"},
                "resources": {"*"},
                "condition": {
                    "StringEquals": {"cloudwatch:namespace": EXPECTED_METRIC_NAMESPACE}
                },
            }
        },
    }


def policy_statements(policy_text: str) -> list[dict[str, Any]]:
    """Parse the reviewed Terraform jsonencode([...]) policy shape.

    IAM also accepts a singleton Statement object, but every policy in this
    contract is generated from a list; reject any other shape fail closed.
    """
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid endpoint policy JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise ValueError("endpoint policy must be a JSON object")
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not all(
        isinstance(item, dict) for item in statements
    ):
        raise ValueError("endpoint policy Statement must be a list of objects")
    return statements


def statements_with_effect(
    statements: Iterable[dict[str, Any]], effect: str
) -> list[dict[str, Any]]:
    return [statement for statement in statements if statement.get("Effect") == effect]


def index_by_sid(
    statements: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {str(statement.get("Sid")): statement for statement in statements}


def is_cross_account_deny(statement: dict[str, Any]) -> bool:
    # Pin the reviewed literal shape, not merely IAM-equivalent semantics.
    # {"AWS": "*"} therefore fails closed and requires an explicit contract
    # review instead of silently widening the accepted policy representation.
    not_equals = string_condition(statement, "StringNotEquals")
    return (
        statement.get("Sid") == "DenyCrossAccountPrincipals"
        and statement.get("Effect") == "Deny"
        and statement.get("Principal") == "*"
        and set(as_strings(statement.get("Action"))) == {"*"}
        and statement.get("Resource") == "*"
        and not_equals is not None
        and set(not_equals) == {"aws:PrincipalAccount"}
        and not_equals["aws:PrincipalAccount"] == EXPECTED_SANDBOX_ACCOUNT_ID
    )


def check_endpoint_policy(
    v: Validation,
    key: str,
    policy_text: str,
    allow_contracts: dict[str, dict[str, dict[str, Any]]],
) -> None:
    expected_actions = EXPECTED_INTERFACE_ENDPOINTS.get(key)
    if expected_actions is None:
        v.errors.append(f"{key} endpoint has no reviewed action contract")
        return
    try:
        statements = policy_statements(policy_text)
    except ValueError as exc:
        v.errors.append(f"{key} endpoint: {exc}")
        return

    denies = [statement for statement in statements if is_cross_account_deny(statement)]
    v.require(
        len(denies) == 1,
        f"{key} endpoint must contain exactly one complete cross-account deny",
    )
    v.require(
        len(statements_with_effect(statements, "Deny")) == 1,
        f"{key} endpoint must not replace or dilute the reviewed deny shape",
    )

    allow_statements = statements_with_effect(statements, "Allow")
    allow_actions: set[str] = set()
    for statement in allow_statements:
        v.require(
            "NotAction" not in statement,
            f"{key} endpoint allow statements must not use NotAction",
        )
        allow_actions.update(as_strings(statement.get("Action")))

    v.require(
        allow_actions == expected_actions,
        f"{key} endpoint allow actions changed: got {sorted(allow_actions)!r}",
    )
    if key != "guardduty-data":
        # The durable-secret check emits the primary sequencing error when the
        # ARN is unknown. If a Secrets Manager policy nevertheless resolves,
        # its empty expected resource set deliberately produces a secondary
        # fail-closed contract error rather than accepting an unverified ARN.
        expected_by_sid = allow_contracts.get(key)
        if expected_by_sid is None:
            v.errors.append(f"{key} endpoint has no reviewed allow contract")
            return
        actual_by_sid = index_by_sid(allow_statements)
        v.require(
            len(allow_statements) == len(expected_by_sid)
            and set(actual_by_sid) == set(expected_by_sid),
            f"{key} endpoint allow statement set changed",
        )
        for sid, expected in expected_by_sid.items():
            statement = actual_by_sid.get(sid)
            if not statement:
                continue
            v.require(
                statement.get("Effect") == "Allow"
                and statement.get("Principal") == "*"
                and set(as_strings(statement.get("Action"))) == expected["actions"]
                and set(as_strings(statement.get("Resource"))) == expected["resources"]
                and statement.get("Condition") == expected["condition"],
                f"{key} endpoint {sid} allow contract changed",
            )
    if "*" in allow_actions:
        v.require(
            key == "guardduty-data"
            and len(statements) == 2
            and any(
                statement.get("Sid") == "RelayRuntimeTelemetry"
                and statement.get("Effect") == "Allow"
                and statement.get("Principal") == "*"
                and set(as_strings(statement.get("Action"))) == {"*"}
                and statement.get("Resource") == "*"
                for statement in statements
            )
            and len(denies) == 1,
            "Action=* is allowed only for the exact GuardDuty telemetry allow plus cross-account deny",
        )


def check_relay_iam_policy(
    v: Validation,
    policy_text: str,
    expected_secret_resource: str | None,
    expected_repo_resource: str | None,
    expected_log_resource: str | None,
    expected_image_tag_resource: str | None,
    expected_kms_resource: str | None,
) -> None:
    try:
        statements = policy_statements(policy_text)
    except ValueError as exc:
        v.errors.append(f"relay IAM policy: {exc}")
        return

    allow_statements = statements_with_effect(statements, "Allow")
    v.require(
        len(allow_statements) == len(statements),
        "relay IAM policy may contain only reviewed Allow statements",
    )
    actions = {
        action
        for statement in allow_statements
        for action in as_strings(statement.get("Action"))
    }
    expected_actions = set(EXPECTED_RELAY_IAM_ACTIONS)
    if "kms:Decrypt" in actions:
        expected_actions.add("kms:Decrypt")
    v.require(
        actions == expected_actions,
        f"relay IAM action set changed: got {sorted(actions)!r}",
    )
    v.require(
        not any(action.startswith("ec2messages:") for action in actions)
        and "ssm:GetDeployablePatchSnapshotForInstance" not in actions,
        "relay IAM must not regain ec2messages or patch-snapshot permissions",
    )

    expected_statements: list[tuple[str, set[str], set[str], dict[str, Any] | None]] = [
        (
            "Secrets Manager identity read",
            {"secretsmanager:GetSecretValue"},
            {expected_secret_resource}
            if isinstance(expected_secret_resource, str)
            else set(),
            None,
        ),
        ("ECR authorization token", {"ecr:GetAuthorizationToken"}, {"*"}, None),
        (
            "ECR repository read",
            {
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
            },
            {expected_repo_resource}
            if isinstance(expected_repo_resource, str)
            else set(),
            None,
        ),
        (
            "relay log write",
            {"logs:CreateLogStream", "logs:PutLogEvents"},
            {expected_log_resource}
            if isinstance(expected_log_resource, str)
            else set(),
            None,
        ),
        (
            "relay image-tag read",
            {"ssm:GetParameter"},
            {expected_image_tag_resource}
            if isinstance(expected_image_tag_resource, str)
            else set(),
            None,
        ),
        (
            "SSM Agent core",
            EXPECTED_RELAY_IAM_SSM_ACTIONS,
            {"*"},
            None,
        ),
        (
            "SSM message channels",
            set(EXPECTED_INTERFACE_ENDPOINTS["ssmmessages"]),
            {"*"},
            None,
        ),
        (
            "SSM regional bucket read",
            {"s3:GetObject"},
            set(EXPECTED_RELAY_IAM_S3_RESOURCES),
            None,
        ),
        (
            "bootstrap metric write",
            {"cloudwatch:PutMetricData"},
            {"*"},
            {"StringEquals": {"cloudwatch:namespace": EXPECTED_METRIC_NAMESPACE}},
        ),
    ]
    if "kms:Decrypt" in actions:
        expected_statements.append(
            (
                "Secrets Manager KMS decrypt",
                {"kms:Decrypt"},
                {expected_kms_resource}
                if isinstance(expected_kms_resource, str)
                else set(),
                {
                    "StringEquals": {
                        "kms:CallerAccount": EXPECTED_SANDBOX_ACCOUNT_ID,
                        "kms:ViaService": f"secretsmanager.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
                    }
                },
            )
        )

    actual_action_groups = Counter(
        frozenset(as_strings(statement.get("Action"))) for statement in allow_statements
    )
    expected_action_groups = Counter(
        frozenset(statement_actions)
        for _, statement_actions, _, _ in expected_statements
    )
    v.require(
        actual_action_groups == expected_action_groups,
        "relay IAM statement action partitions changed",
    )
    for (
        label,
        statement_actions,
        statement_resources,
        statement_condition,
    ) in expected_statements:
        matches = [
            statement
            for statement in allow_statements
            if set(as_strings(statement.get("Action"))) == statement_actions
        ]
        v.require(
            len(matches) == 1,
            f"relay IAM must contain exactly one {label} statement",
        )
        if len(matches) != 1:
            continue
        statement = matches[0]
        expected_keys = {"Effect", "Action", "Resource"}
        if statement_condition is not None:
            expected_keys.add("Condition")
        v.require(
            set(statement) == expected_keys,
            f"relay IAM {label} statement shape changed",
        )
        v.require(
            set(as_strings(statement.get("Resource"))) == statement_resources,
            f"relay IAM {label} resource allowlist changed",
        )
        v.require(
            statement.get("Condition") == statement_condition,
            f"relay IAM {label} condition changed",
        )

    s3_statements = [
        statement
        for statement in allow_statements
        if set(as_strings(statement.get("Action"))) == {"s3:GetObject"}
    ]
    v.require(
        len(s3_statements) == 1,
        "relay IAM must contain exactly one S3 GetObject statement",
    )
    if len(s3_statements) == 1:
        v.require(
            set(as_strings(s3_statements[0].get("Resource")))
            == EXPECTED_RELAY_IAM_S3_RESOURCES,
            "relay IAM S3 bucket allowlist changed",
        )

    kms_statements = [
        statement
        for statement in allow_statements
        if "kms:Decrypt" in set(as_strings(statement.get("Action")))
    ]
    v.require(
        len(kms_statements) <= 1,
        "relay IAM may contain at most one KMS decrypt statement",
    )
    if len(kms_statements) == 1:
        kms_statement = kms_statements[0]
        v.require(
            set(as_strings(kms_statement.get("Action"))) == {"kms:Decrypt"},
            "relay KMS decrypt must be isolated in its own statement",
        )
        v.require(
            expected_kms_resource is not None
            and set(as_strings(kms_statement.get("Resource")))
            == {expected_kms_resource},
            "relay KMS decrypt must target exactly the planned sandbox Secrets Manager KMS key",
        )
        equals = string_condition(kms_statement, "StringEquals")
        v.require(
            equals is not None
            and set(equals) == {"kms:CallerAccount", "kms:ViaService"}
            and equals.get("kms:CallerAccount") == EXPECTED_SANDBOX_ACCOUNT_ID
            and str(equals.get("kms:ViaService", ""))
            == f"secretsmanager.{EXPECTED_SANDBOX_REGION}.amazonaws.com",
            "relay KMS decrypt must require the sandbox CallerAccount and the regional Secrets Manager ViaService",
        )


def check_context_lookups_ssm_policy(
    v: Validation, context_policy_text: str, relay_policy_text: str
) -> None:
    """Pin the complete SSM envelope while preserving unrelated base lookups.

    ``context_lookups`` predates the relay and also owns non-SSM discovery such
    as EC2 describes; those grants belong to the shared context-lookup contract,
    outside this relay-DMZ delta. This checker therefore rejects any drift in its
    SSM actions without claiming to bound the base policy's non-SSM statements.
    The relay-added ``context_lookups_relay_ssm`` policy is fully shape-pinned
    below because that entire policy is new relay reachability.
    """
    try:
        context_statements = policy_statements(context_policy_text)
        relay_statements = policy_statements(relay_policy_text)
    except ValueError as exc:
        v.errors.append(f"context-lookups SSM policy: {exc}")
        return

    statements = context_statements + relay_statements
    normalized_ssm_actions: Counter[str] = Counter()
    ssm_wildcards: list[str] = []
    not_action_sids: list[str] = []
    for statement in statements:
        if "NotAction" in statement:
            not_action_sids.append(str(statement.get("Sid")))
        for action in as_strings(statement.get("Action")):
            normalized = action.lower()
            if normalized in {"*", "ssm*"} or (
                normalized.startswith("ssm:") and "*" in normalized
            ):
                ssm_wildcards.append(action)
            if normalized.startswith("ssm:"):
                normalized_ssm_actions[normalized] += 1
    v.require(
        not not_action_sids,
        f"context-lookups IAM must not use NotAction; found in {not_action_sids!r}",
    )
    v.require(
        not ssm_wildcards,
        f"context-lookups IAM must not use wildcard actions that include Systems Manager: {ssm_wildcards!r}",
    )
    v.require(
        normalized_ssm_actions
        == Counter(
            {
                "ssm:getparameter": 1,
                "ssm:sendcommand": 2,
                "ssm:getcommandinvocation": 1,
            }
        ),
        f"context-lookups case-normalized SSM action envelope changed: {dict(normalized_ssm_actions)!r}",
    )
    context_ssm_statements = [
        statement
        for statement in context_statements
        if any(
            action.lower().startswith("ssm:")
            for action in as_strings(statement.get("Action"))
        )
    ]
    v.require(
        len(context_ssm_statements) == 1
        and context_ssm_statements[0].get("Sid") == "ContextLookups"
        and "ssm:GetParameter" in as_strings(context_ssm_statements[0].get("Action")),
        "context-lookups must retain only the existing ssm:GetParameter action in ContextLookups when relay is enabled",
    )

    command_actions = {"ssm:sendcommand", "ssm:getcommandinvocation"}
    command_statements = [
        statement
        for statement in relay_statements
        if {action.lower() for action in as_strings(statement.get("Action"))}
        & command_actions
    ]
    by_sid = index_by_sid(command_statements)
    v.require(
        len(command_statements) == 3
        and set(by_sid)
        == {
            "SSMHealthCheckDocument",
            "SSMHealthCheckSandboxInstances",
            "SSMHealthCheckInvocation",
        },
        "relay-only SSM policy must contain exactly document, sandbox-instance, and invocation statements",
    )
    v.require(
        by_sid.get("SSMHealthCheckDocument")
        == {
            "Sid": "SSMHealthCheckDocument",
            "Effect": "Allow",
            "Action": "ssm:SendCommand",
            "Resource": f"arn:aws:ssm:{EXPECTED_SANDBOX_REGION}::document/AWS-RunShellScript",
        },
        "SSM SendCommand document access must name only the commercial AWS-owned AWS-RunShellScript document",
    )
    v.require(
        by_sid.get("SSMHealthCheckSandboxInstances")
        == {
            "Sid": "SSMHealthCheckSandboxInstances",
            "Effect": "Allow",
            "Action": "ssm:SendCommand",
            "Resource": f"arn:aws:ec2:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:instance/*",
            "Condition": {"StringEquals": {"ssm:resourceTag/Environment": "sandbox"}},
        },
        "SSM SendCommand instance access must be same-account and require Environment=sandbox",
    )
    v.require(
        by_sid.get("SSMHealthCheckInvocation")
        == {
            "Sid": "SSMHealthCheckInvocation",
            "Effect": "Allow",
            "Action": "ssm:GetCommandInvocation",
            "Resource": "*",
        },
        "SSM GetCommandInvocation must remain an action-only Resource=* grant because AWS exposes no resource type for it",
    )


def check_logs_kms_policy(v: Validation, policy_text: str) -> None:
    try:
        statements = policy_statements(policy_text)
    except ValueError as exc:
        v.errors.append(f"relay logs KMS policy: {exc}")
        return
    by_sid = index_by_sid(statements)
    v.require(
        len(statements) == 2
        and set(by_sid) == {"EnableAccountAdministration", "AllowDmzCloudWatchLogs"},
        "relay logs KMS policy statement set changed",
    )
    admin = by_sid.get("EnableAccountAdministration")
    if isinstance(admin, dict):
        v.require(
            admin
            == {
                "Sid": "EnableAccountAdministration",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{EXPECTED_SANDBOX_ACCOUNT_ID}:root"
                },
                "Action": "kms:*",
                "Resource": "*",
            },
            "relay logs KMS administration must remain pinned to the sandbox account root",
        )
    service = by_sid.get("AllowDmzCloudWatchLogs")
    if not isinstance(service, dict):
        return
    v.require(
        service.get("Effect") == "Allow"
        and service.get("Principal")
        == {"Service": f"logs.{EXPECTED_SANDBOX_REGION}.amazonaws.com"}
        and set(as_strings(service.get("Action"))) == EXPECTED_LOG_KMS_ACTIONS
        and service.get("Resource") == "*",
        "relay logs KMS service grant changed",
    )
    conditions = service.get("Condition")
    arn_equals = string_condition(service, "ArnEquals")
    contexts = (
        as_strings(arn_equals.get("kms:EncryptionContext:aws:logs:arn"))
        if arn_equals is not None
        else []
    )
    v.require(
        isinstance(conditions, dict) and set(conditions) == {"ArnEquals"},
        "relay logs KMS grant must use only the exact Logs encryption-context condition",
    )
    v.require(
        len(contexts) == 2
        and set(contexts)
        == {
            EXPECTED_SANDBOX_DMZ_FLOW_LOG_GROUP_ARN,
            EXPECTED_SANDBOX_DMZ_RESOLVER_LOG_GROUP_ARN,
        },
        "relay logs KMS encryption context must name exactly the flow and Resolver log groups",
    )


def check_flow_logs_role(
    v: Validation, policy_text: str, trust_policy_text: str
) -> None:
    group_arn = EXPECTED_SANDBOX_DMZ_FLOW_LOG_GROUP_ARN
    try:
        statements = policy_statements(policy_text)
        trust_statements = policy_statements(trust_policy_text)
    except ValueError as exc:
        v.errors.append(f"Flow Logs role: {exc}")
        return
    by_sid = index_by_sid(statements)
    v.require(
        len(statements) == 3
        and set(by_sid)
        == {
            "DiscoverFlowLogGroup",
            "DescribeFlowLogStreams",
            "WriteFlowLogStreams",
        },
        "Flow Logs role must contain exactly the three action-scoped statements",
    )
    discover = by_sid.get("DiscoverFlowLogGroup", {})
    describe = by_sid.get("DescribeFlowLogStreams", {})
    write = by_sid.get("WriteFlowLogStreams", {})
    v.require(
        discover.get("Effect") == "Allow"
        and discover.get("Action") == "logs:DescribeLogGroups"
        and discover.get("Resource") == "*",
        "Flow Logs DescribeLogGroups must use Resource=*",
    )
    v.require(
        describe.get("Effect") == "Allow"
        and describe.get("Action") == "logs:DescribeLogStreams"
        and describe.get("Resource") == group_arn,
        "Flow Logs DescribeLogStreams must use the exact log-group ARN",
    )
    v.require(
        write.get("Effect") == "Allow"
        and set(as_strings(write.get("Action")))
        == {"logs:CreateLogStream", "logs:PutLogEvents"}
        and write.get("Resource") == f"{group_arn}:*",
        "Flow Logs stream writes must use only the dedicated log-stream ARN wildcard",
    )
    v.require(
        trust_statements
        == [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": EXPECTED_SANDBOX_ACCOUNT_ID},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:ec2:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:vpc-flow-log/*"
                    },
                },
            }
        ],
        "Flow Logs role trust must be scoped to this account's regional flow logs",
    )


def resolve_relay_topology(
    v: Validation,
    resources: list[PlannedResource],
    *,
    require_enabled: bool,
) -> RelayTopology | None:
    """Find root or nested relay modules and compose their address prefixes."""
    network_vpc_suffix = "module.relay_network[0].aws_vpc.relay"
    vpcs = [
        resource
        for resource in resources
        if address_matches_suffix(resource.address, network_vpc_suffix)
    ]
    if not vpcs:
        if require_enabled:
            v.errors.append("relay DMZ is not present in the final planned state")
        return None
    vpc = v.one(vpcs, "relay-network VPC")
    if not vpc:
        return None

    network_prefix = vpc.address[: -len(".aws_vpc.relay")]
    network_module_address = "module.relay_network[0]"
    parent_prefix = (
        ""
        if network_prefix == network_module_address
        else network_prefix[: -(len(network_module_address) + 1)]
    )
    relay_prefix = (
        f"{parent_prefix}.module.relay[0]" if parent_prefix else "module.relay[0]"
    )
    parent_config_prefix = re.sub(r"\[[^]]+\]", "", parent_prefix)
    network_config_suffix = (
        f"{parent_config_prefix}.module.relay_network"
        if parent_config_prefix
        else "module.relay_network"
    )
    relay_config_suffix = (
        f"{parent_config_prefix}.module.relay"
        if parent_config_prefix
        else "module.relay"
    )
    return RelayTopology(
        vpc=vpc,
        network=[
            resource
            for resource in resources
            if resource.address.startswith(f"{network_prefix}.")
        ],
        relay=[
            resource
            for resource in resources
            if resource.address.startswith(f"{relay_prefix}.")
        ],
        parent_prefix=parent_prefix,
        parent_config_suffix=parent_config_prefix,
        network_config_suffix=network_config_suffix,
        relay_config_suffix=relay_config_suffix,
    )


def check_relay_routes(
    v: Validation,
    resources: list[PlannedResource],
    network: list[PlannedResource],
    network_config: dict[str, Any] | None,
    parent_prefix: str,
    relay_cidrs: list[str],
) -> set[str]:
    """Validate all explicit DMZ and peering routes against planned subnets."""
    routes = [resource for resource in network if resource.resource_type == "aws_route"]
    v.require(
        Counter(resource.name for resource in routes)
        == Counter(
            {
                "public_default": 1,
                "relay_to_main_private": 9,
                "main_private_to_relay": 3,
            }
        ),
        "explicit DMZ route inventory changed",
    )
    defaults = [
        resource
        for resource in routes
        if resource.values.get("destination_cidr_block") == EXPECTED_IPV4_DEFAULT_CIDR
        or resource.values.get("destination_ipv6_cidr_block") == "::/0"
    ]
    v.require(
        len(defaults) == 1 and defaults[0].name == "public_default",
        "the public route table must be the only DMZ route table with a default route",
    )
    # This concrete-value check is belt-and-suspenders. A newly-created NAT
    # target can remain unknown at plan time, so the resource-level NAT ban in
    # validate_plan and the exact default-route contract above are the primary
    # defenses.
    v.require(
        all(not resource.values.get("nat_gateway_id") for resource in routes),
        "no DMZ route may target a NAT gateway",
    )
    v.require(
        all(
            not resource.values.get("destination_prefix_list_id") for resource in routes
        ),
        "explicit DMZ routes must not use destination prefix lists",
    )

    main_network_prefix = (
        f"{parent_prefix}.module.networking" if parent_prefix else "module.networking"
    )
    main_private_subnets = [
        resource
        for resource in resources
        if resource.address.startswith(f"{main_network_prefix}.")
        and resource.resource_type == "aws_subnet"
        and resource.name == "private"
    ]
    main_private_cidrs = [
        resource.values.get("cidr_block") for resource in main_private_subnets
    ]
    v.require(
        len(main_private_subnets) == 3
        and all(isinstance(cidr, str) for cidr in main_private_cidrs)
        and len(set(main_private_cidrs)) == 3,
        "main networking must expose exactly three concrete private subnet CIDRs",
    )

    relay_to_main = resources_named(network, "aws_route", "relay_to_main_private")
    main_private_route_destinations = Counter(
        resource.values.get("destination_cidr_block") for resource in relay_to_main
    )
    expected_forward = Counter(
        {str(cidr): 3 for cidr in main_private_cidrs if isinstance(cidr, str)}
    )
    v.require(
        len(relay_to_main) == 9 and main_private_route_destinations == expected_forward,
        "relay-to-main peering routes must target each exact planned main-private subnet /24 from all three relay route tables",
    )

    main_to_relay = resources_named(network, "aws_route", "main_private_to_relay")
    return_destinations = Counter(
        resource.values.get("destination_cidr_block") for resource in main_to_relay
    )
    v.require(
        len(main_to_relay) == 3 and return_destinations == Counter(relay_cidrs),
        "main-private return routes must cover each of the three relay /24s exactly once and no broader CIDR",
    )
    expected_peering_refs = {
        "aws_vpc_peering_connection.main.id",
        "aws_vpc_peering_connection.main",
    }
    alternative_target_fields = {
        "carrier_gateway_id",
        "core_network_arn",
        "egress_only_gateway_id",
        "gateway_id",
        "instance_id",
        "local_gateway_id",
        "nat_gateway_id",
        "network_interface_id",
        "odb_network_arn",
        "transit_gateway_id",
        "vpc_endpoint_id",
    }
    for route_name, route_resources in (
        ("relay_to_main_private", relay_to_main),
        ("main_private_to_relay", main_to_relay),
    ):
        route_config = config_resource(v, network_config, "aws_route", route_name)
        v.require(
            expression_refs(route_config, "vpc_peering_connection_id")
            == expected_peering_refs,
            f"{route_name} routes must target only the reviewed main VPC peering connection",
        )
        v.require(
            all(
                not any(route.values.get(field) for field in alternative_target_fields)
                for route in route_resources
            ),
            f"{route_name} routes must not use an alternative next-hop target",
        )
    return {
        str(cidr) for cidr in main_private_route_destinations if isinstance(cidr, str)
    }


def policy_text(
    v: Validation, value: Any, label: str, *, require_known: bool
) -> str | None:
    """Return a resolved policy or fail final pre-apply validation."""
    if isinstance(value, str):
        return value
    if require_known:
        v.errors.append(f"{label} must be fully known in the final pre-apply plan")
    return None


def validate_plan(
    plan: dict[str, Any],
    *,
    require_enabled: bool = True,
    require_pr0_applied: bool = False,
    require_dmz_boundary_noop: bool = False,
) -> list[str]:
    v = Validation()
    if require_dmz_boundary_noop:
        v.errors.extend(validate_dmz_boundary_noop(plan))
    for raw in plan.get("resource_changes", []):
        if raw.get("mode", "managed") != "managed":
            continue
        previous_address = str(raw.get("previous_address") or "")
        # All 13 PR0 moves originate under the old module.relay[0], including
        # resources now owned at root/relay_identity; relay_network is #3150-new.
        if (
            require_pr0_applied
            and re.search(r"(?:^|\.)module\.relay\[0\]\.", previous_address)
            and previous_address != str(raw.get("address", ""))
        ):
            v.errors.append(
                f"PR 0 state move {previous_address} -> {raw.get('address')} is still pending; apply and verify PR 0 before the DMZ replacement"
            )
        address = str(raw.get("address", ""))
        protects_main_egress = (
            re.search(
                r"(?:^|\.)module\.networking\."
                r"(?:aws_nat_gateway\.main|aws_eip\.nat|aws_subnet\.private|"
                r"aws_route_table\.private|aws_route_table_association\.private)"
                r"(?:\[|$)",
                address,
            )
            is not None
        )
        actions = tuple((raw.get("change") or {}).get("actions") or ())
        if protects_main_egress and (
            "delete" in actions or "create" in actions or "forget" in actions
        ):
            v.errors.append(
                f"live main-private egress resource {address} must not be created, replaced, destroyed, or forgotten during the DMZ route-table cutover"
            )

    resources = active_resources(plan)
    topology = resolve_relay_topology(v, resources, require_enabled=require_enabled)
    durable_parents = durable_parent_prefixes(plan)
    if topology is not None:
        durable_parents.add(topology.parent_prefix)

    for raw in plan.get("resource_changes", []):
        if raw.get("mode", "managed") != "managed":
            continue
        identity = (str(raw.get("type", "")), str(raw.get("name", "")))
        relative_parent = DURABLE_RELAY_RESOURCES.get(identity)
        if relative_parent is None:
            continue
        actions = tuple((raw.get("change") or {}).get("actions") or ())
        if ("delete" in actions or "forget" in actions) and any(
            address_is_scoped_resource(
                str(raw.get("address", "")),
                child_module_prefix(parent, relative_parent),
                *identity,
            )
            for parent in durable_parents
        ):
            v.errors.append(
                f"durable relay resource {raw.get('address')} must not be destroyed, replaced, or forgotten"
            )

    if topology is None:
        return v.errors
    vpc = topology.vpc
    network = topology.network
    relay = topology.relay
    parent_prefix = topology.parent_prefix
    parent_config_suffix = topology.parent_config_suffix
    network_config_suffix = topology.network_config_suffix
    relay_config_suffix = topology.relay_config_suffix

    def network_named(resource_type: str, name: str) -> list[PlannedResource]:
        return resources_named(network, resource_type, name)

    def relay_named(resource_type: str, name: str) -> list[PlannedResource]:
        return resources_named(relay, resource_type, name)

    kms_parent = child_module_prefix(parent_prefix, "module.kms")
    secrets_kms_key = v.one(
        (
            resource
            for resource in resources
            if address_is_scoped_resource(
                resource.address, kms_parent, "aws_kms_key", "secrets"
            )
        ),
        "sandbox Secrets Manager KMS key",
    )
    expected_secrets_kms_arn = (
        secrets_kms_key.values.get("arn") if secrets_kms_key is not None else None
    )
    v.require(
        isinstance(expected_secrets_kms_arn, str)
        and re.fullmatch(
            rf"arn:aws:kms:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:key/[A-Za-z0-9-]+",
            expected_secrets_kms_arn,
        )
        is not None,
        "sandbox Secrets Manager KMS key ARN must be concrete and account/region pinned",
    )

    # Dedicated VPC and three distinct no-public-IP subnet tiers.
    v.require(
        vpc.values.get("cidr_block") == EXPECTED_SANDBOX_RELAY_VPC_CIDR,
        "sandbox relay VPC must use 10.101.0.0/16",
    )
    for key in (
        "enable_dns_hostnames",
        "enable_dns_support",
        "enable_network_address_usage_metrics",
    ):
        v.require(vpc.values.get(key) is True, f"relay VPC must set {key}=true")

    # active_resources omits pure deletes from the final graph. These exact
    # cardinality checks therefore double as deletion detectors for every
    # non-durable network resource that the raw durable-resource pass ignores.
    tiers: dict[str, list[PlannedResource]] = {}
    for tier, cidrs in EXPECTED_SANDBOX_RELAY_SUBNET_CIDRS.items():
        tier_resources = sorted(
            network_named("aws_subnet", tier), key=lambda resource: resource.address
        )
        tiers[tier] = tier_resources
        v.require(
            len(tier_resources) == 3,
            f"{tier} subnet tier must contain exactly three subnets",
        )
        v.require(
            tuple(resource.values.get("cidr_block") for resource in tier_resources)
            == cidrs,
            f"{tier} subnet CIDRs changed",
        )
        v.require(
            all(
                resource.values.get("map_public_ip_on_launch") is False
                for resource in tier_resources
            ),
            f"{tier} subnets must disable public IP assignment",
        )
    if all(len(tier) == 3 for tier in tiers.values()):
        az_sets = [
            {resource.values.get("availability_zone") for resource in tier}
            for tier in tiers.values()
        ]
        # With -refresh=false, aws_availability_zones can be a planned read and
        # the AZ values remain unknown. The module test resolves that data source
        # with a mock and proves the exact three-AZ mapping; validate it here too
        # whenever the real plan has concrete AZ values.
        if all(None not in az_set for az_set in az_sets):
            v.require(
                len(az_sets[0]) == 3 and az_sets[0] == az_sets[1] == az_sets[2],
                "all subnet tiers must span the same three AZs",
            )

    for name, count in (("public", 1), ("relay", 3), ("endpoint", 3)):
        v.require(
            len(network_named("aws_route_table", name)) == count,
            f"expected {count} {name} route table(s)",
        )
        v.require(
            len(network_named("aws_route_table_association", name)) == 3,
            f"expected three explicit {name} route-table associations",
        )

    v.require(
        len(network_named("aws_internet_gateway", "relay")) == 1,
        "relay DMZ must have exactly one IGW for its public edge tier",
    )
    peering = v.one(
        network_named("aws_vpc_peering_connection", "main"), "DMZ-to-main VPC peering"
    )
    if peering:
        v.require(
            peering.values.get("auto_accept") is True,
            "same-account DMZ peering must auto-accept",
        )
    peering_options = v.one(
        network_named("aws_vpc_peering_connection_options", "main"),
        "DMZ peering DNS options",
    )
    if peering_options:
        requester = peering_options.values.get("requester") or []
        accepter = peering_options.values.get("accepter") or []
        v.require(
            len(requester) == 1
            and requester[0].get("allow_remote_vpc_dns_resolution") is True
            and len(accepter) == 1
            and accepter[0].get("allow_remote_vpc_dns_resolution") is True,
            "DMZ peering must enable remote DNS resolution in both directions",
        )

    v.require(
        not network_named("aws_nat_gateway", "relay"),
        "relay DMZ must not contain a NAT gateway",
    )
    identity_parent = child_module_prefix(parent_prefix, DURABLE_RELAY_IDENTITY_PARENT)
    parent_prefix_with_dot = f"{parent_prefix}." if parent_prefix else ""
    relay_boundary_addresses = {resource.address for resource in (*network, *relay)}
    relay_boundary_addresses.update(
        resource.address
        for resource in resources
        if resource.address.startswith(f"{identity_parent}.")
        or (
            resource.address.startswith(parent_prefix_with_dot)
            and not resource.address[len(parent_prefix_with_dot) :].startswith(
                "module."
            )
        )
    )
    v.require(
        not any(
            resource.address in relay_boundary_addresses
            and resource.resource_type
            in {"aws_nat_gateway", "aws_egress_only_internet_gateway"}
            for resource in resources
        ),
        "relay DMZ must not contain NAT or egress-only internet gateways",
    )
    network_config = config_module(v, plan, network_config_suffix)
    relay_config = config_module(v, plan, relay_config_suffix)
    main_private_route_destinations = check_relay_routes(
        v,
        resources,
        network,
        network_config,
        parent_prefix,
        list(EXPECTED_SANDBOX_RELAY_SUBNET_CIDRS["relay"]),
    )

    identity_secret = v.one(
        (
            resource
            for resource in resources
            if address_is_scoped_resource(
                resource.address,
                identity_parent,
                "aws_secretsmanager_secret",
                "relay",
            )
        ),
        "root-owned relay identity secret",
    )
    relay_secret_arn = (
        identity_secret.values.get("arn") if identity_secret is not None else None
    )
    # PR1 is a replacement, never a greenfield identity bootstrap. PR0 must
    # create/apply this durable secret before any DMZ layer is planned or
    # applied, so an unknown ARN is a sequencing failure rather than a value
    # that the endpoint-policy fallback may tolerate.
    v.require(
        isinstance(relay_secret_arn, str)
        and re.fullmatch(
            rf"arn:aws:secretsmanager:{EXPECTED_SANDBOX_REGION}:{EXPECTED_SANDBOX_ACCOUNT_ID}:"
            r"secret:layerv-nhp-sandbox-relay-[A-Za-z0-9]{6}",
            relay_secret_arn,
        )
        is not None,
        "relay identity secret ARN must be the concrete sandbox relay secret created by applied PR0",
    )

    # Main-VPC route ownership. The legacy private tables retain an inline NAT
    # route and therefore must never receive a standalone aws_route. The relay
    # enables a parallel no-inline table, installs its NAT route first, then
    # moves the existing subnet associations with ReplaceRouteTableAssociation.
    main_network_prefix = (
        f"{parent_prefix}.module.networking" if parent_prefix else "module.networking"
    )
    main_network = [
        resource
        for resource in resources
        if resource.address.startswith(f"{main_network_prefix}.")
    ]

    def main_network_named(resource_type: str, name: str) -> list[PlannedResource]:
        return [
            resource
            for resource in main_network
            if resource.resource_type == resource_type and resource.name == name
        ]

    legacy_private_tables = main_network_named("aws_route_table", "private")
    extensible_private_tables = main_network_named(
        "aws_route_table", "private_extensible"
    )
    extensible_defaults = main_network_named("aws_route", "private_extensible_default")
    v.require(
        len(legacy_private_tables) == 1,
        "sandbox must retain exactly one legacy inline-NAT private route table as a rollback anchor",
    )
    v.require(
        len(extensible_private_tables) == 1 and len(extensible_defaults) == 1,
        "sandbox relay must use exactly one extensible private route table with one standalone NAT default",
    )
    v.require(
        all("delete" not in resource.actions for resource in legacy_private_tables),
        "legacy private route table rollback anchor must not be deleted",
    )
    v.require(
        all(
            resource.values.get("destination_cidr_block") == "0.0.0.0/0"
            and bool(resource.values.get("nat_gateway_id"))
            for resource in extensible_defaults
        ),
        "extensible private route table must retain its standalone NAT default",
    )

    # PR-time plans may leave endpoint policy rendering unknown for unrelated
    # Terraform evaluation reasons; the configuration graph check below then
    # retains local.endpoint_policies. Final pre-apply plans must resolve every
    # policy so its complete content is checked.
    interface = network_named("aws_vpc_endpoint", "interface")
    interface_by_key = index_by_address_key(v, interface, "interface endpoint")
    allow_contracts = endpoint_allow_contracts(relay_secret_arn)
    v.require(
        set(allow_contracts) == set(EXPECTED_INTERFACE_ENDPOINTS) - {"guardduty-data"},
        "reviewed endpoint allow-contract keys must match all non-GuardDuty interface endpoints",
    )
    v.require(
        set(interface_by_key) == set(EXPECTED_INTERFACE_ENDPOINTS),
        "interface endpoint set changed",
    )
    for key, endpoint in interface_by_key.items():
        if key not in EXPECTED_INTERFACE_ENDPOINTS:
            continue
        v.require(
            endpoint.values.get("vpc_endpoint_type") == "Interface",
            f"{key} must be an interface endpoint",
        )
        v.require(
            endpoint.values.get("private_dns_enabled") is True,
            f"{key} must enable private DNS",
        )
        endpoint_policy = policy_text(
            v,
            endpoint.values.get("policy"),
            f"{key} interface endpoint policy",
            require_known=require_pr0_applied,
        )
        if endpoint_policy is not None:
            check_endpoint_policy(v, key, endpoint_policy, allow_contracts)
    endpoint_sg = v.one(
        network_named("aws_security_group", "endpoints"), "endpoint security group"
    )
    if endpoint_sg:
        # After a partial apply/provider refresh, aws_security_group can project
        # the separately managed HTTPS rule into this legacy aggregate field
        # even though configuration still declares explicit empty inline lists.
        # Accept only that exact projection; the config-graph check below still
        # rejects any actual inline rule declaration.
        endpoint_ingress = endpoint_sg.values.get("ingress") or []
        endpoint_https_rule = v.one(
            relay_named(
                "aws_vpc_security_group_ingress_rule",
                "vpc_endpoints_from_relay",
            ),
            "standalone endpoint HTTPS ingress rule projection",
        )
        relay_node_sg_id = (
            endpoint_https_rule.values.get("referenced_security_group_id")
            if endpoint_https_rule is not None
            else None
        )
        projected_ingress_is_exact = endpoint_ingress == []
        if len(endpoint_ingress) == 1 and isinstance(endpoint_ingress[0], dict):
            rule = endpoint_ingress[0]
            projected_ingress_is_exact = (
                rule.get("description") == "HTTPS from relay nodes only"
                and rule.get("from_port") == EXPECTED_HTTPS_PORT
                and rule.get("to_port") == EXPECTED_HTTPS_PORT
                and rule.get("protocol") == "tcp"
                and isinstance(relay_node_sg_id, str)
                and set(as_strings(rule.get("security_groups")))
                == {relay_node_sg_id}
                and all(
                    not rule.get(field)
                    for field in (
                        "cidr_blocks",
                        "ipv6_cidr_blocks",
                        "prefix_list_ids",
                    )
                )
                and rule.get("self") in (None, False)
            )
        v.require(
            projected_ingress_is_exact
            and (endpoint_sg.values.get("egress") or []) == [],
            "endpoint SG aggregate rules must be empty or exactly the standalone relay HTTPS projection",
        )

    logs_key = v.one(
        network_named("aws_kms_key", "logs"), "dedicated relay telemetry KMS key"
    )
    if logs_key:
        v.require(
            logs_key.values.get("enable_key_rotation") is True,
            "relay telemetry KMS key must rotate",
        )
        logs_policy = policy_text(
            v,
            logs_key.values.get("policy"),
            "relay telemetry KMS key policy",
            require_known=require_pr0_applied,
        )
        if logs_policy is not None:
            check_logs_kms_policy(v, logs_policy)
    logs_alias = v.one(
        network_named("aws_kms_alias", "logs"), "dedicated relay telemetry KMS alias"
    )
    if logs_alias:
        v.require(
            logs_alias.values.get("name") == "alias/layerv-nhp-sandbox-relay-dmz-logs",
            "relay telemetry KMS alias name changed",
        )

    flow_log_group = v.one(
        network_named("aws_cloudwatch_log_group", "flow"), "DMZ Flow Logs log group"
    )
    resolver_log_group = v.one(
        network_named("aws_cloudwatch_log_group", "resolver"), "DMZ Resolver log group"
    )
    log_groups = (flow_log_group, resolver_log_group)
    known_log_key_ids = {
        group.values.get("kms_key_id")
        for group in log_groups
        if group and isinstance(group.values.get("kms_key_id"), str)
    }
    # A first DMZ apply necessarily leaves the new KMS key ARN unknown. In every
    # mode, accept only a concrete string value or Terraform's explicit unknown
    # marker. The exact configuration-graph checks below bind unknown values
    # directly to aws_kms_key.logs.arn.
    for group in log_groups:
        if group is None:
            continue
        kms_id_unknown = (
            group.after_unknown is not None
            and group.after_unknown.get("kms_key_id") is True
        )
        v.require(
            isinstance(group.values.get("kms_key_id"), str) or kms_id_unknown,
            f"{group.name} log-group KMS key ID must be concrete or explicitly apply-time unknown",
        )
    if known_log_key_ids:
        v.require(
            len(known_log_key_ids) == 1,
            "both DMZ log groups must use the same dedicated KMS key",
        )
    flow_role = v.one(network_named("aws_iam_role", "flow"), "Flow Logs IAM role")
    flow_role_policy = v.one(
        network_named("aws_iam_role_policy", "flow"), "Flow Logs IAM role policy"
    )
    if flow_role and flow_role_policy:
        # These generated policy documents can remain unknown in a PR-time plan,
        # where they have no independent configuration-graph fallback. The final
        # pre-apply mode makes policy_text reject either unknown before apply.
        flow_policy = policy_text(
            v,
            flow_role_policy.values.get("policy"),
            "Flow Logs role policy",
            require_known=require_pr0_applied,
        )
        flow_trust = policy_text(
            v,
            flow_role.values.get("assume_role_policy"),
            "Flow Logs role trust policy",
            require_known=require_pr0_applied,
        )
        if flow_policy is not None and flow_trust is not None:
            check_flow_logs_role(v, flow_policy, flow_trust)

    s3_endpoint = v.one(
        network_named("aws_vpc_endpoint", "s3"), "relay S3 gateway endpoint"
    )
    if s3_endpoint:
        # This route-table-scoped gateway endpoint intentionally has no interface-
        # endpoint-style cross-account deny: its one GetObject statement and exact
        # object allowlist are the boundary. Its generated policy may be unknown at
        # PR time, but policy_text requires it to resolve in final pre-apply mode.
        v.require(
            s3_endpoint.values.get("vpc_endpoint_type") == "Gateway",
            "S3 must be a gateway endpoint",
        )
        s3_policy = policy_text(
            v,
            s3_endpoint.values.get("policy"),
            "S3 gateway endpoint policy",
            require_known=require_pr0_applied,
        )
        if s3_policy is not None:
            try:
                statements = policy_statements(s3_policy)
                v.require(
                    len(statements) == 1,
                    "S3 endpoint policy must contain one allow statement",
                )
                if len(statements) == 1:
                    statement = statements[0]
                    v.require(
                        set(as_strings(statement.get("Action"))) == {"s3:GetObject"},
                        "S3 endpoint may allow only GetObject",
                    )
                    v.require(
                        set(as_strings(statement.get("Resource")))
                        == EXPECTED_S3_RESOURCES,
                        "S3 endpoint bucket allowlist changed",
                    )
            except ValueError as exc:
                v.errors.append(f"S3 endpoint: {exc}")

    # DNS Firewall is deny-by-default, logs every query, and evaluates AWS's
    # advanced threat detections before the explicit allowlist.
    allow_domains = v.one(
        network_named("aws_route53_resolver_firewall_domain_list", "allow"),
        "DNS allowlist",
    )
    if allow_domains and isinstance(allow_domains.values.get("domains"), list):
        v.require(
            set(allow_domains.values["domains"]) == EXPECTED_ALLOW_DOMAINS,
            "DNS allowlist changed",
        )
    all_domains = v.one(
        network_named("aws_route53_resolver_firewall_domain_list", "all"),
        "DNS wildcard list",
    )
    if all_domains and isinstance(all_domains.values.get("domains"), list):
        v.require(
            all_domains.values["domains"] == ["*"],
            "DNS catch-all domain list must be ['*']",
        )

    advanced = index_by_address_key(
        v,
        network_named("aws_route53_resolver_firewall_rule", "advanced"),
        "advanced DNS threat rule",
    )
    expected_advanced = {"DGA": 100, "DICTIONARY_DGA": 110, "DNS_TUNNELING": 120}
    v.require(
        set(advanced) == set(expected_advanced), "advanced DNS threat rule set changed"
    )
    for key, priority in expected_advanced.items():
        rule = advanced.get(key)
        if rule:
            v.require(
                rule.values.get("action") == "BLOCK"
                and rule.values.get("block_response") == "NODATA"
                and rule.values.get("confidence_threshold")
                == EXPECTED_DNS_THREAT_CONFIDENCE
                and rule.values.get("dns_threat_protection") == key
                and rule.values.get("priority") == priority,
                f"advanced DNS rule {key} changed",
            )
    allow_rule = v.one(
        network_named("aws_route53_resolver_firewall_rule", "allow"), "DNS allow rule"
    )
    if allow_rule:
        v.require(
            allow_rule.values.get("action") == "ALLOW"
            and allow_rule.values.get("priority") == 200
            and allow_rule.values.get("firewall_domain_redirection_action")
            == "TRUST_REDIRECTION_DOMAIN",
            "DNS allow rule must remain priority 200 with trusted allowlisted redirections",
        )
    block_rule = v.one(
        network_named("aws_route53_resolver_firewall_rule", "block_all"),
        "DNS catch-all block",
    )
    if block_rule:
        v.require(
            block_rule.values.get("action") == "BLOCK"
            and block_rule.values.get("block_response") == "NODATA"
            and block_rule.values.get("priority") == 900,
            "DNS catch-all must remain a priority-900 NODATA block",
        )
    firewall_config = v.one(
        network_named("aws_route53_resolver_firewall_config", "relay"),
        "DNS Firewall config",
    )
    if firewall_config:
        v.require(
            firewall_config.values.get("firewall_fail_open") == "DISABLED",
            "DNS Firewall must fail closed",
        )
    firewall_assoc = v.one(
        network_named("aws_route53_resolver_firewall_rule_group_association", "relay"),
        "DNS Firewall association",
    )
    if firewall_assoc:
        # Accepted rollback tradeoff: AWS will not delete a mutation-protected
        # association. Terraform must be able to disassociate it during rollback;
        # the post-apply live detector fails if that association is missing.
        v.require(
            firewall_assoc.values.get("mutation_protection") == "DISABLED"
            and firewall_assoc.values.get("priority") == 101,
            "DNS Firewall association must stay rollback-safe at non-reserved priority 101",
        )
    v.one(
        network_named("aws_route53_resolver_query_log_config", "relay"),
        "Resolver query log config",
    )
    v.one(
        network_named("aws_route53_resolver_query_log_config_association", "relay"),
        "Resolver query log association",
    )

    dns_metric = v.one(
        network_named("aws_cloudwatch_log_metric_filter", "dns_blocked"),
        "blocked-DNS metric filter",
    )
    expected_dns_pattern = (
        '{ $.firewall_rule_action = "BLOCK" && $.query_name != %^example\\.com\\.*$% }'
    )
    if dns_metric:
        transformations = dns_metric.values.get("metric_transformation") or []
        v.require(
            dns_metric.values.get("pattern") == expected_dns_pattern
            and len(transformations) == 1
            and transformations[0].get("name") == "RelayDmzDnsBlocked"
            and transformations[0].get("namespace") == EXPECTED_METRIC_NAMESPACE
            and transformations[0].get("value") == "1",
            "blocked-DNS metric must page on every non-probe DNS Firewall block",
        )

    dns_alarms = resources_named(
        resources, "aws_cloudwatch_metric_alarm", "relay_dmz_dns_blocked"
    )
    dns_alarm = v.one(dns_alarms, "blocked-DNS alarm")
    if dns_alarm:
        alarm_actions = dns_alarm.values.get("alarm_actions")
        v.require(
            dns_alarm.values.get("metric_name") == "RelayDmzDnsBlocked"
            and dns_alarm.values.get("namespace") == EXPECTED_METRIC_NAMESPACE
            and dns_alarm.values.get("statistic") == "Sum"
            and dns_alarm.values.get("period") == 60
            and dns_alarm.values.get("evaluation_periods") == 1
            and dns_alarm.values.get("datapoints_to_alarm") == 1
            and dns_alarm.values.get("threshold") == 1
            and dns_alarm.values.get("comparison_operator")
            == "GreaterThanOrEqualToThreshold"
            and dns_alarm.values.get("treat_missing_data") == "notBreaching"
            and len(alarm_actions or []) == 1
            and dns_alarm.values.get("ok_actions") == alarm_actions,
            "blocked-DNS alarm must notify on the first non-probe block and recovery",
        )

    flow = v.one(network_named("aws_flow_log", "relay"), "DMZ VPC Flow Log")
    if flow:
        v.require(
            flow.values.get("traffic_type") == "ALL"
            and flow.values.get("max_aggregation_interval") == 60
            and flow.values.get("log_format") == EXPECTED_FLOW_LOG_FORMAT,
            "DMZ Flow Logs must retain the exact ALL-traffic 60s forensic field order",
        )

    # Cross-module wiring: the public ALB and isolated relay ASG must consume
    # only relay-network outputs, while the server gets exact UDP /24 ingress.
    root_config = (plan.get("configuration") or {}).get("root_module") or {}
    parent_module = (
        config_module(v, plan, parent_config_suffix)
        if parent_config_suffix
        else root_config
    )
    relay_call = (
        (parent_module.get("module_calls") or {}).get("relay")
        if isinstance(parent_module, dict)
        else None
    )
    for argument, expected_refs in {
        "vpc_id": {"module.relay_network[0].vpc_id", "module.relay_network[0]"},
        "public_subnet_ids": {
            "module.relay_network[0].public_subnet_ids",
            "module.relay_network[0]",
        },
        "relay_subnet_ids": {
            "module.relay_network[0].relay_subnet_ids",
            "module.relay_network[0]",
        },
        "vpc_endpoint_security_group_id": {
            "module.relay_network[0].endpoint_security_group_id",
            "module.relay_network[0]",
        },
    }.items():
        v.require(
            call_refs(relay_call, argument) == expected_refs,
            f"relay module {argument} must come from relay_network",
        )
    v.require(
        call_refs(relay_call, "nhp_server_cidr_blocks")
        == {"module.networking.private_subnet_cidr_blocks", "module.networking"},
        "relay server egress CIDRs must come from main networking private subnets",
    )
    v.require(
        call_refs(relay_call, "server_security_group_id")
        == {"module.compute.security_group_id", "module.compute"},
        "relay private UDP 62207 return source must come from the canonical server security group",
    )
    relay_cell_routing_config = config_resource(
        v, parent_module, "terraform_data", "relay_cell_routing"
    )
    v.require(
        references((relay_cell_routing_config or {}).get("count_expression"))
        == {"var.deploy_relay"}
        and expression_refs(relay_cell_routing_config, "input")
        == {
            "var.environment",
            "var.cell_id",
            "module.compute.server_public_key_b64",
            "module.compute.internal_nlb_dns_name",
            "module.compute",
        },
        "relay cell-routing contract must share the relay fleet gate and come from the canonical compute key and internal server NLB",
    )
    v.require(
        call_refs(relay_call, "cell_servers")
        == {
            "terraform_data.relay_cell_routing[0].input",
            "terraform_data.relay_cell_routing[0]",
            "terraform_data.relay_cell_routing",
        },
        "relay cell_servers must come from the plan-visible cell-routing contract",
    )
    relay_cell_routing = v.one(
        (
            resource
            for resource in resources
            if address_is_scoped_resource(
                resource.address,
                parent_prefix,
                "terraform_data",
                "relay_cell_routing",
            )
        ),
        "plan-visible relay cell-routing contract",
    )
    authoritative_cell_servers = (
        relay_cell_routing.values.get("input")
        if relay_cell_routing is not None
        else None
    )
    dmz_iam_wait_config = config_resource(
        v, parent_module, "time_sleep", "relay_dmz_iam_propagation"
    )
    v.require(
        set((dmz_iam_wait_config or {}).get("depends_on") or [])
        == {"terraform_data.relay_dmz_preconditions"},
        "relay-DMZ IAM propagation wait must preserve the root CIDR-overlap precondition dependency",
    )

    dns_call = (
        (parent_module.get("module_calls") or {}).get("dns")
        if isinstance(parent_module, dict)
        else None
    )
    dns_name_refs = call_refs(dns_call, "nlb_dns_name")
    dns_zone_refs = call_refs(dns_call, "nlb_zone_id")
    v.require(
        dns_name_refs == {"module.compute.nlb_dns_name", "module.compute"}
        and dns_zone_refs == {"module.compute.nlb_zone_id", "module.compute"},
        "public NHP DNS must target the assigned cell's server NLB directly",
    )
    public_nlb_output_refs = config_output_refs(parent_module, "nlb_dns_name")
    v.require(
        public_nlb_output_refs
        == {"module.compute.nlb_dns_name", "module.compute"},
        "public nlb_dns_name output must expose the assigned cell's server NLB",
    )

    for tier, expected_subnet_refs, expected_route_table_refs in (
        (
            "public",
            {"aws_subnet.public", "count.index"},
            {"aws_route_table.public.id", "aws_route_table.public"},
        ),
        (
            "relay",
            {"aws_subnet.relay", "count.index"},
            {"aws_route_table.relay", "count.index"},
        ),
        (
            "endpoint",
            {"aws_subnet.endpoint", "count.index"},
            {"aws_route_table.endpoint", "count.index"},
        ),
    ):
        association_config = config_resource(
            v, network_config, "aws_route_table_association", tier
        )
        v.require(
            expression_refs(association_config, "subnet_id") == expected_subnet_refs
            and expression_refs(association_config, "route_table_id")
            == expected_route_table_refs,
            f"{tier} subnets must attach only to matching {tier} route tables",
        )
        route_table_config = config_resource(v, network_config, "aws_route_table", tier)
        v.require(
            route_table_config is not None
            and "route" not in (route_table_config.get("expressions") or {}),
            f"{tier} DMZ route tables must use only reviewed standalone route resources",
        )

    def has_explicit_empty_rule_lists(resource_config: dict[str, Any] | None) -> bool:
        expressions = (resource_config or {}).get("expressions") or {}
        return all(
            isinstance(expressions.get(direction), dict)
            and expressions[direction].get("constant_value") == []
            for direction in ("ingress", "egress")
        )

    endpoint_sg_config = config_resource(
        v, network_config, "aws_security_group", "endpoints"
    )
    alb_sg_config = config_resource(v, relay_config, "aws_security_group", "alb")
    relay_sg_config = config_resource(v, relay_config, "aws_security_group", "relay")
    v.require(
        has_explicit_empty_rule_lists(endpoint_sg_config),
        "endpoint SG must declare explicit empty inline ingress and egress lists",
    )
    v.require(
        has_explicit_empty_rule_lists(alb_sg_config),
        "relay ALB SG must declare explicit empty inline ingress and egress lists",
    )
    relay_sg_expressions = (relay_sg_config or {}).get("expressions") or {}
    v.require(
        relay_sg_config is not None
        and not ({"ingress", "egress"} & set(relay_sg_expressions)),
        "relay node SG must not declare inline ingress or egress rules",
    )
    networking_config_suffix = (
        f"{parent_config_suffix}.module.networking"
        if parent_config_suffix
        else "module.networking"
    )
    networking_config = config_module(v, plan, networking_config_suffix)
    ecr_config_suffix = (
        f"{parent_config_suffix}.module.ecr" if parent_config_suffix else "module.ecr"
    )
    ecr_config = config_module(v, plan, ecr_config_suffix)
    ecr_call = (
        (parent_module.get("module_calls") or {}).get("ecr")
        if isinstance(parent_module, dict)
        else None
    )
    v.require(
        call_refs(ecr_call, "deploy_relay_network") == {"var.deploy_relay"},
        "relay-enabled context-lookups policy must be gated by deploy_relay",
    )
    context_lookups_config = config_resource(
        v, ecr_config, "aws_iam_role_policy", "context_lookups"
    )
    v.require(
        {
            "var.deploy_relay_network",
            "var.environment",
            "local.region",
            "local.account_id",
        }.issubset(expression_refs(context_lookups_config, "policy")),
        "context-lookups SSM policy must retain relay gate, environment tag, region, and account references",
    )
    relay_ssm_config = config_resource(
        v, ecr_config, "aws_iam_role_policy", "context_lookups_relay_ssm"
    )
    v.require(
        references((relay_ssm_config or {}).get("count_expression"))
        == {"var.deploy_relay_network"},
        "relay-only SSM policy must be gated directly by deploy_relay_network",
    )
    v.require(
        {
            "var.environment",
            "local.region",
            "local.account_id",
        }.issubset(expression_refs(relay_ssm_config, "policy")),
        "relay-only SSM policy must retain environment tag, region, and account references",
    )
    networking_call = (
        (parent_module.get("module_calls") or {}).get("networking")
        if isinstance(parent_module, dict)
        else None
    )
    v.require(
        call_refs(networking_call, "enable_extensible_private_route_tables")
        == {"var.deploy_relay"},
        "extensible main-private route tables must be gated by deploy_relay",
    )
    v.require(
        "time_sleep.relay_dmz_iam_propagation[0].id"
        in call_refs(networking_call, "extensible_private_route_table_ready_token"),
        "main-private association cutover must consume the relay-DMZ IAM propagation token",
    )
    relay_network_call = (
        (parent_module.get("module_calls") or {}).get("relay_network")
        if isinstance(parent_module, dict)
        else None
    )
    v.require(
        not (relay_network_call or {}).get("depends_on")
        and not (relay_call or {}).get("depends_on"),
        "relay network and fleet module calls must not use broad depends_on edges that defer security policy rendering",
    )
    v.require(
        call_refs(relay_network_call, "apply_role_ready_token")
        == {
            "time_sleep.relay_dmz_iam_propagation[0].id",
            "time_sleep.relay_dmz_iam_propagation[0]",
            "time_sleep.relay_dmz_iam_propagation",
        },
        "relay network apply barrier must consume only the IAM propagation token",
    )
    apply_ready_config = config_resource(
        v, network_config, "terraform_data", "apply_role_ready"
    )
    v.require(
        expression_refs(apply_ready_config, "input") == {"var.apply_role_ready_token"},
        "relay network apply barrier must be driven directly by its root readiness input",
    )
    for resource_type, resource_name in (
        ("aws_vpc", "relay"),
        ("aws_kms_key", "logs"),
        ("aws_iam_role", "flow"),
        ("aws_route53_resolver_firewall_domain_list", "allow"),
        ("aws_route53_resolver_firewall_domain_list", "all"),
        ("aws_route53_resolver_firewall_rule_group", "relay"),
    ):
        gated_config = config_resource(v, network_config, resource_type, resource_name)
        v.require(
            set((gated_config or {}).get("depends_on") or [])
            == {"terraform_data.apply_role_ready"},
            f"relay network DAG root {resource_type}.{resource_name} must wait only on the apply-role readiness barrier",
        )
    network_ready_config = config_resource(
        v, parent_module, "terraform_data", "relay_network_ready"
    )
    v.require(
        references((network_ready_config or {}).get("count_expression"))
        == {"var.deploy_relay"}
        and expression_refs(network_ready_config, "input")
        == {"module.relay_network[0].vpc_id", "module.relay_network[0]"}
        and set((network_ready_config or {}).get("depends_on") or [])
        == {"module.relay_network"},
        "root relay-network readiness barrier must wait for the complete count-gated DMZ module",
    )
    v.require(
        call_refs(relay_call, "network_ready_token")
        == {
            "terraform_data.relay_network_ready[0].output",
            "terraform_data.relay_network_ready[0]",
            "terraform_data.relay_network_ready",
        },
        "relay fleet must consume only the complete relay-network readiness token",
    )
    v.require(
        "module.networking.private_route_table_ids"
        in call_refs(relay_network_call, "main_private_route_table_ids"),
        "relay return routes must consume the networking module active private-route-table output",
    )
    return_route_config = config_resource(
        v, network_config, "aws_route", "main_private_to_relay"
    )
    v.require(
        "var.main_private_route_table_ids"
        in expression_refs(return_route_config, "route_table_id"),
        "relay return routes must target the reviewed active route-table input",
    )
    extensible_table_config = config_resource(
        v, networking_config, "aws_route_table", "private_extensible"
    )
    v.require(
        extensible_table_config is not None
        and "route" not in (extensible_table_config.get("expressions") or {}),
        "extensible private route table must not declare inline routes",
    )
    extensible_default_config = config_resource(
        v, networking_config, "aws_route", "private_extensible_default"
    )
    v.require(
        "aws_route_table.private_extensible"
        in expression_refs(extensible_default_config, "route_table_id")
        and "aws_nat_gateway.main"
        in expression_refs(extensible_default_config, "nat_gateway_id"),
        "extensible private default must be a standalone route to the existing NAT gateway",
    )
    private_association_config = config_resource(
        v, networking_config, "aws_route_table_association", "private"
    )
    association_dependencies = set(
        (private_association_config or {}).get("depends_on") or []
    )
    v.require(
        "local.active_private_route_table_ids"
        in expression_refs(private_association_config, "route_table_id")
        and {
            "aws_route.private_extensible_default",
            "terraform_data.private_extensible_association_ready",
        }.issubset(association_dependencies),
        "private subnet cutover must wait for both active-table NAT defaults and IAM propagation",
    )
    association_ready_config = config_resource(
        v,
        networking_config,
        "terraform_data",
        "private_extensible_association_ready",
    )
    v.require(
        "var.extensible_private_route_table_ready_token"
        in expression_refs(association_ready_config, "input"),
        "private subnet cutover readiness must be driven by the root IAM propagation token",
    )
    v.require(
        config_output_refs(networking_config, "private_route_table_ids")
        == {"local.active_private_route_table_ids"},
        "networking private_route_table_ids output must expose only the active table set",
    )
    for endpoint_name in ("s3", "dynamodb"):
        endpoint_config = config_resource(
            v, networking_config, "aws_vpc_endpoint", endpoint_name
        )
        v.require(
            "local.all_private_route_table_ids"
            in expression_refs(endpoint_config, "route_table_ids"),
            f"main-VPC {endpoint_name} gateway endpoint must retain both legacy and extensible private route tables",
        )
    standalone_legacy_owners = []
    for resource_config in (networking_config or {}).get("resources", []):
        if resource_config.get("type") != "aws_route":
            continue
        refs = expression_refs(resource_config, "route_table_id")
        if any(
            ref == "aws_route_table.private"
            or ref.startswith("aws_route_table.private[")
            for ref in refs
        ):
            standalone_legacy_owners.append(resource_config.get("name"))
    v.require(
        not standalone_legacy_owners,
        f"legacy inline-NAT private tables must not have standalone route owners: {standalone_legacy_owners}",
    )
    public_route_config = config_resource(
        v, network_config, "aws_route", "public_default"
    )
    v.require(
        expression_refs(public_route_config, "gateway_id")
        == {"aws_internet_gateway.relay.id", "aws_internet_gateway.relay"}
        and expression_refs(public_route_config, "route_table_id")
        == {"aws_route_table.public.id", "aws_route_table.public"},
        "public default route must target the DMZ IGW from the public route table",
    )
    s3_config = config_resource(v, network_config, "aws_vpc_endpoint", "s3")
    v.require(
        expression_refs(s3_config, "route_table_ids") == {"aws_route_table.relay"},
        "S3 gateway endpoint must attach only to relay route tables",
    )
    interface_config = config_resource(
        v, network_config, "aws_vpc_endpoint", "interface"
    )
    v.require(
        expression_refs(interface_config, "policy")
        == {"local.endpoint_policies", "each.key"},
        "interface endpoints must use the reviewed endpoint_policies map",
    )
    v.require(
        expression_refs(interface_config, "subnet_ids") == {"aws_subnet.endpoint"},
        "interface endpoints must use only endpoint subnets",
    )
    v.require(
        expression_refs(interface_config, "security_group_ids")
        == {"aws_security_group.endpoints.id", "aws_security_group.endpoints"},
        "interface endpoints must use only the dedicated endpoint SG",
    )
    kms_config = config_resource(v, network_config, "aws_kms_key", "logs")
    v.require(
        expression_refs(kms_config, "policy") == EXPECTED_LOGS_KMS_POLICY_REFS,
        "unresolved relay logs KMS policy references changed",
    )
    for log_group_name in ("flow", "resolver"):
        log_group_config = config_resource(
            v, network_config, "aws_cloudwatch_log_group", log_group_name
        )
        v.require(
            expression_refs(log_group_config, "kms_key_id")
            == {"aws_kms_key.logs.arn", "aws_kms_key.logs"},
            f"{log_group_name} log group must use the dedicated relay logs KMS key",
        )

    target_group = v.one(
        relay_named("aws_lb_target_group", "relay"), "relay target group"
    )
    if target_group:
        health = target_group.values.get("health_check") or []
        v.require(
            target_group.values.get("protocol") == "HTTPS"
            and target_group.values.get("port") == EXPECTED_RELAY_BACKEND_PORT
            # Accept the provider's schema-native string while rejecting
            # non-integral or alternative values.
            and matches_exact_int_or_int_string(
                target_group.values.get("deregistration_delay"),
                EXPECTED_DEREGISTRATION_DELAY,
            )
            and len(health) == 1
            and health[0].get("protocol") == "HTTPS"
            and health[0].get("path") == EXPECTED_RELAY_HEALTH_PATH,
            f"relay target group must use HTTPS:8080, {EXPECTED_DEREGISTRATION_DELAY}s draining, and /health/live",
        )
    https_listener = v.one(
        relay_named("aws_lb_listener", "https"), "relay HTTPS listener"
    )
    if https_listener:
        v.require(
            https_listener.values.get("protocol") == "HTTPS"
            and https_listener.values.get("port") == EXPECTED_HTTPS_PORT,
            "relay HTTPS listener must expose TCP/HTTPS 443 only",
        )
    v.require(
        {resource.name for resource in relay if resource.resource_type == "aws_lb"}
        == {"relay"},
        "relay module load-balancer inventory must be exactly the HTTPS ALB",
    )
    v.require(
        {
            resource.name
            for resource in relay
            if resource.resource_type == "aws_lb_listener"
        }
        == {"https"},
        "relay module listener inventory must be exactly HTTPS 443",
    )
    alb = v.one(relay_named("aws_lb", "relay"), "public relay ALB")
    if alb:
        access_logs = alb.values.get("access_logs") or []
        v.require(
            alb.values.get("internal") is False
            and alb.values.get("load_balancer_type") == "application",
            "relay ingress must be an internet-facing application load balancer",
        )
        v.require(
            alb.values.get("enable_deletion_protection") is False
            and alb.values.get("idle_timeout") == 30
            and alb.values.get("drop_invalid_header_fields") is True
            and alb.values.get("desync_mitigation_mode") == "defensive"
            and alb.values.get("xff_header_processing_mode") == "append"
            and alb.values.get("enable_xff_client_port") is False
            and alb.values.get("enable_waf_fail_open") is False
            and len(access_logs) == 1
            and access_logs[0].get("enabled") is True
            and access_logs[0].get("bucket")
            == f"layerv-nhp-sandbox-relay-alb-logs-{EXPECTED_SANDBOX_ACCOUNT_ID}"
            and access_logs[0].get("prefix") in (None, ""),
            "relay ALB must retain exact deletion protection, WAF/XFF/HTTP hardening, and access-log destination",
        )
        if vpc.actions == ("create",) and alb.before and alb.before.get("vpc_id"):
            v.require(
                "create" in alb.actions and "delete" in alb.actions,
                "an existing relay ALB must be replaced when the dedicated DMZ VPC is first created",
            )
    asg = v.one(relay_named("aws_autoscaling_group", "relay"), "relay ASG")
    if asg:
        # min/desired forbid scale-to-zero. max_size is deliberately unpinned;
        # the integration's current max=6 preserves reviewed scale-out headroom.
        v.require(
            str(asg.values.get("name", "")).endswith("-relay-dmz")
            and asg.values.get("health_check_type") == "ELB"
            and asg.values.get("desired_capacity") == 3
            and asg.values.get("min_size") == 3,
            "relay ASG must be the three-instance DMZ fleet with ELB health",
        )
    asg_config = config_resource(v, relay_config, "aws_autoscaling_group", "relay")
    alb_config = config_resource(v, relay_config, "aws_lb", "relay")
    relay_ready_config = config_resource(
        v, relay_config, "terraform_data", "network_ready"
    )
    fleet_security_ready_config = config_resource(
        v, relay_config, "terraform_data", "fleet_security_ready"
    )
    v.require(
        expression_refs(relay_ready_config, "input") == {"var.network_ready_token"},
        "relay child readiness barrier must be driven directly by the root network token",
    )
    expected_fleet_security_dependencies = {
        "aws_vpc_security_group_ingress_rule.alb_https",
        "aws_vpc_security_group_egress_rule.alb_to_relay",
        "aws_vpc_security_group_ingress_rule.relay_http_from_alb",
        "aws_vpc_security_group_ingress_rule.relay_udp_ack_return",
        "aws_vpc_security_group_egress_rule.relay_to_nhp_udp",
        "aws_vpc_security_group_egress_rule.relay_to_vpc_endpoints_https",
        "aws_vpc_security_group_ingress_rule.vpc_endpoints_from_relay",
        "aws_vpc_security_group_egress_rule.relay_to_s3_https",
    }
    v.require(
        expression_refs(fleet_security_ready_config, "input")
        == {"aws_security_group.relay.id", "aws_security_group.relay"}
        and set((fleet_security_ready_config or {}).get("depends_on") or [])
        == expected_fleet_security_dependencies,
        "relay fleet security barrier must wait for every mandatory standalone SG path",
    )
    v.require(
        set((alb_config or {}).get("depends_on") or [])
        == {
            "aws_s3_bucket_policy.alb_access_logs",
            "terraform_data.network_ready",
        },
        "public relay ALB must wait for complete DMZ network readiness",
    )
    v.require(
        set((asg_config or {}).get("depends_on") or [])
        == {
            "terraform_data.network_ready",
            "terraform_data.fleet_security_ready",
        },
        "relay ASG must wait for network readiness and the complete fleet security barrier",
    )
    v.require(
        references_exact_resources(
            expression_refs(asg_config, "target_group_arns"),
            {"aws_lb_target_group.relay"},
        ),
        "relay ASG must attach to exactly the HTTPS target group",
    )
    rendered_relay_servers: list[dict[str, Any]] = []
    launch_template = v.one(
        relay_named("aws_launch_template", "relay"), "relay launch template"
    )
    if launch_template:
        network_interfaces = launch_template.values.get("network_interfaces") or []
        metadata = launch_template.values.get("metadata_options") or []
        v.require(
            len(network_interfaces) == 1
            and str(network_interfaces[0].get("associate_public_ip_address")).lower()
            == "false",
            "relay instances must never receive public IP addresses",
        )
        v.require(
            len(metadata) == 1
            and metadata[0].get("http_tokens") == "required"
            and metadata[0].get("http_put_response_hop_limit") == 1,
            "relay launch template must require IMDSv2 with hop limit 1",
        )
        rendered_user_data = launch_template.values.get("user_data")
        decoded_user_data: str | None = None
        if isinstance(rendered_user_data, str):
            try:
                decoded_user_data = base64.b64decode(
                    rendered_user_data, validate=True
                ).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        server_blocks = (
            re.findall(
                r"(?ms)^\[\[servers\]\]\s*\n(.*?)(?=^\[\[servers\]\]\s*$|\Z)",
                decoded_user_data,
            )
            if decoded_user_data is not None
            else []
        )
        for block in server_blocks:
            quoted = {
                key: match.group(1) if match else None
                for key in ("name", "public_key", "host")
                for match in [re.search(rf'(?m)^\s*{key}\s*=\s*"([^"]*)"\s*$', block)]
            }
            port_match = re.search(r"(?m)^\s*port\s*=\s*([0-9]+)\s*$", block)
            rendered_relay_servers.append(
                {
                    **quoted,
                    "port": int(port_match.group(1)) if port_match else None,
                }
            )
        recognized_plaintext_config = bool(rendered_relay_servers) and all(
            all(
                entry.get(key) not in (None, "")
                for key in ("name", "public_key", "host")
            )
            and entry.get("port") is not None
            for entry in rendered_relay_servers
        )
        v.require(
            recognized_plaintext_config,
            "rendered relay launch-template user_data must remain base64-encoded UTF-8 plaintext containing [[servers]] relay TOML markers; gzip or multipart user_data requires an explicitly reviewed parser update",
        )

    relay_repo_parent = child_module_prefix(parent_prefix, "module.ecr")
    relay_repo = v.one(
        (
            resource
            for resource in resources
            if resource.address.startswith(f"{relay_repo_parent}.")
            and resource.resource_type == "aws_ecr_repository"
            and resource.name == "main"
            and address_key(resource.address) == "nhp-relay"
        ),
        "sandbox relay ECR repository",
    )
    relay_repo_arn = relay_repo.values.get("arn") if relay_repo else None
    v.require(
        relay_repo_arn == EXPECTED_SANDBOX_RELAY_REPO_ARN,
        "sandbox relay ECR repository ARN changed",
    )
    relay_log_group = v.one(
        relay_named("aws_cloudwatch_log_group", "relay"),
        "relay application log group",
    )
    relay_log_group_arn = relay_log_group.values.get("arn") if relay_log_group else None
    v.require(
        relay_log_group_arn == EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN.removesuffix(":*"),
        "sandbox relay application log-group ARN changed",
    )
    relay_image_tag = v.one(
        (
            resource
            for resource in resources
            if address_is_scoped_resource(
                resource.address,
                parent_prefix,
                "aws_ssm_parameter",
                "relay_image_tag",
            )
        ),
        "relay image-tag SSM parameter",
    )
    relay_image_tag_arn = relay_image_tag.values.get("arn") if relay_image_tag else None
    v.require(
        relay_image_tag_arn == EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN,
        "sandbox relay image-tag parameter ARN changed",
    )
    relay_iam = v.one(
        relay_named("aws_iam_role_policy", "relay"), "resolved relay IAM policy"
    )
    if relay_iam:
        relay_policy = policy_text(
            v,
            relay_iam.values.get("policy"),
            "relay IAM policy",
            require_known=require_pr0_applied,
        )
        if relay_policy is not None:
            check_relay_iam_policy(
                v,
                relay_policy,
                relay_secret_arn,
                relay_repo_arn,
                f"{relay_log_group_arn}:*"
                if isinstance(relay_log_group_arn, str)
                else None,
                relay_image_tag_arn,
                expected_secrets_kms_arn,
            )
        else:
            iam_config = config_resource(
                v, relay_config, "aws_iam_role_policy", "relay"
            )
            v.require(
                expression_refs(iam_config, "policy") == EXPECTED_RELAY_IAM_POLICY_REFS,
                "unresolved relay IAM policy references changed",
            )

    context_lookups = v.one(
        [
            resource
            for resource in resources
            if address_matches_suffix(
                resource.address,
                "module.ecr.aws_iam_role_policy.context_lookups",
            )
        ],
        "resolved context-lookups IAM policy",
    )
    relay_ssm = v.one(
        [
            resource
            for resource in resources
            if address_matches_suffix(
                resource.address,
                "module.ecr.aws_iam_role_policy.context_lookups_relay_ssm[0]",
            )
        ],
        "resolved relay-only SSM IAM policy",
    )
    if context_lookups and relay_ssm:
        context_policy = context_lookups.values.get("policy")
        relay_policy = relay_ssm.values.get("policy")
        v.require(
            isinstance(context_policy, str),
            "relay-enabled context-lookups IAM policy must resolve at plan time",
        )
        v.require(
            isinstance(relay_policy, str),
            "relay-only SSM IAM policy must resolve at plan time",
        )
        if isinstance(context_policy, str) and isinstance(relay_policy, str):
            check_context_lookups_ssm_policy(v, context_policy, relay_policy)

    def exact_rule(
        resource: PlannedResource | None, protocol: str, port: int, label: str
    ) -> None:
        if resource:
            v.require(
                resource.values.get("ip_protocol") == protocol
                and resource.values.get("from_port") == port
                and resource.values.get("to_port") == port,
                f"{label} must remain {protocol.upper()} {port}",
            )

    for resource_type, name, protocol, port, label in (
        (
            "aws_vpc_security_group_ingress_rule",
            "alb_https",
            "tcp",
            EXPECTED_HTTPS_PORT,
            "public ALB ingress",
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "alb_to_relay",
            "tcp",
            EXPECTED_RELAY_BACKEND_PORT,
            "ALB backend egress",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_http_from_alb",
            "tcp",
            EXPECTED_RELAY_BACKEND_PORT,
            "relay backend ingress",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
            "udp",
            EXPECTED_RELAY_ACK_PORT,
            "relay ACK ingress",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "vpc_endpoints_from_relay",
            "tcp",
            EXPECTED_HTTPS_PORT,
            "endpoint ingress",
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "relay_to_vpc_endpoints_https",
            "tcp",
            EXPECTED_HTTPS_PORT,
            "relay endpoint egress",
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "relay_to_s3_https",
            "tcp",
            EXPECTED_HTTPS_PORT,
            "relay S3 egress",
        ),
    ):
        exact_rule(
            v.one(relay_named(resource_type, name), label), protocol, port, label
        )

    alb_ingress = v.one(
        relay_named("aws_vpc_security_group_ingress_rule", "alb_https"),
        "public ALB ingress CIDR",
    )
    if alb_ingress:
        v.require(
            alb_ingress.values.get("cidr_ipv4") == EXPECTED_IPV4_DEFAULT_CIDR,
            "public ALB ingress must be TCP 443 from IPv4 internet",
        )
    ack_ingress = v.one(
        relay_named("aws_vpc_security_group_ingress_rule", "relay_udp_ack_return"),
        "private relay ACK ingress source",
    )
    if ack_ingress:
        v.require(
            all(
                ack_ingress.values.get(field) in (None, "")
                for field in ("cidr_ipv4", "cidr_ipv6", "prefix_list_id")
            ),
            "relay UDP 62207 ACK ingress must not use any public or CIDR source",
        )
    ack_config = config_resource(
        v,
        relay_config,
        "aws_vpc_security_group_ingress_rule",
        "relay_udp_ack_return",
    )
    if ack_config:
        v.require(
            set(ack_config.get("depends_on") or [])
            == {"terraform_data.network_ready"},
            "relay UDP 62207 ACK ingress must wait for the active cross-VPC peering barrier",
        )
    for resource_type, name, expected_owner_ref, expected_peer_ref, label in (
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_http_from_alb",
            "aws_security_group.relay",
            "aws_security_group.alb",
            "relay HTTPS backend ingress",
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "alb_to_relay",
            "aws_security_group.alb",
            "aws_security_group.relay",
            "ALB HTTPS backend egress",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "vpc_endpoints_from_relay",
            "var.vpc_endpoint_security_group_id",
            "aws_security_group.relay",
            "VPC endpoint HTTPS ingress",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
            "aws_security_group.relay",
            "var.server_security_group_id",
            "relay UDP 62207 ACK ingress",
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "relay_to_vpc_endpoints_https",
            "aws_security_group.relay",
            "var.vpc_endpoint_security_group_id",
            "relay endpoint HTTPS egress",
        ),
    ):
        rule_config = config_resource(v, relay_config, resource_type, name)
        owner_refs = expression_refs(rule_config, "security_group_id")
        owner_is_exact = refs_match_expected(owner_refs, expected_owner_ref)
        peer_refs = expression_refs(rule_config, "referenced_security_group_id")
        peer_is_exact = refs_match_expected(peer_refs, expected_peer_ref)
        planned_rules = relay_named(resource_type, name)
        planned_rule_has_only_sg_peer = len(planned_rules) == 1 and all(
            planned_rules[0].values.get(field) in (None, "")
            for field in ("cidr_ipv4", "cidr_ipv6", "prefix_list_id")
        )
        config_expressions = (rule_config or {}).get("expressions") or {}
        config_has_only_sg_peer = all(
            field not in config_expressions
            for field in ("cidr_ipv4", "cidr_ipv6", "prefix_list_id")
        )
        v.require(
            owner_is_exact
            and peer_is_exact
            and planned_rule_has_only_sg_peer
            and config_has_only_sg_peer,
            f"{label} must use only the reviewed SG-to-SG path",
        )

    for name, expected_owner_ref, label in (
        ("alb_https", "aws_security_group.alb", "public ALB HTTPS ingress"),
    ):
        ingress_config = config_resource(
            v, relay_config, "aws_vpc_security_group_ingress_rule", name
        )
        expressions = (ingress_config or {}).get("expressions") or {}
        v.require(
            references_exact_resources(
                expression_refs(ingress_config, "security_group_id"),
                {expected_owner_ref},
            )
            and (expressions.get("cidr_ipv4") or {}).get("constant_value")
            == EXPECTED_IPV4_DEFAULT_CIDR
            and all(
                field not in expressions
                for field in (
                    "cidr_ipv6",
                    "prefix_list_id",
                    "referenced_security_group_id",
                )
            ),
            f"{label} must use only its reviewed SG and IPv4 0.0.0.0/0 source",
        )

    s3_egress_config = config_resource(
        v,
        relay_config,
        "aws_vpc_security_group_egress_rule",
        "relay_to_s3_https",
    )
    s3_expressions = (s3_egress_config or {}).get("expressions") or {}
    # Unlike SG-to-SG fields above, S3 egress deliberately targets AWS's
    # regional managed prefix list, so the reviewed provenance is this exact
    # data-source traversal rather than an aws_security_group resource.
    v.require(
        references_exact_resources(
            expression_refs(s3_egress_config, "security_group_id"),
            {"aws_security_group.relay"},
        )
        and expression_refs(s3_egress_config, "prefix_list_id")
        == {"data.aws_prefix_list.s3.id", "data.aws_prefix_list.s3"}
        and all(
            field not in s3_expressions
            for field in ("cidr_ipv4", "cidr_ipv6", "referenced_security_group_id")
        ),
        "relay S3 HTTPS egress must target only the regional S3 prefix list",
    )

    server_egress_config = config_resource(
        v,
        relay_config,
        "aws_vpc_security_group_egress_rule",
        "relay_to_nhp_udp",
    )
    server_egress_expressions = (server_egress_config or {}).get("expressions") or {}
    v.require(
        references_exact_resources(
            expression_refs(server_egress_config, "security_group_id"),
            {"aws_security_group.relay"},
        )
        and references((server_egress_config or {}).get("for_each_expression"))
        == {"local.nhp_server_cidr_blocks"}
        and expression_refs(server_egress_config, "cidr_ipv4") == {"each.value"}
        and all(
            field not in server_egress_expressions
            for field in ("cidr_ipv6", "prefix_list_id", "referenced_security_group_id")
        ),
        "relay server UDP egress must use only the relay SG and reviewed per-server CIDRs",
    )

    allowed_ingress_names = {
        "alb_https",
        "relay_http_from_alb",
        "relay_udp_ack_return",
        "vpc_endpoints_from_relay",
    }
    allowed_egress_names = {
        "alb_to_relay",
        "relay_to_nhp_udp",
        "relay_to_vpc_endpoints_https",
        "relay_to_s3_https",
    }
    egress_rules = [
        resource
        for resource in relay
        if resource.resource_type == "aws_vpc_security_group_egress_rule"
    ]
    v.require(
        {
            resource.name
            for resource in relay
            if resource.resource_type == "aws_vpc_security_group_ingress_rule"
        }
        == allowed_ingress_names,
        "relay/ALB/endpoint ingress rule inventory changed",
    )
    v.require(
        {resource.name for resource in egress_rules} == allowed_egress_names,
        "relay/ALB egress rule inventory changed",
    )
    v.require(
        all(
            resource.values.get("cidr_ipv4") != EXPECTED_IPV4_DEFAULT_CIDR
            and resource.values.get("cidr_ipv6") != "::/0"
            for resource in egress_rules
        ),
        "relay and ALB security groups must not allow IPv4 or IPv6 internet-wide egress",
    )
    v.require(
        not any(
            resource.resource_type == "aws_security_group_rule" for resource in relay
        ),
        "legacy standalone aws_security_group_rule resources are forbidden in the relay module",
    )

    udp_egress = relay_named("aws_vpc_security_group_egress_rule", "relay_to_nhp_udp")
    v.require(
        len(udp_egress) == 3
        and {resource.values.get("cidr_ipv4") for resource in udp_egress}
        == set(main_private_route_destinations)
        and all(
            resource.values.get("ip_protocol") == "udp"
            and resource.values.get("from_port") == EXPECTED_NHP_SERVER_PORT
            and resource.values.get("to_port") == EXPECTED_NHP_SERVER_PORT
            for resource in udp_egress
        ),
        "relay may reach main private subnets only on UDP 62206",
    )
    compute_parent = child_module_prefix(parent_prefix, "module.compute")
    compute = [
        resource
        for resource in resources
        if address_is_scoped_resource(
            resource.address,
            compute_parent,
            resource.resource_type,
            resource.name,
        )
    ]
    compute_config_suffix = (
        f"{parent_config_suffix}.module.compute"
        if parent_config_suffix
        else "module.compute"
    )
    compute_config = config_module(v, plan, compute_config_suffix)
    v.require(
        compute_config is not None,
        "assigned-cell compute module configuration is missing",
    )
    public_server_nlb = resources_named(compute, "aws_lb", "server")
    public_server_nlb_tags = (
        public_server_nlb[0].values.get("tags") or []
        if len(public_server_nlb) == 1
        else []
    )
    expected_public_server_nlb_tags = {
        "Environment": "sandbox",
        "Component": "compute",
        "Cell": EXPECTED_SANDBOX_CELL_ID,
        "Name": EXPECTED_SANDBOX_SERVER_NLB_NAME,
    }
    v.require(
        len(public_server_nlb) == 1
        and public_server_nlb[0].values.get("internal") is False
        and public_server_nlb[0].values.get("load_balancer_type") == "network"
        and public_server_nlb[0].values.get("name") == EXPECTED_SANDBOX_SERVER_NLB_NAME
        and isinstance(public_server_nlb_tags, dict)
        and all(
            public_server_nlb_tags.get(key) == value
            for key, value in expected_public_server_nlb_tags.items()
        ),
        "assigned cell must retain exactly one canonically named and tagged internet-facing server NLB",
    )
    public_target_group_specs = (
        (
            "udp",
            EXPECTED_SANDBOX_SERVER_UDP_TG_NAME,
            "layerv-nhp-sandbox-tg-udp",
            {},
            "assigned cell public NHP target group must retain canonical identity, tags, preserved client IP, instance UDP 62206, and HTTP /health/live contract in values and authored config",
        ),
        (
            "udp_green",
            EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME,
            "layerv-nhp-sandbox-tg-udp-green",
            {"DeployColor": "green"},
            "standby public NHP target group must retain canonical green identity, tags, preserved client IP, instance UDP 62206, and HTTP /health/live contract in values and authored config",
        ),
    )
    public_target_groups: dict[str, list[PlannedResource]] = {}
    for (
        resource_name,
        expected_name,
        expected_tag_name,
        color_tags,
        error_message,
    ) in public_target_group_specs:
        matches = resources_named(compute, "aws_lb_target_group", resource_name)
        public_target_groups[resource_name] = matches
        values = matches[0].values if len(matches) == 1 else {}
        tags = values.get("tags") or []
        health = values.get("health_check") or []
        target_group_config = config_resource(
            v, compute_config, "aws_lb_target_group", resource_name
        )
        preserve_expression = (
            (target_group_config or {}).get("expressions") or {}
        ).get("preserve_client_ip") or {}
        expected_tags = {
            "Environment": "sandbox",
            "Component": "compute",
            "Cell": EXPECTED_SANDBOX_CELL_ID,
            "Name": expected_tag_name,
            **color_tags,
        }
        v.require(
            len(matches) == 1
            and values.get("name") == expected_name
            and values.get("protocol") == "UDP"
            and values.get("port") == EXPECTED_NHP_SERVER_PORT
            and values.get("target_type") == "instance"
            and str(values.get("preserve_client_ip")).lower() == "true"
            and isinstance(tags, dict)
            and all(tags.get(key) == value for key, value in expected_tags.items())
            and len(health) == 1
            and health[0].get("enabled") is True
            and health[0].get("protocol") == "HTTP"
            and str(health[0].get("port")) == "8888"
            and health[0].get("path") == "/health/live"
            and health[0].get("matcher") == "200"
            and preserve_expression.get("constant_value") is True,
            error_message,
        )
    public_server_target_group = public_target_groups["udp"]
    public_server_green_target_group = public_target_groups["udp_green"]
    udp_capable_listeners = [
        resource
        for resource in compute
        if resource.resource_type == "aws_lb_listener"
        and str(resource.values.get("protocol", "")).upper() in {"UDP", "TCP_UDP"}
    ]
    v.require(
        len(udp_capable_listeners) == 2
        and {resource.name for resource in udp_capable_listeners}
        == {"udp", "udp_internal"}
        and all(
            resource.values.get("protocol") == "UDP"
            and resource.values.get("port") == EXPECTED_NHP_SERVER_PORT
            for resource in udp_capable_listeners
        ),
        "assigned cell public NHP NLB must expose exactly one UDP listener on 62206; compute UDP-capable listener inventory must also contain only private udp_internal on UDP 62206",
    )
    public_listener_config = config_resource(
        v, compute_config, "aws_lb_listener", "udp"
    )
    v.require(
        references_exact_resources(
            expression_refs(public_listener_config, "load_balancer_arn"),
            {"aws_lb.server"},
        )
        and references_exact_resources(
            expression_refs(public_listener_config, "default_action"),
            {"aws_lb_target_group.udp"},
        ),
        "assigned-cell public UDP listener must forward only aws_lb.server to aws_lb_target_group.udp",
    )
    public_attachment = v.one(
        resources_named(compute, "aws_autoscaling_attachment", "server"),
        "assigned-cell public UDP target-group attachment",
    )
    public_attachment_config = config_resource(
        v, compute_config, "aws_autoscaling_attachment", "server"
    )
    v.require(
        public_attachment is not None
        and references_exact_resources(
            expression_refs(public_attachment_config, "autoscaling_group_name"),
            {"aws_autoscaling_group.server"},
        )
        and references_exact_resources(
            expression_refs(public_attachment_config, "lb_target_group_arn"),
            {"aws_lb_target_group.udp"},
        ),
        "assigned-cell public UDP target group must attach only to the canonical server ASG",
    )
    v.require(
        not any(
            resource.resource_type == "aws_lb"
            and resource.values.get("load_balancer_type") == "network"
            and resource.values.get("internal") is False
            and resource.name != "server"
            for resource in compute
        ),
        "assigned cell server NLB must be the only internet-facing compute NLB",
    )
    server_base = resources_named(
        compute, "aws_vpc_security_group_ingress_rule", "server_nhp_udp"
    )
    v.require(
        len(server_base) == 1
        and server_base[0].values.get("ip_protocol") == "udp"
        and server_base[0].values.get("from_port") == EXPECTED_NHP_SERVER_PORT
        and server_base[0].values.get("to_port") == EXPECTED_NHP_SERVER_PORT
        and server_base[0].values.get("cidr_ipv4") == EXPECTED_IPV4_DEFAULT_CIDR,
        "assigned cell server SG must accept public NHP UDP 62206",
    )
    server_base_config = config_resource(
        v,
        compute_config,
        "aws_vpc_security_group_ingress_rule",
        "server_nhp_udp",
    )
    v.require(
        references_exact_resources(
            expression_refs(server_base_config, "security_group_id"),
            {"aws_security_group.server"},
        ),
        "assigned cell public UDP 62206 rule must belong only to the canonical server SG",
    )
    server_sg_config = config_resource(
        v, compute_config, "aws_security_group", "server"
    )
    server_sg_expressions = (server_sg_config or {}).get("expressions") or {}
    v.require(
        server_sg_config is not None
        and not ({"ingress", "egress"} & set(server_sg_expressions)),
        "canonical server SG must use only reviewed standalone rules and declare no inline ingress or egress",
    )
    v.require(
        not any(
            resource.resource_type == "aws_security_group_rule" for resource in compute
        ),
        "legacy aws_security_group_rule resources are forbidden in the assigned-cell compute module",
    )

    def public_udp_capable_rule(resource: PlannedResource) -> bool:
        if resource.resource_type not in {
            "aws_vpc_security_group_ingress_rule",
            "aws_security_group_rule",
        }:
            return False
        if not (
            resource.values.get("cidr_ipv4") == EXPECTED_IPV4_DEFAULT_CIDR
            or resource.values.get("cidr_ipv6") == "::/0"
        ):
            return False
        protocol = str(
            resource.values.get("ip_protocol", resource.values.get("protocol", ""))
        ).lower()
        if protocol not in {"udp", "-1", "all"}:
            return False
        return True

    public_server_udp_rules = [
        resource for resource in compute if public_udp_capable_rule(resource)
    ]
    v.require(
        len(public_server_udp_rules) == 1
        and public_server_udp_rules[0].name == "server_nhp_udp"
        and public_server_udp_rules[0].values.get("ip_protocol") == "udp"
        and public_server_udp_rules[0].values.get("from_port")
        == EXPECTED_NHP_SERVER_PORT
        and public_server_udp_rules[0].values.get("to_port") == EXPECTED_NHP_SERVER_PORT
        and public_server_udp_rules[0].values.get("cidr_ipv4")
        == EXPECTED_IPV4_DEFAULT_CIDR,
        "server SG public UDP-capable ingress must be exactly server_nhp_udp on UDP 62206",
    )
    internal_server_nlb = resources_named(compute, "aws_lb", "server_internal")
    v.require(
        len(internal_server_nlb) == 1
        and internal_server_nlb[0].values.get("internal") is True
        and internal_server_nlb[0].values.get("load_balancer_type") == "network",
        "server knock path must retain exactly one private main-VPC network load balancer",
    )
    expected_internal_dns = (
        internal_server_nlb[0].values.get("dns_name")
        if len(internal_server_nlb) == 1
        else None
    )
    authoritative_cell_server = (
        authoritative_cell_servers[0]
        if isinstance(authoritative_cell_servers, list)
        and len(authoritative_cell_servers) == 1
        and isinstance(authoritative_cell_servers[0], dict)
        else None
    )
    v.require(
        isinstance(expected_internal_dns, str)
        and bool(expected_internal_dns)
        and isinstance(authoritative_cell_server, dict)
        and authoritative_cell_server.get("name") == "sandbox-cell0"
        and authoritative_cell_server.get("host") == expected_internal_dns
        and authoritative_cell_server.get("port") == EXPECTED_NHP_SERVER_PORT
        and re.fullmatch(
            r"[A-Za-z0-9+/]{43}=",
            str(authoritative_cell_server.get("public_key", "")),
        )
        is not None
        and len(rendered_relay_servers) == 1
        and rendered_relay_servers[0] == authoritative_cell_server,
        "rendered relay server table must exactly match the plan-visible sandbox-cell0 route to the canonical internal NLB DNS on UDP 62206 and its authoritative server public key",
    )
    internal_server_listener = resources_named(
        compute, "aws_lb_listener", "udp_internal"
    )
    v.require(
        len(internal_server_listener) == 1
        and internal_server_listener[0].values.get("protocol") == "UDP"
        and internal_server_listener[0].values.get("port") == EXPECTED_NHP_SERVER_PORT,
        "internal server NLB must retain exactly one UDP 62206 listener",
    )
    internal_target_group_specs = (
        (
            "udp_internal",
            EXPECTED_SANDBOX_INTERNAL_UDP_TG_NAME,
            "layerv-nhp-sandbox-tg-srv-int-udp-blue",
            "blue",
        ),
        (
            "udp_internal_green",
            EXPECTED_SANDBOX_INTERNAL_UDP_GREEN_TG_NAME,
            "layerv-nhp-sandbox-tg-srv-int-udp-green",
            "green",
        ),
    )
    internal_target_groups: dict[str, PlannedResource | None] = {}
    for (
        resource_name,
        expected_name,
        expected_tag_name,
        color,
    ) in internal_target_group_specs:
        matches = resources_named(compute, "aws_lb_target_group", resource_name)
        target_group = matches[0] if len(matches) == 1 else None
        internal_target_groups[resource_name] = target_group
        values = target_group.values if target_group is not None else {}
        tags = values.get("tags") or []
        health = values.get("health_check") or []
        target_group_config = config_resource(
            v, compute_config, "aws_lb_target_group", resource_name
        )
        preserve_expression = (
            (target_group_config or {}).get("expressions") or {}
        ).get("preserve_client_ip") or {}
        v.require(
            len(matches) == 1
            and values.get("name") == expected_name
            and values.get("protocol") == "UDP"
            and values.get("port") == EXPECTED_NHP_SERVER_PORT
            and values.get("target_type") == "instance"
            and str(values.get("preserve_client_ip")).lower() == "true"
            and isinstance(tags, dict)
            and all(
                tags.get(key) == value
                for key, value in {
                    "Environment": "sandbox",
                    "Component": "compute",
                    "Cell": EXPECTED_SANDBOX_CELL_ID,
                    "Name": expected_tag_name,
                    "DeployColor": color,
                }.items()
            )
            and len(health) == 1
            and health[0].get("enabled") is True
            and health[0].get("protocol") == "HTTP"
            and str(health[0].get("port")) == "8888"
            and health[0].get("path") == "/health/live"
            and health[0].get("matcher") == "200"
            and preserve_expression.get("constant_value") is True,
            f"internal {color} server target group must retain canonical identity, tags, preserved client IP, instance UDP 62206, and HTTP /health/live contract in values and authored config",
        )
    internal_listener_config = config_resource(
        v, compute_config, "aws_lb_listener", "udp_internal"
    )
    v.require(
        references_exact_resources(
            expression_refs(internal_listener_config, "load_balancer_arn"),
            {"aws_lb.server_internal"},
        )
        and references_exact_resources(
            expression_refs(internal_listener_config, "default_action"),
            {"aws_lb_target_group.udp_internal"},
        ),
        "private UDP listener must forward only aws_lb.server_internal to aws_lb_target_group.udp_internal",
    )
    internal_attachment = v.one(
        resources_named(compute, "aws_autoscaling_attachment", "server_internal"),
        "internal server UDP target-group attachment",
    )
    internal_attachment_config = config_resource(
        v, compute_config, "aws_autoscaling_attachment", "server_internal"
    )
    v.require(
        internal_attachment is not None
        and references_exact_resources(
            expression_refs(internal_attachment_config, "autoscaling_group_name"),
            {"aws_autoscaling_group.server"},
        )
        and references_exact_resources(
            expression_refs(internal_attachment_config, "lb_target_group_arn"),
            {"aws_lb_target_group.udp_internal"},
        ),
        "internal UDP target group must attach only to the canonical server ASG",
    )
    green_asg = v.one(
        resources_named(compute, "aws_autoscaling_group", "server_green"),
        "green server ASG",
    )
    green_asg_config = config_resource(
        v, compute_config, "aws_autoscaling_group", "server_green"
    )
    green_asg_refs = expression_refs(green_asg_config, "target_group_arns")
    expected_green_tg_refs = {
        "aws_lb_target_group.udp_green",
        "aws_lb_target_group.https_green",
        "aws_lb_target_group.udp_internal_green",
    }
    public_green_arn = (
        public_server_green_target_group[0].values.get("arn")
        if len(public_server_green_target_group) == 1
        else None
    )
    internal_green = internal_target_groups.get("udp_internal_green")
    internal_green_arn = (
        internal_green.values.get("arn") if internal_green is not None else None
    )
    green_asg_target_group_arns = (
        green_asg.values.get("target_group_arns") if green_asg is not None else None
    )
    green_https_target_groups = resources_named(
        compute, "aws_lb_target_group", "https_green"
    )
    green_https_arns = {
        resource.values.get("arn")
        for resource in green_https_target_groups
        if isinstance(resource.values.get("arn"), str)
    }
    known_green_arns = {
        arn for arn in (public_green_arn, internal_green_arn) if isinstance(arn, str)
    } | green_https_arns
    v.require(
        green_asg is not None
        and references_exact_resources(
            green_asg_refs,
            expected_green_tg_refs,
            allowed_metadata=frozenset(
                {"var.enable_qurl_resolve_endpoint", "var.relay_enabled"}
            ),
        )
        and (
            not known_green_arns
            or (
                isinstance(green_asg_target_group_arns, list)
                and set(green_asg_target_group_arns) == known_green_arns
            )
        ),
        "green server ASG must attach to the standby public and internal UDP target groups in planned values and authored config",
    )
    server_return = resources_named(
        resources,
        "aws_vpc_security_group_ingress_rule",
        "server_nhp_udp_additional",
    )
    v.require(
        len(server_return) == 3
        and {resource.values.get("cidr_ipv4") for resource in server_return}
        == set(EXPECTED_SANDBOX_RELAY_SUBNET_CIDRS["relay"])
        and all(
            resource.values.get("ip_protocol") == "udp"
            and resource.values.get("from_port") == EXPECTED_NHP_SERVER_PORT
            and resource.values.get("to_port") == EXPECTED_NHP_SERVER_PORT
            for resource in server_return
        ),
        "main server SG must accept UDP 62206 from exactly the three relay /24s",
    )

    v.require(
        not any(
            resource.resource_type == "aws_iam_role_policy_attachment"
            and "AmazonSSMManagedInstanceCore"
            in str(resource.values.get("policy_arn", ""))
            for resource in relay
        ),
        "relay role must not retain AmazonSSMManagedInstanceCore",
    )
    return v.errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan_json", type=Path, help="terraform show -json output")
    parser.add_argument(
        "--allow-disabled",
        action="store_true",
        help="pass when the relay DMZ is absent",
    )
    parser.add_argument(
        "--require-pr0-applied",
        action="store_true",
        help="fail if any relay control-plane moved block is still pending in state",
    )
    parser.add_argument(
        "--require-dmz-boundary-noop",
        action="store_true",
        help=(
            "fail if the automatic apply plan changes the relay DMZ boundary; "
            "future migrations require a newly reviewed temporary path"
        ),
    )
    args = parser.parse_args()

    # Boundary-noop is an orthogonal saved-plan constraint and intentionally
    # combines with either enabled-mode policy. Only disabled bootstrap and the
    # "PR0 already applied" state assertion are logically contradictory.
    if args.allow_disabled and args.require_pr0_applied:
        parser.error(
            "--allow-disabled and --require-pr0-applied are mutually exclusive"
        )

    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"::error::cannot read Terraform plan JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
        print(
            "::error::Terraform plan JSON has no resource_changes array",
            file=sys.stderr,
        )
        return 2

    errors = validate_plan(
        plan,
        require_enabled=not args.allow_disabled,
        require_pr0_applied=args.require_pr0_applied,
        require_dmz_boundary_noop=args.require_dmz_boundary_noop,
    )
    if errors:
        for error in errors:
            print(f"::error title=Relay DMZ plan contract::{error}", file=sys.stderr)
        print(
            f"relay DMZ plan contract failed with {len(errors)} violation(s)",
            file=sys.stderr,
        )
        return 1
    print("relay DMZ plan contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
