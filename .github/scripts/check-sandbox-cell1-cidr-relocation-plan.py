#!/usr/bin/env python3
"""Fail closed on the attended sandbox-cell1 VPC relocation plan.

The checker filename describes the saved plan's CIDR contract. The companion
``vpc-relocation-preflight`` script describes the wider live-AWS drain and VPC
inventory contract. The distinct names are intentional.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


OLD_CIDR = "10.102.0.0/16"
NEW_CIDR = "10.104.0.0/16"
CELL_DNS_NAME = "cell1.nhp.layerv.xyz"
HOSTED_ZONE_ID = "Z10394893FM38A1RXLL32"
REQUIRED_SUSPENDED_PROCESSES = {
    "AlarmNotification",
    "AZRebalance",
    "InstanceRefresh",
    "Launch",
    "ReplaceUnhealthy",
    "ScheduledActions",
}

# This is deliberately an exact allowlist. A live drift repair, provider
# behavior change, or new replacement must be reviewed as a new plan rather
# than hidden inside the attended VPC relocation.
EXPECTED_ACTIONS: dict[str, tuple[str, ...]] = {
    "aws_service_discovery_private_dns_namespace.cell1": ("create", "delete"),
    "module.compute.aws_autoscaling_attachment.server[0]": ("delete", "create"),
    "module.compute.aws_autoscaling_group.server": ("update",),
    "module.compute.aws_autoscaling_group.server_green[0]": ("update",),
    "module.compute.aws_iam_role_policy.server": ("update",),
    "module.compute.aws_launch_template.server": ("update",),
    "module.compute.aws_lb.server[0]": ("delete", "create"),
    "module.compute.aws_lb_listener.udp[0]": ("delete", "create"),
    "module.compute.aws_lb_target_group.udp[0]": ("delete", "create"),
    "module.compute.aws_lb_target_group.udp_green[0]": ("create", "delete"),
    "module.compute.aws_s3_object.server_init_script[0]": ("update",),
    "module.compute.aws_security_group.server": ("create", "delete"),
    "module.compute.aws_service_discovery_service.server": ("create", "delete"),
    "module.compute.aws_ssm_parameter.blue_udp_tg_arn[0]": ("update",),
    "module.compute.aws_ssm_parameter.green_udp_tg_arn[0]": ("update",),
    "module.compute.aws_ssm_parameter.udp_listener_arn[0]": ("update",),
    "module.compute.aws_vpc_security_group_egress_rule.server_all": (
        "delete",
        "create",
    ),
    "module.compute.aws_vpc_security_group_ingress_rule.server_http_plugins": (
        "delete",
        "create",
    ),
    "module.compute.aws_vpc_security_group_ingress_rule.server_http_traefik": (
        "delete",
        "create",
    ),
    "module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp": (
        "delete",
        "create",
    ),
    "module.dns.aws_route53_record.nhp[0]": ("update",),
    "module.networking.aws_flow_log.main": ("delete", "create"),
    "module.networking.aws_internet_gateway.main": ("update",),
    "module.networking.aws_nat_gateway.main[0]": ("delete", "create"),
    "module.networking.aws_network_acl.isolated": ("delete", "create"),
    "module.networking.aws_network_acl.private": ("delete", "create"),
    "module.networking.aws_network_acl.public": ("delete", "create"),
    "module.networking.aws_route_table.isolated": ("delete", "create"),
    "module.networking.aws_route_table.private[0]": ("delete", "create"),
    "module.networking.aws_route_table.public": ("delete", "create"),
    "module.networking.aws_route_table_association.isolated[0]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.isolated[1]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.isolated[2]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.private[0]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.private[1]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.private[2]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.public[0]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.public[1]": (
        "delete",
        "create",
    ),
    "module.networking.aws_route_table_association.public[2]": (
        "delete",
        "create",
    ),
    "module.networking.aws_security_group.vpc_endpoints": ("create", "delete"),
    "module.networking.aws_subnet.isolated[0]": ("delete", "create"),
    "module.networking.aws_subnet.isolated[1]": ("delete", "create"),
    "module.networking.aws_subnet.isolated[2]": ("delete", "create"),
    "module.networking.aws_subnet.private[0]": ("create", "delete"),
    "module.networking.aws_subnet.private[1]": ("create", "delete"),
    "module.networking.aws_subnet.private[2]": ("create", "delete"),
    "module.networking.aws_subnet.public[0]": ("delete", "create"),
    "module.networking.aws_subnet.public[1]": ("delete", "create"),
    "module.networking.aws_subnet.public[2]": ("delete", "create"),
    "module.networking.aws_vpc.main": ("create", "delete"),
    'module.networking.aws_vpc_endpoint.interface["ecr-api"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["ecr-dkr"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["guardduty-data"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["logs"]': ("delete", "create"),
    'module.networking.aws_vpc_endpoint.interface["monitoring"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["secretsmanager"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["servicediscovery"]': (
        "delete",
        "create",
    ),
    'module.networking.aws_vpc_endpoint.interface["ssm"]': ("delete", "create"),
    'module.networking.aws_vpc_endpoint.interface["ssmmessages"]': (
        "delete",
        "create",
    ),
    "module.networking.aws_vpc_endpoint.s3": ("delete", "create"),
}
EXPECTED_ADD_COUNT = sum(
    "create" in actions for actions in EXPECTED_ACTIONS.values()
)
EXPECTED_CHANGE_COUNT = sum(
    actions == ("update",) for actions in EXPECTED_ACTIONS.values()
)
EXPECTED_DESTROY_COUNT = sum(
    "delete" in actions for actions in EXPECTED_ACTIONS.values()
)

PRESERVED_NO_OP = {
    "aws_secretsmanager_secret.nhp_internal_auth",
    "terraform_data.nhp_internal_auth_seed",
    "module.compute.aws_lambda_invocation.keygen",
    "module.compute.aws_secretsmanager_secret.cookie_secret",
    "module.compute.aws_secretsmanager_secret.overload_cookie_secret",
    "module.compute.aws_secretsmanager_secret.server",
    "module.compute.aws_ssm_parameter.active_color[0]",
    "module.compute.aws_ssm_parameter.asg_name",
    "module.compute.aws_ssm_parameter.blue_asg_name[0]",
    "module.compute.aws_ssm_parameter.deployed_at",
    "module.compute.aws_ssm_parameter.deployed_commit",
    "module.compute.aws_ssm_parameter.green_asg_name[0]",
    "module.compute.aws_ssm_parameter.green_image_tag[0]",
    "module.compute.aws_ssm_parameter.image_tag",
    "module.compute.aws_ssm_parameter.last_switch_timestamp[0]",
    "module.dynamodb.aws_dynamodb_table.ac_assignments",
    "module.dynamodb.aws_dynamodb_table.ack_tokens",
    "module.dynamodb.aws_dynamodb_table.licenses",
    "module.dynamodb.aws_dynamodb_table.resources",
    "module.dynamodb.aws_dynamodb_table.server_ac_index",
    "module.kms.aws_kms_key.ebs",
    "module.kms.aws_kms_key.logs",
    "module.kms.aws_kms_key.secrets",
    "module.plugins.aws_s3_bucket.plugins",
    "module.plugins.aws_s3_bucket_server_side_encryption_configuration.plugins",
}

PRESERVED_NO_OP_PREFIXES = (
    "module.dynamodb.",
    "module.kms.",
    "module.plugins.",
)

SUBNET_OCTETS = {
    "public": (0, 1, 2),
    "private": (10, 11, 12),
    "isolated": (20, 21, 22),
}


class PlanError(ValueError):
    """The plan violates the attended relocation contract."""


def _actions_by_address(plan: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise PlanError("resource_changes must be a list")
    result: dict[str, tuple[str, ...]] = {}
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise PlanError("every resource change must have an address")
        if item["address"] in result:
            raise PlanError(f"duplicate resource change address: {item['address']}")
        change = item.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            raise PlanError(f"{item['address']}: actions must be a string list")
        result[item["address"]] = tuple(actions)
    return result


def _resource(plan: dict[str, Any], address: str) -> dict[str, Any]:
    for item in plan["resource_changes"]:
        if item["address"] == address:
            return item
    raise PlanError(f"required plan resource missing: {address}")


def _is_reviewable_change(actions: tuple[str, ...], mode: Any) -> bool:
    """A change worth gating: not a no-op and not a data-source read."""
    return actions != ("no-op",) and not (mode == "data" and actions == ("read",))


def _require_exact_action_inventory(plan: dict[str, Any]) -> None:
    all_actions = _actions_by_address(plan)
    observed = {
        item["address"]: all_actions[item["address"]]
        for item in plan["resource_changes"]
        if _is_reviewable_change(all_actions[item["address"]], item.get("mode"))
    }
    if observed != EXPECTED_ACTIONS:
        missing = sorted(set(EXPECTED_ACTIONS) - set(observed))
        extra = sorted(set(observed) - set(EXPECTED_ACTIONS))
        mismatched = sorted(
            address
            for address in set(observed) & set(EXPECTED_ACTIONS)
            if observed[address] != EXPECTED_ACTIONS[address]
        )
        raise PlanError(
            "unexpected relocation action inventory: "
            f"missing={missing!r}, extra={extra!r}, mismatched="
            f"{[(item, observed[item], EXPECTED_ACTIONS[item]) for item in mismatched]!r}"
        )

def _require_max_capacity_contract(plan: dict[str, Any]) -> int:
    try:
        references = plan["configuration"]["root_module"]["module_calls"]["compute"][
            "expressions"
        ]["max_capacity"]["references"]
        max_capacity = plan["variables"]["max_capacity"]["value"]
    except (KeyError, TypeError) as exc:
        raise PlanError("compute max_capacity contract is missing") from exc
    if references != ["var.max_capacity"]:
        raise PlanError(
            "compute.max_capacity must derive only from var.max_capacity; "
            f"found {references!r}"
        )
    if type(max_capacity) is not int or max_capacity != 2:
        raise PlanError(
            "var.max_capacity must remain the reviewed cell1 migration value 2; "
            f"found {max_capacity!r}"
        )
    return max_capacity


def _require_drained_asgs(
    plan: dict[str, Any], expected_max_capacity: int
) -> None:
    for address in (
        "module.compute.aws_autoscaling_group.server",
        "module.compute.aws_autoscaling_group.server_green[0]",
    ):
        change = _resource(plan, address)["change"]
        before = change.get("before")
        after = change.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise PlanError(f"{address}: before/after must be objects")
        for field in ("min_size", "max_size", "desired_capacity"):
            if before.get(field) != 0:
                raise PlanError(
                    f"{address}: live {field} must be 0 before saved-plan "
                    f"creation, found {before.get(field)!r}"
                )
        if after.get("min_size") != 0 or after.get("desired_capacity") != 0:
            raise PlanError(
                f"{address}: saved plan must keep min_size and "
                "desired_capacity at 0 while Launch is suspended"
            )
        if after.get("max_size") != expected_max_capacity:
            raise PlanError(
                f"{address}: saved plan must restore configured max_size "
                f"{expected_max_capacity}, "
                f"found {after.get('max_size')!r}"
            )
        prior_suspended = before.get("suspended_processes")
        planned_suspended = after.get("suspended_processes")
        if not isinstance(prior_suspended, list) or not (
            REQUIRED_SUSPENDED_PROCESSES <= set(prior_suspended)
        ):
            raise PlanError(
                f"{address}: prior suspended_processes must include the "
                f"relocation freeze, found {prior_suspended!r}"
            )
        if not isinstance(planned_suspended, list) or set(planned_suspended) != set(
            prior_suspended
        ):
            raise PlanError(
                f"{address}: planned suspended_processes must exactly preserve "
                f"the prior operator state; prior={prior_suspended!r}, "
                f"planned={planned_suspended!r}"
            )


def _require_cidr_direction(plan: dict[str, Any], direction: str) -> None:
    expected_before, expected_after = (
        (OLD_CIDR, NEW_CIDR) if direction == "forward" else (NEW_CIDR, OLD_CIDR)
    )
    change = _resource(plan, "module.networking.aws_vpc.main")["change"]
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or before.get("cidr_block") != expected_before:
        raise PlanError(
            "VPC prior CIDR mismatch: expected "
            f"{expected_before}, found {before.get('cidr_block') if isinstance(before, dict) else None}"
        )
    if not isinstance(after, dict) or after.get("cidr_block") != expected_after:
        raise PlanError(
            "VPC planned CIDR mismatch: expected "
            f"{expected_after}, found {after.get('cidr_block') if isinstance(after, dict) else None}"
        )


def _require_exact_subnet_cidrs(plan: dict[str, Any], direction: str) -> None:
    def _second_octet_prefix(cidr: str) -> str:
        return ".".join(cidr.split(".")[:2])

    old_prefix, new_prefix = _second_octet_prefix(OLD_CIDR), _second_octet_prefix(
        NEW_CIDR
    )
    before_prefix, after_prefix = (
        (old_prefix, new_prefix) if direction == "forward" else (new_prefix, old_prefix)
    )
    for subnet_type, octets in SUBNET_OCTETS.items():
        for index, octet in enumerate(octets):
            address = f"module.networking.aws_subnet.{subnet_type}[{index}]"
            change = _resource(plan, address)["change"]
            before = change.get("before")
            after = change.get("after")
            expected_before = f"{before_prefix}.{octet}.0/24"
            expected_after = f"{after_prefix}.{octet}.0/24"
            if (
                not isinstance(before, dict)
                or before.get("cidr_block") != expected_before
            ):
                found = before.get("cidr_block") if isinstance(before, dict) else None
                raise PlanError(
                    f"{address}: prior cidr_block must be {expected_before}, "
                    f"found {found!r}"
                )
            if not isinstance(after, dict) or after.get("cidr_block") != expected_after:
                found = after.get("cidr_block") if isinstance(after, dict) else None
                raise PlanError(
                    f"{address}: planned cidr_block must be {expected_after}, "
                    f"found {found!r}"
                )


def _require_identity_preserved(plan: dict[str, Any]) -> None:
    actions = _actions_by_address(plan)
    missing = sorted(PRESERVED_NO_OP - set(actions))
    if missing:
        raise PlanError(f"identity/data preservation resources missing: {missing!r}")
    changed = sorted(
        (address, actions[address])
        for address in PRESERVED_NO_OP
        if actions[address] != ("no-op",)
    )
    if changed:
        raise PlanError(
            f"identity/data preservation resources must be no-op: {changed!r}"
        )

    changed_prefix_resources = sorted(
        (item["address"], actions[item["address"]])
        for item in plan["resource_changes"]
        if item["address"].startswith(PRESERVED_NO_OP_PREFIXES)
        and _is_reviewable_change(actions[item["address"]], item.get("mode"))
    )
    if changed_prefix_resources:
        raise PlanError(
            "all DynamoDB, KMS, and plugin-bucket module resources must be "
            f"no-op: {changed_prefix_resources!r}"
        )

    dns_actions = actions.get("module.dns.aws_route53_record.nhp[0]")
    if dns_actions != ("update",):
        raise PlanError(
            "cell1.nhp.layerv.xyz record identity must update in place, found "
            f"{dns_actions!r}"
        )


def _require_dns_targeting(plan: dict[str, Any]) -> None:
    try:
        dns_expressions = plan["configuration"]["root_module"]["module_calls"]["dns"][
            "expressions"
        ]
        variables = plan["variables"]
    except (KeyError, TypeError) as exc:
        raise PlanError(
            "DNS module configuration or root variables are missing"
        ) from exc

    expected_references = {
        "domain_name": {"var.cell_dns_name"},
        "hosted_zone_id": {"var.hosted_zone_id"},
        "nlb_dns_name": {"module.compute.nlb_dns_name", "module.compute"},
        "nlb_zone_id": {"module.compute.nlb_zone_id", "module.compute"},
    }
    for field, expected in expected_references.items():
        refs = dns_expressions.get(field, {}).get("references")
        if not isinstance(refs, list) or set(refs) != expected:
            raise PlanError(
                f"dns.{field} must have exact references {sorted(expected)!r}; "
                f"found {refs!r}"
            )

    expected_variables = {
        "cell_dns_name": CELL_DNS_NAME,
        "hosted_zone_id": HOSTED_ZONE_ID,
    }
    for name, expected in expected_variables.items():
        value = variables.get(name, {}).get("value")
        if value != expected:
            raise PlanError(f"var.{name} must be {expected!r}; found {value!r}")

    change = _resource(plan, "module.dns.aws_route53_record.nhp[0]")["change"]
    before = change.get("before")
    after = change.get("after")
    after_unknown = change.get("after_unknown")
    expected_record = {
        "name": CELL_DNS_NAME,
        "fqdn": CELL_DNS_NAME,
        "zone_id": HOSTED_ZONE_ID,
        "type": "A",
    }
    for phase, record in (("prior", before), ("planned", after)):
        if not isinstance(record, dict):
            raise PlanError(f"DNS {phase} record must be an object")
        mismatched = {
            field: (record.get(field), expected)
            for field, expected in expected_record.items()
            if record.get(field) != expected
        }
        if mismatched:
            raise PlanError(f"DNS {phase} record identity mismatch: {mismatched!r}")
    expected_alias_unknown = [{"name": True, "zone_id": True}]
    if not isinstance(after_unknown, dict) or (
        after_unknown.get("alias") != expected_alias_unknown
    ):
        found = after_unknown.get("alias") if isinstance(after_unknown, dict) else None
        raise PlanError(
            "DNS planned alias must resolve from the replacement compute NLB; "
            f"found after_unknown.alias={found!r}"
        )


def _require_compute_network_dependencies(plan: dict[str, Any]) -> None:
    try:
        expressions = plan["configuration"]["root_module"]["module_calls"]["compute"][
            "expressions"
        ]
    except (KeyError, TypeError) as exc:
        raise PlanError("compute module configuration is missing") from exc

    expected = {
        "vpc_id": "module.networking.vpc_id",
        "public_subnet_ids": "module.networking.public_subnet_ids",
        "private_subnet_ids": "module.networking.private_subnet_ids",
    }
    for field, reference in expected.items():
        refs = expressions.get(field, {}).get("references", [])
        if reference not in refs:
            raise PlanError(
                f"compute.{field} must depend on {reference}; found {refs!r}"
            )


def check_plan(plan: dict[str, Any], direction: str) -> None:
    if plan.get("format_version") != "1.2":
        raise PlanError(
            f"expected Terraform plan JSON format 1.2, found {plan.get('format_version')!r}"
        )
    if plan.get("terraform_version") != "1.14.3":
        raise PlanError(
            "attended relocation is pinned to Terraform 1.14.3, found "
            f"{plan.get('terraform_version')!r}"
        )
    _require_identity_preserved(plan)
    _require_exact_action_inventory(plan)
    expected_max_capacity = _require_max_capacity_contract(plan)
    _require_drained_asgs(plan, expected_max_capacity)
    _require_cidr_direction(plan, direction)
    _require_exact_subnet_cidrs(plan, direction)
    _require_compute_network_dependencies(plan)
    _require_dns_targeting(plan)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument(
        "--direction", choices=("forward", "rollback"), default="forward"
    )
    args = parser.parse_args()

    try:
        with args.plan_json.open(encoding="utf-8") as source:
            plan = json.load(source)
        if not isinstance(plan, dict):
            raise PlanError("plan JSON root must be an object")
        check_plan(plan, args.direction)
    except (OSError, json.JSONDecodeError, PlanError) as exc:
        print(
            f"ERROR: sandbox-cell1 CIDR relocation plan rejected: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        "PASS: exact drained-fleet sandbox-cell1 CIDR relocation plan "
        f"({EXPECTED_ADD_COUNT} add, {EXPECTED_CHANGE_COUNT} change, "
        f"{EXPECTED_DESTROY_COUNT} destroy) preserves server identity and data"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
