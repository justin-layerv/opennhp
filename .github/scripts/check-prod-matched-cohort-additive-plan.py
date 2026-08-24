#!/usr/bin/env python3
"""Fail closed unless a saved prod plan is the exact matched-cohort change set."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any


class ContractError(RuntimeError):
    pass


ALLOWED_RESOURCE_NAMES = {
    # Root-owned inventory and candidate image slot.
    "module.nhp.aws_ssm_parameter.matched_cohort_contract[0]",
    "module.nhp.aws_ssm_parameter.relay_matched_cohort_image_tag[0]",
    "module.nhp.module.dynamodb.aws_dynamodb_table.matched_cohort_ac_assignments[0]",
    "module.nhp.module.dynamodb.aws_dynamodb_table.matched_cohort_operator_lock[0]",
    "module.nhp.module.dynamodb.aws_iam_policy.matched_cohort_server[0]",
    # Compute candidate and color-isolated endpoints.
    "module.nhp.module.compute.aws_ssm_parameter.matched_cohort_server_image_tag[0]",
    "module.nhp.module.compute.aws_service_discovery_service.server_candidate[0]",
    "module.nhp.module.compute.aws_iam_role.server_candidate[0]",
    "module.nhp.module.compute.aws_iam_instance_profile.server_candidate[0]",
    "module.nhp.module.compute.aws_iam_role_policy.server_candidate_base[0]",
    "module.nhp.module.compute.aws_iam_role_policy_attachment.server_candidate_ssm[0]",
    "module.nhp.module.compute.aws_iam_role_policy_attachment.server_candidate_dynamodb[0]",
    "module.nhp.module.compute.aws_iam_role_policy_attachment.server_candidate_keypair[0]",
    "module.nhp.module.compute.aws_iam_role_policy_attachment.server_candidate_plugins[0]",
    "module.nhp.module.compute.aws_s3_object.matched_cohort_server_init_script[0]",
    "module.nhp.module.compute.aws_launch_template.server_candidate[0]",
    "module.nhp.module.compute.aws_lb.server_registration_blue[0]",
    "module.nhp.module.compute.aws_lb.server_registration_green[0]",
    "module.nhp.module.compute.aws_lb.server_relay_green[0]",
    "module.nhp.module.compute.aws_lb.server_candidate[0]",
    "module.nhp.module.compute.aws_lb_target_group.server_registration_blue[0]",
    "module.nhp.module.compute.aws_lb_target_group.server_registration_green[0]",
    "module.nhp.module.compute.aws_lb_target_group.server_relay_green[0]",
    "module.nhp.module.compute.aws_lb_target_group.server_candidate[0]",
    "module.nhp.module.compute.aws_lb_target_group.server_candidate_promotion[0]",
    "module.nhp.module.compute.aws_lb_listener.server_registration_blue[0]",
    "module.nhp.module.compute.aws_lb_listener.server_registration_green[0]",
    "module.nhp.module.compute.aws_lb_listener.server_relay_green[0]",
    "module.nhp.module.compute.aws_lb_listener.server_candidate[0]",
    "module.nhp.module.compute.aws_autoscaling_attachment.server_registration_blue[0]",
    "module.nhp.module.compute.aws_autoscaling_group.server_candidate[0]",
    "module.nhp.module.compute.aws_iam_role.server_candidate_termination_hook[0]",
    "module.nhp.module.compute.aws_iam_role_policy.server_candidate_termination_hook[0]",
    "module.nhp.module.compute.aws_autoscaling_lifecycle_hook.server_candidate_termination[0]",
    "module.nhp.module.compute.aws_cloudwatch_event_rule.server_candidate_termination[0]",
    "module.nhp.module.compute.aws_cloudwatch_event_target.server_candidate_termination[0]",
    "module.nhp.module.compute.aws_lambda_permission.server_candidate_termination[0]",
    "module.nhp.module.compute.aws_sqs_queue.server_candidate_termination_cleanup_dlq[0]",
    "module.nhp.module.compute.aws_sqs_queue_policy.server_candidate_termination_cleanup_dlq[0]",
    "module.nhp.module.compute.aws_cloudwatch_log_group.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_iam_role.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_iam_role_policy.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_iam_role_policy_attachment.server_candidate_termination_logs[0]",
    "module.nhp.module.compute.aws_lambda_function.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_lambda_event_source_mapping.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_lambda_function_event_invoke_config.server_candidate_termination_cleanup[0]",
    "module.nhp.module.compute.aws_cloudwatch_metric_alarm.server_candidate_termination_cleanup_dlq[0]",
    "module.nhp.module.compute.aws_cloudwatch_metric_alarm.server_candidate_termination_event_failures[0]",
    "module.nhp.module.compute.aws_security_group.server_candidate_nlb[0]",
    "module.nhp.module.compute.aws_vpc_security_group_egress_rule.server_candidate_nlb_udp[0]",
    "module.nhp.module.compute.aws_vpc_security_group_egress_rule.server_candidate_nlb_health[0]",
    "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_candidate_target[0]",
    "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_candidate_health[0]",
    # AC isolated launch slots and candidate edge.
    "module.nhp.module.ac.aws_ssm_parameter.matched_cohort_ac_image_tag[0]",
    "module.nhp.module.ac.aws_s3_object.matched_cohort_blue_init_script[0]",
    "module.nhp.module.ac.aws_s3_object.matched_cohort_green_init_script[0]",
    "module.nhp.module.ac.aws_launch_template.ac_matched_blue[0]",
    "module.nhp.module.ac.aws_launch_template.ac_matched_green[0]",
    "module.nhp.module.ac.aws_lb_target_group.ac_candidate[0]",
    "module.nhp.module.ac.aws_lb_target_group.ac_candidate_smoke[0]",
    "module.nhp.module.ac.aws_security_group.ac_candidate_nlb[0]",
    "module.nhp.module.ac.aws_vpc_security_group_egress_rule.ac_candidate_nlb_https[0]",
    "module.nhp.module.ac.aws_vpc_security_group_egress_rule.ac_candidate_nlb_health[0]",
    "module.nhp.module.ac.aws_vpc_security_group_ingress_rule.ac_candidate_target_https[0]",
    "module.nhp.module.ac.aws_lb.ac_candidate[0]",
    "module.nhp.module.ac.aws_lb_listener.ac_candidate[0]",
    "module.nhp.module.ac.aws_autoscaling_group.ac_candidate[0]",
    "module.nhp.module.ac.aws_autoscaling_group.ac_matched_blue[0]",
    "module.nhp.module.ac.aws_vpc_security_group_ingress_rule.server_matched_cohort_internal[0]",
    # Relay candidate on the existing ALB and shared identity.
    "module.nhp.module.relay[0].aws_iam_role_policy.relay_matched_cohort_image[0]",
    "module.nhp.module.relay[0].aws_launch_template.relay_candidate[0]",
    "module.nhp.module.relay[0].aws_lb_target_group.relay_candidate[0]",
    "module.nhp.module.relay[0].aws_security_group.relay_candidate_alb[0]",
    "module.nhp.module.relay[0].aws_vpc_security_group_egress_rule.relay_candidate_alb_to_relay[0]",
    "module.nhp.module.relay[0].aws_vpc_security_group_ingress_rule.relay_candidate_from_alb[0]",
    "module.nhp.module.relay[0].aws_lb.relay_candidate[0]",
    "module.nhp.module.relay[0].aws_lb_listener.candidate_https[0]",
    "module.nhp.module.relay[0].aws_lb_listener_rule.relay_candidate[0]",
    "module.nhp.module.relay[0].aws_lb_listener_rule.relay_maintenance[0]",
    "module.nhp.module.relay[0].aws_autoscaling_group.relay_candidate[0]",
}

ALLOWED_INDEXED_PREFIXES = (
    "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_candidate_nlb[\"",
    "module.nhp.module.ac.aws_vpc_security_group_ingress_rule.ac_candidate_nlb[\"",
    "module.nhp.module.relay[0].aws_vpc_security_group_ingress_rule.alb_candidate_https[\"",
)

ALLOWED_FRPS_KEY_PREFIXES = (
    "module.nhp.module.ac.aws_lb_target_group.ac_candidate_frps[\"",
    "module.nhp.module.ac.aws_lb_listener.ac_candidate_frps[\"",
    "module.nhp.module.ac.aws_vpc_security_group_egress_rule.ac_candidate_nlb_frps[\"",
    "module.nhp.module.ac.aws_vpc_security_group_ingress_rule.ac_candidate_target_frps[\"",
)

AC_FRPS_INGRESS_PREFIX = (
    "module.nhp.module.ac.aws_vpc_security_group_ingress_rule.ac_candidate_nlb_frps[\""
)

ALLOWED_NUMERIC_PREFIXES = (
    "module.nhp.module.ac.aws_eip.matched_cohort_blue[",
    "module.nhp.module.ac.aws_eip.matched_cohort_green[",
)

REQUIRED = ALLOWED_RESOURCE_NAMES
CONNECTOR_VPCE_UPDATE = "module.nhp.module.compute.aws_vpc_endpoint.connector_authority_lambda[0]"
RELAY_RULE_PRIORITY_UPDATE = "module.nhp.module.relay[0].aws_lb_listener_rule.relay"
EXPECTED_PROD_ACCOUNT_ID = "235500187906"
EXPECTED_PROD_REGION = "us-east-2"
EXPECTED_PROD_SERVER_ROLE_ARN = (
    f"arn:aws:iam::{EXPECTED_PROD_ACCOUNT_ID}:role/layerv-nhp-prod-server"
)
EXPECTED_CONNECTOR_OPERATIONS = frozenset({"ar", "ccr", "cr", "iro"})
CONNECTOR_AUTHORITY_CREATES = {
    "module.nhp.module.compute.aws_iam_role_policy.server_candidate_connector_authority[0]",
}


def _strict_json(raw: str, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise ContractError(f"{label} is malformed JSON") from error


def _contains_unknown(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return any(_contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unknown(item) for item in value)
    return value not in (None, "", 0)


def _validate_connector_vpce_update(change: dict[str, Any]) -> None:
    if change.get("actions") != ["update"]:
        raise ContractError("Connector Authority VPCE must be one in-place policy update")
    before = _object(change.get("before"), "Connector Authority VPCE before")
    after = _object(change.get("after"), "Connector Authority VPCE after")
    if set(before) != set(after) or "policy" not in before:
        raise ContractError("Connector Authority VPCE update must preserve the exact resource shape")
    before_without_policy = dict(before)
    after_without_policy = dict(after)
    before_policy_raw = before_without_policy.pop("policy")
    after_policy_raw = after_without_policy.pop("policy")
    if before_without_policy != after_without_policy:
        raise ContractError("Connector Authority VPCE update may change only policy")
    if not isinstance(before_policy_raw, str) or not isinstance(after_policy_raw, str):
        raise ContractError("Connector Authority VPCE policies must be JSON strings")
    before_policy = _object(_strict_json(before_policy_raw, "before VPCE policy"), "before VPCE policy")
    after_policy = _object(_strict_json(after_policy_raw, "after VPCE policy"), "after VPCE policy")
    if set(before_policy) != {"Version", "Statement"} or before_policy.get("Version") != "2012-10-17":
        raise ContractError("before VPCE policy is not the exact reviewed envelope")
    if set(after_policy) != {"Version", "Statement"} or after_policy.get("Version") != "2012-10-17":
        raise ContractError("after VPCE policy is not the exact reviewed envelope")
    before_statements = before_policy.get("Statement")
    after_statements = after_policy.get("Statement")
    if not isinstance(before_statements, list) or len(before_statements) != 1:
        raise ContractError("before VPCE policy must contain one statement")
    if not isinstance(after_statements, list) or len(after_statements) != 1:
        raise ContractError("after VPCE policy must contain one statement")
    before_statement = _object(before_statements[0], "before VPCE statement")
    after_statement = _object(after_statements[0], "after VPCE statement")
    statement_keys = {"Sid", "Effect", "Principal", "Action", "Resource", "Condition"}
    if set(before_statement) != statement_keys or set(after_statement) != statement_keys:
        raise ContractError("Connector Authority VPCE statement shape changed")
    for key, expected in (
        ("Sid", "CellServerInvokeConnectorAuthority"),
        ("Effect", "Allow"),
        ("Principal", "*"),
        ("Action", "lambda:InvokeFunction"),
    ):
        if before_statement.get(key) != expected or after_statement.get(key) != expected:
            raise ContractError(f"Connector Authority VPCE {key} changed")
    resources = before_statement.get("Resource")
    if (
        not isinstance(resources, list)
        or not resources
        or resources != sorted(set(resources))
        or any(not isinstance(item, str) or not item.startswith("arn:aws:lambda:") for item in resources)
        or after_statement.get("Resource") != resources
    ):
        raise ContractError("Connector Authority VPCE alias resources changed")
    alias_pattern = re.compile(
        rf"arn:aws:lambda:{EXPECTED_PROD_REGION}:{EXPECTED_PROD_ACCOUNT_ID}:"
        r"function:layerv-nhp-prod-ca-(ar|ccr|cr|iro|creso)-cell0:(blue|green)"
    )
    parsed_aliases = [alias_pattern.fullmatch(item) for item in resources]
    if any(match is None for match in parsed_aliases):
        raise ContractError("Connector Authority VPCE resources are not exact prod cell0 aliases")
    operations = {match.group(1) for match in parsed_aliases if match is not None}
    colors = {match.group(2) for match in parsed_aliases if match is not None}
    if operations not in (EXPECTED_CONNECTOR_OPERATIONS, EXPECTED_CONNECTOR_OPERATIONS | {"creso"}) or len(colors) != 1:
        raise ContractError("Connector Authority VPCE aliases must be the exact same-color 4-operation predecessor or 5-operation graph")

    def roles(statement: dict[str, Any], label: str) -> list[str]:
        condition = statement.get("Condition")
        if not isinstance(condition, dict) or set(condition) != {"StringEquals"}:
            raise ContractError(f"{label} condition is not exact")
        equals = condition["StringEquals"]
        if not isinstance(equals, dict) or set(equals) != {"aws:PrincipalArn"}:
            raise ContractError(f"{label} principal condition is not exact")
        values = equals["aws:PrincipalArn"]
        if not isinstance(values, list) or values != sorted(set(values)):
            raise ContractError(f"{label} principal list is not canonical")
        return values

    before_roles = roles(before_statement, "before VPCE")
    after_roles = roles(after_statement, "after VPCE")
    if len(before_roles) != 1 or len(after_roles) != 2:
        raise ContractError("Connector Authority VPCE must add exactly one candidate principal")
    active_role = before_roles[0]
    if active_role != EXPECTED_PROD_SERVER_ROLE_ARN or after_roles != sorted([active_role, active_role + "-candidate"]):
        raise ContractError("Connector Authority VPCE candidate principal is not derived from the active server role")
    if _contains_unknown(change.get("after_unknown", {})):
        raise ContractError("Connector Authority VPCE update contains unresolved authority")


def _validate_relay_rule_priority_update(change: dict[str, Any]) -> None:
    if change.get("actions") != ["update"]:
        raise ContractError("canonical relay rule must be one in-place priority update")
    before = _object(change.get("before"), "canonical relay rule before")
    after = _object(change.get("after"), "canonical relay rule after")
    if set(before) != set(after) or before.get("priority") != 1 or after.get("priority") != 2:
        raise ContractError("canonical relay rule must move exactly from priority 1 to 2")
    before_without_priority = dict(before)
    after_without_priority = dict(after)
    before_without_priority.pop("priority")
    after_without_priority.pop("priority")
    if before_without_priority != after_without_priority:
        raise ContractError("canonical relay rule priority update changed another field")
    if _contains_unknown(change.get("after_unknown", {})):
        raise ContractError("canonical relay rule priority update contains unresolved authority")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _allowed(address: str) -> bool:
    return address in (ALLOWED_RESOURCE_NAMES | CONNECTOR_AUTHORITY_CREATES) or any(
        address.startswith(prefix) and address.endswith('"]')
        for prefix in ALLOWED_INDEXED_PREFIXES
    ) or any(
        address.startswith(prefix)
        and address.endswith("]")
        and address[len(prefix):-1].isdigit()
        for prefix in ALLOWED_NUMERIC_PREFIXES
    ) or any(
        address.startswith(prefix) and address.endswith('\"]')
        for prefix in ALLOWED_FRPS_KEY_PREFIXES + (AC_FRPS_INGRESS_PREFIX,)
    )


def validate(plan: dict[str, Any]) -> None:
    if set(plan.get("format_version", "").split(".")[:1]) != {"1"}:
        raise ContractError("Terraform plan format_version must be 1.x")

    variables = _object(plan.get("variables"), "variables")
    environment = _object(variables.get("environment"), "variables.environment").get("value")
    enabled = _object(
        variables.get("enable_matched_cohort_canary"),
        "variables.enable_matched_cohort_canary",
    ).get("value")
    if environment != "prod" or enabled is not True:
        raise ContractError("the additive cohort plan must be prod with enable_matched_cohort_canary=true")
    cidrs = _object(
        variables.get("matched_cohort_smoke_ingress_cidrs"),
        "variables.matched_cohort_smoke_ingress_cidrs",
    ).get("value")
    if (
        not isinstance(cidrs, list)
        or not cidrs
        or cidrs != sorted(set(cidrs))
        or any(not isinstance(cidr, str) for cidr in cidrs)
    ):
        raise ContractError("matched_cohort_smoke_ingress_cidrs must be a non-empty canonical list")
    try:
        smoke_networks = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs]
    except ValueError as error:
        raise ContractError("matched_cohort_smoke_ingress_cidrs contains malformed CIDR") from error
    if any(network.version != 4 or network.prefixlen != 32 for network in smoke_networks):
        raise ContractError("matched_cohort_smoke_ingress_cidrs must contain only exact IPv4 /32s")
    ac_max_capacity = _object(
        variables.get("ac_max_capacity"),
        "variables.ac_max_capacity",
    ).get("value")
    if (
        not isinstance(ac_max_capacity, int)
        or isinstance(ac_max_capacity, bool)
        or ac_max_capacity < 1
        or ac_max_capacity > 100
    ):
        raise ContractError("ac_max_capacity must be an integer in [1,100]")
    connector_authority_enabled = _object(
        variables.get("connector_authority_cell_from_control_enabled"),
        "variables.connector_authority_cell_from_control_enabled",
    ).get("value")
    if not isinstance(connector_authority_enabled, bool):
        raise ContractError("connector_authority_cell_from_control_enabled must be boolean")
    deploy_frps = _object(variables.get("deploy_frps"), "variables.deploy_frps").get("value")
    frps_suffixes = _object(
        variables.get("frps_az_suffixes"),
        "variables.frps_az_suffixes",
    ).get("value")
    if deploy_frps is not True:
        raise ContractError("the complete matched cohort requires deploy_frps=true")
    if (
        not isinstance(frps_suffixes, list)
        or not frps_suffixes
        or frps_suffixes != sorted(set(frps_suffixes))
        or any(not isinstance(suffix, str) or re.fullmatch(r"[a-z]", suffix) is None for suffix in frps_suffixes)
    ):
        raise ContractError("frps_az_suffixes must be a non-empty canonical list")
    frps_keys = ["primary", *frps_suffixes[1:]]
    expected_indexed = {
        f'{prefix}{cidr}"]'
        for prefix in ALLOWED_INDEXED_PREFIXES
        for cidr in cidrs
    }
    expected_numeric = {
        f"{prefix}{index}]"
        for prefix in ALLOWED_NUMERIC_PREFIXES
        for index in range(ac_max_capacity + 1)
    }
    expected_frps = {
        f'{prefix}{name}"]'
        for prefix in ALLOWED_FRPS_KEY_PREFIXES
        for name in frps_keys
    } | {
        f'{AC_FRPS_INGRESS_PREFIX}{name}|{cidr}"]'
        for name in frps_keys
        for cidr in cidrs
    }

    changed: set[str] = set()
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ContractError("resource_changes must be a list")
    for entry in changes:
        item = _object(entry, "resource change")
        address = item.get("address")
        actions = _object(item.get("change"), f"{address}.change").get("actions")
        if actions in (["no-op"], ["read"]):
            continue
        if address == CONNECTOR_VPCE_UPDATE:
            _validate_connector_vpce_update(_object(item.get("change"), f"{address}.change"))
            if address in changed:
                raise ContractError(f"duplicate resource change: {address}")
            changed.add(address)
            continue
        if address == RELAY_RULE_PRIORITY_UPDATE:
            _validate_relay_rule_priority_update(_object(item.get("change"), f"{address}.change"))
            if address in changed:
                raise ContractError(f"duplicate resource change: {address}")
            changed.add(address)
            continue
        if not isinstance(address, str) or not _allowed(address):
            raise ContractError(f"unreviewed resource change: {address!r}")
        if actions != ["create"]:
            raise ContractError(f"{address} must be create-only; got {actions!r}")
        if address in changed:
            raise ContractError(f"duplicate resource change: {address}")
        changed.add(address)

    expected = REQUIRED | expected_indexed | expected_numeric | expected_frps | {RELAY_RULE_PRIORITY_UPDATE}
    if connector_authority_enabled:
        expected |= CONNECTOR_AUTHORITY_CREATES | {CONNECTOR_VPCE_UPDATE}
    missing = sorted(expected - changed)
    unexpected = sorted(changed - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise ContractError("plan does not contain the exact cohort change set (" + "; ".join(details) + ")")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()
    try:
        raw = _strict_json(args.plan_json.read_text(encoding="utf-8"), "saved plan")
        validate(_object(raw, "plan"))
    except (OSError, ContractError) as error:
        print(f"matched-cohort additive plan rejected: {error}", file=sys.stderr)
        return 1
    print("matched-cohort additive plan accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
