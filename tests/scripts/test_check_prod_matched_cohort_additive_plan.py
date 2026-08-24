from __future__ import annotations

import importlib.util
import copy
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / ".github/scripts/check-prod-matched-cohort-additive-plan.py"
SPEC = importlib.util.spec_from_file_location("cohort_plan", PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def plan(*, connector_authority_enabled: bool = True) -> dict:
    cidr = "203.0.113.4/32"
    ac_max_capacity = 10
    frps_suffixes = ["a", "b", "c"]
    frps_keys = ["primary", *frps_suffixes[1:]]
    changes = [
        {"address": address, "change": {"actions": ["create"]}}
        for address in sorted(
            CHECKER.REQUIRED
            | (CHECKER.CONNECTOR_AUTHORITY_CREATES if connector_authority_enabled else set())
            | {f'{prefix}{cidr}"]' for prefix in CHECKER.ALLOWED_INDEXED_PREFIXES}
            | {
                f"{prefix}{index}]"
                for prefix in CHECKER.ALLOWED_NUMERIC_PREFIXES
                for index in range(ac_max_capacity + 1)
            }
            | {
                f'{prefix}{name}"]'
                for prefix in CHECKER.ALLOWED_FRPS_KEY_PREFIXES
                for name in frps_keys
            }
            | {
                f'{CHECKER.AC_FRPS_INGRESS_PREFIX}{name}|{cidr}"]'
                for name in frps_keys
            }
        )
    ]
    active_role = "arn:aws:iam::235500187906:role/layerv-nhp-prod-server"
    aliases = [
        "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-prod-ca-ar-cell0:blue",
        "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-prod-ca-ccr-cell0:blue",
        "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-prod-ca-cr-cell0:blue",
        "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-prod-ca-iro-cell0:blue",
    ]

    def vpce_policy(roles: list[str]) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "CellServerInvokeConnectorAuthority",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "lambda:InvokeFunction",
                    "Resource": aliases,
                    "Condition": {"StringEquals": {"aws:PrincipalArn": roles}},
                }],
            },
            sort_keys=True,
        )

    before = {"id": "vpce-123", "vpc_id": "vpc-123", "policy": vpce_policy([active_role])}
    after = {
        "id": "vpce-123",
        "vpc_id": "vpc-123",
        "policy": vpce_policy(sorted([active_role, active_role + "-candidate"])),
    }
    if connector_authority_enabled:
        changes.append({
            "address": CHECKER.CONNECTOR_VPCE_UPDATE,
            "change": {
                "actions": ["update"],
                "before": before,
                "after": after,
                "after_unknown": {"policy": False},
            },
        })
    relay_rule = {
        "rule_arn": "arn:aws:elasticloadbalancing:us-east-2:235500187906:listener-rule/relay",
        "listener_arn": "arn:aws:elasticloadbalancing:us-east-2:235500187906:listener/relay",
        "priority": 1,
        "action": [{"type": "forward", "target_group_arn": "arn:relay-blue"}],
        "condition": [
            {"path_pattern": [{"values": ["/relay/*"]}]},
            {"http_request_method": [{"values": ["POST", "OPTIONS"]}]},
        ],
    }
    relay_rule_after = copy.deepcopy(relay_rule)
    relay_rule_after["priority"] = 2
    changes.append({
        "address": CHECKER.RELAY_RULE_PRIORITY_UPDATE,
        "change": {
            "actions": ["update"],
            "before": relay_rule,
            "after": relay_rule_after,
            "after_unknown": {},
        },
    })
    return {
        "format_version": "1.2",
        "variables": {
            "environment": {"value": "prod"},
            "enable_matched_cohort_canary": {"value": True},
            "matched_cohort_smoke_ingress_cidrs": {"value": [cidr]},
            "ac_max_capacity": {"value": ac_max_capacity},
            "deploy_frps": {"value": True},
            "frps_az_suffixes": {"value": frps_suffixes},
            "connector_authority_cell_from_control_enabled": {
                "value": connector_authority_enabled,
            },
        },
        "resource_changes": changes,
    }


class AdditivePlanTest(unittest.TestCase):
    def test_accepts_exact_create_only_plan(self) -> None:
        CHECKER.validate(plan())
        CHECKER.validate(plan(connector_authority_enabled=False))
        with self.assertRaisesRegex(CHECKER.ContractError, "duplicate key"):
            CHECKER._strict_json('{"format_version":"1.2","format_version":"1.2"}', "saved plan")

    def test_rejects_update_delete_or_replace(self) -> None:
        for actions in (["update"], ["delete"], ["delete", "create"]):
            with self.subTest(actions=actions):
                value = plan()
                value["resource_changes"][0]["change"]["actions"] = actions
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.validate(value)

    def test_rejects_active_listener_or_capacity_mutation(self) -> None:
        for address in (
            "module.nhp.module.compute.aws_lb_listener.udp[0]",
            "module.nhp.module.ac.aws_autoscaling_group.ac",
            "module.nhp.module.relay[0].aws_lb_listener_rule.relay",
            "module.nhp.aws_ssm_parameter.minimum_protocol_profile[0]",
        ):
            with self.subTest(address=address):
                value = plan()
                value["resource_changes"].append(
                    {"address": address, "change": {"actions": ["update"]}}
                )
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.validate(value)

    def test_rejects_wrong_environment_disabled_or_any_missing_inventory(self) -> None:
        cases = []
        wrong = plan()
        wrong["variables"]["environment"]["value"] = "sandbox"
        cases.append(wrong)
        disabled = plan()
        disabled["variables"]["enable_matched_cohort_canary"]["value"] = False
        cases.append(disabled)
        for value in cases:
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.validate(value)
        base = plan()
        for index in range(len(base["resource_changes"])):
            with self.subTest(missing=index):
                missing = plan()
                missing["resource_changes"].pop(index)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.validate(missing)

    def test_cidr_indexed_resources_are_closed_prefixes(self) -> None:
        value = plan()
        value["resource_changes"].append(
            {
                "address": 'module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_candidate_nlb["203.0.113.4/32"]',
                "change": {"actions": ["create"]},
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate(value)
        value = plan()
        value["resource_changes"].append(
            {
                "address": 'module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_candidate_nlb["203.0.113.5/32"]',
                "change": {"actions": ["create"]},
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate(value)

    def test_eip_pool_count_is_exactly_max_capacity_plus_spare_per_cohort(self) -> None:
        for mutation in (
            'module.nhp.module.ac.aws_eip.matched_cohort_blue[11]',
            'module.nhp.module.ac.aws_eip.matched_cohort_green[11]',
            'module.nhp.module.ac.aws_eip.matched_cohort_blue["0"]',
        ):
            with self.subTest(mutation=mutation):
                value = plan()
                value["resource_changes"].append(
                    {"address": mutation, "change": {"actions": ["create"]}}
                )
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.validate(value)

    def test_frps_listener_vector_and_restricted_ingress_are_exact(self) -> None:
        mutations = []

        disabled = plan()
        disabled["variables"]["deploy_frps"]["value"] = False
        mutations.append(disabled)

        for suffixes in ([], ["a", "c", "b"], ["a", "a"], ["a", "north"]):
            value = plan()
            value["variables"]["frps_az_suffixes"]["value"] = suffixes
            mutations.append(value)

        missing = plan()
        missing["resource_changes"] = [
            item
            for item in missing["resource_changes"]
            if item["address"]
            != 'module.nhp.module.ac.aws_lb_listener.ac_candidate_frps["b"]'
        ]
        mutations.append(missing)

        extra_key = plan()
        extra_key["resource_changes"].append({
            "address": 'module.nhp.module.ac.aws_lb_target_group.ac_candidate_frps["d"]',
            "change": {"actions": ["create"]},
        })
        mutations.append(extra_key)

        extra_cidr = plan()
        extra_cidr["resource_changes"].append({
            "address": (
                'module.nhp.module.ac.aws_vpc_security_group_ingress_rule.'
                'ac_candidate_nlb_frps["primary|203.0.113.5/32"]'
            ),
            "change": {"actions": ["create"]},
        })
        mutations.append(extra_cidr)

        for cidrs in (
            ["203.0.113.4/32", "203.0.113.4/32"],
            ["203.0.113.5/32", "203.0.113.4/32"],
            ["203.0.113.0/24"],
            ["2001:db8::1/128"],
            ["not-a-cidr"],
        ):
            value = plan()
            value["variables"]["matched_cohort_smoke_ingress_cidrs"]["value"] = cidrs
            mutations.append(value)

        for index, value in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(CHECKER.ContractError):
                CHECKER.validate(value)

    def test_connector_vpce_update_is_the_only_admitted_existing_resource_change(self) -> None:
        base = plan()
        vpce = next(
            item for item in base["resource_changes"]
            if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE
        )
        mutations = []

        value = copy.deepcopy(base)
        target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
        target["change"]["actions"] = ["delete", "create"]
        mutations.append(value)

        for mutate in (
            lambda statement: statement.update(Action="lambda:*") ,
            lambda statement: statement.update(Resource=["arn:aws:lambda:us-east-2:235500187906:function:other"]),
            lambda statement: statement["Condition"]["StringEquals"]["aws:PrincipalArn"].append(
                "arn:aws:iam::235500187906:role/unreviewed"
            ),
        ):
            value = copy.deepcopy(base)
            target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
            policy = json.loads(target["change"]["after"]["policy"])
            mutate(policy["Statement"][0])
            target["change"]["after"]["policy"] = json.dumps(policy, sort_keys=True)
            mutations.append(value)

        value = copy.deepcopy(base)
        target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
        target["change"]["after"]["vpc_id"] = "vpc-other"
        mutations.append(value)

        value = copy.deepcopy(base)
        target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
        target["change"]["after_unknown"] = {"policy": True}
        mutations.append(value)

        value = copy.deepcopy(base)
        target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
        target["change"]["after"]["policy"] = target["change"]["after"]["policy"].replace(
            '"Version":', '"Version":"2012-10-17","Version":', 1
        )
        mutations.append(value)

        for mutate_resources in (
            lambda resources: resources.pop(),
            lambda resources: resources.__setitem__(0, resources[0].replace(":blue", ":green")),
        ):
            value = copy.deepcopy(base)
            target = next(item for item in value["resource_changes"] if item["address"] == CHECKER.CONNECTOR_VPCE_UPDATE)
            for side in ("before", "after"):
                policy = json.loads(target["change"][side]["policy"])
                mutate_resources(policy["Statement"][0]["Resource"])
                target["change"][side]["policy"] = json.dumps(policy, sort_keys=True)
            mutations.append(value)

        for index, value in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(CHECKER.ContractError):
                CHECKER.validate(value)

        missing = copy.deepcopy(base)
        missing["resource_changes"] = [
            item for item in missing["resource_changes"]
            if item["address"] != CHECKER.CONNECTOR_VPCE_UPDATE
        ]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate(missing)

        self.assertEqual(vpce["change"]["actions"], ["update"])

        disabled = plan(connector_authority_enabled=False)
        CHECKER.validate(disabled)
        disabled["resource_changes"].append(copy.deepcopy(vpce))
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate(disabled)

        for invalid in (None, 0, 101, True, "10"):
            with self.subTest(ac_max_capacity=invalid):
                value = plan()
                value["variables"]["ac_max_capacity"]["value"] = invalid
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.validate(value)

    def test_relay_rule_update_is_exact_priority_shift_only(self) -> None:
        base = plan()
        target = next(
            item for item in base["resource_changes"]
            if item["address"] == CHECKER.RELAY_RULE_PRIORITY_UPDATE
        )
        self.assertEqual(target["change"]["before"]["priority"], 1)
        self.assertEqual(target["change"]["after"]["priority"], 2)
        for mutation in (
            lambda item: item["change"]["after"].update(priority=3),
            lambda item: item["change"]["after"].update(listener_arn="arn:other"),
            lambda item: item["change"].update(actions=["delete", "create"]),
            lambda item: item["change"].update(after_unknown={"priority": True}),
        ):
            value = plan()
            item = next(
                candidate for candidate in value["resource_changes"]
                if candidate["address"] == CHECKER.RELAY_RULE_PRIORITY_UPDATE
            )
            mutation(item)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.validate(value)


if __name__ == "__main__":
    unittest.main()
