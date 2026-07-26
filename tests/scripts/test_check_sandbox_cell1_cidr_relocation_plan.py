#!/usr/bin/env python3
"""Fixture coverage for the attended cell1 CIDR relocation plan checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / ".github/scripts/check-sandbox-cell1-cidr-relocation-plan.py"
SPEC = importlib.util.spec_from_file_location("cell1_relocation_checker", CHECKER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def plan_fixture(direction: str = "forward") -> dict:
    before_cidr, after_cidr = (
        (MODULE.OLD_CIDR, MODULE.NEW_CIDR)
        if direction == "forward"
        else (MODULE.NEW_CIDR, MODULE.OLD_CIDR)
    )
    changes = []
    for address, actions in MODULE.EXPECTED_ACTIONS.items():
        before = {}
        after = {}
        if address == "module.networking.aws_vpc.main":
            before = {"cidr_block": before_cidr}
            after = {"cidr_block": after_cidr}
        elif address.startswith("module.networking.aws_subnet."):
            subnet_type, index_text = address.rsplit(".", 1)[1].split("[")
            index = int(index_text.rstrip("]"))
            octet = MODULE.SUBNET_OCTETS[subnet_type][index]
            before_prefix = ".".join(before_cidr.split(".")[:2])
            after_prefix = ".".join(after_cidr.split(".")[:2])
            before = {"cidr_block": f"{before_prefix}.{octet}.0/24"}
            after = {"cidr_block": f"{after_prefix}.{octet}.0/24"}
        elif address == "module.dns.aws_route53_record.nhp[0]":
            before = {
                "name": MODULE.CELL_DNS_NAME,
                "fqdn": MODULE.CELL_DNS_NAME,
                "zone_id": MODULE.HOSTED_ZONE_ID,
                "type": "A",
            }
            after = copy.deepcopy(before)
        elif address in {
            "module.compute.aws_autoscaling_group.server",
            "module.compute.aws_autoscaling_group.server_green[0]",
        }:
            suspended = sorted(MODULE.REQUIRED_SUSPENDED_PROCESSES)
            before = {
                "min_size": 0,
                "max_size": 0,
                "desired_capacity": 0,
                "suspended_processes": suspended,
            }
            after = {
                "min_size": 0,
                "max_size": 2,
                "desired_capacity": 0,
                "suspended_processes": suspended,
            }
        changes.append(
            {
                "address": address,
                "change": {
                    "actions": list(actions),
                    "before": before,
                    "after": after,
                    **(
                        {"after_unknown": {"alias": [{"name": True, "zone_id": True}]}}
                        if address == "module.dns.aws_route53_record.nhp[0]"
                        else {}
                    ),
                },
            }
        )
    for address in MODULE.PRESERVED_NO_OP:
        changes.append(
            {
                "address": address,
                "change": {"actions": ["no-op"], "before": {}, "after": {}},
            }
        )
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.3",
        "resource_changes": changes,
        "configuration": {
            "root_module": {
                "module_calls": {
                    "compute": {
                        "expressions": {
                            "vpc_id": {
                                "references": [
                                    "module.networking.vpc_id",
                                    "module.networking",
                                ]
                            },
                            "public_subnet_ids": {
                                "references": [
                                    "module.networking.public_subnet_ids",
                                    "module.networking",
                                ]
                            },
                            "private_subnet_ids": {
                                "references": [
                                    "module.networking.private_subnet_ids",
                                    "module.networking",
                                ]
                            },
                            "max_capacity": {
                                "references": ["var.max_capacity"]
                            },
                        }
                    },
                    "dns": {
                        "expressions": {
                            "domain_name": {"references": ["var.cell_dns_name"]},
                            "hosted_zone_id": {"references": ["var.hosted_zone_id"]},
                            "nlb_dns_name": {
                                "references": [
                                    "module.compute.nlb_dns_name",
                                    "module.compute",
                                ]
                            },
                            "nlb_zone_id": {
                                "references": [
                                    "module.compute.nlb_zone_id",
                                    "module.compute",
                                ]
                            },
                        }
                    },
                }
            }
        },
        "variables": {
            "cell_dns_name": {"value": MODULE.CELL_DNS_NAME},
            "hosted_zone_id": {"value": MODULE.HOSTED_ZONE_ID},
            "max_capacity": {"value": 2},
        },
    }


def run_checker(plan: dict, direction: str = "forward") -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
        json.dump(plan, handle)
        handle.flush()
        return subprocess.run(
            [
                "python3",
                str(CHECKER),
                handle.name,
                "--direction",
                direction,
            ],
            check=False,
            capture_output=True,
            text=True,
        )


def resource_change(plan: dict, address: str) -> dict:
    return next(
        item["change"]
        for item in plan["resource_changes"]
        if item["address"] == address
    )


class RelocationPlanTest(unittest.TestCase):
    def test_exact_forward_plan_passes(self) -> None:
        result = run_checker(plan_fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("53 add, 12 change, 50 destroy", result.stdout)

    def test_exact_rollback_plan_passes(self) -> None:
        result = run_checker(plan_fixture("rollback"), "rollback")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_extra_mutation_fails(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(
            {
                "address": "module.compute.aws_secretsmanager_secret.unreviewed",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {},
                    "after": {},
                },
            }
        )
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("extra=", result.stderr)

    def test_identity_replacement_fails(self) -> None:
        plan = plan_fixture()
        resource_change(
            plan, "module.compute.aws_secretsmanager_secret.server"
        )["actions"] = ["delete", "create"]
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity/data preservation", result.stderr)

    def test_plan_created_before_full_drain_fails(self) -> None:
        plan = plan_fixture()
        resource_change(
            plan, "module.compute.aws_autoscaling_group.server"
        )["before"]["desired_capacity"] = 1
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("live desired_capacity must be 0", result.stderr)

    def test_any_kms_mutation_fails(self) -> None:
        plan = plan_fixture()
        resource_change(plan, "module.kms.aws_kms_key.secrets")["actions"] = ["update"]
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity/data preservation", result.stderr)

    def test_preserved_module_data_source_read_passes(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(
            {
                "address": "module.dynamodb.data.aws_region.current",
                "mode": "data",
                "change": {"actions": ["read"], "before": {}, "after": {}},
            }
        )
        result = run_checker(plan)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preserved_module_data_source_mutation_fails(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(
            {
                "address": "module.dynamodb.data.aws_region.current",
                "mode": "data",
                "change": {"actions": ["update"], "before": {}, "after": {}},
            }
        )
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("all DynamoDB, KMS, and plugin-bucket", result.stderr)

    def test_preserved_managed_resource_read_fails(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(
            {
                "address": "module.dynamodb.aws_dynamodb_table.unexpected",
                "mode": "managed",
                "change": {"actions": ["read"], "before": {}, "after": {}},
            }
        )
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("all DynamoDB, KMS, and plugin-bucket", result.stderr)

    def test_unpreserved_managed_resource_read_fails(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(
            {
                "address": "module.compute.aws_instance.unexpected",
                "mode": "managed",
                "change": {"actions": ["read"], "before": {}, "after": {}},
            }
        )
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("extra=", result.stderr)

    def test_plan_cannot_resume_launch_processes(self) -> None:
        plan = plan_fixture()
        resource_change(
            plan, "module.compute.aws_autoscaling_group.server"
        )["after"]["suspended_processes"] = []
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("planned suspended_processes", result.stderr)

    def test_duplicate_address_fails(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][0]))
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate resource change address", result.stderr)

    def test_missing_subnet_dependency_fails(self) -> None:
        plan = copy.deepcopy(plan_fixture())
        plan["configuration"]["root_module"]["module_calls"]["compute"]["expressions"][
            "private_subnet_ids"
        ]["references"] = []
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "must depend on module.networking.private_subnet_ids", result.stderr
        )

    def test_wrong_dns_target_dependency_fails(self) -> None:
        plan = plan_fixture()
        plan["configuration"]["root_module"]["module_calls"]["dns"]["expressions"][
            "nlb_dns_name"
        ]["references"] = ["module.unreviewed.nlb_dns_name", "module.unreviewed"]
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dns.nlb_dns_name must have exact references", result.stderr)

    def test_wrong_subnet_range_fails(self) -> None:
        plan = plan_fixture()
        resource_change(plan, "module.networking.aws_subnet.private[1]")["after"][
            "cidr_block"
        ] = "10.104.99.0/24"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "module.networking.aws_subnet.private[1]: planned cidr_block",
            result.stderr,
        )

    def test_wrong_vpc_prior_cidr_fails(self) -> None:
        plan = plan_fixture()
        resource_change(plan, "module.networking.aws_vpc.main")["before"][
            "cidr_block"
        ] = "10.101.0.0/16"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VPC prior CIDR mismatch", result.stderr)

    def test_wrong_vpc_planned_cidr_fails(self) -> None:
        plan = plan_fixture()
        resource_change(plan, "module.networking.aws_vpc.main")["after"][
            "cidr_block"
        ] = "10.105.0.0/16"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VPC planned CIDR mismatch", result.stderr)

    def test_dns_alias_not_derived_from_replacement_fails(self) -> None:
        plan = plan_fixture()
        resource_change(plan, "module.dns.aws_route53_record.nhp[0]")[
            "after_unknown"
        ]["alias"] = []
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("after_unknown.alias=[]", result.stderr)

    def test_wrong_plan_format_version_fails(self) -> None:
        plan = plan_fixture()
        plan["format_version"] = "1.1"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected Terraform plan JSON format 1.2", result.stderr)

    def test_wrong_terraform_version_fails(self) -> None:
        plan = plan_fixture()
        plan["terraform_version"] = "1.14.2"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned to Terraform 1.14.3", result.stderr)

    def test_wrong_cell_dns_name_fails(self) -> None:
        plan = plan_fixture()
        plan["variables"]["cell_dns_name"]["value"] = "other.nhp.layerv.xyz"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("var.cell_dns_name must be", result.stderr)

    def test_wrong_hosted_zone_id_fails(self) -> None:
        plan = plan_fixture()
        plan["variables"]["hosted_zone_id"]["value"] = "Z00000000000000000000"
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("var.hosted_zone_id must be", result.stderr)

    def test_missing_vpc_dependency_fails(self) -> None:
        plan = plan_fixture()
        plan["configuration"]["root_module"]["module_calls"]["compute"]["expressions"][
            "vpc_id"
        ]["references"] = []
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must depend on module.networking.vpc_id", result.stderr)

    def test_missing_public_subnet_dependency_fails(self) -> None:
        plan = plan_fixture()
        plan["configuration"]["root_module"]["module_calls"]["compute"]["expressions"][
            "public_subnet_ids"
        ]["references"] = []
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "must depend on module.networking.public_subnet_ids", result.stderr
        )

    def test_max_capacity_reference_drift_fails(self) -> None:
        plan = plan_fixture()
        plan["configuration"]["root_module"]["module_calls"]["compute"]["expressions"][
            "max_capacity"
        ]["references"] = ["local.unreviewed_max"]
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compute.max_capacity must derive only", result.stderr)

    def test_max_capacity_value_drift_fails(self) -> None:
        plan = plan_fixture()
        plan["variables"]["max_capacity"]["value"] = 3
        result = run_checker(plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reviewed cell1 migration value 2", result.stderr)


if __name__ == "__main__":
    unittest.main()
