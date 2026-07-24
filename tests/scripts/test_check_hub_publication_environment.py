#!/usr/bin/env python3
"""Tests for the live Hub publication Environment policy validator."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/check-hub-publication-environment.py"
SPEC = importlib.util.spec_from_file_location("hub_environment", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def environment_fixture(name: str = "hub-publish-sandbox") -> dict[str, object]:
    return {
        "name": name,
        "can_admins_bypass": True,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {
                            "id": CHECKER.REVIEWER_ID,
                            "login": "justin-layerv",
                        },
                    }
                ],
            },
            {"type": "branch_policy"},
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def branch_fixture() -> dict[str, object]:
    return {
        "total_count": 1,
        "branch_policies": [{"name": "main", "type": "branch", "id": 123}],
    }


class EnvironmentContractTests(unittest.TestCase):
    def check(
        self,
        *,
        target: str = "sandbox",
        publication: str = "hub-publish-sandbox",
        environment: dict[str, object] | None = None,
        branches: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return CHECKER.check_environment(
            repository=CHECKER.REPOSITORY,
            target_environment=target,
            publication_environment=publication,
            environment=environment or environment_fixture(publication),
            branch_policies=branches or branch_fixture(),
        )

    def test_exact_sandbox_and_production_contracts_pass(self) -> None:
        sandbox = self.check()
        production = self.check(
            target="production",
            publication="hub-publish-production",
        )
        self.assertEqual(sandbox["required_reviewer_id"], CHECKER.REVIEWER_ID)
        self.assertEqual(production["deployment_branch"], "main")

    def test_stricter_admin_and_self_review_settings_remain_compatible(self) -> None:
        for can_admins_bypass, prevent_self_review in (
            (False, False),
            (True, True),
            (False, True),
        ):
            with self.subTest(
                can_admins_bypass=can_admins_bypass,
                prevent_self_review=prevent_self_review,
            ):
                environment = environment_fixture()
                environment["can_admins_bypass"] = can_admins_bypass
                environment["protection_rules"][0]["prevent_self_review"] = (  # type: ignore[index]
                    prevent_self_review
                )
                self.check(environment=environment)

    def test_shared_and_cross_target_environments_fail(self) -> None:
        for target, publication in (
            ("sandbox", "sandbox"),
            ("production", "production"),
            ("sandbox", "hub-publish-production"),
            ("production", "hub-publish-sandbox"),
        ):
            with self.subTest(target=target, publication=publication):
                with self.assertRaises(CHECKER.ContractError):
                    self.check(target=target, publication=publication)

    def test_missing_extra_and_duplicate_rules_fail(self) -> None:
        cases: list[dict[str, object]] = []
        missing = environment_fixture()
        missing["protection_rules"] = [{"type": "branch_policy"}]
        cases.append(missing)
        extra = environment_fixture()
        extra["protection_rules"].append({"type": "wait_timer"})  # type: ignore[union-attr]
        cases.append(extra)
        duplicate = environment_fixture()
        duplicate["protection_rules"] = [
            {"type": "branch_policy"},
            {"type": "branch_policy"},
        ]
        cases.append(duplicate)
        for environment in cases:
            with self.subTest(environment=environment):
                with self.assertRaises(CHECKER.ContractError):
                    self.check(environment=environment)

    def test_reviewer_is_exactly_justin_user_id(self) -> None:
        for reviewer in (
            [],
            [{"type": "User", "reviewer": {"id": 1}}],
            [{"type": "Team", "reviewer": {"id": CHECKER.REVIEWER_ID}}],
            [
                {"type": "User", "reviewer": {"id": CHECKER.REVIEWER_ID}},
                {"type": "User", "reviewer": {"id": 1}},
            ],
        ):
            with self.subTest(reviewer=reviewer):
                environment = environment_fixture()
                environment["protection_rules"][0]["reviewers"] = reviewer  # type: ignore[index]
                with self.assertRaises(CHECKER.ContractError):
                    self.check(environment=environment)

    def test_only_custom_main_branch_policy_passes(self) -> None:
        environment_cases = (
            None,
            {"protected_branches": True, "custom_branch_policies": False},
            {"protected_branches": False, "custom_branch_policies": False},
        )
        for deployment_policy in environment_cases:
            with self.subTest(deployment_policy=deployment_policy):
                environment = environment_fixture()
                environment["deployment_branch_policy"] = deployment_policy
                with self.assertRaises(CHECKER.ContractError):
                    self.check(environment=environment)

        for branches in (
            {"total_count": 0, "branch_policies": []},
            {
                "total_count": 1,
                "branch_policies": [{"name": "release/*", "type": "branch"}],
            },
            {
                "total_count": 2,
                "branch_policies": [
                    {"name": "main", "type": "branch"},
                    {"name": "release/*", "type": "branch"},
                ],
            },
            {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "tag"}],
            },
        ):
            with self.subTest(branches=branches):
                with self.assertRaises(CHECKER.ContractError):
                    self.check(branches=copy.deepcopy(branches))


if __name__ == "__main__":
    unittest.main()
