#!/usr/bin/env python3
"""Fail closed unless a Hub publication Environment has the exact live policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REPOSITORY = "layervai/nhp"
REVIEWER_ID = 178750268
ENVIRONMENTS = {
    "sandbox": "hub-publish-sandbox",
    "production": "hub-publish-production",
}
SHARED_ENVIRONMENTS = frozenset({"sandbox", "production"})


class ContractError(ValueError):
    """The live GitHub Environment does not match the publication contract."""


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"{label}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"{label}: expected a JSON object")
    return value


def check_environment(
    *,
    repository: str,
    target_environment: str,
    publication_environment: str,
    environment: dict[str, Any],
    branch_policies: dict[str, Any],
) -> dict[str, Any]:
    if repository != REPOSITORY:
        raise ContractError(f"repository must be {REPOSITORY}")
    expected_environment = ENVIRONMENTS.get(target_environment)
    if expected_environment is None:
        raise ContractError("target environment must be sandbox or production")
    if publication_environment in SHARED_ENVIRONMENTS:
        raise ContractError("shared deployment Environments cannot publish Hub images")
    if publication_environment != expected_environment:
        raise ContractError(
            f"publication environment must be {expected_environment} for {target_environment}"
        )
    if environment.get("name") != expected_environment:
        raise ContractError("live Environment name does not match the selected target")

    rules = environment.get("protection_rules")
    if not isinstance(rules, list) or len(rules) != 2:
        raise ContractError("Environment must have exactly two protection rules")
    by_type: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            raise ContractError("Environment protection rule is malformed")
        rule_type = rule["type"]
        if rule_type in by_type:
            raise ContractError(f"duplicate Environment protection rule: {rule_type}")
        by_type[rule_type] = rule
    if set(by_type) != {"branch_policy", "required_reviewers"}:
        raise ContractError("Environment has an unapproved protection rule")

    reviewer_rule = by_type["required_reviewers"]
    # This is deliberately a single-operator approval/audit checkpoint, not a
    # two-person or malicious-repository-admin boundary. The accepted
    # can_admins_bypass/prevent_self_review policy and its threat model are
    # documented in terraform/control/README.md. Do not pin those booleans
    # here: either may be tightened independently without widening access.
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1:
        raise ContractError("Environment must have exactly one required reviewer")
    reviewer = reviewers[0]
    if (
        not isinstance(reviewer, dict)
        or reviewer.get("type") != "User"
        or not isinstance(reviewer.get("reviewer"), dict)
        or reviewer["reviewer"].get("id") != REVIEWER_ID
    ):
        raise ContractError(f"required reviewer must be user id {REVIEWER_ID}")

    deployment_policy = environment.get("deployment_branch_policy")
    if deployment_policy != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        raise ContractError(
            "Environment must use only custom deployment branch policies"
        )

    if (
        type(branch_policies.get("total_count")) is not int
        or branch_policies["total_count"] != 1
    ):
        raise ContractError(
            "Environment must have exactly one deployment branch policy"
        )
    policies = branch_policies.get("branch_policies")
    if not isinstance(policies, list) or len(policies) != 1:
        raise ContractError("Environment branch-policy response is malformed")
    policy = policies[0]
    if (
        not isinstance(policy, dict)
        or policy.get("name") != "main"
        or policy.get("type") != "branch"
    ):
        raise ContractError("the sole deployment branch policy must be the main branch")

    return {
        "repository": repository,
        "target_environment": target_environment,
        "publication_environment": publication_environment,
        "required_reviewer_id": REVIEWER_ID,
        "deployment_branch": "main",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--target-environment", required=True)
    parser.add_argument("--publication-environment", required=True)
    parser.add_argument("--environment-json", type=Path, required=True)
    parser.add_argument("--branch-policies-json", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        summary = check_environment(
            repository=args.repository,
            target_environment=args.target_environment,
            publication_environment=args.publication_environment,
            environment=load_object(args.environment_json, "Environment"),
            branch_policies=load_object(args.branch_policies_json, "branch policies"),
        )
    except ContractError as error:
        raise SystemExit(
            f"Hub publication Environment check failed: {error}"
        ) from error
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
