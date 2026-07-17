#!/usr/bin/env python3
"""Fail-closed contract checks for the staged qURL agent transaction grant."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


RESOURCE_ADDRESS = "aws_iam_role_policy.qurl_agent_keys_transact"
POLICY_NAME = "qurl-agent-keys-transact-write"
ROLE_NAME = "layerv-nhp-prod-cell0-qurl-api-task"
TABLE_ARN = (
    "arn:aws:dynamodb:us-east-2:235500187906:table/"
    "layerv-nhp-prod-cell0-qurl-agent-keys"
)
# Keep this contract in lockstep with the policy in the staged root's main.tf;
# the Terraform 1.14.3 golden fixtures pin both serialized plan shapes.
EXPECTED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "QURLAgentKeysTransactWrite",
            "Effect": "Allow",
            "Action": ["dynamodb:TransactWriteItems"],
            "Resource": [TABLE_ARN],
        }
    ],
}


class ContractError(ValueError):
    """The reviewed one-resource contract was not preserved."""


def canonical_policy(document: Any) -> dict[str, Any]:
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ContractError(f"policy is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ContractError("policy document must be an object")

    normalized = copy.deepcopy(document)
    statements = normalized.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
        normalized["Statement"] = statements
    if not isinstance(statements, list):
        raise ContractError("policy Statement must be an array")

    for statement in statements:
        if not isinstance(statement, dict):
            raise ContractError("every policy statement must be an object")
        for field in ("Action", "Resource"):
            value = statement.get(field)
            if isinstance(value, str):
                statement[field] = [value]

    return normalized


def policy_sha256(document: dict[str, Any]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def check_policy(document: Any) -> str:
    normalized = canonical_policy(document)
    if normalized != EXPECTED_POLICY:
        raise ContractError(
            "policy is not the reviewed one-action, one-table singleton document"
        )
    return policy_sha256(normalized)


def check_plan(plan: Any, expected_action: str) -> str:
    if not isinstance(plan, dict):
        raise ContractError("plan JSON must be an object")
    # These top-level fields are part of the pinned Terraform 1.14.3 plan-JSON
    # contract. Fail closed if a future toolchain changes or omits them.
    if plan.get("errored") is not False or plan.get("complete") is not True:
        raise ContractError("Terraform plan completion status is absent or unsafe")

    changes = plan.get("resource_changes")
    if not isinstance(changes, list) or len(changes) != 1:
        raise ContractError("plan must contain exactly one resource change")

    change = changes[0]
    if change.get("address") != RESOURCE_ADDRESS:
        raise ContractError(f"unexpected resource address: {change.get('address')!r}")
    if change.get("mode") != "managed":
        raise ContractError(f"unexpected resource mode: {change.get('mode')!r}")

    detail = change.get("change")
    if not isinstance(detail, dict):
        raise ContractError("resource change body is missing")
    expected_actions = [expected_action]
    if detail.get("actions") != expected_actions:
        raise ContractError(
            f"expected actions {expected_actions!r}, got {detail.get('actions')!r}"
        )

    after = detail.get("after")
    if not isinstance(after, dict):
        raise ContractError("planned after value is missing")
    if after.get("name") != POLICY_NAME or after.get("role") != ROLE_NAME:
        raise ContractError("planned policy name or role escaped the reviewed scope")
    digest = check_policy(after.get("policy"))

    if expected_action == "create":
        if plan.get("applyable") is not True:
            raise ContractError("initial create plan must be applyable")
        before = detail.get("before")
        if before is not None:
            raise ContractError("initial create plan unexpectedly has prior state")
    elif expected_action == "no-op":
        if plan.get("applyable") is not False:
            raise ContractError("converged plan must not be applyable")
        if detail.get("before") != after:
            raise ContractError("converged plan before and after values must match")

    return digest


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("path", type=Path)
    plan_parser.add_argument(
        "--expected-action", choices=("create", "no-op"), required=True
    )

    policy_parser = subparsers.add_parser("policy")
    policy_parser.add_argument("path", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "plan":
            digest = check_plan(load_json(args.path), args.expected_action)
        else:
            digest = check_policy(load_json(args.path))
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"policy_sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
