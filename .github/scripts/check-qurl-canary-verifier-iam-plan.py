#!/usr/bin/env python3
"""Fail closed unless a plan adds only the exact canary-verifier Scan grant."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


POLICY_ADDRESS = "module.nhp.module.ecr.aws_iam_role_policy.qurl_agent_key_inventory"
ROLE_NAME = "nhp-sandbox-github-actions"
POLICY_NAME = "qurl-agent-key-inventory"
TERRAFORM_VERSION = "1.14.3"
AGENT_API_RESOURCES = [
    "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-*-qurl-api-keys",
    "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-*-qurl-agent-keys",
]
AUTHORITY_RESOURCE = (
    "arn:aws:dynamodb:us-east-2:767397897469:table/"
    "layerv-nhp-sandbox-control-connector-authority"
)
INVENTORY_STATEMENT = {
    "Sid": "DynamoDBQurlAgentKeyInventoryGate",
    "Effect": "Allow",
    "Action": ["dynamodb:Scan"],
    "Resource": AGENT_API_RESOURCES,
}
VERIFIER_STATEMENT = {
    "Sid": "DynamoDBQurlCanaryBindingVerifier",
    "Effect": "Allow",
    "Action": ["dynamodb:Scan"],
    "Resource": [AUTHORITY_RESOURCE],
}
EXPECTED_BEFORE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [INVENTORY_STATEMENT],
}
EXPECTED_AFTER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [INVENTORY_STATEMENT, VERIFIER_STATEMENT],
}


class ContractError(ValueError):
    """The plan is not the exact reviewed read-only policy update."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _decode_document(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, str), f"{label} must be a JSON string")
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{label} is not valid JSON") from exc
    _require(isinstance(document, dict), f"{label} must decode to an object")
    return document


def _has_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unknown(item) for item in value)
    return False


def check_plan(plan: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(plan, dict), "plan root must be an object")
    _require(plan.get("errored") is not True, "Terraform marked the plan errored")
    _require(plan.get("format_version") == "1.2", "plan format must be exact 1.2")
    _require(
        plan.get("terraform_version") == TERRAFORM_VERSION,
        f"Terraform plan must use exact {TERRAFORM_VERSION}",
    )
    changes = plan.get("resource_changes")
    _require(isinstance(changes, list), "resource_changes must be a list")
    material = []
    target = []
    for item in changes:
        _require(isinstance(item, dict), "resource change must be an object")
        change = item.get("change")
        _require(isinstance(change, dict), "change must be an object")
        if item.get("address") == POLICY_ADDRESS:
            target.append(item)
        if change.get("actions") != ["no-op"]:
            material.append(item)
    _require(len(target) == 1, f"plan must contain exactly one {POLICY_ADDRESS}")
    _require(len(material) == 1, "plan must contain exactly one non-no-op change")
    policy = target[0]
    _require(policy is material[0], f"only {POLICY_ADDRESS} may change")
    _require(policy.get("mode") == "managed", "policy must be managed")
    _require(policy.get("type") == "aws_iam_role_policy", "policy type drifted")
    _require(policy.get("name") == "qurl_agent_key_inventory", "policy name drifted")
    _require(
        policy.get("module_address") == "module.nhp.module.ecr",
        "policy module address drifted",
    )
    _require(
        policy.get("provider_name") == "registry.terraform.io/hashicorp/aws",
        "policy provider drifted",
    )
    change = policy["change"]
    _require(change.get("actions") == ["update"], "policy must update in place")
    _require(change.get("replace_paths") in (None, []), "policy must not replace")
    _require(
        not _has_unknown(change.get("after_unknown", {})),
        "policy after value must be fully known",
    )
    _require(
        change.get("before_sensitive", {}) == change.get("after_sensitive", {}),
        "policy sensitivity metadata changed",
    )
    before = change.get("before")
    after = change.get("after")
    _require(
        isinstance(before, dict) and isinstance(after, dict),
        "policy before and after values must be objects",
    )
    before_other = dict(before)
    after_other = dict(after)
    before_document = _decode_document(before_other.pop("policy", None), "before policy")
    after_document = _decode_document(after_other.pop("policy", None), "after policy")
    _require(before_other == after_other, "a policy attribute other than document changed")
    _require(
        after.get("name") == POLICY_NAME
        and after.get("role") == ROLE_NAME
        and after.get("id") == f"{ROLE_NAME}:{POLICY_NAME}",
        "policy identity drifted",
    )
    _require(before_document == EXPECTED_BEFORE_POLICY, "before policy drifted")
    _require(after_document == EXPECTED_AFTER_POLICY, "after policy is not exact")
    _require(plan.get("resource_drift", []) == [], "plan contains resource drift")
    _require(plan.get("deferred_changes", []) == [], "plan contains deferred changes")
    outputs = plan.get("output_changes", {})
    _require(isinstance(outputs, dict), "output_changes must be an object")
    for name, output in outputs.items():
        _require(
            isinstance(output, dict) and output.get("actions") == ["no-op"],
            f"output {name} must be a no-op",
        )
    return {
        "target": POLICY_ADDRESS,
        "actions": ["update"],
        "added_action": "dynamodb:Scan",
        "added_resource": AUTHORITY_RESOURCE,
        "resource_change_count": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
        summary = check_plan(plan)
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"qURL canary-verifier IAM plan rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
