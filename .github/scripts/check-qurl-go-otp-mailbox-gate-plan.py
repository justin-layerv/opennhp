#!/usr/bin/env python3
"""Fail closed unless a plan adds only qurl-go's exact main OIDC subject."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROLE_ADDRESS = "module.nhp.aws_iam_role.qurl_go_otp_mailbox_gate[0]"
POLICY_ADDRESS = "module.nhp.aws_iam_role_policy.qurl_go_otp_mailbox_gate[0]"
ROLE_NAME = "layerv-nhp-sandbox-qurl-go-otp-mailbox-gate"
ROLE_ARN = f"arn:aws:iam::767397897469:role/{ROLE_NAME}"
TERRAFORM_VERSION = "1.14.3"
PROVIDER_ARN = (
    "arn:aws:iam::767397897469:"
    "oidc-provider/token.actions.githubusercontent.com"
)
PULL_REQUEST_SUBJECT = "repo:layervai/qurl-go:pull_request"
MAIN_SUBJECT = "repo:layervai/qurl-go:ref:refs/heads/main"
QUEUE_ARN = (
    "arn:aws:sqs:us-east-2:767397897469:"
    "layerv-nhp-sandbox-agent-otp-ci-mailbox"
)
OBJECT_ARN = (
    "arn:aws:s3:::layerv-nhp-sandbox-agent-otp-ci-mailbox/otp/*"
)

EXPECTED_BEFORE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Federated": PROVIDER_ARN},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": PULL_REQUEST_SUBJECT,
                }
            },
        }
    ],
}
EXPECTED_AFTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Federated": PROVIDER_ARN},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": [
                        PULL_REQUEST_SUBJECT,
                        MAIN_SUBJECT,
                    ],
                }
            },
        }
    ],
}
EXPECTED_MAILBOX_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AgentOTPCIMailboxDrainQueue",
            "Effect": "Allow",
            "Action": [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
            ],
            "Resource": [QUEUE_ARN],
        },
        {
            "Sid": "AgentOTPCIMailboxReadMessage",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [OBJECT_ARN],
        },
    ],
}


class ContractError(ValueError):
    """The plan is not the exact reviewed trust-only update."""


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


def _resource_changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    changes = plan.get("resource_changes")
    _require(isinstance(changes, list), "resource_changes must be a list")
    for item in changes:
        _require(isinstance(item, dict), "resource change must be an object")
        _require(isinstance(item.get("change"), dict), "change must be an object")
    return changes


def _find(changes: list[dict[str, Any]], address: str) -> dict[str, Any]:
    matches = [item for item in changes if item.get("address") == address]
    _require(len(matches) == 1, f"plan must contain exactly one {address}")
    return matches[0]


def _check_identity(resource: dict[str, Any], resource_type: str, name: str) -> None:
    _require(resource.get("mode") == "managed", "resource must be managed")
    _require(resource.get("type") == resource_type, "resource type drifted")
    _require(resource.get("name") == name, "resource name drifted")
    _require(
        resource.get("module_address") == "module.nhp",
        "resource module address drifted",
    )
    _require(
        resource.get("provider_name") == "registry.terraform.io/hashicorp/aws",
        "resource provider drifted",
    )


def check_plan(plan: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(plan, dict), "plan root must be an object")
    _require(plan.get("errored") is not True, "Terraform marked the plan errored")
    _require(plan.get("format_version") == "1.2", "plan format must be exact 1.2")
    _require(
        plan.get("terraform_version") == TERRAFORM_VERSION,
        f"Terraform plan must use exact {TERRAFORM_VERSION}",
    )
    changes = _resource_changes(plan)
    material = [item for item in changes if item["change"].get("actions") != ["no-op"]]
    _require(len(material) == 1, "plan must contain exactly one non-no-op change")

    role = _find(changes, ROLE_ADDRESS)
    _require(role is material[0], f"only {ROLE_ADDRESS} may change")
    _check_identity(role, "aws_iam_role", "qurl_go_otp_mailbox_gate")
    role_change = role["change"]
    _require(role_change.get("actions") == ["update"], "role must update in place")
    _require(role_change.get("replace_paths") in (None, []), "role must not replace")
    _require(
        not _has_unknown(role_change.get("after_unknown", {})),
        "role after value must be fully known",
    )
    _require(
        role_change.get("before_sensitive", {})
        == role_change.get("after_sensitive", {}),
        "role sensitivity metadata changed",
    )
    before = role_change.get("before")
    after = role_change.get("after")
    _require(
        isinstance(before, dict) and isinstance(after, dict),
        "role before and after values must be objects",
    )
    _require(
        before.get("arn") == ROLE_ARN
        and after.get("arn") == ROLE_ARN
        and before.get("id") == ROLE_NAME
        and after.get("id") == ROLE_NAME
        and before.get("name") == ROLE_NAME
        and after.get("name") == ROLE_NAME
        and before.get("path") == "/"
        and after.get("path") == "/",
        "role identity drifted",
    )
    before_other = dict(before)
    after_other = dict(after)
    before_trust = _decode_document(
        before_other.pop("assume_role_policy", None), "before trust policy"
    )
    after_trust = _decode_document(
        after_other.pop("assume_role_policy", None), "after trust policy"
    )
    _require(before_other == after_other, "a role attribute other than trust changed")
    _require(before_trust == EXPECTED_BEFORE_TRUST, "before trust policy drifted")
    _require(after_trust == EXPECTED_AFTER_TRUST, "after trust policy is not exact")

    policy = _find(changes, POLICY_ADDRESS)
    _check_identity(policy, "aws_iam_role_policy", "qurl_go_otp_mailbox_gate")
    policy_change = policy["change"]
    _require(
        policy_change.get("actions") == ["no-op"],
        "mailbox permission policy must be a no-op",
    )
    _require(
        not _has_unknown(policy_change.get("after_unknown", {})),
        "mailbox permission policy must be fully known",
    )
    policy_before = policy_change.get("before")
    policy_after = policy_change.get("after")
    _require(
        isinstance(policy_before, dict) and isinstance(policy_after, dict),
        "permission policy before and after values must be objects",
    )
    _require(policy_before == policy_after, "mailbox permission attributes changed")
    _require(
        policy_after.get("name") == "agent-otp-ci-mailbox-read"
        and policy_after.get("role") == ROLE_NAME,
        "mailbox permission policy identity drifted",
    )
    _require(
        _decode_document(policy_after.get("policy"), "mailbox permission policy")
        == EXPECTED_MAILBOX_POLICY,
        "mailbox permission policy is not exact",
    )

    output_changes = plan.get("output_changes", {})
    _require(isinstance(output_changes, dict), "output_changes must be an object")
    for name, output_change in output_changes.items():
        _require(
            isinstance(output_change, dict)
            and output_change.get("actions") == ["no-op"],
            f"output {name} must be a no-op",
        )
    _require(plan.get("resource_drift", []) == [], "plan contains resource drift")
    _require(plan.get("deferred_changes", []) == [], "plan contains deferred changes")

    return {
        "target": ROLE_ADDRESS,
        "actions": ["update"],
        "added_subject": MAIN_SUBJECT,
        "permission_policy": "no-op",
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
        print(f"qurl-go OTP mailbox gate plan rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
