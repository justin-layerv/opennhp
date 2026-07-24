#!/usr/bin/env python3
"""Fail-closed contract for the one-time sandbox terraform_read recovery plan."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

TARGET_ADDRESS = "module.nhp.module.ecr.aws_iam_policy.terraform_read"
TARGET_TYPE = "aws_iam_policy"
TARGET_NAME = "terraform_read"
TARGET_POLICY_ARN = (
    "arn:aws:iam::767397897469:"
    "policy/nhp-sandbox-github-actions-terraform-read"
)
TARGET_POLICY_NAME = "nhp-sandbox-github-actions-terraform-read"
POLICY_VERSION_RE = re.compile(r"v([1-9][0-9]*)")
RELAY_STATUS_ARN = (
    "arn:aws:lambda:us-east-2:767397897469:"
    "function:layerv-nhp-sandbox-relay-status:$LATEST"
)
EXPECTED_STATEMENT = {
    "Sid": "RelayIdentityStatusInvoke",
    "Effect": "Allow",
    "Action": ["lambda:InvokeFunction"],
    "Resource": [RELAY_STATUS_ARN],
}


class ContractError(ValueError):
    """The plan is not the exact reviewed recovery."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _decode_policy(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, str), f"{label} policy must be a JSON string")
    try:
        policy = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{label} policy is not valid JSON") from exc
    return _validate_policy_object(policy, label)


def _validate_policy_object(policy: Any, label: str) -> dict[str, Any]:
    _require(isinstance(policy, dict), f"{label} policy must decode to an object")
    # This one-shot deliberately rejects even otherwise valid top-level IAM
    # policy fields: the recovery is reviewed against this exact document shape.
    _require(
        set(policy) == {"Version", "Statement"},
        f"{label} policy must contain only Version and Statement",
    )
    _require(
        policy["Version"] == "2012-10-17",
        f"{label} policy version is not 2012-10-17",
    )
    _require(
        isinstance(policy["Statement"], list),
        f"{label} policy Statement must be a list",
    )
    return policy


def _has_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unknown(item) for item in value)
    return False


def _select_target_change(plan: dict[str, Any]) -> dict[str, Any]:
    """Return the single non-no-op resource change; fail closed otherwise."""
    resource_changes = plan.get("resource_changes")
    _require(isinstance(resource_changes, list), "resource_changes must be a list")
    for item in resource_changes:
        _require(isinstance(item, dict), "resource change must be an object")
        _require(
            isinstance(item.get("change"), dict),
            "resource change must contain a change object",
        )
    changes = [
        item for item in resource_changes if item["change"].get("actions") != ["no-op"]
    ]
    _require(len(changes) == 1, "plan must contain exactly one non-no-op change")
    return changes[0]


def check_plan(plan: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(plan, dict), "plan root must be an object")
    _require(plan.get("errored") is not True, "Terraform marked the plan errored")

    resource = _select_target_change(plan)
    _require(
        resource.get("address") == TARGET_ADDRESS,
        f"only {TARGET_ADDRESS} may change",
    )
    _require(resource.get("mode") == "managed", "target must be managed")
    _require(resource.get("type") == TARGET_TYPE, "target type drifted")
    _require(resource.get("name") == TARGET_NAME, "target name drifted")
    _require(
        resource.get("provider_name") == "registry.terraform.io/hashicorp/aws",
        "target provider drifted",
    )
    _require(
        resource.get("module_address") == "module.nhp.module.ecr",
        "target module address drifted",
    )

    change = resource.get("change")
    _require(isinstance(change, dict), "target change must be an object")
    _require(change.get("actions") == ["update"], "target must update in place")
    _require(
        change.get("replace_paths") in (None, []),
        "target must not contain replacement paths",
    )
    _require(
        not _has_unknown(change.get("after_unknown", {})),
        "target after value must be fully known",
    )
    _require(
        change.get("before_sensitive", {}) == change.get("after_sensitive", {}),
        "target sensitivity metadata changed",
    )

    before = change.get("before")
    after = change.get("after")
    _require(
        isinstance(before, dict) and isinstance(after, dict),
        "target before and after values must be objects",
    )
    _require(
        before.get("arn") == TARGET_POLICY_ARN
        and before.get("id") == TARGET_POLICY_ARN
        and before.get("name") == TARGET_POLICY_NAME
        and before.get("path") == "/",
        "target policy identity does not match the sandbox terraform_read policy",
    )
    _require(
        isinstance(before.get("policy_id"), str) and bool(before["policy_id"]),
        "target policy_id must be a nonempty string",
    )
    before_without_policy = dict(before)
    after_without_policy = dict(after)
    before_policy_raw = before_without_policy.pop("policy", None)
    after_policy_raw = after_without_policy.pop("policy", None)
    _require(
        before_without_policy == after_without_policy,
        "an aws_iam_policy attribute other than policy changed",
    )

    before_policy = _decode_policy(before_policy_raw, "before")
    after_policy = _decode_policy(after_policy_raw, "after")
    _require(
        before_policy["Version"] == after_policy["Version"],
        "policy Version changed",
    )
    _require(
        EXPECTED_STATEMENT not in before_policy["Statement"],
        "qualified relay-status grant already existed before recovery",
    )
    _require(
        after_policy["Statement"].count(EXPECTED_STATEMENT) == 1,
        "after policy must contain the exact qualified relay-status statement once",
    )
    after_without_grant = list(after_policy["Statement"])
    after_without_grant.remove(EXPECTED_STATEMENT)
    _require(
        after_without_grant == before_policy["Statement"],
        "policy delta must add only the exact qualified relay-status statement",
    )

    output_changes = plan.get("output_changes", {})
    _require(isinstance(output_changes, dict), "output_changes must be an object")
    for name, output_change in output_changes.items():
        _require(
            isinstance(output_change, dict)
            and output_change.get("actions") == ["no-op"],
            f"output {name} must be a no-op",
        )

    _require(
        plan.get("resource_drift", []) == [],
        "recovery plan must not contain resource drift",
    )
    _require(
        plan.get("deferred_changes", []) == [],
        "recovery plan must not contain deferred changes",
    )

    return {
        "target": TARGET_ADDRESS,
        "actions": ["update"],
        "added_statement": EXPECTED_STATEMENT,
        "resource_change_count": 1,
    }


def _live_default_version(
    metadata: dict[str, Any],
    expected_policy_id: str,
    label: str,
) -> str:
    policy = metadata.get("Policy")
    _require(isinstance(policy, dict), f"{label} metadata must contain Policy")
    _require(
        policy.get("Arn") == TARGET_POLICY_ARN
        and policy.get("PolicyName") == TARGET_POLICY_NAME
        and policy.get("Path") == "/"
        and policy.get("PolicyId") == expected_policy_id
        and policy.get("IsAttachable") is True,
        f"{label} metadata identity does not match the target policy",
    )
    version_id = policy.get("DefaultVersionId")
    _require(
        isinstance(version_id, str)
        and POLICY_VERSION_RE.fullmatch(version_id) is not None,
        f"{label} default version id is invalid",
    )
    return version_id


def _live_policy_document(
    version: dict[str, Any],
    expected_version_id: str,
    label: str,
) -> dict[str, Any]:
    policy_version = version.get("PolicyVersion")
    _require(
        isinstance(policy_version, dict),
        f"{label} version must contain PolicyVersion",
    )
    _require(
        policy_version.get("VersionId") == expected_version_id,
        f"{label} document version does not match metadata",
    )
    _require(
        policy_version.get("IsDefaultVersion") is True,
        f"{label} document is not the default policy version",
    )
    return _validate_policy_object(policy_version.get("Document"), f"{label} live")


def _version_number(version_id: str, label: str) -> int:
    match = POLICY_VERSION_RE.fullmatch(version_id)
    _require(match is not None, f"{label} version id is invalid")
    return int(match.group(1))


def check_live_policy(
    plan: dict[str, Any],
    *,
    phase: str,
    metadata: dict[str, Any],
    version: dict[str, Any],
    confirmed_metadata: dict[str, Any],
    previous_default_version: str | None = None,
) -> dict[str, Any]:
    check_plan(plan)
    _require(phase in {"before", "after"}, "live policy phase must be before or after")
    resource = _select_target_change(plan)
    change = resource["change"]
    planned = change[phase]
    expected_policy = _decode_policy(planned["policy"], f"planned {phase}")
    expected_policy_id = planned["policy_id"]

    default_version = _live_default_version(
        metadata,
        expected_policy_id,
        f"{phase} initial",
    )
    confirmed_default_version = _live_default_version(
        confirmed_metadata,
        expected_policy_id,
        f"{phase} confirmation",
    )
    _require(
        confirmed_default_version == default_version,
        f"{phase} default policy version changed during live readback",
    )
    live_policy = _live_policy_document(version, default_version, phase)
    _require(
        live_policy == expected_policy,
        f"live default policy does not equal the planned {phase} policy",
    )

    if phase == "before":
        _require(
            previous_default_version is None,
            "before phase cannot receive a previous default version",
        )
    else:
        _require(
            previous_default_version is not None,
            "after phase requires the before default version",
        )
        _require(
            _version_number(default_version, "after")
            > _version_number(previous_default_version, "before"),
            "after default policy version did not advance",
        )

    return {
        "target": TARGET_ADDRESS,
        "phase": phase,
        "live_default_version_matches": True,
        "live_policy_matches": True,
    }


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"{label} is not valid JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument("--live-phase", choices=("before", "after"))
    parser.add_argument("--policy-metadata-json", type=Path)
    parser.add_argument("--policy-version-json", type=Path)
    parser.add_argument("--confirmed-policy-metadata-json", type=Path)
    parser.add_argument("--previous-default-version")
    args = parser.parse_args(argv)
    try:
        plan = _load_object(args.plan_json, "plan")
        live_paths = (
            args.policy_metadata_json,
            args.policy_version_json,
            args.confirmed_policy_metadata_json,
        )
        if args.live_phase is None:
            _require(
                all(path is None for path in live_paths)
                and args.previous_default_version is None,
                "live policy arguments require --live-phase",
            )
            summary = check_plan(plan)
        else:
            _require(
                all(path is not None for path in live_paths),
                "live policy phase requires metadata, version, and confirmation JSON",
            )
            summary = check_live_policy(
                plan,
                phase=args.live_phase,
                metadata=_load_object(
                    args.policy_metadata_json,
                    "policy metadata",
                ),
                version=_load_object(
                    args.policy_version_json,
                    "policy version",
                ),
                confirmed_metadata=_load_object(
                    args.confirmed_policy_metadata_json,
                    "confirmed policy metadata",
                ),
                previous_default_version=args.previous_default_version,
            )
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
