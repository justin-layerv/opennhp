#!/usr/bin/env python3
"""Apply the exact sandbox session-control terminal-close IAM incident grant."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from typing import Any


SCHEMA = "layerv.durable-aop-session-control-delete-iam-intent.v1"
RECEIPT_SCHEMA = "layerv.durable-aop-session-control-delete-iam-receipt.v1"
REGION = "us-east-2"
ACCOUNT_ID = "767397897469"
POLICY_NAME = "layerv-nhp-sandbox-dynamodb-read"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/{POLICY_NAME}"
POLICY_ID = "ANPA3FLD2UT65P2XBQDPY"
POLICY_PATH = "/"
POLICY_DESCRIPTION = (
    "Read access to NHP DynamoDB tables, plus write access to ac-assignments "
    "for server auto-assignment"
)
ROLE_NAME = "layerv-nhp-sandbox-server"
ROLE_ID = "AROA3FLD2UT64E3ZXY7UH"
TABLE_ARN = (
    "arn:aws:dynamodb:us-east-2:767397897469:table/"
    "layerv-nhp-sandbox-cell0-nhp-session-control"
)
DELETE_ACTION = "dynamodb:DeleteItem"
ENCLOSING_OPERATION = "TransactWriteItems"
LEADING_KEYS = [
    "ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153",
    "EVENT#*",
]
STATEMENT_SID = "DynamoDBSessionControlTerminalCloseDelete"
BEFORE_DEFAULT_VERSION = "v8"
DESIRED_DEFAULT_VERSION = "v9"
PRUNE_VERSION = "v4"
BEFORE_VERSIONS = ["v4", "v5", "v6", "v7", "v8"]
AFTER_PRUNE_VERSIONS = ["v5", "v6", "v7", "v8"]
FINAL_VERSIONS = ["v5", "v6", "v7", "v8", "v9"]
BEFORE_POLICY_SHA256 = (
    "5c7a320579ae3651861e16014816358eca255e42159e6bcfbe9ea181a29c4073"
)
DESIRED_POLICY_SHA256 = (
    "c08cde9b65bb0e088ae7534c28f4f7a751ff6888f432bbc451949615b941b4c1"
)
MAX_AWS_STDOUT = 1024 * 1024
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}$")

EXPECTED_TAGS = {
    "Application": "nhp",
    "CostCenter": "infrastructure",
    "Environment": "sandbox",
    "ManagedBy": "terraform",
    "Organization": "LayerV",
    "Owner": "platform-team",
    "Project": "NHP",
    "Repository": "layervai/nhp",
    "Service": "shared",
}


class RecoveryError(RuntimeError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def parse_aws_json(raw: str, label: str) -> Any:
    encoded = raw.encode()
    if not encoded or len(encoded) > MAX_AWS_STDOUT:
        raise RecoveryError(f"{label} output is empty or exceeds its bound")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RecoveryError(f"{label} output is not one JSON value") from exc


def aws(args: list[str], *, mutation: bool = False) -> tuple[int, str, str]:
    command = [
        "aws",
        "iam",
        *args,
        "--region",
        REGION,
        "--no-cli-pager",
        "--output",
        "json",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if not mutation and result.returncode != 0:
        raise RecoveryError(
            f"AWS read failed: {' '.join(command[2:])}: {result.stderr.strip()}"
        )
    return result.returncode, result.stdout, result.stderr


def read_policy() -> dict[str, Any]:
    _, raw, _ = aws(["get-policy", "--policy-arn", POLICY_ARN])
    value = parse_aws_json(raw, "get-policy")
    if not exact_keys(value, {"Policy"}):
        raise RecoveryError("managed-policy response is not closed")
    policy = value["Policy"]
    expected_keys = {
        "Arn",
        "AttachmentCount",
        "CreateDate",
        "DefaultVersionId",
        "Description",
        "IsAttachable",
        "Path",
        "PermissionsBoundaryUsageCount",
        "PolicyId",
        "PolicyName",
        "Tags",
        "UpdateDate",
    }
    if not exact_keys(policy, expected_keys):
        raise RecoveryError("managed-policy metadata response is not closed")
    tags = policy["Tags"]
    if (
        policy["PolicyName"] != POLICY_NAME
        or policy["PolicyId"] != POLICY_ID
        or policy["Arn"] != POLICY_ARN
        or policy["Path"] != POLICY_PATH
        or policy["Description"] != POLICY_DESCRIPTION
        or policy["AttachmentCount"] != 1
        or policy["PermissionsBoundaryUsageCount"] != 0
        or policy["IsAttachable"] is not True
        or not isinstance(policy["DefaultVersionId"], str)
        or not isinstance(policy["CreateDate"], str)
        or not DATE_RE.fullmatch(policy["CreateDate"])
        or not isinstance(policy["UpdateDate"], str)
        or not DATE_RE.fullmatch(policy["UpdateDate"])
        or not isinstance(tags, list)
        or any(not exact_keys(tag, {"Key", "Value"}) for tag in tags)
        or {tag["Key"]: tag["Value"] for tag in tags} != EXPECTED_TAGS
        or len(tags) != len(EXPECTED_TAGS)
    ):
        raise RecoveryError(
            "managed-policy metadata differs from the exact sandbox authority"
        )
    return policy


def read_entities() -> None:
    _, raw, _ = aws(["list-entities-for-policy", "--policy-arn", POLICY_ARN])
    value = parse_aws_json(raw, "list-entities-for-policy")
    if not exact_keys(value, {"PolicyGroups", "PolicyRoles", "PolicyUsers"}):
        raise RecoveryError("managed-policy attachment response is not closed")
    if (
        value["PolicyGroups"] != []
        or value["PolicyUsers"] != []
        or value["PolicyRoles"] != [{"RoleName": ROLE_NAME, "RoleId": ROLE_ID}]
    ):
        raise RecoveryError(
            "managed policy is not attached only to the exact sandbox server role"
        )


def read_versions() -> tuple[list[str], str]:
    _, raw, _ = aws(["list-policy-versions", "--policy-arn", POLICY_ARN])
    value = parse_aws_json(raw, "list-policy-versions")
    if not exact_keys(value, {"Versions"}) or not isinstance(value["Versions"], list):
        raise RecoveryError("managed-policy version response is not closed")
    versions: list[str] = []
    defaults: list[str] = []
    for version in value["Versions"]:
        if (
            not exact_keys(version, {"CreateDate", "IsDefaultVersion", "VersionId"})
            or not isinstance(version["VersionId"], str)
            or not re.fullmatch(r"v[1-9][0-9]*", version["VersionId"])
            or not isinstance(version["IsDefaultVersion"], bool)
            or not isinstance(version["CreateDate"], str)
            or not DATE_RE.fullmatch(version["CreateDate"])
        ):
            raise RecoveryError("managed-policy version row is malformed")
        versions.append(version["VersionId"])
        if version["IsDefaultVersion"]:
            defaults.append(version["VersionId"])
    if len(versions) != len(set(versions)) or len(defaults) != 1:
        raise RecoveryError("managed-policy version inventory is ambiguous")
    return sorted(versions, key=lambda item: int(item[1:])), defaults[0]


def read_document(version_id: str) -> dict[str, Any]:
    _, raw, _ = aws(
        ["get-policy-version", "--policy-arn", POLICY_ARN, "--version-id", version_id]
    )
    value = parse_aws_json(raw, "get-policy-version")
    if not exact_keys(value, {"PolicyVersion"}):
        raise RecoveryError("managed-policy document response is not closed")
    version = value["PolicyVersion"]
    if (
        not exact_keys(
            version, {"CreateDate", "Document", "IsDefaultVersion", "VersionId"}
        )
        or version["VersionId"] != version_id
        or not isinstance(version["IsDefaultVersion"], bool)
        or not isinstance(version["CreateDate"], str)
        or not DATE_RE.fullmatch(version["CreateDate"])
        or not isinstance(version["Document"], dict)
    ):
        raise RecoveryError("managed-policy document authority is malformed")
    return version


def terminal_delete_statement() -> dict[str, Any]:
    return {
        "Sid": STATEMENT_SID,
        "Effect": "Allow",
        "Action": [DELETE_ACTION],
        "Resource": [TABLE_ARN],
        "Condition": {
            "ForAllValues:StringLike": {"dynamodb:LeadingKeys": LEADING_KEYS},
            "ForAnyValue:StringEquals": {
                "dynamodb:EnclosingOperation": [ENCLOSING_OPERATION]
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        },
    }


def desired_document(before: dict[str, Any]) -> dict[str, Any]:
    if digest(before) != BEFORE_POLICY_SHA256:
        raise RecoveryError(
            "current managed-policy document is not the pinned v8 authority"
        )
    if (
        not exact_keys(before, {"Statement", "Version"})
        or before["Version"] != "2012-10-17"
    ):
        raise RecoveryError("current managed-policy document is malformed")
    statements = before["Statement"]
    if not isinstance(statements, list):
        raise RecoveryError("current managed-policy statements are malformed")
    authority_indexes = [
        index
        for index, statement in enumerate(statements)
        if isinstance(statement, dict)
        and statement.get("Sid") == "DynamoDBSessionControlAuthority"
    ]
    due_index_indexes = [
        index
        for index, statement in enumerate(statements)
        if isinstance(statement, dict)
        and statement.get("Sid") == "DynamoDBSessionControlDueIndex"
    ]
    if (
        len(authority_indexes) != 1
        or len(due_index_indexes) != 1
        or due_index_indexes[0] != authority_indexes[0] + 1
        or any(
            isinstance(statement, dict) and statement.get("Sid") == STATEMENT_SID
            for statement in statements
        )
    ):
        raise RecoveryError("current managed-policy statement boundary drifted")
    # Match Terraform's concat order exactly so the next ordinary plan is a
    # no-op, not merely an IAM-semantically equivalent reordered document.
    index = due_index_indexes[0] + 1
    result = {
        "Version": before["Version"],
        "Statement": [
            *statements[:index],
            terminal_delete_statement(),
            *statements[index:],
        ],
    }
    if digest(result) != DESIRED_POLICY_SHA256:
        raise RecoveryError(
            "derived managed-policy document differs from the reviewed Terraform policy"
        )
    return result


def intent() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "policy_arn": POLICY_ARN,
        "policy_id": POLICY_ID,
        "policy_name": POLICY_NAME,
        "policy_path": POLICY_PATH,
        "attached_role": ROLE_NAME,
        "attached_role_id": ROLE_ID,
        "table_arn": TABLE_ARN,
        "action": DELETE_ACTION,
        "enclosing_operation": ENCLOSING_OPERATION,
        "leading_keys": LEADING_KEYS,
        "before_default_version": BEFORE_DEFAULT_VERSION,
        "before_versions": BEFORE_VERSIONS,
        "before_policy_sha256": BEFORE_POLICY_SHA256,
        "prune_version": PRUNE_VERSION,
        "desired_default_version": DESIRED_DEFAULT_VERSION,
        "desired_versions": FINAL_VERSIONS,
        "desired_policy_sha256": DESIRED_POLICY_SHA256,
    }


def validate_intent(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RecoveryError("IAM intent is not one JSON value") from exc
    expected = intent()
    if value != expected or canonical(value) != raw:
        raise RecoveryError(
            "IAM intent differs from the exact reviewed sandbox authority"
        )
    return value


def receipt() -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "policy_arn": POLICY_ARN,
        "policy_id": POLICY_ID,
        "attached_role": ROLE_NAME,
        "attached_role_id": ROLE_ID,
        "table_arn": TABLE_ARN,
        "action": DELETE_ACTION,
        "enclosing_operation": ENCLOSING_OPERATION,
        "leading_keys": LEADING_KEYS,
        "default_version": DESIRED_DEFAULT_VERSION,
        "versions": FINAL_VERSIONS,
        "policy_sha256": DESIRED_POLICY_SHA256,
    }


def classify() -> tuple[str, dict[str, Any] | None]:
    policy = read_policy()
    read_entities()
    versions, default = read_versions()
    if policy["DefaultVersionId"] != default:
        raise RecoveryError("managed-policy metadata and version inventory disagree")
    version = read_document(default)
    if version["IsDefaultVersion"] is not True:
        raise RecoveryError("managed-policy default document is not marked default")
    document = version["Document"]
    if default == BEFORE_DEFAULT_VERSION and digest(document) == BEFORE_POLICY_SHA256:
        desired_document(document)
        if versions == BEFORE_VERSIONS:
            return "before", document
        if versions == AFTER_PRUNE_VERSIONS:
            return "pruned", document
    if (
        default == DESIRED_DEFAULT_VERSION
        and versions == FINAL_VERSIONS
        and digest(document) == DESIRED_POLICY_SHA256
        and terminal_delete_statement() in document.get("Statement", [])
    ):
        return "ready", document
    raise RecoveryError("managed-policy authority is not an exact incident boundary")


def plan() -> dict[str, Any]:
    state, _ = classify()
    if state != "before":
        raise RecoveryError("IAM plan requires the exact live v8 five-version boundary")
    return intent()


def verify() -> dict[str, Any]:
    state, _ = classify()
    if state != "ready":
        raise RecoveryError("terminal-close IAM authority is not ready")
    return receipt()


def apply_exact() -> dict[str, Any]:
    state, document = classify()
    if state == "ready":
        return receipt()
    if state == "before":
        returncode, _, stderr = aws(
            [
                "delete-policy-version",
                "--policy-arn",
                POLICY_ARN,
                "--version-id",
                PRUNE_VERSION,
            ],
            mutation=True,
        )
        next_state, document = classify()
        if next_state != "pruned":
            raise RecoveryError(
                "delete-policy-version did not reach the exact pruned boundary: "
                + (stderr.strip() if returncode else "unexpected authority")
            )
        state = next_state
    if state != "pruned" or document is None:
        raise RecoveryError(
            "managed-policy recovery did not reach its exact create boundary"
        )
    desired = desired_document(document)
    returncode, stdout, stderr = aws(
        [
            "create-policy-version",
            "--policy-arn",
            POLICY_ARN,
            "--policy-document",
            canonical(desired),
            "--set-as-default",
        ],
        mutation=True,
    )
    if returncode == 0:
        response = parse_aws_json(stdout, "create-policy-version")
        if (
            not isinstance(response, dict)
            or not isinstance(response.get("PolicyVersion"), dict)
            or response["PolicyVersion"].get("VersionId") != DESIRED_DEFAULT_VERSION
            or response["PolicyVersion"].get("IsDefaultVersion") is not True
        ):
            raise RecoveryError("create-policy-version response is malformed")
    try:
        return verify()
    except RecoveryError as exc:
        detail = stderr.strip() if returncode else "unexpected authority"
        raise RecoveryError(
            f"create-policy-version did not reach the exact desired default: {detail}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "apply", "verify"))
    parser.add_argument("--intent-json")
    args = parser.parse_args()
    if args.mode == "plan":
        if args.intent_json is not None:
            raise RecoveryError("plan does not accept caller IAM authority")
        value = plan()
    else:
        if args.intent_json is None:
            raise RecoveryError(f"{args.mode} requires the exact durable IAM intent")
        validate_intent(args.intent_json)
        value = apply_exact() if args.mode == "apply" else verify()
    print(canonical(value))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
