#!/usr/bin/env python3
"""Apply the exact sandbox recovery-role session-control Query grant."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from typing import Any


SCHEMA = "layerv.durable-aop-session-control-query-iam-intent.v1"
RECEIPT_SCHEMA = "layerv.durable-aop-session-control-query-iam-receipt.v1"
REGION = "us-east-2"
ACCOUNT_ID = "767397897469"
POLICY_NAME = "nhp-sandbox-github-actions-terraform-apply-data"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/{POLICY_NAME}"
POLICY_ID = "ANPA3FLD2UT62EB536PKL"
POLICY_PATH = "/"
POLICY_DESCRIPTION = "Data services permissions for Terraform apply (sandbox)"
ROLE_NAME = "nhp-sandbox-github-actions"
ROLE_ID = "AROA3FLD2UT6QBE2U53EL"
TABLE_ARN = (
    "arn:aws:dynamodb:us-east-2:767397897469:table/"
    "layerv-nhp-sandbox-cell0-nhp-session-control"
)
QUERY_ACTION = "dynamodb:Query"
LEADING_KEYS = [
    "AC#c1f4c688a88e7309e89533f7e95343901da66587f3bb03f98539a16fccf33be2",
    "TARGET#2b6e9d783ef49c0df152d3a640d63b8846bb056b6ed1672fb27829ac340b85b1",
    "TARGET#71844969e300ec3c25da593e211196c45a03736a57c3850a3bcfab30d5c005f1",
    "TARGET#a8d6468608a3380b602b53c11365972843f0a4ecde6fd44e9aae6a97509e313b",
    "TARGETWORK#2e858d866b8756b13117959015df2228a2f9582e24152035b5962b0142aa0420",
    "TARGETWORK#316b00aa5b86de97fd481b7af9cb1ef1a6a432aba90a9c768c26b4bcd4ea4665",
    "TARGETWORK#76dc3461739e82e34f454d811b88ac0e90e0bf4e2bdcf77b5f160b018975ac92",
]
STATEMENT_SID = "DynamoDBSessionControlRecoveryQuery"
BEFORE_DEFAULT_VERSION = "v21"
DESIRED_DEFAULT_VERSION = "v22"
PRUNE_VERSION = "v17"
BEFORE_VERSIONS = ["v17", "v18", "v19", "v20", "v21"]
AFTER_PRUNE_VERSIONS = ["v18", "v19", "v20", "v21"]
FINAL_VERSIONS = ["v18", "v19", "v20", "v21", "v22"]
BEFORE_POLICY_SHA256 = (
    "de72b914f4019aa10587414dd759bb4b46e2dcd1843d3183b913547c17129433"
)
DESIRED_POLICY_SHA256 = (
    "161dc3acd79e1f63accca5df94da0c4deeebebe1271b202f648fcb853ba1f9ce"
)
MAX_AWS_STDOUT = 1024 * 1024
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}$")

EXPECTED_TAGS = {
    "Environment": "sandbox",
    "ManagedBy": "terraform",
    "Project": "LayerV-NHP",
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
            "managed policy is not attached only to the exact sandbox recovery role"
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


def recovery_query_statement() -> dict[str, Any]:
    return {
        "Sid": STATEMENT_SID,
        "Effect": "Allow",
        "Action": [QUERY_ACTION],
        "Resource": [TABLE_ARN],
        "Condition": {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": LEADING_KEYS},
            "StringEquals": {
                "aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}"
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        },
    }


def desired_document(before: dict[str, Any]) -> dict[str, Any]:
    if digest(before) != BEFORE_POLICY_SHA256:
        raise RecoveryError(
            "current managed-policy document is not the pinned v21 authority"
        )
    if (
        not exact_keys(before, {"Statement", "Version"})
        or before["Version"] != "2012-10-17"
    ):
        raise RecoveryError("current managed-policy document is malformed")
    statements = before["Statement"]
    if not isinstance(statements, list):
        raise RecoveryError("current managed-policy statements are malformed")
    table_indexes = [
        index
        for index, statement in enumerate(statements)
        if isinstance(statement, dict)
        and statement.get("Sid") == "DynamoDBTables"
    ]
    if (
        len(table_indexes) != 1
        or table_indexes[0] != 0
        or any(
            isinstance(statement, dict) and statement.get("Sid") == STATEMENT_SID
            for statement in statements
        )
    ):
        raise RecoveryError("current managed-policy statement boundary drifted")
    # Match Terraform's concat order exactly so the next ordinary plan is a
    # no-op, not merely an IAM-semantically equivalent reordered document.
    index = table_indexes[0] + 1
    result = {
        "Version": before["Version"],
        "Statement": [
            *statements[:index],
            recovery_query_statement(),
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
        "action": QUERY_ACTION,
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
        "action": QUERY_ACTION,
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
        and recovery_query_statement() in document.get("Statement", [])
    ):
        return "ready", document
    raise RecoveryError("managed-policy authority is not an exact incident boundary")


def plan() -> dict[str, Any]:
    state, _ = classify()
    if state != "before":
        raise RecoveryError("IAM plan requires the exact live v21 five-version boundary")
    return intent()


def verify() -> dict[str, Any]:
    state, _ = classify()
    if state != "ready":
        raise RecoveryError("session-control recovery Query IAM authority is not ready")
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
