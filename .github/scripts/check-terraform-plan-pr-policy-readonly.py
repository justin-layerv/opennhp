#!/usr/bin/env python3
"""Assert the Terraform Plan PR role policy stays read-only."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _tf_lint_lib import (  # noqa: E402  # pyright: ignore[reportMissingImports]
    error,
    extract_policy_body,
    iter_resources,
    parse_tf_files,
    statement_actions,
    unquote,
)


# The verb gate only proves actions are non-mutating. Value-bearing reads must
# live in one of the scoped Sids below, where validate_sensitive_statement_scopes
# pins the exact resource/condition invariant.
READ_ACTION_RE = re.compile(r"^[a-z0-9-]+:(?:describe|get|list)[a-z0-9*]*$")
EXACT_ALLOWED_ACTIONS = {
    "kms:decrypt",
}
VALUE_BEARING_SCOPED_SIDS = {
    "KMSDecryptInAccount",
    "S3ObjectRead",
    "SecretsManagerRead",
    "SSMParameterRead",
}
VALUE_BEARING_ACTIONS = {
    "kms:decrypt",
    "s3:get*",
    "s3:getobject",
    "s3:getobject*",
    "secretsmanager:get*",
    "secretsmanager:getsecretvalue",
    "ssm:get*",
    "ssm:getparameter",
    "ssm:getparameter*",
    "ssm:getparameters",
    "ssm:getparametersbypath",
}
FORBIDDEN_ACTIONS = {
    # The PR plan role refreshes DynamoDB table metadata only. Item reads expose
    # application data and are not needed for sandbox plans with S3 locking.
    "dynamodb:getitem",
    "ec2:get*",
    "ec2:getconsoleoutput",
    "ec2:getconsolescreenshot",
    "ec2:getlaunchtemplatedata",
    "ec2:getpassworddata",
    "iam:passrole",
    "sts:assumerole",
    "sts:assumerolewithwebidentity",
}
POLICY_RESOURCE_TYPE = "aws_iam_policy"
POLICY_RESOURCE_NAME = "terraform_plan_pr_read"
SSM_PARAMETER_READ_RESOURCES = {
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/layerv/nhp/${var.environment}/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/*",
    "arn:aws:ssm:${local.region}::parameter/aws/service/canonical/ubuntu/*",
}
KMS_DECRYPT_ALIASES = {
    "alias/terraform-state",
    "alias/${var.name_prefix}-ebs",
    "alias/${var.name_prefix}-efs",
    "alias/${var.name_prefix}-secrets",
    "alias/${var.name_prefix}-logs",
    "alias/${var.name_prefix}-rds",
    "alias/${var.name_prefix}-cert",
}


def is_read_only_action(action: str) -> bool:
    normalized = action.lower()
    return normalized in EXACT_ALLOWED_ACTIONS or READ_ACTION_RE.fullmatch(normalized) is not None


def has_allow_not_action(policy: dict) -> bool:
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "Allow")
        if isinstance(effect, str) and unquote(effect).lower() == "allow" and "NotAction" in stmt:
            return True
    return False


def as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return [value]


def normalized_strings(value: object) -> list[str]:
    return [unquote(item) for item in as_list(value) if isinstance(item, str)]


def condition_values(stmt: dict, operator: str, key: str) -> list[str]:
    condition = stmt.get("Condition")
    if not isinstance(condition, dict):
        return []
    operator_body = condition.get(operator) or condition.get(f'"{operator}"')
    if not isinstance(operator_body, dict):
        return []
    raw = operator_body.get(key) or operator_body.get(f'"{key}"')
    return normalized_strings(raw)


def statements_by_sid(policy: dict) -> dict[str, dict]:
    by_sid: dict[str, dict] = {}
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        sid = stmt.get("Sid")
        if isinstance(sid, str):
            by_sid[unquote(sid)] = stmt
    return by_sid


def is_value_bearing_action(action: str) -> bool:
    return action.lower() in VALUE_BEARING_ACTIONS


def validate_sensitive_statement_scopes(file: Path, policy: dict) -> list[str]:
    statements = statements_by_sid(policy)
    violations: list[str] = []

    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        sid = unquote(stmt.get("Sid", "<missing Sid>")) if isinstance(stmt.get("Sid"), str) else "<missing Sid>"
        if sid in VALUE_BEARING_SCOPED_SIDS:
            continue
        value_actions = sorted(
            action.lower()
            for action in normalized_strings(stmt.get("Action"))
            if is_value_bearing_action(action)
        )
        if value_actions:
            formatted = ", ".join(value_actions)
            violations.append(
                f"{sid} contains value-bearing read action(s) outside scoped Sids: {formatted}"
            )

    ssm = statements.get("SSMParameterRead")
    if not ssm:
        violations.append("missing SSMParameterRead")
    else:
        ssm_resources = set(normalized_strings(ssm.get("Resource")))
        if ssm_resources != SSM_PARAMETER_READ_RESOURCES:
            violations.append("SSMParameterRead resources must stay on the reviewed SSM path allowlist")

    secrets = statements.get("SecretsManagerRead")
    if not secrets:
        violations.append("missing SecretsManagerRead")
    else:
        secrets_actions = {action.lower() for action in normalized_strings(secrets.get("Action"))}
        if any(action.startswith("secretsmanager:list") for action in secrets_actions):
            violations.append("SecretsManagerRead must not include Secrets Manager List* actions")
        secrets_resources = normalized_strings(secrets.get("Resource"))
        if secrets_resources != [
            "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
        ]:
            violations.append("SecretsManagerRead must stay scoped to layerv-nhp secrets in local.account_id")

    s3 = statements.get("S3ObjectRead")
    if not s3:
        violations.append("missing S3ObjectRead")
    else:
        if normalized_strings(s3.get("Resource")) != ["${local.terraform_plan_pr_s3_object_arns}"]:
            violations.append("S3ObjectRead must use local.terraform_plan_pr_s3_object_arns")
        if condition_values(s3, "StringEquals", "aws:ResourceAccount") != ["${local.account_id}"]:
            violations.append("S3ObjectRead must require aws:ResourceAccount = local.account_id")

    kms = statements.get("KMSDecryptInAccount")
    if not kms:
        violations.append("missing KMSDecryptInAccount")
    else:
        if normalized_strings(kms.get("Resource")) != ["*"]:
            violations.append("KMSDecryptInAccount resource shape changed; update this lint intentionally")
        if condition_values(kms, "StringEquals", "aws:ResourceAccount") != ["${local.account_id}"]:
            violations.append("KMSDecryptInAccount must require aws:ResourceAccount = local.account_id")
        aliases = set(condition_values(kms, "ForAnyValue:StringLike", "kms:ResourceAliases"))
        if aliases != KMS_DECRYPT_ALIASES:
            violations.append("KMSDecryptInAccount aliases must stay on the reviewed NHP alias allowlist")

    if violations:
        for violation in violations:
            error(
                f"{POLICY_RESOURCE_TYPE}.{POLICY_RESOURCE_NAME}: {violation}",
                file=file,
            )
    return violations


def find_plan_pr_policy(terraform_root: Path) -> tuple[Path, dict]:
    for file, rtype, name, body in iter_resources(parse_tf_files(terraform_root)):
        if rtype != POLICY_RESOURCE_TYPE or name != POLICY_RESOURCE_NAME:
            continue
        policy = extract_policy_body(body.get("policy"))
        if policy is None:
            error(
                f"{POLICY_RESOURCE_TYPE}.{POLICY_RESOURCE_NAME}: policy could not be decoded",
                file=file,
            )
            sys.exit(2)
        return file, policy

    error(
        f"{POLICY_RESOURCE_TYPE}.{POLICY_RESOURCE_NAME}: resource not found under {terraform_root}"
    )
    sys.exit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "terraform_root",
        nargs="?",
        default="terraform",
        type=Path,
        help="Terraform root to scan (default: terraform)",
    )
    args = parser.parse_args()

    file, policy = find_plan_pr_policy(args.terraform_root)
    if has_allow_not_action(policy):
        error(
            f"{POLICY_RESOURCE_TYPE}.{POLICY_RESOURCE_NAME}: Allow statements must not use NotAction",
            file=file,
        )
        return 1

    actions = statement_actions(policy)
    violations = sorted(
        action
        for action in actions
        if action in FORBIDDEN_ACTIONS or not is_read_only_action(action)
    )
    if violations:
        formatted = ", ".join(violations)
        error(
            f"{POLICY_RESOURCE_TYPE}.{POLICY_RESOURCE_NAME}: non-read-only action(s): {formatted}",
            file=file,
        )
        return 1
    scope_violations = validate_sensitive_statement_scopes(file, policy)
    if scope_violations:
        return 1

    print(
        "OK: terraform_plan_pr_read policy actions and sensitive resource scopes are constrained "
        f"({len(actions)} action patterns checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
