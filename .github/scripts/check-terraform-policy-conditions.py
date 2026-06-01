#!/usr/bin/env python3
"""check-terraform-policy-conditions.py

Class-B drift detector (#1324, extended for #1146). Asserts terraform
doesn't reintroduce IAM policy shapes that make AWS authz silently diverge
from the intended environment boundary:

- resource-policy Conditions that AWS *doesn't populate* in the cross-account
  or service-linked-role evaluation paths — Conditions that pass sandbox
  apply happily and silently deny in prod.
- wildcard Route53 ChangeResourceRecordSets grants without Route53's
  normalized-record-name condition — grants that let sandbox CI mutate records
  in orphan hosted zones that are not part of the environment's Terraform
  surface.

Why this exists
===============

#1316: `aws_ecr_registry_policy.replication` carried a
`Condition.StringEquals.aws:SourceAccount` block as defense-in-depth over
`Principal`. Empirically, ECR's cross-account replication service does not
populate `aws:SourceAccount` in the destination-side authz context — the
Condition always evaluated to the implicit deny, and replication to prod
ECR was silently broken from the day the policy applied. Sandbox CI never
hit it because sandbox is the source account; the gap surfaced at the
2026-04-24 promote-time preflight when a multi-week window of zero
replicated images came to light.

This lint blocks reintroduction of that anti-pattern (and any others added
to `BANNED_CONDITIONS` going forward) at PR time, with no AWS credentials
required.

Adding a new entry should always be paired with a regression-fence note
in the lint's table — the bar to extend the denylist is "we have a
verified case where AWS doesn't populate this key in the auth path", not
"this looks suspicious".

See `docs/runbooks/terraform-prod-drift.md` for what to do when this fires.
The reviewer-facing companion (when to pin `aws:SourceAccount` vs not,
plus the per-module audit) lives in
`docs/incidents/2026-04-24-ecr-source-account-trap.md`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

# Importable as a sibling — both lints live in .github/scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _tf_lint_lib import (  # noqa: E402  # pyright: ignore[reportMissingImports]
    error,
    extract_policy_body,
    iter_resources,
    parse_tf_files,
    unquote,
    warn_undecodable_policy,
)


class BannedCondition(NamedTuple):
    resource_type: str
    condition_key: str
    citation: str
    incident: str


# Bar to extend: empirical verification that AWS does not populate the key
# in the auth path that the resource policy is on. Speculative bans are
# rejected to keep the FP rate at the floor.
BANNED_CONDITIONS: list[BannedCondition] = [
    BannedCondition(
        resource_type="aws_ecr_registry_policy",
        condition_key="aws:SourceAccount",
        # AWS's cross-account ECR replication policy examples omit this
        # condition because the replication service-linked role does not
        # populate aws:SourceAccount on the destination-side auth.
        citation="https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions-cross-account-examples.html",
        incident="PR #1316 / 2026-04-24 prod release incident",
    ),
    BannedCondition(
        resource_type="aws_ecr_registry_policy",
        condition_key="aws:SourceArn",
        # Same root cause as aws:SourceAccount above — neither key is
        # populated by ECR's cross-account replication service-linked role.
        # docs/runbooks/ecr-replication-failure.md flags both as the same
        # failure mode; pin both here.
        citation="https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions-cross-account-examples.html",
        incident="docs/runbooks/ecr-replication-failure.md (sibling of #1316)",
    ),
]

ROUTE53_RECORDSET_NAME_CONDITION = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
ROUTE53_RECORDSET_ACTIONS_CONDITION = "route53:ChangeResourceRecordSetsActions"
ROUTE53_RECORDSET_TYPES_CONDITION = "route53:ChangeResourceRecordSetsRecordTypes"
ROUTE53_RECORDSET_NAME_OPERATORS = {
    "ForAllValues:StringEquals",
    "ForAllValues:StringLike",
}
ROUTE53_GUARD_POLICY_TYPES = {
    "aws_iam_group_policy",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
}
ROUTE53_ARN_RE = re.compile(r"^arn:[^:]+:route53:::(?P<resource>.*)$", re.IGNORECASE)
ROUTE53_ACME_RECORD_ACTIONS = {"CREATE", "UPSERT", "DELETE"}
# This allowlist is intentionally narrow: it is safe only because
# terraform/modules/ecr validates this exact input's runtime values with the
# same shape rule before plan/apply.
ROUTE53_REVIEWED_RECORD_NAME_REFS = {
    "${var.route53_change_record_name_patterns}",
}
CANONICAL_GITHUB_ACTIONS_ROLE_DIR = ("modules", "ecr")


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [unquote(value)]
    if isinstance(value, list):
        return [unquote(v) for v in value if isinstance(v, str)]
    return []


def _iam_glob_matches(value: str, pattern: str) -> bool:
    """Match IAM-style action globs where only `*` and `?` are wildcards."""
    regex = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char)
        for char in pattern.lower()
    )
    return re.fullmatch(regex, value.lower()) is not None


def _statement_allows_action(stmt: dict[str, Any], action: str) -> bool:
    effect = stmt.get("Effect", "Allow")
    if not isinstance(effect, str) or unquote(effect).lower() != "allow":
        return False
    actions = _as_string_list(stmt.get("Action"))
    if actions:
        for pattern in actions:
            if _iam_glob_matches(action, pattern):
                return True
        return False
    # IAM rejects statements that specify both Action and NotAction. If a
    # malformed fixture ever does, the explicit Action branch above wins so the
    # lint does not infer broader access than the statement declares.
    not_actions = _as_string_list(stmt.get("NotAction"))
    if not_actions:
        for pattern in not_actions:
            if _iam_glob_matches(action, pattern):
                return False
        return True
    return False


def _condition_values(stmt: dict[str, Any], key: str) -> list[tuple[str, Any]]:
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return []
    target = key.lower()
    values: list[tuple[str, Any]] = []
    for op_name, op_block in cond.items():
        if not isinstance(op_name, str) or not isinstance(op_block, dict):
            continue
        normalized_op = unquote(op_name)
        for cond_key, value in op_block.items():
            if unquote(cond_key).lower() == target:
                values.append((normalized_op, value))
    return values


def _statement_has_forall_values_subset_condition(
    stmt: dict[str, Any], key: str, allowed_values: set[str]
) -> bool:
    found_condition = False
    for op_name, value in _condition_values(stmt, key):
        if op_name != "ForAllValues:StringEquals":
            continue
        values = {item.strip().upper() for item in _as_string_list(value)}
        if not values or values - allowed_values:
            return False
        found_condition = True
    return found_condition and _statement_has_null_false_condition(stmt, key)


def _statement_has_acme_txt_only_conditions(stmt: dict[str, Any]) -> bool:
    return _statement_has_forall_values_subset_condition(
        stmt, ROUTE53_RECORDSET_ACTIONS_CONDITION, ROUTE53_ACME_RECORD_ACTIONS
    ) and _statement_has_forall_values_subset_condition(
        stmt, ROUTE53_RECORDSET_TYPES_CONDITION, {"TXT"}
    )


def _is_narrow_route53_record_name_pattern(stmt: dict[str, Any], pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern or pattern != pattern.lower() or pattern.endswith("."):
        return False
    if pattern == "_acme-challenge.*":
        return _statement_has_acme_txt_only_conditions(stmt)
    if "${" in pattern or "}" in pattern:
        # Variable-sourced patterns are allowed only for the reviewed ECR module
        # input whose Terraform validation enforces the same shape at plan time.
        return pattern in ROUTE53_REVIEWED_RECORD_NAME_REFS
    # Keep this exact-name-only rule aligned with the
    # route53_change_record_name_patterns validation in terraform/modules/ecr.
    # Review any future wildcard use as a code change rather than accepting it
    # by default under this wildcard hosted-zone ARN.
    if any(char in pattern for char in "*?"):
        return False
    return True


def _statement_has_narrow_route53_record_name_condition(stmt: dict[str, Any]) -> bool:
    found_name_condition = False
    for op_name, value in _condition_values(stmt, ROUTE53_RECORDSET_NAME_CONDITION):
        if op_name not in ROUTE53_RECORDSET_NAME_OPERATORS:
            continue
        patterns = _as_string_list(value)
        if not patterns or not all(
            _is_narrow_route53_record_name_pattern(stmt, pattern)
            for pattern in patterns
        ):
            return False
        found_name_condition = True
    return found_name_condition and _statement_has_null_false_condition(
        stmt, ROUTE53_RECORDSET_NAME_CONDITION
    )


def _statement_has_null_false_condition(stmt: dict[str, Any], key: str) -> bool:
    for op_name, value in _condition_values(stmt, key):
        if op_name != "Null":
            continue
        if value is False:
            return True
        values = _as_string_list(value)
        return bool(values) and all(v.strip().lower() == "false" for v in values)
    return False


def _is_route53_recordset_wildcard_resource(resource: str) -> bool:
    if resource == "*":
        return True
    match = ROUTE53_ARN_RE.match(resource)
    if not match:
        return False
    route53_resource = match.group("resource")
    return route53_resource == "*" or (
        route53_resource.lower().startswith("hostedzone/")
        and any(char in route53_resource for char in "*?")
    )


def route53_recordset_wildcard_findings(
    policy: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Return Route53 ChangeResourceRecordSets wildcard-write findings.

    The GitHub Actions role is terraform-apply-equivalent, but
    ChangeResourceRecordSets is the blast-radius edge behind nhp#1146:
    Route53 hosted zones are global and do not expose aws:ResourceAccount, so
    Resource="*" lets sandbox CI populate records in orphan zones such as the
    stale qurl.link zone. A wildcard hosted-zone resource is allowed only when
    the same statement uses Route53's normalized-record-name condition.

    This is a static lint over literal Resource/NotResource strings in decoded
    policy JSON. It does not evaluate Terraform expressions such as concat(...)
    or interpolations; undecodable policy bodies warn rather than silently
    claiming full coverage.
    """
    if not policy:
        return []
    findings: list[dict[str, Any]] = []
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        if not _statement_allows_action(stmt, "route53:ChangeResourceRecordSets"):
            continue
        wildcard_resources: list[str] = []
        for resource in _as_string_list(stmt.get("Resource")):
            if _is_route53_recordset_wildcard_resource(resource):
                wildcard_resources.append(resource)
        not_resources = [
            f"NotResource:{not_resource}"
            for not_resource in _as_string_list(stmt.get("NotResource"))
        ]
        if not_resources:
            # Allow + NotResource is a broad complement, so ban the shape.
            findings.append(
                {
                    "sid": stmt.get("Sid", "<no Sid>"),
                    "resources": not_resources,
                }
            )
            continue
        if wildcard_resources and not _statement_has_narrow_route53_record_name_condition(
            stmt
        ):
            findings.append(
                {
                    "sid": stmt.get("Sid", "<no Sid>"),
                    "resources": wildcard_resources,
                }
            )
    return findings


def _is_canonical_github_actions_role(file: Path, rtype: str, name: str) -> bool:
    return (
        rtype == "aws_iam_role"
        and name == "github_actions"
        and len(file.parent.parts) >= 2
        and file.parent.parts[-2:] == CANONICAL_GITHUB_ACTIONS_ROLE_DIR
    )


def policy_has_condition_key(policy: dict[str, Any] | None, key: str) -> bool:
    """True if `policy` has a non-`*IfExists` Condition with `key` (case-insensitive).

    AWS treats IAM condition *keys* as case-insensitive at auth time —
    `aws:SourceAccount`, `AWS:SourceAccount`, and `aws:sourceaccount`
    all evaluate the same. The lint normalizes both sides to lowercase
    so a future copy-paste with non-canonical casing doesn't slip
    through. Condition *operators* (`StringEquals`, etc.) ARE
    case-sensitive at AWS eval time — kept exact-match.

    The `unquote` calls are load-bearing: condition keys and
    `ForAllValues:*` operator names contain `:` so they're written as
    quoted strings in HCL and python-hcl2 surfaces them with the
    surrounding quotes intact.
    """
    if not policy:
        return False
    target = key.lower()
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        cond = stmt.get("Condition")
        if not isinstance(cond, dict):
            continue
        for op_name, op_block in cond.items():
            # `*IfExists` operators (e.g., `StringEqualsIfExists`,
            # `BoolIfExists`) evaluate to true when the key is absent —
            # the documented mitigation for unpopulated keys (see
            # docs/runbooks/terraform-prod-drift.md). Don't flag them
            # alongside the bare operators. Operators are case-
            # sensitive at AWS eval time, so the exact-suffix
            # `endswith("IfExists")` is correct: a non-canonical-cased
            # operator like `stringequalsifexists` would NOT be
            # evaluated by AWS as the author intended, and AWS rejects
            # non-canonical-cased operators at apply time. The lint
            # relies on that AWS-side rejection rather than
            # re-implementing the check.
            if isinstance(op_name, str) and unquote(op_name).endswith("IfExists"):
                continue
            if isinstance(op_block, dict) and any(
                unquote(k).lower() == target for k in op_block
            ):
                return True
    return False


def main() -> int:
    epilog = (
        "Exit codes: 0 = clean; 1 = at least one banned condition or "
        "Route53 wildcard record-mutation finding; 3 = internal error."
    )
    ap = argparse.ArgumentParser(epilog=epilog)
    ap.add_argument(
        "--terraform-root",
        default=str(Path(__file__).resolve().parent.parent.parent / "terraform"),
        help="Path to the terraform/ directory to scan.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text.",
    )
    args = ap.parse_args()

    root = Path(args.terraform_root)
    if not root.is_dir():
        error(f"terraform root not found: {root}")
        return 3

    parsed = parse_tf_files(root)
    targeted_types = {entry.resource_type for entry in BANNED_CONDITIONS}
    scanned_types = targeted_types | ROUTE53_GUARD_POLICY_TYPES | {"aws_iam_role"}

    findings: list[dict[str, Any]] = []
    for file, rtype, name, body in iter_resources(parsed):
        if rtype not in scanned_types:
            continue
        if _is_canonical_github_actions_role(file, rtype, name) and body.get(
            "permissions_boundary"
        ):
            findings.append(
                {
                    "kind": "github_actions_permissions_boundary",
                    "file": str(file),
                    "type": rtype,
                    "name": name,
                }
            )
        policy_items: list[tuple[str, dict[str, Any] | None, Any]] = []
        if rtype in ROUTE53_GUARD_POLICY_TYPES or rtype in targeted_types:
            policy_attr = body.get("policy")
            policy_items.append((name, extract_policy_body(policy_attr), policy_attr))
        if rtype == "aws_iam_role":
            for idx, inline_policy in enumerate(body.get("inline_policy", []) or []):
                if not isinstance(inline_policy, dict):
                    continue
                inline_name = inline_policy.get("name")
                inline_label = (
                    unquote(inline_name)
                    if isinstance(inline_name, str)
                    else f"inline_policy[{idx}]"
                )
                policy_attr = inline_policy.get("policy")
                policy_items.append(
                    (
                        f"{name}.{inline_label}",
                        extract_policy_body(policy_attr),
                        policy_attr,
                    )
                )

        for policy_name, policy, policy_attr in policy_items:
            # Mirror the IAM-coverage lint's warn-not-silent posture: if
            # the policy can't be decoded, surface as a warning so a future
            # refactor (e.g. moving the body to
            # `data.aws_iam_policy_document` or `file(...)`) doesn't
            # quietly disable the regression fence.
            if policy is None and policy_attr is not None:
                warn_undecodable_policy(
                    file,
                    rtype,
                    policy_name,
                    finding="banned-condition and Route53 wildcard-record checks for this resource will be skipped",
                )
            for route53_finding in route53_recordset_wildcard_findings(policy):
                findings.append(
                    {
                        "kind": "route53_recordset_wildcard",
                        "file": str(file),
                        "type": rtype,
                        "name": policy_name,
                        "sid": route53_finding["sid"],
                        "resources": route53_finding["resources"],
                    }
                )
            for entry in BANNED_CONDITIONS:
                if entry.resource_type != rtype:
                    continue
                if policy_has_condition_key(policy, entry.condition_key):
                    findings.append(
                        {
                            "kind": "banned_condition",
                            "file": str(file),
                            "type": rtype,
                            "name": policy_name,
                            "key": entry.condition_key,
                            "citation": entry.citation,
                            "incident": entry.incident,
                        }
                    )

    if args.json:
        json.dump({"findings": findings}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for f in findings:
            if f.get("kind") == "route53_recordset_wildcard":
                error(
                    f"resource `{f['type']}.{f['name']}` statement "
                    f"`{f['sid']}` grants route53:ChangeResourceRecordSets "
                    f"on wildcard hosted-zone resource(s) {f['resources']} "
                    f"without a narrow `ForAllValues` "
                    f"`{ROUTE53_RECORDSET_NAME_CONDITION}` condition. Scope "
                    f"record writes to explicit hosted-zone ARNs, or add a "
                    f"non-wildcard normalized-record-name condition for "
                    f"computed zones. "
                    f"Reference: nhp#1146 orphan qurl.link hosted zone.",
                    file=Path(f["file"]),
                )
                continue
            if f.get("kind") == "github_actions_permissions_boundary":
                error(
                    f"resource `{f['type']}.{f['name']}` must not set "
                    "`permissions_boundary`: the security module boundary is "
                    "ACME TXT-only and would cap terraform-apply Route53 "
                    "writes. Add a separate reviewed boundary if CI ever "
                    "needs one.",
                    file=Path(f["file"]),
                )
                continue
            # The reviewer-rule path below is duplicated in the docstring
            # at the top of this file and in
            # docs/runbooks/ecr-replication-failure.md. If the reviewer
            # artifact is ever moved or renamed, all three sites need
            # updating in lockstep.
            error(
                f"resource `{f['type']}.{f['name']}` contains banned "
                f"Condition key `{f['key']}` — AWS does not populate "
                f"this key in the auth path for this resource type and "
                f"the Condition will silently deny in prod. See "
                f"{f['citation']}. Reference: {f['incident']}. "
                f"Reviewer rule: docs/incidents/"
                f"2026-04-24-ecr-source-account-trap.md.",
                file=Path(f["file"]),
            )
        if findings:
            print(
                f"\nterraform policy-condition denylist check: FAILED "
                f"({len(findings)} hit(s))",
                file=sys.stderr,
            )
        else:
            print("terraform policy-condition denylist check: OK")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
