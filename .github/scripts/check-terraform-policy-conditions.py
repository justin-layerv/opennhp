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
- identity-policy KMS grants on `Resource = "*"` that can decrypt across
  account boundaries — an unconditioned `kms:Decrypt` + `Resource="*"`, or one
  "scoped" only by the `kms:CallerAccount` tautology, that advertises a
  same-account restriction it never enforces (#1523, regression-prevention for
  #1125 / PR #1520).

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

# ---- #1523: identity-policy KMS wildcard-decrypt without same-account scope ---
# A decrypt-capable KMS action on `Resource = "*"` in an *identity* policy must
# be scoped to same-account resources. The empirically correct key is
# `aws:ResourceAccount` (resolves to the account that owns the key being acted
# on). `kms:CallerAccount` is a tautology in identity policies — it resolves to
# the *principal's* own account, which is always this account, so it advertises
# a cross-account restriction it never enforces (the #1125 / PR #1520 trap).
# `kms:ViaService` bounds the call to a specific same-region AWS service
# endpoint and is AWS's documented pattern for AWS-managed keys whose ARN is not
# known at plan time (SecretsManager/SSM), so it counts as real scoping.
#
# Scope: this is an identity-policy rule. KMS *key* policies (`aws_kms_key`,
# resource-based, carry a `Principal`) legitimately use `kms:CallerAccount` and
# are out of scope — they are not in KMS_GUARD_POLICY_TYPES, and the
# statement-level Principal guard in the finder is belt-and-braces. Like the
# rest of Class B, this does not decode `data.aws_iam_policy_document` sources;
# every `Resource = "*"` KMS grant in the tree today is `jsonencode` form.

# Decrypt-capable actions that expose plaintext from *existing* ciphertext —
# the #1125 data-exfil vector. kms:Decrypt returns plaintext directly;
# kms:ReEncryptFrom decrypts the source ciphertext. Deliberately limited to
# these two: kms:GenerateDataKey*/GenerateDataKeyPair* also return plaintext but
# mint *new* material rather than reading an existing secret, and
# kms:ReEncryptTo only re-wraps without exposing plaintext — both are out of
# scope to keep the signal tight and match the #1125 incident. Add here (with a
# fixture) if that risk assessment changes.
KMS_DECRYPT_TRIGGER_ACTIONS = ("kms:Decrypt", "kms:ReEncryptFrom")
# The only condition keys accepted as same-account scope. A grant scoped some
# other way is flagged and must refactor to one of these or to explicit
# same-account key ARNs. This is deliberate: tag conditions
# (`aws:ResourceTag/...`) and `aws:ResourceOrgID` do NOT bound to a single
# account (a foreign key can carry a matching tag; same-org spans accounts), so
# they are not a defense against the #1125 cross-account-decrypt vector.
KMS_SCOPING_CONDITION_KEYS = ("aws:ResourceAccount", "kms:ViaService")
# Positive string-match operators that actually bind a same-account string key.
# Negated operators (StringNotEquals/StringNotLike) invert the set and don't
# scope; `*IfExists` variants evaluate true when the key is absent; set/numeric/
# date/bool operators don't apply to these keys. A `ForAllValues:`/`ForAnyValue:`
# set-qualifier prefix is stripped before this lookup. This mirrors the error
# message's "positive StringEquals/StringLike" guidance and the stricter
# operator allowlist on the sibling Route53 path.
KMS_SCOPING_CONDITION_OPERATORS = {"StringEquals", "StringLike"}
# Mirrors ROUTE53_GUARD_POLICY_TYPES (the identity-policy set) but kept separate
# on purpose: the two guards target different blast radii, so a future change to
# one set must not silently move the other. `aws_iam_role` inline policies are
# covered via the inline-policy decode in main(), not this set.
KMS_GUARD_POLICY_TYPES = {
    "aws_iam_group_policy",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
}


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


def _is_pure_wildcard_value(value: str) -> bool:
    """True if `value` is non-empty and only `*`/`?` — a bare wildcard that
    matches any account/service and so provides no bound."""
    value = value.strip()
    return value != "" and all(char in "*?" for char in value)


def _statement_has_scoping_condition(stmt: dict[str, Any], key: str) -> bool:
    """True if `stmt` scopes `key` with a positive, non-wildcard string match.

    A condition only counts as real same-account scoping when both hold:
    - the operator is a positive string match (in
      `KMS_SCOPING_CONDITION_OPERATORS`, after any `ForAllValues:`/
      `ForAnyValue:` set-qualifier is stripped). Negated operators don't bind,
      and `*IfExists` variants evaluate true when the key is absent —
      `kms:ViaServiceIfExists` would let a direct (non-service) caller straight
      through;
    - the matched values actually bind the account/service set. A pure `*`/`?`
      value provides no bound; the operator decides how a wildcard interacts
      with concrete siblings in the value list (the values are OR-ed):
      - `StringEquals` matches the literal value, so a `"*"` arm is a dead
        literal (account IDs are never the string `"*"`) and a concrete sibling
        still binds — `StringEquals = ["<acct>", "*"]` counts as scoped;
      - `StringLike` treats `"*"` as a wildcard that matches every
        account/service, so *any* pure-wildcard value unbinds the whole list —
        `StringLike = "*"` and `StringLike = ["<acct>", "*"]` both fail to scope.

    Key match is case-insensitive (handled in `_condition_values`); the
    operator match is exact because AWS rejects non-canonical-cased operators
    at apply time.
    """
    for op_name, value in _condition_values(stmt, key):
        base_op = op_name
        for prefix in ("ForAllValues:", "ForAnyValue:"):
            if base_op.startswith(prefix):
                base_op = base_op[len(prefix) :]
                break
        if base_op not in KMS_SCOPING_CONDITION_OPERATORS:
            continue
        values = _as_string_list(value)
        # A concrete bind is a non-empty, non-pure-wildcard value. The
        # `v.strip()` guard drops an empty/whitespace value (`= ""`), which
        # binds nothing yet isn't a wildcard, so it must not count as scope.
        has_concrete = any(
            v.strip() and not _is_pure_wildcard_value(v) for v in values
        )
        has_wildcard = any(_is_pure_wildcard_value(v) for v in values)
        # No concrete value at all (e.g. `["*"]`) is no bound. Under StringLike a
        # bare-wildcard value matches everything, so any wildcard in the OR-list
        # unbinds it; under StringEquals a `"*"` arm is a dead literal, so a
        # concrete sibling still binds.
        if not has_concrete or (base_op == "StringLike" and has_wildcard):
            continue
        return True
    return False


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


def _is_account_wildcard_arn(resource: str) -> bool:
    """True if `resource` is an ARN whose account-id field is `*` or empty.

    A `*` account field (`arn:aws:kms:*:*:key/*`) matches keys in *any*
    account, so for cross-account decrypt it is as broad as `Resource = "*"`
    even though it isn't the literal `"*"`. An empty account field
    (`arn:aws:kms:us-east-1::key/*`) denotes no real key — every KMS key ARN
    carries an account — so it is flagged conservatively as a malformed broad
    grant rather than assumed safe. The account-id is the 5th colon-delimited
    ARN field (`arn:partition:service:region:account:resource`); a concrete
    account id (even a foreign one, which a reviewer would catch) is treated as
    scoped. The resource segment can itself contain `:` (e.g. an alias), so the
    leading fields are read positionally and the rest ignored.
    """
    parts = resource.split(":")
    if len(parts) < 6 or parts[0].lower() != "arn":
        return False
    account = parts[4].strip()
    return account in ("", "*")


def kms_wildcard_decrypt_findings(
    policy: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Return identity-policy KMS wildcard-decrypt findings (#1523).

    Flags an `Allow` statement that grants a decrypt-capable KMS action on a
    broad resource unless it carries a real (non-`IfExists`)
    `aws:ResourceAccount` or `kms:ViaService` condition. This is the #1125
    shape: an unconditioned `kms:Decrypt` grant — or one "scoped" only by the
    `kms:CallerAccount` tautology — lets a same-account principal decrypt across
    account boundaries.

    A resource is "broad" when it is the literal `Resource = "*"` OR an ARN
    whose account-id field is `*`/empty (`arn:aws:kms:*:*:key/*` reaches every
    account just like `"*"`). An `Allow` + `NotResource` is a broad complement
    (everything *except* a few ARNs still includes other accounts' keys), so it
    is treated as wildcard-equivalent too — the same posture as the sibling
    Route53 path. A concrete-account key ARN (e.g. `[var.kms_key_arn]` or
    `arn:aws:kms:us-east-1:<acct>:key/...`) is scoped and does not match. The
    action match is IAM-glob-aware, so `kms:*` (or `*`) trips the trigger too.
    `Deny` statements are guardrails and are never flagged.

    This proves the *presence* of same-account-scoping syntax, not the
    correctness of the bound account value — a hardcoded foreign concrete
    account passes, so a reviewer must still verify the literal. See the KMS
    wildcard-decrypt section of docs/runbooks/terraform-prod-drift.md.
    """
    if not policy:
        return []
    findings: list[dict[str, Any]] = []
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        # Identity policies never carry a statement-level Principal. A doc that
        # does is a resource-based (KMS key) policy pasted into an identity
        # resource — out of scope, skip rather than misclassify. Resource-based
        # key policies legitimately use kms:CallerAccount.
        if "Principal" in stmt or "NotPrincipal" in stmt:
            continue
        if not any(
            _statement_allows_action(stmt, action)
            for action in KMS_DECRYPT_TRIGGER_ACTIONS
        ):
            continue
        resources = _as_string_list(stmt.get("Resource"))
        not_resources = _as_string_list(stmt.get("NotResource"))
        broad_resource = "*" in resources or any(
            _is_account_wildcard_arn(r) for r in resources
        )
        if not broad_resource and not not_resources:
            continue
        if any(
            _statement_has_scoping_condition(stmt, key)
            for key in KMS_SCOPING_CONDITION_KEYS
        ):
            continue
        findings.append({"sid": stmt.get("Sid", "<no Sid>")})
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
        "Exit codes: 0 = clean; 1 = at least one banned condition, "
        "Route53 wildcard record-mutation, or KMS wildcard-decrypt finding; "
        "3 = internal error."
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
    # Each guard's own type set is load-bearing in this union: KMS_GUARD_POLICY_
    # TYPES is listed explicitly (not relied on via its current equality with
    # ROUTE53_GUARD_POLICY_TYPES) so narrowing one guard's set can't silently
    # drop a type from the other — matching the "kept separate on purpose"
    # contract on those constants.
    scanned_types = (
        targeted_types
        | ROUTE53_GUARD_POLICY_TYPES
        | KMS_GUARD_POLICY_TYPES
        | {"aws_iam_role"}
    )

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
        if (
            rtype in ROUTE53_GUARD_POLICY_TYPES
            or rtype in KMS_GUARD_POLICY_TYPES
            or rtype in targeted_types
        ):
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
                    finding="banned-condition, Route53 wildcard-record, and KMS wildcard-decrypt checks for this resource will be skipped",
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
            # KMS wildcard-decrypt is an identity-policy rule (#1523); skip
            # resource-based types like aws_ecr_registry_policy that also reach
            # this loop via the banned-condition path. aws_iam_role inline
            # policies arrive here as policy_items with rtype == aws_iam_role.
            if rtype in KMS_GUARD_POLICY_TYPES or rtype == "aws_iam_role":
                for kms_finding in kms_wildcard_decrypt_findings(policy):
                    findings.append(
                        {
                            "kind": "kms_wildcard_decrypt",
                            "file": str(file),
                            "type": rtype,
                            "name": policy_name,
                            "sid": kms_finding["sid"],
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
            if f.get("kind") == "kms_wildcard_decrypt":
                error(
                    f"resource `{f['type']}.{f['name']}` statement "
                    f"`{f['sid']}` grants a decrypt-capable KMS action on a "
                    f"broad resource (`Resource = \"*\"`, an account-wildcard "
                    f"ARN, or `NotResource`) with no same-account-resource "
                    f"condition. An unconditioned grant — or one scoped only "
                    f"by the `kms:CallerAccount` tautology (which resolves to "
                    f"the principal's own account in an identity policy) — "
                    f"lets a same-account principal decrypt across account "
                    f"boundaries. Add `aws:ResourceAccount` (or, for "
                    f"AWS-managed keys, `kms:ViaService`) in a positive "
                    f"`StringEquals`/`StringLike` condition, or scope "
                    f"`Resource` to explicit key ARNs. Reference: #1523 "
                    f"(regression-prevention for #1125 / PR #1520).",
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
