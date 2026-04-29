#!/usr/bin/env python3
"""check-terraform-policy-conditions.py

Class-B drift detector (#1324). Asserts terraform doesn't reintroduce
resource-policy Conditions that AWS *doesn't populate* in the cross-account
or service-linked-role evaluation paths — Conditions that pass sandbox
apply happily and silently deny in prod.

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


def policy_has_condition_key(policy: dict[str, Any] | None, key: str) -> bool:
    """True if `policy` has a non-`*IfExists` Condition with `key` (case-insensitive).

    AWS treats IAM condition *keys* as case-insensitive at auth time —
    `aws:SourceAccount`, `AWS:SourceAccount`, and `aws:sourceaccount`
    all evaluate the same. The lint normalizes both sides to lowercase
    so a future copy-paste with non-canonical casing doesn't slip
    through. Condition *operators* (`StringEquals`, etc.) ARE
    case-sensitive at AWS eval time — kept exact-match.

    The `unquote` on the inner key is load-bearing: condition keys
    (e.g., `aws:SourceAccount`) contain `:` so they're written as
    quoted strings in HCL and python-hcl2 surfaces them with the
    surrounding quotes intact. The operator name is a bare HCL
    identifier and arrives unquoted, so no `unquote` there.
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
            if isinstance(op_name, str) and op_name.endswith("IfExists"):
                continue
            if isinstance(op_block, dict) and any(
                unquote(k).lower() == target for k in op_block
            ):
                return True
    return False


def main() -> int:
    epilog = (
        "Exit codes: 0 = clean; 1 = at least one banned (resource_type, "
        "condition_key) pair found; 3 = internal error."
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

    findings: list[dict[str, Any]] = []
    for file, rtype, name, body in iter_resources(parsed):
        if rtype not in targeted_types:
            continue
        policy_attr = body.get("policy")
        policy = extract_policy_body(policy_attr)
        # Mirror the IAM-coverage lint's warn-not-silent posture: if
        # the policy can't be decoded, surface as a warning so a future
        # refactor (e.g. moving the body to
        # `data.aws_iam_policy_document` or `file(...)`) doesn't
        # quietly disable the regression fence.
        if policy is None and policy_attr is not None:
            warn_undecodable_policy(
                file,
                rtype,
                name,
                finding="banned-condition checks for this resource will be skipped",
            )
        for entry in BANNED_CONDITIONS:
            if entry.resource_type != rtype:
                continue
            if policy_has_condition_key(policy, entry.condition_key):
                findings.append(
                    {
                        "file": str(file),
                        "type": rtype,
                        "name": name,
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
