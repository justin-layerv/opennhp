#!/usr/bin/env python3
"""Reject mixed inline/standalone security-group rule ownership (#3281).

The failure this fences
-----------------------
`ingress` and `egress` on `aws_security_group` are Optional+Computed. When
the config declares *no* block for an attribute, Terraform adopts whatever
AWS reports and never diffs it. The moment the config declares even one
inline block — or an explicit `egress = []` — that resource becomes
authoritative for the WHOLE attribute and will revoke every rule it does
not itself declare.

So an `aws_security_group` carrying inline rules, plus any standalone
`aws_security_group_rule` / `aws_vpc_security_group_{ingress,egress}_rule`
pointed at the same group, is not merely untidy: the two owners fight on
every plan, and an ordinary apply silently revokes the standalone owner's
rule. #3281 found exactly that armed against the prod Redis SG — the
module's inline `ingress` block was planning to revoke qurl-service's
`ecs_to_redis` rule, which is the only rule naming the ECS tasks' SG.

The invariant
-------------
For each `aws_security_group`, for each of `ingress`/`egress`: if the
resource declares that attribute inline AND some standalone rule resource
attaches to that group, the attribute must be listed in
`lifecycle.ignore_changes`. Freezing it demotes the SG out of the
authoritative role and leaves the standalone resources as sole owners.

Removing the inline block entirely also satisfies the invariant (nothing
is declared, so nothing is authoritative) — that is what redis-cluster
does, and it is the preferred shape. `ignore_changes` is the escape hatch
for groups that must keep an inline attribute; bootstrap-alb, relay,
relay-network, and udp-proof-runner use it for their `egress = []`.

Cross-module resolution
-----------------------
The Redis bug is invisible to a same-file check: the rule lives in
`modules/qurl-service` and targets `var.redis_security_group_id`, while
the SG lives in `modules/redis-cluster`. This lint therefore resolves
targets in two tiers:

  1. Direct — `security_group_id = aws_security_group.NAME.id` names a
     group in the rule's own module directory.
  2. Through the module graph — `security_group_id = var.V` is chased to
     every `module "M" { source = <this module> }` call site, its
     argument for `V` is scanned for `module.P[...].OUT` references, and
     `OUT` is resolved in module P's directory to the
     `aws_security_group.NAME.id` it exports.

A `security_group_id` this lint cannot resolve is reported as a warning,
not silently dropped — an unresolvable target is exactly where a
regression would hide.

Usage: check-terraform-sg-rule-ownership.py [terraform_root]
Exit 0 clean, 1 on violation, 3 on unparseable HCL.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _tf_lint_lib import (  # noqa: E402
    error,
    iter_module_calls,
    iter_outputs,
    iter_resources,
    parse_tf_files,
    unquote,
    warn,
)

# Every resource type that writes a single rule into someone else's
# security group. `aws_security_group_rule` is the legacy form and is
# still in use (qurl-service's ecs_to_redis); the `aws_vpc_*` pair is the
# modern replacement. All three conflict with an inline block identically.
#
# The value is the rule's direction, or None when the resource carries it
# in a `type` attribute. Direction matters: `ingress` and `egress` are
# separate Optional+Computed attributes, so an inline `ingress` block is
# authoritative for ingress only and does not fight a standalone *egress*
# rule on the same group (udp-proof-runner is exactly that shape).
STANDALONE_RULE_TYPES: dict[str, str | None] = {
    "aws_security_group_rule": None,
    "aws_vpc_security_group_ingress_rule": "ingress",
    "aws_vpc_security_group_egress_rule": "egress",
}

RULE_ATTRS = ("ingress", "egress")

# `${aws_security_group.NAME.id}` — the same-module reference form. The
# optional index matches `count`/`for_each` gated groups
# (`aws_security_group.server_nlb[0].id`), which are common in this repo.
SG_REF_RE = re.compile(
    r"aws_security_group\.([A-Za-z_][A-Za-z0-9_-]*)(?:\[[^\]]*\])?\.id"
)
# `${var.NAME}` — the cross-module handoff form.
VAR_REF_RE = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)")
# `module.NAME.OUTPUT` / `module.NAME[0].OUTPUT` / `module.NAME["k"].OUTPUT`
MODULE_OUT_RE = re.compile(
    r"\bmodule\.([A-Za-z_][A-Za-z0-9_-]*)(?:\[[^\]]*\])?\.([A-Za-z_][A-Za-z0-9_-]*)"
)


def _as_text(value: Any) -> str:
    """Flatten an attribute value to searchable text.

    A `security_group_id` may arrive as a plain interpolation string, or —
    when the caller wrote a ternary or a list — as a nested structure.
    The reference regexes only need the concatenated text, so nested
    containers are flattened rather than modelled.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_as_text(v) for v in value.values())
    return ""


def _ignored_attrs(body: dict[str, Any]) -> set[str]:
    """Return the attribute names frozen by `lifecycle.ignore_changes`.

    python-hcl2 surfaces `lifecycle` as a single-element list of blocks and
    renders `ignore_changes = [ingress, egress]` as bare strings. `all` is
    accepted as freezing everything, matching Terraform's own semantics.
    """
    ignored: set[str] = set()
    for block in body.get("lifecycle", []) or []:
        if not isinstance(block, dict):
            continue
        raw = block.get("ignore_changes")
        if isinstance(raw, str):
            raw = [raw]
        for item in raw or []:
            if not isinstance(item, str):
                continue
            name = unquote(item).strip()
            # A bare identifier may still arrive wrapped as `${ingress}`
            # depending on how the list was written; normalize both.
            if name.startswith("${") and name.endswith("}"):
                name = name[2:-1].strip()
            if name == "all":
                return {"all"}
            ignored.add(name)
    return ignored


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "terraform")
    if not root.is_dir():
        error(f"terraform root not found: {root}")
        return 3
    parsed = parse_tf_files(root)

    # ---- module graph -------------------------------------------------
    # (calling_dir, label) -> callee_dir, for resolving `module.X.out`.
    module_dirs: dict[tuple[Path, str], Path] = {}
    # callee_dir -> list of (calling_file, args) for chasing `var.V` up.
    callers: dict[Path, list[tuple[Path, dict[str, Any]]]] = {}
    for file, label, body in iter_module_calls(parsed):
        source = unquote(body.get("source", ""))
        if not isinstance(source, str) or not source.startswith("."):
            # Registry/remote modules are outside this repo's tree; a rule
            # in one cannot reference a local SG resource.
            continue
        callee = (file.parent / source).resolve()
        module_dirs[(file.parent.resolve(), label)] = callee
        callers.setdefault(callee, []).append((file, body))

    # callee_dir -> {output_name: sg_resource_name}
    sg_outputs: dict[Path, dict[str, str]] = {}
    for file, name, body in iter_outputs(parsed):
        m = SG_REF_RE.search(_as_text(body.get("value")))
        if m:
            sg_outputs.setdefault(file.parent.resolve(), {})[name] = m.group(1)

    # ---- security groups ----------------------------------------------
    # (dir, name) -> (file, {attr: authoritative?})
    groups: dict[tuple[Path, str], tuple[Path, dict[str, bool]]] = {}
    for file, rtype, name, body in iter_resources(parsed):
        if rtype != "aws_security_group" or not isinstance(body, dict):
            continue
        ignored = _ignored_attrs(body)
        # Presence of the key is the test, not its contents: an inline
        # `ingress {}` block and a bare `egress = []` both render as a
        # list here, and both make the resource authoritative.
        authoritative = {
            attr: attr in body and not ({attr, "all"} & ignored) for attr in RULE_ATTRS
        }
        groups[(file.parent.resolve(), name)] = (file, authoritative)

    # ---- standalone rules ----------------------------------------------
    # (dir, sg_name, direction) -> list of "file::type.name" attaching to it
    attached: dict[tuple[Path, str, str], list[str]] = {}
    for file, rtype, name, body in iter_resources(parsed):
        if rtype not in STANDALONE_RULE_TYPES or not isinstance(body, dict):
            continue
        attr = "security_group_id"
        where = f"{file}::{rtype}.{name}"

        direction = STANDALONE_RULE_TYPES[rtype]
        if direction is None:
            # Legacy `aws_security_group_rule` carries direction in `type`.
            direction = unquote(_as_text(body.get("type"))).strip()
            if direction not in RULE_ATTRS:
                warn(
                    f"{rtype}.{name}: `type` is not a literal "
                    f"\"ingress\"/\"egress\" ({direction!r}), so the rule's "
                    f"direction is unknown and mixed-ownership against its "
                    f"target is NOT checked.",
                    file=file,
                )
                continue

        expr = _as_text(body.get(attr))
        if not expr:
            warn(
                f"{rtype}.{name}: no resolvable `{attr}` — this rule's target "
                f"security group cannot be determined, so mixed-ownership "
                f"against it is not checked. Point it at an "
                f"`aws_security_group.<name>.id` or a module variable.",
                file=file,
            )
            continue
        here = file.parent.resolve()

        direct = SG_REF_RE.findall(expr)
        for sg_name in direct:
            attached.setdefault((here, sg_name, direction), []).append(where)
        if direct:
            continue

        # Cross-module: chase each `var.V` to the call sites of this module.
        resolved = False
        for var_name in VAR_REF_RE.findall(expr):
            for calling_file, args in callers.get(here, []):
                arg = args.get(var_name)
                if arg is None:
                    continue
                caller_dir = calling_file.parent.resolve()
                for mod_label, out_name in MODULE_OUT_RE.findall(_as_text(arg)):
                    callee = module_dirs.get((caller_dir, mod_label))
                    if callee is None:
                        continue
                    sg_name = sg_outputs.get(callee, {}).get(out_name)
                    if sg_name is None:
                        continue
                    attached.setdefault((callee, sg_name, direction), []).append(where)
                    resolved = True
        if not resolved:
            warn(
                f"{rtype}.{name}: `{attr}` resolves to neither a local "
                f"`aws_security_group` nor a module output carrying one "
                f"({expr!r}). Mixed-ownership against its target is NOT "
                f"checked — extend the resolver in "
                f".github/scripts/check-terraform-sg-rule-ownership.py.",
                file=file,
            )

    # ---- verdict --------------------------------------------------------
    violations = 0
    for (sg_dir, sg_name, direction), owners in sorted(
        attached.items(), key=lambda kv: (str(kv[0][0]), kv[0][1], kv[0][2])
    ):
        entry = groups.get((sg_dir, sg_name))
        if entry is None:
            # Rule points at an SG this repo doesn't declare (e.g. an id
            # supplied by tfvars). Nothing to conflict with here.
            continue
        sg_file, authoritative = entry
        if not authoritative[direction]:
            continue
        violations += 1
        error(
            f"aws_security_group.{sg_name} declares an inline `{direction}` "
            f"attribute while {len(owners)} standalone {direction} rule "
            f"resource(s) write to the same group: "
            f"{', '.join(sorted(owners))}. `{direction}` is "
            f"Optional+Computed, so this resource is authoritative for the "
            f"whole {direction} set and will revoke the standalone rule(s) "
            f"on the next apply (#3281). Fix: delete the inline "
            f"`{direction}` and express it as a standalone rule resource, "
            f"or add `{direction}` to this resource's "
            f"`lifecycle.ignore_changes`.",
            file=sg_file,
        )

    if violations:
        print(
            f"FAIL: {violations} security group(s) mix inline and standalone "
            f"rule ownership",
            file=sys.stderr,
        )
        return 1

    print(
        f"PASS: {len(groups)} aws_security_group resource(s) checked; "
        f"{len(attached)} group(s) have standalone rule owners and none of "
        f"them also declare an unfrozen inline ingress/egress"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
