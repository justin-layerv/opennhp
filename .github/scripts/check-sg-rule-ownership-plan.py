#!/usr/bin/env python3
"""Gate a saved plan against unsafe security-group rule mutations (#3281).

The #3281 ownership transition moves a live production rule from an inline
`ingress` block to a standalone `aws_vpc_security_group_ingress_rule`. Done
right that is a pure state-ownership change: the rule is *adopted*, not
revoked and recreated. Done wrong it is an outage on a security group that
fronts live Redis traffic.

The source lint (`check-terraform-sg-rule-ownership.py`) proves the config
can no longer express mixed ownership. This script proves the specific
plan about to be applied is non-disruptive, which is the assertion an
approver actually needs:

  1. No security group is replaced or destroyed. Replacing an SG detaches
     every ENI attached to it.
  2. No rule resource is destroyed, and no rule is replaced. A standalone
     rule that replaces is a revoke followed by a re-authorize — a real
     gap, however brief, on a group serving live traffic.
  3. No `aws_security_group` update removes an entry from its inline
     `ingress`/`egress` list. This is the exact revocation the mixed
     ownership was arming: the SG silently dropping a rule some other
     resource owns.
  4. No rule is broadened. Port range must not widen, protocol must not
     become "all", and the source must not change (a swapped CIDR or
     referenced group is a different grant, and a widened CIDR prefix is
     strictly more access).

Rules being *added* are reported but not failed — a transition may
legitimately introduce a rule. Adoption via `import` is the expected shape
here and is called out explicitly in the summary.

`--only SUBSTR` restricts the check to resource addresses containing
SUBSTR. Default is the whole plan, which is the stricter and preferred
mode; scope it only when an unrelated in-flight migration is in the same
plan and you need to gate one transition on its own. The summary always
states how many changes were skipped so a filter cannot silently hide a
finding.

Usage: check-sg-rule-ownership-plan.py <plan.json> [--only SUBSTR] [--quiet]
Exit 0 clean, 1 on violation, 2 on unusable input.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

SG_TYPE = "aws_security_group"
RULE_TYPES = {
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
}
# Attributes whose change would grant access to a different or larger set
# of sources than the reviewed rule did.
SOURCE_ATTRS = (
    "cidr_ipv4",
    "cidr_ipv6",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "prefix_list_id",
    "prefix_list_ids",
    "referenced_security_group_id",
    "source_security_group_id",
    "self",
)
# Protocol values meaning "every protocol".
ANY_PROTOCOL = {"-1", "all"}


def error(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)


def _port_span(state: dict[str, Any]) -> tuple[int, int] | None:
    """Return (from_port, to_port) when both are concrete integers."""
    lo, hi = state.get("from_port"), state.get("to_port")
    if isinstance(lo, bool) or isinstance(hi, bool):
        return None
    if not isinstance(lo, int) or not isinstance(hi, int):
        return None
    return lo, hi


def _protocol(state: dict[str, Any]) -> str | None:
    # `aws_security_group_rule` calls it `protocol`; the vpc_* pair calls
    # it `ip_protocol`.
    for key in ("ip_protocol", "protocol"):
        value = state.get(key)
        if isinstance(value, str):
            return value.lower()
    return None


def _cidr_widened(before: Any, after: Any) -> bool:
    """True when `after` is a strict superset of `before` as an IP network.

    Falls back to False for anything unparseable — the caller already
    fails on any source change, so this only decides whether the message
    says "widened" or "changed".
    """
    try:
        b = ipaddress.ip_network(before, strict=False)
        a = ipaddress.ip_network(after, strict=False)
    except (ValueError, TypeError):
        return False
    return b.version == a.version and b.subnet_of(a) and b != a


def main() -> int:
    argv = sys.argv[1:]
    quiet = "--quiet" in argv
    only: str | None = None
    args: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--quiet":
            i += 1
        elif argv[i] == "--only":
            if i + 1 >= len(argv):
                error("--only requires a value")
                return 2
            only = argv[i + 1]
            i += 2
        elif argv[i].startswith("--only="):
            only = argv[i].split("=", 1)[1]
            i += 1
        else:
            args.append(argv[i])
            i += 1
    if len(args) != 1:
        error(
            "usage: check-sg-rule-ownership-plan.py <plan.json> "
            "[--only SUBSTR] [--quiet]"
        )
        return 2
    path = Path(args[0])
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"could not read plan JSON {path}: {exc}")
        return 2

    violations: list[str] = []
    notes: list[str] = []
    sg_seen = rules_seen = imported = skipped = 0

    for rc in plan.get("resource_changes", []) or []:
        rtype = rc.get("type")
        if rtype != SG_TYPE and rtype not in RULE_TYPES:
            continue
        address = rc.get("address", "<unknown>")
        change = rc.get("change", {}) or {}
        actions = change.get("actions", []) or []
        if actions == ["no-op"] and not change.get("importing"):
            continue
        if only is not None and only not in address:
            skipped += 1
            continue
        before = change.get("before") or {}
        after = change.get("after") or {}
        if rtype == SG_TYPE:
            sg_seen += 1
        else:
            rules_seen += 1
        if change.get("importing"):
            imported += 1
            notes.append(f"{address}: adopted via import (no AWS mutation)")

        replaced = "create" in actions and "delete" in actions
        destroyed = actions == ["delete"]

        # --- 1 & 2: no destroy, no replace -----------------------------
        if rtype == SG_TYPE and (replaced or destroyed):
            violations.append(
                f"{address}: security group would be "
                f"{'REPLACED' if replaced else 'DESTROYED'} — this detaches "
                f"every ENI using it. Rule-ownership transitions must never "
                f"touch the group itself."
            )
            continue
        if rtype in RULE_TYPES and (replaced or destroyed):
            violations.append(
                f"{address}: rule would be "
                f"{'REPLACED (revoke + re-authorize)' if replaced else 'DESTROYED'}"
                f" — that is a reachability gap on a live security group. An "
                f"ownership move must adopt the existing rule via `import`, "
                f"not recreate it."
            )
            continue

        # --- 3: inline rule set must not shrink ------------------------
        if rtype == SG_TYPE and "update" in actions:
            for attr in ("ingress", "egress"):
                b_list = before.get(attr) or []
                a_list = after.get(attr) or []
                if not isinstance(b_list, list) or not isinstance(a_list, list):
                    continue
                # Compare structurally; entries are dicts of primitives and
                # lists, so canonical JSON is a stable identity.
                a_keys = {json.dumps(e, sort_keys=True) for e in a_list}
                dropped = [
                    e for e in b_list if json.dumps(e, sort_keys=True) not in a_keys
                ]
                for entry in dropped:
                    violations.append(
                        f"{address}: inline `{attr}` drops a rule "
                        f"({entry.get('description') or entry!r}) — this is "
                        f"the silent revocation #3281 exists to prevent. The "
                        f"group is authoritative for `{attr}` and is removing "
                        f"a rule another resource owns."
                    )

        # --- 4: no broadening ------------------------------------------
        if rtype in RULE_TYPES and "update" in actions:
            b_span, a_span = _port_span(before), _port_span(after)
            if b_span and a_span and (a_span[0] < b_span[0] or a_span[1] > b_span[1]):
                violations.append(
                    f"{address}: port range widens from {b_span[0]}-{b_span[1]} "
                    f"to {a_span[0]}-{a_span[1]}."
                )
            b_proto, a_proto = _protocol(before), _protocol(after)
            if b_proto is not None and a_proto is not None and b_proto != a_proto:
                if a_proto in ANY_PROTOCOL:
                    violations.append(
                        f"{address}: protocol broadens from {b_proto!r} to "
                        f"{a_proto!r} (all protocols)."
                    )
                else:
                    violations.append(
                        f"{address}: protocol changes from {b_proto!r} to "
                        f"{a_proto!r} — a different grant than the one reviewed."
                    )
            for attr in SOURCE_ATTRS:
                if attr not in before and attr not in after:
                    continue
                b_val, a_val = before.get(attr), after.get(attr)
                if b_val == a_val:
                    continue
                kind = (
                    "WIDENS"
                    if _cidr_widened(b_val, a_val)
                    else "changes (not necessarily wider, but not the reviewed grant)"
                )
                violations.append(
                    f"{address}: source `{attr}` {kind}: {b_val!r} -> {a_val!r}."
                )

    if violations:
        for v in violations:
            error(v)
        print(
            f"FAIL: {len(violations)} unsafe security-group change(s) in {path}",
            file=sys.stderr,
        )
        return 1

    if notes and not quiet:
        for n in notes:
            print(f"  note: {n}")
    print(
        f"PASS: {sg_seen} security group change(s) and {rules_seen} rule "
        f"change(s) inspected in {path}; no replacement, no destroy, no "
        f"inline-rule removal, no broadened source/port/protocol"
        + (f"; {imported} adopted via import" if imported else "")
        + (
            f"; {skipped} change(s) SKIPPED by --only {only!r} and NOT checked"
            if only is not None
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
