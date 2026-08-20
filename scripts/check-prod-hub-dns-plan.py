#!/usr/bin/env python3
"""Fail closed unless a saved plan is inert or creates the exact Hub alias."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """Raised when a plan exceeds the production Hub DNS boundary."""


ALLOWED_OUTPUTS = {"hub_fqdn", "hub_nlb_dns_name", "hub_nlb_zone_id"}


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def check_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan.get("format_version"), str) or not isinstance(
        plan.get("terraform_version"), str
    ):
        raise ContractError("plan is missing Terraform format/version identity")
    if "resource_changes" not in plan:
        raise ContractError("plan is missing resource_changes")
    changes = plan["resource_changes"]
    if not isinstance(changes, list):
        raise ContractError("resource_changes must be an array")

    seen: set[str] = set()
    for raw_change in changes:
        item = require_object(raw_change, "resource change")
        address = item.get("address")
        if not isinstance(address, str) or address in seen:
            raise ContractError(f"resource change has invalid or duplicate address: {address!r}")
        seen.add(address)

        change = require_object(item.get("change"), f"{address}.change")
        actions = change.get("actions")
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            raise ContractError(f"{address}.change.actions must be a string array")

        if address == "data.aws_lb.hub[0]":
            if item.get("mode") != "data" or item.get("type") != "aws_lb":
                raise ContractError(f"{address} is not the exact Hub NLB data source")
            if actions not in (["read"], ["no-op"]):
                raise ContractError(f"{address} has forbidden actions: {actions}")
            continue

        if address == "aws_route53_record.hub[0]":
            if item.get("mode", "managed") != "managed" or item.get(
                "type"
            ) != "aws_route53_record":
                raise ContractError(f"{address} is not the exact Hub DNS resource")
            if actions not in (["create"], ["no-op"]):
                raise ContractError(f"{address} has forbidden actions: {actions}")

            after = require_object(change.get("after"), f"{address}.change.after")
            for key, expected in (
                ("name", "hub.nhp.layerv.ai"),
                ("type", "A"),
                ("zone_id", "Z0748438C8EK6UAW94ST"),
            ):
                if after.get(key) != expected:
                    raise ContractError(
                        f"{address} {key} must be {expected!r}, got {after.get(key)!r}"
                    )
            aliases = after.get("alias")
            if not isinstance(aliases, list) or len(aliases) != 1:
                raise ContractError(f"{address} must have exactly one alias target")
            alias = require_object(aliases[0], f"{address}.alias[0]")
            if alias.get("evaluate_target_health") is not True:
                raise ContractError(f"{address} must evaluate target health")
            continue

        raise ContractError(f"unexpected resource in production Hub DNS plan: {address}")

    outputs = plan.get("output_changes", {})
    if outputs is None:
        outputs = {}
    if not isinstance(outputs, dict):
        raise ContractError("output_changes must be an object")
    unexpected_outputs = set(outputs) - ALLOWED_OUTPUTS
    if unexpected_outputs:
        raise ContractError(
            "unexpected output changes: " + ", ".join(sorted(unexpected_outputs))
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()

    try:
        with args.plan_json.open(encoding="utf-8") as handle:
            plan = require_object(json.load(handle), "plan")
        check_plan(plan)
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: production Hub DNS plan rejected: {exc}", file=sys.stderr)
        return 1

    print("OK: production Hub DNS plan is inert or an exact Hub A-alias create")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
