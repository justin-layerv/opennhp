#!/usr/bin/env python3
"""Plan, apply, or verify the exact qURL Sharing canonical machine owner."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from typing import Any, Callable


INTENT_SCHEMA = "layerv.durable-aop-customer-owner-intent.v1"
TABLE = "layerv-nhp-sandbox-control-qurl-customers"
REGION = "us-east-2"
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ROW_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
UINT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
CELL_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_INT64 = (1 << 63) - 1
REQUIRED_FIELDS = {
    "auth0_subject",
    "email",
    "tier",
    "frozen",
    "frozen_reason",
    "created_at",
    "updated_at",
    "current_period_usage",
    "spending_cap_cents",
    "unit_price_cents",
}
OPTIONAL_FIELDS = {"assigned_cell_id"}
INTENT_FIELDS = {
    "action",
    "before_row_sha256",
    "client_id",
    "email",
    "expected_row_sha256",
    "expected_created_at",
    "expected_updated_at",
    "expected_usage",
    "expected_assigned_cell_id",
    "provisioned_at",
    "region",
    "schema",
    "source_sha",
    "subject",
    "table",
}


class ProjectionError(RuntimeError):
    """The owner cannot be projected without weakening an exact authority."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def strict_json(raw: str, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProjectionError(f"{label} repeats a JSON field")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except ProjectionError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"{label} is not canonical JSON") from exc


def exact_attr(item: dict[str, Any], name: str, kind: str) -> Any:
    value = item.get(name)
    if not isinstance(value, dict) or set(value) != {kind}:
        raise ProjectionError(f"customer row {name} must be one DynamoDB {kind}")
    return value[kind]


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        raise ProjectionError(f"{label} must be canonical RFC3339 UTC seconds")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise ProjectionError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ProjectionError(f"{label} is not canonical RFC3339 UTC seconds")
    return parsed


def machine_identity(client_id: str) -> tuple[str, str]:
    if CLIENT_ID_RE.fullmatch(client_id) is None:
        raise ProjectionError("client id is not the exact 32-character Auth0 shape")
    return (
        f"{client_id}@clients",
        f"{client_id.lower()}-clients@machine.notify.layerv.xyz",
    )


def row_digest(item: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(item).encode()).hexdigest()


def validate_row(
    item: Any,
    subject: str,
    email: str,
    *,
    tier: str | None = None,
) -> dict[str, Any]:
    if not isinstance(item, dict) or not REQUIRED_FIELDS.issubset(item):
        raise ProjectionError("customer row is missing canonical owner fields")
    if set(item) - REQUIRED_FIELDS not in (set(), OPTIONAL_FIELDS):
        raise ProjectionError("customer row has fields outside the reviewed owner shape")
    stored_subject = exact_attr(item, "auth0_subject", "S")
    stored_email = exact_attr(item, "email", "S")
    stored_tier = exact_attr(item, "tier", "S")
    frozen = exact_attr(item, "frozen", "BOOL")
    reason = exact_attr(item, "frozen_reason", "S")
    created = exact_attr(item, "created_at", "S")
    updated = exact_attr(item, "updated_at", "S")
    usage = exact_attr(item, "current_period_usage", "N")
    spending = exact_attr(item, "spending_cap_cents", "N")
    price = exact_attr(item, "unit_price_cents", "N")
    if stored_subject != subject or stored_email != email:
        raise ProjectionError("customer row identity differs from the dedicated machine owner")
    allowed_tiers = {tier} if tier is not None else {"free", "system"}
    if stored_tier not in allowed_tiers:
        raise ProjectionError("customer row tier is paid, unknown, or ineligible")
    if frozen is not False or reason != "":
        raise ProjectionError("customer row is frozen or has a freeze reason")
    if parse_timestamp(updated, "customer updated_at") < parse_timestamp(
        created, "customer created_at"
    ):
        raise ProjectionError("customer row timestamps are out of order")
    for value, label in ((usage, "usage"), (spending, "spending cap"), (price, "unit price")):
        if not isinstance(value, str) or UINT_RE.fullmatch(value) is None or int(value) > MAX_INT64:
            raise ProjectionError(f"customer row {label} is not a non-negative int64")
    if spending != "0" or price != "0":
        raise ProjectionError("customer row has paid billing authority")
    if "assigned_cell_id" in item:
        assigned = exact_attr(item, "assigned_cell_id", "S")
        if not isinstance(assigned, str) or len(assigned) > 32 or CELL_RE.fullmatch(assigned) is None:
            raise ProjectionError("customer row assigned_cell_id is not canonical")
    return item


def absent_row(subject: str, email: str, provisioned_at: str) -> dict[str, Any]:
    return {
        "auth0_subject": {"S": subject},
        "created_at": {"S": provisioned_at},
        "current_period_usage": {"N": "0"},
        "email": {"S": email},
        "frozen": {"BOOL": False},
        "frozen_reason": {"S": ""},
        "spending_cap_cents": {"N": "0"},
        "tier": {"S": "system"},
        "unit_price_cents": {"N": "0"},
        "updated_at": {"S": provisioned_at},
    }


def expected_row_from_intent(intent: dict[str, Any]) -> dict[str, Any]:
    row = {
        "auth0_subject": {"S": intent["subject"]},
        "created_at": {"S": intent["expected_created_at"]},
        "current_period_usage": {"N": intent["expected_usage"]},
        "email": {"S": intent["email"]},
        "frozen": {"BOOL": False},
        "frozen_reason": {"S": ""},
        "spending_cap_cents": {"N": "0"},
        "tier": {"S": "system"},
        "unit_price_cents": {"N": "0"},
        "updated_at": {"S": intent["expected_updated_at"]},
    }
    if intent["expected_assigned_cell_id"]:
        row["assigned_cell_id"] = {"S": intent["expected_assigned_cell_id"]}
    return row


def aws_json(result: subprocess.CompletedProcess[str], label: str) -> dict[str, Any]:
    value = strict_json(result.stdout, label)
    if not isinstance(value, dict):
        raise ProjectionError(f"{label} returned a non-object")
    return value


def strong_read(table: str, subject: str, region: str, runner: Runner) -> dict[str, Any] | None:
    key = canonical_json({"auth0_subject": {"S": subject}})
    result = runner(
        [
            "aws",
            "--region",
            region,
            "dynamodb",
            "get-item",
            "--table-name",
            table,
            "--key",
            key,
            "--consistent-read",
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_PAGER": ""},
    )
    response = aws_json(result, "strong customer read")
    if set(response) not in (set(), {"Item"}):
        raise ProjectionError("strong customer read did not return the exact requested shape")
    item = response.get("Item")
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ProjectionError("strong customer read returned a malformed item")
    return item


def validate_inputs(table: str, region: str, source_sha: str, provisioned_at: str) -> None:
    if table != TABLE or region != REGION:
        raise ProjectionError("table or region differs from the reviewed sandbox authority")
    if not isinstance(source_sha, str) or SHA_RE.fullmatch(source_sha) is None:
        raise ProjectionError("source SHA must be exact lowercase 40-hex")
    parse_timestamp(provisioned_at, "owner provisioned_at")


def plan(
    table: str,
    client_id: str,
    region: str,
    provisioned_at: str,
    source_sha: str,
    *,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    validate_inputs(table, region, source_sha, provisioned_at)
    subject, email = machine_identity(client_id)
    current = strong_read(table, subject, region, runner)
    intent_provisioned_at = provisioned_at
    if current is None:
        action = "create"
        before = "absent"
        expected = absent_row(subject, email, provisioned_at)
    else:
        validate_row(current, subject, email)
        before = row_digest(current)
        if exact_attr(current, "tier", "S") == "free":
            action = "promote"
            expected = json.loads(canonical_json(current))
            expected["tier"] = {"S": "system"}
            # Promotion changes only tier. Preserve both timestamps and use
            # the existing updated_at as the durable owner-ready boundary.
            intent_provisioned_at = exact_attr(current, "updated_at", "S")
        else:
            action = "replay"
            expected = current
            # No write occurs for an exact system replay. Its existing update
            # timestamp is therefore the durable owner-ready timestamp.
            intent_provisioned_at = exact_attr(current, "updated_at", "S")
        validate_row(expected, subject, email, tier="system")
    assigned = expected.get("assigned_cell_id", {"S": ""})["S"]
    return {
        "action": action,
        "before_row_sha256": before,
        "client_id": client_id,
        "email": email,
        "expected_row_sha256": row_digest(expected),
        "expected_created_at": exact_attr(expected, "created_at", "S"),
        "expected_updated_at": exact_attr(expected, "updated_at", "S"),
        "expected_usage": exact_attr(expected, "current_period_usage", "N"),
        "expected_assigned_cell_id": assigned,
        "provisioned_at": intent_provisioned_at,
        "region": region,
        "schema": INTENT_SCHEMA,
        "source_sha": source_sha,
        "subject": subject,
        "table": table,
    }


def validate_intent(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != INTENT_FIELDS:
        raise ProjectionError("owner intent has an unexpected field set")
    if value.get("schema") != INTENT_SCHEMA:
        raise ProjectionError("owner intent schema is unsupported")
    client_id = value.get("client_id")
    if not isinstance(client_id, str):
        raise ProjectionError("owner intent client id is malformed")
    subject, email = machine_identity(client_id)
    if value.get("subject") != subject or value.get("email") != email:
        raise ProjectionError("owner intent identity is not derived from its client id")
    validate_inputs(
        value.get("table"), value.get("region"), value.get("source_sha"), value.get("provisioned_at")
    )
    action = value.get("action")
    before = value.get("before_row_sha256")
    expected = value.get("expected_row_sha256")
    if (
        action not in {"create", "promote", "replay"}
        or not isinstance(expected, str)
        or ROW_SHA_RE.fullmatch(expected) is None
    ):
        raise ProjectionError("owner intent action or final digest is malformed")
    if action == "create" and before != "absent":
        raise ProjectionError("owner create intent has a non-absent prior row")
    if (
        action in {"promote", "replay"}
        and (not isinstance(before, str) or ROW_SHA_RE.fullmatch(before) is None)
    ):
        raise ProjectionError("owner existing-row intent lacks an exact prior digest")
    if action == "replay" and before != expected:
        raise ProjectionError("owner replay intent changes the row")
    created = value.get("expected_created_at")
    updated = value.get("expected_updated_at")
    usage = value.get("expected_usage")
    assigned = value.get("expected_assigned_cell_id")
    created_at = parse_timestamp(created, "owner intent expected_created_at")
    updated_at = parse_timestamp(updated, "owner intent expected_updated_at")
    provisioned_at = parse_timestamp(value.get("provisioned_at"), "owner intent provisioned_at")
    if updated_at < created_at or updated_at < provisioned_at:
        raise ProjectionError("owner intent timestamps are not monotonic")
    if not isinstance(usage, str) or UINT_RE.fullmatch(usage) is None or int(usage) > MAX_INT64:
        raise ProjectionError("owner intent expected usage is malformed")
    if not isinstance(assigned, str) or (
        assigned != "" and (len(assigned) > 32 or CELL_RE.fullmatch(assigned) is None)
    ):
        raise ProjectionError("owner intent assigned cell is malformed")
    reconstructed = expected_row_from_intent(value)
    validate_row(reconstructed, subject, email, tier="system")
    if row_digest(reconstructed) != expected:
        raise ProjectionError("owner intent final digest does not match its persisted anchors")
    return value


def promotion_transaction(table: str, current: dict[str, Any]) -> list[dict[str, Any]]:
    names = {
        "#assigned": "assigned_cell_id",
        "#created": "created_at",
        "#email": "email",
        "#frozen": "frozen",
        "#hardware": "hardware_key_storage",
        "#price": "unit_price_cents",
        "#reason": "frozen_reason",
        "#spending": "spending_cap_cents",
        "#stripe": "stripe_customer_id",
        "#subject": "auth0_subject",
        "#tier": "tier",
        "#updated": "updated_at",
        "#usage": "current_period_usage",
    }
    values = {
        ":created": current["created_at"],
        ":email": current["email"],
        ":false": {"BOOL": False},
        ":free": {"S": "free"},
        ":price": current["unit_price_cents"],
        ":reason": current["frozen_reason"],
        ":spending": current["spending_cap_cents"],
        ":subject": current["auth0_subject"],
        ":system": {"S": "system"},
        ":updated": current["updated_at"],
        ":usage": current["current_period_usage"],
    }
    conditions = [
        "#subject = :subject",
        "#email = :email",
        "#tier = :free",
        "#frozen = :false",
        "#reason = :reason",
        "#created = :created",
        "#updated = :updated",
        "#usage = :usage",
        "#spending = :spending",
        "#price = :price",
        "attribute_not_exists(#stripe)",
        "attribute_not_exists(#hardware)",
    ]
    if "assigned_cell_id" in current:
        values[":assigned"] = current["assigned_cell_id"]
        conditions.append("#assigned = :assigned")
    else:
        conditions.append("attribute_not_exists(#assigned)")
    return [
        {
            "Update": {
                "ConditionExpression": " AND ".join(conditions),
                "ExpressionAttributeNames": names,
                "ExpressionAttributeValues": values,
                "Key": {"auth0_subject": current["auth0_subject"]},
                "TableName": table,
                "UpdateExpression": "SET #tier = :system",
            }
        }
    ]


def create_transaction(table: str, expected: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "Put": {
                "ConditionExpression": "attribute_not_exists(#subject)",
                "ExpressionAttributeNames": {"#subject": "auth0_subject"},
                "Item": expected,
                "TableName": table,
            }
        }
    ]


def apply_intent(intent: dict[str, Any], *, runner: Runner = subprocess.run) -> str:
    intent = validate_intent(intent)
    table = intent["table"]
    region = intent["region"]
    subject = intent["subject"]
    email = intent["email"]
    expected_digest = intent["expected_row_sha256"]
    current = strong_read(table, subject, region, runner)
    if current is not None:
        try:
            validate_row(current, subject, email, tier="system")
        except ProjectionError:
            pass
        else:
            if row_digest(current) == expected_digest:
                return expected_digest
    if intent["action"] == "replay":
        raise ProjectionError("owner replay row differs from the precommitted digest")
    if intent["action"] == "create":
        if current is not None:
            raise ProjectionError("owner create intent found a different existing row")
        expected = expected_row_from_intent(intent)
        if row_digest(expected) != expected_digest:
            raise ProjectionError("owner create intent final digest is inconsistent")
        transaction = create_transaction(table, expected)
    else:
        if current is None:
            raise ProjectionError("owner promotion intent lost its prior row")
        validate_row(current, subject, email, tier="free")
        if row_digest(current) != intent["before_row_sha256"]:
            raise ProjectionError("owner promotion prior row differs from its intent")
        expected = expected_row_from_intent(intent)
        if row_digest(expected) != expected_digest:
            raise ProjectionError("owner promotion intent final digest is inconsistent")
        transaction = promotion_transaction(table, current)
    transaction_json = canonical_json(transaction)
    token = "qshare-" + hashlib.sha256(transaction_json.encode()).hexdigest()[:29]
    result = runner(
        [
            "aws",
            "--region",
            region,
            "dynamodb",
            "transact-write-items",
            "--client-request-token",
            token,
            "--transact-items",
            transaction_json,
            "--output",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "AWS_PAGER": ""},
    )
    # A transport error or lost response is successful only when a fresh strong
    # read equals the digest committed before this transaction was attempted.
    final = strong_read(table, subject, region, runner)
    if final is not None:
        validate_row(final, subject, email, tier="system")
        if row_digest(final) == expected_digest:
            return expected_digest
    if result.returncode != 0:
        raise ProjectionError("owner transaction failed and no exact committed result exists")
    raise ProjectionError("owner transaction returned success without the exact final row")


def verify_intent(intent: dict[str, Any], *, runner: Runner = subprocess.run) -> str:
    intent = validate_intent(intent)
    current = strong_read(intent["table"], intent["subject"], intent["region"], runner)
    if current is None:
        raise ProjectionError("owner row is absent after owner_ready")
    validate_row(current, intent["subject"], intent["email"], tier="system")
    digest = row_digest(current)
    if digest != intent["expected_row_sha256"]:
        raise ProjectionError("owner row differs from the precommitted final digest")
    return digest


def verify_current_owner(intent: dict[str, Any], *, runner: Runner = subprocess.run) -> str:
    """Verify the live canonical owner while allowing normal usage descendants."""
    intent = validate_intent(intent)
    current = strong_read(intent["table"], intent["subject"], intent["region"], runner)
    if current is None:
        raise ProjectionError("canonical owner row is absent")
    validate_row(current, intent["subject"], intent["email"], tier="system")
    if exact_attr(current, "created_at", "S") != intent["expected_created_at"]:
        raise ProjectionError("canonical owner created_at changed after owner_ready")
    current_updated = parse_timestamp(
        exact_attr(current, "updated_at", "S"), "canonical owner updated_at"
    )
    minimum_updated = parse_timestamp(
        intent["expected_updated_at"], "owner intent expected_updated_at"
    )
    if current_updated < minimum_updated:
        raise ProjectionError("canonical owner updated_at rolled back after owner_ready")
    current_usage = int(exact_attr(current, "current_period_usage", "N"))
    if current_usage < int(intent["expected_usage"]):
        raise ProjectionError("canonical owner usage rolled back after owner_ready")
    if exact_attr(current, "assigned_cell_id", "S") != "cell0":
        raise ProjectionError("canonical owner is not pinned to exact cell0 after lifecycle")
    return row_digest(current)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--table", required=True)
    plan_parser.add_argument("--client-id", required=True)
    plan_parser.add_argument("--region", required=True)
    plan_parser.add_argument("--provisioned-at", required=True)
    plan_parser.add_argument("--source-sha", required=True)
    for name in ("apply", "verify", "verify-current"):
        command = sub.add_parser(name)
        command.add_argument("--intent-json", required=True)
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(
            canonical_json(
                plan(
                    args.table,
                    args.client_id,
                    args.region,
                    args.provisioned_at,
                    args.source_sha,
                )
            )
        )
    else:
        intent = validate_intent(strict_json(args.intent_json, "owner intent"))
        if args.command == "apply":
            digest = apply_intent(intent)
        elif args.command == "verify":
            digest = verify_intent(intent)
        else:
            digest = verify_current_owner(intent)
        print(digest)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ProjectionError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: customer-owner projection failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
