#!/usr/bin/env python3
"""Fail when control-plane copies of canonical qURL tables drift in schema.

Operational settings (SSE, PITR, and deletion protection) are deliberately
outside schema parity.
Identity billing, keys, attributes, GSIs, LSIs, TTL, and stream configuration
deliberately stay lockstep; cell-only evolution requires an explicit reviewed
divergence policy.
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path
from typing import Any

import hcl2

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _tf_lint_lib import (  # noqa: E402  # pyright: ignore[reportMissingImports]
    iter_resources,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CELL_TABLES = REPO_ROOT / "terraform/modules/dynamodb/main.tf"
CONTROL_TABLES = (
    REPO_ROOT / "terraform/modules/connector-authority-foundation/dynamodb.tf"
)
TABLE_PAIRS = {
    "qurl_api_keys": "api_keys",
    "qurl_agent_keys": "agent_keys",
    "qurl_customers": "customers",
    "qurl_apikey_idempotency": "api_key_idempotency",
}
SCALAR_COMPARED_FIELDS = frozenset(
    {
        "billing_mode",
        "hash_key",
        "range_key",
        "stream_enabled",
        "stream_view_type",
    }
)
BLOCK_COMPARED_FIELDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "attribute": ("attributes", ("name", "type")),
    "global_secondary_index": (
        "global_secondary_indexes",
        ("name", "hash_key", "range_key", "projection_type", "non_key_attributes"),
    ),
    "local_secondary_index": (
        "local_secondary_indexes",
        ("name", "range_key", "projection_type", "non_key_attributes"),
    ),
    "ttl": ("ttl", ("attribute_name", "enabled")),
}
COMPARED_TOP_LEVEL_FIELDS = SCALAR_COMPARED_FIELDS | BLOCK_COMPARED_FIELDS.keys()
INTENTIONALLY_EXCLUDED_TOP_LEVEL_FIELDS = frozenset(
    {
        # Meta-arguments and deployment ownership differ across the cell and
        # separately-stateful control roots.
        "count",
        "depends_on",
        "for_each",
        "lifecycle",
        "name",
        "provider",
        "tags",
        # Operational posture is deliberately outside schema parity.
        "deletion_protection_enabled",
        "point_in_time_recovery",
        "server_side_encryption",
    }
)


def unquote(value: Any) -> Any:
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
        return json.loads(value)
    return value


def load_tables(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        document = hcl2.load(source)

    tables: dict[str, dict[str, Any]] = {}
    for _file, resource_type, name, body in iter_resources([(path, document)]):
        if resource_type == "aws_dynamodb_table":
            tables[name] = body
    return tables


def normalized_block(block: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for field in fields:
        if field not in block:
            continue
        value = block[field]
        if isinstance(value, list):
            value = sorted(unquote(item) for item in value)
        else:
            value = unquote(value)
        normalized[field] = value
    return normalized


def schema(table: dict[str, Any]) -> dict[str, Any]:
    normalized_schema = {
        field: unquote(table.get(field)) for field in SCALAR_COMPARED_FIELDS
    }
    for source_field, (schema_field, block_fields) in BLOCK_COMPARED_FIELDS.items():
        blocks = [
            normalized_block(block, block_fields)
            for block in table.get(source_field, [])
        ]
        normalized_schema[schema_field] = sorted(
            blocks, key=lambda item: json.dumps(item, sort_keys=True)
        )
    return normalized_schema


def unclassified_top_level_fields(table: dict[str, Any]) -> list[str]:
    """Return real HCL fields missing from the explicit parity policy."""
    classified = COMPARED_TOP_LEVEL_FIELDS | INTENTIONALLY_EXCLUDED_TOP_LEVEL_FIELDS
    return sorted(
        field
        for field in table
        if not field.startswith("__") and field not in classified
    )


def render(value: dict[str, Any]) -> list[str]:
    return json.dumps(value, indent=2, sort_keys=True).splitlines(keepends=True)


def compare_table_schemas(
    cell_tables_path: Path,
    control_tables_path: Path,
    table_pairs: dict[str, str],
) -> int:
    """Compare selected DynamoDB schemas and report every missing/drifted pair."""
    cell_tables = load_tables(cell_tables_path)
    control_tables = load_tables(control_tables_path)
    failed = False

    for cell_name, control_name in table_pairs.items():
        if cell_name not in cell_tables:
            print(
                f"ERROR: canonical table aws_dynamodb_table.{cell_name} is missing",
                file=sys.stderr,
            )
            failed = True
            continue
        if control_name not in control_tables:
            print(
                f"ERROR: control table aws_dynamodb_table.{control_name} is missing",
                file=sys.stderr,
            )
            failed = True
            continue

        pair_has_unclassified_fields = False
        for role, table_name, table in (
            ("canonical", cell_name, cell_tables[cell_name]),
            ("control", control_name, control_tables[control_name]),
        ):
            unclassified = unclassified_top_level_fields(table)
            if not unclassified:
                continue
            print(
                f"ERROR: {role} table {table_name} has unclassified top-level "
                f"fields: {', '.join(unclassified)}; classify each field as "
                "compared or intentionally excluded",
                file=sys.stderr,
            )
            failed = True
            pair_has_unclassified_fields = True
        if pair_has_unclassified_fields:
            continue

        canonical_schema = schema(cell_tables[cell_name])
        control_schema = schema(control_tables[control_name])
        if canonical_schema == control_schema:
            continue

        failed = True
        print(
            f"ERROR: control table {control_name} drifted from canonical {cell_name}:",
            file=sys.stderr,
        )
        sys.stderr.writelines(
            difflib.unified_diff(
                render(canonical_schema),
                render(control_schema),
                fromfile=f"canonical/{cell_name}",
                tofile=f"control/{control_name}",
            )
        )

    if failed:
        return 1

    print("Connector control table schemas match the canonical qURL tables")
    return 0


def main() -> int:
    return compare_table_schemas(CELL_TABLES, CONTROL_TABLES, TABLE_PAIRS)


if __name__ == "__main__":
    raise SystemExit(main())
