#!/usr/bin/env python3
"""Unit tests for the Connector control-table schema comparator."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = (
    REPO_ROOT / ".github" / "scripts" / "check-connector-control-table-schemas.py"
)


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_connector_control_table_schemas", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def table_fixture(
    name: str,
    projection_type: str = "ALL",
    *,
    stream_enabled: bool | None = None,
    stream_view_type: str | None = None,
    lsi_projection_type: str | None = None,
    extra_top_level: str = "",
) -> str:
    stream_lines = ""
    if stream_enabled is not None:
        stream_lines += f"  stream_enabled   = {str(stream_enabled).lower()}\n"
    if stream_view_type is not None:
        stream_lines += f'  stream_view_type = "{stream_view_type}"\n'
    range_key_line = ""
    lsi_attributes = ""
    lsi_block = ""
    if lsi_projection_type is not None:
        range_key_line = '  range_key   = "sk"\n'
        lsi_attributes = '''
  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "lsi_sk"
    type = "S"
  }
'''
        lsi_block = f'''
  local_secondary_index {{
    name            = "by-lsi"
    range_key       = "lsi_sk"
    projection_type = "{lsi_projection_type}"
  }}
'''

    return f'''resource "aws_dynamodb_table" "{name}" {{
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
{range_key_line}
{stream_lines}
{extra_top_level}

  attribute {{
    name = "pk"
    type = "S"
  }}
{lsi_attributes}

  global_secondary_index {{
    name            = "by-pk"
    hash_key        = "pk"
    projection_type = "{projection_type}"
  }}
{lsi_block}

  ttl {{
    attribute_name = "expires_at"
    enabled        = true
  }}
}}
'''


class SchemaComparatorTests(unittest.TestCase):
    def compare_sources(
        self, canonical_source: str, control_source: str
    ) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "canonical.tf"
            control = root / "control.tf"
            canonical.write_text(canonical_source, encoding="utf-8")
            control.write_text(control_source, encoding="utf-8")

            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = CHECKER.compare_table_schemas(
                    canonical, control, {"canonical": "control"}
                )
            return result, stdout.getvalue(), stderr.getvalue()

    def compare(self, control_projection: str) -> tuple[int, str, str]:
        return self.compare_sources(
            table_fixture("canonical"), table_fixture("control", control_projection)
        )

    def test_matching_schema_passes(self) -> None:
        result, stdout, stderr = self.compare("ALL")

        self.assertEqual(result, 0)
        self.assertIn("schemas match", stdout)
        self.assertEqual(stderr, "")

    def test_projection_drift_fails_with_diff(self) -> None:
        result, stdout, stderr = self.compare("KEYS_ONLY")

        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("drifted from canonical", stderr)
        self.assertIn('"projection_type": "ALL"', stderr)
        self.assertIn('"projection_type": "KEYS_ONLY"', stderr)

    def test_stream_configuration_drift_fails_with_diff(self) -> None:
        result, stdout, stderr = self.compare_sources(
            table_fixture(
                "canonical",
                stream_enabled=True,
                stream_view_type="NEW_AND_OLD_IMAGES",
            ),
            table_fixture("control"),
        )

        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("drifted from canonical", stderr)
        self.assertIn('"stream_enabled": true', stderr)
        self.assertIn('"stream_view_type": "NEW_AND_OLD_IMAGES"', stderr)

    def test_local_secondary_index_drift_fails_with_diff(self) -> None:
        result, stdout, stderr = self.compare_sources(
            table_fixture("canonical", lsi_projection_type="ALL"),
            table_fixture("control", lsi_projection_type="KEYS_ONLY"),
        )

        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("drifted from canonical", stderr)
        self.assertIn('"local_secondary_indexes"', stderr)
        self.assertIn('"projection_type": "ALL"', stderr)
        self.assertIn('"projection_type": "KEYS_ONLY"', stderr)

    def test_unclassified_top_level_field_fails_even_when_both_sides_match(
        self,
    ) -> None:
        new_argument = '  table_class = "STANDARD_INFREQUENT_ACCESS"\n'
        result, stdout, stderr = self.compare_sources(
            table_fixture("canonical", extra_top_level=new_argument),
            table_fixture("control", extra_top_level=new_argument),
        )

        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("canonical table canonical", stderr)
        self.assertIn("control table control", stderr)
        self.assertIn("unclassified top-level fields: table_class", stderr)


if __name__ == "__main__":
    unittest.main()
