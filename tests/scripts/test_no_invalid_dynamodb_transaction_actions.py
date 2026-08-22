#!/usr/bin/env python3
"""Prevent nonexistent DynamoDB transaction API names from becoming IAM actions."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_SOURCE_SUFFIXES = {
    ".go",
    ".hcl",
    ".json",
    ".py",
    ".sh",
    ".tf",
    ".tftpl",
    ".yaml",
    ".yml",
}
SKIPPED_TOP_LEVEL = {"docs", "tests", "vendor"}
# This checker validates the exact old -> corrected policy transition. Its old
# action literals are migration input, never an emitted after-policy.
MIGRATION_INPUT_FILES = {
    Path(".github/scripts/check-control-sandbox-first-apply.py"),
}
INVALID_ACTION = re.compile(
    r"(?<![A-Za-z0-9_.:/-])dynamodb:Transact(?:Get|Write)Items"
    r"(?![A-Za-z0-9_.:/-])",
    re.IGNORECASE,
)


def policy_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in POLICY_SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if relative.parts[0] in SKIPPED_TOP_LEVEL or "tests" in relative.parts:
            continue
        if ".terraform" in relative.parts or relative in MIGRATION_INPUT_FILES:
            continue
        yield relative, path


def invalid_action_literals(root: Path) -> list[str]:
    findings = []
    for relative, path in policy_source_files(root):
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if INVALID_ACTION.search(line):
                findings.append(f"{relative}:{line_number}:{line.strip()}")
    return findings


class InvalidDynamoDBTransactionActionTest(unittest.TestCase):
    def test_repository_policy_sources_have_no_invalid_transaction_actions(
        self,
    ) -> None:
        self.assertEqual(invalid_action_literals(ROOT), [])

    def test_invalid_iam_action_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.tf"
            policy.write_text(
                'Action = ["dynamodb:TransactWriteItems"]\n', encoding="utf-8"
            )
            self.assertEqual(
                invalid_action_literals(root),
                ['policy.tf:1:Action = ["dynamodb:TransactWriteItems"]'],
            )

    def test_unquoted_yaml_iam_action_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.yml"
            policy.write_text(
                "Action:\n  - dynamodb:TransactWriteItems\n", encoding="utf-8"
            )
            self.assertEqual(
                invalid_action_literals(root),
                ["policy.yml:2:- dynamodb:TransactWriteItems"],
            )

    def test_iam_action_detection_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.yaml"
            policy.write_text("Action: DYNAMODB:transactgetITEMS\n", encoding="utf-8")
            self.assertEqual(
                invalid_action_literals(root),
                ["policy.yaml:1:Action: DYNAMODB:transactgetITEMS"],
            )

    def test_enclosing_operation_condition_is_not_an_iam_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.tf"
            policy.write_text(
                '"dynamodb:EnclosingOperation" = ["TransactWriteItems"]\n',
                encoding="utf-8",
            )
            self.assertEqual(invalid_action_literals(root), [])


if __name__ == "__main__":
    unittest.main()
