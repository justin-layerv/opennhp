#!/usr/bin/env python3
"""Lock the sandbox native-session OP IAM and endpoint authority."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _block(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    quoted = False
    escaped = False
    for index in range(brace, len(source)):
        char = source[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated block: {marker}")


def _session_item_allowed(action: str, key: str, enclosing: str | None) -> bool:
    """Evaluate the closed OP subset rendered by the Terraform statements."""
    base_actions = {
        "dynamodb:ConditionCheckItem",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
    }
    if action not in base_actions:
        return False
    if not key.startswith("OP#"):
        return True
    if action == "dynamodb:PutItem":
        return enclosing == "TransactWriteItems"
    if action == "dynamodb:GetItem":
        return enclosing == "TransactGetItems"
    return False


def _agent_key_allowed(
    action: str, resource: str, enclosing: str | None, exact_table: str
) -> bool:
    return (
        action == "dynamodb:ConditionCheckItem"
        and resource == exact_table
        and enclosing == "TransactWriteItems"
    )


class NativeSessionOperationIAMContractTest(unittest.TestCase):
    def test_rendered_policy_sources_hold_the_transaction_only_fences(self) -> None:
        for relative, write_sid, mutation_sid, read_sid in (
            (
                "terraform/modules/dynamodb/main.tf",
                "DenyDirectNativeSessionOperationWrite",
                "DenyNativeSessionOperationUpdateDelete",
                "DenyDirectNativeSessionOperationRead",
            ),
            (
                "terraform/modules/dynamodb/matched_cohort.tf",
                "DenyCandidateDirectNativeSessionOperationWrite",
                "DenyCandidateNativeSessionOperationUpdateDelete",
                "DenyCandidateDirectNativeSessionOperationRead",
            ),
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            write = _block(source, f'Sid      = "{write_sid}"')
            mutation = _block(source, f'Sid    = "{mutation_sid}"')
            read = _block(source, f'Sid      = "{read_sid}"')
            self.assertIn('"dynamodb:LeadingKeys" = ["OP#*"]', write)
            self.assertIn('"StringNotEqualsIfExists"', write)
            self.assertIn('"dynamodb:EnclosingOperation" = "TransactWriteItems"', write)
            self.assertIn('"dynamodb:DeleteItem"', mutation)
            self.assertIn('"dynamodb:ConditionCheckItem"', mutation)
            self.assertIn('"dynamodb:Query"', mutation)
            self.assertIn('"dynamodb:UpdateItem"', mutation)
            self.assertNotIn('"dynamodb:EnclosingOperation"', mutation)
            self.assertIn('"dynamodb:LeadingKeys" = ["OP#*"]', read)
            self.assertIn('"StringNotEqualsIfExists"', read)
            self.assertIn('"dynamodb:EnclosingOperation" = "TransactGetItems"', read)

    def test_effective_session_policy_truth_table(self) -> None:
        cases = (
            ("direct OP Put", "dynamodb:PutItem", "OP#abc", None, False),
            ("wrong OP Put enclosure", "dynamodb:PutItem", "OP#abc", "TransactGetItems", False),
            ("transactional OP Put", "dynamodb:PutItem", "OP#abc", "TransactWriteItems", True),
            ("direct OP Update", "dynamodb:UpdateItem", "OP#abc", None, False),
            ("transactional OP Update", "dynamodb:UpdateItem", "OP#abc", "TransactWriteItems", False),
            ("direct OP Get", "dynamodb:GetItem", "OP#abc", None, False),
            ("wrong OP Get enclosure", "dynamodb:GetItem", "OP#abc", "TransactWriteItems", False),
            ("transactional OP Get", "dynamodb:GetItem", "OP#abc", "TransactGetItems", True),
            ("OP Query", "dynamodb:Query", "OP#abc", None, False),
            (
                "OP transactional condition",
                "dynamodb:ConditionCheckItem",
                "OP#abc",
                "TransactWriteItems",
                False,
            ),
            ("OP Delete", "dynamodb:DeleteItem", "OP#abc", "TransactWriteItems", False),
            ("ordinary session Put", "dynamodb:PutItem", "SESSION#1", None, True),
            ("ordinary session Get", "dynamodb:GetItem", "SESSION#1", None, True),
        )
        for name, action, key, enclosing, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(_session_item_allowed(action, key, enclosing), expected)

    def test_agent_keys_authority_is_condition_only_on_one_base_table(self) -> None:
        exact = "arn:aws:dynamodb:us-east-2:111122223333:table/control-qurl-agent-keys"
        cases = (
            ("exact condition", "dynamodb:ConditionCheckItem", exact, "TransactWriteItems", True),
            ("direct condition", "dynamodb:ConditionCheckItem", exact, None, False),
            ("wrong transaction", "dynamodb:ConditionCheckItem", exact, "TransactGetItems", False),
            ("index", "dynamodb:ConditionCheckItem", exact + "/index/pubkey-index", "TransactWriteItems", False),
            ("other table", "dynamodb:ConditionCheckItem", exact + "-other", "TransactWriteItems", False),
            ("write", "dynamodb:PutItem", exact, "TransactWriteItems", False),
        )
        for name, action, resource, enclosing, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(_agent_key_allowed(action, resource, enclosing, exact), expected)

        compute = (ROOT / "terraform/modules/compute/main.tf").read_text(encoding="utf-8")
        active = _block(compute, 'Sid      = "ControlIdentityAgentKeysTransactionCondition"')
        self.assertIn('Action   = ["dynamodb:ConditionCheckItem"]', active)
        self.assertIn("Resource = var.control_identity_agent_keys_table_arn", active)
        self.assertIn('"dynamodb:EnclosingOperation" = "TransactWriteItems"', active)
        matched = (ROOT / "terraform/modules/compute/matched_cohort.tf").read_text(encoding="utf-8")
        candidate = _block(
            matched, 'Sid      = "CandidateControlIdentityAgentKeysTransactionCondition"'
        )
        self.assertIn('Action   = ["dynamodb:ConditionCheckItem"]', candidate)
        self.assertIn("Resource = var.control_identity_agent_keys_table_arn", candidate)

    def test_vpc_endpoint_does_not_block_cross_table_transaction_and_kms_is_exact(self) -> None:
        networking = (ROOT / "terraform/modules/networking/vpc_endpoints.tf").read_text(
            encoding="utf-8"
        )
        endpoint = _block(networking, 'resource "aws_vpc_endpoint" "dynamodb"')
        self.assertIsNone(re.search(r"(?m)^\s*policy\s*=", endpoint))

        compute = (ROOT / "terraform/modules/compute/main.tf").read_text(encoding="utf-8")
        kms = _block(compute, 'Sid      = "ControlIdentityAgentKeysKMSDecrypt"')
        self.assertIn('Action   = ["kms:Decrypt"]', kms)
        self.assertIn("Resource = [var.control_identity_kms_key_arn]", kms)
        self.assertIn('"kms:CallerAccount" = data.aws_caller_identity.current.account_id', kms)
        self.assertIn(
            '"kms:ViaService"    = "dynamodb.${var.control_identity_home_region}.amazonaws.com"',
            kms,
        )


if __name__ == "__main__":
    unittest.main()
