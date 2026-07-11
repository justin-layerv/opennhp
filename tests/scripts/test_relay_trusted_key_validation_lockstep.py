#!/usr/bin/env python3

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    (Path("terraform/variables.tf"), "relay_additional_trusted_public_keys_b64"),
    (
        Path("terraform/environments/sandbox/variables.tf"),
        "relay_additional_trusted_public_keys_b64",
    ),
    (
        Path("terraform/environments/prod/variables.tf"),
        "relay_additional_trusted_public_keys_b64",
    ),
    (Path("terraform/modules/compute/variables.tf"), "relay_trusted_public_keys_b64"),
)


def validation_conditions_from_source(
    source: str, path: Path, variable_name: str
) -> list[str]:
    variable_match = re.search(
        rf'(?ms)^variable\s+"{re.escape(variable_name)}"\s*\{{.*?^\}}', source
    )
    if variable_match is None:
        raise AssertionError(f"{path}: missing variable {variable_name}")
    validation_blocks = re.findall(
        r"(?ms)^  validation\s*\{\s*(.*?)^  \}", variable_match.group(0)
    )
    if len(validation_blocks) != 2:
        raise AssertionError(
            f"{path}: {variable_name} must have exactly two validation blocks; "
            f"found {len(validation_blocks)}"
        )

    conditions: list[str] = []
    for block in validation_blocks:
        condition_match = re.search(
            r"(?ms)^\s*condition\s*=\s*(.*?)^\s*error_message\s*=", block
        )
        if condition_match is None:
            raise AssertionError(
                f"{path}: {variable_name} validation lacks condition/error_message"
            )
        normalized = re.sub(
            rf"\bvar\.{re.escape(variable_name)}\b",
            "var.RELAY_TRUST_KEYS",
            condition_match.group(1),
        )
        conditions.append(re.sub(r"\s+", "", normalized))
    return conditions


def validation_conditions(path: Path, variable_name: str) -> list[str]:
    return validation_conditions_from_source(
        (REPO_ROOT / path).read_text(encoding="utf-8"), path, variable_name
    )


class RelayTrustedKeyValidationLockstepTests(unittest.TestCase):
    def test_all_declarations_share_canonical_key_and_ordering_conditions(
        self,
    ) -> None:
        canonical_path, canonical_name = TARGETS[0]
        canonical = validation_conditions(canonical_path, canonical_name)
        self.assertIn("can(base64decode(key))", canonical[0])
        self.assertIn("length(base64decode(key))==32", canonical[0])
        self.assertIn("base64encode(base64decode(key))==key", canonical[0])
        self.assertEqual(
            "var.RELAY_TRUST_KEYS==sort(distinct(var.RELAY_TRUST_KEYS))",
            canonical[1],
        )

        for path, variable_name in TARGETS[1:]:
            with self.subTest(path=path):
                self.assertEqual(
                    canonical,
                    validation_conditions(path, variable_name),
                    f"{path}: relay trust-key validation drifted from {canonical_path}",
                )

    def test_semantic_drift_changes_the_normalized_contract(self) -> None:
        path, variable_name = TARGETS[1]
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        drifted = source.replace(
            "length(base64decode(key)) == 32", "length(base64decode(key)) == 31", 1
        )
        self.assertNotEqual(source, drifted)
        self.assertNotEqual(
            validation_conditions(TARGETS[0][0], TARGETS[0][1]),
            validation_conditions_from_source(drifted, path, variable_name),
        )


if __name__ == "__main__":
    unittest.main()
