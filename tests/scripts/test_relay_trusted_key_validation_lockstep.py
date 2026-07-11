#!/usr/bin/env python3

from __future__ import annotations

import base64
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
STANDARD_BASE64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
CANONICAL_FINAL_CHARS = "AEIMQUYcgkosw048"
CANONICAL_X25519_PUBLIC_KEY_PATTERN = re.compile(
    rf"^[A-Za-z0-9+/]{{42}}[{CANONICAL_FINAL_CHARS}]=$"
)
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
        self.assertIn(
            'can(regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$",key))',
            canonical[0],
        )
        self.assertNotIn("base64decode", canonical[0])
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
            "[A-Za-z0-9+/]{42}", "[A-Za-z0-9+/]{41}", 1
        )
        self.assertNotEqual(source, drifted)
        self.assertNotEqual(
            validation_conditions(TARGETS[0][0], TARGETS[0][1]),
            validation_conditions_from_source(drifted, path, variable_name),
        )

    def test_byte_safe_pattern_accepts_non_utf8_key_and_rejects_near_misses(
        self,
    ) -> None:
        # This is the valid live key that exposed Terraform base64decode's
        # text-only behavior: the decoded X25519 bytes are not UTF-8.
        live_key = "tP4JYpmBTd/8tgqh0E2yP9mqxp5pg+4A7sXYscnJ5lM="
        decoded = base64.b64decode(live_key, validate=True)
        self.assertEqual(32, len(decoded))
        with self.assertRaises(UnicodeDecodeError):
            decoded.decode("utf-8")
        self.assertEqual(CANONICAL_FINAL_CHARS, STANDARD_BASE64_ALPHABET[::4])
        valid_keys = (
            live_key,
            base64.b64encode(b"\x00" * 32).decode("ascii"),
            base64.b64encode(b"\xff" * 32).decode("ascii"),
            base64.b64encode(bytes(range(32))).decode("ascii"),
        )
        for key in valid_keys:
            with self.subTest(valid_key=key):
                self.assertIsNotNone(
                    CANONICAL_X25519_PUBLIC_KEY_PATTERN.fullmatch(key)
                )

        noncanonical_same_bytes = f"{live_key[:-2]}N="
        self.assertEqual(
            decoded,
            base64.b64decode(noncanonical_same_bytes, validate=True),
            "the fixture must differ only in ignored non-zero pad bits",
        )
        invalid_keys = (
            base64.b64encode(b"\xff" * 31).decode("ascii"),
            base64.b64encode(b"\xff" * 33).decode("ascii"),
            f"-{live_key[1:]}",
            base64.urlsafe_b64encode(b"\xff" * 32).decode("ascii"),
            live_key.removesuffix("="),
            noncanonical_same_bytes,
            f"{live_key}\n",
            "pending-keygen",
        )
        for key in invalid_keys:
            with self.subTest(key=repr(key)):
                self.assertIsNone(CANONICAL_X25519_PUBLIC_KEY_PATTERN.fullmatch(key))

        for final_char in set(STANDARD_BASE64_ALPHABET) - set(
            CANONICAL_FINAL_CHARS
        ):
            with self.subTest(noncanonical_final_char=final_char):
                key = f"{live_key[:42]}{final_char}="
                self.assertIsNone(CANONICAL_X25519_PUBLIC_KEY_PATTERN.fullmatch(key))

    def test_pattern_exhaustively_enforces_the_two_zero_padding_bits(self) -> None:
        prefix = b"\xa5" * 30
        canonical_accepted = 0
        noncanonical_rejected = 0

        for suffix in range(1 << 16):
            payload = prefix + suffix.to_bytes(2, "big")
            canonical = base64.b64encode(payload).decode("ascii")
            self.assertIsNotNone(
                CANONICAL_X25519_PUBLIC_KEY_PATTERN.fullmatch(canonical)
            )
            canonical_accepted += 1

            final_index = STANDARD_BASE64_ALPHABET.index(canonical[-2])
            self.assertEqual(0, final_index % 4)
            for nonzero_pad_bits in (1, 2, 3):
                mutated = (
                    canonical[:-2]
                    + STANDARD_BASE64_ALPHABET[final_index + nonzero_pad_bits]
                    + "="
                )
                self.assertEqual(
                    payload,
                    base64.b64decode(mutated, validate=True),
                )
                self.assertIsNone(
                    CANONICAL_X25519_PUBLIC_KEY_PATTERN.fullmatch(mutated)
                )
                noncanonical_rejected += 1

        self.assertEqual(65_536, canonical_accepted)
        self.assertEqual(196_608, noncanonical_rejected)


if __name__ == "__main__":
    unittest.main()
