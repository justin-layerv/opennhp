#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_udp_proof_authority_evidence.py")
SPEC = importlib.util.spec_from_file_location("authority_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def provenance(color="green"):
    functions = []
    for index, function_name in enumerate(evidence.FUNCTIONS, start=7):
        prefix = (
            f"arn:aws:lambda:{evidence.REGION}:{evidence.ACCOUNT}:"
            f"function:{function_name}:"
        )
        functions.append(
            {
                "alias_arn": f"{prefix}{color}",
                "version_arn": f"{prefix}{index}",
            }
        )
    return {
        "evidence": {
            "workloads": {
                "qurl_service_authority": {
                    "functions": functions,
                }
            }
        }
    }


class AuthorityEvidenceTests(unittest.TestCase):
    def test_selects_exact_four_same_color_versions(self):
        self.assertEqual(
            evidence._selected_versions(provenance()),
            {
                function_name: ("green", str(index))
                for index, function_name in enumerate(evidence.FUNCTIONS, start=7)
            },
        )

    def test_rejects_mixed_color_or_missing_function(self):
        mixed = provenance()
        mixed["evidence"]["workloads"]["qurl_service_authority"]["functions"][0][
            "alias_arn"
        ] = mixed["evidence"]["workloads"]["qurl_service_authority"]["functions"][
            0
        ]["alias_arn"].replace(":green", ":blue")
        with self.assertRaises(evidence.EvidenceError):
            evidence._selected_versions(mixed)
        missing = provenance()
        missing["evidence"]["workloads"]["qurl_service_authority"]["functions"].pop()
        with self.assertRaises(evidence.EvidenceError):
            evidence._selected_versions(missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
