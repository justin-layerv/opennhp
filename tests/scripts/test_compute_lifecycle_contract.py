#!/usr/bin/env python3
"""Durable regression fences for shared NHP compute lifecycle ownership."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPUTE_MAIN = ROOT / "terraform/modules/compute/main.tf"
COMPUTE_BLUE_GREEN = ROOT / "terraform/modules/compute/blue_green.tf"


class ComputeLifecycleContractTest(unittest.TestCase):
    def test_asgs_preserve_cutover_capacity_and_suspensions(self) -> None:
        expected = (
            "ignore_changes = "
            "[desired_capacity, min_size, max_size, suspended_processes]"
        )
        self.assertEqual(
            COMPUTE_MAIN.read_text(encoding="utf-8").count(expected),
            1,
            "the blue server ASG must leave cutover capacity and suspensions operator-owned",
        )
        self.assertEqual(
            COMPUTE_BLUE_GREEN.read_text(encoding="utf-8").count(expected),
            1,
            "the green server ASG must leave cutover capacity and suspensions operator-owned",
        )

    def test_nlb_replacement_is_scoped_to_server_vpc_change(self) -> None:
        compute = COMPUTE_MAIN.read_text(encoding="utf-8")
        self.assertEqual(
            compute.count(
                "replace_triggered_by = [aws_security_group.server.vpc_id]"
            ),
            2,
            "both public and internal server NLBs must follow a server VPC move",
        )
        self.assertNotIn(
            "replace_triggered_by = [aws_security_group.server.id]",
            compute,
            "an unrelated server security-group replacement must not replace NLBs",
        )


if __name__ == "__main__":
    unittest.main()
