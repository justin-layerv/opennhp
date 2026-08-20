#!/usr/bin/env python3
"""Contract tests for the PR Terraform prod-drift lint job."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/build-and-push.yml"
JOB_NAME = "terraform-prod-drift-lint"
EXPECTED_TIMEOUT_MINUTES = 6


class TerraformProdDriftWorkflowTest(unittest.TestCase):
    def test_job_keeps_the_evidence_based_timeout(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")) or {}
        jobs = workflow.get("jobs", {})

        self.assertIn(
            JOB_NAME,
            jobs,
            "the prod-drift lint job disappeared or was renamed without updating its contract",
        )
        self.assertEqual(
            "github.event_name == 'pull_request'",
            jobs[JOB_NAME].get("if"),
            "the measured timeout belongs to the PR-only prod-drift job; "
            "keep the push drift gate separate",
        )
        self.assertEqual(
            EXPECTED_TIMEOUT_MINUTES,
            jobs[JOB_NAME].get("timeout-minutes"),
            "the prod-drift lint timeout must remain at the measured six-minute bound; "
            "update the workflow evidence and this contract together after new timing data",
        )


if __name__ == "__main__":
    unittest.main()
