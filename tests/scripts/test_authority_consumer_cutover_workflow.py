#!/usr/bin/env python3
"""Fence Control-to-cell alias materialization and runtime verification order."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "build-and-push.yml"


class AuthorityConsumerCutoverWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = (yaml.safe_load(WORKFLOW.read_text()) or {}).get("jobs", {})

    def job(self, name: str) -> dict:
        self.assertIn(name, self.jobs, f"required job {name!r} disappeared")
        return self.jobs[name]

    @staticmethod
    def needs(job: dict) -> set[str]:
        raw = job.get("needs", [])
        return {raw} if isinstance(raw, str) else set(raw)

    def ancestors(self, name: str) -> set[str]:
        found: set[str] = set()
        pending = list(self.needs(self.job(name)))
        while pending:
            dependency = pending.pop()
            if dependency in found:
                continue
            found.add(dependency)
            pending.extend(self.needs(self.job(dependency)))
        return found

    def test_control_precedes_every_cell_materialization_and_refresh(self) -> None:
        control = self.job("deploy-sandbox-control")
        self.assertNotIn(
            "deploy-sandbox-infra",
            self.needs(control),
            "Control cannot consume cell0 infra and also precede its alias materialization",
        )
        for consumer in (
            "deploy-sandbox-infra",
            "deploy-sandbox-blue-green",
            "deploy-sandbox-cell1-infra",
            "deploy-sandbox-cell1-blue-green",
        ):
            self.assertIn(
                "deploy-sandbox-control",
                self.ancestors(consumer),
                f"{consumer} can race the Authority selector",
            )

    def test_each_refresh_requires_its_post_control_terraform_apply(self) -> None:
        matching_pairs = (
            ("deploy-sandbox-blue-green", "deploy-sandbox-infra"),
            ("deploy-sandbox-cell1-blue-green", "deploy-sandbox-cell1-infra"),
        )
        for refresh_name, terraform_name in matching_pairs:
            refresh = self.job(refresh_name)
            self.assertIn(
                terraform_name,
                self.needs(refresh),
                f"{refresh_name} can start without its matching Terraform apply",
            )
            self.assertIn(
                f"needs.{terraform_name}.result == 'success'",
                str(refresh.get("if", "")),
                f"{refresh_name} does not fail closed when {terraform_name} fails",
            )

        cell0_infra = self.job("deploy-sandbox-infra")
        self.assertIn("deploy-sandbox-control", self.needs(cell0_infra))
        self.assertIn(
            "needs.deploy-sandbox-control.result == 'success'",
            str(cell0_infra.get("if", "")),
        )

    def test_validation_waits_for_both_cells_and_checks_live_aliases(self) -> None:
        validate = self.job("deploy-sandbox-validate")
        self.assertIn("deploy-sandbox-cell1-blue-green", self.needs(validate))
        self.assertIn(
            "needs.deploy-sandbox-cell1-blue-green.result == 'success'",
            str(validate.get("if", "")),
        )
        matching_steps = [
            step
            for step in validate.get("steps", [])
            if step.get("name") == "Verify active cell Authority alias convergence"
        ]
        self.assertEqual(len(matching_steps), 1)
        self.assertGreaterEqual(
            int(matching_steps[0].get("timeout-minutes", 0)),
            12,
            "two sequential ASG probes need headroom to fail with their own message",
        )
        run = str(matching_steps[0].get("run", ""))
        self.assertIn("verify-authority-cell-alias-convergence.sh", run)
        self.assertNotIn("continue-on-error", matching_steps[0])


if __name__ == "__main__":
    unittest.main()
