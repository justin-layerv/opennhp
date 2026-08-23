#!/usr/bin/env python3
"""Structural fences for the one-time two-cell durable-AOP cutover."""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


def load(path: str):
    return yaml.load((ROOT / path).read_text(), Loader=yaml.BaseLoader)


class DurableAOPCutoverWorkflowTest(unittest.TestCase):
    def test_generic_blue_green_has_non_serving_prepare_and_profile_floor(self):
        workflow = load(".github/workflows/blue-green-deploy.yml")
        action = workflow["on"]["workflow_dispatch"]["inputs"]["action"]
        self.assertIn("prepare-only", action["options"])
        self.assertIn("protocol_profile", workflow["on"]["workflow_dispatch"]["inputs"])
        jobs = workflow["jobs"]
        self.assertIn("prepare-only", jobs["deploy-to-standby"]["if"])
        self.assertIn("inputs.action != 'prepare-only'", jobs["switch-traffic"]["if"])

        text = (ROOT / ".github/workflows/blue-green-deploy.yml").read_text()
        self.assertIn("/sandbox/nhp/minimum-protocol-profile", text)
        self.assertIn("only the dedicated forward-retry workflow may mutate", text)
        self.assertIn("${STANDBY_COLOR}-protocol-profile", text)

        deploy_steps = jobs["deploy-to-standby"]["steps"]
        by_name = {step["name"]: step for step in deploy_steps}
        server_update = by_name["[Server] Update Standby Image Tag"]["run"]
        ac_update = by_name["[AC] Update Standby Image Tag"]["run"]
        health_index = next(
            i for i, step in enumerate(deploy_steps)
            if step["name"] == "[Parallel] Verify Standby Health (Server + AC)"
        )
        record_index = next(
            i for i, step in enumerate(deploy_steps)
            if step["name"] == "Record Exact Prepared Slot Attestations"
        )
        self.assertIn("server/${STANDBY_COLOR}-prepared-slot-attestation", server_update)
        self.assertIn("ac/${STANDBY_COLOR}-prepared-slot-attestation", ac_update)
        self.assertIn("ssm delete-parameter", server_update)
        self.assertIn("ssm delete-parameter", ac_update)
        self.assertLess(
            server_update.index("ssm delete-parameter"),
            server_update.index("ssm put-parameter --name \"$SSM_PARAM\""),
        )
        self.assertLess(
            ac_update.index("ssm delete-parameter"),
            ac_update.index("ssm put-parameter --name \"$SSM_PARAM\""),
        )
        refresh_index = next(
            i for i, step in enumerate(deploy_steps)
            if step["name"] == "[Parallel] Instance Refresh on Standby (Server + AC)"
        )
        self.assertGreater(health_index, refresh_index)
        self.assertGreater(record_index, health_index)
        record = deploy_steps[record_index]["run"]
        self.assertIn("verify-durable-aop-image-provenance.sh", record)
        self.assertIn("v2|${PROTOCOL_PROFILE}|${provenance#v1|}|${asg}", record)
        self.assertIn("ssm put-parameter", record)
        for step_name in ("[Server] Scale Up Standby ASG", "[AC] Scale Up Standby ASG"):
            scale = by_name[step_name]["run"]
            self.assertIn("DesiredCapacity,MaxSize", scale)
            self.assertIn('--max-size "$ACTIVE_MAX_SIZE"', scale)
            self.assertIn('"$ACTIVE_MAX_SIZE" -lt "$ACTIVE_CAPACITY"', scale)
            self.assertIn("resume-processes", scale)
            self.assertLess(scale.index("update-auto-scaling-group"), scale.index("resume-processes"))

        workflow_text = (ROOT / ".github/workflows/blue-green-deploy.yml").read_text()
        self.assertLess(workflow_text.index("[Server] Update Standby Image Tag"), workflow_text.index("[Server] Scale Up Standby ASG"))
        self.assertLess(workflow_text.index("[AC] Update Standby Image Tag"), workflow_text.index("[AC] Scale Up Standby ASG"))

    def test_terraform_preserves_zeroed_legacy_capacity_and_suspension(self):
        for path in (
            "terraform/modules/compute/main.tf",
            "terraform/modules/compute/blue_green.tf",
            "terraform/modules/ac/main.tf",
            "terraform/modules/ac/blue_green.tf",
        ):
            text = (ROOT / path).read_text()
            self.assertIn(
                "ignore_changes = [desired_capacity, min_size, max_size, suspended_processes]",
                text,
                path,
            )

    def test_standalone_main_ref_dispatch_is_removed(self):
        self.assertFalse((ROOT / ".github/workflows/sandbox-durable-aop-cutover.yml").exists())
        self.assertFalse((ROOT / ".github/scripts/dispatch-and-poll-durable-aop-cutover.sh").exists())

    def test_main_pipeline_prewarms_both_cells_then_runs_exact_parent_cutover(self):
        text = (ROOT / ".github/workflows/build-and-push.yml").read_text()
        cell0 = text.index("  deploy-sandbox-blue-green:")
        cell1 = text.index("  deploy-sandbox-cell1-blue-green:")
        next_job = re.search(r"^  [A-Za-z][A-Za-z0-9_-]*:\s*$", text[cell1 + 1 :], re.M)
        end = cell1 + 1 + next_job.start() if next_job else len(text)
        cell0_block = text[cell0:cell1]
        cell1_block = text[cell1:end]
        self.assertIn("cutover_required", cell0_block)
        self.assertIn("export BLUE_GREEN_ACTION=prepare-only", cell0_block)
        self.assertIn("PROTOCOL_PROFILE: durable-aop-v1", cell0_block)
        self.assertIn("export BLUE_GREEN_ACTION=prepare-only", cell1_block)
        self.assertIn("run-durable-aop-cutover-under-lock.sh", cell1_block)
        self.assertIn("attestations: read", cell1_block)
        self.assertIn("classify-durable-aop-cutover-resume.sh", cell1_block)
        self.assertIn("Exact durable cutover state already exists", cell1_block)
        self.assertIn("cancel-in-progress: false", cell1_block)
        self.assertNotIn("--ref main", cell1_block)
        self.assertLess(cell1_block.index("classify-durable-aop-cutover-resume.sh"),
                        cell1_block.index("./.github/scripts/dispatch-and-poll-blue-green.sh"))
        self.assertLess(cell1_block.rindex("./.github/scripts/dispatch-and-poll-blue-green.sh"),
                        cell1_block.rindex("run-durable-aop-cutover-under-lock.sh"))

    def test_main_terraform_mutations_have_durable_recovery_preflight(self):
        workflow = load(".github/workflows/build-and-push.yml")
        for job_name in ("deploy-sandbox-infra", "deploy-sandbox-cell1-infra"):
            job = workflow["jobs"][job_name]
            dumped = yaml.safe_dump(job)
            self.assertIn("assert-durable-aop-mutation-allowed.sh", dumped)
            self.assertEqual(job["timeout-minutes"], "180")
            steps = job["steps"]
            by_name = {step["name"]: step for step in steps}
            acquire = next(step for step in steps if step["name"].startswith("Acquire sandbox"))
            release = next(step for step in steps if step["name"].startswith("Release sandbox"))
            retain = next(step for step in steps if step["name"].startswith("Retain sandbox"))
            self.assertEqual(acquire["uses"], "./.github/actions/sandbox-live-env-lock")
            self.assertEqual(release["uses"], "./.github/actions/sandbox-live-env-lock")
            self.assertEqual(acquire["with"]["owner"], release["with"]["owner"])
            self.assertEqual(acquire["with"]["ssm-parameter-name"], "/layerv-nhp-sandbox/qurl-live-env-lock")
            self.assertIn("always()", retain["if"])
            self.assertIn(f"steps.{acquire['id']}.outcome == 'success'", retain["if"])
            self.assertIn(f"steps.{release['id']}.outcome != 'success'", retain["if"])
            self.assertIn("exit 1", retain["run"])

            apply_name = "Terraform Apply" if job_name == "deploy-sandbox-infra" else "Terraform apply (sandbox-cell1)"
            apply_run = by_name[apply_name]["run"]
            commands = [
                line.strip() for line in apply_run.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            apply_index = next(i for i, line in enumerate(commands) if line.startswith("terraform apply "))
            self.assertEqual(commands[apply_index - 1], "../../../.github/scripts/assert-durable-aop-mutation-allowed.sh")
            # Counterexample: the fixture must detect even one API-shaped
            # operation inserted into the guard/apply race window.
            raced = commands[:apply_index] + ["aws ssm put-parameter --name /race"] + commands[apply_index:]
            raced_apply = next(i for i, line in enumerate(raced) if line.startswith("terraform apply "))
            self.assertNotEqual(raced[raced_apply - 1], "../../../.github/scripts/assert-durable-aop-mutation-allowed.sh")

            acquire_index = steps.index(acquire)
            apply_step_index = steps.index(by_name[apply_name])
            release_index = steps.index(release)
            self.assertLess(acquire_index, apply_step_index)
            self.assertGreater(release_index, apply_step_index)

        main_steps = workflow["jobs"]["deploy-sandbox-infra"]["steps"]
        main_names = [step["name"] for step in main_steps]
        self.assertLess(main_names.index("Get Terraform Outputs"), main_names.index("Release sandbox infrastructure live-environment lock"))
        cell1_steps = workflow["jobs"]["deploy-sandbox-cell1-infra"]["steps"]
        cell1_names = [step["name"] for step in cell1_steps]
        self.assertLess(cell1_names.index("Prove the bootstrap script carries the agent-serving config"), cell1_names.index("Release sandbox cell1 infrastructure live-environment lock"))


if __name__ == "__main__":
    unittest.main()
