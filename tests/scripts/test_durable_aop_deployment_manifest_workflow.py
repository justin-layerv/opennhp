from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/udp-proof-deployment-manifest.yml"


class DurableAOPDeploymentManifestWorkflowTest(unittest.TestCase):
    def test_attended_claim_free_producer(self):
        text = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertNotRegex(text, re.compile(r"^\s+(push|schedule|workflow_run):", re.MULTILINE))
        self.assertIn("group: deploy-sandbox-cell1-blue-green", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("environment: sandbox", text)
        inputs = re.search(r"(?ms)^\s{4}inputs:\n(?P<body>.*?)(?=^# This proof)", text)
        self.assertIsNotNone(inputs)
        self.assertEqual(
            re.findall(r"(?m)^\s{6}([a-z0-9_]+):$", inputs.group("body")),
            ["schema3_recovery_run_id", "schema3_recovery_run_attempt", "confirmation"],
        )
        for forbidden in ("repair_source", "image_digest", "active_color", "active_asg", "manifest"):
            self.assertNotIn(f"      {forbidden}", inputs.group("body"))

    def test_exact_one_file_artifact_contract(self):
        text = WORKFLOW.read_text()
        self.assertIn("emit-durable-aop-nhp-deployment-manifest.sh", text)
        self.assertIn("durable-aop-nhp-deployment-${{ steps.authority.outputs.repair_source_sha }}", text)
        self.assertIn("${RUNNER_TEMP}/durable-aop-nhp-deployment.json", text)
        self.assertIn("if-no-files-found: error", text)
        self.assertIn("compression-level: 0", text)
        self.assertIn("ARTIFACT_ID: ${{ steps.upload.outputs.artifact-id }}", text)
        self.assertIn("ARTIFACT_DIGEST: ${{ steps.upload.outputs.artifact-digest }}", text)
        self.assertRegex(text, r"ARTIFACT_DIGEST.*sha256:\[0-9a-f\]\{64\}")


if __name__ == "__main__":
    unittest.main()
