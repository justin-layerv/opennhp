from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/recover-sandbox-durable-aop-schema3.yml"
SCRIPT = ROOT / ".github/scripts/recover-durable-aop-cutover-schema3.sh"
BUILD_WORKFLOW = ROOT / ".github/workflows/build-and-push.yml"
BUILD_VERIFIER = ROOT / ".github/scripts/verify-durable-aop-build-only-run.sh"


class DurableAOPSchema3RecoveryWorkflowTest(unittest.TestCase):
    def assert_exact_receipt_token_contract(self, text):
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", text)
        self.assertIn("owner: layervai", text)
        match = re.search(r"(?m)^\s{10}repositories: \|\n((?:\s{12}[^\n]+\n)+)", text)
        self.assertIsNotNone(match)
        self.assertEqual(
            [line.strip() for line in match.group(1).splitlines()],
            ["nhp", "qurl-integrations-infra", "qurl-integrations", "qurl-go", "qurl-connector"],
        )
        self.assertIn("GH_TOKEN: ${{ steps.recovery_receipt_token.outputs.token }}", text)
        self.assertNotIn("GH_TOKEN: ${{ github.token }}", text)
        self.assertNotRegex(text, re.compile(r"GH_TOKEN:\s*\$\{\{\s*secrets\.", re.MULTILINE))
        permissions = re.findall(r"(?m)^\s{10}permission-([a-z-]+):\s*([^\s]+)\s*$", text)
        self.assertEqual(permissions, [("actions", "read"), ("contents", "read")])

    def test_workflow_is_attended_exact_source_and_non_cancelable(self):
        text = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertNotRegex(text, re.compile(r"^\s+(push|schedule):", re.MULTILINE))
        self.assertIn("group: deploy-sandbox-cell1-blue-green", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn('[[ "$GITHUB_REF" == refs/heads/main', text)
        self.assertIn('"$EXPECTED_RECOVERY_SHA" == "$GITHUB_SHA"', text)
        self.assertIn("environment: sandbox", text)
        self.assertIn("attestations: read", text)
        self.assertIn("id-token: write", text)
        self.assert_exact_receipt_token_contract(text)

    def test_receipt_reader_rejects_repo_or_token_fallback_drift(self):
        text = WORKFLOW.read_text()
        mutations = (
            text.replace("            qurl-connector\n", "            qurl-connector\n            unrelated-repo\n", 1),
            text.replace(
                "GH_TOKEN: ${{ steps.recovery_receipt_token.outputs.token }}",
                "GH_TOKEN: ${{ github.token }}",
                1,
            ),
            text.replace(
                "GH_TOKEN: ${{ steps.recovery_receipt_token.outputs.token }}",
                "GH_TOKEN: ${{ secrets.CALLER_PAT }}",
                1,
            ),
            text.replace("          permission-actions: read\n", "", 1),
            text.replace("          permission-contents: read", "          permission-contents: write", 1),
        )
        for mutation in mutations:
            with self.assertRaises(AssertionError):
                self.assert_exact_receipt_token_contract(mutation)

    def test_workflow_binds_original_repair_and_protected_lifecycle_authority(self):
        text = WORKFLOW.read_text()
        inputs = re.search(r"(?ms)^  workflow_dispatch:\n    inputs:\n(?P<body>.*?)(?=^# The original)", text)
        self.assertIsNotNone(inputs)
        self.assertEqual(
            re.findall(r"(?m)^      ([a-z0-9_]+):$", inputs.group("body")),
            [
                "expected_recovery_sha", "repair_source_sha", "repair_build_run_id",
                "repair_build_run_attempt", "lifecycle_run_id", "lifecycle_run_attempt",
                "connector_lifecycle_run_id", "connector_lifecycle_run_attempt", "confirmation",
            ],
        )
        self.assertGreaterEqual(text.count("e9b11398a4cea98da6ae5b41cfe635562e1b7c72"), 2)
        self.assertIn("CUTOVER_ORIGINAL_RUN_ID: '32635672597'", text)
        self.assertNotIn("repair_runtime_manifest", text)
        self.assertNotIn("repair_runtime_source_sha", text)
        self.assertIn("APPROVED_REPAIR_RUNTIME_MANIFEST", SCRIPT.read_text())
        self.assertIn("repair_build_run_id", text)
        self.assertIn("repair_build_run_attempt", text)
        self.assertIn("lifecycle_run_attempt", text)
        self.assertNotIn("lifecycle_integrations_sha", text)
        self.assertNotIn("connector_lifecycle_source_sha", text)
        self.assertNotIn("connector_pr_head_sha", text)
        self.assertNotIn("connector_nhp_controller_run_attempt", text)
        self.assertIn("ADOPT_EXACT_E9_DURABLE_AOP_REPAIR", text)
        self.assertIn("APPROVED_REPAIR_SOURCE_SHA=422b1d9acac53d50fe5602158fb02c8120ef108d", SCRIPT.read_text())
        self.assertNotIn("CUTOVER_VERIFY_CUSTOMER_LIFECYCLE_SCRIPT", text)
        self.assertNotIn("CUTOVER_VERIFY_CONNECTOR_LIFECYCLE_SCRIPT", text)

    def test_script_orders_servers_before_ac_and_terminal_receipts_before_floor(self):
        text = SCRIPT.read_text()
        cell0 = text.index('write_state cell0_refreshed')
        cell1 = text.index('write_state cell1_refreshed')
        ac = text.index('write_state repaired')
        ready = text.index("schema3-ac-ready")
        lifecycle = text.index('candidate_lifecycle=$(CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=')
        connector = text.index('candidate_connector_lifecycle=$(CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=')
        floor = text.rindex("ensure_exact_floor")
        release = text.index('ssm-live-env-lock.sh" release')
        self.assertLess(cell0, cell1)
        self.assertLess(cell1, ac)
        self.assertLess(ac, ready)
        self.assertLess(ready, lifecycle)
        self.assertLess(lifecycle, connector)
        self.assertLess(connector, floor)
        self.assertLess(lifecycle, floor)
        self.assertLess(floor, release)
        self.assertIn('--no-overwrite --region "$AWS_REGION"', text)
        self.assertNotIn('put_param "$FLOOR_PARAM"', text)
        self.assertIn("CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA", text)
        self.assertIn("CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT", text)
        self.assertIn("CUTOVER_EXPECTED_AC_DIGEST", text)
        self.assertIn("sessionAdmissionReady", (ROOT / "endpoints/ac/httpac.go").read_text())

    def test_build_authority_is_exact_force_build_no_deploy(self):
        workflow = BUILD_WORKFLOW.read_text()
        verifier = BUILD_VERIFIER.read_text()
        self.assertIn("Require build-only recovery attestation", workflow)
        self.assertIn("inputs.deploy == false", workflow)
        self.assertIn("inputs.force_build == true", workflow)
        for authority_check in (
            '[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]',
            '[[ "$PROVENANCE_OUTCOME" == success ]]',
            '[[ "$SBOM_ATTEST_OUTCOME" == success ]]',
        ):
            self.assertIn(authority_check, workflow)
        self.assertIn('.event == "workflow_dispatch"', verifier)
        self.assertNotIn('.event == "push"', verifier)
        self.assertIn('exact_step("Detect Changes"; "Force build override"; "success")', verifier)
        self.assertIn('exact_job("Test"; "success")', verifier)
        self.assertIn('exact_step("Test"; "Run tests (privileged container for iptables)"; "success")', verifier)
        for job in (
            "Deploy Sandbox - Infrastructure", "Deploy Sandbox - QURL Service",
            "Deploy Sandbox - Relay", "Deploy Sandbox - Blue/Green",
            "Deploy Sandbox cell1 - Infrastructure", "Deploy Sandbox cell1 - Blue/Green",
            "Deploy Sandbox - Control", "Deploy Sandbox - Validate",
        ):
            self.assertIn(f'"{job}"', verifier)


if __name__ == "__main__":
    unittest.main()
