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
        token_action = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
        self.assertEqual(text.count(token_action), 2)
        self.assertEqual(text.count("          owner: layervai"), 2)
        repositories = re.findall(r"(?m)^\s{10}repositories: \|\n((?:\s{12}[^\n]+\n)+)", text)
        self.assertEqual(
            [[line.strip() for line in block.splitlines()] for block in repositories],
            [["qurl-integrations-infra"], ["qurl-connector"]],
        )
        self.assertEqual(text.count("          permission-actions: read"), 2)
        self.assertEqual(text.count("          permission-contents: read"), 2)
        self.assertNotIn("permission-pull-requests:", text)
        self.assertIn("GH_TOKEN: ${{ github.token }}", text)
        self.assertIn("CUTOVER_CUSTOMER_GH_TOKEN: ${{ steps.customer_lifecycle_token.outputs.token }}", text)
        self.assertIn("CUTOVER_CONNECTOR_GH_TOKEN: ${{ steps.connector_lifecycle_token.outputs.token }}", text)
        self.assertNotRegex(text, re.compile(r"GH_TOKEN:\s*\$\{\{\s*secrets\.", re.MULTILINE))
        for repository, workflow in (
            ("qurl-integrations-infra", "qurl-sharing-sandbox.yml"),
            ("qurl-connector", "sandbox-smoke.yml"),
        ):
            self.assertIn(f"gh api repos/layervai/{repository} --jq .full_name", text)
            self.assertIn(f"repos/layervai/{repository}/actions/runs?per_page=1", text)
            self.assertIn(f"repos/layervai/{repository}/contents/.github/workflows/{workflow}?ref=main", text)

        customer_mint = text.index("- name: Mint customer lifecycle reader token")
        customer_check = text.index("- name: Verify customer lifecycle reader access")
        connector_mint = text.index("- name: Mint connector lifecycle reader token")
        connector_check = text.index("- name: Verify connector lifecycle reader access")
        aws = text.index("- name: Configure AWS credentials")
        self.assertIn(
            "GH_TOKEN: ${{ steps.customer_lifecycle_token.outputs.token }}",
            text[customer_check:connector_mint],
        )
        self.assertIn(
            "GH_TOKEN: ${{ steps.connector_lifecycle_token.outputs.token }}",
            text[connector_check:aws],
        )
        self.assertIn(
            "repos/layervai/qurl-connector/git/commits/16dd7d3c835bf4f44b212e2d6a34205a3c04a8d8 --jq .sha",
            text[connector_check:aws],
        )
        self.assertLess(customer_mint, customer_check)
        self.assertLess(customer_check, connector_mint)
        self.assertLess(connector_mint, connector_check)
        self.assertLess(connector_check, aws)
        conditional_token_steps = re.findall(
            r"(?m)^      - name: (?:Mint|Verify) (?:customer|connector) lifecycle reader (?:token|access)\n"
            r"        if: inputs\.lifecycle_run_id != ''$",
            text,
        )
        self.assertEqual(len(conditional_token_steps), 4)
        aws_step = text[text.index("- name: Configure AWS credentials"):text.index("- name: Adopt and advance exact schema-3 recovery")]
        recovery_step = text[text.index("- name: Adopt and advance exact schema-3 recovery"):]
        self.assertNotIn("if: inputs.lifecycle_run_id", aws_step)
        self.assertNotIn("if: inputs.lifecycle_run_id", recovery_step)

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
                "GH_TOKEN: ${{ steps.customer_lifecycle_token.outputs.token }}",
                "GH_TOKEN: ${{ github.token }}",
                1,
            ),
            text.replace(
                "GH_TOKEN: ${{ steps.connector_lifecycle_token.outputs.token }}",
                "GH_TOKEN: ${{ secrets.CALLER_PAT }}",
                1,
            ),
            text.replace("          permission-actions: read\n", "", 1),
            text.replace("          permission-contents: read", "          permission-contents: write", 1),
            text.replace("gh api 'repos/layervai/qurl-connector/actions/runs?per_page=1' >/dev/null\n", "", 1),
            text.replace(
                "CUTOVER_CUSTOMER_GH_TOKEN: ${{ steps.customer_lifecycle_token.outputs.token }}",
                "CUTOVER_CUSTOMER_GH_TOKEN: ${{ github.token }}",
                1,
            ),
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
        self.assertIn("recovery_outcome: ${{ steps.recovery.outputs.recovery_outcome }}", text)
        self.assertIn("Install exact Go toolchain", text)
        self.assertIn("go-version-file: endpoints/go.mod", text)
        self.assertIn("Build incident-only stale-target retirement command", text)
        self.assertIn(
            "go build -trimpath -o ../.bin/session-control-stale-target-retirement "
            "./cmd/session-control-stale-target-retirement",
            text.replace("\n", " "),
        )
        self.assertIn(
            "CUTOVER_STALE_TARGET_RETIRE_SCRIPT: ${{ github.workspace }}/.bin/session-control-stale-target-retirement",
            text,
        )
        reject = text[text.index("- name: Reject mutable or malformed recovery dispatch"):text.index("- name: Checkout exact recovery controller")]
        self.assertIn('if [[ -z "$LIFECYCLE_RUN_ID$LIFECYCLE_RUN_ATTEMPT$CONNECTOR_LIFECYCLE_RUN_ID$CONNECTOR_LIFECYCLE_RUN_ATTEMPT" ]]', reject)
        self.assertEqual(reject.count('=~ ^[1-9][0-9]*$'), 6)

    def test_script_orders_servers_before_ac_and_terminal_receipts_before_floor(self):
        text = SCRIPT.read_text()
        cell0 = text.index('write_state cell0_refreshed')
        cell1 = text.index('write_state cell1_refreshed')
        ac = text.index('write_state repaired', cell1)
        owner_plan = text.index('OWNER_INTENT=$("$OWNER_PROJECTOR" plan')
        owner_preparing = text.index('write_state repaired', owner_plan)
        owner_apply = text.index('"$OWNER_PROJECTOR" apply --intent-json "$OWNER_INTENT"')
        owner_ready = text.index('write_state repaired', owner_apply)
        deferred = text.index('emit_recovery_outcome repaired_owner_ready_waiting_for_lifecycle')
        ready = text.index("schema3-ac-ready")
        lifecycle = text.index('candidate_lifecycle=$(CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=')
        connector = text.index('candidate_connector_lifecycle=$(GH_TOKEN=$CUTOVER_CONNECTOR_GH_TOKEN')
        floor = text.rindex("ensure_exact_floor")
        release = text.index('ssm-live-env-lock.sh" release')
        self.assertLess(cell0, cell1)
        self.assertLess(cell1, ac)
        self.assertLess(ac, owner_plan)
        self.assertLess(owner_plan, owner_preparing)
        self.assertLess(owner_preparing, owner_apply)
        self.assertLess(owner_apply, owner_ready)
        runtime_flow = text.index("# The merged runtime repair contains both server close-drain")
        runtime_cell0 = text.index("advance_runtime_component_refresh cell0", runtime_flow)
        runtime_cell1 = text.index("advance_runtime_component_refresh cell1", runtime_flow)
        fence_drain = text.index("record_fence_drain", runtime_cell1)
        incident_retirement = text.index("advance_stale_target_retirement", fence_drain)
        ac_intent = text.index("initialize_ac_runtime_refresh", incident_retirement)
        runtime_ac = text.index("advance_runtime_component_refresh ac", ac_intent)
        predecessor_retirement = text.index("advance_predecessor_retirement", runtime_ac)
        self.assertLess(owner_ready, runtime_cell0)
        self.assertLess(runtime_cell0, runtime_cell1)
        self.assertLess(runtime_cell1, fence_drain)
        self.assertLess(fence_drain, incident_retirement)
        self.assertLess(incident_retirement, ac_intent)
        self.assertLess(ac_intent, runtime_ac)
        self.assertLess(runtime_ac, predecessor_retirement)
        self.assertLess(predecessor_retirement, deferred)
        self.assertLess(ac, ready)
        self.assertLess(ready, lifecycle)
        self.assertLess(lifecycle, connector)
        self.assertLess(connector, floor)
        self.assertLess(lifecycle, floor)
        self.assertLess(floor, release)
        current_verifies = [match.start() for match in re.finditer(
            '"\\$OWNER_PROJECTOR" verify-current --intent-json "\\$OWNER_INTENT"', text
        )]
        self.assertEqual(len(current_verifies), 3)
        self.assertLess(current_verifies[-2], floor)
        self.assertLess(floor, current_verifies[-1])
        self.assertLess(current_verifies[-1], text.rindex('write_state complete'))
        self.assertIn('--no-overwrite --region "$AWS_REGION"', text)
        self.assertNotIn('put_param "$FLOOR_PARAM"', text)
        self.assertIn("CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA", text)
        self.assertIn("CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT", text)
        self.assertIn("CUTOVER_EXPECTED_AC_DIGEST", text)
        self.assertIn("sessionAdmissionReady", (ROOT / "endpoints/ac/httpac.go").read_text())

    def test_owner_projection_is_fixed_and_deferred_success_retains_authority(self):
        text = SCRIPT.read_text()
        for authority in (
            "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy",
            "oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz",
            "layerv-nhp-sandbox-control-qurl-customers",
            "layerv.durable-aop-customer-owner-intent.v1",
        ):
            self.assertIn(authority, text)
        self.assertIn("OWNER_STATUS=preparing", text)
        self.assertIn("OWNER_STATUS=ready", text)
        deferred_start = text.index('if [[ "$LIFECYCLE_MODE" == deferred ]]')
        deferred_end = text.index("\nfi\n\nrequire_hard_lock", deferred_start) + len("\nfi")
        deferred = text[deferred_start:deferred_end]
        self.assertIn("require_hard_lock", deferred)
        self.assertIn("repaired_owner_ready_waiting_for_lifecycle", deferred)
        self.assertIn("exit 0", deferred)
        self.assertNotIn("ensure_exact_floor", deferred)
        self.assertNotIn("ssm-live-env-lock.sh", deferred)

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
