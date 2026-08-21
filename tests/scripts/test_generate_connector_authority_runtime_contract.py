#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / ".github"
    / "scripts"
    / "generate-connector-authority-runtime-contract.py"
)
MANIFEST_REL = Path(
    "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
)
MANIFEST = ROOT / MANIFEST_REL
SPEC = importlib.util.spec_from_file_location("authority_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def run(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def terraform_variable_block(path: Path, variable_name: str) -> str:
    text = path.read_text(encoding="utf-8")
    marker = f'variable "{variable_name}" {{'
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"{path}: missing {marker}")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"{path}: unterminated {marker}")


class CellActivationDefaultTests(unittest.TestCase):
    def test_auto_deployed_cell_roots_stay_dark_by_default(self) -> None:
        for relative_path in (
            "terraform/environments/sandbox/variables.tf",
            "terraform/environments/sandbox-cell1/variables.tf",
            "terraform/environments/prod/variables.tf",
        ):
            with self.subTest(root=relative_path):
                block = terraform_variable_block(
                    ROOT / relative_path, "connector_authority_cell_config"
                )
                self.assertEqual(
                    re.findall(r"(?m)^\s*default\s*=\s*(.+?)\s*$", block),
                    ["null"],
                )

    def test_sandbox_cell_roots_activate_only_from_a_reviewed_source(self) -> None:
        """The module argument must come from the var OR a Control-derived local.

        This replaces a literal `= var.connector_authority_cell_config` match.
        That literal encoded WHERE the value came from, but the property worth
        protecting is that an auto-deployed root cannot activate the capability
        on its own -- activation must trace to something a human reviewed.

        Reading Control's published alias targets satisfies that: the output is
        null until Control's authority runtime is live, and making it live is
        itself a reviewed Control apply. The deliberate step moved from a
        sandbox tfvars edit to the Control apply; it did not disappear. The
        fail-closed half is asserted separately below.

        A derived root must still honour an explicit var so prod parity and
        break-glass overrides keep working.
        """
        for relative_path in (
            "terraform/environments/sandbox/main.tf",
            "terraform/environments/sandbox-cell1/main.tf",
            "terraform/environments/prod/main.tf",
        ):
            with self.subTest(root=relative_path):
                text = (ROOT / relative_path).read_text(encoding="utf-8")
                direct = (
                    "connector_authority_cell_config = "
                    "var.connector_authority_cell_config" in text
                )
                derived = (
                    "connector_authority_cell_config = "
                    "local.connector_authority_cell_config" in text
                )
                self.assertTrue(
                    direct or derived,
                    "root must pass either the var or a Control-derived local",
                )
                if derived:
                    root_dir = (ROOT / relative_path).parent
                    body = "\n".join(
                        path.read_text(encoding="utf-8")
                        for path in sorted(root_dir.glob("*.tf"))
                    )
                    self.assertIn(
                        "var.connector_authority_cell_config != null",
                        body,
                        "a derived root must still let an explicit var win",
                    )

    def test_derived_cell_activation_fails_closed_without_control(self) -> None:
        """A derived root stays dark when Control has published nothing.

        This is the half that actually keeps an auto-deploy safe. The remote
        state read must be wrapped so a missing output resolves to null rather
        than erroring or, worse, partially populating the config.
        """
        for relative_path in (
            "terraform/environments/sandbox/main.tf",
            "terraform/environments/sandbox-cell1/main.tf",
            "terraform/environments/prod/main.tf",
        ):
            with self.subTest(root=relative_path):
                root_dir = (ROOT / relative_path).parent
                body = "\n".join(
                    path.read_text(encoding="utf-8")
                    for path in sorted(root_dir.glob("*.tf"))
                )
                if "local.connector_authority_cell_config" not in body:
                    continue
                self.assertIn("authority_cell_alias_targets", body)
                self.assertRegex(
                    body,
                    r"try\(\s*\n?\s*data\.terraform_remote_state\.control"
                    r"(?:\[0\])?\.outputs\.authority_cell_alias_targets",
                )
                # Cell-agnostic on purpose: each derived root names its local
                # after its own cell (control_cell1_alias_targets in the cell1
                # root), so pinning cell0 here would force every future cell to
                # mislabel its local after cell0.
                self.assertRegex(
                    body,
                    r"control_cell[0-9]+_alias_targets == null \? null",
                )

    def test_prod_control_state_handoff_is_explicit_and_dark_by_default(self) -> None:
        root = ROOT / "terraform/environments/prod"
        variables = terraform_variable_block(
            root / "variables.tf", "connector_authority_cell_from_control_enabled"
        )
        self.assertEqual(
            re.findall(r"(?m)^\s*default\s*=\s*(.+?)\s*$", variables),
            ["false"],
        )
        self.assertIn(
            "condition     = !var.connector_authority_cell_from_control_enabled",
            variables,
        )

        config = terraform_variable_block(
            root / "variables.tf", "connector_authority_cell_config"
        )
        self.assertIn(
            "condition     = var.connector_authority_cell_config == null", config
        )

        source = (root / "connector_authority_cell.tf").read_text(encoding="utf-8")
        self.assertIn(
            'count   = var.connector_authority_cell_from_control_enabled ? 1 : 0',
            source,
        )
        self.assertIn('bucket = "layerv-terraform-state-235500187906"', source)
        self.assertIn('key    = "nhp/prod/control/terraform.tfstate"', source)
        self.assertIn(
            "var.connector_authority_cell_from_control_enabled ? try(", source
        )
        main = (root / "main.tf").read_text(encoding="utf-8")
        self.assertIn(
            "connector_authority_cell_config = local.connector_authority_cell_config",
            main,
        )
        tfvars = (root / "terraform.tfvars").read_text(encoding="utf-8")
        self.assertIn(
            "connector_authority_cell_from_control_enabled = false", tfvars
        )


class ManifestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_repository_manifest_is_canonical_and_valid(self) -> None:
        self.assertEqual(MANIFEST.read_text(encoding="utf-8"), canonical(self.manifest))
        contract = CHECKER.validate_manifest(self.manifest)
        self.assertEqual(contract["phase"], "measurement")
        expected_functions = {
            "layerv-nhp-sandbox-ca-ia",
            "layerv-nhp-sandbox-ca-ra",
            "layerv-nhp-sandbox-ca-icr",
        } | {
            f"layerv-nhp-sandbox-ca-{suffix}-{cell_id}"
            for cell_id in ("cell0", "cell1")
            for suffix in ("iro", "ar", "cr", "ccr", "creso")
        }
        self.assertEqual(set(contract["functions"]), expected_functions)
        self.assertEqual(
            contract["provisioned_cells"], CHECKER.EXPECTED_CELLS
        )

    def assert_rejected(self, mutate) -> None:
        value = copy.deepcopy(self.manifest)
        mutate(value)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.validate_manifest(value)

    def test_rejects_closed_schema_defects(self) -> None:
        cases = {
            "extra manifest key": lambda value: value.__setitem__("extra", True),
            "missing contract key": lambda value: value["contract"].pop("phase"),
            "unsupported schema": lambda value: value.__setitem__("schema_version", 2),
            "ready phase": lambda value: value["contract"].__setitem__("phase", "ready"),
            "extra global key": lambda value: value["contract"]["global"].__setitem__("extra", 1),
            "boolean integer": lambda value: value["contract"]["global"].__setitem__(
                "regional_lambda_concurrency_quota", True
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(mutate)

    def test_rejects_environment_account_region_and_aws_identity_drift(self) -> None:
        cases = {
            "environment": ("environment", "prod"),
            "account": ("aws_account_id", "235500187906"),
            "region": ("aws_region", "us-west-2"),
            "partition": ("aws_partition", "aws-us-gov"),
            "repository": (
                "authority_repository_url",
                "example.invalid/layerv/qurl-connector-authority",
            ),
            "parameter": (
                "authority_digest_parameter_name",
                "/prod/nhp/control/connector-authority/image-digest",
            ),
            "alias": (
                "qat1_alias_arn",
                "arn:aws:kms:us-east-2:767397897469:alias/other",
            ),
            "raw key": (
                "qat1_raw_key_arn",
                "arn:aws:kms:us-east-2:767397897469:"
                "key/11111111-1111-1111-1111-111111111111",
            ),
            "redis": ("otp_redis_cache_name", "other"),
            "redis endpoint": (
                "otp_redis_endpoint",
                "layerv-nhp-sandbox-control-otp-other."
                "serverless.use2.cache.amazonaws.com:6379",
            ),
        }
        for label, (key, replacement) in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(
                    lambda value, key=key, replacement=replacement: value["contract"][
                        "global"
                    ].__setitem__(key, replacement)
                )

    def test_rejects_function_inventory_and_capacity_drift(self) -> None:
        cases = {
            "missing function": lambda value: value["contract"]["functions"].pop(
                "layerv-nhp-sandbox-ca-ra"
            ),
            "extra function": lambda value: value["contract"]["functions"].__setitem__(
                "layerv-nhp-sandbox-ca-extra",
                copy.deepcopy(value["contract"]["functions"]["layerv-nhp-sandbox-ca-ia"]),
            ),
            "steady algebra": lambda value: value["contract"]["functions"][
                "layerv-nhp-sandbox-ca-ia"
            ].__setitem__("steady_reserved_concurrency", 3),
            "rollout algebra": lambda value: value["contract"]["functions"][
                "layerv-nhp-sandbox-ca-ia"
            ].__setitem__("rollout_reserved_concurrency", 5),
            "caller concurrency": lambda value: value["contract"]["functions"][
                "layerv-nhp-sandbox-ca-ia"
            ].__setitem__("max_caller_in_flight", 1),
            "caller rate": lambda value: value["contract"]["functions"][
                "layerv-nhp-sandbox-ca-ia"
            ].__setitem__("max_caller_requests_per_second", 5),
            "regional aggregate": lambda value: value["contract"]["global"].__setitem__(
                "regional_lambda_concurrency_quota", 110
            ),
            "regional steady aggregate": lambda value: (
                value["contract"]["global"].__setitem__(
                    "regional_lambda_concurrency_quota", 112
                ),
                [
                    function.update(
                        {
                            "steady_provisioned_concurrency": 5,
                            "steady_reserved_concurrency": 5,
                        }
                    )
                    for function in value["contract"]["functions"].values()
                ],
            ),
            "unknown operation": lambda value: value["contract"]["global"][
                "caller_capacity"
            ]["hub_workers"]["preinvoke_limits"].__setitem__("unknown", 1),
            "cell mismatch": lambda value: value["contract"]["global"][
                "caller_capacity"
            ]["cell_workers"].__setitem__(
                "cell2",
                copy.deepcopy(
                    value["contract"]["global"]["caller_capacity"]["cell_workers"][
                        "cell0"
                    ]
                ),
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(mutate)


class GitBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        run("git", "init", "-q", cwd=self.root)
        run("git", "config", "user.name", "Test", cwd=self.root)
        run("git", "config", "user.email", "test@example.com", cwd=self.root)
        run("git", "config", "commit.gpgsign", "false", cwd=self.root)
        self.path = self.root / MANIFEST_REL
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(MANIFEST.read_bytes())
        self.path.chmod(0o644)
        run("git", "add", str(MANIFEST_REL), cwd=self.root)
        run("git", "commit", "-q", "-m", "basis", cwd=self.root)
        self.source_commit = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.strip()
        (self.root / "unrelated.txt").write_text("later\n", encoding="utf-8")
        run("git", "add", "unrelated.txt", cwd=self.root)
        run("git", "commit", "-q", "-m", "unrelated", cwd=self.root)
        self.head = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.strip()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def generate(
        self,
        *,
        mode: str = "sandbox-exact-main",
        manifest: str = MANIFEST_REL.as_posix(),
        expected: str | None = None,
        output: Path | None = None,
        runtime_functions_enabled: bool = False,
        hub_edge_enabled: bool = False,
        hub_worker_enabled: bool = False,
        proof_mutation_controls_enabled: bool = False,
        proof_policy_consumers_staged: bool = False,
        proof_policy_selected_color: str | None = None,
        proof_policy_prepared_color: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        destination = output or (self.root / "generated.tfvars.json")
        args = [
            "python3",
            str(SCRIPT),
            "--mode",
            mode,
            "--repository-root",
            str(self.root),
            "--manifest",
            manifest,
            "--expected-checkout-commit",
            expected or self.head,
            "--output",
            str(destination),
        ]
        if runtime_functions_enabled:
            args.append("--runtime-functions-enabled")
        if hub_edge_enabled:
            args.append("--hub-edge-enabled")
        if hub_worker_enabled:
            args.append("--hub-worker-enabled")
        if proof_mutation_controls_enabled:
            args.append("--proof-mutation-controls-enabled")
        if proof_policy_consumers_staged:
            args.append("--proof-policy-consumers-staged")
        if proof_policy_selected_color is not None:
            args.extend(
                ["--proof-policy-selected-color", proof_policy_selected_color]
            )
        if proof_policy_prepared_color is not None:
            args.extend(
                ["--proof-policy-prepared-color", proof_policy_prepared_color]
            )
        return run(*args, cwd=self.root, check=False)

    def test_generates_stable_blob_owned_evidence_and_private_atomic_output(self) -> None:
        output = self.root / "generated.tfvars.json"
        result = self.generate(output=output)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        generated = json.loads(output.read_text(encoding="utf-8"))
        evidence = generated["authority_runtime_contract"]["global"]["basis_evidence"]
        self.assertEqual(summary["source_commit"], self.source_commit)
        self.assertEqual(evidence["source_commit"], self.source_commit)
        self.assertEqual(
            evidence["sha256"],
            __import__("hashlib").sha256(MANIFEST.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            generated["authority_runtime_contract"]["provisioned_cells_evidence"],
            evidence,
        )
        self.assertTrue(generated["authority_runtime_contract_evidence_verified"])
        self.assertTrue(
            all(
                function["basis_evidence"] == evidence
                and function["result_evidence"] is None
                for function in generated["authority_runtime_contract"][
                    "functions"
                ].values()
            )
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.read_text(encoding="utf-8"), canonical(generated))

    def test_runtime_functions_enable_flag_governs_gate_key(self) -> None:
        # Dark by default: without --runtime-functions-enabled the gate key is
        # absent entirely, so the committed Terraform default (false) governs.
        default_output = self.root / "default.tfvars.json"
        default_result = self.generate(output=default_output)
        self.assertEqual(default_result.returncode, 0, default_result.stderr)
        default_generated = json.loads(default_output.read_text(encoding="utf-8"))
        self.assertNotIn("authority_runtime_functions_enabled", default_generated)

        # Opt-in: the emitted key is exactly the Terraform variable name, set to
        # a genuine JSON boolean true (assertIs rejects a truthy 1 or "true").
        enabled_output = self.root / "enabled.tfvars.json"
        enabled_result = self.generate(
            output=enabled_output, runtime_functions_enabled=True
        )
        self.assertEqual(enabled_result.returncode, 0, enabled_result.stderr)
        enabled_generated = json.loads(enabled_output.read_text(encoding="utf-8"))
        self.assertIs(
            enabled_generated["authority_runtime_functions_enabled"], True
        )

        # The opt-in adds ONLY that one top-level key; the verified contract and
        # the evidence latch are otherwise identical to the default output.
        self.assertEqual(
            set(enabled_generated) - set(default_generated),
            {"authority_runtime_functions_enabled"},
        )
        self.assertEqual(set(default_generated) - set(enabled_generated), set())
        self.assertEqual(
            enabled_generated["authority_runtime_contract"],
            default_generated["authority_runtime_contract"],
        )
        self.assertEqual(
            enabled_generated["authority_runtime_contract_evidence_verified"],
            default_generated["authority_runtime_contract_evidence_verified"],
        )

        # Emission stays deterministic canonical sorted two-space JSON with one
        # trailing newline, so the apply job's byte cmp against the reviewed plan
        # input holds whenever the same flag value is passed.
        self.assertEqual(
            enabled_output.read_text(encoding="utf-8"), canonical(enabled_generated)
        )

    def test_proof_opt_in_adds_exact_caller_function_and_root_inputs(self) -> None:
        dark_output = self.root / "proof-dark.tfvars.json"
        dark_result = self.generate(
            output=dark_output,
            runtime_functions_enabled=True,
        )
        self.assertEqual(dark_result.returncode, 0, dark_result.stderr)
        dark = json.loads(dark_output.read_text(encoding="utf-8"))
        dark_contract = dark["authority_runtime_contract"]
        self.assertNotIn(
            "proof_controller",
            dark_contract["global"]["caller_capacity"],
        )
        self.assertNotIn(
            "layerv-nhp-sandbox-ca-pm",
            dark_contract["functions"],
        )
        self.assertNotIn(
            "authority_proof_mutation_controls_enabled",
            dark,
        )
        self.assertNotIn("authority_proof_mutation_owner_id", dark)
        self.assertNotIn(
            "authority_proof_mutation_controller_role_arns",
            dark,
        )

        enabled_output = self.root / "proof-enabled.tfvars.json"
        enabled_result = self.generate(
            output=enabled_output,
            runtime_functions_enabled=True,
            proof_mutation_controls_enabled=True,
        )
        self.assertEqual(enabled_result.returncode, 0, enabled_result.stderr)
        self.assertEqual(json.loads(enabled_result.stdout)["function_count"], 15)

        enabled = json.loads(enabled_output.read_text(encoding="utf-8"))
        contract = enabled["authority_runtime_contract"]
        self.assertEqual(
            contract["global"]["caller_capacity"]["proof_controller"],
            {
                "max_replicas": 1,
                "preinvoke_limits": {
                    "mutate_proof_agent": 1,
                    "prepare_proof_credential_recovery": 1,
                },
                "preinvoke_rate_limits": {
                    "mutate_proof_agent": {
                        "burst": 1,
                        "refill_per_second": 1,
                    },
                    "prepare_proof_credential_recovery": {
                        "burst": 1,
                        "refill_per_second": 1,
                    }
                },
            },
        )
        self.assertEqual(
            contract["functions"]["layerv-nhp-sandbox-ca-pm"],
            {
                "basis_evidence": contract["global"]["basis_evidence"],
                "max_caller_in_flight": 1,
                "max_caller_requests_per_second": 2,
                "result_evidence": None,
                "rollback_retention_seconds": 3600,
                "rollout_active_provisioned_concurrency": 1,
                "rollout_reserved_concurrency": 2,
                "rollout_standby_provisioned_concurrency": 1,
                "steady_provisioned_concurrency": 1,
                "steady_reserved_concurrency": 1,
            },
        )
        self.assertEqual(
            contract["functions"]["layerv-nhp-sandbox-ca-pcr"],
            contract["functions"]["layerv-nhp-sandbox-ca-pm"],
        )
        self.assertEqual(
            set(contract["functions"]),
            set(dark_contract["functions"])
            | {"layerv-nhp-sandbox-ca-pm", "layerv-nhp-sandbox-ca-pcr"},
        )
        self.assertIs(
            enabled["authority_proof_mutation_controls_enabled"],
            True,
        )

        one_color = self.generate(
            output=self.root / "proof-rollout-one-color.json",
            runtime_functions_enabled=True,
            hub_edge_enabled=True,
            hub_worker_enabled=True,
            proof_mutation_controls_enabled=True,
            proof_policy_consumers_staged=True,
            proof_policy_selected_color="blue",
        )
        self.assertNotEqual(one_color.returncode, 0)
        self.assertIn("exact selected and prepared colors", one_color.stderr)

        rollout_output = self.root / "proof-rollout.json"
        rollout = self.generate(
            output=rollout_output,
            runtime_functions_enabled=True,
            hub_edge_enabled=True,
            hub_worker_enabled=True,
            proof_mutation_controls_enabled=True,
            proof_policy_consumers_staged=True,
            proof_policy_selected_color="blue",
            proof_policy_prepared_color="green",
        )
        self.assertEqual(rollout.returncode, 0, rollout.stderr)
        rollout_payload = json.loads(rollout_output.read_text(encoding="utf-8"))
        self.assertEqual(rollout_payload["authority_proof_policy_selected_color"], "blue")
        self.assertEqual(rollout_payload["authority_proof_policy_prepared_color"], "green")
        self.assertEqual(
            enabled["authority_proof_mutation_owner_id"],
            CHECKER.EXPECTED_PROOF_OWNER_ID,
        )
        self.assertEqual(
            enabled["authority_proof_mutation_controller_role_arns"],
            [CHECKER.EXPECTED_PROOF_CONTROLLER_ROLE_ARN],
        )
        self.assertEqual(
            set(enabled) - set(dark),
            {
                "authority_proof_mutation_controller_role_arns",
                "authority_proof_mutation_controls_enabled",
                "authority_proof_mutation_owner_id",
            },
        )
        self.assertEqual(
            enabled_output.read_text(encoding="utf-8"),
            canonical(enabled),
        )

    def test_proof_inputs_are_closed_around_the_explicit_gate(
        self,
    ) -> None:
        without_runtime = self.generate(
            output=self.root / "proof-without-runtime.json",
            proof_mutation_controls_enabled=True,
        )
        self.assertNotEqual(without_runtime.returncode, 0)
        self.assertIn("runtime functions", without_runtime.stderr)

        consumers_without_mutation = self.generate(
            output=self.root / "proof-consumers-without-mutation.json",
            runtime_functions_enabled=True,
            proof_policy_consumers_staged=True,
        )
        self.assertNotEqual(consumers_without_mutation.returncode, 0)
        self.assertIn("require proof mutation controls", consumers_without_mutation.stderr)

        consumers_output = self.root / "proof-consumers-enabled.json"
        consumers = self.generate(
            output=consumers_output,
            runtime_functions_enabled=True,
            proof_mutation_controls_enabled=True,
            proof_policy_consumers_staged=True,
        )
        self.assertEqual(consumers.returncode, 0, consumers.stderr)
        self.assertIs(
            json.loads(consumers_output.read_text(encoding="utf-8"))[
                "authority_proof_policy_consumers_staged"
            ],
            True,
        )

    def test_rejects_mode_path_checkout_and_byte_mismatch(self) -> None:
        cases = {
            "mode": {"mode": "sandbox"},
            "absolute path": {"manifest": str(self.path)},
            "traversal": {
                "manifest": "docs/evidence/connector-authority/v1/../basis.json"
            },
            "wrong checkout": {"expected": self.source_commit},
        }
        for label, kwargs in cases.items():
            with self.subTest(label=label):
                result = self.generate(
                    output=self.root / f"{label.replace(' ', '-')}.json", **kwargs
                )
                self.assertNotEqual(result.returncode, 0)

        self.path.write_text(self.path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        result = self.generate(output=self.root / "tampered.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bytes differ", result.stderr)

    def test_rejects_symlink_and_non_regular_source_mode(self) -> None:
        original = self.path.read_bytes()
        self.path.unlink()
        self.path.symlink_to(self.root / "unrelated.txt")
        result = self.generate(output=self.root / "symlink.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)

        self.path.unlink()
        self.path.write_bytes(original)
        self.path.chmod(0o755)
        run("git", "add", str(MANIFEST_REL), cwd=self.root)
        run("git", "commit", "-q", "-m", "executable", cwd=self.root)
        executable_head = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.strip()
        result = self.generate(
            expected=executable_head, output=self.root / "executable.json"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("100644", result.stderr)

    def test_rejects_duplicate_keys_and_noncanonical_json(self) -> None:
        self.path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        run("git", "add", str(MANIFEST_REL), cwd=self.root)
        run("git", "commit", "-q", "-m", "duplicate", cwd=self.root)
        duplicate_head = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.strip()
        result = self.generate(
            expected=duplicate_head, output=self.root / "duplicate.json"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate key", result.stderr)

    def test_rejects_shallow_history(self) -> None:
        clone = self.root.parent / f"{self.root.name}-shallow"
        run(
            "git",
            "clone",
            "-q",
            "--depth",
            "1",
            f"file://{self.root}",
            str(clone),
            cwd=self.root.parent,
        )
        head = run("git", "rev-parse", "HEAD", cwd=clone).stdout.strip()
        output = clone / "generated.json"
        result = run(
            "python3",
            str(SCRIPT),
            "--mode",
            "sandbox-exact-main",
            "--repository-root",
            str(clone),
            "--manifest",
            MANIFEST_REL.as_posix(),
            "--expected-checkout-commit",
            head,
            "--output",
            str(output),
            cwd=clone,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full Git history", result.stderr)
        subprocess.run(["rm", "-rf", str(clone)], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
