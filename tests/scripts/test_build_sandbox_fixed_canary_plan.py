from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_sandbox_fixed_canary_plan",
    ROOT / ".github/scripts/build_sandbox_fixed_canary_plan.py",
)
assert SPEC and SPEC.loader
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)

OWNER = "abcdefghijklmnopqrstuv@clients"
KEY = "A" * 43 + "="
NHP_SOURCE = "a" * 40
QURL_GO_SOURCE = "b" * 40


def runtime() -> dict:
    body = {
        "schema": 1,
        "environment": "sandbox",
        "aws_account_id": PLAN.ACCOUNT_ID,
        "aws_region": PLAN.REGION,
        "active_colors": {"server": "blue", "ac": "green"},
        "cohorts": {
            "blue": {
                "server_asg": "layerv-nhp-sandbox-server",
                "ac_asg": "layerv-nhp-sandbox-ac",
                "server": {"source_sha": NHP_SOURCE, "image_digest": "sha256:" + "1" * 64},
                "ac": {"source_sha": NHP_SOURCE, "image_digest": "sha256:" + "2" * 64},
            },
            "green": {
                "server_asg": "layerv-nhp-sandbox-server-green",
                "ac_asg": "layerv-nhp-sandbox-ac-green",
                "server": {"source_sha": "3" * 40, "image_digest": "sha256:" + "3" * 64},
                "ac": {"source_sha": "4" * 40, "image_digest": "sha256:" + "4" * 64},
            },
        },
        "relay": {"asg": PLAN.RELAY_ASG, "hostname": "relay.qurl.link.layerv.xyz", "source_sha": NHP_SOURCE, "image_digest": "sha256:" + "5" * 64},
        "session_control_table": PLAN.SESSION_TABLE,
        "qurl_agent_keys_table": PLAN.AGENT_KEYS_TABLE,
        "cell_id": PLAN.CELL_ID,
        "assignment_generation": 1,
        "hub_endpoint": {"host": "hub.nhp.layerv.xyz", "port": 443, "server_public_key_b64": KEY},
        "cell_endpoint": {"host": "cell0.nhp.layerv.xyz", "port": 443, "server_public_key_b64": KEY},
        "frps_host": "connect.layerv.xyz",
        "issuer": {"kid": "qurl-issuer-sandbox-2026-07", "spki_der_b64": "issuer-key"},
        "asgs": {},
        "tables": {},
        "qurl_service": {
            "source_tag": "1234567",
            "image_digest": "sha256:" + "6" * 64,
            "platform_image_digest": "sha256:" + "7" * 64,
            "task_definition": "arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-cell0-qurl-api:1",
        },
        "parameter_versions": {},
    }
    body["runtime_sha256"] = hashlib.sha256(
        (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    return body


def write_runtime(path: Path, value: dict) -> None:
    path.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


class BuildSandboxFixedCanaryPlanTest(unittest.TestCase):
    def test_plan_is_exact_go_struct_order_and_shared_four_identity_authority(self) -> None:
        value = runtime()
        plan = PLAN.build_plan(value, OWNER, NHP_SOURCE, QURL_GO_SOURCE)
        self.assertEqual(
            list(plan),
            [
                "schema",
                "environment",
                "generation_id",
                "owner_subject",
                "aws_account_id",
                "aws_region",
                "nhp_source_sha",
                "qurl_go_source_sha",
                "cohorts",
                "identities",
            ],
        )
        self.assertEqual(len(plan["cohorts"]), 1)
        self.assertNotIn("color", plan["cohorts"][0])
        self.assertEqual(plan["cohorts"][0]["server_asg"], value["cohorts"]["blue"]["server_asg"])
        self.assertEqual(plan["cohorts"][0]["ac_asg"], value["cohorts"]["green"]["ac_asg"])
        self.assertEqual(len(plan["identities"]), 4)
        self.assertEqual([item["label"] for item in plan["identities"]], list(PLAN.LABELS))
        self.assertTrue(all("color" not in item for item in plan["identities"]))
        self.assertEqual(
            [(item["frps_selector"]["resource_id"], item["frps_selector"]["port"]) for item in plan["identities"][:4]],
            list(PLAN.SELECTORS),
        )
        self.assertEqual(plan, PLAN.build_plan(value, OWNER, NHP_SOURCE, QURL_GO_SOURCE))
        self.assertEqual(plan["nhp_source_sha"], NHP_SOURCE)
        self.assertEqual(plan["qurl_go_source_sha"], QURL_GO_SOURCE)
        for source in ("bad", "A" * 40):
            with self.assertRaises(PLAN.PlanError):
                PLAN.build_plan(value, OWNER, source, QURL_GO_SOURCE)
        opposite = runtime()
        opposite["active_colors"] = {"server": "green", "ac": "blue"}
        opposite_plan = PLAN.build_plan(opposite, OWNER, NHP_SOURCE, QURL_GO_SOURCE)
        self.assertEqual(opposite_plan["cohorts"][0]["server_asg"], opposite["cohorts"]["green"]["server_asg"])
        self.assertEqual(opposite_plan["cohorts"][0]["ac_asg"], opposite["cohorts"]["blue"]["ac_asg"])
        generation_two = runtime()
        generation_two["assignment_generation"] = 2
        self.assertEqual(PLAN.build_plan(generation_two, OWNER, NHP_SOURCE, QURL_GO_SOURCE)["cohorts"][0]["assignment_generation"], 2)

    def test_runtime_digest_and_every_authority_field_fail_closed(self) -> None:
        mutations = (
            ("environment", "prod"),
            ("aws_account_id", "235500187906"),
            ("aws_region", "us-east-1"),
            ("relay", {"asg": "other-relay", "hostname": "relay.qurl.link.layerv.xyz", "source_sha": "5" * 40, "image_digest": "sha256:" + "5" * 64}),
            ("session_control_table", "other-session"),
            ("qurl_agent_keys_table", "other-agent"),
            ("cell_id", "cell1"),
            ("assignment_generation", 0),
            ("frps_host", "connect.layerv.ai"),
        )
        for key, replacement in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw_directory:
                changed = runtime()
                changed[key] = replacement
                body = dict(changed)
                body.pop("runtime_sha256")
                changed["runtime_sha256"] = hashlib.sha256(
                    (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
                ).hexdigest()
                path = Path(raw_directory) / "runtime.json"
                write_runtime(path, changed)
                with self.assertRaises(PLAN.PlanError):
                    PLAN.load_runtime(path)

        with tempfile.TemporaryDirectory() as raw_directory:
            changed = runtime()
            changed["active_colors"]["server"] = "purple"
            body = dict(changed)
            body.pop("runtime_sha256")
            changed["runtime_sha256"] = hashlib.sha256(
                (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).hexdigest()
            path = Path(raw_directory) / "runtime.json"
            write_runtime(path, changed)
            with self.assertRaises(PLAN.PlanError):
                PLAN.load_runtime(path)

    def test_cohort_endpoint_and_inventory_mutations_reject(self) -> None:
        changes = []
        changed = runtime()
        changed["hub_endpoint"]["port"] = 62206
        changes.append(changed)
        changed = runtime()
        changed["cell_endpoint"]["server_public_key_b64"] = "bad"
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["blue"]["server_asg"] = ""
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["blue"]["server_asg"] = changed["cohorts"]["green"]["server_asg"]
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["green"]["ac_asg"] = changed["cohorts"]["blue"]["ac_asg"]
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["green"]["extra"] = "drift"
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["blue"]["server"]["source_sha"] = "not-a-source-sha"
        changes.append(changed)
        changed = runtime()
        changed["cohorts"]["blue"]["ac"]["source_sha"] = "not-a-source-sha"
        changes.append(changed)
        changed = runtime()
        changed["relay"]["source_sha"] = "not-a-source-sha"
        changes.append(changed)
        changed = runtime()
        changed["assignment_generation"] = "1"
        changes.append(changed)
        for index, changed in enumerate(changes):
            body = copy.deepcopy(changed)
            body.pop("runtime_sha256")
            changed["runtime_sha256"] = hashlib.sha256(
                (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).hexdigest()
            with self.subTest(index=index), tempfile.TemporaryDirectory() as raw_directory:
                path = Path(raw_directory) / "runtime.json"
                write_runtime(path, changed)
                with self.assertRaises(PLAN.PlanError):
                    PLAN.load_runtime(path)

    def test_private_plan_write_is_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            output = directory / "plan.json"
            plan = PLAN.build_plan(runtime(), OWNER, NHP_SOURCE, QURL_GO_SOURCE)
            PLAN.write_plan(output, plan)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_bytes()), plan)
            with self.assertRaises(PLAN.PlanError):
                PLAN.write_plan(output, plan)

    def test_successor_generation_global_attempts_are_accepted_but_bounded(self) -> None:
        value = runtime()
        plan = PLAN.build_plan(value, OWNER, NHP_SOURCE, QURL_GO_SOURCE)
        common = {
            "runtime": value,
            "plan": plan,
            "operation": "lifecycle",
            "transport": "direct",
            "authority": {"key": "authority", "version_id": "1" * 64, "sha256": "2" * 64},
            "run_ids": ["0" * 16, "1" * 16, "2" * 16],
            "prepared_at_ms": 1_800_000_000_000,
            "expires_at_ms": 1_800_001_800_000,
            "api_key_file": "/private/api-key",
            "deployment_file": "/private/deployment.json",
            "deployment_sha256": "3" * 64,
            "lifecycle_command_sha256": "4" * 64,
            "qurl_binary": "/private/qurl",
            "qurl_binary_sha256": "5" * 64,
            "qurl_source_sha": "6" * 40,
            "release_id": "7" * 64,
        }
        self.assertEqual(PLAN.build_lifecycle_input(**common, attempt=9)["attempt"], 9)
        with self.assertRaises(PLAN.PlanError):
            PLAN.build_lifecycle_input(**common, attempt=10)
        recovery = dict(common)
        recovery.update(operation="recover-prepared", run_ids=["3" * 16])
        self.assertEqual(PLAN.build_lifecycle_input(**recovery, attempt=3)["attempt"], 3)
        with self.assertRaises(PLAN.PlanError):
            PLAN.build_lifecycle_input(**recovery, attempt=4)


if __name__ == "__main__":
    unittest.main()
