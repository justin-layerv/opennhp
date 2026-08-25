from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNTIME = load("read_sandbox_fixed_canary_runtime", ".github/scripts/read_sandbox_fixed_canary_runtime.py")
PLAN = load("build_sandbox_fixed_canary_plan", ".github/scripts/build_sandbox_fixed_canary_plan.py")
JOURNEY = load("run_sandbox_fixed_canary_customer_journey", ".github/scripts/run_sandbox_fixed_canary_customer_journey.py")


class STS:
    @staticmethod
    def get_caller_identity() -> dict:
        return {"Account": RUNTIME.ACCOUNT}


class SSM:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def get_parameters(self, *, Names: list[str], WithDecryption: bool) -> dict:
        assert WithDecryption is False
        return {
            "Parameters": [
                {"Name": name, "Value": self.values[name], "Version": 1}
                | {"LastModifiedDate": dt.datetime(2026, 8, 25, tzinfo=dt.UTC)}
                for name in Names
            ],
            "InvalidParameters": [],
        }


class Session:
    region_name = RUNTIME.REGION

    def __init__(self, values: dict[str, str]) -> None:
        self.clients = {"sts": STS(), "ssm": SSM(values)}

    def client(self, name: str):
        return self.clients.setdefault(name, object())


def values() -> dict[str, str]:
    result = {
        name: "value"
        for name in RUNTIME.PARAMETERS
    }
    result.update(
        {
            "/sandbox/nhp/server/active-color": "blue",
            "/sandbox/nhp/ac/active-color": "green",
            "/sandbox/nhp/server/asg-name": RUNTIME.ASGS["server_blue"],
            "/sandbox/nhp/server/green-asg-name": RUNTIME.ASGS["server_green"],
            "/sandbox/nhp/ac/asg-name": RUNTIME.ASGS["ac_blue"],
            "/sandbox/nhp/ac/green-asg-name": RUNTIME.ASGS["ac_green"],
            "/sandbox/nhp/relay/asg-name": RUNTIME.ASGS["relay"],
            "/sandbox/nhp/server/image-tag": "1" * 40,
            "/sandbox/nhp/server/green-image-tag": "2" * 40,
            "/sandbox/nhp/ac/image-tag": "3" * 40,
            "/sandbox/nhp/ac/green-image-tag": "1" * 40,
            "/sandbox/nhp/relay/image-tag": "1" * 40,
            "/sandbox/nhp/control/hub/identity/public-key": "A" * 43 + "=",
            "/sandbox/nhp/qurl/qv2-issuer-key": "qurl-issuer-sandbox-2026-07="
            + base64.b64encode(b"i" * 91).decode(),
            "/sandbox/nhp/customer-journey/fixed-canary-v1": json.dumps(
                {
                    "schema": 1,
                    "environment": "sandbox",
                    "assignment_generation": 2,
                    "authority_role_arn": "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-fixed-canary",
                    "state_table": "layerv-nhp-sandbox-fixed-canary",
                    "auth0_secret_name": "layerv-nhp-sandbox-auth0-smoke-test-credentials",
                    "secret_map": {f"shared/{label}": f"arn:{label}" for label in PLAN.LABELS},
                    "otp_mailbox": {"queue_url": "https://sqs.example", "bucket": "mailbox", "recipient": "canary@example.com"},
                },
                separators=(",", ":"),
            ),
        }
    )
    return result


class SandboxFixedCanaryRuntimeContractTest(unittest.TestCase):
    @staticmethod
    def asg_fixture() -> tuple[mock.Mock, mock.Mock, dict[str, dict[str, str]], dict[str, dict[str, object]]]:
        images = {
            label: {"source_sha": format(index + 1, "x") * 40, "image_digest": "sha256:" + format(index + 1, "x") * 64}
            for index, label in enumerate(RUNTIME.ASGS)
        }
        parameters = {
            parameter: {
                "value": images[label]["source_sha"],
                "version": 1,
                "last_modified_ms": int(dt.datetime(2026, 8, 25, tzinfo=dt.UTC).timestamp() * 1000),
            }
            for label, (_repository, parameter) in RUNTIME.IMAGE_RUNTIME.items()
        }
        groups = []
        templates: dict[str, dict] = {}
        actual: dict[str, dict] = {}
        for index, (label, name) in enumerate(RUNTIME.ASGS.items(), start=1):
            instance_id = f"i-{index:08x}"
            template_id = f"lt-{index:08x}"
            repository, parameter = RUNTIME.IMAGE_RUNTIME[label]
            user_data = f'{parameter}\n{RUNTIME.ACCOUNT}.dkr.ecr.{RUNTIME.REGION}.amazonaws.com/{repository}\n'
            if label.startswith("server_"):
                user_data += (
                    f'AgentKeysTable = "{RUNTIME.AGENT_TABLE}"\n'
                    f'SessionControlTable = "{RUNTIME.SESSION_TABLE}"\n'
                    "NativeSessionOperations = true\n"
                )
            launch = {"LaunchTemplateId": template_id, "LaunchTemplateName": f"template-{index}", "Version": "7"}
            groups.append(
                {
                    "AutoScalingGroupName": name,
                    "DesiredCapacity": 1,
                    "MinSize": 1,
                    "MaxSize": 1,
                    "LaunchTemplate": launch,
                    "Instances": [
                        {
                            "InstanceId": instance_id,
                            "HealthStatus": "Healthy",
                            "LifecycleState": "InService",
                            "LaunchTemplate": launch,
                        }
                    ],
                }
            )
            templates[template_id] = {
                "VersionNumber": 7,
                "LaunchTemplateData": {"UserData": base64.b64encode(user_data.encode()).decode()},
            }
            actual[instance_id] = {
                "InstanceId": instance_id,
                "LaunchTemplate": launch,
                "LaunchTime": dt.datetime(2026, 8, 25, 1, tzinfo=dt.UTC),
                "State": {"Name": "running"},
            }
        asg = mock.Mock()
        asg.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": groups}
        ec2 = mock.Mock()
        ec2.describe_launch_template_versions.side_effect = lambda *, LaunchTemplateId, Versions: {
            "LaunchTemplateVersions": [copy.deepcopy(templates[LaunchTemplateId])]
        }
        ec2.describe_instances.side_effect = lambda *, InstanceIds: {
            "Reservations": [{"Instances": [copy.deepcopy(actual[instance_id]) for instance_id in InstanceIds]}]
        }
        return asg, ec2, images, parameters

    def test_active_instances_exactly_bind_launch_template_and_image_authority(self) -> None:
        asg, ec2, images, parameters = self.asg_fixture()
        projection = RUNTIME._asgs(asg, ec2, "blue", "green", images, parameters)
        self.assertEqual(projection["server_blue"]["source_sha"], images["server_blue"]["source_sha"])
        self.assertEqual(projection["ac_green"]["launch_template_version"], "7")

        mutations = []
        stale_asg = copy.deepcopy(asg.describe_auto_scaling_groups.return_value)
        stale_asg["AutoScalingGroups"][0]["Instances"][0]["LaunchTemplate"]["Version"] = "6"
        mutations.append(("asg-instance-version", stale_asg, ec2))

        mixed_ec2 = copy.deepcopy(ec2)
        original_describe = ec2.describe_instances.side_effect
        mixed_ec2.describe_instances.side_effect = lambda *, InstanceIds: {
            "Reservations": [{"Instances": [
                {**row, "LaunchTemplate": {**row["LaunchTemplate"], "Version": "6"}}
                if index == 0 else row
                for index, row in enumerate(original_describe(InstanceIds=InstanceIds)["Reservations"][0]["Instances"])
            ]}]
        }
        mutations.append(("actual-instance-version", asg.describe_auto_scaling_groups.return_value, mixed_ec2))

        stale_launch = copy.deepcopy(ec2)
        stale_launch.describe_instances.side_effect = lambda *, InstanceIds: {
            "Reservations": [{"Instances": [
                {**row, "LaunchTime": dt.datetime(2026, 8, 24, tzinfo=dt.UTC)}
                for row in original_describe(InstanceIds=InstanceIds)["Reservations"][0]["Instances"]
            ]}]
        }
        mutations.append(("instance-before-image-slot", asg.describe_auto_scaling_groups.return_value, stale_launch))

        for label, response, ec2_client in mutations:
            changed_asg = mock.Mock()
            changed_asg.describe_auto_scaling_groups.return_value = response
            with self.subTest(label=label), self.assertRaises(RUNTIME.RuntimeErrorExact):
                RUNTIME._asgs(changed_asg, ec2_client, "blue", "green", images, parameters)

        drifted = copy.deepcopy(images)
        drifted["relay"]["source_sha"] = "f" * 40
        with self.assertRaises(RUNTIME.RuntimeErrorExact):
            RUNTIME._asgs(asg, ec2, "blue", "green", drifted, parameters)

    def test_digest_qualified_image_slot_binds_tag_and_ecr_digest(self) -> None:
        source = "a" * 40
        digest = "sha256:" + "b" * 64
        ecr = mock.Mock()
        ecr.describe_images.return_value = {"imageDetails": [{"imageDigest": digest, "imageTags": [source]}]}
        self.assertEqual(
            RUNTIME._image(ecr, "layerv/nhp-server", source + "@" + digest),
            {"source_sha": source, "image_digest": digest},
        )
        with self.assertRaises(RUNTIME.RuntimeErrorExact):
            RUNTIME._image(ecr, "layerv/nhp-server", source + "@sha256:" + "c" * 64)

    def test_qurl_service_requires_stable_ecs_projection_and_matching_ecr_index(self) -> None:
        projection = {
            "task_definition": "arn:task-definition:1955",
            "task_arns": ["arn:task:1"],
            "image_digest": "sha256:" + "6" * 64,
            "source_tag": "cfa0f3d",
        }
        index = {"image_digest": projection["image_digest"], "platform_image_digest": "sha256:" + "7" * 64}
        with (
            mock.patch.object(RUNTIME, "_qurl_service_projection", side_effect=[projection, dict(projection)]),
            mock.patch.object(RUNTIME, "_qurl_index", return_value=index) as read_index,
        ):
            value = RUNTIME._qurl_service({}, object(), object())
        self.assertEqual(value["source_tag"], "cfa0f3d")
        self.assertEqual(value["platform_image_digest"], index["platform_image_digest"])
        read_index.assert_called_once_with(mock.ANY, "cfa0f3d")

        moved = {**projection, "task_definition": "arn:task-definition:1956"}
        with (
            mock.patch.object(RUNTIME, "_qurl_service_projection", side_effect=[projection, moved]),
            mock.patch.object(RUNTIME, "_qurl_index", return_value=index),
            self.assertRaises(RUNTIME.RuntimeErrorExact),
        ):
            RUNTIME._qurl_service({}, object(), object())

    def test_reader_output_builds_plan_and_exact_lifecycle_inputs(self) -> None:
        source = RUNTIME._source_contract()
        cell = {
            "cell_id": source["cell"]["cell_id"],
            "endpoint_revision": source["cell"]["endpoint_revision"],
            "host": source["cell"]["host"],
            "port": source["cell"]["port"],
            "server_public_key_b64": source["cell"]["server_public_key_b64"],
        }
        with (
            mock.patch.object(RUNTIME, "_asgs", return_value={}) as read_asgs,
            mock.patch.object(
                RUNTIME,
                "_image",
                side_effect=lambda _client, _repository, slot: {
                    "source_sha": slot.split("@", 1)[0],
                    "image_digest": "sha256:" + slot[0] * 64,
                },
            ),
            mock.patch.object(RUNTIME, "_cell_catalog", side_effect=lambda _client, exact: cell if exact == source["cell"] else None),
            mock.patch.object(RUNTIME, "_table", side_effect=lambda _client, name: {"name": name, "arn": "arn:" + name}),
            mock.patch.object(
                RUNTIME,
                "_qurl_service",
                return_value={
                    "source_tag": "cfa0f3d",
                    "image_digest": "sha256:" + "6" * 64,
                    "platform_image_digest": "sha256:" + "7" * 64,
                    "task_definition": "arn:task-definition",
                },
            ),
        ):
            runtime = RUNTIME.collect(Session(values()))
        self.assertEqual(read_asgs.call_count, 2)
        for call in read_asgs.call_args_list:
            self.assertEqual(call.args[2:4], ("blue", "green"))

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            runtime_path = directory / "runtime.json"
            RUNTIME.write_private(runtime_path, runtime)
            loaded, raw = PLAN.load_runtime(runtime_path)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), hashlib.sha256(RUNTIME.canonical(runtime)).hexdigest())
            plan = PLAN.build_plan(loaded, "abcdefghijklmnopqrstuv@clients", "a" * 40, "b" * 40)
            common = {
                "runtime": loaded,
                "plan": plan,
                "authority": {"key": "authority", "version_id": "a" * 64, "sha256": "b" * 64},
                "attempt": 1,
                "prepared_at_ms": 1_800_000_000_000,
                "expires_at_ms": 1_800_001_200_000,
                "api_key_file": "/private/api-key",
                "deployment_file": "/private/deployment.json",
                "deployment_sha256": "c" * 64,
                "lifecycle_command_sha256": "d" * 64,
                "qurl_binary": "/private/qurl",
                "qurl_binary_sha256": "e" * 64,
                "qurl_source_sha": "f" * 40,
            }
            direct = PLAN.build_lifecycle_input(
                **common,
                operation="lifecycle",
                transport="direct",
                run_ids=["0" * 16, "1" * 16, "2" * 16],
            )
            recovery = PLAN.build_lifecycle_input(
                **common,
                operation="recover-prepared",
                transport="direct",
                run_ids=["3" * 16],
            )
            retry_common = dict(common)
            retry_common["attempt"] = 2
            retry = PLAN.build_lifecycle_input(
                **retry_common,
                operation="lifecycle",
                transport="direct",
                run_ids=["4" * 16, "5" * 16, "6" * 16],
            )
        self.assertEqual(direct["admission_cell_endpoint"], runtime["cell_endpoint"])
        self.assertEqual(direct["relay_hostname"], runtime["relay"]["hostname"])
        self.assertEqual(direct["phase"], "fixed_shared_direct")
        self.assertEqual(recovery["phase"], "fixed_shared_recovery_first")
        self.assertEqual(recovery["recovery_endpoint"], runtime["cell_endpoint"])
        self.assertEqual(retry["attempt"], 2)
        self.assertEqual(runtime["active_colors"], {"server": "blue", "ac": "green"})
        self.assertEqual(plan["cohorts"][0]["server_asg"], RUNTIME.ASGS["server_blue"])
        self.assertEqual(plan["cohorts"][0]["ac_asg"], RUNTIME.ASGS["ac_green"])
        self.assertEqual(plan["cohorts"][0]["assignment_generation"], 2)

    def test_maximal_phase_ledger_has_dynamodb_and_rpc_size_margin(self) -> None:
        value = values()

        def entropy(label: str, length: int = 64) -> str:
            output = ""
            counter = 0
            while len(output) < length:
                output += hashlib.sha256(f"{label}:{counter}".encode()).hexdigest()
                counter += 1
            return output[:length]

        for index, parameter in enumerate(
            (
                "/sandbox/nhp/server/image-tag",
                "/sandbox/nhp/server/green-image-tag",
                "/sandbox/nhp/ac/image-tag",
                "/sandbox/nhp/ac/green-image-tag",
                "/sandbox/nhp/relay/image-tag",
            )
        ):
            value[parameter] = entropy(f"image-source-{index}", 40)
        with (
            mock.patch.object(RUNTIME, "_asgs", return_value={}),
            mock.patch.object(
                RUNTIME,
                "_image",
                side_effect=lambda _client, _repository, slot: {
                    "source_sha": entropy("image-source-" + slot, 40),
                    "image_digest": "sha256:" + entropy("image-digest-" + slot),
                },
            ),
            mock.patch.object(RUNTIME, "_cell_catalog", return_value={"cell_id": "cell0", "endpoint_revision": 2, "host": "cell0.nhp.layerv.xyz", "port": 443, "server_public_key_b64": "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8="}),
            mock.patch.object(RUNTIME, "_table", side_effect=lambda _client, name: {"name": name, "arn": "arn:" + name}),
            mock.patch.object(RUNTIME, "_qurl_service", return_value={"source_tag": "cfa0f3d", "image_digest": "sha256:" + entropy("qurl-index"), "platform_image_digest": "sha256:" + entropy("qurl-platform"), "task_definition": "arn:task-definition"}),
        ):
            runtime = RUNTIME.collect(Session(value))
        plan = PLAN.build_plan(runtime, "abcdefghijklmnopqrstuv@clients", entropy("nhp-source", 40), entropy("qurl-source", 40))
        with tempfile.TemporaryDirectory(prefix="fixed-canary-ledger-") as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            deployments = {}
            for transport in ("direct", "relay"):
                path = directory / f"{transport}-{entropy('deployment-path-' + transport, 96)}.json"
                path.write_bytes(JOURNEY.ordered({"transport": transport, "nonce": entropy("deployment-body-" + transport)}))
                path.chmod(0o600)
                deployments[transport] = path
            release = entropy("release")
            authority = {
                "key": "generations/" + entropy("generation") + "/authority",
                "version_id": entropy("version"),
                "sha256": entropy("authority"),
            }
            common = {
                "release_id": release,
                "runtime": runtime,
                "plan": plan,
                "authority": authority,
                "deployment_paths": deployments,
                "lifecycle_binary": {"path": str(directory / ("lifecycle-" + entropy("lifecycle-path", 96))), "sha256": entropy("lifecycle-digest")},
                "qurl_binary": {"path": str(directory / ("qurl-" + entropy("qurl-path", 96))), "sha256": entropy("qurl-digest")},
                "qurl_source": entropy("qurl-source", 40),
                "api_key_file": directory / ("api-key-" + entropy("api-key-path", 96)),
            }
            bundles = [
                JOURNEY.phase_bundle(generation=generation, prepared_at_ms=1_800_000_000_000 + generation * 1_800_001, **common)
                for generation in range(1, JOURNEY.MAX_PHASE_BUNDLE_GENERATIONS + 1)
            ]
        ledger = JOURNEY.phase_ledger(bundles[0])
        ledger["generations"].extend(bundles[1:])
        raw = JOURNEY.canonical(ledger)
        restored = JOURNEY.validate_phase_ledger(ledger, release_id=release, plan=plan, authority=authority)
        self.assertEqual(len(restored), JOURNEY.MAX_PHASE_BUNDLE_GENERATIONS)
        self.assertLess(len(raw), JOURNEY.MAX_DURABLE_PHASE_LEDGER_BYTES)
        self.assertLess(JOURNEY.MAX_DURABLE_PHASE_LEDGER_BYTES, 400 * 1024)
        self.assertGreaterEqual(400 * 1024 - len(raw), 64 * 1024)
        # The authority socket's exact MAX_MESSAGE_BYTES is 16 MiB. Include
        # base64 growth because blob_commit carries the ledger on that wire.
        self.assertLess((len(raw) * 4 + 2) // 3, 16 << 20)

    def test_source_cell_contract_is_exact(self) -> None:
        source = RUNTIME._source_contract()
        self.assertEqual(source["cell"]["server_public_key_b64"], "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8=")
        self.assertEqual(source["cell"]["endpoint_revision"], 2)

    def test_runtime_assignment_generation_rejects_zero_and_string(self) -> None:
        for invalid in (0, "2"):
            changed = values()
            contract = json.loads(changed["/sandbox/nhp/customer-journey/fixed-canary-v1"])
            contract["assignment_generation"] = invalid
            changed["/sandbox/nhp/customer-journey/fixed-canary-v1"] = json.dumps(contract)
            with (
                mock.patch.object(RUNTIME, "_asgs", return_value={}),
                mock.patch.object(RUNTIME, "_image", return_value={"source_sha": "a" * 40, "image_digest": "sha256:" + "b" * 64}),
                mock.patch.object(RUNTIME, "_cell_catalog", return_value={"cell_id": "cell0", "endpoint_revision": 2, "host": "cell0.nhp.layerv.xyz", "port": 443, "server_public_key_b64": "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8="}),
                mock.patch.object(RUNTIME, "_table", side_effect=lambda _client, name: {"name": name, "arn": "arn:" + name}),
                mock.patch.object(RUNTIME, "_qurl_service", return_value={"source_tag": "cfa0f3d", "image_digest": "sha256:" + "6" * 64, "platform_image_digest": "sha256:" + "7" * 64, "task_definition": "arn:task-definition"}),
                self.assertRaises(RUNTIME.RuntimeErrorExact),
            ):
                RUNTIME.collect(Session(changed))


if __name__ == "__main__":
    unittest.main()
