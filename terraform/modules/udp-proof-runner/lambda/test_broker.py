import importlib.util
import os
import pathlib
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("udp_proof_broker", pathlib.Path(__file__).with_name("broker.py"))
broker_module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(broker_module)


class ResourceNotFoundException(Exception):
    pass


class InvalidRequestException(Exception):
    pass


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages


class FakeSecrets:
    class exceptions:
        ResourceNotFoundException = ResourceNotFoundException
        InvalidRequestException = InvalidRequestException

    def __init__(self, secrets=None, pages=None):
        self.secrets = secrets or {}
        self.paginator = FakePaginator(pages or [{"SecretList": []}])
        self.deleted = []

    def describe_secret(self, SecretId):
        if SecretId in self.secrets:
            return self.secrets[SecretId]
        for page in self.paginator.pages:
            for item in page.get("SecretList", []):
                if item.get("Name") == SecretId:
                    return item
        raise ResourceNotFoundException(SecretId)

    def delete_secret(self, **kwargs):
        name = kwargs["SecretId"]
        if name not in self.secrets and not any(
            item.get("Name") == name
            for page in self.paginator.pages
            for item in page.get("SecretList", [])
        ):
            raise ResourceNotFoundException(name)
        self.deleted.append(kwargs)

    def get_paginator(self, name):
        assert name == "list_secrets"
        return self.paginator


class FakeEC2:
    def __init__(self, instances=None, source_instance_id=None, instance_pages=None):
        self.instances = instances or []
        self.instance_pages = instance_pages
        self.source_instance_id = source_instance_id
        if source_instance_id is None and len(self.instances) == 1:
            self.source_instance_id = self.instances[0]["InstanceId"]
        self.run_calls = []
        self.describe_calls = []
        self.associate_calls = []
        self.terminated = []
        self.wait_calls = []

    def get_paginator(self, name):
        assert name == "describe_instances"
        client = self

        class DescribeInstancesPaginator:
            def paginate(self, **kwargs):
                client.describe_calls.append(kwargs)
                if client.instance_pages is not None:
                    return client.instance_pages
                return [{"Reservations": [{"Instances": client.instances}] if client.instances else []}]

        return DescribeInstancesPaginator()

    def run_instances(self, **kwargs):
        self.run_calls.append(kwargs)
        return {"Instances": [{"InstanceId": "i-0123456789abcdef0"}]}

    def get_waiter(self, name):
        assert name == "instance_running"
        client = self

        class InstanceRunningWaiter:
            def wait(self, **kwargs):
                client.wait_calls.append(kwargs)

        return InstanceRunningWaiter()

    def describe_addresses(self, AllocationIds):
        self.describe_address_ids = AllocationIds
        return {"Addresses": [{"AllocationId": "eipalloc-0123456789abcdef0", "InstanceId": self.source_instance_id}]}

    def associate_address(self, **kwargs):
        self.associate_calls.append(kwargs)
        if self.source_instance_id and not kwargs["AllowReassociation"]:
            raise RuntimeError("address already associated")
        self.source_instance_id = kwargs["InstanceId"]

    def terminate_instances(self, InstanceIds):
        self.terminated.append(InstanceIds)


NOW = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)
PREFIX = "layerv-nhp-sandbox/udp-proof/jit/"
RECOVERY_REQUEST_PREFIX = "layerv-nhp-sandbox/udp-proof/recovery/request/"
RECOVERY_RESPONSE_PREFIX = "layerv-nhp-sandbox/udp-proof/recovery/response/"
RUN_ID = "123456789"
RUN_ATTEMPT = "1"


def tags(run_id=RUN_ID, run_attempt=RUN_ATTEMPT, purpose="udp-proof"):
    return [
        {"Key": "Component", "Value": "udp-proof-runner"},
        {"Key": "Environment", "Value": "sandbox"},
        {"Key": "Purpose", "Value": purpose},
        {"Key": "GitHubRunId", "Value": run_id},
        {"Key": "GitHubRunAttempt", "Value": run_attempt},
    ]


def recovery_tags(run_id=RUN_ID, run_attempt=RUN_ATTEMPT, purpose="udp-proof"):
    return [
        {"Key": "Environment", "Value": "sandbox"},
        {"Key": "Purpose", "Value": purpose},
        {"Key": "GitHubRunId", "Value": run_id},
        {"Key": "GitHubRunAttempt", "Value": run_attempt},
    ]


def instance(
    run_id=RUN_ID,
    run_attempt=RUN_ATTEMPT,
    launched=NOW,
    template_id="lt-0123456789abcdef0",
    version="7",
    state="running",
):
    return {
        "InstanceId": f"i-{run_id:0>17}",
        "LaunchTime": launched,
        "LaunchTemplate": {"LaunchTemplateId": template_id, "Version": version},
        "State": {"Name": state},
        "Tags": tags(run_id, run_attempt),
    }


def secret(run_id=RUN_ID, run_attempt=RUN_ATTEMPT, created=NOW):
    name = PREFIX + run_id + "/" + run_attempt
    return {
        "Name": name,
        "ARN": "arn:aws:secretsmanager:us-east-2:767397897469:secret:" + name + "-abc123",
        "CreatedDate": created,
        "Tags": tags(run_id, run_attempt),
    }

def account_secret(run_id=RUN_ID, run_attempt=RUN_ATTEMPT, created=NOW):
    value = secret(run_id, run_attempt, created)
    name = PREFIX + "credential/" + run_id + "/" + run_attempt
    value["Name"] = name
    value["ARN"] = "arn:aws:secretsmanager:us-east-2:767397897469:secret:" + name + "-abc123"
    value["Tags"] = [
        tag if tag["Key"] != "Purpose" else {"Key": "Purpose", "Value": "udp-proof-account-credential-run"}
        for tag in value["Tags"]
    ]
    return value


def recovery_secret(
    prefix,
    purpose,
    run_id=RUN_ID,
    run_attempt=RUN_ATTEMPT,
    created=NOW,
):
    name = prefix + run_id + "/" + run_attempt
    return {
        "Name": name,
        "ARN": "arn:aws:secretsmanager:us-east-2:767397897469:secret:" + name + "-abc123",
        "CreatedDate": created,
        "Tags": recovery_tags(run_id, run_attempt, purpose),
    }


def new_broker(ec2=None, secrets=None):
    return broker_module.Broker(
        ec2 or FakeEC2(),
        secrets or FakeSecrets(),
        environment="sandbox",
        eip_allocation_id="eipalloc-0123456789abcdef0",
        launch_template_id="lt-0123456789abcdef0",
        launch_template_version="7",
        max_runtime_seconds=3600,
        secret_prefix=PREFIX,
        account_credential_secret_prefix=PREFIX + "credential/",
        recovery_request_secret_prefix=RECOVERY_REQUEST_PREFIX,
        recovery_response_secret_prefix=RECOVERY_RESPONSE_PREFIX,
        now=lambda: NOW,
    )


class BrokerTest(unittest.TestCase):
    def test_instance_inventory_reads_every_describe_page(self):
        first = instance("111111111", "1")
        second = instance("222222222", "2")
        ec2 = FakeEC2(
            instance_pages=[
                {"Reservations": [{"Instances": [first]}]},
                {"Reservations": []},
                {"Reservations": [{"Instances": [second]}]},
            ]
        )

        found = new_broker(ec2)._instances()

        self.assertEqual([first, second], found)
        self.assertEqual(1, len(ec2.describe_calls))
        self.assertIn(
            {"Name": "instance-state-name", "Values": list(broker_module.ACTIVE_STATES)},
            ec2.describe_calls[0]["Filters"],
        )

    def test_required_env_and_handler_wiring(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            RuntimeError, "missing required environment variable MISSING"
        ):
            broker_module._required_env("MISSING")
        with patch.dict(os.environ, {"MISSING": "   "}, clear=True), self.assertRaisesRegex(
            RuntimeError, "missing required environment variable MISSING"
        ):
            broker_module._required_env("MISSING")

        ec2 = FakeEC2()
        secrets = FakeSecrets()
        client_calls = []
        boto3_module = types.ModuleType("boto3")
        botocore_module = types.ModuleType("botocore")
        config_module = types.ModuleType("botocore.config")

        class FakeConfig:
            def __init__(self, **kwargs):
                self.retries = kwargs["retries"]

        def client(name, *, config):
            client_calls.append((name, config.retries))
            return {"ec2": ec2, "secretsmanager": secrets}[name]

        boto3_module.client = client
        config_module.Config = FakeConfig
        botocore_module.config = config_module
        environment = {
            "ENVIRONMENT": "sandbox",
            "EIP_ALLOCATION_ID": "eipalloc-0123456789abcdef0",
            "LAUNCH_TEMPLATE_ID": "lt-0123456789abcdef0",
            "LAUNCH_TEMPLATE_VERSION": "7",
            "MAX_RUNTIME_SECONDS": "3600",
            "JIT_SECRET_PREFIX": PREFIX,
            "ACCOUNT_CREDENTIAL_SECRET_PREFIX": PREFIX + "credential/",
            "RECOVERY_REQUEST_SECRET_PREFIX": RECOVERY_REQUEST_PREFIX,
            "RECOVERY_RESPONSE_SECRET_PREFIX": RECOVERY_RESPONSE_PREFIX,
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.dict(
                sys.modules,
                {
                    "boto3": boto3_module,
                    "botocore": botocore_module,
                    "botocore.config": config_module,
                },
            ),
        ):
            result = broker_module.handler(
                {"source": "aws.events", "detail-type": "Scheduled Event"},
                None,
            )

        self.assertEqual(result["action"], "sweep")
        self.assertEqual(
            client_calls,
            [
                ("ec2", {"mode": "standard", "total_max_attempts": 4}),
                ("secretsmanager", {"mode": "standard", "total_max_attempts": 4}),
            ],
        )

    def test_dispatch_rejects_non_object_event(self):
        for event in (None, [], "start"):
            with self.subTest(event=event), self.assertRaisesRegex(
                broker_module.ContractError, "event must be an object"
            ):
                new_broker().dispatch(event)

    def test_constructor_rejects_invalid_configuration(self):
        valid = {
            "environment": "sandbox",
            "eip_allocation_id": "eipalloc-0123456789abcdef0",
            "launch_template_id": "lt-0123456789abcdef0",
            "launch_template_version": "7",
            "max_runtime_seconds": 3600,
            "secret_prefix": PREFIX,
            "account_credential_secret_prefix": PREFIX + "credential/",
            "recovery_request_secret_prefix": RECOVERY_REQUEST_PREFIX,
            "recovery_response_secret_prefix": RECOVERY_RESPONSE_PREFIX,
        }
        invalid_values = (
            ("environment", "production"),
            ("eip_allocation_id", "eni-0123456789abcdef0"),
            ("launch_template_id", "ami-0123456789abcdef0"),
            ("launch_template_version", "latest"),
            ("max_runtime_seconds", 1799),
            ("max_runtime_seconds", 14401),
            ("secret_prefix", PREFIX.rstrip("/")),
            ("account_credential_secret_prefix", PREFIX + "other/"),
            ("recovery_request_secret_prefix", RECOVERY_REQUEST_PREFIX.rstrip("/")),
            ("recovery_response_secret_prefix", RECOVERY_RESPONSE_PREFIX.rstrip("/")),
            ("recovery_response_secret_prefix", RECOVERY_REQUEST_PREFIX),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                broker_module.Broker(FakeEC2(), FakeSecrets(), **(valid | {field: value}))

    def test_dispatch_routes_scheduled_event_to_sweep(self):
        broker = new_broker()
        expected = {"action": "sweep", "terminated_instances": [], "deleted_secret_names": []}
        broker.sweep = lambda: expected
        self.assertEqual(
            broker.dispatch({"source": "aws.events", "detail-type": "Scheduled Event"}),
            expected,
        )

    def test_dispatch_rejects_unknown_or_aliased_fields(self):
        broker = new_broker()
        invalid = [
            {},
            {
                "action": "start",
                "github_run_id": RUN_ID,
                "github_run_attempt": RUN_ATTEMPT,
                "extra": True,
            },
            {"action": "launch", "github_run_id": RUN_ID, "github_run_attempt": RUN_ATTEMPT},
            {"action": "start", "githubRunId": RUN_ID, "github_run_attempt": RUN_ATTEMPT},
            {"action": "start", "github_run_id": "0", "github_run_attempt": RUN_ATTEMPT},
            {"action": "start", "github_run_id": 123, "github_run_attempt": RUN_ATTEMPT},
            {"action": "start", "github_run_id": RUN_ID, "github_run_attempt": "0"},
            {"action": "start", "github_run_id": RUN_ID, "github_run_attempt": 1},
        ]
        for event in invalid:
            with self.subTest(event=event), self.assertRaises(broker_module.ContractError):
                broker.dispatch(event)

    def test_start_requires_owned_jit_secret_and_uses_exact_template(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT
        ec2 = FakeEC2()
        secrets = FakeSecrets({name: secret()})
        result = new_broker(ec2, secrets).dispatch(
            {"action": "start", "github_run_id": RUN_ID, "github_run_attempt": RUN_ATTEMPT}
        )

        self.assertEqual(result["status"], "launched")
        self.assertEqual(len(ec2.run_calls), 1)
        call = ec2.run_calls[0]
        self.assertEqual(
            call["LaunchTemplate"],
            {"LaunchTemplateId": "lt-0123456789abcdef0", "Version": "7"},
        )
        self.assertEqual(call["MinCount"], 1)
        self.assertEqual(call["MaxCount"], 1)
        self.assertEqual({item["ResourceType"] for item in call["TagSpecifications"]}, {"instance", "volume"})
        for specification in call["TagSpecifications"]:
            self.assertEqual(specification["Tags"], tags())
        self.assertEqual(
            ec2.associate_calls,
            [
                {
                    "AllocationId": "eipalloc-0123456789abcdef0",
                    "InstanceId": "i-0123456789abcdef0",
                    "AllowReassociation": False,
                }
            ],
        )
        self.assertEqual(
            ec2.wait_calls,
            [
                {
                    "InstanceIds": ["i-0123456789abcdef0"],
                    "WaiterConfig": {"Delay": 2, "MaxAttempts": 10},
                }
            ],
        )

        malformed = secret()
        malformed["Tags"] = tags()[:-1]
        invalid_ec2 = FakeEC2()
        with self.assertRaises(broker_module.ContractError):
            new_broker(invalid_ec2, FakeSecrets({name: malformed})).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(invalid_ec2.run_calls, [])

    def test_start_fails_closed_when_a_different_run_is_active(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT
        ec2 = FakeEC2([instance("987654321")])
        secrets = FakeSecrets({name: secret()})
        with self.assertRaises(broker_module.ConcurrencyError):
            new_broker(ec2, secrets).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(ec2.run_calls, [])

    def test_new_attempt_has_a_distinct_idempotency_and_secret_contract(self):
        prior_attempt = instance(run_attempt="1")
        name = PREFIX + RUN_ID + "/2"
        ec2 = FakeEC2([prior_attempt])
        secrets = FakeSecrets({name: secret(run_attempt="2")})
        with self.assertRaises(broker_module.ConcurrencyError):
            new_broker(ec2, secrets).start(RUN_ID, "2")

        ec2 = FakeEC2()
        result = new_broker(ec2, secrets).start(RUN_ID, "2")
        self.assertEqual(result["status"], "launched")
        expected_token = broker_module.hashlib.sha256(b"sandbox:123456789:2").hexdigest()
        self.assertEqual(ec2.run_calls[0]["ClientToken"], expected_token)
        for specification in ec2.run_calls[0]["TagSpecifications"]:
            self.assertEqual(specification["Tags"], tags(run_attempt="2"))

    def test_start_terminates_new_instance_if_source_address_attachment_fails(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT
        ec2 = FakeEC2(source_instance_id="i-existing-owner")
        secrets = FakeSecrets({name: secret()})
        with self.assertRaises(RuntimeError):
            new_broker(ec2, secrets).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(len(ec2.run_calls), 1)
        self.assertEqual(ec2.terminated, [["i-0123456789abcdef0"]])

    def test_start_leaves_pending_instance_for_bounded_same_run_retry(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT

        class SlowEC2(FakeEC2):
            def get_waiter(self, name):
                assert name == "instance_running"
                client = self

                class InstanceRunningWaiter:
                    def wait(self, **kwargs):
                        client.wait_calls.append(kwargs)
                        raise RuntimeError("instance still pending")

                return InstanceRunningWaiter()

        ec2 = SlowEC2()
        with self.assertRaisesRegex(RuntimeError, "instance still pending"):
            new_broker(ec2, FakeSecrets({name: secret()})).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(ec2.terminated, [])
        self.assertEqual(ec2.associate_calls, [])

    def test_start_rejects_ambiguous_launch_results(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT

        class LaunchResultEC2(FakeEC2):
            def __init__(self, instances):
                super().__init__()
                self.launch_result = instances

            def run_instances(self, **kwargs):
                self.run_calls.append(kwargs)
                return {"Instances": self.launch_result}

        cases = (
            ([], []),
            ([{}], []),
            (
                [{"InstanceId": "i-first"}, {"InstanceId": "i-second"}],
                [["i-first", "i-second"]],
            ),
        )
        for returned, terminated in cases:
            with self.subTest(returned=returned):
                ec2 = LaunchResultEC2(returned)
                with self.assertRaises(RuntimeError):
                    new_broker(ec2, FakeSecrets({name: secret()})).start(RUN_ID, RUN_ATTEMPT)
                self.assertEqual(ec2.terminated, terminated)

    def test_start_is_idempotent_only_for_same_run_and_template(self):
        existing = instance()
        ec2 = FakeEC2([existing])
        # The runner deletes its JIT secret immediately after consuming it.
        # Same-run controller retries must still observe the existing launch.
        secrets = FakeSecrets()
        result = new_broker(ec2, secrets).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(
            result,
            {"action": "start", "status": "existing", "instance_id": existing["InstanceId"]},
        )
        self.assertEqual(ec2.run_calls, [])
        self.assertEqual(ec2.associate_calls, [])

        unattached_source = FakeEC2([existing], source_instance_id="")
        result = new_broker(unattached_source, FakeSecrets()).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(
            result,
            {"action": "start", "status": "existing", "instance_id": existing["InstanceId"]},
        )
        self.assertEqual(
            unattached_source.associate_calls,
            [
                {
                    "AllocationId": "eipalloc-0123456789abcdef0",
                    "InstanceId": existing["InstanceId"],
                    "AllowReassociation": False,
                }
            ],
        )
        self.assertEqual(
            unattached_source.wait_calls,
            [
                {
                    "InstanceIds": [existing["InstanceId"]],
                    "WaiterConfig": {"Delay": 2, "MaxAttempts": 10},
                }
            ],
        )

        wrong_source = FakeEC2([existing], source_instance_id="i-unexpected-source-owner")
        with self.assertRaises(RuntimeError):
            new_broker(wrong_source, FakeSecrets()).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(wrong_source.terminated, [[existing["InstanceId"]]])

        class UnreadableAddressEC2(FakeEC2):
            def describe_addresses(self, AllocationIds):
                raise RuntimeError("address inventory unavailable")

        unreadable_source = UnreadableAddressEC2([existing])
        with self.assertRaises(RuntimeError):
            new_broker(unreadable_source, FakeSecrets()).start(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(unreadable_source.terminated, [[existing["InstanceId"]]])

        for invalid in (
            instance(state="stopping"),
            instance(state="stopped"),
            instance(launched=NOW - timedelta(hours=2)),
            instance(template_id="lt-fffffffffffffffff"),
        ):
            with self.subTest(invalid=invalid):
                invalid_ec2 = FakeEC2([invalid])
                with self.assertRaises(RuntimeError):
                    new_broker(invalid_ec2, FakeSecrets()).start(RUN_ID, RUN_ATTEMPT)
                self.assertEqual(invalid_ec2.terminated, [[invalid["InstanceId"]]])

    def test_stop_terminates_owned_run_and_deletes_only_its_secret(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT
        owned = instance()
        ec2 = FakeEC2([owned])
        secrets = FakeSecrets({name: secret()})
        result = new_broker(ec2, secrets).stop(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(ec2.terminated, [[owned["InstanceId"]]])
        self.assertIn({"Name": "tag:GitHubRunId", "Values": [RUN_ID]}, ec2.describe_calls[0]["Filters"])
        self.assertIn(
            {"Name": "tag:Component", "Values": ["udp-proof-runner"]},
            ec2.describe_calls[0]["Filters"],
        )
        self.assertIn(
            {"Name": "tag:GitHubRunAttempt", "Values": [RUN_ATTEMPT]},
            ec2.describe_calls[0]["Filters"],
        )
        self.assertEqual(secrets.deleted, [{"SecretId": name, "ForceDeleteWithoutRecovery": True}])
        self.assertTrue(result["secret_deleted"])
        self.assertFalse(result["account_credential_secret_deleted"])
        self.assertEqual(result["recovery_secrets_deleted"], [])

    def test_stop_deletes_only_the_same_run_account_credential_secret(self):
        name = PREFIX + "credential/" + RUN_ID + "/" + RUN_ATTEMPT
        secrets = FakeSecrets({name: account_secret()})
        result = new_broker(FakeEC2(), secrets).stop(RUN_ID, RUN_ATTEMPT)
        self.assertEqual(secrets.deleted, [{"SecretId": name, "ForceDeleteWithoutRecovery": True}])
        self.assertTrue(result["account_credential_secret_deleted"])

    def test_stop_deletes_exact_owned_recovery_mailboxes(self):
        request = recovery_secret(
            RECOVERY_REQUEST_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
        )
        response = recovery_secret(
            RECOVERY_RESPONSE_PREFIX,
            broker_module.RECOVERY_RESPONSE_PURPOSE,
        )
        secrets = FakeSecrets({request["Name"]: request, response["Name"]: response})

        result = new_broker(FakeEC2(), secrets).stop(RUN_ID, RUN_ATTEMPT)

        self.assertEqual(
            result["recovery_secrets_deleted"],
            [request["Name"], response["Name"]],
        )
        self.assertEqual(
            [deleted["SecretId"] for deleted in secrets.deleted],
            [request["Name"], response["Name"]],
        )

        wrong_binding = dict(request)
        wrong_binding["Tags"] = recovery_tags(
            "987654321",
            RUN_ATTEMPT,
            broker_module.RECOVERY_REQUEST_PURPOSE,
        )
        with self.assertRaisesRegex(
            broker_module.ContractError,
            "proof secret failed its ownership contract",
        ):
            new_broker(
                FakeEC2(),
                FakeSecrets({request["Name"]: wrong_binding}),
            ).stop(RUN_ID, RUN_ATTEMPT)

    def test_stop_accepts_only_proved_already_deleting_secret(self):
        name = PREFIX + RUN_ID + "/" + RUN_ATTEMPT

        class DeletingSecrets(FakeSecrets):
            def __init__(self, secrets=None):
                super().__init__(secrets)
                self.describe_count = 0

            def describe_secret(self, SecretId):
                value = super().describe_secret(SecretId)
                self.describe_count += 1
                if self.describe_count > 1:
                    value = dict(value)
                    value["DeletedDate"] = NOW
                return value

            def delete_secret(self, **_kwargs):
                raise InvalidRequestException("already scheduled")

        result = new_broker(FakeEC2(), DeletingSecrets({name: secret()})).stop(RUN_ID, RUN_ATTEMPT)
        self.assertFalse(result["secret_deleted"])

        class InvalidSecrets(DeletingSecrets):
            def describe_secret(self, SecretId):
                return FakeSecrets.describe_secret(self, SecretId)

        with self.assertRaises(InvalidRequestException):
            new_broker(FakeEC2(), InvalidSecrets({name: secret()})).stop(RUN_ID, RUN_ATTEMPT)

        self.assertFalse(new_broker(FakeEC2(), FakeSecrets()).stop(RUN_ID, RUN_ATTEMPT)["secret_deleted"])

        foreign = secret()
        foreign["Tags"] = [{"Key": "Environment", "Value": "production"}]
        with self.assertRaises(broker_module.ContractError):
            new_broker(FakeEC2(), FakeSecrets({name: foreign})).stop(RUN_ID, RUN_ATTEMPT)

    def test_sweep_terminates_expired_or_wrong_template_runner(self):
        for invalid in (
            instance(launched=NOW - timedelta(hours=2)),
            instance(launched=NOW - timedelta(hours=1)),
            instance(template_id="lt-fffffffffffffffff"),
            instance(state="stopped"),
        ):
            with self.subTest(invalid=invalid):
                ec2 = FakeEC2([invalid])
                result = new_broker(ec2, FakeSecrets()).sweep()
                self.assertEqual(result["terminated_instances"], [invalid["InstanceId"]])

        wrong_source = instance()
        ec2 = FakeEC2([wrong_source], source_instance_id="i-unexpected-source-owner")
        result = new_broker(ec2, FakeSecrets()).sweep()
        self.assertEqual(result["terminated_instances"], [wrong_source["InstanceId"]])

        class UnreadableAddressEC2(FakeEC2):
            def describe_addresses(self, AllocationIds):
                raise RuntimeError("address inventory unavailable")

        unverifiable = instance()
        ec2 = UnreadableAddressEC2([unverifiable])
        result = new_broker(ec2, FakeSecrets()).sweep()
        self.assertEqual(result["terminated_instances"], [unverifiable["InstanceId"]])

    def test_sweep_terminates_every_runner_on_concurrency_violation(self):
        first = instance(RUN_ID)
        second = instance("987654321")
        ec2 = FakeEC2([first, second])
        result = new_broker(ec2, FakeSecrets()).sweep()
        self.assertEqual(result["terminated_instances"], sorted([first["InstanceId"], second["InstanceId"]]))

    def test_sweep_deletes_only_expired_owned_jit_metadata(self):
        expired = secret(created=NOW - timedelta(hours=2))
        fresh = secret("987654321", created=NOW)
        malformed_owned = secret("invalid", created=NOW - timedelta(hours=2))
        foreign = secret("777777777", created=NOW - timedelta(hours=2))
        foreign["Tags"] = [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Purpose", "Value": "udp-proof"},
        ]
        expired_account = account_secret(created=NOW - timedelta(hours=2))
        pages = [{"SecretList": [expired, fresh, malformed_owned, foreign, expired_account]}]
        secrets = FakeSecrets(pages=pages)
        result = new_broker(FakeEC2(), secrets).sweep()
        self.assertEqual(
            result["deleted_secret_names"],
            [
                PREFIX + RUN_ID + "/" + RUN_ATTEMPT,
                PREFIX + "credential/" + RUN_ID + "/" + RUN_ATTEMPT,
                PREFIX + "invalid/" + RUN_ATTEMPT,
            ],
        )
        self.assertEqual(
            [deleted["SecretId"] for deleted in secrets.deleted],
            [
                PREFIX + RUN_ID + "/" + RUN_ATTEMPT,
                PREFIX + "credential/" + RUN_ID + "/" + RUN_ATTEMPT,
                PREFIX + "invalid/" + RUN_ATTEMPT,
            ],
        )
        self.assertEqual(secrets.paginator.calls[0]["Filters"], [{"Key": "name", "Values": [PREFIX]}])

    def test_sweep_deletes_only_exact_expired_recovery_contracts(self):
        request = recovery_secret(
            RECOVERY_REQUEST_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
            created=NOW - timedelta(hours=2),
        )
        response = recovery_secret(
            RECOVERY_RESPONSE_PREFIX,
            broker_module.RECOVERY_RESPONSE_PURPOSE,
            created=NOW - timedelta(hours=2),
        )
        malformed_name = recovery_secret(
            RECOVERY_REQUEST_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
            run_id="invalid",
            created=NOW - timedelta(hours=2),
        )
        wrong_purpose = recovery_secret(
            RECOVERY_RESPONSE_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
            run_id="777777777",
            created=NOW - timedelta(hours=2),
        )
        wrong_binding = recovery_secret(
            RECOVERY_REQUEST_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
            run_id="888888888",
            created=NOW - timedelta(hours=2),
        )
        wrong_binding["Tags"] = recovery_tags(
            "999999999",
            RUN_ATTEMPT,
            broker_module.RECOVERY_REQUEST_PURPOSE,
        )
        fresh = recovery_secret(
            RECOVERY_REQUEST_PREFIX,
            broker_module.RECOVERY_REQUEST_PURPOSE,
            run_id="666666666",
            created=NOW,
        )
        secrets = FakeSecrets(
            pages=[
                {
                    "SecretList": [
                        request,
                        response,
                        malformed_name,
                        wrong_purpose,
                        wrong_binding,
                        fresh,
                    ]
                }
            ]
        )

        result = new_broker(FakeEC2(), secrets).sweep()

        self.assertEqual(
            result["deleted_secret_names"],
            [request["Name"], response["Name"]],
        )
        self.assertEqual(
            [deleted["SecretId"] for deleted in secrets.deleted],
            [request["Name"], response["Name"]],
        )
        self.assertEqual(
            [call["Filters"] for call in secrets.paginator.calls],
            [
                [{"Key": "name", "Values": [PREFIX]}],
                [{"Key": "name", "Values": [RECOVERY_REQUEST_PREFIX]}],
                [{"Key": "name", "Values": [RECOVERY_RESPONSE_PREFIX]}],
            ],
        )

    def test_sweep_bounds_secret_deletions(self):
        secrets_to_delete = [
            secret(str(100000000 + index), created=NOW - timedelta(hours=2))
            for index in range(broker_module.MAX_SECRET_DELETIONS_PER_SWEEP + 5)
        ]
        secrets = FakeSecrets(pages=[{"SecretList": secrets_to_delete}])

        result = new_broker(FakeEC2(), secrets).sweep()

        self.assertEqual(
            len(result["deleted_secret_names"]),
            broker_module.MAX_SECRET_DELETIONS_PER_SWEEP,
        )
        self.assertEqual(
            len(secrets.deleted),
            broker_module.MAX_SECRET_DELETIONS_PER_SWEEP,
        )


if __name__ == "__main__":
    unittest.main()
