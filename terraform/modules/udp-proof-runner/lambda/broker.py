"""Bounded launcher and independent reaper for the sandbox UDP proof runner."""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT_RE = re.compile(r"^[1-9][0-9]{0,9}$")
ACTIVE_STATES = ("pending", "running", "stopping", "stopped")

# Ownership tags the broker filters and stamps. These mirror local.component /
# local.purpose on the Terraform side; both are fixed for this module.
COMPONENT = "udp-proof-runner"
PURPOSE = "udp-proof"


class ContractError(ValueError):
    """The attended controller supplied an invalid command."""


class ConcurrencyError(RuntimeError):
    """A different proof run already owns the single runner slot."""


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable {name}")
    return value


def _tags(items: list[dict[str, str]] | None) -> dict[str, str]:
    return {item.get("Key", ""): item.get("Value", "") for item in items or []}


class Broker:
    def __init__(
        self,
        ec2: Any,
        secrets: Any,
        *,
        environment: str,
        eip_allocation_id: str,
        launch_template_id: str,
        launch_template_version: str,
        max_runtime_seconds: int,
        secret_prefix: str,
        now: Any = None,
    ) -> None:
        if (
            environment != "sandbox"
            or not eip_allocation_id.startswith("eipalloc-")
            or not launch_template_id.startswith("lt-")
            or not launch_template_version.isdigit()
            # Keep this range in lockstep with the max_runtime_minutes 30-240
            # validation in variables.tf (MAX_RUNTIME_SECONDS = minutes * 60).
            or max_runtime_seconds < 1800
            or max_runtime_seconds > 14400
            or not secret_prefix.endswith("/")
        ):
            raise RuntimeError("invalid broker configuration")
        self.ec2 = ec2
        self.secrets = secrets
        self.environment = environment
        self.eip_allocation_id = eip_allocation_id
        self.launch_template_id = launch_template_id
        self.launch_template_version = launch_template_version
        self.max_runtime = timedelta(seconds=max_runtime_seconds)
        self.secret_prefix = secret_prefix
        self.now = now or (lambda: datetime.now(timezone.utc))

    def dispatch(self, event: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise ContractError("event must be an object")
        if event.get("source") == "aws.events" and event.get("detail-type") == "Scheduled Event":
            return self.sweep()
        if set(event) != {"action", "github_run_id", "github_run_attempt"}:
            raise ContractError("command must contain exactly action, github_run_id, and github_run_attempt")
        action = event.get("action")
        run_id = event.get("github_run_id")
        run_attempt = event.get("github_run_attempt")
        if (
            action not in ("start", "stop")
            or not isinstance(run_id, str)
            or not RUN_ID_RE.fullmatch(run_id)
            or not isinstance(run_attempt, str)
            or not RUN_ATTEMPT_RE.fullmatch(run_attempt)
        ):
            raise ContractError("invalid action, github_run_id, or github_run_attempt")
        if action == "start":
            return self.start(run_id, run_attempt)
        return self.stop(run_id, run_attempt)

    def _secret_name(self, run_id: str, run_attempt: str) -> str:
        return f"{self.secret_prefix}{run_id}/{run_attempt}"

    def _instances(self, run_id: str | None = None, run_attempt: str | None = None) -> list[dict[str, Any]]:
        if (run_id is None) != (run_attempt is None):
            raise RuntimeError("run ID and attempt filters must be supplied together")
        filters: list[dict[str, Any]] = [
            {"Name": "tag:Component", "Values": [COMPONENT]},
            {"Name": "tag:Environment", "Values": [self.environment]},
            {"Name": "tag:Purpose", "Values": [PURPOSE]},
            {"Name": "instance-state-name", "Values": list(ACTIVE_STATES)},
        ]
        if run_id is not None:
            filters.append({"Name": "tag:GitHubRunId", "Values": [run_id]})
            filters.append({"Name": "tag:GitHubRunAttempt", "Values": [run_attempt]})
        pages = self.ec2.get_paginator("describe_instances").paginate(Filters=filters)
        return [
            instance
            for page in pages
            for reservation in page.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]

    def _is_expected_instance(self, instance: dict[str, Any]) -> bool:
        template = instance.get("LaunchTemplate") or {}
        return (
            template.get("LaunchTemplateId") == self.launch_template_id
            and str(template.get("Version", "")) == self.launch_template_version
        )

    def _is_reusable_instance(self, instance: dict[str, Any]) -> bool:
        launched = instance.get("LaunchTime")
        state = (instance.get("State") or {}).get("Name")
        return (
            self._is_expected_instance(instance)
            and isinstance(launched, datetime)
            and launched + self.max_runtime > self.now()
            and state in ("pending", "running")
        )

    def _source_instance_id(self) -> str:
        response = self.ec2.describe_addresses(AllocationIds=[self.eip_allocation_id])
        addresses = response.get("Addresses", [])
        if len(addresses) != 1:
            raise RuntimeError("dedicated source EIP was not returned exactly once")
        return addresses[0].get("InstanceId", "")

    def _attach_source_address(self, instance_id: str) -> None:
        self.ec2.associate_address(
            AllocationId=self.eip_allocation_id,
            InstanceId=instance_id,
            AllowReassociation=False,
        )

    def _validate_jit_secret(self, run_id: str, run_attempt: str) -> None:
        secret_name = self._secret_name(run_id, run_attempt)
        secret = self.secrets.describe_secret(SecretId=secret_name)
        tags = _tags(secret.get("Tags"))
        if (
            secret.get("Name") != secret_name
            or secret.get("DeletedDate") is not None
            or tags.get("Environment") != self.environment
            or tags.get("Purpose") != PURPOSE
            or tags.get("GitHubRunId") != run_id
            or tags.get("GitHubRunAttempt") != run_attempt
        ):
            raise ContractError("JIT configuration secret failed its ownership contract")

    def start(self, run_id: str, run_attempt: str) -> dict[str, Any]:
        # A retry inside EC2's brief DescribeInstances propagation window can
        # see no active runner and then fail closed because the JIT secret is
        # already gone. Recovery from that rare state requires a new attempt.
        active = self._instances()
        if active:
            same_run = [
                instance
                for instance in active
                if (tags := _tags(instance.get("Tags"))).get("GitHubRunId") == run_id
                and tags.get("GitHubRunAttempt") == run_attempt
            ]
            if len(active) == 1 and len(same_run) == 1:
                instance = same_run[0]
                if not self._is_reusable_instance(instance):
                    self.ec2.terminate_instances(InstanceIds=[instance["InstanceId"]])
                    raise RuntimeError("same-run instance failed its reusable-runner contract")
                try:
                    if self._source_instance_id() != instance["InstanceId"]:
                        self._attach_source_address(instance["InstanceId"])
                except Exception:
                    self.ec2.terminate_instances(InstanceIds=[instance["InstanceId"]])
                    raise
                return {"action": "start", "status": "existing", "instance_id": instance["InstanceId"]}
            raise ConcurrencyError("the UDP proof runner slot is already occupied")

        # Check the one-time launch credential only when a launch is actually
        # needed. A successful runner deletes this secret before repository
        # code executes, so requiring it on a same-run retry would make the
        # broker non-idempotent precisely after startup succeeds.
        self._validate_jit_secret(run_id, run_attempt)

        fixed_tags = [
            {"Key": "Component", "Value": COMPONENT},
            {"Key": "Environment", "Value": self.environment},
            {"Key": "Purpose", "Value": PURPOSE},
            {"Key": "GitHubRunId", "Value": run_id},
            {"Key": "GitHubRunAttempt", "Value": run_attempt},
        ]
        # An attach/launch failure intentionally requires a new GitHub attempt:
        # EC2 idempotency can keep returning the failed instance for this token.
        token = hashlib.sha256(f"{self.environment}:{run_id}:{run_attempt}".encode()).hexdigest()
        response = self.ec2.run_instances(
            LaunchTemplate={
                "LaunchTemplateId": self.launch_template_id,
                "Version": self.launch_template_version,
            },
            MinCount=1,
            MaxCount=1,
            ClientToken=token,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": fixed_tags},
                {"ResourceType": "volume", "Tags": fixed_tags},
            ],
        )
        instances = response.get("Instances", [])
        if len(instances) != 1 or not instances[0].get("InstanceId"):
            returned_ids = sorted(instance["InstanceId"] for instance in instances if instance.get("InstanceId"))
            if returned_ids:
                self.ec2.terminate_instances(InstanceIds=returned_ids)
            raise RuntimeError("EC2 did not return exactly one runner instance")
        instance_id = instances[0]["InstanceId"]
        try:
            self._attach_source_address(instance_id)
        except Exception:
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            raise
        return {"action": "start", "status": "launched", "instance_id": instance_id}

    def _delete_secret_name(self, secret_name: str) -> bool:
        try:
            secret = self.secrets.describe_secret(SecretId=secret_name)
        except self.secrets.exceptions.ResourceNotFoundException:
            return False
        tags = _tags(secret.get("Tags"))
        if secret.get("DeletedDate") is not None:
            return False
        if (
            secret.get("Name") != secret_name
            or tags.get("Environment") != self.environment
            or tags.get("Purpose") != PURPOSE
        ):
            raise ContractError("JIT configuration secret failed its ownership contract")

        try:
            self.secrets.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True,
            )
            return True
        except self.secrets.exceptions.ResourceNotFoundException:
            return False
        except self.secrets.exceptions.InvalidRequestException:
            # Force deletion is asynchronous. A repeated stop can observe the
            # secret after DeletedDate is set but before its name disappears.
            # Suppress only that proved idempotent state; every other invalid
            # request remains a cleanup failure.
            try:
                secret = self.secrets.describe_secret(SecretId=secret_name)
            except self.secrets.exceptions.ResourceNotFoundException:
                return False
            if secret.get("DeletedDate") is not None:
                return False
            raise

    def stop(self, run_id: str, run_attempt: str) -> dict[str, Any]:
        instance_ids = sorted(instance["InstanceId"] for instance in self._instances(run_id, run_attempt))
        if instance_ids:
            self.ec2.terminate_instances(InstanceIds=instance_ids)
        secret_deleted = self._delete_secret_name(self._secret_name(run_id, run_attempt))
        return {
            "action": "stop",
            "status": "terminated" if instance_ids else "absent",
            "instances": instance_ids,
            "secret_deleted": secret_deleted,
        }

    def _expired_secret_names(self, cutoff: datetime) -> list[str]:
        names: list[str] = []
        paginator = self.secrets.get_paginator("list_secrets")
        for page in paginator.paginate(
            Filters=[{"Key": "name", "Values": [self.secret_prefix]}],
            IncludePlannedDeletion=False,
        ):
            for secret in page.get("SecretList", []):
                name = secret.get("Name", "")
                created = secret.get("CreatedDate")
                if not name.startswith(self.secret_prefix) or not isinstance(created, datetime) or created > cutoff:
                    continue
                tags = _tags(secret.get("Tags"))
                if (
                    tags.get("Environment") == self.environment
                    and tags.get("Purpose") == PURPOSE
                ):
                    names.append(name)
        return sorted(set(names))

    def sweep(self) -> dict[str, Any]:
        now = self.now()
        active = self._instances()
        terminate: set[str] = set()

        # More than one active tagged instance is an integrity failure even if
        # one looks valid. Terminate all rather than choosing evidence from an
        # ambiguous source. Serialized launches should prevent this path.
        if len(active) > 1:
            terminate.update(instance["InstanceId"] for instance in active)
        else:
            for instance in active:
                launched = instance.get("LaunchTime")
                expired = not isinstance(launched, datetime) or launched + self.max_runtime <= now
                stopped = (instance.get("State") or {}).get("Name") == "stopped"
                invalid = expired or stopped or not self._is_expected_instance(instance)
                if not invalid:
                    try:
                        invalid = self._source_instance_id() != instance["InstanceId"]
                    except Exception:
                        # The sweep cannot certify a proof runner whose stable
                        # source association is unreadable. Terminate it rather
                        # than letting unverifiable evidence continue.
                        invalid = True
                if invalid:
                    terminate.add(instance["InstanceId"])

        if terminate:
            self.ec2.terminate_instances(InstanceIds=sorted(terminate))

        deleted_secrets: list[str] = []
        for secret_name in self._expired_secret_names(now - self.max_runtime):
            if self._delete_secret_name(secret_name):
                deleted_secrets.append(secret_name)

        return {
            "action": "sweep",
            "terminated_instances": sorted(terminate),
            "deleted_secret_names": deleted_secrets,
        }


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    import boto3
    from botocore.config import Config

    sdk_config = Config(retries={"mode": "standard", "total_max_attempts": 4})

    broker = Broker(
        boto3.client("ec2", config=sdk_config),
        boto3.client("secretsmanager", config=sdk_config),
        environment=_required_env("ENVIRONMENT"),
        eip_allocation_id=_required_env("EIP_ALLOCATION_ID"),
        launch_template_id=_required_env("LAUNCH_TEMPLATE_ID"),
        launch_template_version=_required_env("LAUNCH_TEMPLATE_VERSION"),
        max_runtime_seconds=int(_required_env("MAX_RUNTIME_SECONDS")),
        secret_prefix=_required_env("JIT_SECRET_PREFIX"),
    )
    return broker.dispatch(event)
