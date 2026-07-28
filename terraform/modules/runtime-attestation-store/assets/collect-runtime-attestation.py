#!/usr/bin/env python3
"""Publish this instance's canonical runtime attestation to the sandbox store.

One root-owned collector, installed and repaired only by the pinned State
Manager document `layerv-nhp-sandbox-runtime-attestation-repair`, run by a
root-owned systemd timer.  It writes exactly one object:

    s3://<bucket>/runtime/<aws:userid>/latest.json

The bucket policy grants each node role `s3:PutObject` beneath
`runtime/${aws:userid}/` and nothing else, and for an EC2 role AWS defines
`aws:userid` as `<role-id>:<instance-id>`.  The prefix is therefore self-bound:
this collector cannot name, read, list, or overwrite another instance's row
even if it tried.  Deliberately NOT SSM custom Inventory — `ssm:PutInventory`
is not resource-scoped, so one compromised instance role could forge another
instance's row.

Every step fails closed.  A stale, partial, or unverifiable observation is
never published: the deployment-manifest producer requires a fresh object and
treats a missing one as a hard failure, so silence is the correct output.

The emitted document is the exact canonical JSON the producer's contract
accepts (`sort_keys`, `(",", ":")` separators, ASCII).  Its schema is owned by
`.github/scripts/udp_proof_deployment_contract.py::normalize_runtime_attestation`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
IMDS_BASE = "http://169.254.169.254"
IMDS_TIMEOUT = 5
AWS_TIMEOUT = 60
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 32 * 1024

COLLECTOR_PATH = Path("/usr/local/bin/layerv-collect-runtime-attestation.py")
SERVICE_UNIT_PATH = Path("/etc/systemd/system/layerv-runtime-attestation.service")
TIMER_UNIT_PATH = Path("/etc/systemd/system/layerv-runtime-attestation.timer")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
STATE_DIR = Path("/var/lib/layerv/runtime-attestation")
BOOT_CAPTURE_PATH = STATE_DIR / "boot-capture.json"

LAUNCH_TEMPLATE_ID_TAG = "aws:ec2launchtemplate:id"
LAUNCH_TEMPLATE_VERSION_TAG = "aws:ec2launchtemplate:version"

NHP_CONTAINER_NAME = "nhp-server"
NHP_IMAGE_REPOSITORY = "layerv/nhp-server"
QRTS_IMAGE_REPOSITORY = "layerv/qurl-reverse-tunnel-server"
QRTS_BINARY_PATH = Path("/opt/layerv/qurl-reverse-tunnel-server/nhp-frps")

ACCOUNT_ID = "767397897469"
REGION = "us-east-2"

ASSUMED_ROLE_RE = re.compile(
    r"^arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/(?P<role>[A-Za-z0-9+=,.@_-]+)/"
    r"(?P<instance>i-[0-9a-f]{8,17})$"
)
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
USERID_RE = re.compile(r"^AROA[A-Z0-9]+:i-[0-9a-f]{8,17}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
LAUNCH_TEMPLATE_ID_RE = re.compile(r"^lt-[0-9a-f]{8,17}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class CollectorError(RuntimeError):
    """A fail-closed collection error.  Nothing is published."""


def _canonical_bytes(value: Any) -> bytes:
    raw = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not raw or len(raw) > MAX_OBJECT_BYTES:
        raise CollectorError(f"attestation must be 1..{MAX_OBJECT_BYTES} bytes")
    return raw


def _sha256_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not os.path.isfile(path):
            raise CollectorError(f"{path} must be a regular file")
        if metadata.st_size > 4 * 1024 * 1024:
            raise CollectorError(f"{path} is too large to hash")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CollectorError(f"cannot hash {path}") from exc


def _imds(path: str, token: str) -> str:
    request = urllib.request.Request(
        f"{IMDS_BASE}{path}",
        headers={"X-aws-ec2-metadata-token": token},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=IMDS_TIMEOUT) as response:
            if response.status != 200:
                raise CollectorError(f"IMDS {path} returned {response.status}")
            return response.read(MAX_OUTPUT_BYTES).decode("utf-8")
    except (urllib.error.URLError, OSError, UnicodeDecodeError) as exc:
        raise CollectorError(f"IMDS {path} is unavailable") from exc


def _imds_token() -> str:
    request = urllib.request.Request(
        f"{IMDS_BASE}/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=IMDS_TIMEOUT) as response:
            if response.status != 200:
                raise CollectorError("IMDSv2 token request failed")
            return response.read(4096).decode("ascii")
    except (urllib.error.URLError, OSError, UnicodeDecodeError) as exc:
        raise CollectorError("IMDSv2 is unavailable") from exc


def _run(argv: list[str], name: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            check=False,
            text=True,
            timeout=AWS_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CollectorError(f"{name} could not run") from exc
    if completed.returncode != 0:
        raise CollectorError(f"{name} failed: {completed.stderr.strip()[:512]}")
    if len(completed.stdout) > MAX_OUTPUT_BYTES:
        raise CollectorError(f"{name} produced an oversized response")
    return completed.stdout


def _run_json(argv: list[str], name: str) -> Any:
    try:
        return json.loads(_run(argv, name))
    except json.JSONDecodeError as exc:
        raise CollectorError(f"{name} did not return JSON") from exc


def _aws(service: str, arguments: list[str], name: str) -> Any:
    return _run_json(
        ["aws", service, *arguments, "--region", REGION, "--output", "json"],
        name,
    )


def _docker_json(arguments: list[str], name: str) -> Any:
    return _run_json(["docker", *arguments], name)


def _require(value: Any, pattern: re.Pattern[str], name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CollectorError(f"{name} is missing or malformed")
    return value


def _iso_utc_seconds(value: Any, name: str) -> str:
    """Normalize exactly as the producer does, so both sides compare equal."""

    if not isinstance(value, str):
        raise CollectorError(f"{name} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollectorError(f"{name} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CollectorError(f"{name} timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _launch_template_identity(source: Any, name: str) -> tuple[str, int]:
    """Normalize one control-plane launch-template record, failing closed.

    Deliberately NOT sourced from IMDS.  IMDS would serve the same launch
    template through `/latest/meta-data/tags/instance/`, but it answers
    unauthenticated plaintext HTTP on a link-local address: one on-box NAT
    redirect makes it say anything, and the IMDSv2 token is issued by the very
    endpoint being impersonated, so it proves nothing.  Only the signed
    instance-identity documents carry integrity, and they have no launch
    template field.  Every source normalized here instead comes back over a
    SigV4-signed call to a regional control-plane endpoint.
    """

    if not isinstance(source, dict):
        raise CollectorError(f"{name} has no launch-template identity")
    template_id = _require(
        source.get("LaunchTemplateId"),
        LAUNCH_TEMPLATE_ID_RE,
        f"{name} launch template id",
    )
    try:
        version = int(str(source.get("Version")))
    except (TypeError, ValueError) as exc:
        raise CollectorError(
            f"{name} launch template version is not an integer"
        ) from exc
    if version <= 0:
        raise CollectorError(f"{name} launch template version must be positive")
    return template_id, version


def _reserved_launch_template_tags(instance: dict[str, Any]) -> dict[str, Any]:
    """Read the reserved launch-template tags EC2 stamps on the instance.

    The `aws:` tag namespace is reserved: AWS refuses every principal —
    including this node's own instance role, whatever `ec2:CreateTags` it
    holds — permission to create, edit, or delete a key in it.  These values
    are therefore the EC2 control plane's own record of what launched this
    instance, not something the node can author about itself.
    """

    tags = instance.get("Tags")
    if not isinstance(tags, list):
        raise CollectorError("instance description carries no tags")
    reserved: dict[str, Any] = {}
    for tag in tags:
        if not isinstance(tag, dict):
            raise CollectorError("instance tag set is malformed")
        key = tag.get("Key")
        if key in (LAUNCH_TEMPLATE_ID_TAG, LAUNCH_TEMPLATE_VERSION_TAG):
            if key in reserved:
                raise CollectorError("instance has duplicate launch-template tags")
            reserved[key] = tag.get("Value")
    return {
        "LaunchTemplateId": reserved.get(LAUNCH_TEMPLATE_ID_TAG),
        "Version": reserved.get(LAUNCH_TEMPLATE_VERSION_TAG),
    }


def _collect_identity() -> dict[str, Any]:
    token = _imds_token()
    try:
        document = json.loads(_imds("/latest/dynamic/instance-identity/document", token))
    except json.JSONDecodeError as exc:
        raise CollectorError("instance identity document is not JSON") from exc
    if not isinstance(document, dict):
        raise CollectorError("instance identity document is not an object")
    instance_id = _require(document.get("instanceId"), INSTANCE_ID_RE, "instanceId")
    if document.get("accountId") != ACCOUNT_ID or document.get("region") != REGION:
        raise CollectorError("instance is outside the sandbox account/region")

    caller = _aws("sts", ["get-caller-identity"], "caller identity")
    if not isinstance(caller, dict):
        raise CollectorError("caller identity is not an object")
    aws_userid = _require(caller.get("UserId"), USERID_RE, "caller UserId")
    if not aws_userid.endswith(f":{instance_id}"):
        raise CollectorError("caller UserId is not bound to this instance")
    assumed = ASSUMED_ROLE_RE.fullmatch(str(caller.get("Arn")))
    if (
        assumed is None
        or assumed.group("account") != ACCOUNT_ID
        or assumed.group("instance") != instance_id
    ):
        raise CollectorError("caller ARN is not this instance's EC2 role session")
    # The producer resolves the role ARN from the live instance profile; a path
    # on the role would make this derivation differ and the producer would then
    # fail closed rather than accept a mismatched identity.
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{assumed.group('role')}"

    membership = _aws(
        "autoscaling",
        ["describe-auto-scaling-instances", "--instance-ids", instance_id],
        "ASG membership",
    )
    rows = membership.get("AutoScalingInstances") if isinstance(membership, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise CollectorError("instance has no unique ASG membership")
    autoscaling_group = rows[0].get("AutoScalingGroupName")
    if not isinstance(autoscaling_group, str) or not autoscaling_group:
        raise CollectorError("ASG name is missing")
    if rows[0].get("LifecycleState") != "InService":
        raise CollectorError("instance is not InService")

    described = _aws(
        "ec2",
        ["describe-instances", "--instance-ids", instance_id],
        "instance description",
    )
    reservations = described.get("Reservations") if isinstance(described, dict) else None
    if (
        not isinstance(reservations, list)
        or len(reservations) != 1
        or not isinstance(reservations[0], dict)
        or not isinstance(reservations[0].get("Instances"), list)
        or len(reservations[0]["Instances"]) != 1
    ):
        raise CollectorError("instance description is ambiguous")
    instance = reservations[0]["Instances"][0]
    # `ec2:DescribeInstances` returns no top-level `LaunchTemplate` for an
    # ASG-launched instance — that field is only populated for an instance the
    # RunInstances caller launched from a template directly.  The launch
    # identity of an ASG member lives in two independent control-plane records:
    # the Auto Scaling membership row, and the reserved `aws:ec2launchtemplate:*`
    # tags EC2 stamps at launch.  Both are read here over SigV4 and must agree;
    # each records what this instance was *launched with*, so neither drifts to
    # the group's newer desired version during a rolling replacement.
    launch_template_id, launch_template_version = _launch_template_identity(
        rows[0].get("LaunchTemplate"), "ASG membership"
    )
    tagged_id, tagged_version = _launch_template_identity(
        _reserved_launch_template_tags(instance), "reserved instance tag"
    )
    if (tagged_id, tagged_version) != (launch_template_id, launch_template_version):
        raise CollectorError(
            "launch-template identity differs across control-plane records"
        )

    try:
        boot_id = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise CollectorError("boot id is unreadable") from exc

    return {
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "instance_id": instance_id,
        "role_arn": role_arn,
        "aws_userid": aws_userid,
        "autoscaling_group": autoscaling_group,
        "launch_template_id": launch_template_id,
        "launch_template_version": launch_template_version,
        "boot_id": _require(boot_id, BOOT_ID_RE, "boot id"),
    }


def _collect_repair(document_name: str, autoscaling_group: str) -> dict[str, Any]:
    listed = _aws(
        "ssm",
        [
            "list-associations",
            "--association-filter-list",
            f"key=Name,value={document_name}",
            "--max-results",
            "50",
        ],
        "repair associations",
    )
    associations = listed.get("Associations") if isinstance(listed, dict) else None
    if not isinstance(associations, list):
        raise CollectorError("repair associations are unreadable")
    expected_targets = [
        {"Key": "tag:aws:autoscaling:groupName", "Values": [autoscaling_group]}
    ]
    matches = [
        association
        for association in associations
        if isinstance(association, dict)
        and association.get("Name") == document_name
        and association.get("Targets") == expected_targets
    ]
    if len(matches) != 1:
        raise CollectorError("this ASG has no unique repair association")
    association_id = matches[0].get("AssociationId")
    if not isinstance(association_id, str) or not association_id:
        raise CollectorError("repair association id is missing")

    executions = _aws(
        "ssm",
        [
            "describe-association-executions",
            "--association-id",
            association_id,
            # DELIBERATELY UNFILTERED. A Status filter destroys the API's
            # ordering: the unfiltered page is strictly newest-first, but
            # "Key=Status,Value=Success,Type=EQUAL" returns a stably jumbled page
            # (observed live: 19:08, 14:08, then the PREVIOUS day's 20:38, then
            # 21:38, then 00:38). Taking rows[0] from that page recorded an
            # arbitrary successful execution as last_success_at rather than the
            # latest one.
            #
            # The consequence was not cosmetic. Every instance in this fleet
            # reported the same 01:08:29Z execution, which had targeted the
            # previous, pre-refresh generation and predates every current
            # instance's launch -- so the producer's per-target check correctly
            # refused an attestation naming a run that never touched the
            # instance, and the 6h21m gap also blew MAX_REPAIR_AGE.
            #
            # Unfiltered keeps newest-first, so rows[0] is genuinely the latest
            # execution. Ordering is then asserted below rather than assumed.
            "--max-results",
            "20",
        ],
        "repair executions",
    )
    rows = (
        executions.get("AssociationExecutions") if isinstance(executions, dict) else None
    )
    if not isinstance(rows, list) or not rows or not all(
        isinstance(row, dict) for row in rows
    ):
        raise CollectorError("this ASG has no successful repair execution")
    # Fail closed if the page is not newest-first, rather than trusting it. This
    # is exactly the property the Status filter silently broke, so it is asserted
    # here instead of assumed.
    created = [_iso_utc_seconds(row.get("CreatedTime"), "repair") for row in rows]
    if created != sorted(created, reverse=True):
        raise CollectorError("repair executions are not newest-first")
    if rows[0].get("Status") != "Success":
        raise CollectorError("latest repair execution did not succeed")
    return {
        "document_name": document_name,
        "association_id": association_id,
        "last_success_at": _iso_utc_seconds(rows[0].get("CreatedTime"), "repair"),
        "status": "Success",
    }


def _collect_docker_runtime() -> dict[str, Any]:
    inspected = _docker_json(
        ["inspect", NHP_CONTAINER_NAME], f"{NHP_CONTAINER_NAME} inspect"
    )
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise CollectorError("the NHP container is not uniquely running")
    container = inspected[0]
    state = container.get("State") if isinstance(container, dict) else None
    if not isinstance(state, dict) or state.get("Running") is not True:
        raise CollectorError("the NHP container is not running")
    container_id = _require(container.get("Id"), CONTAINER_ID_RE, "container id")
    name = container.get("Name")
    if name != f"/{NHP_CONTAINER_NAME}":
        raise CollectorError("the running container is not the NHP server")
    image_id = container.get("Image")
    if not isinstance(image_id, str) or not image_id:
        raise CollectorError("the running container has no image id")

    image = _docker_json(["image", "inspect", image_id], "running image inspect")
    if not isinstance(image, list) or len(image) != 1:
        raise CollectorError("the running image is not unique")
    repo_digests = image[0].get("RepoDigests") if isinstance(image[0], dict) else None
    if not isinstance(repo_digests, list):
        raise CollectorError("the running image has no repository digest")
    digests = {
        reference.split("@", 1)[1]
        for reference in repo_digests
        if isinstance(reference, str)
        and "@" in reference
        and reference.split("@", 1)[0].endswith(f"/{NHP_IMAGE_REPOSITORY}")
    }
    if len(digests) != 1:
        raise CollectorError("the running image has no unique sandbox ECR digest")
    labels = (image[0].get("Config") or {}).get("Labels") or {}
    if not isinstance(labels, dict):
        raise CollectorError("the running image has no labels")
    revision = labels.get("org.opencontainers.image.revision")
    return {
        "kind": "docker_container",
        "container_name": NHP_CONTAINER_NAME,
        "container_id": container_id,
        "image_repository": NHP_IMAGE_REPOSITORY,
        "image_digest": _require(digests.pop(), DIGEST_RE, "running image digest"),
        "source_revision": _require(revision, SHA_RE, "running image revision"),
    }


def _collect_installed_binary_runtime() -> dict[str, Any]:
    """qRTS keeps no container: bind the installed binary to its boot capture.

    The one-shot extraction image is removed at boot, so the ECR digest and the
    canonical build receipt must have been captured *before* that removal.  The
    producer independently re-verifies both against the signed publisher
    attestation for the digest actually running on the fleet.
    """

    try:
        raw = BOOT_CAPTURE_PATH.read_bytes()
    except OSError as exc:
        raise CollectorError(
            "qRTS boot capture is missing; the S3 binary fallback is not proof"
        ) from exc
    try:
        capture = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("qRTS boot capture is not JSON") from exc
    if not isinstance(capture, dict) or set(capture) != {
        "image_digest",
        "source_revision",
        "build_receipt_sha256",
        "installed_binary_sha256",
        "source_kind",
    }:
        raise CollectorError("qRTS boot capture has an unexpected shape")
    if capture.get("source_kind") != "ecr_build_receipt":
        raise CollectorError("qRTS boot capture is not ECR-receipt sourced")
    installed = _sha256_file(QRTS_BINARY_PATH)
    if installed != _require(
        capture.get("installed_binary_sha256"), SHA256_RE, "captured binary hash"
    ):
        raise CollectorError("the installed qRTS binary differs from its boot capture")
    return {
        "kind": "installed_binary",
        "image_repository": QRTS_IMAGE_REPOSITORY,
        "image_digest": _require(
            capture.get("image_digest"), DIGEST_RE, "captured image digest"
        ),
        "source_revision": _require(
            capture.get("source_revision"), SHA_RE, "captured source revision"
        ),
        "installed_binary_sha256": installed,
        "build_receipt_sha256": _require(
            capture.get("build_receipt_sha256"), SHA256_RE, "captured receipt hash"
        ),
        "source_kind": "ecr_build_receipt",
    }


def _collect_runtime() -> dict[str, Any]:
    if BOOT_CAPTURE_PATH.exists():
        return _collect_installed_binary_runtime()
    return _collect_docker_runtime()


def _publish(bucket: str, kms_key_arn: str, key: str, raw: bytes) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        body = Path(temporary) / "attestation.json"
        body.write_bytes(raw)
        _run(
            [
                "aws",
                "s3api",
                "put-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--body",
                str(body),
                "--content-type",
                "application/json",
                "--server-side-encryption",
                "aws:kms",
                "--ssekms-key-id",
                kms_key_arn,
                "--region",
                REGION,
                "--output",
                "json",
            ],
            "attestation upload",
        )


def main() -> int:
    bucket = os.environ.get("LAYERV_ATTESTATION_BUCKET", "")
    kms_key_arn = os.environ.get("LAYERV_ATTESTATION_KMS_KEY_ARN", "")
    document_name = os.environ.get("LAYERV_ATTESTATION_REPAIR_DOCUMENT", "")
    if not bucket or not kms_key_arn or not document_name:
        print("collector environment is incomplete", file=sys.stderr)
        return 2
    try:
        identity = _collect_identity()
        attestation = {
            "schema_version": SCHEMA_VERSION,
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "identity": identity,
            "collector": {
                "sha256": _sha256_file(COLLECTOR_PATH),
                "service_unit_sha256": _sha256_file(SERVICE_UNIT_PATH),
                "timer_unit_sha256": _sha256_file(TIMER_UNIT_PATH),
            },
            "repair": _collect_repair(document_name, identity["autoscaling_group"]),
            "runtime": _collect_runtime(),
        }
        _publish(
            bucket,
            kms_key_arn,
            f"runtime/{identity['aws_userid']}/latest.json",
            _canonical_bytes(attestation),
        )
    except CollectorError as exc:
        print(f"runtime attestation not published: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
