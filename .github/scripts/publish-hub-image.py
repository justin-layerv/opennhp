#!/usr/bin/env python3
"""Publish and pin one immutable Connector Hub source-SHA image."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


REPOSITORY = "layervai/nhp"
REGION = "us-east-2"
ECR_REPOSITORY = "layerv/nhp-hub"
SOURCE_URL = "https://github.com/layervai/nhp"
WORKFLOW_REF = "layervai/nhp/.github/workflows/publish-hub-image.yml@refs/heads/main"
APPROVED_SCAN_SEVERITIES = ("CRITICAL", "HIGH")

# Time-boxed waivers for vulnerabilities with NO upstream fix.
#
# Every entry is an exact (CVE, package) pair, never a severity or a package
# wildcard, so an unrelated CVE in the same package -- or the same CVE in a
# different package -- still blocks.
#
# These four are one root cause: glibc 2.43-2ubuntu2 in the ubuntu:26.04 runtime
# base, each reported against libc6, glibc and libc-bin, which is what turns four
# CVEs into twelve findings. Ubuntu has published no fix:
#   CVE-2026-5450 (CRITICAL) -- Ubuntu 26.04 status "Needs evaluation"
#   CVE-2026-5435 (HIGH)     -- Ubuntu 26.04 status "Vulnerable"
# Repinning every ubuntu base to the then-current digest (3131b4cc, #3561) was
# tried first and produced an identical {"CRITICAL":3,"HIGH":9}, so this is not
# a stale-pin problem and no base bump or apt upgrade clears it.
#
# The waiver is deliberately inert after SCAN_WAIVER_EXPIRES_AT: past that date
# these findings block again, with an error naming the expired waiver rather than
# silently continuing. Renewing is a conscious act, which is the point.
SCAN_WAIVER_EXPIRES_AT = "2026-08-27"
SCAN_WAIVER_PACKAGES = ("libc6", "glibc", "libc-bin")
SCAN_WAIVED_VULNERABILITIES = frozenset(
    (cve, package)
    for cve in ("CVE-2026-5450", "CVE-2026-5435", "CVE-2026-5928", "CVE-2026-4046")
    for package in SCAN_WAIVER_PACKAGES
)
SHA_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")


@dataclasses.dataclass(frozen=True)
class Target:
    name: str
    publication_environment: str
    account_id: str
    terraform_environment: str

    @property
    def registry(self) -> str:
        return f"{self.account_id}.dkr.ecr.{REGION}.amazonaws.com"

    @property
    def repository_url(self) -> str:
        return f"{self.registry}/{ECR_REPOSITORY}"

    @property
    def role_name(self) -> str:
        return f"layerv-nhp-{self.terraform_environment}-control-hub-publisher"

    @property
    def role_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"

    @property
    def parameter_name(self) -> str:
        return f"/{self.terraform_environment}/nhp/control/hub/image-digest"


@dataclasses.dataclass(frozen=True)
class ScanEvidence:
    status: str
    completed_at: str
    vulnerability_source_updated_at: str | None
    finding_severity_counts: dict[str, int]


TARGETS = {
    "sandbox": Target(
        name="sandbox",
        publication_environment="hub-publish-sandbox",
        account_id="767397897469",
        terraform_environment="sandbox",
    ),
    "production": Target(
        name="production",
        publication_environment="hub-publish-production",
        account_id="235500187906",
        terraform_environment="prod",
    ),
}


class ContractError(RuntimeError):
    """Publication cannot safely continue."""


class CommandError(ContractError):
    """A required external command failed."""

    def __init__(self, command: Sequence[str], returncode: int, stderr: str):
        rendered = " ".join(command)
        detail = stderr.strip()
        super().__init__(
            f"command failed ({returncode}): {rendered}"
            + (f": {detail}" if detail else "")
        )
        self.stderr = stderr


class Runner:
    def run(
        self,
        command: Sequence[str],
        *,
        input_text: str | None = None,
    ) -> str:
        result = subprocess.run(
            list(command),
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise CommandError(command, result.returncode, result.stderr)
        return result.stdout

    def aws(self, *arguments: str) -> str:
        return self.run(("aws", "--no-cli-pager", "--region", REGION, *arguments))


def parse_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractError(f"{label}: invalid JSON") from error
    if not isinstance(value, dict):
        raise ContractError(f"{label}: expected a JSON object")
    return value


def canonical_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ContractError(f"{label}: expected lowercase sha256:<64hex>")
    return value


def finding_package(finding: object) -> str:
    """Extract a finding's package name from its attribute list."""
    if not isinstance(finding, dict):
        return ""
    for attribute in finding.get("attributes") or ():
        if (
            isinstance(attribute, dict)
            and attribute.get("key") == "package_name"
            and isinstance(attribute.get("value"), str)
        ):
            return attribute["value"]
    return ""


def partition_scan_findings(
    findings: object, counts: dict, today: str
) -> tuple[list, list]:
    """Split blocking-severity findings into (waived, blocking).

    Reconciles the enumerated findings against findingSeverityCounts first. ECR
    reports the counts independently of the findings list, so without that check
    a truncated or paginated list would silently hide real vulnerabilities behind
    a short enumeration -- the waiver must never be able to cause that.
    """
    if not isinstance(findings, list):
        raise ContractError("ECR image scan findings are missing")
    blocking_severity = set(APPROVED_SCAN_SEVERITIES)
    enumerated = [
        finding
        for finding in findings
        if isinstance(finding, dict) and finding.get("severity") in blocking_severity
    ]
    for severity in APPROVED_SCAN_SEVERITIES:
        expected = counts.get(severity, 0)
        seen = sum(1 for f in enumerated if f.get("severity") == severity)
        if seen != expected:
            raise ContractError(
                f"ECR image scan enumerated {seen} {severity} findings but "
                f"reported {expected}; refusing to evaluate waivers against an "
                "incomplete list"
            )
    waived: list = []
    blocking: list = []
    for finding in enumerated:
        name = finding.get("name")
        package = finding_package(finding)
        if not isinstance(name, str) or not name or not package:
            raise ContractError("ECR image scan finding is missing a name or package")
        if (name, package) in SCAN_WAIVED_VULNERABILITIES:
            if today > SCAN_WAIVER_EXPIRES_AT:
                raise ContractError(
                    f"ECR scan waiver for {name} ({package}) expired on "
                    f"{SCAN_WAIVER_EXPIRES_AT}; re-check for an upstream fix and "
                    "either drop the waiver or consciously renew it"
                )
            waived.append(finding)
        else:
            blocking.append(finding)
    return waived, blocking


def canonical_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label}: expected a nonempty timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{label}: invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractError(f"{label}: timestamp must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def validate_invocation(args: argparse.Namespace) -> Target:
    target = TARGETS.get(args.target_environment)
    if target is None:
        raise ContractError("target environment must be sandbox or production")
    if args.repository != REPOSITORY:
        raise ContractError(f"repository must be {REPOSITORY}")
    if args.source_ref != "refs/heads/main":
        raise ContractError("Hub publication is restricted to refs/heads/main")
    if args.workflow_ref != WORKFLOW_REF:
        raise ContractError("workflow ref is not the reviewed main-branch carrier")
    if SHA_RE.fullmatch(args.source_sha) is None:
        raise ContractError(
            "source SHA must be exactly 40 lowercase hexadecimal characters"
        )
    if COMMIT_TIME_RE.fullmatch(args.source_commit_time) is None:
        raise ContractError("source commit time has an invalid format")
    if args.publication_environment != target.publication_environment:
        raise ContractError(
            "publication Environment does not match the selected target"
        )
    if args.local_image != f"local/{ECR_REPOSITORY}:{args.source_sha}":
        raise ContractError("local image reference does not match the exact source SHA")
    if not args.run_id.isdecimal() or int(args.run_id) <= 0:
        raise ContractError("run id must be a positive integer")
    if not args.run_attempt.isdecimal() or int(args.run_attempt) <= 0:
        raise ContractError("run attempt must be a positive integer")
    return target


def inspect_image(
    runner: Runner,
    reference: str,
    source_sha: str,
    *,
    expected_repo_digest: str | None = None,
) -> dict[str, Any]:
    raw = runner.run(("docker", "image", "inspect", reference))
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractError("docker inspect returned invalid JSON") from error
    if (
        not isinstance(values, list)
        or len(values) != 1
        or not isinstance(values[0], dict)
    ):
        raise ContractError("docker inspect must return exactly one image")
    image = values[0]
    image_id = canonical_digest(image.get("Id"), "docker image identity")
    descriptor = image.get("Descriptor")
    if descriptor is None:
        # Classic Docker stores image configuration objects directly and
        # reports the config digest as .Id.
        config_digest = image_id
    else:
        # Docker's containerd image store reports the selected manifest digest
        # as .Id and carries the config identity in a descriptor annotation.
        if not isinstance(descriptor, dict):
            raise ContractError("docker image descriptor is malformed")
        if descriptor.get("mediaType") not in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        }:
            raise ContractError(
                "docker image descriptor is not a single image manifest"
            )
        if (
            canonical_digest(descriptor.get("digest"), "docker manifest digest")
            != image_id
        ):
            raise ContractError(
                "docker descriptor digest disagrees with its image identity"
            )
        annotations = descriptor.get("annotations")
        if not isinstance(annotations, dict):
            raise ContractError("docker image descriptor annotations are missing")
        config_digest = canonical_digest(
            annotations.get("config.digest"),
            "docker image config digest",
        )
    if image.get("Architecture") != "amd64" or image.get("Os") != "linux":
        raise ContractError("Hub image must be linux/amd64")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        raise ContractError("Hub image labels are missing")
    if labels.get("org.opencontainers.image.revision") != source_sha:
        raise ContractError("Hub image revision label does not match the source SHA")
    if labels.get("org.opencontainers.image.source") != SOURCE_URL:
        raise ContractError("Hub image source label does not match the NHP repository")
    if expected_repo_digest is not None:
        repo_digests = image.get("RepoDigests")
        if (
            not isinstance(repo_digests, list)
            or expected_repo_digest not in repo_digests
        ):
            raise ContractError(
                "pulled image does not carry the expected repository digest"
            )
    return {
        "architecture": "amd64",
        "os": "linux",
        "config_digest": config_digest,
        "labels": {
            "org.opencontainers.image.revision": source_sha,
            "org.opencontainers.image.source": SOURCE_URL,
        },
    }


def batch_get_image(
    runner: Runner,
    source_sha: str,
) -> tuple[dict[str, Any] | None, str | None]:
    response = parse_object(
        runner.aws(
            "ecr",
            "batch-get-image",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-ids",
            f"imageTag={source_sha}",
            "--accepted-media-types",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "--output",
            "json",
        ),
        "ECR batch-get-image",
    )
    images = response.get("images")
    failures = response.get("failures")
    if not isinstance(images, list) or not isinstance(failures, list):
        raise ContractError("ECR batch-get-image response is malformed")
    if not images:
        if len(failures) != 1 or not isinstance(failures[0], dict):
            raise ContractError("ECR omitted the image without an exact failure")
        failure = failures[0]
        if failure.get("failureCode") != "ImageNotFound" or failure.get("imageId") != {
            "imageTag": source_sha
        }:
            raise ContractError("ECR returned an unexpected image lookup failure")
        return None, None
    if len(images) != 1 or failures or not isinstance(images[0], dict):
        raise ContractError("ECR returned an ambiguous image lookup")
    image = images[0]
    image_id = image.get("imageId")
    if not isinstance(image_id, dict) or image_id.get("imageTag") != source_sha:
        raise ContractError("ECR returned the wrong source-SHA tag")
    digest = canonical_digest(image_id.get("imageDigest"), "ECR image digest")
    manifest_raw = image.get("imageManifest")
    if not isinstance(manifest_raw, str):
        raise ContractError("ECR image manifest is missing")
    calculated = f"sha256:{hashlib.sha256(manifest_raw.encode('utf-8')).hexdigest()}"
    if calculated != digest:
        raise ContractError(
            "ECR image digest does not match the returned manifest bytes"
        )
    manifest = parse_object(manifest_raw, "ECR image manifest")
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise ContractError("ECR image manifest config is missing")
    canonical_digest(config.get("digest"), "ECR image config digest")
    return manifest, digest


def verify_described_image(runner: Runner, source_sha: str, digest: str) -> None:
    response = parse_object(
        runner.aws(
            "ecr",
            "describe-images",
            "--repository-name",
            ECR_REPOSITORY,
            "--image-ids",
            f"imageTag={source_sha}",
            "--output",
            "json",
        ),
        "ECR describe-images",
    )
    details = response.get("imageDetails")
    if (
        not isinstance(details, list)
        or len(details) != 1
        or not isinstance(details[0], dict)
    ):
        raise ContractError("ECR describe-images must return exactly one image")
    detail = details[0]
    if canonical_digest(detail.get("imageDigest"), "described image digest") != digest:
        raise ContractError("ECR describe-images digest disagrees with the manifest")
    if detail.get("imageTags") != [source_sha]:
        raise ContractError(
            "the Hub manifest must have only its immutable source-SHA tag"
        )


def login(runner: Runner, target: Target) -> None:
    password = runner.aws("ecr", "get-login-password")
    if not password.strip():
        raise ContractError("ECR returned an empty login password")
    runner.run(
        ("docker", "login", "--username", "AWS", "--password-stdin", target.registry),
        input_text=password,
    )


def verify_identity(runner: Runner, target: Target) -> str:
    identity = parse_object(
        runner.aws("sts", "get-caller-identity", "--output", "json"),
        "STS caller identity",
    )
    if identity.get("Account") != target.account_id:
        raise ContractError("AWS caller is in the wrong account")
    arn = identity.get("Arn")
    prefix = f"arn:aws:sts::{target.account_id}:assumed-role/{target.role_name}/"
    if (
        not isinstance(arn, str)
        or not arn.startswith(prefix)
        or len(arn) == len(prefix)
    ):
        raise ContractError("AWS caller is not the dedicated Hub publisher role")
    return arn


def publish_or_reuse(
    runner: Runner,
    target: Target,
    source_sha: str,
    local_image: str,
    local_config_digest: str,
) -> tuple[str, bool]:
    manifest, existing_digest = batch_get_image(runner, source_sha)
    pushed = existing_digest is None
    if pushed:
        remote_tag = f"{target.repository_url}:{source_sha}"
        runner.run(("docker", "tag", local_image, remote_tag))
        runner.run(("docker", "push", remote_tag))
    else:
        assert manifest is not None
        config = manifest["config"]
        if config.get("digest") != local_config_digest:
            raise ContractError(
                "immutable source-SHA tag already exists with different image content"
            )

    manifest, digest = batch_get_image(runner, source_sha)
    if manifest is None or digest is None:
        raise ContractError("source-SHA image is absent after publication")
    if manifest["config"].get("digest") != local_config_digest:
        raise ContractError("published manifest does not match the built image config")
    verify_described_image(runner, source_sha, digest)
    return digest, pushed


def wait_for_scan(
    runner: Runner,
    target: Target,
    digest: str,
    *,
    attempts: int,
    poll_seconds: float,
) -> ScanEvidence:
    if attempts <= 0 or poll_seconds < 0:
        raise ContractError("scan polling bounds are invalid")

    def poll_again(attempt: int) -> bool:
        """Sleep before the next poll; return False once the attempts are spent."""
        if attempt + 1 == attempts:
            return False
        time.sleep(poll_seconds)
        return True

    for attempt in range(attempts):
        try:
            response = parse_object(
                runner.aws(
                    "ecr",
                    "describe-image-scan-findings",
                    "--repository-name",
                    ECR_REPOSITORY,
                    "--image-id",
                    f"imageDigest={digest}",
                    "--output",
                    "json",
                ),
                "ECR image scan",
            )
        except CommandError as error:
            if "ScanNotFoundException" not in error.stderr:
                raise
            if not poll_again(attempt):
                break
            continue
        if (
            response.get("registryId") != target.account_id
            or response.get("repositoryName") != ECR_REPOSITORY
        ):
            raise ContractError(
                "ECR image scan does not match the target account/repository"
            )
        image_id = response.get("imageId")
        if (
            not isinstance(image_id, dict)
            or canonical_digest(
                image_id.get("imageDigest"),
                "ECR scan image digest",
            )
            != digest
        ):
            raise ContractError("ECR image scan does not match the requested digest")
        status_object = response.get("imageScanStatus")
        status = (
            status_object.get("status") if isinstance(status_object, dict) else None
        )
        if status in {"PENDING", "IN_PROGRESS"}:
            if not poll_again(attempt):
                break
            continue
        if status not in {"COMPLETE", "ACTIVE"}:
            raise ContractError(f"ECR image scan ended with status {status!r}")
        findings = response.get("imageScanFindings")
        completed_at = (
            findings.get("imageScanCompletedAt") if isinstance(findings, dict) else None
        )
        counts = (
            findings.get("findingSeverityCounts")
            if isinstance(findings, dict)
            else None
        )
        if status == "ACTIVE" and (
            not isinstance(completed_at, str)
            or not completed_at
            or not isinstance(counts, dict)
        ):
            if not poll_again(attempt):
                break
            continue
        completed_at = canonical_timestamp(
            completed_at,
            "ECR image scan completion",
        )
        if not isinstance(counts, dict):
            raise ContractError("ECR image scan severity counts are missing")
        normalized: dict[str, int] = {}
        for severity, count in counts.items():
            if not isinstance(severity, str) or type(count) is not int or count < 0:
                raise ContractError("ECR image scan severity counts are malformed")
            normalized[severity] = count
        blocked = {
            severity: normalized.get(severity, 0)
            for severity in APPROVED_SCAN_SEVERITIES
            if normalized.get(severity, 0) != 0
        }
        if blocked:
            # A non-empty count is not by itself a block: some findings may carry
            # a time-boxed waiver. Enumerate and partition, which reconciles the
            # findings list against these counts first so the waiver can never
            # hide an unlisted vulnerability.
            if findings.get("nextToken"):
                raise ContractError(
                    "ECR image scan findings are paginated; refusing to evaluate "
                    "waivers against a partial list"
                )
            waived, still_blocking = partition_scan_findings(
                findings.get("findings"),
                normalized,
                dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
            )
            if still_blocking:
                unwaived = {}
                for finding in still_blocking:
                    severity = finding.get("severity")
                    unwaived[severity] = unwaived.get(severity, 0) + 1
                raise ContractError(
                    "ECR image scan found policy-blocking vulnerabilities: "
                    + json.dumps(unwaived, sort_keys=True, separators=(",", ":"))
                )
            print(
                f"::warning::ECR scan: {len(waived)} finding(s) waived until "
                f"{SCAN_WAIVER_EXPIRES_AT} (no upstream fix): "
                + ", ".join(
                    sorted({str(f.get("name")) for f in waived})
                )
            )
        source_updated_at = findings.get("vulnerabilitySourceUpdatedAt")
        if source_updated_at is not None:
            source_updated_at = canonical_timestamp(
                source_updated_at,
                "ECR vulnerability source update",
            )
        return ScanEvidence(
            status=status,
            completed_at=completed_at,
            vulnerability_source_updated_at=source_updated_at,
            finding_severity_counts=dict(sorted(normalized.items())),
        )
    raise ContractError("ECR image scan did not complete within the bounded wait")


def get_parameter(runner: Runner, target: Target) -> dict[str, Any]:
    response = parse_object(
        runner.aws(
            "ssm",
            "get-parameter",
            "--name",
            target.parameter_name,
            "--output",
            "json",
        ),
        "SSM get-parameter",
    )
    parameter = response.get("Parameter")
    if not isinstance(parameter, dict):
        raise ContractError("SSM parameter is missing")
    if (
        parameter.get("Name") != target.parameter_name
        or parameter.get("Type") != "String"
        or type(parameter.get("Version")) is not int
        or parameter["Version"] <= 0
        or not isinstance(parameter.get("Value"), str)
    ):
        raise ContractError("SSM parameter shape does not match the Hub digest pin")
    return parameter


def pin_digest(runner: Runner, target: Target, digest: str) -> int:
    canonical_digest(digest, "Hub digest pin")
    current = get_parameter(runner, target)
    minimum_version = current["Version"]
    if current["Value"] != "UNPUBLISHED":
        canonical_digest(current["Value"], "current Hub digest pin")
    if current["Value"] != digest:
        response = parse_object(
            runner.aws(
                "ssm",
                "put-parameter",
                "--name",
                target.parameter_name,
                "--type",
                "String",
                "--value",
                digest,
                "--overwrite",
                "--output",
                "json",
            ),
            "SSM put-parameter",
        )
        version = response.get("Version")
        if type(version) is not int or version <= current["Version"]:
            raise ContractError(
                "SSM digest update did not advance the parameter version"
            )
        minimum_version = version
    readback = get_parameter(runner, target)
    if readback["Value"] != digest or readback["Version"] < minimum_version:
        raise ContractError(
            "SSM Hub digest readback does not match the published image/version"
        )
    return readback["Version"]


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--target-environment", required=True)
    parser.add_argument("--publication-environment", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-commit-time", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--local-image", required=True)
    parser.add_argument("--provenance-file", type=Path, required=True)
    return parser.parse_args()


def publish(
    args: argparse.Namespace,
    runner: Runner,
    *,
    generated_at: dt.datetime | None = None,
) -> dict[str, str]:
    target = validate_invocation(args)
    local = inspect_image(runner, args.local_image, args.source_sha)
    caller_arn = verify_identity(runner, target)
    login(runner, target)
    digest, pushed = publish_or_reuse(
        runner,
        target,
        args.source_sha,
        args.local_image,
        local["config_digest"],
    )
    digest_ref = f"{target.repository_url}@{digest}"
    runner.run(("docker", "pull", "--platform", "linux/amd64", digest_ref))
    remote = inspect_image(
        runner,
        digest_ref,
        args.source_sha,
        expected_repo_digest=digest_ref,
    )
    if remote != local:
        raise ContractError("pulled image contract differs from the built image")
    scan = wait_for_scan(
        runner,
        target,
        digest,
        attempts=int(os.environ.get("HUB_SCAN_MAX_ATTEMPTS", "120")),
        poll_seconds=float(os.environ.get("HUB_SCAN_POLL_SECONDS", "5")),
    )
    parameter_version = pin_digest(runner, target, digest)
    if generated_at is None:
        generated_at = dt.datetime.now(dt.timezone.utc)
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ContractError("provenance time must be timezone-aware")
    provenance = {
        "schema_version": 1,
        "generated_at": generated_at.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "source": {
            "repository": REPOSITORY,
            "ref": args.source_ref,
            "sha": args.source_sha,
            "commit_time": args.source_commit_time,
            "workflow_ref": args.workflow_ref,
            "run_id": int(args.run_id),
            "run_attempt": int(args.run_attempt),
        },
        "target": {
            "environment": target.name,
            "publication_environment": target.publication_environment,
            "aws_account_id": target.account_id,
            "aws_region": REGION,
            "publisher_role_arn": target.role_arn,
            "assumed_role_arn": caller_arn,
        },
        "image": {
            "repository": target.repository_url,
            "tag": args.source_sha,
            "digest": digest,
            "reference": digest_ref,
            "pushed_by_this_attempt": pushed,
            **remote,
        },
        "scan": {
            "status": scan.status,
            "completed_at": scan.completed_at,
            "vulnerability_source_updated_at": scan.vulnerability_source_updated_at,
            "blocking_severities": list(APPROVED_SCAN_SEVERITIES),
            "finding_severity_counts": scan.finding_severity_counts,
        },
        "digest_pin": {
            "parameter_name": target.parameter_name,
            "parameter_version": parameter_version,
            "value": digest,
        },
    }
    write_json_atomic(args.provenance_file, provenance)
    return {
        "digest": digest,
        "parameter": target.parameter_name,
        "provenance": str(args.provenance_file),
    }


def main() -> int:
    try:
        summary = publish(parse_args(), Runner())
    except (ContractError, ValueError) as error:
        raise SystemExit(f"Hub publication failed: {error}") from error
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
