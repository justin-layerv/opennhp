#!/usr/bin/env python3
"""Chain-of-custody checks for reusable Control updates (sandbox and prod)."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


REPOSITORY = "layervai/nhp"
TF_VERSION = "1.14.3"

# Per-environment identity. Every value here is a boundary: an environment that
# silently inherited another's account, bucket, or state key would validate a
# capture of the wrong estate and pass. Selection is by explicit --environment
# with no default, so a caller that forgets it fails rather than guessing.
CONTROL_ENVIRONMENTS = {
    "sandbox": {
        "account_id": "767397897469",
        "workflow_name": "Control Sandbox Update",
        "workflow_path": ".github/workflows/control-sandbox-update.yml",
        "state_key": "nhp/sandbox/control/terraform.tfstate",
        "state_kms_key_arn": (
            "arn:aws:kms:us-east-2:767397897469:key/"
            "289dbe35-ab5a-4752-8564-4c96c607c9f4"
        ),
    },
    "prod": {
        "account_id": "235500187906",
        "workflow_name": "Control Prod Update",
        "workflow_path": ".github/workflows/control-prod-update.yml",
        "state_key": "nhp/prod/control/terraform.tfstate",
        "state_kms_key_arn": (
            "arn:aws:kms:us-east-2:235500187906:key/"
            "00a0e673-cef4-41f0-bfc0-5116a9ab3aa0"
        ),
    },
}


def environment_profile(name: str) -> dict[str, str]:
    profile = CONTROL_ENVIRONMENTS.get(name)
    if profile is None:
        raise ContractError(f"unknown Control environment: {name}")
    return {
        **profile,
        "state_bucket": f"layerv-terraform-state-{profile['account_id']}",
    }


PLAN_MAX_AGE_SECONDS = 2 * 24 * 60 * 60
STATE_SUMMARY_KEYS = {
    "account_id",
    "bucket",
    "content_length",
    "etag",
    "kms_key_arn",
    "lineage",
    "serial",
    "sha256",
    "state_format_version",
    "terraform_version",
    "version_id",
}
METADATA_KEYS = {
    "account_id",
    "commit_sha",
    "contract_checker_sha256",
    "contract_summary_sha256",
    "plan_sha256",
    "plan_text_sha256",
    "planned_at_epoch",
    "repository",
    "runtime_contract_sha256",
    "run_attempt",
    "run_id",
    "schema_version",
    "state",
    "state_summary_sha256",
    "terraform_version",
    "workflow_ref",
}


class ContractError(ValueError):
    """Raised when update evidence violates the reviewed contract."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    try:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise ContractError(f"cannot write JSON {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ContractError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _require_hex(value: str, length: int, label: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ContractError(f"{label} is malformed")
    return value


def _require_positive_int(value: str | int, label: str) -> int:
    rendered = str(value)
    if not re.fullmatch(r"[1-9][0-9]*", rendered):
        raise ContractError(f"{label} is malformed")
    return int(rendered)


def _require_nonnegative_int(value: str | int, label: str) -> int:
    rendered = str(value)
    if not re.fullmatch(r"0|[1-9][0-9]*", rendered):
        raise ContractError(f"{label} is malformed")
    return int(rendered)


def _parse_iso8601_utc(value: object, label: str) -> int:
    """Parse a GitHub ISO 8601 timestamp (e.g. run_started_at) to a UTC epoch."""
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is malformed")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ContractError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return int(parsed.timestamp())


def validate_state_summary(summary: Any, profile: dict[str, str]) -> dict[str, Any]:
    if not isinstance(summary, dict) or set(summary) != STATE_SUMMARY_KEYS:
        raise ContractError("state summary keys are not exact")
    if (
        summary["account_id"] != profile["account_id"]
        or summary["bucket"] != profile["state_bucket"]
        or summary["kms_key_arn"] != profile["state_kms_key_arn"]
        or summary["terraform_version"] != TF_VERSION
        or summary["state_format_version"] != 4
    ):
        raise ContractError("state summary identity is not exact")
    _require_positive_int(summary["content_length"], "state content_length")
    _require_nonnegative_int(summary["serial"], "state serial")
    _require_hex(str(summary["sha256"]), 64, "state sha256")
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        str(summary["lineage"]),
    ):
        raise ContractError("state lineage is malformed")
    version_id = summary["version_id"]
    if not isinstance(version_id, str) or not version_id or version_id == "null":
        raise ContractError("state version_id is malformed")
    # SSE-KMS ETags are opaque identity values, not contracted MD5 digests.
    # Exact before/after equality binds the value; state SHA-256 binds content.
    if not isinstance(summary["etag"], str) or not summary["etag"]:
        raise ContractError("state etag is malformed")
    return summary


def check_state(
    state_path: Path, head_path: Path, profile: dict[str, str]
) -> dict[str, Any]:
    state = load_json(state_path)
    head = load_json(head_path)
    if not isinstance(state, dict) or not isinstance(head, dict):
        raise ContractError("state or S3 head is malformed")
    if (
        state.get("version") != 4
        or state.get("terraform_version") != TF_VERSION
        or not isinstance(state.get("serial"), int)
        or state["serial"] < 0
        or not isinstance(state.get("lineage"), str)
    ):
        raise ContractError("Terraform state header is not exact")
    if (
        head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != profile["state_kms_key_arn"]
        or not isinstance(head.get("ContentLength"), int)
        or head["ContentLength"] <= 0
        or not isinstance(head.get("VersionId"), str)
        or not isinstance(head.get("ETag"), str)
    ):
        raise ContractError("S3 state identity is not exact")
    try:
        actual_length = state_path.stat().st_size
    except OSError as exc:
        raise ContractError(f"cannot stat Terraform state: {exc}") from exc
    if head["ContentLength"] != actual_length:
        raise ContractError("downloaded state length does not match S3 head")
    return validate_state_summary(
        {
            "account_id": profile["account_id"],
            "bucket": profile["state_bucket"],
            "content_length": actual_length,
            "etag": head["ETag"],
            "kms_key_arn": profile["state_kms_key_arn"],
            "lineage": state["lineage"],
            "serial": state["serial"],
            "sha256": sha256_file(state_path),
            "state_format_version": 4,
            "terraform_version": TF_VERSION,
            "version_id": head["VersionId"],
        },
        profile,
    )


def _validate_static_identity(args: argparse.Namespace) -> None:
    if args.repository != REPOSITORY or args.terraform_version != TF_VERSION:
        raise ContractError("artifact repository or Terraform version is wrong")
    profile = environment_profile(args.environment)
    expected_workflow_ref = (
        f"{REPOSITORY}/{profile['workflow_path']}@refs/heads/main"
    )
    if args.workflow_ref != expected_workflow_ref:
        raise ContractError("artifact workflow_ref is not exact main workflow")
    _require_hex(args.commit_sha, 40, "commit_sha")
    _require_hex(args.plan_sha256, 64, "plan_sha256")
    _require_positive_int(args.run_id, "run_id")
    _require_positive_int(args.run_attempt, "run_attempt")


def _artifact_values(
    args: argparse.Namespace, planned_at_epoch: int
) -> dict[str, Any]:
    _validate_static_identity(args)
    state = validate_state_summary(
        load_json(args.state_summary), environment_profile(args.environment)
    )
    contract_summary = load_json(args.contract_summary)
    if not isinstance(contract_summary, dict) or not contract_summary:
        raise ContractError("Control plan contract summary is malformed")
    plan_digest = sha256_file(args.plan)
    if plan_digest != args.plan_sha256:
        raise ContractError("saved plan digest does not match supplied digest")
    return {
        "account_id": environment_profile(args.environment)["account_id"],
        "commit_sha": args.commit_sha,
        "contract_checker_sha256": sha256_file(args.contract_checker),
        "contract_summary_sha256": sha256_file(args.contract_summary),
        "plan_sha256": plan_digest,
        "plan_text_sha256": sha256_file(args.plan_text),
        "planned_at_epoch": planned_at_epoch,
        "repository": REPOSITORY,
        "runtime_contract_sha256": sha256_file(args.runtime_contract),
        "run_attempt": int(args.run_attempt),
        "run_id": int(args.run_id),
        "schema_version": 1,
        "state": state,
        "state_summary_sha256": sha256_file(args.state_summary),
        "terraform_version": TF_VERSION,
        "workflow_ref": (
            f"{REPOSITORY}/"
            f"{environment_profile(args.environment)['workflow_path']}"
            "@refs/heads/main"
        ),
    }


def create_artifact(args: argparse.Namespace) -> dict[str, Any]:
    planned_at_epoch = _require_positive_int(
        args.planned_at_epoch, "planned_at_epoch"
    )
    metadata = _artifact_values(args, planned_at_epoch)
    write_json(args.output, metadata)
    return metadata


def verify_artifact(args: argparse.Namespace) -> dict[str, Any]:
    metadata = load_json(args.metadata)
    if not isinstance(metadata, dict) or set(metadata) != METADATA_KEYS:
        raise ContractError("artifact metadata keys are not exact")
    planned_at_epoch = _require_positive_int(
        metadata.get("planned_at_epoch"), "planned_at_epoch"
    )
    expected = _artifact_values(args, planned_at_epoch)
    if metadata != expected:
        mismatches = sorted(
            key for key in METADATA_KEYS if metadata.get(key) != expected.get(key)
        )
        raise ContractError("artifact metadata mismatch: " + ", ".join(mismatches))

    state = metadata["state"]
    if (
        state["version_id"] != args.state_version_id
        or state["serial"] != _require_nonnegative_int(args.state_serial, "state_serial")
        or state["sha256"] != _require_hex(args.state_sha256, 64, "state_sha256")
    ):
        raise ContractError("approved state identity does not match artifact")

    now_epoch = int(args.now_epoch) if args.now_epoch is not None else int(time.time())

    # Defense-in-depth: anchor the two-day freshness window to GitHub's
    # server-issued run_started_at for the source plan run, not to the
    # artifact's self-reported planned_at_epoch. planned_at_epoch is bound to
    # artifact integrity (any edit fails the metadata match above) but is still
    # a plan-runner wall-clock value; run_started_at is authoritative run
    # metadata that the apply job already fetched and this run was validated as
    # authentic by the source-run check. This window is only a courtesy
    # re-review bound, not the anti-drift control: the apply job's exact-state
    # `cmp`, live-main re-read, and saved-plan contract re-check are what
    # actually refuse a stale or drifted plan.
    run_started_epoch = _parse_iso8601_utc(args.run_started_at, "run_started_at")
    if not run_started_epoch <= planned_at_epoch <= now_epoch:
        raise ContractError(
            "planned_at_epoch is not bracketed by the source run start and now"
        )
    age = now_epoch - run_started_epoch
    if age < 0 or age > PLAN_MAX_AGE_SECONDS:
        raise ContractError("saved plan is outside the two-day approval window")
    return metadata


def check_source_run(args: argparse.Namespace) -> dict[str, Any]:
    run = load_json(args.run_json)
    profile = environment_profile(args.environment)
    expected = {
        "id": _require_positive_int(args.run_id, "run_id"),
        "run_attempt": _require_positive_int(args.run_attempt, "run_attempt"),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": args.commit_sha,
        "name": profile["workflow_name"],
        "path": profile["workflow_path"],
    }
    _require_hex(args.commit_sha, 40, "commit_sha")
    if not isinstance(run, dict):
        raise ContractError("source workflow run is malformed")
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContractError(f"source workflow run {key} is not exact")
    if run.get("repository", {}).get("full_name") != REPOSITORY:
        raise ContractError("source workflow run repository is not exact")
    for actor_field in ("actor", "triggering_actor"):
        login = run.get(actor_field, {}).get("login")
        if not isinstance(login, str) or not login:
            raise ContractError(f"source workflow run {actor_field} is malformed")
    return {"commit_sha": args.commit_sha, "run_attempt": expected["run_attempt"], "run_id": expected["id"]}


def _add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-text", type=Path, required=True)
    parser.add_argument("--contract-summary", type=Path, required=True)
    parser.add_argument("--contract-checker", type=Path, required=True)
    parser.add_argument("--runtime-contract", type=Path, required=True)
    parser.add_argument("--state-summary", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--terraform-version", required=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    def add_environment(sub_parser: argparse.ArgumentParser) -> None:
        # Required with no default: an omitted environment must fail rather than
        # silently validate one estate's capture against another's identity.
        sub_parser.add_argument(
            "--environment",
            required=True,
            choices=sorted(CONTROL_ENVIRONMENTS),
        )


    state = sub.add_parser("state")
    add_environment(state)
    state.add_argument("state_json", type=Path)
    state.add_argument("state_head_json", type=Path)

    create = sub.add_parser("artifact-create")
    add_environment(create)
    _add_artifact_arguments(create)
    create.add_argument("--planned-at-epoch", required=True)
    create.add_argument("--output", type=Path, required=True)

    verify = sub.add_parser("artifact-verify")
    add_environment(verify)
    _add_artifact_arguments(verify)
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--state-version-id", required=True)
    verify.add_argument("--state-serial", required=True)
    verify.add_argument("--state-sha256", required=True)
    verify.add_argument("--run-started-at", required=True)
    verify.add_argument("--now-epoch", type=int)

    source = sub.add_parser("source-run")
    add_environment(source)
    source.add_argument("run_json", type=Path)
    source.add_argument("--run-id", required=True)
    source.add_argument("--run-attempt", required=True)
    source.add_argument("--commit-sha", required=True)

    args = parser.parse_args()
    try:
        if args.command == "state":
            result = check_state(
                args.state_json,
                args.state_head_json,
                environment_profile(args.environment),
            )
        elif args.command == "artifact-create":
            result = create_artifact(args)
        elif args.command == "artifact-verify":
            result = verify_artifact(args)
        else:
            result = check_source_run(args)
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
