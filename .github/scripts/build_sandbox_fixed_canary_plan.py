#!/usr/bin/env python3
"""Build the exact qurl-integrations fixed-canary plan from reviewed runtime bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ACCOUNT_ID = "767397897469"
REGION = "us-east-2"
SESSION_TABLE = "layerv-nhp-sandbox-cell0-nhp-session-control"
AGENT_KEYS_TABLE = "layerv-nhp-sandbox-control-qurl-agent-keys"
CELL_ID = "cell0"
RELAY_ASG = "layerv-nhp-sandbox-relay-dmz"
OWNER = re.compile(r"[A-Za-z0-9_-]{20,128}@clients\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RAW32 = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
DELIVERY_COLORS = ("blue", "green")
SERVER_ASGS = {
    "blue": "layerv-nhp-sandbox-server",
    "green": "layerv-nhp-sandbox-server-green",
}
AC_ASGS = {
    "blue": "layerv-nhp-sandbox-ac",
    "green": "layerv-nhp-sandbox-ac-green",
}
LABELS = ("direct-a", "direct-b", "relay-c", "relay-d")
SELECTORS = (
    ("qurl-tunnel-server-a", 7000),
    ("qurl-tunnel-server-b", 7001),
    ("qurl-tunnel-server-c", 7002),
    ("qurl-tunnel-server-a", 7000),
)


class PlanError(RuntimeError):
    """The immutable runtime cannot produce one exact fixed-canary plan."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError("runtime JSON contains a duplicate field")
        result[key] = value
    return result


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PlanError(f"{label} schema is not exact")
    return value


def _endpoint(value: Any, label: str) -> dict[str, Any]:
    endpoint = _exact(value, {"host", "port", "server_public_key_b64"}, label)
    if (
        not isinstance(endpoint["host"], str)
        or HOST.fullmatch(endpoint["host"]) is None
        or "." not in endpoint["host"]
        or endpoint["port"] != 443
        or not isinstance(endpoint["server_public_key_b64"], str)
        or RAW32.fullmatch(endpoint["server_public_key_b64"]) is None
    ):
        raise PlanError(f"{label} is invalid")
    return endpoint


def load_runtime(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\r" in raw or b"\n" in raw[:-1]:
        raise PlanError("runtime framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PlanError("runtime JSON is invalid") from error
    runtime = _exact(
        value,
        {
            "schema",
            "environment",
            "aws_account_id",
            "aws_region",
            "active_colors",
            "cohorts",
            "relay",
            "session_control_table",
            "qurl_agent_keys_table",
            "cell_id",
            "assignment_generation",
            "hub_endpoint",
            "cell_endpoint",
            "frps_host",
            "issuer",
            "asgs",
            "tables",
            "qurl_service",
            "parameter_versions",
            "runtime_sha256",
        },
        "runtime",
    )
    body = dict(runtime)
    claimed = body.pop("runtime_sha256")
    body_raw = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if claimed != hashlib.sha256(body_raw).hexdigest():
        raise PlanError("runtime digest is not exact")
    active = _exact(runtime["active_colors"], {"server", "ac"}, "active colors")
    cohorts = _exact(runtime["cohorts"], {"blue", "green"}, "runtime cohorts")
    for color in DELIVERY_COLORS:
        cohort = _exact(cohorts[color], {"server_asg", "ac_asg", "server", "ac"}, f"{color} runtime cohort")
        if cohort["server_asg"] != SERVER_ASGS[color] or cohort["ac_asg"] != AC_ASGS[color]:
            raise PlanError(f"{color} runtime cohort is invalid")
        for component in ("server", "ac"):
            image = _exact(cohort[component], {"source_sha", "image_digest"}, f"{color} {component} image")
            if HEX64.fullmatch(str(image["image_digest"]).removeprefix("sha256:")) is None or re.fullmatch(r"[0-9a-f]{40}", str(image["source_sha"])) is None:
                raise PlanError(f"{color} {component} image authority is invalid")
    relay = _exact(runtime["relay"], {"asg", "hostname", "source_sha", "image_digest"}, "relay runtime")
    if relay["asg"] != RELAY_ASG or relay["hostname"] != "relay.qurl.link.layerv.xyz" or re.fullmatch(r"[0-9a-f]{40}", str(relay["source_sha"])) is None or HEX64.fullmatch(str(relay["image_digest"]).removeprefix("sha256:")) is None:
        raise PlanError("relay image authority is invalid")
    issuer = _exact(runtime["issuer"], {"kid", "spki_der_b64"}, "issuer runtime")
    if issuer["kid"] != "qurl-issuer-sandbox-2026-07" or not isinstance(issuer["spki_der_b64"], str) or not issuer["spki_der_b64"]:
        raise PlanError("issuer runtime authority is invalid")
    qurl_service = _exact(runtime["qurl_service"], {"source_tag", "image_digest", "platform_image_digest", "task_definition"}, "qurl-service runtime")
    if re.fullmatch(r"[0-9a-f]{7}", str(qurl_service["source_tag"])) is None or any(HEX64.fullmatch(str(qurl_service[key]).removeprefix("sha256:")) is None for key in ("image_digest", "platform_image_digest")) or not isinstance(qurl_service["task_definition"], str):
        raise PlanError("qurl-service runtime authority is invalid")
    if (
        runtime["schema"] != 1
        or runtime["environment"] != "sandbox"
        or runtime["aws_account_id"] != ACCOUNT_ID
        or runtime["aws_region"] != REGION
        or active["server"] not in DELIVERY_COLORS
        or active["ac"] not in DELIVERY_COLORS
        or relay["asg"] != RELAY_ASG
        or runtime["session_control_table"] != SESSION_TABLE
        or runtime["qurl_agent_keys_table"] != AGENT_KEYS_TABLE
        or runtime["cell_id"] != CELL_ID
        or type(runtime["assignment_generation"]) is not int
        or runtime["assignment_generation"] <= 0
        or runtime["frps_host"] != "connect.layerv.xyz"
    ):
        raise PlanError("runtime sandbox identity is invalid")
    _endpoint(runtime["hub_endpoint"], "Hub endpoint")
    _endpoint(runtime["cell_endpoint"], "cell endpoint")
    return runtime, raw


def _plan_without_generation(
    runtime: dict[str, Any], owner_subject: str, nhp_source_sha: str, qurl_go_source_sha: str
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", nhp_source_sha) is None or re.fullmatch(r"[0-9a-f]{40}", qurl_go_source_sha) is None:
        raise PlanError("resolved source authority is invalid")
    active_server = runtime["active_colors"]["server"]
    active_ac = runtime["active_colors"]["ac"]
    hub = runtime["hub_endpoint"]
    cell = runtime["cell_endpoint"]
    cohorts = [
        {
            "server_asg": runtime["cohorts"][active_server]["server_asg"],
            "ac_asg": runtime["cohorts"][active_ac]["ac_asg"],
            "relay_asg": runtime["relay"]["asg"],
            "session_control_table": runtime["session_control_table"],
            "qurl_agent_keys_table": runtime["qurl_agent_keys_table"],
            "cell_id": runtime["cell_id"],
            "assignment_generation": runtime["assignment_generation"],
            "hub_host": hub["host"],
            "hub_port": hub["port"],
            "hub_server_public_key_b64": hub["server_public_key_b64"],
            "cell_endpoint": {
                "host": cell["host"],
                "port": cell["port"],
                "server_public_key_b64": cell["server_public_key_b64"],
            },
        }
    ]
    identities = []
    for label, (resource_id, port) in zip(LABELS, SELECTORS, strict=True):
        slug = f"fixed-shared-{label}"
        identities.append(
            {
                "label": label,
                "owner_id": owner_subject,
                "agent_id": f"{slug}-agent",
                "connector_id": f"{slug}-connector",
                "frps_selector": {
                    "resource_id": resource_id,
                    "host": runtime["frps_host"],
                    "port": port,
                },
            }
        )
    return {
        "schema": 1,
        "environment": "sandbox",
        "owner_subject": owner_subject,
        "aws_account_id": runtime["aws_account_id"],
        "aws_region": runtime["aws_region"],
        "nhp_source_sha": nhp_source_sha,
        "qurl_go_source_sha": qurl_go_source_sha,
        "cohorts": cohorts,
        "identities": identities,
    }


def build_plan(runtime: dict[str, Any], owner_subject: str, nhp_source_sha: str, qurl_go_source_sha: str) -> dict[str, Any]:
    if OWNER.fullmatch(owner_subject) is None:
        raise PlanError("fixed canary owner subject is invalid")
    body = _plan_without_generation(runtime, owner_subject, nhp_source_sha, qurl_go_source_sha)
    body_raw = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode()
    generation_id = hashlib.sha256(b"layerv/sandbox-fixed-canary-generation/v1\x00" + body_raw).hexdigest()
    return {
        "schema": body["schema"],
        "environment": body["environment"],
        "generation_id": generation_id,
        "owner_subject": body["owner_subject"],
        "aws_account_id": body["aws_account_id"],
        "aws_region": body["aws_region"],
        "nhp_source_sha": body["nhp_source_sha"],
        "qurl_go_source_sha": body["qurl_go_source_sha"],
        "cohorts": body["cohorts"],
        "identities": body["identities"],
    }


def build_lifecycle_input(
    runtime: dict[str, Any],
    plan: dict[str, Any],
    *,
    operation: str,
    transport: str,
    authority: dict[str, str],
    attempt: int,
    run_ids: list[str],
    prepared_at_ms: int,
    expires_at_ms: int,
    api_key_file: str,
    deployment_file: str,
    deployment_sha256: str,
    lifecycle_command_sha256: str,
    qurl_binary: str,
    qurl_binary_sha256: str,
    qurl_source_sha: str,
    release_id: str | None = None,
) -> dict[str, Any]:
    """Project validated runtime and custody bytes into the closed qURL input."""
    if operation not in {"lifecycle", "recover-prepared"} or transport not in {"direct", "relay"} or type(attempt) is not int or not 1 <= attempt <= 9:
        raise PlanError("lifecycle operation identity is invalid")
    if operation == "recover-prepared" and (transport != "direct" or len(run_ids) != 1 or attempt > 3):
        raise PlanError("recovery-first operation is invalid")
    if operation == "lifecycle" and len(run_ids) != 3:
        raise PlanError("customer lifecycle RunID set is invalid")
    if any(re.fullmatch(r"[0-9a-f]{16}", str(run_id)) is None for run_id in run_ids) or len(set(run_ids)) != len(run_ids):
        raise PlanError("customer lifecycle RunIDs are invalid")
    reference = _exact(authority, {"key", "version_id", "sha256"}, "lifecycle authority")
    if not isinstance(reference["key"], str) or not reference["key"] or any(HEX64.fullmatch(str(reference[key])) is None for key in ("version_id", "sha256")):
        raise PlanError("lifecycle authority is invalid")
    if (
        type(prepared_at_ms) is not int
        or type(expires_at_ms) is not int
        or prepared_at_ms <= 0
        or expires_at_ms <= prepared_at_ms
        or any(HEX64.fullmatch(value) is None for value in (deployment_sha256, lifecycle_command_sha256, qurl_binary_sha256, release_id or plan["generation_id"]))
        or re.fullmatch(r"[0-9a-f]{40}", qurl_source_sha) is None
    ):
        raise PlanError("lifecycle artifact or time authority is invalid")
    for path in (api_key_file, deployment_file, qurl_binary):
        if not isinstance(path, str) or not path.startswith("/"):
            raise PlanError("lifecycle private path is invalid")
    if len(plan["cohorts"]) != 1:
        raise PlanError("lifecycle shared cohort is not exact")
    cohort = plan["cohorts"][0]
    if cohort["relay_asg"] != runtime["relay"]["asg"]:
        raise PlanError("lifecycle cohort does not match runtime")
    phase = "fixed_shared_recovery_first" if operation == "recover-prepared" else f"fixed_shared_{transport}"
    return {
        "schema": 1,
        "environment": "sandbox",
        "operation": operation,
        "release_id": release_id or plan["generation_id"],
        "phase": phase,
        "attempt": attempt,
        "transport": transport,
        "authority": reference,
        "admission_hub": runtime["hub_endpoint"],
        "admission_cell_endpoint": runtime["cell_endpoint"],
        "recovery_endpoint": runtime["cell_endpoint"],
        "run_ids": run_ids,
        "prepared_at_ms": prepared_at_ms,
        "expires_at_ms": expires_at_ms,
        "api_endpoint": "https://api.layerv.xyz",
        "api_key_file": api_key_file,
        "deployment_file": deployment_file,
        "deployment_sha256": deployment_sha256,
        "relay_hostname": runtime["relay"]["hostname"],
        "lifecycle_command_sha256": lifecycle_command_sha256,
        "qurl_binary": qurl_binary,
        "qurl_binary_sha256": qurl_binary_sha256,
        "qurl_source_sha": qurl_source_sha,
        "qurl_go_source_sha": plan["qurl_go_source_sha"],
        "client_version": f"sandbox-pr-{qurl_source_sha[:12]}",
    }


def write_plan(path: Path, plan: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or stat_mode(path.parent) != 0o700:
        raise PlanError("plan output path is not fresh and private")
    raw = json.dumps(plan, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PlanError("plan output write was short")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o7777


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-file", type=Path, required=True)
    parser.add_argument("--owner-subject", required=True)
    parser.add_argument("--nhp-source-sha", required=True)
    parser.add_argument("--qurl-go-source-sha", required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    runtime, _ = load_runtime(args.runtime_file)
    write_plan(args.output_file, build_plan(runtime, args.owner_subject, args.nhp_source_sha, args.qurl_go_source_sha))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, PlanError):
        print("sandbox fixed-canary plan construction failed", file=sys.stderr)
        raise SystemExit(1) from None
