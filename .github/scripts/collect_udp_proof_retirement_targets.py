#!/usr/bin/env python3
"""Collect the exact live HTTP/relay targets used by attended retirement probes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import collect_udp_proof_deployment_evidence as evidence
import udp_proof_deployment_contract as deployment
import udp_proof_retirement_targets_contract as targets


QURL_SURFACE_PATH = "tests/e2e/nativeudp/retired_lifecycle_surface.json"


def _alias(host: str, zone_id: str) -> dict[str, str]:
    response = evidence._aws(
        "route53",
        [
            "list-resource-record-sets",
            "--hosted-zone-id",
            zone_id,
            "--start-record-name",
            host,
            "--start-record-type",
            "A",
            "--max-items",
            "10",
        ],
        f"{host} Route53 retirement target",
    )
    records = (
        response.get("ResourceRecordSets") if isinstance(response, dict) else None
    )
    matches = [
        row
        for row in records or []
        if isinstance(row, dict)
        and row.get("Name") == f"{host}."
        and row.get("Type") == "A"
    ]
    if not isinstance(records, list) or len(records) > 10 or len(matches) != 1:
        raise targets.TargetsError(f"{host} does not have one exact A alias")
    record = matches[0]
    if set(record) != {"AliasTarget", "Name", "Type"}:
        raise targets.TargetsError(
            f"{host} Route53 target must be an unweighted alias"
        )
    alias = record["AliasTarget"]
    if (
        not isinstance(alias, dict)
        or set(alias) != {"DNSName", "EvaluateTargetHealth", "HostedZoneId"}
        or not isinstance(alias["DNSName"], str)
        or not alias["DNSName"].endswith(".")
        or type(alias["EvaluateTargetHealth"]) is not bool
        or not isinstance(alias["HostedZoneId"], str)
        or not alias["HostedZoneId"]
    ):
        raise targets.TargetsError(f"{host} Route53 AliasTarget is malformed")
    return {
        "alias_dns_name": alias["DNSName"].removesuffix("."),
        "record_name": host,
        "zone_id": zone_id,
    }


def _surface_sha256(qurl_go_sha: str) -> str:
    result = evidence._run_bounded(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github.raw+json",
            (
                "repos/layervai/qurl-go/contents/"
                f"{QURL_SURFACE_PATH}?ref={qurl_go_sha}"
            ),
        ],
        "qurl-go retirement surface contract",
        maximum=64 * 1024,
    )
    if result.returncode != 0:
        raise targets.TargetsError("could not read qurl-go retirement surface")
    try:
        value = json.loads(
            result.stdout.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise targets.TargetsError(
            "qurl-go retirement surface is not strict JSON"
        ) from exc
    raw = deployment.canonical_bytes(
        value,
        maximum=64 * 1024,
        name="qurl-go retirement surface",
    )
    return hashlib.sha256(raw).hexdigest()


def _server_id(public_key_b64: str) -> str:
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise targets.TargetsError("cell public key is not strict base64") from exc
    if len(raw) != 32:
        raise targets.TargetsError("cell public key is not X25519-sized")
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:8]).decode(
        "ascii"
    ).rstrip("=")


def collect(
    directory: Path,
    *,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime | None = None,
) -> bytes:
    manifest = deployment.load_canonical_file(
        directory / "deployment-manifest.json",
        maximum=deployment.MAX_MANIFEST_BYTES,
        name="deployment-manifest.json",
    )
    runtime = deployment.load_canonical_file(
        directory / "deployment-runtime-inputs.json",
        maximum=deployment.MAX_RUNTIME_BYTES,
        name="deployment-runtime-inputs.json",
    )
    provenance = deployment.load_canonical_file(
        directory / "deployment-provenance.json",
        maximum=deployment.MAX_PROVENANCE_BYTES,
        name="deployment-provenance.json",
    )
    manifest_raw, runtime_raw, provenance_raw = deployment.validate_triplet(
        manifest,
        runtime,
        provenance,
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=validation_time or datetime.now(timezone.utc),
    )
    del manifest_raw, runtime_raw

    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
    surface_sha256 = _surface_sha256(manifest["repositories"]["qurl_go"])
    relay_parameter = evidence._ssm_parameter(targets.RELAY_PARAMETER)
    if relay_parameter["Value"] != targets.RELAY_BASE_URL:
        raise targets.TargetsError("relay SSM value differs from the public target")
    route53_by_host = {
        host: _alias(host, zone_id)
        for host, _, _, zone_id in targets.HTTP_OPERATIONS
    }
    route53_by_host["relay.qurl.link.layerv.xyz"] = _alias(
        "relay.qurl.link.layerv.xyz", targets.PUBLIC_ZONE_ID
    )
    runtime_cells = runtime["cells"]
    if [cell["cell_id"] for cell in runtime_cells] != ["cell0", "cell1"]:
        raise targets.TargetsError("runtime cell identities are not cell0 then cell1")
    document = {
        "schema_version": targets.SCHEMA_VERSION,
        "gate": targets.GATE,
        "phase": proof_phase,
        "observed_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {
            "deployment_provenance_sha256": hashlib.sha256(
                provenance_raw
            ).hexdigest(),
            "head_sha": producer_head_sha,
            "run_attempt": producer_run_attempt,
            "run_id": producer_run_id,
            "surface_contract_sha256": surface_sha256,
        },
        "http_operations": [
            {
                "host": host,
                "method": method,
                "path": path,
                "route53": route53_by_host[host],
            }
            for host, method, path, _ in targets.HTTP_OPERATIONS
        ],
        "relay": {
            "aliases": [
                {
                    "cell_id": cell["cell_id"],
                    "server_id": _server_id(cell["server_public_key_b64"]),
                }
                for cell in runtime_cells
            ],
            "base_url": targets.RELAY_BASE_URL,
            "route53": route53_by_host["relay.qurl.link.layerv.xyz"],
            "ssm": {
                "name": targets.RELAY_PARAMETER,
                "value_sha256": hashlib.sha256(
                    relay_parameter["Value"].encode("ascii")
                ).hexdigest(),
                "version": relay_parameter["Version"],
            },
        },
    }
    targets.validate(
        document,
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        deployment_provenance_sha256=hashlib.sha256(provenance_raw).hexdigest(),
        surface_contract_sha256=surface_sha256,
        validation_time=observed_at,
    )
    return targets.canonical_bytes(document)


def write_exclusive(path: Path, raw: bytes) -> None:
    if path.exists():
        raise targets.TargetsError(f"{path} already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise targets.TargetsError("retirement target artifact mode is not 0600")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-directory", type=Path, required=True)
    parser.add_argument(
        "--proof-phase", choices=("pre_removal", "post_removal"), required=True
    )
    parser.add_argument("--producer-run-id", type=int, required=True)
    parser.add_argument("--producer-run-attempt", type=int, required=True)
    parser.add_argument("--producer-head-sha", required=True)
    args = parser.parse_args()
    try:
        raw = collect(
            args.artifact_directory,
            proof_phase=args.proof_phase,
            producer_run_id=args.producer_run_id,
            producer_run_attempt=args.producer_run_attempt,
            producer_head_sha=args.producer_head_sha,
        )
        write_exclusive(
            args.artifact_directory / targets.ARTIFACT_FILE_NAME,
            raw,
        )
    except (deployment.ContractError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
