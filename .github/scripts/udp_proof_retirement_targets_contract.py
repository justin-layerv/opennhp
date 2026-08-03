#!/usr/bin/env python3
"""Authenticated targets for attended HTTP/relay retirement probes."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from typing import Any

import udp_proof_deployment_contract as deployment


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "retirement-probe-targets.json"
MAX_ARTIFACT_BYTES = 32 * 1024
PUBLIC_ZONE_ID = "Z10394893FM38A1RXLL32"
PRIVATE_ZONE_ID = "Z0583929NF6JQSC2XALS"
RELAY_PARAMETER = "/sandbox/nhp/qurl/relay-url"
RELAY_BASE_URL = "https://relay.qurl.link.layerv.xyz"
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
DNS_NAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}\.?$")

HTTP_OPERATIONS = (
    ("bootstrap.layerv.xyz", "POST", "/v1/agent/bootstrap", PUBLIC_ZONE_ID),
    ("api.layerv.xyz", "GET", "/v1/agent/registration-info", PUBLIC_ZONE_ID),
    (
        "api.layerv.xyz",
        "POST",
        "/v1/agent/registration/complete",
        PUBLIC_ZONE_ID,
    ),
    (
        "internal-api.qurl.layerv.xyz",
        "POST",
        "/internal/v1/agent/otp",
        PRIVATE_ZONE_ID,
    ),
    (
        "internal-api.qurl.layerv.xyz",
        "POST",
        "/internal/v1/agent/register",
        PRIVATE_ZONE_ID,
    ),
)


class TargetsError(deployment.ContractError):
    """The trusted producer did not bind the exact sandbox retirement targets."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise TargetsError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA_RE.fullmatch(value) is None:
        raise TargetsError(f"{name} must be a lowercase commit SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA256_RE.fullmatch(value) is None:
        raise TargetsError(f"{name} must be a lowercase SHA-256")
    return value


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > 9_007_199_254_740_991:
        raise TargetsError(f"{name} must be a positive safe integer")
    return value


def _route53(
    value: Any,
    *,
    host: str,
    zone_id: str,
    name: str,
    expect_present: bool = True,
) -> dict[str, Any]:
    route = _exact(
        value,
        {"alias_dns_name", "record_name", "zone_id"},
        name,
    )
    if route["zone_id"] != zone_id or route["record_name"] != host:
        raise TargetsError(f"{name} is not the exact observed Route53 alias")
    if not expect_present:
        # post_removal records the retired host's alias as gone. None is the
        # only accepted value: a DNS name here would mean the surface survived
        # the retirement, which must fail rather than be recorded as observed.
        if route["alias_dns_name"] is not None:
            raise TargetsError(f"{name} must be absent after the retirement applied")
        return route
    if (
        not isinstance(route["alias_dns_name"], str)
        or DNS_NAME_RE.fullmatch(route["alias_dns_name"]) is None
    ):
        raise TargetsError(f"{name} is not the exact observed Route53 alias")
    return route


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_ARTIFACT_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def validate(
    value: Any,
    *,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    deployment_provenance_sha256: str,
    surface_contract_sha256: str | None = None,
    validation_time: datetime | None = None,
) -> dict[str, Any]:
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise TargetsError("retirement target proof phase is invalid")
    document = _exact(
        value,
        {
            "gate",
            "http_operations",
            "observed_at",
            "phase",
            "producer",
            "relay",
            "schema_version",
        },
        "retirement probe targets",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or type(document["schema_version"]) is not int
        or document["gate"] != GATE
        or document["phase"] != proof_phase
    ):
        raise TargetsError("retirement probe target header drift")
    producer = _exact(
        document["producer"],
        {
            "deployment_provenance_sha256",
            "head_sha",
            "run_attempt",
            "run_id",
            "surface_contract_sha256",
        },
        "retirement probe target producer",
    )
    _positive(producer_run_id, "retirement target producer run_id")
    _positive(producer_run_attempt, "retirement target producer run_attempt")
    _sha(producer_head_sha, "retirement target producer head_sha")
    _sha256(
        deployment_provenance_sha256,
        "retirement target deployment provenance SHA-256",
    )
    _sha256(
        producer["surface_contract_sha256"],
        "retirement target surface contract SHA-256",
    )
    if producer != {
        "deployment_provenance_sha256": deployment_provenance_sha256,
        "head_sha": producer_head_sha,
        "run_attempt": producer_run_attempt,
        "run_id": producer_run_id,
        "surface_contract_sha256": (
            surface_contract_sha256 or producer["surface_contract_sha256"]
        ),
    }:
        raise TargetsError("retirement probe target producer binding drift")

    try:
        observed = deployment._timestamp(
            document["observed_at"], "retirement target observed_at"
        )
        checked = deployment._utc_time(
            validation_time or observed, "retirement target validation time"
        )
    except deployment.ContractError as exc:
        raise TargetsError(str(exc)) from exc
    if (
        observed > checked + deployment.MAX_CLOCK_SKEW
        or checked - observed > timedelta(minutes=10)
    ):
        raise TargetsError("retirement probe targets are outside the live window")

    operations = document["http_operations"]
    if not isinstance(operations, list) or len(operations) != len(HTTP_OPERATIONS):
        raise TargetsError("retirement HTTP target inventory is incomplete")
    for index, expected in enumerate(HTTP_OPERATIONS):
        host, method, path, zone_id = expected
        operation = _exact(
            operations[index],
            {"host", "method", "path", "route53"},
            f"retirement HTTP operation {index}",
        )
        if (
            operation["host"] != host
            or operation["method"] != method
            or operation["path"] != path
        ):
            raise TargetsError(f"retirement HTTP operation {index} drift")
        _route53(
            operation["route53"],
            host=host,
            zone_id=zone_id,
            name=f"retirement HTTP operation {index} Route53",
            expect_present=proof_phase == "pre_removal",
        )

    relay = _exact(
        document["relay"],
        {"aliases", "base_url", "route53", "ssm"},
        "retirement relay target",
    )
    if relay["base_url"] != RELAY_BASE_URL:
        raise TargetsError("retirement relay base URL drift")
    _route53(
        relay["route53"],
        host="relay.qurl.link.layerv.xyz",
        zone_id=PUBLIC_ZONE_ID,
        name="retirement relay Route53",
    )
    parameter = _exact(
        relay["ssm"],
        {"name", "value_sha256", "version"},
        "retirement relay SSM",
    )
    if (
        parameter["name"] != RELAY_PARAMETER
        or _positive(parameter["version"], "retirement relay SSM version") < 1
        or parameter["value_sha256"]
        != hashlib.sha256(RELAY_BASE_URL.encode("ascii")).hexdigest()
    ):
        raise TargetsError("retirement relay SSM binding drift")
    aliases = relay["aliases"]
    if not isinstance(aliases, list) or len(aliases) != 2:
        raise TargetsError("retirement relay aliases must contain exactly two cells")
    observed_aliases: list[tuple[str, str]] = []
    for index, value in enumerate(aliases):
        alias = _exact(value, {"cell_id", "server_id"}, f"relay alias {index}")
        if (
            alias["cell_id"] not in {"cell0", "cell1"}
            or not isinstance(alias["server_id"], str)
            or SERVER_ID_RE.fullmatch(alias["server_id"]) is None
        ):
            raise TargetsError(f"relay alias {index} is invalid")
        observed_aliases.append((alias["cell_id"], alias["server_id"]))
    if [cell_id for cell_id, _ in observed_aliases] != ["cell0", "cell1"]:
        raise TargetsError("retirement relay aliases are not cell0 then cell1")
    if len({server_id for _, server_id in observed_aliases}) != 2:
        raise TargetsError("retirement relay aliases reuse one server identity")
    return document


def validate_bytes(raw: bytes, **kwargs: Any) -> dict[str, Any]:
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_ARTIFACT_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise TargetsError(str(exc)) from exc
    return validate(value, **kwargs)
