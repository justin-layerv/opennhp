#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import produce_udp_proof_deployment_manifest as producer  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402


PRODUCER_SHA = "a" * 40
NHP_SHA = "b" * 40
CONNECTOR_SHA = "c" * 40
QURL_GO_SHA = "d" * 40
FRP_SHA = "e" * 40
QURL_SERVICE_SHA = "1" * 40
QRTS_SHA = "2" * 40
OTHER_SHA = "3" * 40
OBSERVED_AT = "2026-07-25T12:00:00Z"
FRESH_AT = "2026-07-25T11:55:00Z"
REPAIR_AT = "2026-07-25T11:30:00Z"


def public_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


HUB_KEY = public_key(1)
CELL0_KEY = public_key(2)
CELL1_KEY = public_key(3)


def digest(seed: str) -> str:
    return f"sha256:{seed * 64}"


def edge_identity(name: str, target_id: str) -> dict[str, object]:
    identity = "0123456789abcdef"
    security_group_names = {
        "layerv-nhp-sandbox-hub-edge": (
            "layerv-nhp-sandbox-control-hub-nlb",
            "layerv-nhp-sandbox-control-hub",
            [],
            [],
        ),
        "layerv-nhp-sandbox-edge": (
            "layerv-nhp-sandbox-sg-nlb",
            "layerv-nhp-sandbox-sg-server",
            [
                "10.100.0.0/16",
                "10.101.10.0/24",
                "10.101.11.0/24",
                "10.101.12.0/24",
            ],
            ["10.100.0.0/16"],
        ),
        "layerv-nhp-sandbox-cell1-edge": (
            "layerv-nhp-sandbox-cell1-sg-nlb",
            "layerv-nhp-sandbox-cell1-sg-server",
            ["10.104.0.0/16"],
            ["10.104.0.0/16"],
        ),
    }
    (
        nlb_security_group_name,
        backend_security_group_name,
        backend_udp_cidrs,
        backend_health_cidrs,
    ) = security_group_names[name]
    return {
        "load_balancer_name": name,
        "load_balancer_arn": (
            "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            f"loadbalancer/net/{name}/{identity}"
        ),
        "load_balancer_dns_name": (f"{name}-{identity}.elb.us-east-2.amazonaws.com"),
        "load_balancer_security_group_id": "sg-00000000000000001",
        "load_balancer_security_group_name": nlb_security_group_name,
        "backend_security_group_id": "sg-00000000000000002",
        "backend_security_group_name": backend_security_group_name,
        "backend_udp_cidrs": backend_udp_cidrs,
        "backend_health_cidrs": backend_health_cidrs,
        "proof_source_cidr": "3.141.109.76/32",
        "listener_arn": (
            "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            f"listener/net/{name}/{identity}/{identity}"
        ),
        "target_group_arn": (
            "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            f"targetgroup/{name[:24]}-udp/{identity}"
        ),
        "healthy_target_ids": [target_id],
        "route53_zone_id": "Z10394893FM38A1RXLL32",
    }


IMAGE_DIGESTS = {
    "nhp_cell0": digest("1"),
    "nhp_cell1": digest("2"),
    "nhp_hub": digest("3"),
    "qurl_connector": digest("4"),
    "qurl_reverse_tunnel_server": digest("5"),
    "qurl_service_authority": digest("6"),
    "qurl_service_cell0": digest("7"),
    "qurl_service_cell1": digest("8"),
}


def repository_shas() -> dict[str, str]:
    return {
        "frp": FRP_SHA,
        "nhp": NHP_SHA,
        "qurl_connector": CONNECTOR_SHA,
        "qurl_go": QURL_GO_SHA,
        "qurl_integrations": OTHER_SHA,
        "qurl_mcp": "4" * 40,
        "qurl_python": "5" * 40,
        "qurl_reverse_tunnel_server": QRTS_SHA,
        "qurl_service": QURL_SERVICE_SHA,
        "qurl_typescript": "6" * 40,
        "website": "7" * 40,
    }


def source_evidence(workload: str) -> dict[str, object]:
    image_digest = IMAGE_DIGESTS[workload]
    if workload in {"qurl_service_cell0", "qurl_service_cell1"}:
        cell = "sandbox" if workload.endswith("cell0") else "sandbox-cell1"
        image_uri = (
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
            f"layerv/nhp-qurl@{image_digest}"
        )
        payload = {
            "image_uri": image_uri,
            "schema_version": 1,
            "source_revision": QURL_SERVICE_SHA,
        }
        return {
            "kind": "ssm_runtime_contract",
            "parameter_name": f"/{cell}/nhp/qurl-service/runtime-contract",
            "parameter_version": 1,
            "contract_sha256": hashlib.sha256(
                contract.canonical_bytes(payload, maximum=4096, name="runtime contract")
            ).hexdigest(),
            "image_uri": image_uri,
            "source_revision": QURL_SERVICE_SHA,
        }
    if workload == "qurl_reverse_tunnel_server":
        return {
            "kind": "ecr_build_receipt",
            "manifest_digest": image_digest,
            "config_digest": digest("9"),
            "revision_label": QRTS_SHA,
            "installed_binary_sha256": "8" * 64,
            "build_receipt_sha256": "9" * 64,
        }
    source_revision = (
        NHP_SHA
        if workload in {"nhp_cell0", "nhp_cell1", "nhp_hub"}
        else QURL_SERVICE_SHA
    )
    return {
        "kind": "oci_revision_label",
        "manifest_digest": image_digest,
        "config_digest": digest("9"),
        "revision_label": source_revision,
    }


def attestation(
    *,
    component: str,
    instance_id: str,
    role_id: str,
    image_repository: str,
    image_digest: str,
    source_revision: str,
) -> dict[str, object]:
    runtime: dict[str, object]
    if component == "qurl_reverse_tunnel_server":
        runtime = {
            "kind": "installed_binary",
            "image_repository": image_repository,
            "image_digest": image_digest,
            "source_revision": source_revision,
            "installed_binary_sha256": "8" * 64,
            "build_receipt_sha256": "9" * 64,
            "source_kind": "ecr_build_receipt",
        }
    else:
        runtime = {
            "kind": "docker_container",
            "container_name": "nhp-server",
            "container_id": "a" * 64,
            "image_repository": image_repository,
            "image_digest": image_digest,
            "source_revision": source_revision,
        }
    aws_userid = f"{role_id}:{instance_id}"
    return {
        "bucket_arn": "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestation",
        "key": f"runtime/{aws_userid}/latest.json",
        "version_id": "version-1",
        "object_sha256": "a" * 64,
        "observed_at": FRESH_AT,
        "instance_id": instance_id,
        "role_arn": f"arn:aws:iam::767397897469:role/{component}",
        "aws_userid": aws_userid,
        "launch_template_id": "lt-0123456789abcdef0",
        "launch_template_version": 7,
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "collector_sha256": "b" * 64,
        "service_unit_sha256": "c" * 64,
        "timer_unit_sha256": "d" * 64,
        "repair_document_name": "layerv-nhp-sandbox-runtime-attestation-repair",
        "repair_association_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "repair_last_success_at": REPAIR_AT,
        "runtime": runtime,
    }


def valid_snapshot() -> dict[str, object]:
    collector_contract = {
        "schema_version": 1,
        "parameter_name": (
            "/sandbox/nhp/udp-proof/runtime-attestation-collector-contract"
        ),
        "parameter_version": 3,
        "contract_sha256": "e" * 64,
        "collector_sha256": "b" * 64,
        "service_unit_sha256": "c" * 64,
        "timer_unit_sha256": "d" * 64,
        "repair_document_name": ("layerv-nhp-sandbox-runtime-attestation-repair"),
        "repair_document_version": "2",
        "repair_document_sha256": "f" * 64,
        "bucket_policy_sha256": "9" * 64,
    }
    repositories = repository_shas()
    manifest = {
        "schema_version": 1,
        "phase": "pre_removal",
        "retirement_state": "http_lifecycle_present",
        "repositories": repositories,
        "connector_modules": {"frp": FRP_SHA, "qurl_go": QURL_GO_SHA},
        "images": IMAGE_DIGESTS,
        "hub": {
            "host": "hub.nhp.layerv.xyz",
            "port": 443,
            "server_public_key_sha256": hashlib.sha256(
                base64.b64decode(HUB_KEY)
            ).hexdigest(),
        },
        "cells": [
            {
                "cell_id": "cell0",
                "host": "cell0.nhp.layerv.xyz",
                "port": 443,
                "server_public_key_sha256": hashlib.sha256(
                    base64.b64decode(CELL0_KEY)
                ).hexdigest(),
            },
            {
                "cell_id": "cell1",
                "host": "cell1.nhp.layerv.xyz",
                "port": 443,
                "server_public_key_sha256": hashlib.sha256(
                    base64.b64decode(CELL1_KEY)
                ).hexdigest(),
            },
        ],
    }
    runtime = {
        "schema_version": 1,
        "connector_sealed_state": {
            "provider": "aws-kms",
            "region": "us-east-2",
            "key_arn": (
                "arn:aws:kms:us-east-2:767397897469:key/"
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            ),
        },
        "hub": {
            "host": "hub.nhp.layerv.xyz",
            "port": 443,
            "server_public_key_b64": HUB_KEY,
        },
        "cells": [
            {
                "cell_id": "cell0",
                "host": "cell0.nhp.layerv.xyz",
                "port": 443,
                "server_public_key_b64": CELL0_KEY,
            },
            {
                "cell_id": "cell1",
                "host": "cell1.nhp.layerv.xyz",
                "port": 443,
                "server_public_key_b64": CELL1_KEY,
            },
        ],
    }
    # Candidates are main, always. The fixture used to name two feature branches
    # and their pull request numbers, which is the state the proof was rebuilt to
    # make unrepresentable.
    candidates = {
        "qurl_connector": {
            "repository": "layervai/qurl-connector",
            "head_ref": "main",
            "head_sha": CONNECTOR_SHA,
        },
        "qurl_go": {
            "repository": "layervai/qurl-go",
            "head_ref": "main",
            "head_sha": QURL_GO_SHA,
        },
    }
    repository_evidence = {}
    for key, repository in contract.REPOSITORIES.items():
        if key in contract.DEFAULT_BRANCH_REPOSITORIES:
            source, ref = "default_branch", "refs/heads/main"
        elif key in {"qurl_connector", "qurl_go"}:
            source = "candidate"
            ref = f"refs/heads/{candidates[key]['head_ref']}"
        elif key == "frp":
            source, ref = "canary_module", "refs/tags/v0.70.0-layerv.3"
        else:
            source, ref = "deployed_runtime", "deployed-runtime"
        repository_evidence[key] = {
            "repository": repository,
            "source": source,
            "ref": ref,
            "sha": repositories[key],
        }
    public_identities = {
        "hub": {
            "host": manifest["hub"]["host"],
            "port": 443,
            "public_key_parameter_name": (
                "/sandbox/nhp/control/hub/identity/public-key"
            ),
            "public_key_parameter_version": 1,
            "server_public_key_sha256": manifest["hub"]["server_public_key_sha256"],
            **edge_identity("layerv-nhp-sandbox-hub-edge", "10.102.1.25"),
        },
        "cells": [
            {
                "cell_id": cell_id,
                "catalog_table": ("layerv-nhp-sandbox-control-connector-authority"),
                "pk": "REGISTRY",
                "sk": f"CELL#{cell_id}",
                "status": "active",
                "endpoint_revision": 1,
                "selection_weight": "1",
                "updated_at": "2026-07-25T00:00:00Z",
                "host": manifest["cells"][index]["host"],
                "port": 443,
                "server_public_key_sha256": manifest["cells"][index][
                    "server_public_key_sha256"
                ],
                **edge_identity(
                    (
                        "layerv-nhp-sandbox-edge"
                        if cell_id == "cell0"
                        else "layerv-nhp-sandbox-cell1-edge"
                    ),
                    (
                        "i-00000000000000001"
                        if cell_id == "cell0"
                        else "i-00000000000000002"
                    ),
                ),
            }
            for index, cell_id in enumerate(("cell0", "cell1"))
        ],
    }
    canary = {
        "repository": "layervai/qurl-connector",
        "workflow_path": ".github/workflows/connector-canary-publish.yml",
        "run_id": 12345,
        "run_attempt": 1,
        "head_sha": "f" * 40,
        "artifact_id": 67890,
        "artifact_name": f"connector-canary-main-{CONNECTOR_SHA}",
        "artifact_digest": digest("a"),
        "image_ref": (
            f"ghcr.io/layervai/qurl-connector-canary@{IMAGE_DIGESTS['qurl_connector']}"
        ),
        "image_digest": IMAGE_DIGESTS["qurl_connector"],
        "provenance_sha256": "b" * 64,
        "frp_sha": FRP_SHA,
        "qurl_go_sha": QURL_GO_SHA,
    }
    workloads = {
        "nhp_cell0": {
            "kind": "ec2_attestation_set",
            "autoscaling_group": "layerv-nhp-sandbox-server",
            "in_service_instance_ids": ["i-00000000000000001"],
            "attestations": [
                attestation(
                    component="nhp_cell0",
                    instance_id="i-00000000000000001",
                    role_id="AROA00000000000000001",
                    image_repository="layerv/nhp-server",
                    image_digest=IMAGE_DIGESTS["nhp_cell0"],
                    source_revision=NHP_SHA,
                )
            ],
            "image_repository": "layerv/nhp-server",
            "image_digest": IMAGE_DIGESTS["nhp_cell0"],
            "source_revision": NHP_SHA,
            "source_evidence": source_evidence("nhp_cell0"),
        },
        "nhp_cell1": {
            "kind": "ec2_attestation_set",
            "autoscaling_group": "layerv-nhp-sandbox-cell1-server",
            "in_service_instance_ids": ["i-00000000000000002"],
            "attestations": [
                attestation(
                    component="nhp_cell1",
                    instance_id="i-00000000000000002",
                    role_id="AROA00000000000000002",
                    image_repository="layerv/nhp-server",
                    image_digest=IMAGE_DIGESTS["nhp_cell1"],
                    source_revision=NHP_SHA,
                )
            ],
            "image_repository": "layerv/nhp-server",
            "image_digest": IMAGE_DIGESTS["nhp_cell1"],
            "source_revision": NHP_SHA,
            "source_evidence": source_evidence("nhp_cell1"),
        },
        "nhp_hub": {
            "kind": "ecs",
            "cluster_arn": (
                "arn:aws:ecs:us-east-2:767397897469:"
                "cluster/layerv-nhp-sandbox-control-hub"
            ),
            "service_arn": (
                "arn:aws:ecs:us-east-2:767397897469:"
                "service/layerv-nhp-sandbox-control-hub/"
                "layerv-nhp-sandbox-control-hub"
            ),
            "task_definition_arn": (
                "arn:aws:ecs:us-east-2:767397897469:"
                "task-definition/layerv-nhp-sandbox-control-hub:1"
            ),
            "tasks": [
                {
                    "task_arn": (
                        "arn:aws:ecs:us-east-2:767397897469:"
                        "task/layerv-nhp-sandbox-control-hub/"
                        "00000000000000000000000000000001"
                    ),
                    "container_name": "hub",
                    "image_digest": IMAGE_DIGESTS["nhp_hub"],
                    "private_ipv4_addresses": ["10.102.1.25"],
                }
            ],
            "image_repository": "layerv/nhp-hub",
            "image_digest": IMAGE_DIGESTS["nhp_hub"],
            "source_revision": NHP_SHA,
            "source_evidence": source_evidence("nhp_hub"),
        },
        "qurl_connector": {
            "kind": "connector_canary",
            "image_digest": IMAGE_DIGESTS["qurl_connector"],
            "source_revision": CONNECTOR_SHA,
            "canary_artifact_digest": canary["artifact_digest"],
        },
        "qurl_reverse_tunnel_server": {
            "kind": "ec2_attestation_set",
            "autoscaling_group": "layerv-nhp-sandbox-frps",
            "in_service_instance_ids": ["i-00000000000000003"],
            "attestations": [
                attestation(
                    component="qurl_reverse_tunnel_server",
                    instance_id="i-00000000000000003",
                    role_id="AROA00000000000000003",
                    image_repository="layerv/qurl-reverse-tunnel-server",
                    image_digest=IMAGE_DIGESTS["qurl_reverse_tunnel_server"],
                    source_revision=QRTS_SHA,
                )
            ],
            "image_repository": "layerv/qurl-reverse-tunnel-server",
            "image_digest": IMAGE_DIGESTS["qurl_reverse_tunnel_server"],
            "source_revision": QRTS_SHA,
            "source_evidence": source_evidence("qurl_reverse_tunnel_server"),
        },
        "qurl_service_authority": {
            "kind": "lambda_image_set",
            "proof_policy_consumers_active": True,
            "functions": [
                {
                    "alias_arn": (
                        "arn:aws:lambda:us-east-2:767397897469:"
                        "function:layerv-nhp-sandbox-ca-ia:blue"
                    ),
                    "version_arn": (
                        "arn:aws:lambda:us-east-2:767397897469:"
                        "function:layerv-nhp-sandbox-ca-ia:1"
                    ),
                },
                {
                    "alias_arn": (
                        "arn:aws:lambda:us-east-2:767397897469:"
                        "function:layerv-nhp-sandbox-ca-pcr:blue"
                    ),
                    "version_arn": (
                        "arn:aws:lambda:us-east-2:767397897469:"
                        "function:layerv-nhp-sandbox-ca-pcr:2"
                    ),
                }
            ],
            "image_repository": "layerv/qurl-connector-authority",
            "image_digest": IMAGE_DIGESTS["qurl_service_authority"],
            "source_revision": QURL_SERVICE_SHA,
            "source_evidence": source_evidence("qurl_service_authority"),
        },
    }
    for cell_id in ("cell0", "cell1"):
        key = f"qurl_service_{cell_id}"
        workloads[key] = {
            "kind": "ecs",
            "cluster_arn": (
                f"arn:aws:ecs:us-east-2:767397897469:cluster/qurl-{cell_id}"
            ),
            "service_arn": (
                f"arn:aws:ecs:us-east-2:767397897469:service/qurl-{cell_id}/qurl"
            ),
            "task_definition_arn": (
                f"arn:aws:ecs:us-east-2:767397897469:task-definition/qurl-{cell_id}:1"
            ),
            "tasks": [
                {
                    "task_arn": (
                        "arn:aws:ecs:us-east-2:767397897469:"
                        f"task/qurl-{cell_id}/0000000000000000000000000000000"
                        f"{1 if cell_id == 'cell0' else 2}"
                    ),
                    "container_name": "qurl-api",
                    "image_digest": IMAGE_DIGESTS[key],
                    "private_ipv4_addresses": [
                        "10.102.1.26" if cell_id == "cell0" else "10.103.1.26"
                    ],
                }
            ],
            "image_repository": "layerv/nhp-qurl",
            "image_digest": IMAGE_DIGESTS[key],
            "source_revision": QURL_SERVICE_SHA,
            "source_evidence": source_evidence(key),
        }

    manifest_raw = contract.canonical_bytes(
        manifest,
        maximum=contract.MAX_MANIFEST_BYTES,
        name="deployment-manifest.json",
    )
    runtime_raw = contract.canonical_bytes(
        runtime,
        maximum=contract.MAX_RUNTIME_BYTES,
        name="deployment-runtime-inputs.json",
    )
    provenance = {
        "schema_version": 1,
        "producer": {
            "repository": "layervai/nhp",
            "workflow_path": (".github/workflows/udp-proof-deployment-manifest.yml"),
            "run_id": 999,
            "run_attempt": 1,
            "head_sha": PRODUCER_SHA,
        },
        "candidates": candidates,
        "files": {
            "deployment-manifest.json": (
                f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}"
            ),
            "deployment-runtime-inputs.json": (
                f"sha256:{hashlib.sha256(runtime_raw).hexdigest()}"
            ),
        },
        "evidence": {
            "observed_at": OBSERVED_AT,
            "aws": {
                "account_id": "767397897469",
                "region": "us-east-2",
                "proof_source": {
                    "name": "layerv-nhp-sandbox-udp-proof-source",
                    "allocation_id": "eipalloc-00000000000000001",
                    "public_ip": "3.141.109.76",
                    "cidr": "3.141.109.76/32",
                },
                "runtime_attestation": {
                    "bucket_parameter_name": (
                        "/sandbox/nhp/udp-proof/runtime-attestation-bucket-arn"
                    ),
                    "bucket_parameter_version": 4,
                    "bucket_arn": (
                        "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestation"
                    ),
                    "kms_key_arn": (
                        "arn:aws:kms:us-east-2:767397897469:key/"
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    ),
                    "bucket_policy_sha256": "9" * 64,
                    "collector_contract": collector_contract,
                },
            },
            "repositories": repository_evidence,
            "public_identities": public_identities,
            "connector_canary": canary,
            "workloads": workloads,
        },
    }
    return {"manifest": manifest, "runtime": runtime, "provenance": provenance}


class ContractTest(unittest.TestCase):
    def test_canonical_loader_rejects_overflow_float(self) -> None:
        with self.assertRaisesRegex(contract.ContractError, "non-finite JSON number"):
            contract.parse_canonical_bytes(
                b'{"value":1e999}',
                maximum=1024,
                name="overflow fixture",
            )

    def validate(self, snapshot: dict[str, object]) -> tuple[bytes, bytes, bytes]:
        return contract.validate_triplet(
            snapshot["manifest"],
            snapshot["runtime"],
            snapshot["provenance"],
            proof_phase="pre_removal",
            producer_run_id=999,
            producer_run_attempt=1,
            producer_head_sha=PRODUCER_SHA,
            validation_time=datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc),
        )

    def test_valid_triplet_is_canonical_and_producer_head_is_independent(self) -> None:
        snapshot = valid_snapshot()
        manifest_raw, runtime_raw, provenance_raw = self.validate(snapshot)
        self.assertNotEqual(PRODUCER_SHA, NHP_SHA)
        for raw in (manifest_raw, runtime_raw, provenance_raw):
            self.assertNotIn(b"\n", raw)
            self.assertEqual(
                raw,
                json.dumps(
                    json.loads(raw),
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii"),
            )

    def test_accepts_distinct_deployed_revisions_contained_in_main(self) -> None:
        snapshot = valid_snapshot()
        workloads = snapshot["provenance"]["evidence"]["workloads"]
        nhp_hub_revision = "8" * 40
        workloads["nhp_hub"]["source_revision"] = nhp_hub_revision
        workloads["nhp_hub"]["source_evidence"][
            "revision_label"
        ] = nhp_hub_revision
        authority_revision = "9" * 40
        workloads["qurl_service_authority"][
            "source_revision"
        ] = authority_revision
        workloads["qurl_service_authority"]["source_evidence"][
            "revision_label"
        ] = authority_revision

        self.validate(snapshot)

    def test_rejects_unknown_influence_bearing_key(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["surprise"] = True
        with self.assertRaisesRegex(contract.ContractError, "exactly"):
            self.validate(snapshot)

    def test_rejects_inactive_cell(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["public_identities"]["cells"][1][
            "status"
        ] = "disabled"
        with self.assertRaisesRegex(contract.ContractError, "catalog evidence"):
            self.validate(snapshot)

    def test_rejects_legacy_or_unfenced_public_edge_identity(self) -> None:
        snapshot = valid_snapshot()
        hub = snapshot["provenance"]["evidence"]["public_identities"]["hub"]
        hub["load_balancer_name"] = "layerv-nhp-sandbox-control-hub"
        with self.assertRaisesRegex(contract.ContractError, "protected sandbox edge"):
            self.validate(snapshot)

        for field, value in (
            ("proof_source_cidr", "0.0.0.0/0"),
            (
                "load_balancer_security_group_name",
                "layerv-nhp-sandbox-control-other",
            ),
            ("backend_security_group_id", "sg-00000000000000001"),
            ("backend_udp_cidrs", ["0.0.0.0/0"]),
            ("backend_health_cidrs", ["0.0.0.0/0"]),
        ):
            with self.subTest(field=field):
                snapshot = valid_snapshot()
                snapshot["provenance"]["evidence"]["public_identities"]["hub"][
                    field
                ] = value
                with self.assertRaises(contract.ContractError):
                    self.validate(snapshot)

    def test_accepts_strict_multi_region_attestation_kms_key(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["aws"]["runtime_attestation"][
            "kms_key_arn"
        ] = (
            "arn:aws:kms:us-east-2:767397897469:key/"
            "mrk-0123456789abcdef0123456789abcdef"
        )
        self.validate(snapshot)

    def test_rejects_wrong_proof_source_eip(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["aws"]["proof_source"][
            "public_ip"
        ] = "198.51.100.7"
        with self.assertRaisesRegex(contract.ContractError, "proof source EIP"):
            self.validate(snapshot)

    def test_rejects_runtime_public_key_digest_drift(self) -> None:
        snapshot = valid_snapshot()
        snapshot["runtime"]["hub"]["server_public_key_b64"] = public_key(9)
        with self.assertRaisesRegex(contract.ContractError, "Runtime Hub|runtime Hub"):
            self.validate(snapshot)

    def test_rejects_stale_ec2_attestation(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["nhp_cell0"]["attestations"][0][
            "observed_at"
        ] = "2026-07-25T11:49:59Z"
        with self.assertRaisesRegex(contract.ContractError, "10 minute"):
            self.validate(snapshot)

    def test_rejects_self_asserted_collector_identity(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["nhp_cell0"]["attestations"][0][
            "collector_sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(
            contract.ContractError, "authoritative collector contract"
        ):
            self.validate(snapshot)

    def test_rejects_attestation_bucket_policy_drift(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["aws"]["runtime_attestation"][
            "bucket_policy_sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(contract.ContractError, "bucket policy differs"):
            self.validate(snapshot)

    def test_rejects_unsupported_qrts_s3_fallback(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["qurl_reverse_tunnel_server"][
            "attestations"
        ][0]["runtime"]["source_kind"] = "s3_fallback"
        with self.assertRaisesRegex(contract.ContractError, "S3 binary fallback"):
            self.validate(snapshot)

    def test_rejects_ecs_task_digest_drift(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["nhp_hub"]["tasks"][0][
            "image_digest"
        ] = digest("f")
        with self.assertRaisesRegex(contract.ContractError, "task image digest"):
            self.validate(snapshot)

    def test_rejects_hub_edge_target_task_drift(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["nhp_hub"]["tasks"][0][
            "private_ipv4_addresses"
        ] = ["10.102.1.99"]
        with self.assertRaisesRegex(contract.ContractError, "Hub public NLB targets"):
            self.validate(snapshot)

    def test_rejects_qurl_service_short_source_revision(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["evidence"]["workloads"]["qurl_service_cell0"][
            "source_evidence"
        ]["source_revision"] = "1286e42"
        with self.assertRaisesRegex(contract.ContractError, "40-character"):
            self.validate(snapshot)

    def test_rejects_candidate_head_drift(self) -> None:
        snapshot = valid_snapshot()
        snapshot["provenance"]["candidates"]["qurl_go"]["head_sha"] = "0" * 40
        with self.assertRaisesRegex(contract.ContractError, "candidate head SHA"):
            self.validate(snapshot)

    def test_rejects_ambiguous_lambda_pair_order(self) -> None:
        snapshot = valid_snapshot()
        functions = snapshot["provenance"]["evidence"]["workloads"][
            "qurl_service_authority"
        ]["functions"]
        functions.append(
            {
                "alias_arn": (
                    "arn:aws:lambda:us-east-2:767397897469:"
                    "function:layerv-nhp-sandbox-ca-ar-cell0:blue"
                ),
                "version_arn": (
                    "arn:aws:lambda:us-east-2:767397897469:"
                    "function:layerv-nhp-sandbox-ca-ar-cell0:1"
                ),
            }
        )
        with self.assertRaisesRegex(contract.ContractError, "sorted unique pairs"):
            self.validate(snapshot)

    def test_dispatch_revalidation_rejects_stale_complete_evidence(self) -> None:
        snapshot = valid_snapshot()
        with self.assertRaisesRegex(contract.ContractError, "10 minutes old"):
            contract.validate_triplet(
                snapshot["manifest"],
                snapshot["runtime"],
                snapshot["provenance"],
                proof_phase="pre_removal",
                producer_run_id=999,
                producer_run_attempt=1,
                producer_head_sha=PRODUCER_SHA,
                validation_time=datetime(2026, 7, 25, 12, 10, 1, tzinfo=timezone.utc),
            )

    def test_current_attempt_artifact_selection_tolerates_older_attempt(self) -> None:
        artifacts = [
            {
                "artifact_id": 100,
                "name": contract.producer_artifact_name(999, 1),
                "digest": digest("1"),
                "size_in_bytes": 100_000,
                "expired": False,
                "workflow_run_id": 999,
                "created_at": "2026-07-25T11:50:00Z",
            },
            {
                "artifact_id": 101,
                "name": contract.producer_artifact_name(999, 2),
                "digest": digest("2"),
                "size_in_bytes": 100_000,
                "expired": False,
                "workflow_run_id": 999,
                "created_at": "2026-07-25T12:00:00Z",
            },
        ]
        selected = contract.select_producer_artifact(
            artifacts,
            producer_run_id=999,
            producer_run_attempt=2,
            current_time=datetime(2026, 7, 25, 12, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(selected["artifact_id"], 101)

    def test_artifact_selection_rejects_oversized_current_attempt(self) -> None:
        artifact = {
            "artifact_id": 101,
            "name": contract.producer_artifact_name(999, 2),
            "digest": digest("2"),
            "size_in_bytes": contract.MAX_PRODUCER_ARTIFACT_BYTES + 1,
            "expired": False,
            "workflow_run_id": 999,
            "created_at": "2026-07-25T12:00:00Z",
        }
        with self.assertRaisesRegex(contract.ContractError, "bounded artifact size"):
            contract.select_producer_artifact(
                [artifact],
                producer_run_id=999,
                producer_run_attempt=2,
                current_time=datetime(2026, 7, 25, 12, 1, tzinfo=timezone.utc),
            )

    def test_authenticated_run_binds_workflow_code_not_deployed_nhp(self) -> None:
        run = {
            "repository": "layervai/nhp",
            "workflow_path": (".github/workflows/udp-proof-deployment-manifest.yml"),
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "run_id": 999,
            "run_attempt": 2,
            "head_branch": "main",
            "head_sha": PRODUCER_SHA,
        }
        self.assertEqual(
            contract.validate_authenticated_producer_run(
                run,
                producer_run_id=999,
                producer_run_attempt=2,
                producer_head_sha=PRODUCER_SHA,
            )["head_sha"],
            PRODUCER_SHA,
        )
        self.assertNotEqual(PRODUCER_SHA, NHP_SHA)


class ProducerTest(unittest.TestCase):
    def test_snapshot_loader_rejects_overflow_float(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot_path = Path(temporary) / "snapshot.json"
            snapshot_path.write_text(
                '{"manifest":{"value":1e999},"provenance":{},"runtime":{}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                contract.ContractError, "non-finite JSON number"
            ):
                producer._load_snapshot(snapshot_path)

    def test_render_writes_exact_three_regular_canonical_files(self) -> None:
        snapshot = valid_snapshot()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            output = root / "artifact"
            producer.render(
                snapshot_path,
                output,
                proof_phase="pre_removal",
                producer_run_id=999,
                producer_run_attempt=1,
                producer_head_sha=PRODUCER_SHA,
                validation_time=datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(
                {path.name for path in output.iterdir()}, producer.OUTPUT_FILES
            )
            # The renderer owns exactly the deployment triplet. Independent
            # collectors add the orchestrator evidence and retirement targets
            # before upload, so the loader is exercised only once all five
            # canonical files are present.
            with self.assertRaises(contract.ContractError):
                contract.load_triplet_directory(output)
            (output / contract.ORCHESTRATOR_EVIDENCE_FILE).write_bytes(b"{}")
            (output / contract.RETIREMENT_TARGETS_FILE).write_bytes(b"{}")
            loaded_manifest, loaded_runtime, loaded_provenance = (
                contract.load_triplet_directory(output)
            )
            self.assertEqual(loaded_manifest, snapshot["manifest"])
            self.assertEqual(loaded_runtime, snapshot["runtime"])
            self.assertEqual(loaded_provenance, snapshot["provenance"])
            for path in output.iterdir():
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                raw = path.read_bytes()
                self.assertEqual(
                    raw,
                    contract.canonical_bytes(
                        json.loads(raw),
                        maximum=max(
                            contract.MAX_MANIFEST_BYTES,
                            contract.MAX_RUNTIME_BYTES,
                            contract.MAX_PROVENANCE_BYTES,
                        ),
                        name=path.name,
                    ),
                )

    def test_render_rejects_nonempty_output_directory(self) -> None:
        snapshot = valid_snapshot()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            output = root / "artifact"
            output.mkdir()
            (output / "user-file").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(contract.ContractError, "must be empty"):
                producer.render(
                    snapshot_path,
                    output,
                    proof_phase="pre_removal",
                    producer_run_id=999,
                    producer_run_attempt=1,
                    producer_head_sha=PRODUCER_SHA,
                    validation_time=datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc),
                )


if __name__ == "__main__":
    unittest.main()
