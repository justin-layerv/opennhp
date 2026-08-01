#!/usr/bin/env python3
"""Pure schema contract for the NHP-side per-scenario proof evidence document.

`deployment-manifest.json` proves *what is deployed*.  This fourth artifact file
proves the orchestrator-owned scenario rows of qurl-go's pre-retirement
inventory -- the rows whose evidence is structurally impossible to produce from
the client, because it lives in NHP's own source, substrate, or authority plane.

Like `udp_proof_deployment_contract`, this module performs no GitHub or AWS I/O.
The trusted-main producer hydrates observations, builds the document below, and
uses this module to fail closed before publishing.  The proof controller imports
the same contract when it revalidates the downloaded producer artifact.

Fail-closed properties enforced here:

* `produced_rows` must equal both the sorted row keys and the frozen
  `PRODUCED_ROWS` tuple, so a producer that cannot observe one row fails the
  whole artifact instead of silently shipping a partial document.
* A row key must be an orchestrator-owned scenario id, and its `kind` must be
  the typed-evidence kind qurl-go's `typed_evidence_contract.json` requires for
  that id.
* The document is bound to one proof run: the producer run identity, the exact
  canonical digests of the sibling artifact files, the deployed source
  revisions those files pin, and a bounded `observed_at`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import udp_proof_deployment_contract as deployment


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "orchestrator-evidence.json"
MAX_ORCHESTRATOR_EVIDENCE_BYTES = 64 * 1024

# Closed map of every orchestrator-owned scenario in qurl-go's
# `pre_retirement_scenarios.json` to the single typed-evidence kind that
# `typed_evidence_contract.json` requires for it.  A row may only be emitted
# for a key in this map, and only under the kind recorded here.
ORCHESTRATOR_SCENARIO_KINDS = {
    "negative.wrong_caller": "rejection_observation",
    "negative.wrong_source": "rejection_observation",
    "orchestrator.dedicated_linux_fault_runner": "runner_attestation",
    "orchestrator.real_hub_authority_and_two_cells": "topology_observation",
    "retirement.generated_artifact_parity": "surface_inventory",
    "retirement.http_lifecycle_surface_state": "surface_inventory",
    "retirement.nhp_registrar_surface_state": "surface_inventory",
    "retirement.relay_rejects_native_lifecycle_messages": "surface_inventory",
    "retirement.terraform_saved_plan_and_live_state": "surface_inventory",
    "wire.registration_lst_lrt_reg_rak_completion": "wire_trace",
    "wire.session_knk_ack_ext_ack": "wire_trace",
}

# Exactly the rows this producer proves today.  Extending the producer means
# adding a key here *and* a validator in ROW_VALIDATORS; nothing else in the
# pipeline changes.
PRODUCED_ROWS = (
    "orchestrator.real_hub_authority_and_two_cells",
    "retirement.generated_artifact_parity",
    "retirement.nhp_registrar_surface_state",
    "retirement.terraform_saved_plan_and_live_state",
)

# `retired_lifecycle_surface.json` in layervai/qurl-go is the human-reviewed,
# digest-pinned contract both sides quote.  These are the two digests the
# reviewed Go literal and the qurl-go proof workflow independently pin: the
# canonical-JSON digest asserted by `reviewedRetiredLifecycleSurfaceSHA256` in
# `retired_lifecycle_surface_test.go`, and the raw-bytes digest the proof
# workflow computes with `sha256sum`.  Binding both means the producer and the
# client cannot be quoting different revisions of the surface contract.
RETIRED_SURFACE_PATH = "tests/e2e/nativeudp/retired_lifecycle_surface.json"
RETIRED_SURFACE_CANONICAL_SHA256 = (
    "3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c"
)
RETIRED_SURFACE_RAW_SHA256 = (
    "39fe3deb3c92c5506e8b101b843529099d67ab462d350168122d3732a8adf3eb"
)

# The NHP wire message types `retired_lifecycle_surface.json` retires, with the
# wire values it pins.  The producer re-derives these from the `iota` block of
# the deployed NHP source; this table is what it must match.
RETIRED_MESSAGE_TYPE_WIRE_VALUES = {
    "NHP_LST": 5,
    "NHP_LRT": 6,
    "NHP_OTP": 12,
    "NHP_REG": 13,
    "NHP_RAK": 14,
}
MESSAGE_TYPE_SOURCE_PATH = "nhp/core/packet.go"

# The internal HTTP operations qurl-go's surface contract retires.  NHP's legacy
# registrar (`endpoints/server/staticplugins/agent/registrar.go`) is the *client*
# of exactly these two operations, which is why NHP can attest their retirement
# and the client cannot.
RETIRED_INTERNAL_HTTP_OPERATIONS = (
    {"method": "POST", "path": "/internal/v1/agent/otp"},
    {"method": "POST", "path": "/internal/v1/agent/register"},
)

GENERATED_ARTIFACT_SURFACES = (
    (
        "connector_tarball",
        "qurl_connector",
        ".github/workflows/build-binaries.yml",
    ),
    (
        "distribution",
        "qurl_connector",
        ".github/workflows/docker-publish.yml",
    ),
    ("generated_config", "qurl_connector", "pkg/config/frpgen.go"),
    ("go", "qurl_go", RETIRED_SURFACE_PATH),
    ("integration_installer", "qurl_integrations", "scripts/install.sh"),
    ("mcp", "qurl_mcp", "api-spec/qurls.yaml"),
    ("python", "qurl_python", "src/layerv_qurl/client.py"),
    ("typescript", "qurl_typescript", "contract/openapi.snapshot.yaml"),
    ("website", "website", ".github/workflows/update-api-docs.yml"),
)
GENERATED_ARTIFACT_REPOSITORIES = dict(deployment.REPOSITORIES)
PUBLIC_HTTP_LIFECYCLE_PATHS = (
    "/v1/agent/bootstrap",
    "/v1/agent/registration-info",
    "/v1/agent/registration/complete",
)
ALL_RETIRED_EXPORT_MARKERS = (
    *PUBLIC_HTTP_LIFECYCLE_PATHS,
    *(operation["path"] for operation in RETIRED_INTERNAL_HTTP_OPERATIONS),
    "relayknock.Exchange",
    "relayknock.Send",
    "relayknock.TypeListRequest",
    "relayknock.TypeListResult",
    "relayknock.TypeOTP",
    "relayknock.TypeRegister",
    "relayknock.TypeRegisterAck",
)
# Reviewed semantic anchors for each artifact class. A blob must contain every
# stable anchor, plus every phase-specific anchor, before the producer may call
# it `matches_contract`. Post-removal additionally rejects every retired export
# marker (except the canonical Go contract, which intentionally preserves the
# reviewed retirement inventory).
GENERATED_ARTIFACT_SEMANTICS = {
    "connector_tarball": {
        "required": (
            "binary_name=qurl-connector",
            "archive_prefix=qurl-connector",
            "qurl-connector Release Binaries",
        ),
        "pre_removal_required": (),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "distribution": {
        "required": (
            "REGISTRY: ghcr.io",
            "IMAGE_NAME: layervai/qurl-connector",
            "docker/build-push-action",
        ),
        "pre_removal_required": (),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "generated_config": {
        "required": (
            "MetaQURLKnockToken",
            "GenerateFRPClientConfig",
            "MetaResourceID",
        ),
        "pre_removal_required": (),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "go": {
        "required": ('"gate": "udp_lifecycle_retirement"',),
        "pre_removal_required": PUBLIC_HTTP_LIFECYCLE_PATHS,
        "post_removal_forbidden": (),
    },
    "integration_installer": {
        "required": (
            'REPO="layervai/qurl-integrations"',
            'BINARY="qurl"',
            'ARCHIVE="qurl_${VERSION}_${OS}_${ARCH}.tar.gz"',
        ),
        "pre_removal_required": (),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "mcp": {
        "required": ("openapi: 3.0.3", "qurl:agent"),
        "pre_removal_required": ("/v1/agent/bootstrap",),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "python": {
        "required": ("class QURLClient:", "/v1/resources/{resource_id}/qurls"),
        "pre_removal_required": (),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "typescript": {
        "required": (
            "Minimal OpenAPI snapshot",
            "title: QURL API",
        ),
        "pre_removal_required": ("/v1/agent/bootstrap",),
        "post_removal_forbidden": ALL_RETIRED_EXPORT_MARKERS,
    },
    "website": {
        "required": (
            "repos/layervai/qurl-service/contents/api/openapi.yaml",
            "public/docs/qurls.yaml",
            "public/docs/qurls.json",
            "public/docs/qurls.md",
        ),
        "pre_removal_required": (),
        "post_removal_forbidden": (),
    },
}

# Exact logical Terraform resource addresses whose only purpose is the retired
# HTTP bootstrap/registration path.  The bootstrap ALB is represented by its
# module instance address so the proof covers the entire module, including
# newly added child resources, without maintaining a brittle child-resource
# allowlist.
TERRAFORM_RETIREMENT_RESOURCES = (
    "module.nhp.aws_cloudwatch_log_metric_filter.agent_otp_rate_limited",
    "module.nhp.aws_cloudwatch_log_metric_filter.agent_otp_send_failed",
    "module.nhp.aws_cloudwatch_log_metric_filter.agent_register_attempts_exceeded",
    "module.nhp.aws_cloudwatch_log_metric_filter.agent_register_credential_invalid",
    "module.nhp.aws_cloudwatch_log_metric_filter.agent_register_rate_limited",
    "module.nhp.aws_cloudwatch_log_metric_filter.bootstrap_rate_limited",
    "module.nhp.aws_cloudwatch_log_metric_filter.bootstrap_unauthorized",
    "module.nhp.aws_cloudwatch_metric_alarm.agent_otp_rate_limited_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.agent_otp_send_failed_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.agent_register_attempts_exceeded_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.agent_register_credential_invalid_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.agent_register_rate_limited_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.bootstrap_rate_limited_spike",
    "module.nhp.aws_cloudwatch_metric_alarm.bootstrap_unauthorized_spike",
    "module.nhp.aws_secretsmanager_secret.agent_otp_pepper",
    "module.nhp.module.bootstrap_alb[0]",
    "module.nhp.module.qurl_service[0].aws_iam_role_policy.task_agent_otp_ses",
    "module.nhp.module.qurl_service[0].terraform_data.qurl_bootstrap_chain_inputs",
    "module.nhp.terraform_data.agent_otp_pepper_seed",
    "module.nhp.terraform_data.agent_otp_preconditions",
    "module.nhp.terraform_data.agent_otp_registration_plugin_preconditions",
    "module.nhp.terraform_data.agent_registration_preconditions",
    "module.nhp.terraform_data.bootstrap_alb_dns_preconditions",
    "module.nhp.terraform_data.qurl_bootstrap_activation_preconditions",
    "module.nhp.terraform_data.qurl_bootstrap_chain_preconditions",
)
TERRAFORM_APPLY_RECEIPT_SCHEMA_VERSION = 1
TERRAFORM_APPLY_WORKFLOW_PATH = ".github/workflows/build-and-push.yml"
TERRAFORM_APPLY_RECEIPT_FILE = "udp-proof-terraform-apply-receipt.json"
TERRAFORM_APPLY_RECEIPT_ARTIFACT_PREFIX = "udp-proof-terraform-apply"

MAX_SURFACE_ENTRIES = 64
# `state` describes only whether the reviewed declaration exists in the deployed
# blob. Whether a still-deployed entry point can actually do lifecycle work is a
# separate axis (`dispatches_lifecycle_work`), decided by its fail-closed fence.
# There is deliberately no "compatibility_stub" state: no such stub exists yet,
# and admitting a state the observer cannot derive would let a row pass on a
# value nothing produces.
SURFACE_STATES = frozenset({"present", "absent"})
SURFACE_ROLES = frozenset({"legacy_registrar", "native_runtime"})


class OrchestratorContractError(deployment.ContractError):
    """One orchestrator evidence value violates the frozen contract."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OrchestratorContractError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA256_RE.fullmatch(value):
        raise OrchestratorContractError(f"{name} must be a lowercase SHA-256")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA_RE.fullmatch(value):
        raise OrchestratorContractError(f"{name} must be a lowercase commit SHA")
    return value


def _string(
    value: Any, name: str, *, maximum: int = deployment.MAX_LABEL_LENGTH
) -> str:
    try:
        return deployment._string(value, name, maximum=maximum)
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc


def _repository_path(value: Any, name: str) -> str:
    path = _string(value, name, maximum=512)
    if (
        path != path.strip()
        or path.startswith("/")
        or path.endswith("/")
        or ".." in path.split("/")
        or "//" in path
        or "\\" in path
    ):
        raise OrchestratorContractError(f"{name} must be a clean relative repo path")
    return path


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise OrchestratorContractError(f"{name} must be a JSON boolean")
    return value


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def _canonical_sha256(value: Any, name: str) -> str:
    return hashlib.sha256(
        deployment.canonical_bytes(
            value,
            maximum=deployment.MAX_PROVENANCE_BYTES,
            name=name,
        )
    ).hexdigest()


def _validate_topology_surface(
    value: Any,
    *,
    manifest: dict[str, Any],
    runtime: dict[str, Any],
    provenance: dict[str, Any],
    **_: Any,
) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "kind",
            "manifest_topology_sha256",
            "runtime_topology_sha256",
            "public_identities_sha256",
            "workload_observations_sha256",
            "hub",
            "cells",
            "authority",
        },
        "orchestrator topology row",
    )
    if (
        row["kind"]
        != ORCHESTRATOR_SCENARIO_KINDS["orchestrator.real_hub_authority_and_two_cells"]
    ):
        raise OrchestratorContractError("orchestrator topology row kind drift")

    expected_digests = {
        "manifest_topology_sha256": _canonical_sha256(
            {"hub": manifest["hub"], "cells": manifest["cells"]},
            "manifest topology",
        ),
        "runtime_topology_sha256": _canonical_sha256(
            {"hub": runtime["hub"], "cells": runtime["cells"]},
            "runtime topology",
        ),
        "public_identities_sha256": _canonical_sha256(
            provenance["evidence"]["public_identities"],
            "public identities",
        ),
        "workload_observations_sha256": _canonical_sha256(
            provenance["evidence"]["workloads"],
            "workload observations",
        ),
    }
    for field, expected in expected_digests.items():
        if _sha256(row[field], f"orchestrator topology {field}") != expected:
            raise OrchestratorContractError(
                f"orchestrator topology {field} is not the authenticated "
                "deployment observation"
            )

    hub = _exact(
        row["hub"],
        {"host", "port", "server_public_key_sha256"},
        "orchestrator topology hub",
    )
    cells = row["cells"]
    if not isinstance(cells, list) or len(cells) != 2:
        raise OrchestratorContractError(
            "orchestrator topology cells must contain exactly cell0 and cell1"
        )
    try:
        deployment._endpoint(
            hub,
            "orchestrator topology hub",
            include_cell_id=False,
            include_public_key=False,
        )
        for index, cell in enumerate(cells):
            deployment._endpoint(
                cell,
                f"orchestrator topology cells[{index}]",
                include_cell_id=True,
                include_public_key=False,
            )
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    if hub != manifest["hub"] or cells != manifest["cells"]:
        raise OrchestratorContractError(
            "orchestrator topology endpoints differ from the deployment manifest"
        )
    if [cell["cell_id"] for cell in cells] != ["cell0", "cell1"]:
        raise OrchestratorContractError(
            "orchestrator topology cells must be ordered cell0, cell1"
        )
    endpoint_hosts = [hub["host"], *(cell["host"] for cell in cells)]
    endpoint_keys = [
        hub["server_public_key_sha256"],
        *(cell["server_public_key_sha256"] for cell in cells),
    ]
    if len(set(endpoint_hosts)) != 3 or len(set(endpoint_keys)) != 3:
        raise OrchestratorContractError(
            "Hub and both cells must have distinct hosts and server identities"
        )

    authority = _exact(
        row["authority"],
        {"source_sha", "image_digest", "proof_policy_consumers_active"},
        "orchestrator topology authority",
    )
    authority_observation = provenance["evidence"]["workloads"][
        "qurl_service_authority"
    ]
    if (
        _sha(authority["source_sha"], "orchestrator topology authority.source_sha")
        != authority_observation["source_revision"]
        or authority["image_digest"] != manifest["images"]["qurl_service_authority"]
        or authority["image_digest"] != authority_observation["image_digest"]
        or _bool(
            authority["proof_policy_consumers_active"],
            "orchestrator topology authority.proof_policy_consumers_active",
        )
        is not True
        or authority["proof_policy_consumers_active"]
        != authority_observation["proof_policy_consumers_active"]
    ):
        raise OrchestratorContractError(
            "orchestrator topology authority differs from the authenticated "
            "qurl-service authority deployment"
        )
    return row


def _validate_generated_artifact_parity(
    value: Any,
    *,
    proof_phase: str,
    qurl_go_source_sha: str,
    manifest: dict[str, Any],
    **_: Any,
) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "kind",
            "surface",
            "phase",
            "canonical_contract",
            "artifacts",
            "artifacts_sha256",
        },
        "generated artifact parity row",
    )
    if (
        row["kind"]
        != ORCHESTRATOR_SCENARIO_KINDS["retirement.generated_artifact_parity"]
        or row["surface"] != "generated_artifact_parity"
        or row["phase"] != proof_phase
    ):
        raise OrchestratorContractError(
            "generated artifact parity identity or phase drift"
        )
    contract = _exact(
        row["canonical_contract"],
        {
            "repository",
            "path",
            "source_sha",
            "raw_sha256",
            "canonical_sha256",
        },
        "generated artifact parity canonical_contract",
    )
    if contract != {
        "repository": "layervai/qurl-go",
        "path": RETIRED_SURFACE_PATH,
        "source_sha": qurl_go_source_sha,
        "raw_sha256": RETIRED_SURFACE_RAW_SHA256,
        "canonical_sha256": RETIRED_SURFACE_CANONICAL_SHA256,
    }:
        raise OrchestratorContractError(
            "generated artifact parity canonical contract drift"
        )

    artifacts = row["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(
        GENERATED_ARTIFACT_SURFACES
    ):
        raise OrchestratorContractError(
            "generated artifact parity must contain the exact reviewed surfaces"
        )
    normalized: list[dict[str, Any]] = []
    for index, expected in enumerate(GENERATED_ARTIFACT_SURFACES):
        surface, repository_key, path = expected
        artifact = _exact(
            artifacts[index],
            {
                "surface",
                "repository",
                "source_sha",
                "path",
                "path_sha256",
                "contract_sha256",
                "state",
            },
            f"generated artifact parity artifacts[{index}]",
        )
        expected_repository = GENERATED_ARTIFACT_REPOSITORIES[repository_key]
        _sha256(
            artifact["path_sha256"],
            f"generated artifact parity artifacts[{index}].path_sha256",
        )
        if (
            artifact["surface"] != surface
            or artifact["repository"] != expected_repository
            or _sha(
                artifact["source_sha"],
                f"generated artifact parity artifacts[{index}].source_sha",
            )
            != manifest["repositories"][repository_key]
            or artifact["path"] != path
            or _repository_path(
                artifact["path"],
                f"generated artifact parity artifacts[{index}].path",
            )
            != path
            or artifact["contract_sha256"] != RETIRED_SURFACE_CANONICAL_SHA256
            or artifact["state"] != "matches_contract"
        ):
            raise OrchestratorContractError(
                f"generated artifact parity artifacts[{index}] differs from "
                "the reviewed repository surface"
            )
        normalized.append(artifact)
    if _sha256(
        row["artifacts_sha256"],
        "generated artifact parity artifacts_sha256",
    ) != _canonical_sha256(normalized, "generated artifact parity artifacts"):
        raise OrchestratorContractError(
            "generated artifact parity artifacts_sha256 is wrong"
        )
    return row


def _validate_terraform_retirement(
    value: Any,
    *,
    proof_phase: str,
    **_: Any,
) -> dict[str, Any]:
    row = _exact(
        value,
        {"kind", "surface", "phase", "state", "plan", "row_sha256"},
        "Terraform retirement row",
    )
    if (
        row["kind"]
        != ORCHESTRATOR_SCENARIO_KINDS["retirement.terraform_saved_plan_and_live_state"]
        or row["surface"] != "terraform_retirement"
        or row["phase"] != proof_phase
    ):
        raise OrchestratorContractError("Terraform retirement identity or phase drift")
    state = _exact(
        row["state"],
        {"lineage", "serial", "observation_sha256", "resources"},
        "Terraform retirement state",
    )
    lineage = _string(
        state["lineage"], "Terraform retirement state.lineage", maximum=128
    )
    if lineage != lineage.strip():
        raise OrchestratorContractError(
            "Terraform retirement state.lineage must be trimmed"
        )
    try:
        deployment._positive_int(state["serial"], "Terraform retirement state.serial")
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    resources = state["resources"]
    if not isinstance(resources, list) or len(resources) != len(
        TERRAFORM_RETIREMENT_RESOURCES
    ):
        raise OrchestratorContractError(
            "Terraform retirement state must cover the exact reviewed resources"
        )
    normalized_resources: list[dict[str, Any]] = []
    for index, expected_address in enumerate(TERRAFORM_RETIREMENT_RESOURCES):
        resource = _exact(
            resources[index],
            {"address", "state"},
            f"Terraform retirement resources[{index}]",
        )
        if resource["address"] != expected_address:
            raise OrchestratorContractError(
                f"Terraform retirement resources[{index}] address drift"
            )
        expected_state = "present" if proof_phase == "pre_removal" else "absent"
        if resource["state"] != expected_state:
            raise OrchestratorContractError(
                f"Terraform retirement resources[{index}] must be {expected_state}"
            )
        normalized_resources.append(resource)
    expected_observation_sha = _canonical_sha256(
        {
            "lineage": state["lineage"],
            "serial": state["serial"],
            "resources": normalized_resources,
        },
        "Terraform retirement state observation",
    )
    if (
        _sha256(
            state["observation_sha256"],
            "Terraform retirement state.observation_sha256",
        )
        != expected_observation_sha
    ):
        raise OrchestratorContractError(
            "Terraform retirement state observation digest is wrong"
        )

    plan = _exact(
        row["plan"],
        {"saved_plan_sha256", "apply_run_id", "approved_deletions"},
        "Terraform retirement plan",
    )
    if proof_phase == "pre_removal":
        if plan != {
            "saved_plan_sha256": None,
            "apply_run_id": None,
            "approved_deletions": [],
        }:
            raise OrchestratorContractError(
                "pre-removal Terraform evidence must not claim an applied plan"
            )
    else:
        _sha256(
            plan["saved_plan_sha256"],
            "Terraform retirement plan.saved_plan_sha256",
        )
        try:
            deployment._positive_int(
                plan["apply_run_id"], "Terraform retirement plan.apply_run_id"
            )
        except deployment.ContractError as exc:
            raise OrchestratorContractError(str(exc)) from exc
        if plan["approved_deletions"] != list(TERRAFORM_RETIREMENT_RESOURCES):
            raise OrchestratorContractError(
                "post-removal Terraform evidence must bind the exact approved "
                "deletion set"
            )

    expected_row_sha = _canonical_sha256(
        {key: row[key] for key in ("kind", "surface", "phase", "state", "plan")},
        "Terraform retirement row",
    )
    if (
        _sha256(row["row_sha256"], "Terraform retirement row_sha256")
        != expected_row_sha
    ):
        raise OrchestratorContractError("Terraform retirement row_sha256 is wrong")
    return row


def validate_terraform_apply_receipt(
    value: Any,
    *,
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "schema_version",
            "gate",
            "phase",
            "producer",
            "saved_plan_sha256",
            "approved_deletions",
        },
        "Terraform retirement apply receipt",
    )
    if (
        receipt["schema_version"] != TERRAFORM_APPLY_RECEIPT_SCHEMA_VERSION
        or type(receipt["schema_version"]) is not int
        or receipt["gate"] != GATE
        or receipt["phase"] != "post_removal"
    ):
        raise OrchestratorContractError(
            "Terraform retirement apply receipt identity drift"
        )
    producer = _exact(
        receipt["producer"],
        {"repository", "workflow_path", "run_id", "run_attempt", "head_sha"},
        "Terraform retirement apply receipt producer",
    )
    if producer != {
        "repository": "layervai/nhp",
        "workflow_path": TERRAFORM_APPLY_WORKFLOW_PATH,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "head_sha": head_sha,
    }:
        raise OrchestratorContractError(
            "Terraform retirement apply receipt producer identity drift"
        )
    try:
        deployment._positive_int(run_id, "Terraform retirement apply run_id")
        deployment._positive_int(run_attempt, "Terraform retirement apply run_attempt")
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    _sha(head_sha, "Terraform retirement apply head_sha")
    _sha256(
        receipt["saved_plan_sha256"],
        "Terraform retirement apply saved_plan_sha256",
    )
    if receipt["approved_deletions"] != list(TERRAFORM_RETIREMENT_RESOURCES):
        raise OrchestratorContractError(
            "Terraform retirement apply receipt deletion set drift"
        )
    return receipt


def _validate_interface(
    entry: Any,
    name: str,
    *,
    proof_phase: str,
) -> dict[str, Any]:
    item = _exact(
        entry,
        {
            "symbol",
            "path",
            "path_sha256",
            "role",
            "state",
            "lifecycle_message_types",
            "dispatches_lifecycle_work",
        },
        name,
    )
    _string(item["symbol"], f"{name}.symbol")
    _repository_path(item["path"], f"{name}.path")
    role = item["role"]
    if role not in SURFACE_ROLES:
        raise OrchestratorContractError(f"{name}.role is not an allowed role")
    state = item["state"]
    if state not in SURFACE_STATES:
        raise OrchestratorContractError(f"{name}.state is not an allowed state")
    path_sha256 = item["path_sha256"]
    if path_sha256 is None:
        if role != "legacy_registrar" or state != "absent":
            raise OrchestratorContractError(
                f"{name}.path_sha256 may be null only for an absent legacy source"
            )
    else:
        _sha256(path_sha256, f"{name}.path_sha256")
    types = item["lifecycle_message_types"]
    if (
        not isinstance(types, list)
        or not types
        or types != sorted(types)
        or len(types) != len(set(types))
        or any(
            entry_type not in RETIRED_MESSAGE_TYPE_WIRE_VALUES for entry_type in types
        )
    ):
        raise OrchestratorContractError(
            f"{name}.lifecycle_message_types must be a sorted unique non-empty "
            "subset of the retired lifecycle message types"
        )
    dispatches = _bool(
        item["dispatches_lifecycle_work"], f"{name}.dispatches_lifecycle_work"
    )

    # Phase semantics, straight from the scenario requirement.
    #
    #   pre_removal  -- "the exact legacy NHP registrar/runtime interfaces
    #                    remain deployed but unused"
    #   post_removal -- "their implementation is absent and every required
    #                    compatibility stub fails closed without dispatching
    #                    lifecycle work"
    #
    # `native_runtime` entries are the direct-UDP lifecycle NHP keeps. They are
    # the control group: the row fails if they ever stop being present and
    # dispatching, so "the observer saw nothing" cannot pass the scenario.
    if role == "native_runtime":
        if state != "present" or not dispatches:
            raise OrchestratorContractError(
                f"{name} is the retained native runtime and must stay present "
                "and dispatching in both phases"
            )
        return item
    # A legacy entry point must never dispatch lifecycle work in either phase.
    # Before removal that is what "deployed but unused" means; after removal it
    # is what "every required compatibility stub fails closed" means.
    if dispatches:
        raise OrchestratorContractError(
            f"{name} legacy registrar still dispatches lifecycle work"
        )
    if proof_phase == "pre_removal":
        if state != "present":
            raise OrchestratorContractError(
                f"{name} legacy registrar must still be deployed in pre_removal"
            )
        return item
    if state != "absent":
        raise OrchestratorContractError(
            f"{name} legacy registrar implementation is still present in post_removal"
        )
    return item


def _validate_nhp_registrar_surface(
    value: Any,
    *,
    proof_phase: str,
    nhp_source_sha: str,
    **_: Any,
) -> dict[str, Any]:
    """Validate the deployed-NHP legacy registrar/runtime surface row.

    The row is derived from the exact NHP source revision the deployment
    manifest pins, which the deployment collector already cross-checked against
    the OCI revision labels of the running Hub and cell containers.  "Deployed"
    is therefore established by the manifest, not asserted here.
    """

    row = _exact(
        value,
        {
            "kind",
            "surface",
            "phase",
            "source_repository",
            "source_sha",
            "message_type_source_path",
            "message_type_source_sha256",
            "retired_message_type_wire_values",
            "retired_internal_http_operations",
            "interfaces",
            "interfaces_sha256",
        },
        "nhp registrar surface row",
    )
    expected_kind = ORCHESTRATOR_SCENARIO_KINDS[
        "retirement.nhp_registrar_surface_state"
    ]
    if row["kind"] != expected_kind:
        raise OrchestratorContractError("nhp registrar surface row kind drift")
    if row["surface"] != "nhp_registrar":
        raise OrchestratorContractError("nhp registrar surface row identity drift")
    if row["phase"] != proof_phase:
        raise OrchestratorContractError("nhp registrar surface row phase drift")
    if row["source_repository"] != "layervai/nhp":
        raise OrchestratorContractError("nhp registrar surface row repository drift")
    if _sha(row["source_sha"], "nhp registrar source_sha") != nhp_source_sha:
        raise OrchestratorContractError(
            "nhp registrar surface row is not the deployed NHP revision"
        )
    if row["message_type_source_path"] != MESSAGE_TYPE_SOURCE_PATH:
        raise OrchestratorContractError("nhp registrar message-type source drift")
    _sha256(
        row["message_type_source_sha256"],
        "nhp registrar message_type_source_sha256",
    )

    wire_values = _exact(
        row["retired_message_type_wire_values"],
        set(RETIRED_MESSAGE_TYPE_WIRE_VALUES),
        "nhp registrar retired_message_type_wire_values",
    )
    for message_type, expected in RETIRED_MESSAGE_TYPE_WIRE_VALUES.items():
        observed = wire_values[message_type]
        if type(observed) is not int or observed != expected:
            raise OrchestratorContractError(
                f"deployed NHP wire value for {message_type} differs from the "
                "reviewed retired lifecycle surface contract"
            )

    operations = row["retired_internal_http_operations"]
    if not isinstance(operations, list) or len(operations) != len(
        RETIRED_INTERNAL_HTTP_OPERATIONS
    ):
        raise OrchestratorContractError(
            "nhp registrar retired_internal_http_operations must list exactly "
            "the retired internal operations"
        )
    for index, operation in enumerate(operations):
        _exact(
            operation,
            {"method", "path"},
            f"nhp registrar retired_internal_http_operations[{index}]",
        )
        if operation != RETIRED_INTERNAL_HTTP_OPERATIONS[index]:
            raise OrchestratorContractError(
                f"nhp registrar retired internal HTTP operation drift at index {index}"
            )

    interfaces = row["interfaces"]
    if (
        not isinstance(interfaces, list)
        or not interfaces
        or len(interfaces) > MAX_SURFACE_ENTRIES
    ):
        raise OrchestratorContractError(
            f"nhp registrar interfaces must be a 1..{MAX_SURFACE_ENTRIES} list"
        )
    seen: set[tuple[str, str]] = set()
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(interfaces):
        item = _validate_interface(
            entry,
            f"nhp registrar interfaces[{index}]",
            proof_phase=proof_phase,
        )
        identity = (item["path"], item["symbol"])
        if identity in seen:
            raise OrchestratorContractError(
                f"nhp registrar interfaces[{index}] duplicates an earlier entry"
            )
        seen.add(identity)
        normalized.append(item)

    roles = {item["role"] for item in normalized}
    if roles != SURFACE_ROLES:
        raise OrchestratorContractError(
            "nhp registrar interfaces must cover both the legacy registrar and "
            "the retained native runtime"
        )
    for role in sorted(SURFACE_ROLES):
        covered = {
            message_type
            for item in normalized
            if item["role"] == role
            for message_type in item["lifecycle_message_types"]
        }
        if covered != set(RETIRED_MESSAGE_TYPE_WIRE_VALUES):
            raise OrchestratorContractError(
                f"nhp registrar {role} interfaces must cover every retired "
                "lifecycle message type"
            )

    expected_digest = hashlib.sha256(
        deployment.canonical_bytes(
            normalized,
            maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name="nhp registrar interfaces",
        )
    ).hexdigest()
    observed_digest = _sha256(
        row["interfaces_sha256"], "nhp registrar interfaces_sha256"
    )
    if observed_digest != expected_digest:
        raise OrchestratorContractError("nhp registrar interfaces_sha256 is wrong")
    return row


ROW_VALIDATORS = {
    "orchestrator.real_hub_authority_and_two_cells": _validate_topology_surface,
    "retirement.generated_artifact_parity": _validate_generated_artifact_parity,
    "retirement.nhp_registrar_surface_state": _validate_nhp_registrar_surface,
    "retirement.terraform_saved_plan_and_live_state": _validate_terraform_retirement,
}


def validate_orchestrator_evidence(
    value: Any,
    *,
    manifest: dict[str, Any],
    runtime: dict[str, Any],
    provenance: dict[str, Any],
    manifest_bytes: bytes,
    runtime_bytes: bytes,
    provenance_bytes: bytes,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> dict[str, Any]:
    """Validate the orchestrator evidence document against one proof run."""

    if proof_phase not in {"pre_removal", "post_removal"}:
        raise OrchestratorContractError(
            "proof_phase must be pre_removal or post_removal"
        )

    document = _exact(
        value,
        {
            "schema_version",
            "gate",
            "phase",
            "observed_at",
            "producer",
            "bindings",
            "produced_rows",
            "rows",
        },
        "orchestrator evidence",
    )
    version = document["schema_version"]
    if version != SCHEMA_VERSION or type(version) is not int:
        raise OrchestratorContractError(
            "orchestrator evidence schema_version must be 1"
        )
    if document["gate"] != GATE:
        raise OrchestratorContractError("orchestrator evidence gate drift")
    if document["phase"] != proof_phase:
        raise OrchestratorContractError(
            "orchestrator evidence phase differs from the proof phase"
        )

    try:
        observed_at = deployment._timestamp(
            document["observed_at"], "orchestrator evidence observed_at"
        )
        validated_at = deployment._utc_time(
            validation_time, "orchestrator evidence validation_time"
        )
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    if (
        observed_at > validated_at + deployment.MAX_CLOCK_SKEW
        or validated_at - observed_at > deployment.MAX_PROVENANCE_AGE
    ):
        raise OrchestratorContractError(
            "orchestrator evidence must be no more than 10 minutes old"
        )

    producer = _exact(
        document["producer"],
        {"repository", "workflow_path", "run_id", "run_attempt", "head_sha"},
        "orchestrator evidence producer",
    )
    if producer != {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "run_id": producer_run_id,
        "run_attempt": producer_run_attempt,
        "head_sha": producer_head_sha,
    }:
        raise OrchestratorContractError("orchestrator evidence producer identity drift")
    try:
        deployment._positive_int(producer_run_id, "producer run_id")
        deployment._positive_int(producer_run_attempt, "producer run_attempt")
        deployment._sha(producer_head_sha, "producer head_sha")
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc

    bindings = _exact(
        document["bindings"],
        {
            "deployment_manifest_sha256",
            "deployment_runtime_inputs_sha256",
            "deployment_provenance_sha256",
            "nhp_source_sha",
            "qurl_go_source_sha",
            "retired_lifecycle_surface_path",
            "retired_lifecycle_surface_raw_sha256",
            "retired_lifecycle_surface_canonical_sha256",
        },
        "orchestrator evidence bindings",
    )
    if (
        _sha256(
            bindings["deployment_manifest_sha256"],
            "bindings.deployment_manifest_sha256",
        )
        != hashlib.sha256(manifest_bytes).hexdigest()
        or _sha256(
            bindings["deployment_runtime_inputs_sha256"],
            "bindings.deployment_runtime_inputs_sha256",
        )
        != hashlib.sha256(runtime_bytes).hexdigest()
        or _sha256(
            bindings["deployment_provenance_sha256"],
            "bindings.deployment_provenance_sha256",
        )
        != hashlib.sha256(provenance_bytes).hexdigest()
    ):
        raise OrchestratorContractError(
            "orchestrator evidence is not bound to this artifact's manifest files"
        )
    repositories = manifest.get("repositories")
    if not isinstance(repositories, dict):
        raise OrchestratorContractError("deployment manifest has no repository pins")
    nhp_source_sha = _sha(bindings["nhp_source_sha"], "bindings.nhp_source_sha")
    if nhp_source_sha != repositories.get("nhp"):
        raise OrchestratorContractError(
            "orchestrator evidence NHP revision differs from the deployment manifest"
        )
    if _sha(
        bindings["qurl_go_source_sha"], "bindings.qurl_go_source_sha"
    ) != repositories.get("qurl_go"):
        raise OrchestratorContractError(
            "orchestrator evidence qurl-go revision differs from the deployment "
            "manifest"
        )
    if (
        bindings["retired_lifecycle_surface_path"] != RETIRED_SURFACE_PATH
        or _sha256(
            bindings["retired_lifecycle_surface_raw_sha256"],
            "bindings.retired_lifecycle_surface_raw_sha256",
        )
        != RETIRED_SURFACE_RAW_SHA256
        or _sha256(
            bindings["retired_lifecycle_surface_canonical_sha256"],
            "bindings.retired_lifecycle_surface_canonical_sha256",
        )
        != RETIRED_SURFACE_CANONICAL_SHA256
    ):
        raise OrchestratorContractError(
            "orchestrator evidence is not bound to the reviewed retired "
            "lifecycle surface contract"
        )

    rows = document["rows"]
    if not isinstance(rows, dict) or not rows:
        raise OrchestratorContractError(
            "orchestrator evidence rows must be a non-empty object"
        )
    produced = document["produced_rows"]
    if (
        not isinstance(produced, list)
        or produced != sorted(rows)
        or tuple(produced) != tuple(sorted(PRODUCED_ROWS))
    ):
        raise OrchestratorContractError(
            "orchestrator evidence must produce exactly the frozen row set "
            f"{sorted(PRODUCED_ROWS)}"
        )
    for scenario_id in produced:
        if scenario_id not in ORCHESTRATOR_SCENARIO_KINDS:
            raise OrchestratorContractError(
                f"{scenario_id} is not an orchestrator-owned scenario"
            )
        validator = ROW_VALIDATORS.get(scenario_id)
        if validator is None:
            raise OrchestratorContractError(f"{scenario_id} has no row validator")
        rows[scenario_id] = validator(
            rows[scenario_id],
            proof_phase=proof_phase,
            nhp_source_sha=nhp_source_sha,
            qurl_go_source_sha=bindings["qurl_go_source_sha"],
            manifest=manifest,
            runtime=runtime,
            provenance=provenance,
        )
    return document


def validate_orchestrator_bytes(
    raw: bytes,
    *,
    manifest: dict[str, Any],
    runtime: dict[str, Any],
    provenance: dict[str, Any],
    manifest_bytes: bytes,
    runtime_bytes: bytes,
    provenance_bytes: bytes,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> dict[str, Any]:
    """Parse canonical bytes then validate them, for the controller side."""

    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    return validate_orchestrator_evidence(
        value,
        manifest=manifest,
        runtime=runtime,
        provenance=provenance,
        manifest_bytes=manifest_bytes,
        runtime_bytes=runtime_bytes,
        provenance_bytes=provenance_bytes,
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=validation_time,
    )
