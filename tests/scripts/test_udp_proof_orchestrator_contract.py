#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
TESTS = ROOT / "tests" / "scripts"
TESTDATA = TESTS / "testdata"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import collect_udp_proof_orchestrator_evidence as collector  # noqa: E402
import test_udp_proof_deployment_contract as deployment_fixture  # noqa: E402
import udp_proof_deployment_contract as deployment  # noqa: E402
import udp_proof_orchestrator_contract as orchestrator  # noqa: E402


RUN_ID = 999
RUN_ATTEMPT = 1
HEAD_SHA = deployment_fixture.PRODUCER_SHA
VALIDATION_TIME = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
RETIRED_SURFACE_FIXTURE = TESTDATA / "retired_lifecycle_surface.json"


def local_blob_reader(surface_bytes: bytes | None = None):
    """Return a `read_blob` stand-in that serves the working tree."""

    surface = (
        surface_bytes
        if surface_bytes is not None
        else RETIRED_SURFACE_FIXTURE.read_bytes()
    )

    def read_blob(repository: str, path: str, ref: str) -> bytes:
        deployment._sha(ref, "ref")
        if repository == collector.QURL_GO_REPOSITORY:
            if path != orchestrator.RETIRED_SURFACE_PATH:
                raise collector.OrchestratorEvidenceError(f"unexpected path {path}")
            return surface
        if repository == collector.NHP_REPOSITORY:
            return (ROOT / path).read_bytes()
        expected = {
            (
                orchestrator.GENERATED_ARTIFACT_REPOSITORIES[repository_key],
                artifact_path,
            ): surface_name
            for surface_name, repository_key, artifact_path in (
                orchestrator.GENERATED_ARTIFACT_SURFACES
            )
        }
        surface_name = expected.get((repository, path))
        if surface_name is None:
            raise collector.OrchestratorEvidenceError(
                f"unexpected generated artifact {repository}/{path}"
            )
        semantics = orchestrator.GENERATED_ARTIFACT_SEMANTICS[surface_name]
        markers = [
            *semantics["required"],
            *semantics["pre_removal_required"],
        ]
        return ("\n".join(markers) + "\n").encode()

    return read_blob


def local_terraform_state() -> dict[str, object]:
    resources = []
    for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES:
        if address == "module.nhp.module.bootstrap_alb[0]":
            resources.append(
                {
                    "module": address,
                    "type": "aws_lb",
                    "name": "this",
                }
            )
            continue
        module, resource_type, name = address.rsplit(".", 2)
        resources.append(
            {
                "module": module,
                "type": resource_type,
                "name": name,
            }
        )
    return {
        "version": 4,
        "lineage": "dd031dd9-540a-3083-00a5-730b0e3b2bb0",
        "serial": 3280,
        "resources": resources,
    }


def build_document(
    *,
    proof_phase: str = "pre_removal",
    read_blob_fn=None,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    bytes,
    bytes,
    bytes,
]:
    """Run the real producer against the working tree and return its output."""

    snapshot = deployment_fixture.valid_snapshot()
    if proof_phase == "post_removal":
        snapshot["manifest"]["phase"] = "post_removal"
        snapshot["manifest"]["retirement_state"] = "http_lifecycle_removed"
        snapshot["provenance"]["files"] = {
            name: "sha256:"
            + hashlib.sha256(
                deployment.canonical_bytes(snapshot[key], maximum=maximum, name=name)
            ).hexdigest()
            for name, key, maximum in (
                (
                    "deployment-manifest.json",
                    "manifest",
                    deployment.MAX_MANIFEST_BYTES,
                ),
                (
                    "deployment-runtime-inputs.json",
                    "runtime",
                    deployment.MAX_RUNTIME_BYTES,
                ),
            )
        }
    manifest_bytes, runtime_bytes, provenance_bytes = deployment.validate_triplet(
        snapshot["manifest"],
        snapshot["runtime"],
        snapshot["provenance"],
        proof_phase=proof_phase,
        producer_run_id=RUN_ID,
        producer_run_attempt=RUN_ATTEMPT,
        producer_head_sha=HEAD_SHA,
        validation_time=VALIDATION_TIME,
    )
    with tempfile.TemporaryDirectory() as temporary:
        snapshot_path = Path(temporary) / "snapshot.json"
        snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
        raw = collector.build(
            snapshot_path,
            proof_phase=proof_phase,
            producer_run_id=RUN_ID,
            producer_run_attempt=RUN_ATTEMPT,
            producer_head_sha=HEAD_SHA,
            observed_at=VALIDATION_TIME,
            read_blob_fn=read_blob_fn or local_blob_reader(),
            read_terraform_state_fn=local_terraform_state,
        )
    return (
        json.loads(raw),
        snapshot["manifest"],
        snapshot["runtime"],
        snapshot["provenance"],
        manifest_bytes,
        runtime_bytes,
        provenance_bytes,
    )


class ReviewedContractLockstepTest(unittest.TestCase):
    """The frozen literals must still describe the real repository."""

    def test_retired_surface_fixture_matches_the_pinned_digests(self) -> None:
        raw = RETIRED_SURFACE_FIXTURE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            orchestrator.RETIRED_SURFACE_RAW_SHA256,
        )
        canonical = deployment.canonical_bytes(
            json.loads(raw),
            maximum=orchestrator.MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name="retired lifecycle surface",
        )
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            orchestrator.RETIRED_SURFACE_CANONICAL_SHA256,
        )

    def test_pinned_wire_values_match_the_vendored_surface_contract(self) -> None:
        surface = json.loads(RETIRED_SURFACE_FIXTURE.read_bytes())
        pinned = {
            alias["message_type"]: alias["wire_value"]
            for alias in surface["relay_message_type_aliases"]
        }
        self.assertEqual(pinned, orchestrator.RETIRED_MESSAGE_TYPE_WIRE_VALUES)

    def test_pinned_internal_operations_match_the_surface_contract(self) -> None:
        surface = json.loads(RETIRED_SURFACE_FIXTURE.read_bytes())
        observed = [
            {"method": operation["method"], "path": operation["path"]}
            for operation in surface["internal_http_operations"]
        ]
        self.assertEqual(
            observed, [dict(op) for op in orchestrator.RETIRED_INTERNAL_HTTP_OPERATIONS]
        )

    def test_live_packet_source_still_declares_the_pinned_wire_values(self) -> None:
        blob = (ROOT / orchestrator.MESSAGE_TYPE_SOURCE_PATH).read_bytes()
        wire_values = collector.parse_message_type_wire_values(blob)
        for (
            message_type,
            expected,
        ) in orchestrator.RETIRED_MESSAGE_TYPE_WIRE_VALUES.items():
            self.assertEqual(wire_values[message_type], expected, message_type)

    def test_every_reviewed_anchor_still_exists_in_the_working_tree(self) -> None:
        for reviewed in collector.REVIEWED_INTERFACES:
            with self.subTest(symbol=reviewed["symbol"]):
                blob = (ROOT / reviewed["path"]).read_bytes()
                self.assertIn(reviewed["anchor"].encode("utf-8"), blob)
                guard = reviewed["unused_guard"]
                if guard is None:
                    self.assertEqual(reviewed["role"], "native_runtime")
                    continue
                guard_blob = (ROOT / guard["path"]).read_bytes()
                self.assertIn(guard["anchor"].encode("utf-8"), guard_blob)

    def test_scenario_kinds_cover_every_produced_row(self) -> None:
        self.assertEqual(
            set(orchestrator.ROW_VALIDATORS), set(orchestrator.PRODUCED_ROWS)
        )
        for scenario_id in orchestrator.PRODUCED_ROWS:
            self.assertIn(scenario_id, orchestrator.ORCHESTRATOR_SCENARIO_KINDS)


class MessageTypeParserTest(unittest.TestCase):
    def test_derives_ordinals_from_the_iota_block(self) -> None:
        source = (
            "package core\n\nconst (\n"
            "\tNHP_KPL = iota // first\n"
            "\tNHP_KNK\n\tNHP_ACK\n\tNHP_AOP\n\tNHP_ART\n"
            "\tNHP_LST\n\tNHP_LRT\n\tNHP_COK\n\tNHP_RKN\n\tNHP_RLY\n"
            "\tNHP_AOL\n\tNHP_AAK\n\tNHP_OTP\n\tNHP_REG\n\tNHP_RAK\n"
            ")\n"
        ).encode("utf-8")
        self.assertEqual(
            collector.parse_message_type_wire_values(source),
            {
                "NHP_KPL": 0,
                "NHP_KNK": 1,
                "NHP_ACK": 2,
                "NHP_AOP": 3,
                "NHP_ART": 4,
                "NHP_LST": 5,
                "NHP_LRT": 6,
                "NHP_COK": 7,
                "NHP_RKN": 8,
                "NHP_RLY": 9,
                "NHP_AOL": 10,
                "NHP_AAK": 11,
                "NHP_OTP": 12,
                "NHP_REG": 13,
                "NHP_RAK": 14,
            },
        )

    def test_fails_closed_on_missing_or_ambiguous_blocks(self) -> None:
        cases = {
            "no block": b"package core\n",
            "two blocks": (
                "\tNHP_KPL = iota\n\tNHP_LST\n)\n\tNHP_KPL = iota\n\tNHP_LST\n)\n"
            ).encode("utf-8"),
            "missing retired type": ("\tNHP_KPL = iota\n\tNHP_KNK\n)\n").encode(
                "utf-8"
            ),
            "not utf-8": b"\xff\xfe\x00",
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(deployment.ContractError):
                    collector.parse_message_type_wire_values(source)


class InterfaceObservationTest(unittest.TestCase):
    def blobs(self) -> dict[str, bytes]:
        paths = {reviewed["path"] for reviewed in collector.REVIEWED_INTERFACES}
        paths.update(
            reviewed["unused_guard"]["path"]
            for reviewed in collector.REVIEWED_INTERFACES
            if reviewed["unused_guard"] is not None
        )
        return {path: (ROOT / path).read_bytes() for path in sorted(paths)}

    def test_fenced_legacy_entry_points_are_deployed_but_unused(self) -> None:
        observed = collector.observe_interfaces(self.blobs())
        by_symbol = {item["symbol"]: item for item in observed}
        for reviewed in collector.REVIEWED_INTERFACES:
            item = by_symbol[reviewed["symbol"]]
            with self.subTest(symbol=reviewed["symbol"]):
                self.assertEqual(item["state"], "present")
                self.assertEqual(
                    item["dispatches_lifecycle_work"],
                    reviewed["role"] == "native_runtime",
                )

    def test_removing_the_fence_marks_the_legacy_surface_live(self) -> None:
        blobs = self.blobs()
        blobs["endpoints/server/relay.go"] = b"package server\n"
        observed = collector.observe_interfaces(blobs)
        relay = next(
            item for item in observed if item["symbol"] == "httpsAgentTypeAllowed"
        )
        self.assertEqual(relay["state"], "present")
        self.assertTrue(relay["dispatches_lifecycle_work"])

    def test_removing_the_entry_point_marks_it_absent(self) -> None:
        blobs = self.blobs()
        blobs["endpoints/relay/relay.go"] = b"package relay\n"
        observed = collector.observe_interfaces(blobs)
        relay = next(
            item for item in observed if item["symbol"] == "httpsAgentTypeAllowed"
        )
        self.assertEqual(relay["state"], "absent")
        self.assertFalse(relay["dispatches_lifecycle_work"])


class GeneratedArtifactObservationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = deployment_fixture.valid_snapshot()["manifest"]
        self.identities = {
            (
                orchestrator.GENERATED_ARTIFACT_REPOSITORIES[repository_key],
                path,
            ): surface
            for surface, repository_key, path in (
                orchestrator.GENERATED_ARTIFACT_SURFACES
            )
        }

    @staticmethod
    def semantic_blob(surface: str, phase: str) -> bytes:
        semantics = orchestrator.GENERATED_ARTIFACT_SEMANTICS[surface]
        markers = list(semantics["required"])
        if phase == "pre_removal":
            markers.extend(semantics["pre_removal_required"])
        return ("\n".join(markers) + "\n").encode()

    def test_arbitrary_content_cannot_claim_any_matching_surface(self) -> None:
        for rejected_surface in orchestrator.GENERATED_ARTIFACT_SEMANTICS:
            with self.subTest(surface=rejected_surface):

                def read_blob(repository, path, _ref):
                    surface = self.identities[(repository, path)]
                    if surface == rejected_surface:
                        return b"arbitrary content\n"
                    return self.semantic_blob(surface, "pre_removal")

                with self.assertRaises(deployment.ContractError):
                    collector.observe_generated_artifacts(
                        manifest=self.manifest,
                        proof_phase="pre_removal",
                        read_blob_fn=read_blob,
                    )

    def test_post_removal_rejects_a_stale_export(self) -> None:
        def read_blob(repository, path, _ref):
            surface = self.identities[(repository, path)]
            blob = self.semantic_blob(surface, "post_removal")
            if surface == "mcp":
                blob += b"/v1/agent/bootstrap\n"
            return blob

        with self.assertRaisesRegex(
            deployment.ContractError, "still exports retired lifecycle"
        ):
            collector.observe_generated_artifacts(
                manifest=self.manifest,
                proof_phase="post_removal",
                read_blob_fn=read_blob,
            )


class ProducerTest(unittest.TestCase):
    def test_pre_removal_document_validates_against_its_own_artifact(self) -> None:
        (
            document,
            manifest,
            runtime,
            provenance,
            manifest_bytes,
            runtime_bytes,
            provenance_bytes,
        ) = build_document()
        self.assertEqual(document["produced_rows"], sorted(orchestrator.PRODUCED_ROWS))
        row = document["rows"]["retirement.nhp_registrar_surface_state"]
        self.assertEqual(row["kind"], "surface_inventory")
        self.assertEqual(
            row["retired_message_type_wire_values"],
            orchestrator.RETIRED_MESSAGE_TYPE_WIRE_VALUES,
        )
        self.assertEqual(row["source_sha"], manifest["repositories"]["nhp"])
        orchestrator.validate_orchestrator_evidence(
            copy.deepcopy(document),
            manifest=manifest,
            runtime=runtime,
            provenance=provenance,
            manifest_bytes=manifest_bytes,
            runtime_bytes=runtime_bytes,
            provenance_bytes=provenance_bytes,
            proof_phase="pre_removal",
            producer_run_id=RUN_ID,
            producer_run_attempt=RUN_ATTEMPT,
            producer_head_sha=HEAD_SHA,
            validation_time=VALIDATION_TIME,
        )

    def test_post_removal_rejects_a_still_present_legacy_surface(self) -> None:
        # The working tree still ships the fenced legacy relay admission lists,
        # so a post_removal document built from it must fail closed.
        with self.assertRaises(deployment.ContractError):
            build_document(proof_phase="post_removal")

    def test_rejects_a_surface_contract_that_is_not_the_reviewed_one(self) -> None:
        tampered = RETIRED_SURFACE_FIXTURE.read_bytes().replace(
            b'"wire_value": 5', b'"wire_value": 7'
        )
        self.assertNotEqual(tampered, RETIRED_SURFACE_FIXTURE.read_bytes())
        with self.assertRaises(deployment.ContractError):
            build_document(read_blob_fn=local_blob_reader(tampered))


class ValidatorFailClosedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.document,
            cls.manifest,
            cls.runtime,
            cls.provenance,
            cls.manifest_bytes,
            cls.runtime_bytes,
            cls.provenance_bytes,
        ) = build_document()

    def validate(self, document: dict[str, object], **overrides: object) -> None:
        values: dict[str, object] = {
            "manifest": self.manifest,
            "runtime": self.runtime,
            "provenance": self.provenance,
            "manifest_bytes": self.manifest_bytes,
            "runtime_bytes": self.runtime_bytes,
            "provenance_bytes": self.provenance_bytes,
            "proof_phase": "pre_removal",
            "producer_run_id": RUN_ID,
            "producer_run_attempt": RUN_ATTEMPT,
            "producer_head_sha": HEAD_SHA,
            "validation_time": VALIDATION_TIME,
        }
        values.update(overrides)
        orchestrator.validate_orchestrator_evidence(document, **values)

    def mutate(self, mutation) -> dict[str, object]:
        document = copy.deepcopy(self.document)
        mutation(document)
        return document

    def test_accepts_the_unmodified_document(self) -> None:
        self.validate(copy.deepcopy(self.document))

    def test_rejects_influence_bearing_drift(self) -> None:
        row_key = "retirement.nhp_registrar_surface_state"

        def drop_row(document):
            document["rows"] = {}
            document["produced_rows"] = []

        def extra_row(document):
            document["rows"]["negative.wrong_caller"] = {
                "kind": "rejection_observation"
            }
            document["produced_rows"] = sorted(document["rows"])

        def unknown_row(document):
            document["rows"] = {"not.a_scenario": {"kind": "surface_inventory"}}
            document["produced_rows"] = ["not.a_scenario"]

        def wrong_kind(document):
            document["rows"][row_key]["kind"] = "topology_observation"

        def stale_wire_value(document):
            document["rows"][row_key]["retired_message_type_wire_values"]["NHP_REG"] = 9

        def forged_interfaces(document):
            document["rows"][row_key]["interfaces"][0]["state"] = "absent"

        def native_runtime_removed(document):
            for item in document["rows"][row_key]["interfaces"]:
                if item["role"] == "native_runtime":
                    item["state"] = "absent"
                    item["dispatches_lifecycle_work"] = False

        def legacy_still_dispatching(document):
            for item in document["rows"][row_key]["interfaces"]:
                if item["role"] == "legacy_registrar":
                    item["dispatches_lifecycle_work"] = True

        def wrong_internal_operation(document):
            document["rows"][row_key]["retired_internal_http_operations"][0]["path"] = (
                "/internal/v1/agent/other"
            )

        def wrong_manifest_binding(document):
            document["bindings"]["deployment_manifest_sha256"] = "0" * 64

        def wrong_source_revision(document):
            document["bindings"]["nhp_source_sha"] = "9" * 40

        def wrong_surface_digest(document):
            document["bindings"]["retired_lifecycle_surface_raw_sha256"] = "1" * 64

        def wrong_producer(document):
            document["producer"]["run_id"] = RUN_ID + 1

        def wrong_gate(document):
            document["gate"] = "other_gate"

        def wrong_phase(document):
            document["phase"] = "post_removal"

        def extra_key(document):
            document["unexpected"] = True

        mutations = {
            "dropped row": drop_row,
            "extra row": extra_row,
            "unknown row": unknown_row,
            "wrong kind": wrong_kind,
            "stale wire value": stale_wire_value,
            "forged interfaces": forged_interfaces,
            "native runtime removed": native_runtime_removed,
            "legacy still dispatching": legacy_still_dispatching,
            "wrong internal operation": wrong_internal_operation,
            "wrong manifest binding": wrong_manifest_binding,
            "wrong source revision": wrong_source_revision,
            "wrong surface digest": wrong_surface_digest,
            "wrong producer": wrong_producer,
            "wrong gate": wrong_gate,
            "wrong phase": wrong_phase,
            "extra key": extra_key,
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(deployment.ContractError):
                    self.validate(self.mutate(mutation))

    def test_rejects_stale_and_future_observations(self) -> None:
        for name, moment in {
            "stale": VALIDATION_TIME + timedelta(minutes=11),
            "future": VALIDATION_TIME - timedelta(minutes=1),
        }.items():
            with self.subTest(name=name):
                with self.assertRaises(deployment.ContractError):
                    self.validate(copy.deepcopy(self.document), validation_time=moment)

    def test_rejects_noncanonical_bytes(self) -> None:
        canonical = orchestrator.canonical_bytes(self.document)
        for name, raw in {
            "leading space": b" " + canonical,
            "not json": b"{",
            "empty": b"",
        }.items():
            with self.subTest(name=name):
                with self.assertRaises(deployment.ContractError):
                    orchestrator.validate_orchestrator_bytes(
                        raw,
                        manifest=self.manifest,
                        runtime=self.runtime,
                        provenance=self.provenance,
                        manifest_bytes=self.manifest_bytes,
                        runtime_bytes=self.runtime_bytes,
                        provenance_bytes=self.provenance_bytes,
                        proof_phase="pre_removal",
                        producer_run_id=RUN_ID,
                        producer_run_attempt=RUN_ATTEMPT,
                        producer_head_sha=HEAD_SHA,
                        validation_time=VALIDATION_TIME,
                    )

    def test_accepts_the_canonical_round_trip(self) -> None:
        orchestrator.validate_orchestrator_bytes(
            orchestrator.canonical_bytes(self.document),
            manifest=self.manifest,
            runtime=self.runtime,
            provenance=self.provenance,
            manifest_bytes=self.manifest_bytes,
            runtime_bytes=self.runtime_bytes,
            provenance_bytes=self.provenance_bytes,
            proof_phase="pre_removal",
            producer_run_id=RUN_ID,
            producer_run_attempt=RUN_ATTEMPT,
            producer_head_sha=HEAD_SHA,
            validation_time=VALIDATION_TIME,
        )


if __name__ == "__main__":
    unittest.main()
