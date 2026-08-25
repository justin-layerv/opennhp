from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_sandbox_qurl_service_provenance",
    ROOT / ".github/scripts/verify_sandbox_qurl_service_provenance.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
SOURCE_SHA = "cfa0f3dd0353e7c5d6a2d92d56ece91b73ea0cc5"
SOURCE_TAG = SOURCE_SHA[:7]
BUILD_RUN_ID = 32583390880


def raw(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def descriptor(body: bytes, **extra) -> dict:
    return {"mediaType": VERIFY.MANIFEST_MEDIA, "digest": "sha256:" + hashlib.sha256(body).hexdigest(), "size": len(body), **extra}


class ECR:
    def __init__(self, index: bytes, attestation: bytes, statement: bytes) -> None:
        self.index = index
        self.attestation = attestation
        self.statement = statement

    def batch_get_image(self, *, repositoryName, imageIds, acceptedMediaTypes):
        assert repositoryName == VERIFY.REPOSITORY
        body = self.attestation if "imageDigest" in imageIds[0] and imageIds[0]["imageDigest"] != "sha256:" + hashlib.sha256(self.index).hexdigest() else self.index
        media = VERIFY.MANIFEST_MEDIA if body is self.attestation else VERIFY.INDEX_MEDIA
        return {"images": [{"registryId": VERIFY.ACCOUNT, "repositoryName": VERIFY.REPOSITORY, "imageId": imageIds[0], "imageManifest": body.decode(), "imageManifestMediaType": media}], "failures": []}

    @staticmethod
    def get_download_url_for_layer(**_kwargs):
        return {"downloadUrl": "https://ecr.example/statement"}


def fixture() -> tuple[ECR, str]:
    platform_body = b"platform"
    platform = descriptor(platform_body, platform={"architecture": "amd64", "os": "linux"})
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": VERIFY.PREDICATE_TYPE,
        "subject": [{"name": f"pkg:docker/{VERIFY.ACCOUNT}.dkr.ecr.{VERIFY.REGION}.amazonaws.com/{VERIFY.REPOSITORY}@{SOURCE_TAG}?platform=linux%2Famd64", "digest": {"sha256": platform["digest"].removeprefix("sha256:")}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                "externalParameters": {"configSource": {"path": "Dockerfile.api"}, "request": {"root": {"request": {"args": {"vcs:localdir:context": ".", "vcs:localdir:dockerfile": "docker", "vcs:revision": SOURCE_SHA, "vcs:source": VERIFY.SOURCE_URL}}}}},
                "internalParameters": {"github_event_name": "push", "github_ref": VERIFY.SOURCE_REF, "github_repository": VERIFY.SOURCE_REPOSITORY, "github_run_attempt": "1", "github_run_id": str(BUILD_RUN_ID), "github_job": "docker-build", "github_workflow": "Build and Deploy qURL Service", "github_workflow_ref": VERIFY.WORKFLOW_REF, "github_workflow_sha": SOURCE_SHA},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": f"https://github.com/{VERIFY.SOURCE_REPOSITORY}/actions/runs/{BUILD_RUN_ID}/attempts/1"},
                "metadata": {"buildkit_completeness": {"request": True}, "buildkit_metadata": {"vcs": {"localdir:context": ".", "localdir:dockerfile": "docker", "revision": SOURCE_SHA, "source": VERIFY.SOURCE_URL}}, "finishedOn": "2026-08-22T16:13:59Z", "invocationId": "fixture", "startedOn": "2026-08-22T16:11:21Z"},
            },
        },
    }
    statement_raw = raw(statement)
    layer = {"mediaType": "application/vnd.in-toto+json", "digest": "sha256:" + hashlib.sha256(statement_raw).hexdigest(), "size": len(statement_raw), "annotations": {"in-toto.io/predicate-type": VERIFY.PREDICATE_TYPE}}
    subject = {key: platform[key] for key in ("mediaType", "digest", "size")}
    attestation_raw = raw({"schemaVersion": 2, "mediaType": VERIFY.MANIFEST_MEDIA, "artifactType": VERIFY.ATTESTATION_TYPE, "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2, "data": "e30="}, "layers": [layer], "subject": subject})
    attestation = descriptor(attestation_raw, annotations={"vnd.docker.reference.digest": platform["digest"], "vnd.docker.reference.type": "attestation-manifest"}, platform={"architecture": "unknown", "os": "unknown"})
    index_raw = raw({"schemaVersion": 2, "mediaType": VERIFY.INDEX_MEDIA, "manifests": [platform, attestation]})
    return ECR(index_raw, attestation_raw, statement_raw), "sha256:" + hashlib.sha256(index_raw).hexdigest()


class VerifySandboxQURLServiceProvenanceTest(unittest.TestCase):
    def test_exact_oci_chain_binds_source_platform_and_build_run(self) -> None:
        ecr, index_digest = fixture()
        receipt = VERIFY.verify(ecr, index_digest, SOURCE_TAG, lambda _url: ecr.statement)
        self.assertEqual(receipt["image_index_digest"], index_digest)
        self.assertEqual(receipt["source_sha"], SOURCE_SHA)
        self.assertEqual(receipt["build_run_id"], BUILD_RUN_ID)

    def test_source_tag_index_subject_and_build_mutations_reject(self) -> None:
        ecr, index_digest = fixture()
        mutations = []
        wrong_tag = copy.copy(ecr)
        original = wrong_tag.batch_get_image
        wrong_tag.batch_get_image = lambda **kwargs: ({**original(**kwargs), "images": [{**original(**kwargs)["images"][0], "imageManifest": "{}"}]} if "imageTag" in kwargs["imageIds"][0] else original(**kwargs))
        mutations.append((wrong_tag, index_digest, SOURCE_TAG, ecr.statement))
        mutations.append((ecr, "sha256:" + "0" * 64, SOURCE_TAG, ecr.statement))
        mutations.append((ecr, index_digest, "0" * 40, ecr.statement))
        changed = json.loads(ecr.statement)
        changed["subject"][0]["digest"]["sha256"] = "0" * 64
        mutations.append((ecr, index_digest, SOURCE_TAG, raw(changed)))
        changed = json.loads(ecr.statement)
        changed["predicate"]["buildDefinition"]["internalParameters"]["github_workflow_sha"] = "0" * 40
        mutations.append((ecr, index_digest, SOURCE_TAG, raw(changed)))
        for client, digest, source, statement in mutations:
            with self.subTest(source=source, statement=hashlib.sha256(statement).hexdigest()), self.assertRaises(VERIFY.ProvenanceError):
                VERIFY.verify(client, digest, source, lambda _url, body=statement: body)


if __name__ == "__main__":
    unittest.main()
