#!/usr/bin/env python3
"""Verify the delivered sandbox qurl-service ECR OCI/SLSA authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from pathlib import Path
from typing import Any, Callable

ACCOUNT = "767397897469"
REGION = "us-east-2"
REPOSITORY = "layerv/nhp-qurl"
SOURCE_REPOSITORY = "layervai/qurl-service"
SOURCE_URL = "https://github.com/layervai/qurl-service"
SOURCE_REF = "refs/heads/main"
WORKFLOW_REF = "layervai/qurl-service/.github/workflows/build-and-deploy.yml@refs/heads/main"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
ATTESTATION_TYPE = "application/vnd.docker.attestation.manifest.v1+json"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ProvenanceError(RuntimeError):
    """The delivered image does not carry the reviewed source authority."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProvenanceError("qurl-service provenance has duplicate fields")
        value[key] = item
    return value


def decode(raw: bytes, label: str, limit: int = 1 << 20) -> dict[str, Any]:
    if not 2 <= len(raw) <= limit:
        raise ProvenanceError(f"qurl-service {label} size is invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"qurl-service {label} JSON is invalid") from error
    if not isinstance(value, dict):
        raise ProvenanceError(f"qurl-service {label} is not an object")
    return value


def _digest_bytes(raw: bytes, expected: str, label: str) -> None:
    if DIGEST.fullmatch(expected) is None or "sha256:" + hashlib.sha256(raw).hexdigest() != expected:
        raise ProvenanceError(f"qurl-service {label} digest is not exact")


def _ecr_manifest(ecr: Any, image_id: dict[str, str], media_types: list[str]) -> bytes:
    response = ecr.batch_get_image(repositoryName=REPOSITORY, imageIds=[image_id], acceptedMediaTypes=media_types)
    if response.get("failures") or len(response.get("images", [])) != 1:
        raise ProvenanceError("qurl-service ECR manifest is unavailable")
    image = response["images"][0]
    required = {"registryId", "repositoryName", "imageId", "imageManifest", "imageManifestMediaType"}
    if set(image) != required or image["registryId"] != ACCOUNT or image["repositoryName"] != REPOSITORY:
        raise ProvenanceError("qurl-service ECR response identity drifted")
    returned_id = image["imageId"]
    if not isinstance(returned_id, dict) or any(returned_id.get(key) != expected for key, expected in image_id.items()):
        raise ProvenanceError("qurl-service ECR requested image identity drifted")
    if image["imageManifestMediaType"] not in media_types or not isinstance(image["imageManifest"], str):
        raise ProvenanceError("qurl-service ECR manifest media type drifted")
    return image["imageManifest"].encode()


def _descriptor(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProvenanceError(f"qurl-service {label} descriptor is not exact")
    if DIGEST.fullmatch(str(value.get("digest"))) is None or type(value.get("size")) is not int or value["size"] <= 0:
        raise ProvenanceError(f"qurl-service {label} descriptor is invalid")
    return value


def _index(raw: bytes, index_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _digest_bytes(raw, index_digest, "index")
    value = decode(raw, "index")
    if set(value) != {"schemaVersion", "mediaType", "manifests"} or value["schemaVersion"] != 2 or value["mediaType"] != INDEX_MEDIA:
        raise ProvenanceError("qurl-service OCI index is not exact")
    if not isinstance(value["manifests"], list) or len(value["manifests"]) != 2:
        raise ProvenanceError("qurl-service OCI descriptor set is not exact")
    platforms = []
    attestations = []
    for row in value["manifests"]:
        if isinstance(row, dict) and "annotations" in row:
            attestations.append(_descriptor(row, {"mediaType", "digest", "size", "annotations", "platform"}, "attestation"))
        else:
            platforms.append(_descriptor(row, {"mediaType", "digest", "size", "platform"}, "platform"))
    if len(platforms) != 1 or len(attestations) != 1:
        raise ProvenanceError("qurl-service OCI platform/attestation set is not exact")
    platform, attestation = platforms[0], attestations[0]
    if platform["mediaType"] != MANIFEST_MEDIA or platform["platform"] != {"architecture": "amd64", "os": "linux"}:
        raise ProvenanceError("qurl-service OCI platform is not linux/amd64")
    if (
        attestation["mediaType"] != MANIFEST_MEDIA
        or attestation["platform"] != {"architecture": "unknown", "os": "unknown"}
        or attestation["annotations"]
        != {"vnd.docker.reference.digest": platform["digest"], "vnd.docker.reference.type": "attestation-manifest"}
    ):
        raise ProvenanceError("qurl-service OCI attestation descriptor is not exact")
    return platform, attestation


def _attestation(raw: bytes, descriptor: dict[str, Any], platform: dict[str, Any]) -> dict[str, Any]:
    _digest_bytes(raw, descriptor["digest"], "attestation manifest")
    if len(raw) != descriptor["size"]:
        raise ProvenanceError("qurl-service attestation manifest size drifted")
    value = decode(raw, "attestation manifest")
    if set(value) != {"schemaVersion", "mediaType", "artifactType", "config", "layers", "subject"}:
        raise ProvenanceError("qurl-service attestation manifest schema drifted")
    if value["schemaVersion"] != 2 or value["mediaType"] != MANIFEST_MEDIA or value["artifactType"] != ATTESTATION_TYPE:
        raise ProvenanceError("qurl-service attestation manifest authority drifted")
    config = _descriptor(value["config"], {"mediaType", "digest", "size", "data"}, "attestation config")
    if config != {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2, "data": "e30="}:
        raise ProvenanceError("qurl-service attestation config drifted")
    subject = _descriptor(value["subject"], {"mediaType", "digest", "size"}, "attestation subject")
    if subject != {key: platform[key] for key in ("mediaType", "digest", "size")}:
        raise ProvenanceError("qurl-service attestation subject does not bind the platform")
    if not isinstance(value["layers"], list) or len(value["layers"]) != 1:
        raise ProvenanceError("qurl-service SLSA layer set is not exact")
    layer = _descriptor(value["layers"][0], {"mediaType", "digest", "size", "annotations"}, "SLSA layer")
    if layer["mediaType"] != "application/vnd.in-toto+json" or layer["annotations"] != {"in-toto.io/predicate-type": PREDICATE_TYPE}:
        raise ProvenanceError("qurl-service SLSA layer authority drifted")
    return layer


def _statement(raw: bytes, layer: dict[str, Any], platform: dict[str, Any], source_tag: str) -> dict[str, Any]:
    _digest_bytes(raw, layer["digest"], "SLSA statement")
    if len(raw) != layer["size"]:
        raise ProvenanceError("qurl-service SLSA statement size drifted")
    value = decode(raw, "SLSA statement")
    if set(value) != {"_type", "predicate", "predicateType", "subject"} or value["_type"] != "https://in-toto.io/Statement/v1" or value["predicateType"] != PREDICATE_TYPE:
        raise ProvenanceError("qurl-service SLSA statement schema drifted")
    expected_name = f"pkg:docker/{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}@{source_tag}?platform=linux%2Famd64"
    expected_digest = {"sha256": platform["digest"].removeprefix("sha256:")}
    expected_subject = [{"name": expected_name, "digest": expected_digest}]
    if value["subject"] != expected_subject:
        raise ProvenanceError("qurl-service SLSA subject drifted")
    predicate = value["predicate"]
    if not isinstance(predicate, dict) or set(predicate) != {"buildDefinition", "runDetails"}:
        raise ProvenanceError("qurl-service SLSA predicate schema drifted")
    definition, details = predicate["buildDefinition"], predicate["runDetails"]
    if not isinstance(definition, dict) or set(definition) != {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"} or definition["buildType"] != "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md":
        raise ProvenanceError("qurl-service SLSA build definition drifted")
    external, internal = definition["externalParameters"], definition["internalParameters"]
    if not isinstance(external, dict) or set(external) != {"configSource", "request"} or external["configSource"].get("path") != "Dockerfile.api":
        raise ProvenanceError("qurl-service Dockerfile source drifted")
    args = external["request"].get("root", {}).get("request", {}).get("args") if isinstance(external["request"], dict) else None
    source_sha = args.get("vcs:revision") if isinstance(args, dict) else None
    if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None or not source_sha.startswith(source_tag):
        raise ProvenanceError("qurl-service BuildKit source revision is invalid")
    if args != {"vcs:localdir:context": ".", "vcs:localdir:dockerfile": "docker", "vcs:revision": source_sha, "vcs:source": SOURCE_URL}:
        raise ProvenanceError("qurl-service BuildKit request drifted")
    run_id = internal.get("github_run_id") if isinstance(internal, dict) else None
    run_attempt = internal.get("github_run_attempt") if isinstance(internal, dict) else None
    if not isinstance(run_id, str) or re.fullmatch(r"[1-9][0-9]*", run_id) is None or not isinstance(run_attempt, str) or re.fullmatch(r"[1-9][0-9]*", run_attempt) is None:
        raise ProvenanceError("qurl-service GitHub build run identity is invalid")
    required = {"github_event_name": "push", "github_ref": SOURCE_REF, "github_repository": SOURCE_REPOSITORY, "github_run_attempt": run_attempt, "github_run_id": run_id, "github_job": "docker-build", "github_workflow": "Build and Deploy qURL Service", "github_workflow_ref": WORKFLOW_REF, "github_workflow_sha": source_sha}
    if any(internal.get(key) != expected for key, expected in required.items()):
        raise ProvenanceError("qurl-service GitHub build authority drifted")
    builder_id = f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}"
    if not isinstance(details, dict) or set(details) != {"builder", "metadata"} or details["builder"] != {"id": builder_id}:
        raise ProvenanceError("qurl-service SLSA run details drifted")
    metadata = details["metadata"]
    if not isinstance(metadata, dict) or set(metadata) != {"buildkit_completeness", "buildkit_metadata", "finishedOn", "invocationId", "startedOn"}:
        raise ProvenanceError("qurl-service SLSA metadata schema drifted")
    vcs = metadata.get("buildkit_metadata", {}).get("vcs")
    if vcs != {"localdir:context": ".", "localdir:dockerfile": "docker", "revision": source_sha, "source": SOURCE_URL}:
        raise ProvenanceError("qurl-service SLSA VCS authority drifted")
    if any(not isinstance(metadata[field], str) or not metadata[field].endswith("Z") for field in ("startedOn", "finishedOn")):
        raise ProvenanceError("qurl-service SLSA timestamps are invalid")
    return {"source_sha": source_sha, "builder_id": builder_id, "run_id": int(run_id), "run_attempt": int(run_attempt), "started_on": metadata["startedOn"], "finished_on": metadata["finishedOn"]}


def fetch_https(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ProvenanceError("qurl-service SLSA download URL is not HTTPS")
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read((1 << 20) + 1)


def verify(ecr: Any, index_digest: str, source_tag: str, fetch: Callable[[str], bytes] = fetch_https) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{7}", source_tag) is None or DIGEST.fullmatch(index_digest) is None:
        raise ProvenanceError("qurl-service expected source tag or index digest is invalid")
    by_digest = _ecr_manifest(ecr, {"imageDigest": index_digest}, [INDEX_MEDIA])
    by_tag = _ecr_manifest(ecr, {"imageTag": source_tag}, [INDEX_MEDIA])
    if by_digest != by_tag:
        raise ProvenanceError("qurl-service source tag and index digest differ")
    platform, attestation = _index(by_digest, index_digest)
    attestation_raw = _ecr_manifest(ecr, {"imageDigest": attestation["digest"]}, [MANIFEST_MEDIA])
    layer = _attestation(attestation_raw, attestation, platform)
    download = ecr.get_download_url_for_layer(repositoryName=REPOSITORY, layerDigest=layer["digest"])
    if set(download) - {"downloadUrl", "layerDigest", "ResponseMetadata"} or download.get("layerDigest") not in {None, layer["digest"]} or not isinstance(download.get("downloadUrl"), str):
        raise ProvenanceError("qurl-service SLSA download authority drifted")
    statement = _statement(fetch(download["downloadUrl"]), layer, platform, source_tag)
    return {"schema": 1, "environment": "sandbox", "repository": SOURCE_REPOSITORY, "source_sha": statement["source_sha"], "source_tag": source_tag, "source_ref": SOURCE_REF, "image_index_digest": index_digest, "platform_image_digest": platform["digest"], "attestation_manifest_digest": attestation["digest"], "statement_digest": layer["digest"], "builder_id": statement["builder_id"], "build_run_id": statement["run_id"], "build_run_attempt": statement["run_attempt"], "build_started_on": statement["started_on"], "build_finished_on": statement["finished_on"]}


def write_private(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise ProvenanceError("qurl-service provenance receipt path is unsafe")
    raw = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ProvenanceError("qurl-service provenance receipt write was short")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--image-index-digest", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.region != REGION or args.repository != REPOSITORY:
        raise ProvenanceError("qurl-service ECR target is not exact sandbox")
    import boto3

    session = boto3.session.Session(region_name=args.region)
    if session.client("sts").get_caller_identity().get("Account") != ACCOUNT:
        raise ProvenanceError("qurl-service AWS account is not exact sandbox")
    write_private(args.output_file, verify(session.client("ecr"), args.image_index_digest, args.source_tag))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ProvenanceError):
        print("sandbox qurl-service provenance verification failed", file=sys.stderr)
        raise SystemExit(1) from None
