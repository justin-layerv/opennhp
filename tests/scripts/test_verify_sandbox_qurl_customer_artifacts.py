from __future__ import annotations

import copy
import importlib.util
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_sandbox_qurl_customer_artifacts",
    ROOT / ".github/scripts/verify_sandbox_qurl_customer_artifacts.py",
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

HEAD = "d" * 40
QURL_GO = "c" * 40
QURL_INFRA = "e" * 40
RUN_ID = 123456
RUN_ATTEMPT = 2
MODULE_VERSION = f"v0.8.1-0.20260824120000-{QURL_GO[:12]}"


def write_json(path: Path, value: dict) -> None:
    path.write_bytes(VERIFY.canonical(value))


def build_zip(path: Path, members: dict[str, bytes], *, symlink: str = "") -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            info = zipfile.ZipInfo(name)
            mode = stat.S_IFLNK | 0o777 if name == symlink else stat.S_IFREG | 0o644
            info.external_attr = mode << 16
            archive.writestr(info, raw)


def build_info(_: Path) -> str:
    return "\n".join(
        (
            "/private/binary: go1.26.6",
            "\tmod\tgithub.com/layervai/qurl-integrations\t(devel)\t",
            f"\tdep\tgithub.com/layervai/qurl-go\t{MODULE_VERSION}\t",
            "\tbuild\tvcs=git",
            f"\tbuild\tvcs.revision={HEAD}",
            "\tbuild\tvcs.modified=false",
            "",
        )
    )


def fixture(directory: Path) -> dict[str, Path | dict]:
    authority_raw = b"authority binary"
    lifecycle_raw = b"lifecycle binary"
    qurl_raw = b"qurl binary"
    binary_zip = directory / "binaries.zip"
    build_zip(
        binary_zip,
        {
            "bin/sandbox-matched-cohort-authority": authority_raw,
            "bin/sandbox-matched-cohort-lifecycle": lifecycle_raw,
            "bin/qurl": qurl_raw,
        },
    )
    source_receipt = {
        "schema_version": 1,
        "repository": VERIFY.CALLER_REPOSITORY,
        "head_sha": HEAD,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "qurl_go_source_sha": QURL_GO,
        "qurl_go_module_version": MODULE_VERSION,
        "binaries": {
            "qurl": {
                "path": "bin/qurl",
                "sha256": VERIFY.digest(qurl_raw),
            },
            "lifecycle": {
                "path": "bin/sandbox-matched-cohort-lifecycle",
                "sha256": VERIFY.digest(lifecycle_raw),
            },
            "authority": {
                "path": "bin/sandbox-matched-cohort-authority",
                "sha256": VERIFY.digest(authority_raw),
            },
        },
    }
    receipt_zip = directory / "source.zip"
    build_zip(receipt_zip, {VERIFY.SOURCE_RECEIPT_MEMBER: VERIFY.canonical(source_receipt)})
    binary_digest = f"sha256:{VERIFY.digest(binary_zip.read_bytes())}"
    receipt_digest = f"sha256:{VERIFY.digest(receipt_zip.read_bytes())}"
    request = {
        "schema": 1,
        "operation": "qurl-customer-journey",
        "expected_nhp_source_sha": "a" * 40,
        "caller_repository": VERIFY.CALLER_REPOSITORY,
        "caller_mode": "active",
        "caller_head_sha": HEAD,
        "caller_run_id": RUN_ID,
        "caller_run_attempt": RUN_ATTEMPT,
        "qurl_go_source_sha": QURL_GO,
        "qurl_infra_source_sha": QURL_INFRA,
        "qurl_infra_helper_sha256": "f" * 64,
        "binary_artifact_name": "sandbox-matched-cohort-binaries",
        "binary_artifact_digest": binary_digest,
        "source_receipt_artifact_name": "sandbox-matched-cohort-source-receipt",
        "source_receipt_artifact_digest": receipt_digest,
        "correlation_id": f"qurl-{RUN_ID}-{RUN_ATTEMPT}-{HEAD[:12]}",
    }
    run = {
        "schema": 1,
        "repository": VERIFY.CALLER_REPOSITORY,
        "workflow": VERIFY.CALLER_WORKFLOW,
        "head_sha": HEAD,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "event": "pull_request",
        "status": "in_progress",
        "conclusion": None,
    }
    binary_metadata = {
        "schema": 1,
        "name": request["binary_artifact_name"],
        "digest": binary_digest,
        "size_in_bytes": binary_zip.stat().st_size,
        "run_id": RUN_ID,
        "expired": False,
    }
    receipt_metadata = {
        "schema": 1,
        "name": request["source_receipt_artifact_name"],
        "digest": receipt_digest,
        "size_in_bytes": receipt_zip.stat().st_size,
        "run_id": RUN_ID,
        "expired": False,
    }
    paths: dict[str, Path | dict] = {
        "binary_zip": binary_zip,
        "receipt_zip": receipt_zip,
        "request": request,
        "run": run,
        "binary_metadata": binary_metadata,
        "receipt_metadata": receipt_metadata,
    }
    for key in ("request", "run", "binary_metadata", "receipt_metadata"):
        path = directory / f"{key}.json"
        write_json(path, paths[key])  # type: ignore[arg-type]
        paths[f"{key}_path"] = path
    return paths


def invoke(directory: Path, values: dict[str, Path | dict]) -> dict:
    return VERIFY.verify(
        values["request_path"],  # type: ignore[arg-type]
        values["run_path"],  # type: ignore[arg-type]
        values["binary_metadata_path"],  # type: ignore[arg-type]
        values["receipt_metadata_path"],  # type: ignore[arg-type]
        values["binary_zip"],  # type: ignore[arg-type]
        values["receipt_zip"],  # type: ignore[arg-type]
        directory / "installed",
        directory / "source-authority.json",
        build_info=build_info,
    )


class VerifySandboxQURLCustomerArtifactsTest(unittest.TestCase):
    def test_exact_artifacts_materialize_private_opened_inode_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            values = fixture(directory)
            authority = invoke(directory, values)
            self.assertEqual(authority["sources"]["qurl_integrations_head"], HEAD)
            self.assertEqual(authority["sources"]["qurl_go"], QURL_GO)
            self.assertEqual(authority["sources"]["qurl_infra"], QURL_INFRA)
            for name in ("sandbox-matched-cohort-authority", "sandbox-matched-cohort-lifecycle", "qurl"):
                path = directory / "installed" / name
                self.assertTrue(path.is_file())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE((directory / "installed").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / "source-authority.json").stat().st_mode), 0o600)

    def test_request_run_and_metadata_mutations_fail_before_materialization(self) -> None:
        mutations = (
            ("request", "qurl_go_source_sha", "0" * 40),
            ("request", "qurl_infra_source_sha", "0" * 39),
            ("request", "qurl_infra_helper_sha256", "0" * 63),
            ("request", "correlation_id", "qurl-1-1-000000000000"),
            ("run", "head_sha", "0" * 40),
            ("run", "conclusion", "failure"),
            ("run", "workflow", ".github/workflows/other.yml"),
            ("run", "event", "workflow_dispatch"),
            ("binary_metadata", "expired", True),
            ("binary_metadata", "run_id", RUN_ID + 1),
            ("receipt_metadata", "digest", "sha256:" + "0" * 64),
        )
        for group, key, replacement in mutations:
            with self.subTest(group=group, key=key), tempfile.TemporaryDirectory() as raw_directory:
                directory = Path(raw_directory)
                values = fixture(directory)
                changed = copy.deepcopy(values[group])
                changed[key] = replacement  # type: ignore[index]
                write_json(values[f"{group}_path"], changed)  # type: ignore[arg-type]
                with self.assertRaises(VERIFY.VerificationError):
                    invoke(directory, values)
                self.assertFalse((directory / "installed").exists())

    def test_active_mode_rejects_main_push_artifact_replay(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            values = fixture(directory)
            changed = copy.deepcopy(values["run"])
            changed["event"] = "push"
            write_json(values["run_path"], changed)  # type: ignore[arg-type]
            with self.assertRaises(VERIFY.VerificationError):
                invoke(directory, values)

    def test_completed_main_caller_is_exact_and_cross_mode_status_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            values = fixture(directory)
            request = copy.deepcopy(values["request"])
            request["caller_mode"] = "postdeploy"
            run = copy.deepcopy(values["run"])
            run.update({"event": "push", "status": "completed", "conclusion": "success"})
            write_json(values["request_path"], request)  # type: ignore[arg-type]
            write_json(values["run_path"], run)  # type: ignore[arg-type]
            self.assertEqual(invoke(directory, values)["caller"]["head_sha"], HEAD)

        for mode, status, conclusion in (
            ("active", "completed", "success"),
            ("postdeploy", "in_progress", None),
            ("postdeploy", "completed", "failure"),
        ):
            with self.subTest(mode=mode, status=status), tempfile.TemporaryDirectory() as raw_directory:
                directory = Path(raw_directory)
                values = fixture(directory)
                request = copy.deepcopy(values["request"])
                request["caller_mode"] = mode
                run = copy.deepcopy(values["run"])
                run.update({"status": status, "conclusion": conclusion})
                write_json(values["request_path"], request)  # type: ignore[arg-type]
                write_json(values["run_path"], run)  # type: ignore[arg-type]
                with self.assertRaises(VERIFY.VerificationError):
                    invoke(directory, values)

    def test_zip_member_and_digest_mutations_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            values = fixture(directory)
            values["binary_zip"].write_bytes(values["binary_zip"].read_bytes() + b"drift")  # type: ignore[union-attr]
            with self.assertRaisesRegex(VERIFY.VerificationError, "digest"):
                invoke(directory, values)

        for mutation in ("missing", "extra", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw_directory:
                directory = Path(raw_directory)
                values = fixture(directory)
                members = {
                    "bin/sandbox-matched-cohort-authority": b"authority binary",
                    "bin/sandbox-matched-cohort-lifecycle": b"lifecycle binary",
                    "bin/qurl": b"qurl binary",
                }
                symlink = ""
                if mutation == "missing":
                    members.pop("bin/sandbox-matched-cohort-authority")
                elif mutation == "extra":
                    members["bin/extra"] = b"extra"
                else:
                    symlink = "bin/sandbox-matched-cohort-lifecycle"
                build_zip(values["binary_zip"], members, symlink=symlink)  # type: ignore[arg-type]
                changed_request = copy.deepcopy(values["request"])
                changed_metadata = copy.deepcopy(values["binary_metadata"])
                changed_request["binary_artifact_digest"] = f"sha256:{VERIFY.digest(values['binary_zip'].read_bytes())}"  # type: ignore[union-attr]
                changed_metadata["digest"] = changed_request["binary_artifact_digest"]
                changed_metadata["size_in_bytes"] = values["binary_zip"].stat().st_size  # type: ignore[union-attr]
                write_json(values["request_path"], changed_request)  # type: ignore[arg-type]
                write_json(values["binary_metadata_path"], changed_metadata)  # type: ignore[arg-type]
                with self.assertRaises(VERIFY.VerificationError):
                    invoke(directory, values)

    def test_receipt_and_build_metadata_bind_exact_sources(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            values = fixture(directory)

            def wrong_revision(_: Path) -> str:
                return build_info(Path("unused")).replace(HEAD, "0" * 40)

            with self.assertRaisesRegex(VERIFY.VerificationError, "build authority"):
                VERIFY.verify(
                    values["request_path"],  # type: ignore[arg-type]
                    values["run_path"],  # type: ignore[arg-type]
                    values["binary_metadata_path"],  # type: ignore[arg-type]
                    values["receipt_metadata_path"],  # type: ignore[arg-type]
                    values["binary_zip"],  # type: ignore[arg-type]
                    values["receipt_zip"],  # type: ignore[arg-type]
                    directory / "installed",
                    directory / "source-authority.json",
                    build_info=wrong_revision,
                )


if __name__ == "__main__":
    unittest.main()
