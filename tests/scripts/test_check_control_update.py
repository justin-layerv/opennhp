#!/usr/bin/env python3
"""Regression tests for the reusable sandbox Control update lane."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / ".github/scripts/check-control-update.py"
WORKFLOW_PATH = ROOT / ".github/workflows/control-sandbox-update.yml"
CAPTURE_PATH = ROOT / "scripts/capture-control-update-state.sh"
AWS_IDENTITY_PATH = ROOT / "scripts/check-control-aws-identity.sh"
LIVE_MAIN_PATH = ROOT / "scripts/check-live-main-ref.sh"
NO_CREDENTIALS_PATH = ROOT / "scripts/check-no-checkout-credentials.sh"
VERIFY_SECRET_PATH = ROOT / "scripts/verify-control-otp-pepper.sh"
VERIFY_PATH = ROOT / "scripts/verify-control-sandbox-first-apply.sh"
LIVE_BOUNDARY_PATH = ROOT / "scripts/verify-control-sandbox-live-boundary.sh"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate-workflows.yml"
MAKEFILE_PATH = ROOT / "Makefile"

SPEC = importlib.util.spec_from_file_location("control_update_checker", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

# The checker is per-environment now; these cases assert the sandbox profile.
SANDBOX = CHECKER.environment_profile("sandbox")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def state_fixture(root: Path, *, serial: int = 4) -> tuple[Path, Path]:
    state_path = root / "state.tfstate"
    write_json(
        state_path,
        {
            "version": 4,
            "terraform_version": CHECKER.TF_VERSION,
            "serial": serial,
            "lineage": "11111111-2222-3333-4444-555555555555",
            "outputs": {},
            "resources": [],
        },
    )
    head_path = root / "state-head.json"
    write_json(
        head_path,
        {
            "ContentLength": state_path.stat().st_size,
            "ETag": '"0123456789abcdef0123456789abcdef"',
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": SANDBOX["state_kms_key_arn"],
            "VersionId": "state-version-4",
        },
    )
    return state_path, head_path


class StateContractTests(unittest.TestCase):
    def test_exact_versioned_kms_state_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path, head_path = state_fixture(Path(directory))
            summary = CHECKER.check_state(state_path, head_path, SANDBOX)
        self.assertEqual(summary["serial"], 4)
        self.assertEqual(summary["version_id"], "state-version-4")
        self.assertEqual(summary["bucket"], SANDBOX["state_bucket"])
        self.assertEqual(len(summary["sha256"]), 64)

    def test_sse_kms_etag_is_an_opaque_nonempty_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path, head_path = state_fixture(Path(directory))
            head = json.loads(head_path.read_text())
            head["ETag"] = '"opaque-sse-kms-identity"'
            write_json(head_path, head)
            summary = CHECKER.check_state(state_path, head_path, SANDBOX)
        self.assertEqual(summary["etag"], '"opaque-sse-kms-identity"')

    def test_state_header_s3_identity_and_download_length_fail_closed(self) -> None:
        mutations = {
            "kms": lambda state, head: head.update(SSEKMSKeyId="wrong"),
            "version": lambda state, head: head.update(VersionId="null"),
            "length": lambda state, head: head.update(ContentLength=1),
            "empty etag": lambda state, head: head.update(ETag=""),
            "non-string etag": lambda state, head: head.update(ETag=17),
            "serial": lambda state, head: state.update(serial=-1),
            "terraform": lambda state, head: state.update(terraform_version="1.13.0"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state_path, head_path = state_fixture(root)
                state = json.loads(state_path.read_text())
                head = json.loads(head_path.read_text())
                mutate(state, head)
                write_json(state_path, state)
                if label != "length":
                    head["ContentLength"] = state_path.stat().st_size
                write_json(head_path, head)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(state_path, head_path, SANDBOX)


class ArtifactContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        state_path, head_path = state_fixture(self.root)
        summary = CHECKER.check_state(state_path, head_path, SANDBOX)
        self.state_summary = self.root / "planned-state-summary.json"
        CHECKER.write_json(self.state_summary, summary)
        self.plan = self.root / "tfplan"
        self.plan.write_bytes(b"immutable terraform plan\x00")
        self.plan_text = self.root / "tfplan.txt"
        self.plan_text.write_text("Terraform will perform the reviewed actions.\n")
        self.contract_summary = self.root / "plan-contract-summary.json"
        write_json(
            self.contract_summary,
            {
                "bootstrap_create_count": 2,
                "contract_sha256": "a" * 64,
                "normalization_drift_count": 0,
                "resource_count": 43,
            },
        )
        self.contract_checker = self.root / "source-owned-checker.py"
        self.contract_checker.write_text("# reviewed checker\n")
        self.runtime_contract = self.root / "authority-runtime.generated.tfvars.json"
        self.runtime_contract.write_text('{"authority_runtime_contract":{}}\n')
        self.metadata = self.root / "plan-metadata.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "plan": self.plan,
            "plan_text": self.plan_text,
            "contract_summary": self.contract_summary,
            "contract_checker": self.contract_checker,
            "runtime_contract": self.runtime_contract,
            "state_summary": self.state_summary,
            "repository": CHECKER.REPOSITORY,
            "commit_sha": "b" * 40,
            "plan_sha256": CHECKER.sha256_file(self.plan),
            "run_id": "12345",
            "run_attempt": "2",
            "planned_at_epoch": "200000",
            "workflow_ref": f"{CHECKER.REPOSITORY}/{SANDBOX["workflow_path"]}@refs/heads/main",
            "terraform_version": CHECKER.TF_VERSION,
            "output": self.metadata,
            "metadata": self.metadata,
            "state_version_id": "state-version-4",
            "state_serial": "4",
            "state_sha256": json.loads(self.state_summary.read_text())["sha256"],
            # Source-run start (epoch 199000) just before planned_at_epoch
            # (200000); the freshness age is now measured from this authoritative
            # GitHub timestamp, not the artifact's self-reported epoch.
            "run_started_at": "1970-01-03T07:16:40Z",
            "now_epoch": 200001,
        }
        values.setdefault("environment", "sandbox")
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_artifact_round_trip_binds_plan_contract_and_state(self) -> None:
        created = CHECKER.create_artifact(self.args())
        verified = CHECKER.verify_artifact(self.args())
        self.assertEqual(verified, created)
        self.assertEqual(created["state"]["serial"], 4)
        self.assertEqual(created["schema_version"], 1)

    def test_tamper_stale_plan_and_approval_drift_fail(self) -> None:
        CHECKER.create_artifact(self.args())
        cases = (
            ("plan", lambda: self.plan.write_bytes(b"tampered"), {}),
            ("text", lambda: self.plan_text.write_text("tampered\n"), {}),
            (
                "runtime-contract",
                lambda: self.runtime_contract.write_text(
                    '{"authority_runtime_contract":null}\n'
                ),
                {},
            ),
            (
                "contract",
                lambda: write_json(self.contract_summary, {"resource_count": 999}),
                {},
            ),
            ("state-version", lambda: None, {"state_version_id": "other"}),
            ("state-serial", lambda: None, {"state_serial": "5"}),
            ("state-digest", lambda: None, {"state_sha256": "0" * 64}),
            (
                "stale",
                lambda: None,
                {"now_epoch": 200000 + CHECKER.PLAN_MAX_AGE_SECONDS + 1},
            ),
            # run_started_at (epoch 259200) later than the self-reported
            # planned_at_epoch (200000) breaks the source-run bracket, so a
            # forged plan time cannot outrun authoritative GitHub run metadata.
            (
                "run-start-after-plan",
                lambda: None,
                {"run_started_at": "1970-01-04T00:00:00Z"},
            ),
        )
        for label, mutate, overrides in cases:
            with self.subTest(label=label):
                original = {
                    path: path.read_bytes()
                    for path in (
                        self.plan,
                        self.plan_text,
                        self.contract_summary,
                        self.runtime_contract,
                    )
                }
                mutate()
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.verify_artifact(self.args(**overrides))
                for path, content in original.items():
                    path.write_bytes(content)

    def test_metadata_key_injection_and_checker_drift_fail(self) -> None:
        CHECKER.create_artifact(self.args())
        metadata = json.loads(self.metadata.read_text())
        metadata["unreviewed"] = True
        write_json(self.metadata, metadata)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.verify_artifact(self.args())

        CHECKER.create_artifact(self.args())
        self.contract_checker.write_text("# changed checker\n")
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.verify_artifact(self.args())


class SourceRunTests(unittest.TestCase):
    def test_successful_exact_main_plan_run_is_required(self) -> None:
        run = {
            "id": 12345,
            "run_attempt": 2,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": "b" * 40,
            "name": SANDBOX["workflow_name"],
            "path": SANDBOX["workflow_path"],
            "repository": {"full_name": CHECKER.REPOSITORY},
            "actor": {"login": "planner"},
            "triggering_actor": {"login": "planner"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            write_json(path, run)
            args = argparse.Namespace(
                environment="sandbox",
                run_json=path,
                run_id="12345",
                run_attempt="2",
                commit_sha="b" * 40,
            )
            self.assertEqual(CHECKER.check_source_run(args)["run_id"], 12345)
            for field, value in (
                ("conclusion", "failure"),
                ("head_branch", "feature"),
                ("run_attempt", 1),
                ("path", ".github/workflows/other.yml"),
            ):
                with self.subTest(field=field):
                    broken = copy.deepcopy(run)
                    broken[field] = value
                    write_json(path, broken)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_source_run(args)


class ShellBoundaryTests(unittest.TestCase):
    @staticmethod
    def _initialize_repository(root: Path) -> Path:
        repository = root / "repository"
        subprocess.run(["git", "init", "--quiet", repository], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "remote",
                "add",
                "origin",
                "https://github.com/layervai/nhp",
            ],
            check=True,
        )
        return repository

    def test_checkout_credentials_are_absent_or_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = self._initialize_repository(root)
            env = dict(os.environ)
            env.pop("GH_TOKEN", None)
            env.pop("GITHUB_TOKEN", None)
            env["GITHUB_REPOSITORY"] = CHECKER.REPOSITORY
            clean = subprocess.run(
                [str(NO_CREDENTIALS_PATH)], cwd=repository, env=env, capture_output=True, text=True
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)

            env["GH_TOKEN"] = "leaked"
            leaked = subprocess.run(
                [str(NO_CREDENTIALS_PATH)], cwd=repository, env=env, capture_output=True, text=True
            )
            self.assertNotEqual(leaked.returncode, 0)

            env.pop("GH_TOKEN")
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "http.https://github.com/.extraheader",
                    "AUTHORIZATION: basic leaked",
                ],
                check=True,
            )
            configured = subprocess.run(
                [str(NO_CREDENTIALS_PATH)], cwd=repository, env=env, capture_output=True, text=True
            )
            self.assertNotEqual(configured.returncode, 0)

    def test_live_main_uses_authenticated_api_and_exact_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '{\"ref\":\"refs/heads/main\",\"object\":{\"type\":\"commit\",\"sha\":\"%s\"}}\\n' \"$FAKE_SHA\"\n"
            )
            fake_gh.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "GH_TOKEN": "step-scoped",
                "GITHUB_REPOSITORY": CHECKER.REPOSITORY,
                "FAKE_SHA": "c" * 40,
            }
            exact = subprocess.run(
                [str(LIVE_MAIN_PATH), "c" * 40], env=env, capture_output=True, text=True
            )
            self.assertEqual(exact.returncode, 0, exact.stderr)
            mismatch = subprocess.run(
                [str(LIVE_MAIN_PATH), "d" * 40], env=env, capture_output=True, text=True
            )
            self.assertNotEqual(mismatch.returncode, 0)

    def test_state_capture_reads_one_version_and_rejects_a_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path, head_path = state_fixture(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_aws = fake_bin / "aws"
            fake_aws.write_text(
                """#!/usr/bin/env python3
import json
import os
import shutil
import sys
from pathlib import Path

args = sys.argv[1:]
if args[:2] == ["s3api", "head-object"]:
    key = args[args.index("--key") + 1]
    if key.endswith(".tflock"):
        if os.environ.get("FAKE_LOCK") == "1":
            print(json.dumps({"VersionId": "lock"}))
            raise SystemExit(0)
        print("An error occurred (404) when calling HeadObject: Not Found", file=sys.stderr)
        raise SystemExit(254)
    counter = Path(os.environ["FAKE_HEAD_COUNTER"])
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    selected = os.environ.get("FAKE_HEAD_AFTER") if count > 1 else None
    print(Path(selected or os.environ["FAKE_HEAD"]).read_text(), end="")
elif args[:2] == ["s3api", "get-object"]:
    version = args[args.index("--version-id") + 1]
    if version != "state-version-4":
        raise SystemExit("wrong version")
    shutil.copyfile(os.environ["FAKE_STATE"], args[-1])
    print(json.dumps({"VersionId": version}))
else:
    raise SystemExit(f"unexpected aws args: {args}")
"""
            )
            fake_aws.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_STATE": str(state_path),
                "FAKE_HEAD": str(head_path),
                "FAKE_HEAD_COUNTER": str(root / "head-counter"),
            }
            evidence = root / "evidence"
            captured = subprocess.run(
                [str(CAPTURE_PATH), "sandbox", str(evidence)], env=env, capture_output=True, text=True
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
            self.assertEqual(json.loads((evidence / "state-summary.json").read_text())["serial"], 4)

            env["FAKE_LOCK"] = "1"
            locked = subprocess.run(
                [str(CAPTURE_PATH), "sandbox", str(root / "locked")], env=env, capture_output=True, text=True
            )
            self.assertNotEqual(locked.returncode, 0)
            self.assertIn("state is locked", locked.stderr)

            env.pop("FAKE_LOCK")
            (root / "head-counter").unlink(missing_ok=True)
            moved_head = json.loads(head_path.read_text())
            moved_head["VersionId"] = "state-version-5"
            moved_head_path = root / "moved-head.json"
            write_json(moved_head_path, moved_head)
            env["FAKE_HEAD_AFTER"] = str(moved_head_path)
            moved = subprocess.run(
                [str(CAPTURE_PATH), "sandbox", str(root / "moved")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(moved.returncode, 0)
            self.assertIn("state changed during capture", moved.stderr)

    def test_exact_post_assume_role_and_session_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_aws = fake_bin / "aws"
            fake_aws.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "[[ \"$1 $2\" == 'sts get-caller-identity' ]]\n"
                "printf '%s\\n' \"$FAKE_IDENTITY\"\n"
            )
            fake_aws.chmod(0o755)
            session = "control-update-plan-12345"
            exact = {
                "Account": SANDBOX["account_id"],
                "Arn": f"arn:aws:sts::{SANDBOX["account_id"]}:assumed-role/nhp-sandbox-github-actions/{session}",
                "UserId": f"role-id:{session}",
            }
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_IDENTITY": json.dumps(exact),
            }
            accepted = subprocess.run(
                [str(AWS_IDENTITY_PATH), "sandbox", session], env=env, capture_output=True, text=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            for label, arn, account in (
                (
                    "wrong-role",
                    f"arn:aws:sts::{SANDBOX["account_id"]}:assumed-role/other/{session}",
                    SANDBOX["account_id"],
                ),
                (
                    "wrong-session",
                    f"arn:aws:sts::{SANDBOX["account_id"]}:assumed-role/nhp-sandbox-github-actions/other",
                    SANDBOX["account_id"],
                ),
                (
                    "wrong-account",
                    f"arn:aws:sts::000000000000:assumed-role/nhp-sandbox-github-actions/{session}",
                    "000000000000",
                ),
            ):
                with self.subTest(label=label):
                    env["FAKE_IDENTITY"] = json.dumps({"Account": account, "Arn": arn})
                    rejected = subprocess.run(
                        [str(AWS_IDENTITY_PATH), "sandbox", session],
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(rejected.returncode, 0)


class ReadOnlySecretVerificationTests(unittest.TestCase):
    secret_arn = (
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:"
        "layerv-nhp-sandbox-control-otp-pepper-AbCdEf"
    )
    kms_arn = "arn:aws:kms:us-east-2:767397897469:key/data123"

    def run_verifier(self, root: Path, versions: list[dict]) -> subprocess.CompletedProcess[str]:
        fake_bin = root / "bin"
        fake_bin.mkdir()
        evidence = root / "evidence"
        # verify-control-sandbox-first-apply.sh creates the shared evidence
        # directory before invoking this component verifier. Exercise that real
        # call shape so a non-idempotent mkdir cannot break post-apply proof.
        evidence.mkdir(mode=0o755)
        log_path = root / "aws.log"
        versions_path = root / "versions.json"
        write_json(versions_path, {"Versions": versions})
        fake_aws = fake_bin / "aws"
        fake_aws.write_text(
            """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["FAKE_AWS_LOG"]).open("a") as log:
    log.write(" ".join(args) + "\\n")
if args[:2] == ["secretsmanager", "describe-secret"]:
    print('{"KmsKeyId":"' + os.environ["FAKE_KMS_ARN"] + '"}')
elif args[:2] == ["secretsmanager", "list-secret-version-ids"]:
    print(Path(os.environ["FAKE_VERSIONS"]).read_text(), end="")
else:
    raise SystemExit("read-only verifier attempted forbidden AWS operation")
"""
        )
        fake_aws.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "FAKE_AWS_LOG": str(log_path),
            "FAKE_KMS_ARN": self.kms_arn,
            "FAKE_VERSIONS": str(versions_path),
        }
        return subprocess.run(
            [
                str(VERIFY_SECRET_PATH),
                self.secret_arn,
                self.kms_arn,
                "us-east-2",
                str(root / "evidence"),
            ],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_exact_current_version_is_verified_without_mutation(self) -> None:
        token = hashlib.sha256(self.secret_arn.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_verifier(
                root, [{"VersionId": token, "VersionStages": ["AWSCURRENT"]}]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(
                (root / "evidence/secret-verification-summary.json").read_text()
            )
            self.assertEqual((root / "evidence").stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                summary,
                {
                    "ready": True,
                    "secret_version_token_sha256": token,
                    "verified_read_only": True,
                },
            )
            calls = (root / "aws.log").read_text()
            self.assertNotIn("get-random-password", calls)
            self.assertNotIn("put-secret-value", calls)

    def test_missing_and_ambiguous_versions_fail_without_mutation(self) -> None:
        token = hashlib.sha256(self.secret_arn.encode()).hexdigest()
        histories = (
            [],
            [{"VersionId": token, "VersionStages": ["AWSPREVIOUS"]}],
            [
                {"VersionId": token, "VersionStages": ["AWSCURRENT"]},
                {"VersionId": "other", "VersionStages": ["AWSPREVIOUS"]},
            ],
        )
        for versions in histories:
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = self.run_verifier(root, list(versions))
                self.assertNotEqual(result.returncode, 0)
                calls = (root / "aws.log").read_text()
                self.assertNotIn("get-random-password", calls)
                self.assertNotIn("put-secret-value", calls)


class WorkflowContractTests(unittest.TestCase):
    def test_component_verifiers_accept_the_shared_precreated_evidence_directory(self) -> None:
        for helper in (VERIFY_SECRET_PATH, LIVE_BOUNDARY_PATH):
            with self.subTest(helper=helper.name):
                source = helper.read_text(encoding="utf-8")
                self.assertIn('install -d -m 700 "$evidence_dir"', source)
                self.assertNotIn('mkdir -m 700 "$evidence_dir"', source)

        first_apply = VERIFY_PATH.read_text(encoding="utf-8")
        self.assertIn('install -d -m 700 "$evidence_dir"', first_apply)
        self.assertNotIn('mkdir -p "$evidence_dir"', first_apply)

    def test_live_boundary_flow_log_budget_uses_one_derived_bound(self) -> None:
        source = LIVE_BOUNDARY_PATH.read_text(encoding="utf-8")
        for marker in (
            'max_attempts="${FLOW_LOG_MAX_ATTEMPTS:-20}"',
            'attempt <= max_attempts',
            'attempt < max_attempts',
            'within $max_attempts checks at 15-second intervals',
        ):
            self.assertIn(marker, source)
        self.assertNotIn('attempt < 20', source)
        self.assertNotIn('within 20 checks', source)

    def test_live_boundary_accepts_the_optional_phase_argument(self) -> None:
        # #3705 gave the script an optional third `phase` argument but left the
        # arity guard at `-ne 2`, so the workflow's own `pre-apply` call died on
        # the usage error before doing any work. That deadlocked every Control
        # sandbox apply -- including the one that opens the Hub UDP edge.
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            missing_plan = Path(tmp) / "absent-plan.json"
            for args in ([], ["pre-apply"], ["post-apply"]):
                with self.subTest(phase=args or ["<default>"]):
                    result = subprocess.run(
                        [str(LIVE_BOUNDARY_PATH), str(missing_plan), str(evidence), *args],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    # Must get PAST the arity/usage guard and fail on the real
                    # precondition instead.
                    self.assertNotIn("usage:", result.stderr)
                    self.assertIn("Terraform plan JSON does not exist", result.stderr)

            rejected = subprocess.run(
                [str(LIVE_BOUNDARY_PATH), str(missing_plan), str(evidence), "mid-apply"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("usage:", rejected.stderr)

    def test_every_live_boundary_caller_passes_an_accepted_argument_count(self) -> None:
        # The bug above was an arity mismatch between the script and its
        # callers, which no test compared. Assert the contract directly.
        workflow_call = re.search(
            r"scripts/verify-control-sandbox-live-boundary\.sh \\\n((?:\s+\S+ \\\n)*\s+\S+)",
            WORKFLOW_PATH.read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(workflow_call, "workflow no longer invokes the live-boundary script")
        assert workflow_call is not None
        workflow_args = [
            line.strip().rstrip("\\").strip()
            for line in workflow_call.group(1).splitlines()
            if line.strip()
        ]
        self.assertEqual(len(workflow_args), 3, workflow_args)
        self.assertEqual(workflow_args[-1], "pre-apply")

        first_apply_call = re.search(
            r'"\$repo_root/scripts/verify-control-sandbox-live-boundary\.sh" \\\n((?:\s+\S+ \\\n)*\s+\S+)',
            VERIFY_PATH.read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(first_apply_call, "first-apply no longer invokes the live-boundary script")
        assert first_apply_call is not None
        first_apply_args = [
            line.strip().rstrip("\\").strip()
            for line in first_apply_call.group(1).splitlines()
            if line.strip()
        ]
        self.assertEqual(len(first_apply_args), 2, first_apply_args)

    def test_live_boundary_checks_control_and_authority_runtime_namespaces(self) -> None:
        source = LIVE_BOUNDARY_PATH.read_text(encoding="utf-8")
        self.assertIn('authority_prefix="layerv-nhp-sandbox-ca-"', source)
        self.assertEqual(source.count("startswith($authority_prefix)"), 2)

    def test_workflow_is_sandbox_only_saved_plan_and_transition_agnostic(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertNotIn("AWS_ACCOUNT_ID:", workflow)
        self.assertRegex(
            workflow,
            r"(?s)name: Upload immutable saved plan.*?retention-days: 2",
        )
        for marker in (
            "group: deploy-sandbox-infra",
            "cancel-in-progress: false",
            "environment: sandbox",
            "source_plan_run_id",
            "planned_state_version_id",
            "planned_state_serial",
            "planned_state_sha256",
            "plan-refresh-only",
            "PLAN_SANDBOX_CONTROL_REFRESH_ONLY",
            "APPLY_SANDBOX_CONTROL_UPDATE",
            "actions/download-artifact@",
            "run-id: ${{ inputs.source_plan_run_id }}",
            "artifact-verify",
            "source-run",
            "Re-read live main and consume saved plan immediately before exact apply",
            "capture-control-update-state.sh",
            "check-control-aws-identity.sh",
            "verify-control-sandbox-live-boundary.sh",
            "terraform apply -input=false -lock-timeout=5m -no-color",
            "plan_mode=(-refresh-only)",
            "normalization-drift",
            "normalization_drift_kind",
            "jq -cS",
            "live-refresh-drift-summary.raw.json",
            "Apply reruns are forbidden",
            "actions: write",
            "actions/artifacts/$artifact_id",
            "Dispatch a new `plan` from current main and current live state",
            "control-sandbox-update-post-apply-state-${{ github.run_id }}",
            "Do not replay the consumed saved plan",
            "Dispatch `verify` from current main",
            "Production Control remains blocked on the state migration in #3279",
            "generate-connector-authority-runtime-contract.py",
            "sandbox-measurement-basis.json",
            "authority-runtime.generated.tfvars.json",
            "--runtime-contract",
            "-var-file=authority-runtime.generated.tfvars.json",
            '-var-file="$RUNNER_TEMP/authority-runtime.generated.tfvars.json"',
            "Verified Authority runtime input differs from the reviewed plan input",
            "proof_mutation_controls_enabled",
            "Dark proof mutation capability requires the Authority runtime functions gate.",
        ):
            self.assertIn(marker, workflow)
        self.assertEqual(workflow.count("fetch-depth: 0"), 3)
        self.assertEqual(
            workflow.count("generate-connector-authority-runtime-contract.py"),
            3,
        )
        # Three generator call sites (plan/apply/verify) plus one in the guard,
        # which binds these same seven gate names to the committed
        # .github/control-sandbox-runtime-gates.json before any AWS access. The
        # generator count above stays at 3 and is what pins the contract-
        # producing sites; this looser count would otherwise be the only thing
        # standing between a fourth occurrence and a fifth, so assert the guard
        # binding positively rather than trusting the number alone.
        self.assertEqual(
            workflow.count("--proof-mutation-controls-enabled"),
            4,
        )
        self.assertIn("control-sandbox-runtime-gates.py check", workflow)
        # The gate binding lives in `guard`, so it only BLOCKS anything while
        # every AWS-touching job still depends on that job. Drop an edge and the
        # binding still runs and still passes — it just stops gating, which is
        # the failure mode no content assertion can see.
        for job in ("plan", "apply", "verify"):
            job_block = workflow.split(f"\n  {job}:\n", 1)[1].split("\n    steps:", 1)[0]
            self.assertIn(
                "needs: guard",
                job_block,
                f"{job} must depend on guard, or the gate binding does not gate it",
            )
        gate_binding = workflow.split(
            "      - name: Bind dispatch gates to the committed gate file\n", 1
        )[1]
        for gate_flag in (
            "--enable-runtime-functions",
            "--hub-edge-enabled",
            "--hub-worker-enabled",
            "--proof-mutation-controls-enabled",
            "--proof-policy-consumers-staged",
            "--proof-policy-selected-color",
            "--proof-policy-prepared-color",
        ):
            self.assertIn(gate_flag, gate_binding)
        self.assertNotIn("--proof-controller-role-arn", workflow)
        self.assertNotIn("AUTHORITY_PROOF_CONTROLLER_ROLE_ARN", workflow)
        # Still exactly the three AWS-touching jobs (plan/apply/verify). The
        # guard's checkout is source-only and deliberately carries no
        # environment, so this count must NOT move with the checkout count below.
        self.assertEqual(workflow.count("environment: sandbox"), 3)
        # Four checkouts now: plan, apply, verify, and the guard's source-only
        # one for the gate-file binding. Pin the invariant rather than the
        # number — EVERY checkout must decline credentials, so a fifth one added
        # without persist-credentials: false fails here even though a bare count
        # bumped to 4 would have let it through.
        self.assertEqual(
            workflow.count("uses: actions/checkout@"),
            workflow.count("persist-credentials: false"),
        )
        self.assertEqual(workflow.count("persist-credentials: false"), 4)
        self.assertNotIn("persist-credentials: true", workflow)
        self.assertNotIn("ensure-control-otp-pepper.sh", workflow)
        self.assertNotIn("check-control-global-routing.sh", workflow)
        self.assertIn("secret-verification-summary.json", workflow)
        apply_guard = workflow.split("            apply)\n", 1)[1].split(
            "              ;;\n            verify)", 1
        )[0]
        self.assertIn("GITHUB_RUN_ATTEMPT", apply_guard)
        self.assertIn("== '1'", apply_guard)
        refresh_guard = workflow.split("            plan-refresh-only)\n", 1)[1].split(
            "              ;;\n            apply)", 1
        )[0]
        self.assertIn("PLAN_SANDBOX_CONTROL_REFRESH_ONLY", refresh_guard)
        self.assertIn('[[ -z "$selectors" ]]', refresh_guard)

        # The single-use invariant must also live in the apply job itself: a
        # dependency job's guard does not protect a dependent job from GitHub's
        # partial "Re-run failed jobs", which re-runs apply at attempt >= 2
        # without re-running guard. Pin the attempt guard as the apply job's own
        # first step, ahead of the checkout, so a consumed plan cannot be replayed.
        apply_job = workflow.split("\n  apply:\n", 1)[1].split("\n  verify:\n", 1)[0]
        self.assertIn("GITHUB_RUN_ATTEMPT", apply_job)
        self.assertIn("== '1'", apply_job)
        self.assertLess(
            apply_job.index("GITHUB_RUN_ATTEMPT"),
            apply_job.index("Checkout planned main commit"),
        )
        for forbidden in (
            "environment: production",
            "AWS_PROD_ROLE_ARN",
            "terraform/control/environments/prod",
            "recover-plan",
            "recover-apply",
            "41 creates",
            "43 resources",
            "45 resources",
        ):
            self.assertNotIn(forbidden, workflow)

        apply_index = workflow.index("terraform apply -input=false")
        final_main = workflow.rfind("scripts/check-live-main-ref.sh", 0, apply_index)
        final_credentials = workflow.rfind(
            "scripts/check-no-checkout-credentials.sh", 0, apply_index
        )
        final_state = workflow.rfind(
            "scripts/capture-control-update-state.sh", 0, apply_index
        )
        live_boundary = workflow.rfind(
            "scripts/verify-control-sandbox-live-boundary.sh", 0, apply_index
        )
        artifact_delete = workflow.rfind(
            "actions/artifacts/$artifact_id", 0, apply_index
        )
        self.assertLess(live_boundary, final_main)
        self.assertLess(final_main, final_credentials)
        self.assertLess(final_main, artifact_delete)
        self.assertLess(artifact_delete, final_credentials)
        self.assertLess(final_credentials, final_state)
        self.assertLess(final_state, apply_index)

        upload_start = workflow.index("- name: Upload immutable saved plan")
        upload_end = workflow.index("- name: Summarize separate reviewed apply dispatch")
        upload = workflow[upload_start:upload_end]
        self.assertIn("tfplan", upload)
        self.assertIn("planned-state-summary.json", upload)
        self.assertNotIn("tfplan.json", upload)
        self.assertNotIn("state.tfstate", upload)
        self.assertNotIn("state.json", upload)

        self.assertIn(
            '"$RUNNER_TEMP/control-state-before-plan/state.tfstate"', workflow
        )
        self.assertIn(
            'tfplan.json "$RUNNER_TEMP/control-state-before-plan/state.json"',
            workflow,
        )
        self.assertIn(
            '"$RUNNER_TEMP/control-state-before-apply/state.tfstate"', workflow
        )
        self.assertIn(
            '"$RUNNER_TEMP/control-state-before-apply/state.json"', workflow
        )
        live_refresh = workflow.index(
            "      - name: Re-prove exact live refresh observation before apply"
        )
        consume = workflow.index(
            "      - name: Re-read live main and consume saved plan immediately before exact apply"
        )
        self.assertLess(live_boundary, live_refresh)
        self.assertLess(live_refresh, consume)
        live_refresh_step = workflow[live_refresh:consume]
        for marker in (
            "terraform plan -refresh-only",
            "live-refresh-plan.json",
            "control-state-before-apply/state.json",
            "live-refresh-contract-summary.json",
            "live-refresh-drift-summary.raw.json",
            "publisher-role:1|hub-publisher-role:1|authority-digest:1|hub-digest:1|authority-and-hub-digest:2|redis-passwords:2|authority-enablement-normalization:2|authority-runtime-slice-normalization:*|authority-alias-refresh:*|hub-task-selected-projection:1|hub-task-selected-projection-with-authority-digest:2|authority-runtime-slice-with-authority-digest:*|authority-proof-concurrency-recovery:*|authority-proof-rollout-prepare-recovery:*",
            "publisher-role|hub-publisher-role|redis-passwords)",
        ):
            self.assertIn(marker, live_refresh_step)

        authority_drift_case = live_refresh_step.split(
            "            authority-digest|hub-digest|authority-and-hub-digest|authority-enablement-normalization|authority-proof-concurrency-recovery|authority-proof-rollout-prepare-recovery)\n",
            1,
        )[1].split("              ;;\n", 1)[0]
        self.assertEqual(live_refresh_step.count("authority-and-hub-digest"), 2)
        raw_summary = (
            '>"$RUNNER_TEMP/live-refresh-drift-summary.raw.json"'
        )
        canonicalize_live = (
            'jq -cS . "$RUNNER_TEMP/live-refresh-drift-summary.raw.json"'
        )
        canonicalize_expected = "jq -cS '{"
        compare_summaries = (
            'cmp "$RUNNER_TEMP/expected-refresh-drift-summary.json"'
        )
        self.assertEqual(authority_drift_case.count("jq -cS"), 2)
        self.assertNotIn("exit 0", authority_drift_case)
        self.assertLess(
            authority_drift_case.index("normalization-drift"),
            authority_drift_case.index(raw_summary),
        )
        self.assertLess(
            authority_drift_case.index(raw_summary),
            authority_drift_case.index(canonicalize_live),
        )
        self.assertLess(
            authority_drift_case.index(canonicalize_live),
            authority_drift_case.index(canonicalize_expected),
        )
        self.assertLess(
            authority_drift_case.index(canonicalize_expected),
            authority_drift_case.index(compare_summaries),
        )

        for session_name, capture_marker in (
            ("control-update-plan-${GITHUB_RUN_ID}", "control-state-before-plan"),
            ("control-update-apply-${GITHUB_RUN_ID}", "control-state-before-apply"),
            ("control-update-verify-${GITHUB_RUN_ID}", "control-state-before-verify"),
        ):
            with self.subTest(session_name=session_name):
                identity_index = workflow.index(
                    f'check-control-aws-identity.sh sandbox "{session_name}"'
                )
                state_index = workflow.index(capture_marker, identity_index)
                self.assertLess(identity_index, state_index)

    def test_refresh_verifier_uses_remote_state_lock(self) -> None:
        verifier = VERIFY_PATH.read_text(encoding="utf-8")
        self.assertIn("-lock-timeout=5m", verifier)
        self.assertIn('-var-file="$runtime_contract_var_file"', verifier)
        self.assertIn("verified runtime tfvars must be a regular non-symlink", verifier)
        self.assertNotIn("-lock=false", verifier)
        self.assertIn("verify-control-sandbox-live-boundary.sh", verifier)

    def test_all_security_helpers_are_watched_shellchecked_and_tested(self) -> None:
        validate = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        boundary = validate.split(
            "      - name: Test sandbox Control foundation boundary\n", 1
        )[1].split("\n      - name:", 1)[0]
        for helper in (
            "scripts/capture-control-update-state.sh",
            "scripts/check-control-aws-identity.sh",
            "scripts/check-live-main-ref.sh",
            "scripts/check-no-checkout-credentials.sh",
            "scripts/verify-control-otp-pepper.sh",
            "scripts/verify-control-sandbox-first-apply.sh",
            "scripts/verify-control-sandbox-live-boundary.sh",
        ):
            self.assertIn(f'- "{helper}"', validate)
            self.assertIn(helper, boundary)
            self.assertIn(helper, makefile)
        self.assertIn("test_check_control_update.py", boundary)
        self.assertIn("test_check_control_update.py", makefile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
