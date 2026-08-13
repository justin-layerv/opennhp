#!/usr/bin/env python3
"""Fixture coverage for scripts/check-claude-model-lockstep.py."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts/check-claude-model-lockstep.py"
CLAUDE_ACTION_REF = "c038e4dcdedfbbca18dfb17df35a17e40ded4ddc"
ACTION_REF_HINT = (
    "Claude action pin mismatch. The expected SHA is hardcoded on purpose: it "
    "is a tamper fence, not a cache, so it must not be derived from the "
    "workflows a bump edits. Dependabot cannot green its own bump — re-prove "
    "the guarded action properties, then update CLAUDE_ACTION_REF here and "
    "PROVEN_ACTION_REF in scripts/check-claude-model-lockstep.py in the same "
    'PR. See "Updating the Claude workflow contract" in '
    ".github/workflows/README.md."
)
REVIEW_EVENTS = ("opened", "synchronize", "reopened", "ready_for_review")
REVIEW_JOB_IF = (
    "github.event.pull_request.user.type != 'Bot' &&\n"
    "github.event.pull_request.draft == false &&\n"
    "github.event.pull_request.head.repo.full_name == github.repository &&\n"
    "github.event.pull_request.base.repo.full_name == github.repository\n"
)
REVIEW_CONCURRENCY_GROUP = "claude-review-${{ github.event.pull_request.number }}"
COMMAND_CONCURRENCY_GROUP = (
    "claude-command-${{ github.event.issue.number }}"
)
PR_MERGE_REF_EVENTS = frozenset(
    {"pull_request", "pull_request_review", "pull_request_review_comment"}
)
WORKFLOWS = (
    Path(".github/workflows/claude.yml"),
    Path(".github/workflows/claude-code-review.yml"),
)
AUTOMATIC_REVIEW_ARGS = (
    '--model claude-opus-4-8 --disallowed-tools "Bash,Read,Glob,Grep,LS,Task,'
    "Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch,"
    "mcp__github_file_ops__commit_files,mcp__github_file_ops__delete_files,"
    "mcp__github__create_or_update_file,mcp__github__push_files,"
    'mcp__github__delete_file" --allowed-tools "mcp__github__get_pull_request,'
    "mcp__github__get_pull_request_diff,mcp__github__get_pull_request_files,"
    "mcp__github__get_pull_request_review_comments,"
    "mcp__github__get_pull_request_reviews,mcp__github__get_pull_request_status,"
    "mcp__github__get_file_contents,mcp__github__get_issue,"
    "mcp__github__get_issue_comments,mcp__github__search_issues,"
    "mcp__github__search_pull_requests,mcp__github__list_issues,"
    'mcp__github__list_pull_requests,mcp__github__add_issue_comment"'
)


class ClaudeModelLockstepTest(unittest.TestCase):
    def run_checker(
        self,
        values: tuple[str | None, str | None],
        extra_values: tuple[str, ...] = (),
        args_style: str = "quoted",
        extra_action: bool = False,
        omit_second: bool = False,
        invalid_utf8: bool = False,
        uses_quote: str = "",
        native_model: str | None = None,
        native_model_key: str = "model",
        prompt_mentions_model: bool = False,
        prompt_mentions_action: bool = False,
        omit_with: bool = False,
        extra_with: bool = False,
        action_without_step: bool = False,
        with_before_uses_sequence: bool = False,
        flow_with: bool = False,
        extra_uses_repository: str | None = None,
        action_refs: tuple[str, str] = (CLAUDE_ACTION_REF, CLAUDE_ACTION_REF),
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entries = list(zip(WORKFLOWS, values, strict=True))
            if omit_second:
                entries = entries[:1]
            entries.extend(
                (Path(f".github/workflows/claude-extra-{index}.yaml"), value)
                for index, value in enumerate(extra_values)
            )
            for path, value in entries:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                if value is None:
                    args = ""
                elif args_style == "quoted":
                    args = f"          claude_args: '{value}'\n"
                elif args_style == "unquoted":
                    args = f"          claude_args: {value}\n"
                elif args_style == "block":
                    args = f"          claude_args: >\n            {value}\n"
                elif args_style == "double":
                    args = f'          claude_args: "{value}"\n'
                else:
                    raise ValueError(f"unsupported args_style: {args_style}")
                if uses_quote not in {"", "'", '"'}:
                    raise ValueError(f"unsupported uses_quote: {uses_quote}")
                action_repository = (
                    extra_uses_repository
                    if extra_uses_repository is not None and path not in WORKFLOWS
                    else "anthropics/claude-code-action"
                )
                action_ref = (
                    action_refs[WORKFLOWS.index(path)]
                    if path in WORKFLOWS
                    else CLAUDE_ACTION_REF
                )
                action = f"{uses_quote}{action_repository}@{action_ref}{uses_quote}"
                additional_action = f"      - uses: {action}\n" if extra_action else ""
                native_model_input = (
                    f"          {native_model_key}: {native_model}\n"
                    if native_model
                    else ""
                )
                prompt_input = (
                    "          prompt: |\n"
                    "            with:\n"
                    "              model: prose-not-an-action-input\n"
                    if prompt_mentions_model
                    else ""
                )
                if prompt_mentions_action:
                    prompt_input += (
                        "          prompt: |\n"
                        "            uses: anthropics/claude-code-action@prose-only\n"
                    )
                step_prefix = "      " if action_without_step else "      - "
                with_mapping = "" if omit_with else "        with:\n"
                duplicate_with = "        with:\n" if extra_with else ""
                inputs = native_model_input + prompt_input + args
                if omit_with:
                    inputs = ""
                if action_without_step:
                    job_inputs = "".join(
                        line[4:] if line.strip() else line
                        for line in inputs.splitlines(keepends=True)
                    )
                    contents = (
                        f"jobs:\n  claude:\n    uses: {action}\n    with:\n{job_inputs}"
                    )
                elif flow_with:
                    contents = (
                        "jobs:\n"
                        "  claude:\n"
                        "    steps:\n"
                        f"      - uses: {action}\n"
                        f"        with: {{claude_args: '{value}'}}\n"
                    )
                elif with_before_uses_sequence:
                    contents = (
                        "jobs:\n"
                        "  claude:\n"
                        "    steps:\n"
                        "      - name: Claude\n"
                        "        with:\n"
                        "          allowed_tools:\n"
                        "            - Read\n"
                        f"{inputs}"
                        f"        uses: {action}\n"
                        f"{additional_action}"
                    )
                else:
                    contents = (
                        "jobs:\n"
                        "  claude:\n"
                        "    steps:\n"
                        f"{step_prefix}uses: {action}\n"
                        f"{with_mapping}"
                        f"{inputs}"
                        f"{duplicate_with}"
                        f"{additional_action}"
                    )
                target.write_text(contents, encoding="utf-8")
                if invalid_utf8 and path == WORKFLOWS[1]:
                    target.write_bytes(b"\xff")
            return subprocess.run(
                [sys.executable, str(CHECKER), "--repo-root", str(root)],
                capture_output=True,
                check=False,
                text=True,
            )

    def test_matching_models_pass_with_additional_arguments(self) -> None:
        result = self.run_checker(
            (
                "--model claude-opus-4-8",
                '--model claude-opus-4-8 --allowed-tools "Bash(gh pr view:*)"',
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("claude-opus-4-8", result.stdout)

    def test_equals_form_model_passes(self) -> None:
        result = self.run_checker(
            (
                "--model=claude-opus-4-8",
                "--model=claude-opus-4-8 --allowed-tools Read",
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_model_argument_need_not_be_first(self) -> None:
        result = self.run_checker(
            (
                "--allowed-tools Read --model claude-opus-4-8",
                "--allowed-tools Read --model=claude-opus-4-8",
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_different_models_fail(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-sonnet-4-6")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("model pins differ", result.stderr)

    def test_unproven_models_fail_even_when_in_lockstep(self) -> None:
        for model in ("claude-opus-4-8[1m]", "claude-sonnet-4-6"):
            with self.subTest(model=model):
                result = self.run_checker((f"--model {model}", f"--model {model}"))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is not proven for this credential", result.stderr)

    def test_missing_model_fails(self) -> None:
        result = self.run_checker(("--model claude-opus-4-8", None))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one single-quoted claude_args", result.stderr)

    def test_fewer_than_two_claude_workflows_fails(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            omit_second=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "expected at least two Claude action workflows, found 1", result.stderr
        )

    def test_malformed_shell_quoting_fails(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", '--model "claude-opus-4-8')
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid claude_args", result.stderr)

    def test_invalid_utf8_fails_without_traceback(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            invalid_utf8=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith("ERROR: "), result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_duplicate_model_fails(self) -> None:
        result = self.run_checker(
            (
                "--model claude-opus-4-8",
                "--model claude-opus-4-8 --model claude-opus-4-8",
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one --model", result.stderr)

    def test_native_model_input_fails_even_with_valid_claude_args(self) -> None:
        for key in ("model", "model ", "'model'", '"model"'):
            with self.subTest(key=key):
                result = self.run_checker(
                    ("--model claude-opus-4-8", "--model claude-opus-4-8"),
                    native_model="claude-opus-4-8[1m]",
                    native_model_key=key,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native model input is forbidden", result.stderr)
                self.assertIn("claude_args --model", result.stderr)

    def test_model_text_inside_prompt_is_not_a_native_input(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            prompt_mentions_model=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_action_text_inside_prompt_is_not_workflow_discovery(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            prompt_mentions_action=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_structured_walk_handles_sequence_before_uses(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            with_before_uses_sequence=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_model_without_value_fails(self) -> None:
        for invalid in (
            "--model",
            "--model=",
            '--model ""',
            "--model --allowed-tools Read",
        ):
            with self.subTest(invalid=invalid):
                result = self.run_checker(("--model claude-opus-4-8", invalid))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--model must have a value", result.stderr)

    def test_non_single_line_quoted_values_fail(self) -> None:
        values = ("--model claude-opus-4-8", "--model claude-opus-4-8")
        for args_style in ("unquoted", "block", "double"):
            with self.subTest(args_style=args_style):
                result = self.run_checker(values, args_style=args_style)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exactly one single-quoted claude_args", result.stderr)

    def test_new_claude_workflow_is_discovered(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            extra_values=("--model claude-sonnet-4-6",),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("claude-extra-0.yaml=claude-sonnet-4-6", result.stderr)

    def test_quoted_uses_values_are_discovered(self) -> None:
        for uses_quote in ("'", '"'):
            with self.subTest(uses_quote=uses_quote):
                result = self.run_checker(
                    ("--model claude-opus-4-8", "--model claude-opus-4-8"),
                    extra_values=("--model claude-sonnet-4-6",),
                    uses_quote=uses_quote,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("claude-extra-0.yaml=claude-sonnet-4-6", result.stderr)

    def test_action_repository_discovery_is_case_insensitive(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            extra_values=("--model claude-sonnet-4-6",),
            extra_uses_repository="Anthropics/Claude-Code-Action",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("claude-extra-0.yaml=claude-sonnet-4-6", result.stderr)

    def test_multiple_action_invocations_fail_clearly(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            extra_action=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one Claude action invocation, found 2", result.stderr)

    def test_missing_with_mapping_fails_clearly(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            omit_with=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("block-style with mapping", result.stderr)
        self.assertIn("found 0", result.stderr)

    def test_multiple_with_mappings_fail_clearly(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            extra_with=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("block-style with mapping", result.stderr)
        self.assertIn("found 2", result.stderr)

    def test_flow_style_with_mapping_is_rejected(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            flow_with=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("with must be one block-style mapping", result.stderr)

    def test_action_outside_workflow_step_fails_clearly(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            action_without_step=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Claude action is not inside a workflow step", result.stderr)

    def test_unproven_action_ref_fails(self) -> None:
        result = self.run_checker(
            ("--model claude-opus-4-8", "--model claude-opus-4-8"),
            action_refs=(CLAUDE_ACTION_REF, "unreviewed-action-ref"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("action refs must use proven SHA", result.stderr)
        self.assertIn("unreviewed-action-ref", result.stderr)


class ClaudeWorkflowRepositoryContractTest(unittest.TestCase):
    def load_contract(
        self, path: Path, job_name: str
    ) -> tuple[dict[str, object], dict[str, object], dict[str, dict[str, object]]]:
        workflow = yaml.safe_load((REPO_ROOT / path).read_text(encoding="utf-8"))
        self.assertIsInstance(workflow, dict)
        job = workflow["jobs"][job_name]
        self.assertIsInstance(job, dict)
        steps = job.get("steps")
        self.assertIsInstance(steps, list)
        by_name = {
            step["name"]: step
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("name"), str)
        }
        self.assertEqual(len(by_name), len(steps))
        return workflow, job, by_name

    def assert_fragments(self, text: str, *fragments: str) -> None:
        for fragment in fragments:
            self.assertIn(fragment, text)

    def assert_error_blocks_fail_closed(self, script: str) -> None:
        """Every Actions error must terminate before the next command runs."""
        lines = script.splitlines()
        error_indexes = [
            index for index, line in enumerate(lines) if "::error::" in line
        ]
        self.assertTrue(error_indexes, "expected at least one fail-closed error")
        for index in error_indexes:
            following = [line.strip() for line in lines[index + 1 :] if line.strip()]
            self.assertTrue(following, f"error at line {index + 1} has no exit")
            self.assertEqual(following[0], "exit 1")

    def run_git(
        self, workspace: Path, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=check,
        )

    def create_review_repository(
        self, root: Path, head_commits: int
    ) -> tuple[Path, str, str, str]:
        workspace = root / "workspace"
        workspace.mkdir()
        self.run_git(workspace, "init", "--quiet", "--initial-branch=main")
        self.run_git(workspace, "config", "user.name", "Claude Workflow Test")
        self.run_git(
            workspace,
            "config",
            "user.email",
            "claude-workflow@example.invalid",
        )
        history = workspace / "history.txt"
        settings = workspace / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text('{"source":"trusted-base"}\n', encoding="utf-8")
        for index in range(3):
            history.write_text(f"base {index}\n", encoding="utf-8")
            self.run_git(workspace, "add", "history.txt", ".claude/settings.json")
            self.run_git(workspace, "commit", "--quiet", "-m", f"base {index}")
        base_sha = self.run_git(workspace, "rev-parse", "HEAD").stdout.strip()

        head_ref = "feature/deep-review"
        self.run_git(workspace, "checkout", "--quiet", "-b", head_ref)
        settings.write_text('{"source":"pr-head"}\n', encoding="utf-8")
        for index in range(head_commits):
            history.write_text(f"head {index}\n", encoding="utf-8")
            self.run_git(workspace, "add", "history.txt", ".claude/settings.json")
            self.run_git(workspace, "commit", "--quiet", "-m", f"head {index}")
        head_sha = self.run_git(workspace, "rev-parse", "HEAD").stdout.strip()
        self.run_git(
            workspace,
            "remote",
            "add",
            "origin",
            "https://example.invalid/source.git",
        )
        return workspace, base_sha, head_sha, head_ref

    def assert_remote_head_verifier(
        self,
        step: dict[str, object],
        condition: str,
        pr_number: str,
        head_sha: str,
        base_sha: str,
        execution_file: str,
        local_origin: tuple[str, str, str] | None = None,
        source_refs: bool = False,
        expected_local_sha: str | None = None,
        review_marker: str | None = None,
        expected_default_branch: str | None = None,
    ) -> None:
        self.assertEqual(step["if"], condition)
        expected_env = {
            "GH_TOKEN": "${{ github.token }}",
            "PR_NUMBER": pr_number,
            "EXPECTED_HEAD_SHA": head_sha,
            "EXPECTED_BASE_SHA": base_sha,
            "EXECUTION_FILE": execution_file,
        }
        if local_origin:
            expected_env |= {
                "HEAD_REF": local_origin[0],
                "BASE_REF": local_origin[1],
                "LOCAL_ORIGIN": local_origin[2],
            }
        if expected_local_sha is not None:
            expected_env["EXPECTED_LOCAL_SHA"] = expected_local_sha
        if review_marker is not None:
            expected_env["EXPECTED_REVIEW_MARKER"] = review_marker
        if expected_default_branch is not None:
            expected_env["EXPECTED_DEFAULT_BRANCH"] = expected_default_branch
        self.assertEqual(step["env"], expected_env)
        script = step["run"]
        current_field_count = 8 if expected_default_branch is not None else 6
        self.assert_fragments(
            script,
            '[[ -z "${EXECUTION_FILE}" || ! -f "${EXECUTION_FILE}" || ! -s "${EXECUTION_FILE}" ]]',
            'timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"',
            ".head.repo.full_name",
            ".head.sha",
            ".head.ref",
            ".base.repo.full_name",
            ".base.sha",
            ".base.ref",
            f"${{#current_fields[@]}} != {current_field_count}",
            'local_head="$(git rev-parse HEAD 2>/dev/null)"',
            '"${current_head_repo}" != "${GITHUB_REPOSITORY}"',
            '"${current_base_repo}" != "${GITHUB_REPOSITORY}"',
            '"${current_head}" != "${EXPECTED_HEAD_SHA}"',
            '"${current_head_ref}" != "${HEAD_REF}"',
            '"${current_base}" != "${EXPECTED_BASE_SHA}"',
            '"${current_base_ref}" != "${BASE_REF}"',
        )
        if expected_default_branch is not None:
            self.assert_fragments(
                script,
                ".base.repo.default_branch",
                ".state",
                '"${current_pr_state}" != "open"',
                '"${current_default_branch}" != "${EXPECTED_DEFAULT_BRANCH}"',
                '"${current_head_ref}" == "${current_default_branch}"',
            )
        self.assert_error_blocks_fail_closed(script)
        if local_origin:
            self.assert_fragments(
                script,
                '[[ "${HEAD_REF}" == "@" || ! "${HEAD_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]',
                'git check-ref-format --branch "${HEAD_REF}"',
                '[[ "${BASE_REF}" == "@" || ! "${BASE_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]',
                'git check-ref-format --branch "${BASE_REF}"',
                "git remote get-url --all origin",
                "git remote get-url --push --all origin",
                "${#origin_urls[@]} != 1",
                "${#origin_push_urls[@]} != 1",
                '"${origin_urls[0]}" != "${LOCAL_ORIGIN}"',
                '"${origin_push_urls[0]}" != "${LOCAL_ORIGIN}"',
                "git config --local --get-all fetch.recurseSubmodules",
                "${#recurse_submodule_values[@]} != 1",
                '"${recurse_submodule_values[0]}" != "false"',
                'git rev-parse "refs/remotes/origin/${HEAD_REF}"',
                'git rev-parse "refs/remotes/origin/${BASE_REF}"',
                'git --git-dir="${LOCAL_ORIGIN}" rev-parse "refs/heads/${HEAD_REF}"',
                'git --git-dir="${LOCAL_ORIGIN}" rev-parse "refs/heads/${BASE_REF}"',
                '"${EXPECTED_HEAD_SHA}" != "${tracking_head}"',
                '"${EXPECTED_HEAD_SHA}" != "${origin_head}"',
                '"${EXPECTED_BASE_SHA}" != "${tracking_base}"',
                '"${EXPECTED_BASE_SHA}" != "${origin_base}"',
                "git config --local --get-regexp '^http\\..*\\.extraheader$'",
                "git config --local --get-regexp '^credential(\\..*)?\\.helper$'",
            )
            if source_refs:
                self.assert_fragments(
                    script,
                    'git rev-parse "refs/heads/${HEAD_REF}"',
                    'git rev-parse "refs/heads/${BASE_REF}"',
                    '"${EXPECTED_HEAD_SHA}" != "${source_head}"',
                    '"${EXPECTED_BASE_SHA}" != "${source_base}"',
                )
            if expected_local_sha is not None:
                self.assert_fragments(
                    script,
                    '[[ ! "${EXPECTED_LOCAL_SHA}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]',
                    '"${EXPECTED_LOCAL_SHA}" != "${local_head}"',
                )
            if review_marker is not None:
                self.assert_fragments(
                    script,
                    '[[ -z "${EXPECTED_REVIEW_MARKER}" ]]',
                    "timeout 30s gh api --paginate --slurp",
                    '"repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100"',
                    'select(.user.login == "github-actions[bot]")',
                    'rtrimstr("\\n" + $marker)',
                    'gsub("[[:space:]]"; "")',
                    "length > 0",
                    "did not publish the run-specific pull request comment",
                )
            self.assertLess(
                script.index("git remote get-url --all origin"),
                script.index("timeout 30s gh api"),
            )
        errors = [line for line in script.splitlines() if "::error::" in line]
        self.assertFalse(
            any(
                name in line
                for line in errors
                for name in (
                    "current_head",
                    "current_base",
                    "EXPECTED_HEAD_SHA",
                    "EXPECTED_BASE_SHA",
                    "local_head",
                    "tracking_head",
                    "tracking_base",
                    "origin_head",
                    "origin_base",
                )
            )
        )
        self.assertLess(
            script.index(
                '[[ -z "${EXECUTION_FILE}" || ! -f "${EXECUTION_FILE}" || ! -s "${EXECUTION_FILE}" ]]'
            ),
            script.index(
                'timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"'
            ),
        )

    def test_interactive_workflow_entry_contract(self) -> None:
        workflow, job, steps = self.load_contract(WORKFLOWS[0], "claude")
        # PyYAML 1.1 resolves an unquoted ``on`` key as boolean true.
        self.assertEqual(
            workflow[True],
            {"issue_comment": {"types": ["created"]}},
        )
        self.assertTrue(PR_MERGE_REF_EVENTS.isdisjoint(workflow[True]))
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(
            workflow["concurrency"],
            {"group": COMMAND_CONCURRENCY_GROUP, "cancel-in-progress": False},
        )
        self.assertEqual(job["timeout-minutes"], 20)
        self.assertEqual(
            job["permissions"],
            {
                "contents": "read",
                "pull-requests": "read",
                "issues": "read",
                "actions": "read",
                "id-token": "write",
            },
        )
        self.assertEqual(
            list(steps),
            [
                "Validate Claude trigger actor permission",
                "Resolve Claude pull request context",
                "Checkout",
                "Prepare credential-free local origin",
                "Run Claude Code",
                "Verify reviewed pull request head",
            ],
        )

        guard = job["if"]
        self.assert_fragments(
            guard,
            "github.event.issue.pull_request != null",
            "github.event.comment.body == '@claude'",
            "startsWith(github.event.comment.body, '@claude ')",
            "author_association == 'OWNER'",
            "author_association == 'MEMBER'",
            "author_association == 'COLLABORATOR'",
        )
        self.assertNotIn("github.event.review", guard)
        self.assertNotIn("contains(", guard)
        self.assertNotIn("github.event_name == 'issues'", guard)

    def test_interactive_actor_authority_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        actor = steps["Validate Claude trigger actor permission"]
        self.assertEqual(actor["id"], "claude_actor")
        self.assertEqual(
            actor["env"],
            {
                "GH_TOKEN": "${{ github.token }}",
                "TRIGGER_ACTOR": "${{ github.event.comment.user.login }}",
            },
        )
        self.assert_fragments(
            actor["run"],
            'timeout 30s gh api "repos/${GITHUB_REPOSITORY}/collaborators/${TRIGGER_ACTOR}/permission"',
            "admin|maintain|write",
            "authorized=true",
        )
        self.assert_error_blocks_fail_closed(actor["run"])
        self.assertLess(
            actor["run"].rfind("exit 1"), actor["run"].index("authorized=true")
        )

    def test_interactive_pr_snapshot_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        resolve = steps["Resolve Claude pull request context"]
        self.assertEqual(
            resolve["if"],
            "success() && steps.claude_actor.outputs.authorized == 'true'",
        )
        self.assertEqual(
            resolve["env"],
            {
                "GH_TOKEN": "${{ github.token }}",
                "PR_NUMBER": "${{ github.event.issue.number }}",
            },
        )
        self.assert_fragments(
            resolve["run"],
            'timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"',
            ".head.repo.full_name",
            ".head.sha",
            ".head.ref",
            ".base.repo.full_name",
            ".base.sha",
            ".base.ref",
            ".commits",
            ".base.repo.default_branch",
            ".state",
            "${#pr_fields[@]} != 9",
            'elif [[ "${head_repo}" != "${GITHUB_REPOSITORY}" ]]; then',
            'elif [[ "${base_repo}" != "${GITHUB_REPOSITORY}" ]]; then',
            'elif [[ "${pr_state}" != "open" ]]; then',
            'git check-ref-format --branch "${default_branch}"',
            'elif [[ ! "${head_sha}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then',
            'elif [[ ! "${base_sha}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then',
            '[[ "${head_ref}" == "@" || ! "${head_ref}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]',
            'git check-ref-format --branch "${head_ref}"',
            'elif [[ "${head_ref}" == "${default_branch}" ]]; then',
            '[[ "${base_ref}" == "@" || ! "${base_ref}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]',
            'git check-ref-format --branch "${base_ref}"',
            '"${head_ref}" == "${base_ref}"',
            '[[ ! "${commit_count}" =~ ^[0-9]+$ ]]',
            "head_fetch_depth=$(( commit_count > 20 ? commit_count : 20 ))",
            "head_sha=${head_sha}",
            "head_ref=${head_ref}",
            "base_sha=${base_sha}",
            "base_ref=${base_ref}",
            "default_branch=${default_branch}",
            "head_fetch_depth=${head_fetch_depth}",
            "checkout_allowed=true",
        )
        self.assert_error_blocks_fail_closed(resolve["run"])
        self.assertLess(
            resolve["run"].rfind("exit 1"), resolve["run"].index("head_sha=${head_sha}")
        )

    def test_interactive_resolver_rejects_bare_at_ref(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        git_accepts_at = subprocess.run(
            ["git", "check-ref-format", "--branch", "@"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(git_accepts_at.returncode, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            mock_bin = temp / "bin"
            mock_bin.mkdir()
            gh = mock_bin / "gh"
            gh.write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "${GITHUB_REPOSITORY}" "${MOCK_HEAD_SHA}" '
                '"${MOCK_HEAD_REF}" "${GITHUB_REPOSITORY}" '
                '"${MOCK_BASE_SHA}" "${MOCK_BASE_REF}" 1 '
                '"${MOCK_DEFAULT_BRANCH}" "${MOCK_PR_STATE}"\n',
                encoding="utf-8",
            )
            gh.chmod(0o755)
            base_env = os.environ | {
                "PATH": f"{mock_bin}{os.pathsep}{os.environ['PATH']}",
                "GH_TOKEN": "test-token",
                "PR_NUMBER": "123",
                "GITHUB_REPOSITORY": "layervai/nhp",
                "GITHUB_OUTPUT": str(temp / "output"),
                "MOCK_HEAD_SHA": "a" * 40,
                "MOCK_BASE_SHA": "b" * 40,
                "MOCK_DEFAULT_BRANCH": "main",
                "MOCK_PR_STATE": "open",
            }
            for head_ref, base_ref, error in (
                ("@", "main", "PR head branch is invalid"),
                ("feature/review", "@", "PR base branch is invalid"),
                ("main", "release", "cannot write to the repository default branch"),
            ):
                with self.subTest(head_ref=head_ref, base_ref=base_ref):
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            steps["Resolve Claude pull request context"]["run"],
                        ],
                        cwd=REPO_ROOT,
                        env=base_env
                        | {"MOCK_HEAD_REF": head_ref, "MOCK_BASE_REF": base_ref},
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stdout)

            closed = subprocess.run(
                ["bash", "-c", steps["Resolve Claude pull request context"]["run"]],
                cwd=REPO_ROOT,
                env=base_env
                | {
                    "MOCK_HEAD_REF": "feature/review",
                    "MOCK_BASE_REF": "main",
                    "MOCK_PR_STATE": "closed",
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(closed.returncode, 0)
            self.assertIn("currently open pull request", closed.stdout)

    def test_interactive_checkout_and_local_origin_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        checkout = steps["Checkout"]
        self.assertEqual(
            checkout["if"],
            "success() && steps.claude_actor.outputs.authorized == 'true' && "
            "steps.claude_pr.outputs.checkout_allowed == 'true'",
        )
        self.assertFalse(
            any(fn in checkout["if"] for fn in ("always()", "failure()", "cancelled()"))
        )
        self.assertEqual(
            checkout["with"],
            {
                "ref": "${{ github.event.repository.default_branch }}",
                "fetch-depth": 0,
                "persist-credentials": False,
            },
        )

        local_origin = steps["Prepare credential-free local origin"]
        self.assertEqual(
            local_origin["if"], "success() && steps.checkout.outcome == 'success'"
        )
        self.assertEqual(
            local_origin["env"],
            {
                "EXPECTED_HEAD_SHA": "${{ steps.claude_pr.outputs.head_sha }}",
                "HEAD_REF": "${{ steps.claude_pr.outputs.head_ref }}",
                "EXPECTED_BASE_SHA": "${{ steps.claude_pr.outputs.base_sha }}",
                "BASE_REF": "${{ steps.claude_pr.outputs.base_ref }}",
                "HEAD_FETCH_DEPTH": "${{ steps.claude_pr.outputs.head_fetch_depth }}",
                "EXPECTED_DEFAULT_BRANCH": "${{ steps.claude_pr.outputs.default_branch }}",
                "TRUSTED_REF": "${{ github.event.repository.default_branch }}",
                "LOCAL_ORIGIN": "${{ runner.temp }}/claude-local-origin-${{ github.run_id }}-${{ github.run_attempt }}.git",
            },
        )
        self.assert_fragments(
            local_origin["run"],
            '[[ -z "${TRUSTED_REF}" || "${TRUSTED_REF}" == "@"',
            'git check-ref-format --branch "${TRUSTED_REF}"',
            '[[ "${TRUSTED_REF}" != "${EXPECTED_DEFAULT_BRANCH}"',
            '"${HEAD_REF}" == "${EXPECTED_DEFAULT_BRANCH}"',
            'trusted_head="$(git rev-parse HEAD 2>/dev/null)"',
            'trusted_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"',
            'trusted_ref_head="$(git rev-parse "refs/heads/${TRUSTED_REF}" 2>/dev/null)"',
            '[[ "${trusted_branch}" != "${TRUSTED_REF}" || "${trusted_head}" != "${trusted_ref_head}" ]]',
            'git cat-file -e "${EXPECTED_HEAD_SHA}^{commit}"',
            'git cat-file -e "${EXPECTED_BASE_SHA}^{commit}"',
            "sensitive_paths=(",
            ".claude",
            ".mcp.json",
            ".claude.json",
            ".gitmodules",
            ".ripgreprc",
            "CLAUDE.md",
            "CLAUDE.local.md",
            ".husky",
            'git ls-tree -rz --full-tree "${EXPECTED_HEAD_SHA}"',
            '"${object_type}" != "blob"',
            '"${mode}" != "100644"',
            '"${mode}" != "100755"',
            "symlinks and gitlinks are rejected",
            'git checkout --detach "${trusted_head}"',
            'git branch --force "${HEAD_REF}" "${EXPECTED_HEAD_SHA}"',
            'git branch --force "${BASE_REF}" "${EXPECTED_BASE_SHA}"',
            "git symbolic-ref --quiet HEAD",
            'object_format="$(git rev-parse --show-object-format)"',
            'git init --bare --object-format="${object_format}" "${LOCAL_ORIGIN}"',
            'fetch --no-tags --no-recurse-submodules "${GITHUB_WORKSPACE}"',
            '"refs/heads/${HEAD_REF}:refs/heads/${HEAD_REF}"',
            '"refs/heads/${BASE_REF}:refs/heads/${BASE_REF}"',
            'git remote set-url origin "${LOCAL_ORIGIN}"',
            "git config fetch.recurseSubmodules false",
            'git fetch origin "--depth=${HEAD_FETCH_DEPTH}" "${HEAD_REF}"',
            'git fetch origin "${BASE_REF}" --depth=1 --no-recurse-submodules',
            'git --git-dir="${LOCAL_ORIGIN}" rev-parse "refs/heads/${BASE_REF}"',
            '[[ "$(git rev-parse HEAD)" != "${trusted_head}" ]]',
            "git symbolic-ref --quiet HEAD >/dev/null 2>&1",
            "checked out pull-request code before the pinned action",
        )
        helper_guard = "git config --local --get-regexp '^credential(\\..*)?\\.helper$'"
        extraheader_guard = (
            "git config --local --get-regexp '^http\\..*\\.extraheader$'"
        )
        self.assertEqual(local_origin["run"].count(helper_guard), 2)
        self.assertEqual(local_origin["run"].count(extraheader_guard), 2)
        self.assertLess(
            local_origin["run"].index(helper_guard),
            local_origin["run"].index('git fetch origin "--depth=${HEAD_FETCH_DEPTH}"'),
        )
        self.assertGreater(
            local_origin["run"].rindex(helper_guard),
            local_origin["run"].index('git fetch origin "${BASE_REF}" --depth=1'),
        )
        self.assertNotIn("github.com", local_origin["run"])
        self.assertEqual(local_origin["run"].count("git checkout"), 1)
        self.assertNotIn('git checkout "${HEAD_REF}"', local_origin["run"])
        self.assertNotIn('git checkout "${EXPECTED_HEAD_SHA}"', local_origin["run"])
        self.assertLess(
            local_origin["run"].index('git fetch origin "--depth=${HEAD_FETCH_DEPTH}"'),
            local_origin["run"].index('git fetch origin "${BASE_REF}" --depth=1'),
        )

    def test_interactive_action_and_terminal_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        action = steps["Run Claude Code"]
        self.assertEqual(action["id"], "claude")
        self.assertEqual(action["if"], "success()")
        self.assertEqual(
            action["uses"],
            f"anthropics/claude-code-action@{CLAUDE_ACTION_REF}",
            ACTION_REF_HINT,
        )
        self.assertEqual(
            set(action["with"]),
            {
                "anthropic_api_key",
                "use_commit_signing",
                "exclude_comments_by_actor",
                "claude_args",
            },
        )
        self.assertIs(action["with"]["use_commit_signing"], True)
        self.assertEqual(
            action["with"]["exclude_comments_by_actor"], "github-actions[bot]"
        )
        self.assert_remote_head_verifier(
            steps["Verify reviewed pull request head"],
            "success() && steps.claude.outcome == 'success'",
            "${{ github.event.issue.number }}",
            "${{ steps.claude_pr.outputs.head_sha }}",
            "${{ steps.claude_pr.outputs.base_sha }}",
            "${{ steps.claude.outputs.execution_file }}",
            (
                "${{ steps.claude_pr.outputs.head_ref }}",
                "${{ steps.claude_pr.outputs.base_ref }}",
                "${{ runner.temp }}/claude-local-origin-${{ github.run_id }}-${{ github.run_attempt }}.git",
            ),
            source_refs=True,
            expected_default_branch="${{ steps.claude_pr.outputs.default_branch }}",
        )

    def test_local_origin_runtime_contract(self) -> None:
        """Exercise trusted staging plus the action's head/base lifecycle."""
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            workspace, base_sha, head_sha, head_ref = self.create_review_repository(
                temp, head_commits=25
            )
            local_origin = temp / "local-origin.git"
            mock_bin = temp / "bin"
            execution_file = temp / "execution.json"
            mock_bin.mkdir()

            def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
                return self.run_git(workspace, *args, check=check)

            # Mirror actions/checkout's trusted default-branch workspace while
            # retaining the PR head as a fetched object, not a checked-out tree.
            git("checkout", "--quiet", "main")
            git("update-ref", f"refs/remotes/source/{head_ref}", head_sha)
            git("branch", "-D", head_ref)

            runtime_env = os.environ | {
                "EXPECTED_HEAD_SHA": head_sha,
                "HEAD_REF": head_ref,
                "EXPECTED_BASE_SHA": base_sha,
                "BASE_REF": "main",
                "HEAD_FETCH_DEPTH": "25",
                "EXPECTED_DEFAULT_BRANCH": "main",
                "TRUSTED_REF": "main",
                "LOCAL_ORIGIN": str(local_origin),
                "GITHUB_WORKSPACE": str(workspace),
                "RUNNER_TEMP": str(temp),
            }
            for mutation in (
                {"EXPECTED_DEFAULT_BRANCH": "release"},
                {"HEAD_REF": "main"},
            ):
                rejected = subprocess.run(
                    [
                        "bash",
                        "-c",
                        steps["Prepare credential-free local origin"]["run"],
                    ],
                    cwd=workspace,
                    env=runtime_env | mutation,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("trusted default-branch identity", rejected.stdout)

            prepared = subprocess.run(
                ["bash", "-c", steps["Prepare credential-free local origin"]["run"]],
                cwd=workspace,
                env=runtime_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self.assertEqual(git("rev-parse", "HEAD").stdout.strip(), base_sha)
            self.assertNotEqual(
                git(
                    "symbolic-ref", "--quiet", "--short", "HEAD", check=False
                ).returncode,
                0,
            )
            self.assertEqual(
                (workspace / ".claude" / "settings.json").read_text(encoding="utf-8"),
                '{"source":"trusted-base"}\n',
            )
            self.assertEqual(
                git("remote", "get-url", "origin").stdout.strip(), str(local_origin)
            )
            self.assertEqual(
                git(
                    "config", "--local", "--get", "fetch.recurseSubmodules"
                ).stdout.strip(),
                "false",
            )
            expected_refs = {
                f"refs/heads/{head_ref}": head_sha,
                "refs/heads/main": base_sha,
                f"refs/remotes/origin/{head_ref}": head_sha,
                "refs/remotes/origin/main": base_sha,
            }
            for ref, expected_sha in expected_refs.items():
                self.assertEqual(git("rev-parse", ref).stdout.strip(), expected_sha)
            bare_refs = {
                f"refs/heads/{head_ref}": head_sha,
                "refs/heads/main": base_sha,
            }
            for ref, expected_sha in bare_refs.items():
                actual = subprocess.run(
                    ["git", f"--git-dir={local_origin}", "rev-parse", ref],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
                self.assertEqual(actual, expected_sha)
            self.assertEqual(
                git(
                    "rev-list", "--count", f"refs/remotes/origin/{head_ref}"
                ).stdout.strip(),
                "25",
            )
            self.assertEqual(
                git("rev-list", "--count", "refs/remotes/origin/main").stdout.strip(),
                "1",
            )

            # Pinned v1.0.186 tag mode fetches and checks out the same-repo PR
            # branch, then restores startup-sensitive paths from the exact base
            # ref in the credential-free local origin before Claude starts.
            git("fetch", "origin", "--depth=25", head_ref)
            git("checkout", head_ref, "--")
            self.assertEqual(git("rev-parse", "HEAD").stdout.strip(), head_sha)
            self.assertEqual(
                (workspace / ".claude" / "settings.json").read_text(encoding="utf-8"),
                '{"source":"pr-head"}\n',
            )
            shutil.rmtree(workspace / ".claude")
            git("fetch", "origin", "main", "--depth=1", "--no-recurse-submodules")
            git("checkout", "origin/main", "--", ".claude")
            git("reset", "--", ".claude")
            self.assertEqual(git("rev-parse", "HEAD").stdout.strip(), head_sha)
            self.assertEqual(
                (workspace / ".claude" / "settings.json").read_text(encoding="utf-8"),
                '{"source":"trusted-base"}\n',
            )

            gh = mock_bin / "gh"
            gh.write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "${CURRENT_HEAD_REPO}" "${CURRENT_HEAD_SHA}" '
                '"${CURRENT_HEAD_REF}" "${CURRENT_BASE_REPO}" '
                '"${CURRENT_BASE_SHA}" "${CURRENT_BASE_REF}" '
                '"${CURRENT_DEFAULT_BRANCH}" "${CURRENT_PR_STATE}"\n',
                encoding="utf-8",
            )
            gh.chmod(0o755)
            execution_file.write_text("completed\n", encoding="utf-8")
            verifier_env = runtime_env | {
                "PATH": f"{mock_bin}{os.pathsep}{runtime_env['PATH']}",
                "GH_TOKEN": "test-token",
                "PR_NUMBER": "123",
                "GITHUB_REPOSITORY": "layervai/nhp",
                "EXECUTION_FILE": str(execution_file),
                "CURRENT_HEAD_REPO": "layervai/nhp",
                "CURRENT_HEAD_SHA": head_sha,
                "CURRENT_HEAD_REF": head_ref,
                "CURRENT_BASE_REPO": "layervai/nhp",
                "CURRENT_BASE_SHA": base_sha,
                "CURRENT_BASE_REF": "main",
                "CURRENT_DEFAULT_BRANCH": "main",
                "CURRENT_PR_STATE": "open",
                "EXPECTED_DEFAULT_BRANCH": "main",
            }
            verifier = steps["Verify reviewed pull request head"]["run"]
            verified = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env | {"CURRENT_HEAD_SHA": base_sha},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("head or base changed during Claude review", rejected.stdout)

            for mutation in (
                {"CURRENT_HEAD_REF": "main"},
                {"CURRENT_DEFAULT_BRANCH": "release"},
                {"CURRENT_PR_STATE": "closed"},
            ):
                rejected = subprocess.run(
                    ["bash", "-c", verifier],
                    cwd=workspace,
                    env=verifier_env | mutation,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(
                    "head or base changed during Claude review", rejected.stdout
                )

            git("checkout", "--force", "--detach", base_sha)
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("head or base changed during Claude review", rejected.stdout)
            git("checkout", "--force", head_ref)

            git("update-ref", "refs/heads/main", head_sha)
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("head or base changed during Claude review", rejected.stdout)
            git("update-ref", "refs/heads/main", base_sha)

            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env | {"HEAD_REF": "@"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "terminal verification received invalid pull request refs",
                rejected.stdout,
            )

            git("config", "--local", "credential.https://github.com.helper", "store")
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "changed the credential-free repository configuration",
                rejected.stdout,
            )
            git(
                "config",
                "--local",
                "--unset-all",
                "credential.https://github.com.helper",
            )

            git(
                "remote",
                "set-url",
                "origin",
                "https://embedded.invalid@example.invalid/source.git",
            )
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("changed the credential-free local origin", rejected.stdout)

            git("remote", "set-url", "origin", str(local_origin))
            git(
                "remote",
                "set-url",
                "--add",
                "--push",
                "origin",
                "https://embedded.invalid@example.invalid/source.git",
            )
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("changed the credential-free local origin", rejected.stdout)

    def test_local_origin_requires_validated_snapshot_objects(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        for missing, expected_error in (
            ("head", "validated PR head commit is absent"),
            ("base", "validated PR base commit is absent"),
        ):
            with (
                self.subTest(missing=missing),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                temp = Path(temp_dir)
                workspace, base_sha, head_sha, head_ref = self.create_review_repository(
                    temp, head_commits=2
                )
                self.run_git(workspace, "checkout", "--quiet", "main")
                local_origin = temp / "local-origin.git"
                runtime_env = os.environ | {
                    "EXPECTED_HEAD_SHA": "0" * 40 if missing == "head" else head_sha,
                    "HEAD_REF": head_ref,
                    "EXPECTED_BASE_SHA": "0" * 40 if missing == "base" else base_sha,
                    "BASE_REF": "main",
                    "HEAD_FETCH_DEPTH": "20",
                    "EXPECTED_DEFAULT_BRANCH": "main",
                    "TRUSTED_REF": "main",
                    "LOCAL_ORIGIN": str(local_origin),
                    "GITHUB_WORKSPACE": str(workspace),
                    "RUNNER_TEMP": str(temp),
                }

                prepared = subprocess.run(
                    [
                        "bash",
                        "-c",
                        steps["Prepare credential-free local origin"]["run"],
                    ],
                    cwd=workspace,
                    env=runtime_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(prepared.returncode, 0)
                self.assertIn(expected_error, prepared.stdout)
                self.assertFalse(local_origin.exists())
                self.assertEqual(
                    self.run_git(workspace, "rev-parse", "HEAD").stdout.strip(),
                    base_sha,
                )

    def test_local_origin_rejects_nonregular_sensitive_tree_entries(self) -> None:
        """Fence v1.0.186's dereferencing .claude-pr snapshot behavior."""
        _, _, steps = self.load_contract(WORKFLOWS[0], "claude")
        cases = (
            ("symlink", ".claude/settings.json"),
            ("symlink", ".husky/pre-commit"),
            ("gitlink", ".claude/vendor"),
            ("gitlink", ".husky/vendor"),
        )
        for entry_type, path in cases:
            with (
                self.subTest(entry_type=entry_type, path=path),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                temp = Path(temp_dir)
                workspace, base_sha, _, head_ref = self.create_review_repository(
                    temp, head_commits=1
                )
                target = workspace / path
                if entry_type == "symlink":
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.unlink(missing_ok=True)
                    target.symlink_to("/proc/self/environ")
                    self.run_git(workspace, "add", "--", path)
                else:
                    self.run_git(
                        workspace,
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        f"160000,{base_sha},{path}",
                    )
                self.run_git(
                    workspace,
                    "commit",
                    "--quiet",
                    "-m",
                    f"add sensitive {entry_type}",
                )
                head_sha = self.run_git(workspace, "rev-parse", "HEAD").stdout.strip()
                self.run_git(workspace, "checkout", "--quiet", "main")

                local_origin = temp / "local-origin.git"
                runtime_env = os.environ | {
                    "EXPECTED_HEAD_SHA": head_sha,
                    "HEAD_REF": head_ref,
                    "EXPECTED_BASE_SHA": base_sha,
                    "BASE_REF": "main",
                    "HEAD_FETCH_DEPTH": "20",
                    "EXPECTED_DEFAULT_BRANCH": "main",
                    "TRUSTED_REF": "main",
                    "LOCAL_ORIGIN": str(local_origin),
                    "GITHUB_WORKSPACE": str(workspace),
                    "RUNNER_TEMP": str(temp),
                }
                rejected = subprocess.run(
                    [
                        "bash",
                        "-c",
                        steps["Prepare credential-free local origin"]["run"],
                    ],
                    cwd=workspace,
                    env=runtime_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("symlinks and gitlinks are rejected", rejected.stdout)
                self.assertFalse(local_origin.exists())
                self.assertEqual(
                    self.run_git(workspace, "rev-parse", "HEAD").stdout.strip(),
                    base_sha,
                )
                self.assertEqual(
                    self.run_git(
                        workspace, "symbolic-ref", "--quiet", "--short", "HEAD"
                    ).stdout.strip(),
                    "main",
                )

    def test_automatic_review_runtime_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[1], "claude-review")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            workspace, base_sha, head_sha, head_ref = self.create_review_repository(
                temp, head_commits=4
            )
            local_origin = temp / "review-origin.git"
            output_file = temp / "prepare-output"
            self.run_git(workspace, "checkout", "--quiet", "main")
            runtime_env = os.environ | {
                "EXPECTED_HEAD_SHA": head_sha,
                "HEAD_REF": head_ref,
                "EXPECTED_BASE_SHA": base_sha,
                "BASE_REF": "main",
                "LOCAL_ORIGIN": str(local_origin),
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_OUTPUT": str(output_file),
            }
            prepared = subprocess.run(
                ["bash", "-c", steps["Prepare credential-free review origin"]["run"]],
                cwd=workspace,
                env=runtime_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self.assertEqual(
                output_file.read_text(encoding="utf-8"),
                f"trusted_sha={base_sha}\nready=true\n",
            )
            self.assertEqual(
                self.run_git(workspace, "rev-parse", "HEAD").stdout.strip(), base_sha
            )
            self.assertEqual(
                self.run_git(workspace, "remote", "get-url", "origin").stdout.strip(),
                str(local_origin),
            )
            self.assertEqual(
                self.run_git(
                    workspace,
                    "config",
                    "--local",
                    "--get",
                    "fetch.recurseSubmodules",
                ).stdout.strip(),
                "false",
            )
            for ref, expected_sha in (
                (f"refs/heads/{head_ref}", head_sha),
                ("refs/heads/main", base_sha),
                (f"refs/remotes/origin/{head_ref}", head_sha),
                ("refs/remotes/origin/main", base_sha),
            ):
                self.assertEqual(
                    self.run_git(workspace, "rev-parse", ref).stdout.strip(),
                    expected_sha,
                )
                self.assertEqual(
                    self.run_git(workspace, "rev-list", "--count", ref).stdout.strip(),
                    "1",
                )

            mock_bin = temp / "bin"
            mock_bin.mkdir()
            gh = mock_bin / "gh"
            gh.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'/pulls/'*)
    printf '%s\n' "${GITHUB_REPOSITORY}" "${EXPECTED_HEAD_SHA}" \
      "${HEAD_REF}" "${GITHUB_REPOSITORY}" "${EXPECTED_BASE_SHA}" "${BASE_REF}"
    ;;
  *'/issues/'*'/comments'*)
    if [[ "${COMMENTS_API_FAIL:-}" == "1" ]]; then
      exit 1
    fi
    printf '%s\n' "${COMMENTS_JSON}"
    ;;
  *)
    exit 1
    ;;
esac
""",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            execution_file = temp / "execution.json"
            execution_file.write_text("completed\n", encoding="utf-8")
            review_marker = f"<!-- claude-review:layervai/nhp:123:999:2:{head_sha} -->"
            published_comments = [
                [
                    {
                        "user": {"login": "github-actions[bot]"},
                        "body": f"No findings.\n\n{review_marker}\n",
                    }
                ]
            ]
            verifier_env = runtime_env | {
                "PATH": f"{mock_bin}{os.pathsep}{runtime_env['PATH']}",
                "GH_TOKEN": "test-token",
                "PR_NUMBER": "123",
                "GITHUB_REPOSITORY": "layervai/nhp",
                "EXECUTION_FILE": str(execution_file),
                "EXPECTED_LOCAL_SHA": base_sha,
                "EXPECTED_REVIEW_MARKER": review_marker,
                "COMMENTS_JSON": json.dumps(published_comments),
            }
            verifier = steps["Verify terminal Claude review"]["run"]

            def run_verifier(
                env: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", "-c", verifier],
                    cwd=workspace,
                    env=verifier_env if env is None else env,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            verified = run_verifier()
            self.assertEqual(verified.returncode, 0, verified.stderr)

            publication_failures = (
                ("missing", [[]], {}),
                (
                    "marker only",
                    [
                        [
                            {
                                "user": {"login": "github-actions[bot]"},
                                "body": f"  \n\t\n{review_marker}\n",
                            }
                        ]
                    ],
                    {},
                ),
                (
                    "wrong actor",
                    [[{"user": {"login": "claude[bot]"}, "body": review_marker}]],
                    {},
                ),
                (
                    "stale marker",
                    [
                        [
                            {
                                "user": {"login": "github-actions[bot]"},
                                "body": review_marker.replace(":999:2:", ":999:1:"),
                            }
                        ]
                    ],
                    {},
                ),
                ("API failure", published_comments, {"COMMENTS_API_FAIL": "1"}),
            )
            for name, comments, extra_env in publication_failures:
                with self.subTest(publication=name):
                    rejected = run_verifier(
                        verifier_env
                        | {"COMMENTS_JSON": json.dumps(comments)}
                        | extra_env
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    expected_error = (
                        "publication could not refresh pull request comments"
                        if name == "API failure"
                        else "did not publish the run-specific pull request comment"
                    )
                    self.assertIn(expected_error, rejected.stdout)

            tampered_refs = (
                ("tracking head", f"refs/remotes/origin/{head_ref}", base_sha),
                ("source head", f"refs/heads/{head_ref}", base_sha),
            )
            for name, ref, wrong_sha in tampered_refs:
                with self.subTest(tamper=name):
                    self.run_git(workspace, "update-ref", ref, wrong_sha)
                    rejected = run_verifier()
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(
                        "head or base changed during Claude review", rejected.stdout
                    )
                    self.run_git(workspace, "update-ref", ref, head_sha)

            self.run_git(
                workspace,
                f"--git-dir={local_origin}",
                "update-ref",
                f"refs/heads/{head_ref}",
                base_sha,
            )
            rejected = run_verifier()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("head or base changed during Claude review", rejected.stdout)
            self.run_git(
                workspace,
                f"--git-dir={local_origin}",
                "update-ref",
                f"refs/heads/{head_ref}",
                head_sha,
            )

            self.run_git(workspace, "checkout", "--force", "--detach", head_sha)
            rejected = run_verifier()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("head or base changed during Claude review", rejected.stdout)
            self.run_git(workspace, "checkout", "--force", "--detach", base_sha)

            self.run_git(
                workspace,
                "config",
                "--local",
                "credential.https://github.com.helper",
                "store",
            )
            rejected = subprocess.run(
                ["bash", "-c", verifier],
                cwd=workspace,
                env=verifier_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "changed the credential-free review configuration",
                rejected.stdout,
            )

    def test_automatic_review_entry_contract(self) -> None:
        workflow, job, steps = self.load_contract(WORKFLOWS[1], "claude-review")
        self.assertEqual(
            workflow[True], {"pull_request_target": {"types": list(REVIEW_EVENTS)}}
        )
        self.assertTrue(PR_MERGE_REF_EVENTS.isdisjoint(workflow[True]))
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(
            workflow["concurrency"],
            {"group": REVIEW_CONCURRENCY_GROUP, "cancel-in-progress": True},
        )
        self.assertEqual(job["if"], REVIEW_JOB_IF)
        self.assertEqual(job["timeout-minutes"], 20)
        self.assertEqual(
            job["permissions"],
            {"contents": "read", "pull-requests": "write", "issues": "read"},
        )
        self.assertEqual(
            list(steps),
            [
                "Checkout trusted default branch history",
                "Prepare credential-free review origin",
                "Run Claude Code Review",
                "Verify terminal Claude review",
            ],
        )
        self.assertEqual(
            steps["Checkout trusted default branch history"]["with"],
            {
                "ref": "${{ github.event.repository.default_branch }}",
                "fetch-depth": 0,
                "persist-credentials": False,
            },
        )

    def test_secret_bearing_workflows_forbid_pr_merge_ref_events(self) -> None:
        for path, job_name in (
            (WORKFLOWS[0], "claude"),
            (WORKFLOWS[1], "claude-review"),
        ):
            with self.subTest(path=path):
                workflow, _, _ = self.load_contract(path, job_name)
                configured_events = set(workflow[True])
                self.assertFalse(
                    configured_events & PR_MERGE_REF_EVENTS,
                    "secrets-bearing workflows must load from a trusted "
                    "default branch before evaluating guards",
                )

    def test_automatic_review_origin_and_action_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[1], "claude-review")
        review_origin = steps["Prepare credential-free review origin"]
        self.assertEqual(review_origin["id"], "review_origin")
        self.assertEqual(review_origin["if"], "steps.checkout.outcome == 'success'")
        self.assertEqual(
            review_origin["env"],
            {
                "EXPECTED_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
                "HEAD_REF": "${{ github.event.pull_request.head.ref }}",
                "EXPECTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                "BASE_REF": "${{ github.event.pull_request.base.ref }}",
                "LOCAL_ORIGIN": "${{ runner.temp }}/claude-review-origin-${{ github.run_id }}-${{ github.run_attempt }}.git",
            },
        )
        self.assert_fragments(
            review_origin["run"],
            '[[ "$1" != "@" ]]',
            '[[ "$1" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]',
            'git check-ref-format --branch "$1"',
            'trusted_head="$(git rev-parse --verify HEAD 2>/dev/null)"',
            'git cat-file -e "${EXPECTED_HEAD_SHA}^{commit}"',
            'git cat-file -e "${EXPECTED_BASE_SHA}^{commit}"',
            'git checkout --detach --quiet "${trusted_head}"',
            'git init --bare --quiet --object-format="${object_format}" "${LOCAL_ORIGIN}"',
            'fetch --no-tags --no-recurse-submodules "${GITHUB_WORKSPACE}"',
            '"${EXPECTED_HEAD_SHA}:refs/heads/${HEAD_REF}"',
            '"${EXPECTED_BASE_SHA}:refs/heads/${BASE_REF}"',
            'git remote set-url origin "${LOCAL_ORIGIN}"',
            'git branch --force "${HEAD_REF}" "${EXPECTED_HEAD_SHA}"',
            'git branch --force "${BASE_REF}" "${EXPECTED_BASE_SHA}"',
            "git config --local fetch.recurseSubmodules false",
            'git fetch origin "${HEAD_REF}" --depth=1 --no-recurse-submodules',
            'git fetch origin "${BASE_REF}" --depth=1 --no-recurse-submodules',
            'git rev-parse "refs/remotes/origin/${HEAD_REF}"',
            'git rev-parse "refs/remotes/origin/${BASE_REF}"',
            'git --git-dir="${LOCAL_ORIGIN}" rev-parse "refs/heads/${HEAD_REF}"',
            'git --git-dir="${LOCAL_ORIGIN}" rev-parse "refs/heads/${BASE_REF}"',
            "credential(\\..*)?\\.helper",
            'echo "trusted_sha=${trusted_head}"',
            "ready=true",
        )
        self.assert_error_blocks_fail_closed(review_origin["run"])

        action = steps["Run Claude Code Review"]
        self.assertEqual(action["id"], "claude-review")
        self.assertEqual(
            action["if"],
            "steps.checkout.outcome == 'success' &&\n"
            "steps.review_origin.outputs.ready == 'true'\n",
        )
        self.assertEqual(
            action["uses"],
            f"anthropics/claude-code-action@{CLAUDE_ACTION_REF}",
            ACTION_REF_HINT,
        )
        self.assertEqual(
            set(action["with"]),
            {
                "anthropic_api_key",
                "github_token",
                "use_commit_signing",
                "prompt",
                "claude_args",
            },
        )
        self.assertEqual(action["with"]["github_token"], "${{ github.token }}")
        self.assertIs(action["with"]["use_commit_signing"], True)
        self.assertEqual(action["with"]["claude_args"], AUTOMATIC_REVIEW_ARGS)
        self.assertNotIn("Bash(", action["with"]["claude_args"])
        self.assert_fragments(
            action["with"]["prompt"],
            "Review exactly HEAD SHA against BASE SHA",
            "Do not use moving branches",
            "local workspace",
            "CLAUDE.md through",
            "untrusted review data",
            "REVIEW MARKER: <!-- claude-review:",
            "get_file_contents",
            "withholds repository execution tools",
            "GitHub add_issue_comment tool",
            "marker in any other comment",
        )

    def test_automatic_review_terminal_contract(self) -> None:
        _, _, steps = self.load_contract(WORKFLOWS[1], "claude-review")
        self.assert_remote_head_verifier(
            steps["Verify terminal Claude review"],
            "success() && steps.claude-review.outcome == 'success'",
            "${{ github.event.pull_request.number }}",
            "${{ github.event.pull_request.head.sha }}",
            "${{ github.event.pull_request.base.sha }}",
            "${{ steps.claude-review.outputs.execution_file }}",
            (
                "${{ github.event.pull_request.head.ref }}",
                "${{ github.event.pull_request.base.ref }}",
                "${{ runner.temp }}/claude-review-origin-${{ github.run_id }}-${{ github.run_attempt }}.git",
            ),
            source_refs=True,
            expected_local_sha="${{ steps.review_origin.outputs.trusted_sha }}",
            review_marker=(
                "<!-- claude-review:${{ github.repository }}:"
                "${{ github.event.pull_request.number }}:${{ github.run_id }}:"
                "${{ github.run_attempt }}:${{ github.event.pull_request.head.sha }} -->"
            ),
        )


if __name__ == "__main__":
    unittest.main()
