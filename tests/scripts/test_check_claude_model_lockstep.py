#!/usr/bin/env python3
"""Fixture coverage for scripts/check-claude-model-lockstep.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts/check-claude-model-lockstep.py"
WORKFLOWS = (
    Path(".github/workflows/claude.yml"),
    Path(".github/workflows/claude-code-review.yml"),
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
                action = f"{uses_quote}{action_repository}@fixture-sha{uses_quote}"
                additional_action = (
                    f"      - uses: {action}\n"
                    if extra_action
                    else ""
                )
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
                        "jobs:\n"
                        "  claude:\n"
                        f"    uses: {action}\n"
                        "    with:\n"
                        f"{job_inputs}"
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
        self.assertIn("expected at least two Claude action workflows, found 1", result.stderr)

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
                self.assertIn(
                    "exactly one single-quoted claude_args", result.stderr
                )

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
                self.assertIn(
                    "claude-extra-0.yaml=claude-sonnet-4-6", result.stderr
                )

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


if __name__ == "__main__":
    unittest.main()
