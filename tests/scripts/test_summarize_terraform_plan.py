#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / ".github" / "scripts" / "summarize-terraform-plan.py"

spec = importlib.util.spec_from_file_location("summarize_terraform_plan", SCRIPT_PATH)
assert spec and spec.loader
summarizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summarizer)


class SummarizeTerraformPlanTests(unittest.TestCase):
    def test_redacts_key_value_jwt_and_high_entropy_tokens(self) -> None:
        text = (
            "secret=short-lived\n"
            "bare eyJaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccc "
            "value AbCdEf1234567890AbCdEf1234567890AbCdEf12"
        )

        redacted = summarizer.redact(text)

        self.assertIn("secret=[redacted]", redacted)
        self.assertIn("bare [redacted-jwt]", redacted)
        self.assertIn("value [redacted-token]", redacted)
        self.assertNotIn("short-lived", redacted)
        self.assertNotIn("AbCdEf1234567890AbCdEf1234567890AbCdEf12", redacted)

    def test_redactor_keeps_long_non_secret_words(self) -> None:
        benign = "a" * 80

        self.assertEqual(benign, summarizer.redact(benign))

    def test_redactor_keeps_sha_but_redacts_aws_secret_shape(self) -> None:
        sha = "0123456789abcdef0123456789abcdef01234567"
        aws_secret_shape = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        redacted = summarizer.redact(f"sha {sha} secret {aws_secret_shape}")

        self.assertIn(sha, redacted)
        self.assertIn("secret [redacted-token]", redacted)
        self.assertNotIn(aws_secret_shape, redacted)

    def test_redactor_breaks_markdown_code_fence_delimiters(self) -> None:
        redacted = summarizer.redact("before ```md\n# fake\n``` after")

        self.assertNotIn("```", redacted)
        self.assertNotIn("\\u200b", redacted)
        self.assertIn("`\u200b``md", redacted)

    def test_redactor_redacts_bearer_assignments(self) -> None:
        token = "a" * 48

        redacted = summarizer.redact(f"Authorization: Bearer {token}")

        self.assertEqual("Authorization: [redacted]", redacted)
        self.assertNotIn(token, redacted)

    def test_counts_replacement_as_add_and_destroy(self) -> None:
        data = {
            "resource_changes": [
                {"change": {"actions": ["create", "delete"]}},
                {"change": {"actions": ["update"]}},
                {"change": {"actions": ["no-op"]}},
                {"change": {"actions": ["read"]}},
            ]
        }

        self.assertEqual({"add": 1, "change": 1, "destroy": 1}, summarizer.counts_from_json(data))

    def test_counts_fall_back_to_plan_text_when_json_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_json = Path(tmpdir) / "tfplan.json"
            plan_json.write_text("{not json")

            counts, warning = summarizer.counts_from_plan(
                "Plan: 2 to add, 3 to change, 4 to destroy.", plan_json
            )

        self.assertEqual({"add": 2, "change": 3, "destroy": 4}, counts)
        self.assertIn("tfplan.json could not be parsed", warning)

    def test_failed_summary_redacts_failure_excerpt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_json = Path(tmpdir) / "tfplan.json"
            plan_json.write_text(json.dumps({"resource_changes": []}))
            plan_text = "\n".join(
                [
                    "random context",
                    "Error: provider failed",
                    "authorization=Bearer " + ("a" * 48),
                    "eyJaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccc",
                ]
            )

            summary = summarizer.build_summary(
                exit_code=1,
                marker="<!-- marker -->",
                run_id="123",
                server_url="https://github.com",
                repository="layervai/nhp",
                plan_text=plan_text,
                plan_json_path=plan_json,
                show_json_failed=False,
            )

        self.assertIn("#### Failure Excerpt", summary)
        self.assertIn("authorization=[redacted]", summary)
        self.assertIn("[redacted-jwt]", summary)
        self.assertNotIn("Bearer " + ("a" * 48), summary)

    def test_comment_summary_omits_failure_excerpt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_json = Path(tmpdir) / "tfplan.json"
            plan_json.write_text(json.dumps({"resource_changes": []}))
            plan_text = "\n".join(
                [
                    "Error: provider failed",
                    "attacker markdown ```md",
                    "authorization=Bearer " + ("a" * 48),
                ]
            )

            summary = summarizer.build_summary(
                exit_code=1,
                marker="<!-- marker -->",
                run_id="123",
                server_url="https://github.com",
                repository="layervai/nhp",
                plan_text=plan_text,
                plan_json_path=plan_json,
                show_json_failed=False,
                include_failure_excerpt=False,
            )

        self.assertIn("#### Failure Details", summary)
        self.assertIn("workflow run summary and artifact", summary)
        self.assertNotIn("#### Failure Excerpt", summary)
        self.assertNotIn("attacker markdown", summary)
        self.assertNotIn("Bearer " + ("a" * 48), summary)

    def test_failure_excerpt_redacts_before_final_truncation(self) -> None:
        token = "a" * 48
        suffix = "y" * 4941
        plan_text = "\n".join(
            [
                "Error: provider failed",
                ("x" * 100) + f"authorization=Bearer {token}" + suffix,
            ]
        )

        excerpt = summarizer.failure_excerpt(plan_text)

        self.assertIn("authorization=[redacted]", excerpt)
        self.assertNotIn(token, excerpt)

    def test_failure_excerpt_final_truncation_keeps_first_error(self) -> None:
        plan_text = "\n".join(
            [
                "Error: first provider failure",
                ("x" * 6000) + "late-tail-marker",
            ]
        )

        excerpt = summarizer.failure_excerpt(plan_text)

        self.assertIn("Error: first provider failure", excerpt)
        self.assertNotIn("late-tail-marker", excerpt)

    def test_show_json_failure_uses_distinct_summary_message(self) -> None:
        summary = summarizer.build_summary(
            exit_code=1,
            marker="<!-- marker -->",
            run_id="123",
            server_url="https://github.com",
            repository="layervai/nhp",
            plan_text="Plan: 0 to add, 0 to change, 0 to destroy.",
            plan_json_path=Path("/definitely/missing/tfplan.json"),
            show_json_failed=True,
        )

        self.assertIn("#### Summary Error", summary)
        self.assertIn("terraform show -json tfplan", summary)
        self.assertNotIn("#### Failure Excerpt", summary)

    def test_build_summary_reuses_precomputed_counts_when_warning_absent(self) -> None:
        summary = summarizer.build_summary(
            exit_code=0,
            marker="<!-- marker -->",
            run_id="123",
            server_url="https://github.com",
            repository="layervai/nhp",
            plan_text="",
            plan_json_path=Path("/definitely/missing/tfplan.json"),
            show_json_failed=False,
            counts={"add": 7, "change": 8, "destroy": 9},
            parse_warning=None,
        )

        self.assertIn("| Add | `7` |", summary)
        self.assertIn("| Change | `8` |", summary)
        self.assertIn("| Destroy | `9` |", summary)
        self.assertNotIn("tfplan.json", summary)

    def test_failure_excerpt_deduplicates_overlapping_error_windows(self) -> None:
        plan_text = "\n".join(
            [
                "context a",
                "context b",
                "Error: first failure",
                "shared detail",
                "Error: second failure",
                "tail detail",
            ]
        )

        excerpt = summarizer.failure_excerpt(plan_text)

        self.assertEqual(1, excerpt.count("shared detail"))
        self.assertIn("Error: first failure", excerpt)
        self.assertIn("Error: second failure", excerpt)


if __name__ == "__main__":
    unittest.main()
