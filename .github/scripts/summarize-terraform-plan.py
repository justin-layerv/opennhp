#!/usr/bin/env python3
"""Build the Terraform Plan (PR) markdown summary."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)((?:token|secret|password|authorization|api[_-]?key)[A-Za-z0-9_.-]*)(\s*[=:]\s*)([^\s,]+)"
)
BEARER_ASSIGNMENT_RE = re.compile(
    r"(?i)((?:authorization|token)[A-Za-z0-9_.-]*)(\s*[=:]\s*)Bearer\s+([^\s,]+)"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
HIGH_ENTROPY_RE = re.compile(
    r"(?<![A-Za-z0-9_./+=-])"
    r"(?=[A-Za-z0-9_./+=-]{40,}(?![A-Za-z0-9_./+=-]))"
    r"(?=[A-Za-z0-9_./+=-]*[A-Za-z])"
    r"(?=[A-Za-z0-9_./+=-]*[0-9])"
    r"[A-Za-z0-9_./+=-]+"
)
# This may redact benign long IDs that mix letters and digits. Keep that
# conservative behavior because failure excerpts are omitted from the durable PR
# comment and only appear in the workflow run summary/artifact. redact() is only
# used on bounded failure excerpts; bound input first if reusing it on full plans.
# Preserve ordinary Git SHAs in failure excerpts. A lowercase-hex secret with
# the same shape is a known best-effort redaction gap for this private-repo run
# summary/artifact path, so keep failure excerpts out of public repositories.
LOWER_HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PLAN_TEXT_COUNTS_RE = re.compile(r"Plan:\s+(\d+) to add,\s+(\d+) to change,\s+(\d+) to destroy\.")
MAX_FAILURE_EXCERPT_CHARS = 5000


def redact_high_entropy(match: re.Match[str]) -> str:
    token = match.group(0)
    if LOWER_HEX_SHA_RE.fullmatch(token):
        return token
    return "[redacted-token]"


def redact(text: str) -> str:
    text = BEARER_ASSIGNMENT_RE.sub(r"\1\2[redacted]", text)
    text = SECRET_ASSIGNMENT_RE.sub(r"\1\2[redacted]", text)
    text = JWT_RE.sub("[redacted-jwt]", text)
    text = text.replace("```", "`\u200b``")
    return HIGH_ENTROPY_RE.sub(redact_high_entropy, text)


def counts_from_json(data: dict[str, Any]) -> dict[str, int]:
    counts = {"add": 0, "change": 0, "destroy": 0}
    for change in data.get("resource_changes", []):
        actions = change.get("change", {}).get("actions", [])
        if actions in (["no-op"], ["read"]):
            continue
        # Terraform reports replacements as one add and one destroy, with no
        # separate change increment.
        if "create" in actions:
            counts["add"] += 1
        if actions == ["update"]:
            counts["change"] += 1
        if "delete" in actions:
            counts["destroy"] += 1
    return counts


def counts_from_text(plan_text: str) -> dict[str, int] | None:
    match = PLAN_TEXT_COUNTS_RE.search(plan_text)
    if not match:
        return None
    return {
        "add": int(match.group(1)),
        "change": int(match.group(2)),
        "destroy": int(match.group(3)),
    }


def counts_from_plan(plan_text: str, plan_json_path: Path) -> tuple[dict[str, int], str | None]:
    if plan_json_path.exists():
        try:
            return counts_from_json(json.loads(plan_json_path.read_text())), None
        except (OSError, json.JSONDecodeError) as exc:
            text_counts = counts_from_text(plan_text)
            warning = (
                f"tfplan.json could not be parsed ({exc.__class__.__name__}); "
                "counts fall back to plan text when available."
            )
            return text_counts or {"add": 0, "change": 0, "destroy": 0}, warning
    text_counts = counts_from_text(plan_text)
    return text_counts or {"add": 0, "change": 0, "destroy": 0}, None


def failure_excerpt(plan_text: str) -> str:
    interesting: list[str] = []
    interesting_chars = 0
    lines = plan_text.splitlines()
    windows: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if "Error:" in line:
            start = max(0, index - 2)
            end = min(len(lines), index + 18)
            if windows and start <= windows[-1][1]:
                windows[-1] = (windows[-1][0], max(windows[-1][1], end))
            else:
                windows.append((start, end))
    for start, end in windows:
        segment = [*lines[start:end], "..."]
        interesting.extend(segment)
        interesting_chars += sum(len(line) for line in segment) + len(segment)
        if interesting_chars > MAX_FAILURE_EXCERPT_CHARS:
            break
    excerpt = "\n".join(interesting).strip() or "\n".join(lines[-80:]).strip()
    redacted = redact(excerpt)
    if len(redacted) > MAX_FAILURE_EXCERPT_CHARS:
        redacted = redacted[:MAX_FAILURE_EXCERPT_CHARS]
    return redacted or "Terraform exited non-zero before producing plan output."


def build_summary(
    *,
    exit_code: int,
    marker: str,
    run_id: str,
    server_url: str,
    repository: str,
    plan_text: str,
    plan_json_path: Path,
    show_json_failed: bool,
    include_failure_excerpt: bool = True,
    counts: dict[str, int] | None = None,
    parse_warning: str | None = None,
) -> str:
    if counts is None:
        counts, parse_warning = counts_from_plan(plan_text, plan_json_path)
    status = "passed" if exit_code == 0 else "failed"
    body = [
        marker,
        "### Terraform Plan (sandbox)",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Result | `{status}` |",
        f"| Add | `{counts['add']}` |",
        f"| Change | `{counts['change']}` |",
        f"| Destroy | `{counts['destroy']}` |",
        f"| Run | [{run_id}]({server_url}/{repository}/actions/runs/{run_id}) |",
        "",
        "`terraform plan -refresh=false -lock=false -out=tfplan -no-color -var='cross_account_cost_analytics_role_arn='` ran against the sandbox remote state using the read-only PR plan role.",
        "",
        "Plan counts are review signals, not exact deploy drift: this PR plan does not refresh live resources, disables the cross-account billing provider assume-role, uses the PR head SHA for NHP images, the current qurl-reverse-tunnel-server SSM tag when available, and deterministic placeholders for app-level secrets.",
    ]

    if parse_warning:
        body.extend(["", f"> {parse_warning}"])

    if show_json_failed:
        body.extend(
            [
                "",
                "#### Summary Error",
                "",
                "`terraform plan` succeeded, but `terraform show -json tfplan` failed. Open the linked run and inspect the `Terraform Plan` step.",
            ]
        )
    elif exit_code != 0 and include_failure_excerpt:
        body.extend(
            [
                "",
                "#### Failure Excerpt",
                "",
                "```text",
                failure_excerpt(plan_text),
                "```",
            ]
        )
    elif exit_code != 0:
        body.extend(
            [
                "",
                "#### Failure Details",
                "",
                "Terraform plan failed. The detailed, redacted failure excerpt is kept in the workflow run summary and artifact instead of the PR comment so attacker-controlled plan output is not reposted into the discussion.",
            ]
        )

    return "\n".join(body) + "\n"


def main() -> int:
    summary_args = {
        "exit_code": int(os.environ["PLAN_EXIT_CODE"]),
        "marker": os.environ["PLAN_COMMENT_MARKER"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "server_url": os.environ["GITHUB_SERVER_URL"],
        "repository": os.environ["GITHUB_REPOSITORY"],
        "plan_text": Path("plan.txt").read_text(errors="replace") if Path("plan.txt").exists() else "",
        "plan_json_path": Path("tfplan.json"),
        "show_json_failed": os.environ.get("SHOW_JSON_FAILED") == "true",
    }
    counts, parse_warning = counts_from_plan(summary_args["plan_text"], summary_args["plan_json_path"])
    output = build_summary(
        **summary_args,
        include_failure_excerpt=True,
        counts=counts,
        parse_warning=parse_warning,
    )
    comment_output = build_summary(
        **summary_args,
        include_failure_excerpt=False,
        counts=counts,
        parse_warning=parse_warning,
    )
    Path("plan-summary.md").write_text(output)
    Path("plan-comment-summary.md").write_text(comment_output)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(output)
    # Missing env vars or file errors above intentionally propagate as a non-zero
    # process exit; reaching this line means both summaries were written.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
