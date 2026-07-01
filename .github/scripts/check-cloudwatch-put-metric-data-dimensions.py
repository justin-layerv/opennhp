#!/usr/bin/env python3
"""Fence aws cloudwatch put-metric-data dimension shorthand.

put-metric-data is unusual among CloudWatch commands: --dimensions uses the
AWS CLI's Key=Value map shorthand, while commands such as put-metric-alarm use
the Name=...,Value=... structure form. This script catches regressions back to
the wrong put-metric-data form before a deploy workflow can run.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path


# Keep these roots aligned with repo locations that can publish CloudWatch
# metrics at deploy/runtime. Tests that intentionally carry broken examples
# stay outside the default scan roots.
DEFAULT_ROOTS = (
    Path(".github/scripts"),
    Path(".github/workflows"),
    Path("scripts"),
    Path("terraform/modules"),
)
PATTERNS = ("*.sh", "*.yml", "*.yaml", "*.tpl", "*.tf")
BROKEN_DIMENSIONS = re.compile(r"--dimensions(?:=|\s+)(?:[\"'])?Name=")
CONTINUATION = re.compile(r"\\\s*\n\s*")


@dataclass(frozen=True)
class Failure:
    path: Path
    line: int
    message: str


def candidate_paths(roots: tuple[Path, ...]) -> list[Path]:
    paths: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in PATTERNS:
            paths.extend(path for path in root.rglob(pattern) if path.is_file())
    return sorted(set(paths))


def command_blocks(text: str) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "put-metric-data" not in line or line.lstrip().startswith("#"):
            continue
        block = [line]
        for next_line in lines[index + 1:index + 40]:
            if not block[-1].rstrip().endswith("\\"):
                break
            block.append(next_line)
        blocks.append((index + 1, CONTINUATION.sub(" ", "\n".join(block))))
    return blocks


def dimensions_arg(command: str) -> str | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for offset, token in enumerate(tokens):
        if token == "--dimensions":
            return tokens[offset + 1] if offset + 1 < len(tokens) else ""
        if token.startswith("--dimensions="):
            return token.split("=", 1)[1]
    return None


def has_literal_comma_value(dimensions: str) -> bool:
    if "$" in dimensions:
        return False

    # Key=Value shorthand uses commas between dimensions. A segment without "="
    # means a literal comma likely slipped into a value; use --metric-data JSON
    # for that case instead.
    return any(
        "=" not in segment or segment.startswith("=")
        for segment in dimensions.split(",")
    )


def check_text(path: Path, text: str) -> list[Failure]:
    failures: list[Failure] = []
    for line, command in command_blocks(text):
        if BROKEN_DIMENSIONS.search(command):
            failures.append(
                Failure(
                    path,
                    line,
                    "put-metric-data --dimensions must use Key=Value shorthand "
                    "or --metric-data JSON, not Name=...,Value=...",
                )
            )
        dimensions = dimensions_arg(command)
        if dimensions and has_literal_comma_value(dimensions):
            failures.append(
                Failure(
                    path,
                    line,
                    "put-metric-data dimension values containing literal commas "
                    "must use --metric-data JSON",
                )
            )
    return failures


def check_path(path: Path) -> list[Failure]:
    return check_text(path, path.read_text(encoding="utf-8"))


def run_self_test() -> None:
    if Path("terraform/modules") not in DEFAULT_ROOTS:
        raise AssertionError(
            "terraform module scripts/templates must stay in the default scan roots"
        )
    if Path("scripts") not in DEFAULT_ROOTS:
        raise AssertionError(
            "top-level deploy/lint scripts must stay in the scan roots"
        )
    if "*.tpl" not in PATTERNS:
        raise AssertionError(
            "user_data.sh.tpl templates must stay covered by the scanner"
        )
    if "*.tf" not in PATTERNS:
        raise AssertionError(
            "Terraform heredocs must stay covered by the scanner"
        )

    cases = [
        (
            "good shorthand",
            """
            aws cloudwatch put-metric-data \\
              --namespace LayerV/NHP \\
              --dimensions "Environment=prod,Cell=cell0" \\
              --value 1
            """,
            False,
        ),
        (
            "metric-data json",
            """
            aws cloudwatch put-metric-data \\
              --namespace LayerV/NHP \\
              --metric-data '[{"Dimensions":[{"Name":"Environment","Value":"prod"}]}]'
            """,
            False,
        ),
        (
            "bad Name/Value pair form",
            """
            aws cloudwatch put-metric-data \\
              --dimensions Name=Environment,Value=prod Name=Cell,Value=cell0
            """,
            True,
        ),
        (
            "bad literal comma value",
            """
            aws cloudwatch put-metric-data \\
              --dimensions "Environment=prod,Reason=Throttled, transient"
            """,
            True,
        ),
        (
            "dynamic dimensions",
            """
            aws cloudwatch put-metric-data --dimensions "$DIMS" --value 1
            """,
            False,
        ),
        (
            "comment-only mention",
            """
            # aws cloudwatch put-metric-data --dimensions Name=Environment,Value=prod Name=Cell,Value=cell0
            """,
            False,
        ),
    ]
    for name, text, expect_failure in cases:
        failures = check_text(Path(f"<self-test:{name}>"), text)
        if bool(failures) != expect_failure:
            rendered = ", ".join(failure.message for failure in failures) or "none"
            raise AssertionError(f"{name}: expected failure={expect_failure}, got {rendered}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("roots", nargs="*", type=Path)
    args = parser.parse_args(argv)

    if args.self_test:
        run_self_test()
        print("self-test passed")
        return 0

    roots = tuple(args.roots) if args.roots else DEFAULT_ROOTS
    paths = candidate_paths(roots)
    failures = [failure for path in paths for failure in check_path(path)]
    if failures:
        for failure in failures:
            print(
                f"::error file={failure.path},line={failure.line}::"
                f"{failure.message}"
            )
        return 1
    print(f"checked {len(paths)} files for CloudWatch put-metric-data dimensions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
