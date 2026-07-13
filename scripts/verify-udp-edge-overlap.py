#!/usr/bin/env python3
"""Fail closed unless all flood/probe artifacts prove concurrent load."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path


EXPECTED_FLOOD_SOURCES = 8
MAX_START_LAG_SECONDS = 30
EARLY_START_SLACK_SECONDS = 5


def epoch_field(document: dict, field: str, label: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} {field} must be a positive integer epoch")
    return value


def verify_windows(
    flood_documents: list[tuple[str, dict]],
    probe_document: dict,
    expected_start: int,
    expected_end: int,
) -> dict:
    duration = expected_end - expected_start
    if duration <= 0:
        raise ValueError("expected end must be after expected start")

    failures: list[str] = []
    windows: dict[str, dict[str, int]] = {}
    if len(flood_documents) != EXPECTED_FLOOD_SOURCES:
        failures.append(f"found {len(flood_documents)} flood timing artifacts, want {EXPECTED_FLOOD_SOURCES}")

    labeled_documents = [*flood_documents, ("sdk-probe", probe_document)]
    for label, document in labeled_documents:
        try:
            started = epoch_field(document, "started_epoch", label)
            ended = epoch_field(document, "ended_epoch", label)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        windows[label] = {"started_epoch": started, "ended_epoch": ended}
        if started < expected_start - EARLY_START_SLACK_SECONDS:
            failures.append(f"{label} started {expected_start - started}s before the coordinated window")
        if started > expected_start + MAX_START_LAG_SECONDS:
            failures.append(f"{label} started {started - expected_start}s late (max {MAX_START_LAG_SECONDS}s)")
        if ended < started + duration - 1:
            failures.append(f"{label} ran {ended - started}s, want approximately {duration}s")

    common_overlap = 0
    if len(windows) == EXPECTED_FLOOD_SOURCES + 1:
        common_start = max(window["started_epoch"] for window in windows.values())
        common_end = min(window["ended_epoch"] for window in windows.values())
        common_overlap = max(0, common_end - common_start)
        minimum_overlap = duration - MAX_START_LAG_SECONDS
        if common_overlap < minimum_overlap:
            failures.append(f"common flood/probe overlap was {common_overlap}s, want at least {minimum_overlap}s")

    return {
        "expected_start_epoch": expected_start,
        "expected_end_epoch": expected_end,
        "max_start_lag_seconds": MAX_START_LAG_SECONDS,
        "common_overlap_seconds": common_overlap,
        "windows": windows,
        "failures": failures,
    }


def load_document(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-start-epoch", required=True, type=int)
    parser.add_argument("--expected-end-epoch", required=True, type=int)
    parser.add_argument("--flood-glob", required=True)
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()

    failures: list[str] = []
    flood_documents: list[tuple[str, dict]] = []
    for name in sorted(glob.glob(args.flood_glob)):
        path = Path(name)
        try:
            flood_documents.append((path.stem, load_document(path)))
        except (OSError, ValueError) as exc:
            failures.append(f"cannot read {path}: {exc}")
    try:
        probe_document = load_document(args.probe)
    except (OSError, ValueError) as exc:
        probe_document = {}
        failures.append(f"cannot read {args.probe}: {exc}")

    report = verify_windows(
        flood_documents,
        probe_document,
        args.expected_start_epoch,
        args.expected_end_epoch,
    )
    report["failures"] = [*failures, *report["failures"]]
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
