#!/usr/bin/env python3
"""Operate prod matched-cohort public maintenance gates independently."""

from __future__ import annotations

import argparse
import re
import signal
import sys

from prod_matched_cohort_control import (
    ControlError,
    MaintenanceController,
    OperatorLock,
    canonical_json,
    load_contract,
)


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    signal.signal(signal.SIGTERM, _interrupt)
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation", choices=("status", "close", "open"), required=True)
    parser.add_argument("--selector", choices=("blue", "candidate"))
    parser.add_argument("--contract-parameter", default="/prod/nhp/matched-cohort/contract-v2")
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument(
        "--release-id",
        help="SHA-256 of the immutable source and digest-qualified cohort release manifest",
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.contract_sha256) is None:
        parser.error("--contract-sha256 must be 64 lowercase hex")
    if args.operation == "open" and args.selector not in ("blue", "candidate"):
        parser.error("open requires the exact --selector blue|candidate")
    if args.operation in ("close", "open") and (
        not args.release_id or re.fullmatch(r"[0-9a-f]{64}", args.release_id) is None
    ):
        parser.error(f"{args.operation} requires --release-id as 64 lowercase hex")
    if args.operation == "status" and args.resume:
        parser.error("--resume is valid only for close or open")
    try:
        contract = load_contract(args.contract_parameter, args.region, args.contract_sha256)
        operator_lock = None
        if args.operation in ("close", "open"):
            operator_lock = OperatorLock(
                contract["maintenance"]["operator_lock_table"],
                args.release_id,
                args.contract_sha256,
                args.region,
            )
        gates = MaintenanceController(
            contract,
            args.region,
            operator_lock=operator_lock,
            resume_active=args.resume,
        )
        if args.operation == "status":
            result = {"maintenance": gates.state()}
        elif args.operation == "close":
            result = {"maintenance": gates.transition("open", "closed")}
        else:
            result = {"maintenance": gates.transition("closed", "open", required_selector=args.selector)}
    except (ControlError, KeyboardInterrupt) as error:
        print(f"matched-cohort maintenance rejected: {error}", file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
