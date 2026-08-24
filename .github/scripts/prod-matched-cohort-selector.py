#!/usr/bin/env python3
"""Switch all prod matched-cohort selectors while independent gates stay closed."""

from __future__ import annotations

import argparse
import re
import signal
import sys

from prod_matched_cohort_control import (
    BLACK_BOX_DEFAULT_TIMEOUT_SECONDS,
    BLACK_BOX_MAX_TIMEOUT_SECONDS,
    ControlError,
    OperatorLock,
    SelectorController,
    canonical_json,
    load_contract,
    run_black_box_probe,
)


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    signal.signal(signal.SIGTERM, _interrupt)
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation", choices=("status", "switch"), required=True)
    parser.add_argument("--expected", choices=("blue", "candidate"))
    parser.add_argument("--target", choices=("blue", "candidate"))
    parser.add_argument("--contract-parameter", default="/prod/nhp/matched-cohort/contract-v2")
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--black-box-probe")
    parser.add_argument("--black-box-probe-sha256")
    parser.add_argument(
        "--release-id",
        help="SHA-256 of the immutable source and digest-qualified cohort release manifest",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--black-box-timeout-seconds",
        type=float,
        default=BLACK_BOX_DEFAULT_TIMEOUT_SECONDS,
    )
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.contract_sha256) is None:
        parser.error("--contract-sha256 must be 64 lowercase hex")
    if args.operation == "switch":
        if args.expected not in ("blue", "candidate") or args.target not in ("blue", "candidate"):
            parser.error("switch requires --expected and --target")
        if args.expected == args.target:
            parser.error("switch requires distinct --expected and --target")
        if not args.black_box_probe or not args.black_box_probe_sha256:
            parser.error("switch requires the reviewed black-box closure probe and digest")
        if not args.release_id or re.fullmatch(r"[0-9a-f]{64}", args.release_id) is None:
            parser.error("switch requires --release-id as 64 lowercase hex")
        if not 0 < args.black_box_timeout_seconds <= BLACK_BOX_MAX_TIMEOUT_SECONDS:
            parser.error("--black-box-timeout-seconds must be in (0,5]")
    elif args.resume:
        parser.error("--resume is valid only for switch")
    try:
        contract = load_contract(args.contract_parameter, args.region, args.contract_sha256)
        operator_lock = None
        if args.operation == "switch":
            operator_lock = OperatorLock(
                contract["maintenance"]["operator_lock_table"],
                args.release_id,
                args.contract_sha256,
                args.region,
            )
        selector = SelectorController(
            contract,
            args.region,
            operator_lock=operator_lock,
            resume_active=args.resume,
        )
        if args.operation == "status":
            result = selector.state()
        else:
            result = selector.switch(
                args.expected,
                args.target,
                lambda: run_black_box_probe(
                    args.black_box_probe,
                    args.black_box_probe_sha256,
                    args.black_box_timeout_seconds,
                    contract,
                ),
            )
    except (ControlError, KeyboardInterrupt) as error:
        print(f"matched-cohort selector rejected: {error}", file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
