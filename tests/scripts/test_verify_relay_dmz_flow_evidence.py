#!/usr/bin/env python3
"""Deterministic tests for relay DMZ Flow Log rollout evidence."""

from __future__ import annotations

import contextlib
import importlib.util
import ipaddress
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evidence = load_module(
    "verify_relay_dmz_flow_evidence",
    REPO_ROOT / "scripts" / "verify-relay-dmz-flow-evidence.py",
)
live = load_module(
    "check_relay_dmz_live",
    REPO_ROOT / "scripts" / "check-relay-dmz-live.py",
)
plan = load_module(
    "check_relay_dmz_plan",
    REPO_ROOT / ".github" / "scripts" / "check-relay-dmz-plan.py",
)


RELAY_IPS = {"10.101.10.10", "10.101.11.10", "10.101.12.10"}
ENDPOINT_IPS = {"10.101.20.20", "10.101.21.20"}
S3_NETWORKS = [ipaddress.ip_network("52.216.0.0/15")]


def flow_message(
    src: str,
    dst: str,
    *,
    dst_port: str = "443",
    action: str = "ACCEPT",
    direction: str = "egress",
) -> str:
    values = {
        "version": "5",
        "account-id": "767397897469",
        "interface-id": "eni-relay",
        "srcaddr": src,
        "dstaddr": dst,
        "srcport": "40000",
        "dstport": dst_port,
        "protocol": "6",
        "packets": "1",
        "bytes": "60",
        "start": "1",
        "end": "2",
        "action": action,
        "log-status": "OK",
        "pkt-srcaddr": src,
        "pkt-dstaddr": dst,
        "pkt-src-aws-service": "-",
        "pkt-dst-aws-service": "-",
        "flow-direction": direction,
        "traffic-path": "1",
    }
    return " ".join(values[field] for field in evidence.FLOW_LOG_FIELDS)


def good_events() -> dict:
    events = []
    for relay_ip in sorted(RELAY_IPS):
        events.append({"message": flow_message(relay_ip, "10.101.20.20")})
        events.append({"message": flow_message(relay_ip, "52.216.1.10")})
    return {"events": events}


class RelayDmzFlowEvidenceTests(unittest.TestCase):
    def test_exact_flow_log_format_is_lockstep(self) -> None:
        self.assertEqual(
            evidence.EXPECTED_FLOW_LOG_FORMAT, live.EXPECTED_FLOW_LOG_FORMAT
        )
        self.assertEqual(
            evidence.EXPECTED_FLOW_LOG_FORMAT, plan.EXPECTED_FLOW_LOG_FORMAT
        )
        terraform = (REPO_ROOT / "terraform/modules/relay-network/main.tf").read_text()
        self.assertIn(evidence.EXPECTED_FLOW_LOG_FORMAT.replace("${", "$${"), terraform)

    def test_positive_endpoint_and_s3_evidence_passes(self) -> None:
        self.assertEqual(
            [],
            evidence.validate_evidence(
                good_events(), RELAY_IPS, ENDPOINT_IPS, S3_NETWORKS
            ),
        )

    def test_direct_public_https_fails(self) -> None:
        events = good_events()
        events["events"].append({"message": flow_message("10.101.10.10", "8.8.8.8")})
        errors = evidence.validate_evidence(
            events, RELAY_IPS, ENDPOINT_IPS, S3_NETWORKS
        )
        self.assertTrue(any("direct-public" in error for error in errors), errors)

    def test_accepted_http_fails(self) -> None:
        events = good_events()
        events["events"].append(
            {"message": flow_message("10.101.10.10", "52.216.1.10", dst_port="80")}
        )
        errors = evidence.validate_evidence(
            events, RELAY_IPS, ENDPOINT_IPS, S3_NETWORKS
        )
        self.assertTrue(any("HTTP flows" in error for error in errors), errors)

    def test_missing_per_relay_path_fails(self) -> None:
        events = good_events()
        events["events"] = [
            row
            for row in events["events"]
            if not row["message"].startswith("5 767397897469 eni-relay 10.101.12.10")
        ]
        errors = evidence.validate_evidence(
            events, RELAY_IPS, ENDPOINT_IPS, S3_NETWORKS
        )
        self.assertTrue(any("10.101.12.10" in error for error in errors), errors)

    def test_invalid_inventory_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad = Path(temp_dir) / "bad.json"
            bad.write_text("[]", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = evidence.main(
                    [
                        "--flow-events",
                        str(bad),
                        "--relay-ips",
                        "10.101.10.10",
                        "--endpoint-ips",
                        "10.101.20.20",
                        "--s3-prefix-list",
                        str(bad),
                    ]
                )
            self.assertEqual(2, result)
            self.assertIn("must contain one JSON object", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
