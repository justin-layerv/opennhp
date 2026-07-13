#!/usr/bin/env python3
"""Verify per-relay endpoint/S3 egress and absence of direct public egress."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any


FLOW_LOG_FIELDS = (
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
    "pkt-srcaddr",
    "pkt-dstaddr",
    "pkt-src-aws-service",
    "pkt-dst-aws-service",
    "flow-direction",
    "traffic-path",
)
EXPECTED_FLOW_LOG_FORMAT = " ".join(f"${{{field}}}" for field in FLOW_LOG_FIELDS)
FIELD_INDEX = {field: index for index, field in enumerate(FLOW_LOG_FIELDS)}


def _csv_set(value: str, label: str) -> set[str]:
    values = {item.strip() for item in value.split(",") if item.strip()}
    if not values:
        raise ValueError(f"{label} must contain at least one address")
    for item in values:
        ipaddress.ip_address(item)
    return values


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def validate_evidence(
    flow_events: dict[str, Any],
    relay_ips: set[str],
    endpoint_ips: set[str],
    s3_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> list[str]:
    endpoint_https: set[str] = set()
    s3_https: set[str] = set()
    direct_public_https: list[tuple[str, str]] = []
    accepted_http: list[tuple[str, str]] = []

    events = flow_events.get("events")
    if not isinstance(events, list):
        raise ValueError("Flow Log evidence must contain an events array")
    for event in events:
        if not isinstance(event, dict):
            continue
        fields = str(event.get("message", "")).split()
        if len(fields) != len(FLOW_LOG_FIELDS):
            continue
        src = fields[FIELD_INDEX["pkt-srcaddr"]]
        if src == "-":
            src = fields[FIELD_INDEX["srcaddr"]]
        dst = fields[FIELD_INDEX["pkt-dstaddr"]]
        if dst == "-":
            dst = fields[FIELD_INDEX["dstaddr"]]
        if (
            src not in relay_ips
            or fields[FIELD_INDEX["action"]] != "ACCEPT"
            or fields[FIELD_INDEX["flow-direction"]] != "egress"
        ):
            continue
        protocol = fields[FIELD_INDEX["protocol"]]
        dst_port = fields[FIELD_INDEX["dstport"]]
        if protocol == "6" and dst_port == "80":
            accepted_http.append((src, dst))
        if protocol != "6" or dst_port != "443":
            continue
        if dst in endpoint_ips:
            endpoint_https.add(src)
            continue
        try:
            destination_ip = ipaddress.ip_address(dst)
        except ValueError:
            direct_public_https.append((src, dst))
            continue
        if any(destination_ip in network for network in s3_networks):
            s3_https.add(src)
        else:
            direct_public_https.append((src, dst))

    errors: list[str] = []
    if endpoint_https != relay_ips:
        errors.append(
            "accepted interface-endpoint HTTPS evidence is missing for relay IPs: "
            f"{sorted(relay_ips - endpoint_https)!r}"
        )
    if s3_https != relay_ips:
        errors.append(
            "accepted S3-prefix-list HTTPS evidence is missing for relay IPs: "
            f"{sorted(relay_ips - s3_https)!r}"
        )
    if direct_public_https:
        errors.append(
            f"accepted direct-public relay HTTPS flows exist: {direct_public_https!r}"
        )
    if accepted_http:
        errors.append(f"accepted relay HTTP flows exist: {accepted_http!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flow-events", type=Path, required=True)
    parser.add_argument("--relay-ips", required=True)
    parser.add_argument("--endpoint-ips", required=True)
    parser.add_argument("--s3-prefix-list", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        relay_ips = _csv_set(args.relay_ips, "relay IPs")
        endpoint_ips = _csv_set(args.endpoint_ips, "endpoint IPs")
        flow_events = _load_object(args.flow_events)
        prefix_lists = _load_object(args.s3_prefix_list).get("PrefixLists")
        if (
            not isinstance(prefix_lists, list)
            or len(prefix_lists) != 1
            or not isinstance(prefix_lists[0], dict)
        ):
            raise ValueError("S3 evidence must contain exactly one prefix list")
        cidrs = prefix_lists[0].get("Cidrs")
        if not isinstance(cidrs, list) or not cidrs:
            raise ValueError("S3 prefix list must contain CIDRs")
        s3_networks = [ipaddress.ip_network(str(cidr)) for cidr in cidrs]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"relay DMZ Flow Log evidence inventory failed: {exc}", file=sys.stderr)
        return 2

    errors = validate_evidence(flow_events, relay_ips, endpoint_ips, s3_networks)
    for error in errors:
        print(f"relay DMZ Flow Log evidence violation: {error}", file=sys.stderr)
    if errors:
        return 1
    print("relay DMZ Flow Log evidence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
