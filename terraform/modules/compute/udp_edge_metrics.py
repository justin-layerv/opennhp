#!/usr/bin/env python3
"""Emit one-minute NHP UDP edge counters as CloudWatch EMF.

The collector keeps network, kernel, and host-admission sheds distinct. It
reads monotonic kernel/iptables counters, emits per-interval deltas, and treats
missing iptables markers as an explicit collector error rather than a zero.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time


STATE_PATH = Path(os.environ.get("NHP_UDP_EDGE_STATE", "/var/lib/nhp-udp-edge-metrics/state.json"))
LOG_PATH = Path(os.environ.get("NHP_UDP_EDGE_LOG", "/opt/layerv/nhp-server/log/server-udp-edge-metrics.log"))


def read_udp_snmp(path: Path = Path("/proc/net/snmp")) -> dict[str, int]:
    lines = [line.split() for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("Udp:")]
    if len(lines) != 2 or lines[0][0] != "Udp:" or lines[1][0] != "Udp:":
        raise ValueError(f"unexpected UDP SNMP shape in {path}")
    names = lines[0][1:]
    values = [int(value) for value in lines[1][1:]]
    if len(names) != len(values):
        raise ValueError(f"UDP SNMP header/value mismatch in {path}")
    return dict(zip(names, values, strict=True))


def read_iptables_packets(output: str, marker: str) -> int | None:
    """Return one reviewed rule's counter; missing or duplicate markers fail closed."""
    matches = []
    for line in output.splitlines():
        if marker not in line:
            continue
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        matches.append(int(fields[0]))
    if len(matches) != 1:
        return None
    return matches[0]


def read_udp_socket_drops(paths: tuple[Path, ...] = (Path("/proc/net/udp"), Path("/proc/net/udp6")), port: int = 62206) -> int | None:
    """Return total kernel drops for every host-network socket on the port."""
    port_hex = f"{port:04X}"
    matches = []
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 13 or fields[1].rsplit(":", 1)[-1].upper() != port_hex:
                continue
            matches.append(int(fields[-1]))
    if not matches:
        return None
    return sum(matches)


def delta(current: int, previous: int | None) -> int:
    if previous is None:
        return 0
    if current < previous:  # reboot, rule replacement, or counter reset
        return current
    return current - previous


def load_state(path: Path) -> dict[str, int]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    # bool subclasses int in Python, but persisted counters must remain actual
    # integers so a corrupted `true` does not silently become a baseline of 1.
    return {str(key): value for key, value in raw.items() if type(value) is int}


def save_state(path: Path, state: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def marker_error(
    socket_drops: int | None,
    accepted: int | None,
    global_drops: int | None,
    per_source_drops: int | None,
    global_rate_limit_enabled: bool,
) -> int:
    return int(
        socket_drops is None
        or accepted is None
        or per_source_drops is None
        or (global_rate_limit_enabled and global_drops is None)
        or (not global_rate_limit_enabled and global_drops is not None)
    )


def global_rate_limit_enabled() -> bool:
    value = os.environ.get("NHP_GLOBAL_RATE_LIMIT_ENABLED", "").lower()
    if value not in {"true", "false"}:
        raise RuntimeError("NHP_GLOBAL_RATE_LIMIT_ENABLED must be exactly true or false")
    return value == "true"


def collect() -> tuple[dict[str, int], dict[str, int]]:
    udp = read_udp_snmp()
    socket_drops = read_udp_socket_drops()
    global_enabled = global_rate_limit_enabled()
    iptables = subprocess.run(
        ["iptables", "-L", "INPUT", "-v", "-x", "-n"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    accepted = read_iptables_packets(iptables, "nhp-knock-admitted")
    global_drops = read_iptables_packets(iptables, "nhp-knock-global-drop")
    per_source_drops = read_iptables_packets(iptables, "nhp-knock-per-source-drop")
    collector_error = marker_error(socket_drops, accepted, global_drops, per_source_drops, global_enabled)
    current = {
        "udp_in_errors": udp.get("InErrors", 0),
        "udp_socket_drops": socket_drops or 0,
        "iptables_accepted": accepted or 0,
        "iptables_global_drops": global_drops or 0,
        "iptables_per_source_drops": per_source_drops or 0,
    }
    previous = load_state(STATE_PATH)
    accepted_delta = delta(current["iptables_accepted"], previous.get("iptables_accepted"))
    global_drop_delta = delta(current["iptables_global_drops"], previous.get("iptables_global_drops"))
    per_source_drop_delta = delta(current["iptables_per_source_drops"], previous.get("iptables_per_source_drops"))
    metrics = {
        # Every UDP/62206 packet terminates in exactly one of these canonical
        # rules. Unlike host-wide /proc/net/snmp InDatagrams, their sum cannot
        # be inflated by DNS, NTP, or unrelated container traffic.
        "UDPIngressDatagram": accepted_delta + global_drop_delta + per_source_drop_delta,
        "UDPKernelReceiveError": delta(current["udp_in_errors"], previous.get("udp_in_errors")),
        "UDPReceiveBufferDrop": delta(current["udp_socket_drops"], previous.get("udp_socket_drops")),
        "UDPGlobalRateLimitDrop": global_drop_delta,
        "UDPPerSourceRateLimitDrop": per_source_drop_delta,
        "UDPEdgeCollectorError": collector_error,
        "UDPEdgeCollectorHeartbeat": 1,
    }
    return current, metrics


def required_environment() -> dict[str, str]:
    names = ("NHP_ENVIRONMENT", "NHP_CELL_ID", "INSTANCE_ID", "NHP_GLOBAL_RATE_LIMIT_ENABLED")
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"missing required collector environment: {', '.join(missing)}")
    return {name: os.environ[name] for name in names}


def emit(metrics: dict[str, int]) -> None:
    environment = required_environment()
    dimensions = {
        "Environment": environment["NHP_ENVIRONMENT"],
        "Cell": environment["NHP_CELL_ID"],
        "InstanceId": environment["INSTANCE_ID"],
    }
    document = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": "LayerV/NHP",
                    "Dimensions": [
                        ["Environment", "Cell"],
                        ["Environment", "Cell", "InstanceId"],
                    ],
                    "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics],
                }
            ],
        },
        **dimensions,
        **metrics,
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")


def main() -> None:
    current, metrics = collect()
    # Emit before advancing the baseline. If persistence then fails, the next
    # interval may double-count rather than silently lose already-collected
    # drops; that fail-closed bias is preferable for an availability gate.
    emit(metrics)
    save_state(STATE_PATH, current)


if __name__ == "__main__":
    main()
