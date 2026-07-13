#!/usr/bin/env python3
"""Send a deterministic, rate-bounded UDP flood for readiness testing.

One process rotates across many local source ports. The manual GitHub workflow
runs the same seed-stable tool on multiple hosted runners so the public NLB sees
multiple source IPs as well as rotating tuples. This is spoof-like pressure,
not forged-source traffic: the test remains return-routable and auditable.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=62206)
    parser.add_argument("--pps", type=int, default=2000)
    parser.add_argument("--duration-seconds", type=int, default=300)
    parser.add_argument("--source-sockets", type=int, default=64)
    parser.add_argument("--payload-bytes", type=int, default=512)
    parser.add_argument("--seed", type=int, default=3184)
    parser.add_argument("--start-epoch", type=int, default=0)
    args = parser.parse_args()
    if args.pps <= 0 or args.duration_seconds <= 0 or args.source_sockets <= 0:
        parser.error("pps, duration-seconds, and source-sockets must be positive")
    if args.payload_bytes < 256 or args.payload_bytes > 4096:
        parser.error("payload-bytes must be between 256 and 4096")
    return args


def run(args: argparse.Namespace) -> dict[str, int | str]:
    addresses = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_DGRAM)
    if not addresses:
        raise RuntimeError("target did not resolve")
    family, socktype, proto, _, target = addresses[0]
    sockets = [socket.socket(family, socktype, proto) for _ in range(args.source_sockets)]
    for sock in sockets:
        bind_addr = ("::", 0) if family == socket.AF_INET6 else ("0.0.0.0", 0)
        sock.bind(bind_addr)

    rng = random.Random(args.seed)
    payload = bytearray(rng.getrandbits(8) for _ in range(args.payload_bytes))
    # Stable protocol-major byte plus a changing tail keeps packets
    # deterministic without accidentally replaying a real credential.
    payload[0] = 1

    if args.start_epoch:
        delay = args.start_epoch - time.time()
        if delay > 0:
            time.sleep(delay)

    started_epoch = int(time.time())
    start = time.perf_counter()
    deadline = start + args.duration_seconds
    interval = 1.0 / args.pps
    next_send = start
    sent = 0
    errors = 0
    while True:
        now = time.perf_counter()
        if now >= deadline:
            break
        if now < next_send:
            # This is a maximum sleep slice, not a minimum packet interval:
            # at 2,000 pps the requested 0.5 ms remainder is slept exactly.
            time.sleep(min(next_send - now, 0.001))
            continue
        # Bound catch-up bursts after runner scheduling pauses.
        if now - next_send > 0.25:
            next_send = now
        payload[-8:] = sent.to_bytes(8, "big")
        try:
            sockets[sent % len(sockets)].sendto(payload, target)
            sent += 1
        except OSError:
            errors += 1
        next_send += interval

    ended_epoch = int(time.time())
    for sock in sockets:
        sock.close()
    return {
        "host": args.host,
        "port": args.port,
        "pps": args.pps,
        "duration_seconds": args.duration_seconds,
        "started_epoch": started_epoch,
        "ended_epoch": ended_epoch,
        "source_sockets": args.source_sockets,
        "sent": sent,
        "send_errors": errors,
        "seed": args.seed,
    }


def main() -> None:
    print(json.dumps(run(parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
