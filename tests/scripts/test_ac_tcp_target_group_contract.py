#!/usr/bin/env python3
"""Regression fence for the public AC 443 target-group transport contract."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def resource_block(source: str, resource_type: str, name: str) -> str:
    needle = f'resource "{resource_type}" "{name}"'
    start = source.find(needle)
    assert start != -1, f"missing {needle}"

    brace_start = source.find("{", start)
    assert brace_start != -1, f"missing opening brace for {needle}"

    # The target-group resource blocks contain no heredocs today. Extend this
    # scanner or switch to an HCL parser before relying on it for blocks that do.
    depth = 0
    in_block_comment = False
    in_line_comment = False
    in_string = False
    escaped = False
    idx = brace_start
    while idx < len(source):
        char = source[idx]
        next_char = source[idx + 1] if idx + 1 < len(source) else ""

        if in_line_comment:
            in_line_comment = char != "\n"
            idx += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                idx += 2
                continue
            idx += 1
            continue

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            idx += 1
            continue

        if char == "#":
            in_line_comment = True
            idx += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            idx += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            idx += 2
            continue
        if char == '"':
            in_string = True
            idx += 1
            continue

        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
        idx += 1

    raise AssertionError(f"missing closing brace for {needle}")


def has_attr(block: str, name: str, value: str) -> bool:
    block = strip_hcl_comments(block)
    pattern = rf"(?m)^\s*{re.escape(name)}\s*=\s*{re.escape(value)}\s*(?:#.*)?$"
    return re.search(pattern, block) is not None


def strip_hcl_comments(source: str) -> str:
    result: list[str] = []
    in_block_comment = False
    in_line_comment = False
    in_string = False
    escaped = False
    idx = 0
    while idx < len(source):
        char = source[idx]
        next_char = source[idx + 1] if idx + 1 < len(source) else ""

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                result.append(char)
            else:
                result.append(" ")
            idx += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                result.extend("  ")
                idx += 2
                continue
            result.append("\n" if char == "\n" else " ")
            idx += 1
            continue

        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            idx += 1
            continue

        if char == "#":
            in_line_comment = True
            result.append(" ")
            idx += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            result.extend("  ")
            idx += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            result.extend("  ")
            idx += 2
            continue
        if char == '"':
            in_string = True

        result.append(char)
        idx += 1

    return "".join(result)


def collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def assert_ac_tcp_tg_contract(rel: str, name: str) -> None:
    block = resource_block(read(rel), "aws_lb_target_group", name)

    assert has_attr(block, "protocol", '"TCP"'), f"{name} must stay TCP passthrough"
    assert has_attr(block, "target_type", '"instance"'), f"{name} must stay instance-targeted"
    assert has_attr(block, "port", "443"), f"{name} must stay on public HTTPS port 443"
    assert has_attr(block, "preserve_client_ip", "true"), f"{name} must preserve client IP at L3"
    assert has_attr(block, "proxy_protocol_v2", "false"), f"{name} must not inject Proxy Protocol v2"
    assert not has_attr(block, "proxy_protocol_v2", "true"), f"{name} must not re-enable Proxy Protocol v2"


def test_blue_and_green_target_groups() -> None:
    assert_ac_tcp_tg_contract("terraform/modules/ac/main.tf", "ac_tcp")
    assert_ac_tcp_tg_contract("terraform/modules/ac/blue_green.tf", "ac_tcp_green")


def test_blue_green_drift_check_pins_transport_contract() -> None:
    main_tf = read("terraform/modules/ac/main.tf")

    for snippet in [
        "aws_lb_target_group.ac_tcp.preserve_client_ip",
        "aws_lb_target_group.ac_tcp_green[0].preserve_client_ip",
        "!aws_lb_target_group.ac_tcp.proxy_protocol_v2",
        "!aws_lb_target_group.ac_tcp_green[0].proxy_protocol_v2",
    ]:
        assert snippet in main_tf, f"ac_tcp_target_group_drift must pin {snippet!r}"


def test_traefik_entrypoints_do_not_expect_proxy_protocol() -> None:
    user_data = read("terraform/modules/ac/user_data.sh.tpl")

    for stale in [
        "[entryPoints.https.proxyProtocol]",
        "[entryPoints.traefik.proxyProtocol]",
        "ProxyProtocol required because NLB target group has proxy_protocol_v2 enabled",
        "ProxyProtocol for NLB - preserves client IP",
    ]:
        assert stale not in user_data, f"user_data still carries stale Proxy Protocol config/comment {stale!r}"

    assert "[entryPoints.https.forwardedHeaders]" in user_data
    assert 'trustedIPs = ["${vpc_cidr}"]' in user_data
    assert "public AC NLB preserves client IP at L3" in user_data


def test_qurl_site_authz_docs_describe_l3_client_ip_preservation() -> None:
    variables_tf = collapsed(read("terraform/variables.tf"))

    assert "HTTPS entrypoint uses PROXY protocol from the NLB" not in variables_tf
    assert "public AC NLB target groups preserve client IP at L3" in variables_tf
    assert "do NOT inject PROXY protocol" in variables_tf


if __name__ == "__main__":
    test_blue_and_green_target_groups()
    test_blue_green_drift_check_pins_transport_contract()
    test_traefik_entrypoints_do_not_expect_proxy_protocol()
    test_qurl_site_authz_docs_describe_l3_client_ip_preservation()
