#!/usr/bin/env python3
"""Regression fence for the public AC 443 target-group transport contract."""

import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))

from _tf_lint_lib import iter_resources, parse_tf_files, unquote  # noqa: E402

ParsedTf = list[tuple[Path, dict[str, Any]]]


def read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def target_group_body(parsed: ParsedTf, rel: str, name: str) -> dict[str, Any]:
    expected_file = REPO_ROOT / rel
    for _file, rtype, resource_name, body in iter_resources(parsed):
        if _file == expected_file and rtype == "aws_lb_target_group" and resource_name == name:
            return body
    raise AssertionError(f"aws_lb_target_group.{name} not found in {rel}")


def assert_ac_tcp_tg_contract(parsed: ParsedTf, rel: str, name: str) -> None:
    body = target_group_body(parsed, rel, name)

    assert unquote(body.get("protocol")) == "TCP", f"{name} must stay TCP passthrough"
    assert unquote(body.get("target_type")) == "instance", f"{name} must stay instance-targeted"
    assert body.get("port") == 443, f"{name} must stay on public HTTPS port 443"
    assert body.get("preserve_client_ip") is True, f"{name} must preserve client IP at L3"
    assert body.get("proxy_protocol_v2") is False, f"{name} must not inject Proxy Protocol v2"


def test_blue_and_green_target_groups() -> None:
    parsed = parse_tf_files(REPO_ROOT / "terraform" / "modules" / "ac")

    assert_ac_tcp_tg_contract(parsed, "terraform/modules/ac/main.tf", "ac_tcp")
    assert_ac_tcp_tg_contract(parsed, "terraform/modules/ac/blue_green.tf", "ac_tcp_green")


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
