#!/usr/bin/env python3
"""Static observability parity guard for issue #1141.

The #1141 failure mode was not a broken alarm expression; it was an environment
parity gap where prod could miss CloudWatch log groups, metric filters, or
alarms that sandbox had already grown. This lint keeps the load-bearing
surfaces tied together:

* deployable env roots must pass the monitoring ownership knobs into the shared
  root module, so tfvars entries do not become silent no-ops.
* the shared root module must wire the server stderr log group into the
  monitoring module, and the AC module alarms into the shared alert SNS topic.
* the alarm resources named in #1141 must stay present and keep action routing
  to that shared topic in the shared modules.

This deliberately does not compare every alarm in Terraform. Some alarms are
environment- or feature-specific by design. Keep this check scoped to the
prod-vs-sandbox observability plumbing that makes the common alarm set exist.
For the env tfvars booleans, "parity" also means pinning the current intended
prod/sandbox alerting posture to literal `true`, not merely comparing both envs
to each other.

This lives under scripts/ because it is both a local operator lint and a CI
guard; the paired fixture tests exercise the CLI before the real tree scan.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


class LintError(Exception):
    pass


@dataclass(frozen=True)
class HclBlock:
    path: Path
    kind: str
    name: str
    body: str


AC_ALARM_ACTION_EXPR = 'var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []'
# These alarms intentionally do not all share the same `count` expression:
# some are feature-gated, some are maintenance-gated, and some are always
# present. The parity contract here is that the root caller keeps AC alarms
# enabled and every core alarm keeps non-empty action routing when present.
AC_CORE_ALARM_NAMES = (
    "disk_usage_high",
    "registration_failure",
    "server_connection_failure",
    "aop_replay_detected",
    "udp_handler_panic",
    "cert_sync_failures",
    "eip_pool_utilization_high",
    "eip_claim_failure",
    "servers_healthy_low",
    "registration_stale",
    "l3_flush_schedule_wait_timeout",
    "publisher_failures",
)
# Keep exemptions explicit and rare. An exemption means the alarm intentionally
# does not use the shared AC SNS action contract; otherwise a new AC alarm
# should join AC_CORE_ALARM_NAMES so it cannot lose SNS routing by omission.
AC_ALARM_EXEMPTIONS: tuple[str, ...] = ()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise LintError(f"missing required file: {path}") from exc


def _scan_block_end(text: str, open_brace: int) -> int:
    # This parser is intentionally narrow for the module/variable/output blocks
    # it scans today. If a targeted block grows an HCL heredoc, add heredoc
    # support and fixtures in the same PR so braces inside heredocs stay inert.
    depth = 0
    in_string = False
    escaped = False
    in_line_comment = False
    in_block_comment = False

    i = open_brace
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == "#":
            in_line_comment = True
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1

    raise LintError("unterminated HCL block")


def find_block(path: Path, kind: str, name: str) -> HclBlock:
    text = _read(path)
    pattern = re.compile(
        rf'(?m)^[ \t]*{re.escape(kind)}[ \t]+"{re.escape(name)}"[ \t]*\{{'
    )
    match = pattern.search(text)
    if not match:
        raise LintError(f"{path}: missing {kind} \"{name}\" block")

    open_brace = text.find("{", match.start())
    end = _scan_block_end(text, open_brace)
    return HclBlock(path=path, kind=kind, name=name, body=text[open_brace + 1 : end - 1])


def find_blocks(path: Path, kind: str) -> list[HclBlock]:
    text = _read(path)
    pattern = re.compile(rf'(?m)^[ \t]*{re.escape(kind)}[ \t]+"([^"]+)"[ \t]*\{{')
    blocks = []
    for match in pattern.finditer(text):
        open_brace = text.find("{", match.start())
        end = _scan_block_end(text, open_brace)
        blocks.append(
            HclBlock(
                path=path,
                kind=kind,
                name=match.group(1),
                body=text[open_brace + 1 : end - 1],
            )
        )
    return blocks


def _normalise_expr(expr: str) -> str:
    # This is not a general HCL expression normalizer; it is only safe for the
    # simple pinned expressions in this file. If a future pin includes string
    # literals with ` #` or ` //`, teach the scanner about that shape and add a
    # fixture before relying on this helper.
    expr = re.sub(r"\s+#.*$", "", expr)
    expr = re.sub(r"\s+//.*$", "", expr)
    return re.sub(r"\s+", " ", expr.strip())


def assignment(block: HclBlock, key: str) -> str | None:
    # Deliberately single-line: every expression this lint pins today is a
    # simple module arg / output / variable default. If one grows a multi-line
    # expression, update this extractor and its fixtures in the same PR.
    match = re.search(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*(.+)$", block.body)
    if not match:
        return None
    return _normalise_expr(match.group(1))


def require_assignment(block: HclBlock, key: str, expected: str) -> None:
    actual = assignment(block, key)
    expected_norm = _normalise_expr(expected)
    if actual != expected_norm:
        where = f'{block.path}: {block.kind} "{block.name}"'
        if actual is None:
            raise LintError(f"{where} must set `{key} = {expected_norm}`")
        raise LintError(
            f"{where} has `{key} = {actual}`, want `{key} = {expected_norm}`"
        )


def require_absent_assignment(
    block: HclBlock, key: str, reason: str | None = None
) -> None:
    # The monitored module blocks are flat module-argument bodies today. If a
    # future module block grows nested blocks, update this extractor and the
    # negative fixtures so nested attributes do not look like top-level args.
    actual = assignment(block, key)
    if actual is not None:
        reason = (
            reason
            or "the monitoring module should be unconditional for prod/sandbox parity"
        )
        raise LintError(
            f'{block.path}: {block.kind} "{block.name}" must not set `{key}`; '
            f"{reason}"
        )


def require_alarm_actions(
    block: HclBlock,
    expected: str,
    *,
    insufficient_data: bool = False,
) -> None:
    require_assignment(block, "alarm_actions", expected)
    require_assignment(block, "ok_actions", expected)
    if insufficient_data:
        require_assignment(block, "insufficient_data_actions", expected)


def require_variable(path: Path, name: str) -> None:
    find_block(path, "variable", name)


def literal_bool(path: Path, name: str) -> bool | None:
    text = _read(path)
    match = re.search(rf"(?m)^[ \t]*{re.escape(name)}[ \t]*=[ \t]*(true|false)\b", text)
    if not match:
        return None
    return match.group(1) == "true"


def require_tfvars_bool(path: Path, name: str, expected: bool) -> None:
    actual = literal_bool(path, name)
    if actual is None:
        raise LintError(f"{path}: must set `{name} = {str(expected).lower()}`")
    if actual != expected:
        raise LintError(
            f"{path}: `{name}` is {str(actual).lower()}, want {str(expected).lower()}"
        )


def require_resource(path: Path, resource_type: str, name: str) -> None:
    find_block(path, f'resource "{resource_type}"', name)


def deployable_env_names(repo: Path) -> tuple[str, ...]:
    env_root = repo / "terraform" / "environments"
    try:
        names = sorted(path.name for path in env_root.iterdir() if path.is_dir())
    except FileNotFoundError as exc:
        raise LintError(f"missing required directory: {env_root}") from exc
    if not names:
        raise LintError(f"{env_root}: no deployable env roots found")
    return tuple(names)


def check_env_root(repo: Path, env: str) -> None:
    env_dir = repo / "terraform" / "environments" / env
    module = find_block(env_dir / "main.tf", "module", "nhp")
    variables = env_dir / "variables.tf"
    tfvars = env_dir / "terraform.tfvars"

    passthroughs = [
        "deploy_ac",
        "enable_slack_notifications",
        "slack_workspace_id",
        "slack_channel_id",
        "chatbot_owned_externally",
    ]
    for name in passthroughs:
        require_variable(variables, name)
        require_assignment(module, name, f"var.{name}")

    require_tfvars_bool(tfvars, "deploy_ac", True)
    # These literal-true assertions intentionally pin the current production
    # and sandbox alerting posture. A planned routing change should update this
    # lint alongside the tfvars edit, rather than weakening alert coverage by
    # accident in only one environment.
    require_tfvars_bool(tfvars, "enable_slack_notifications", True)
    require_tfvars_bool(tfvars, "chatbot_owned_externally", True)


def check_root_module(repo: Path) -> None:
    root_main = repo / "terraform" / "main.tf"

    monitoring = find_block(root_main, "module", "monitoring")
    require_absent_assignment(monitoring, "count")
    require_absent_assignment(monitoring, "for_each")
    require_assignment(monitoring, "environment", "var.environment")
    require_assignment(monitoring, "cell_id", "var.cell_id")
    require_assignment(
        monitoring,
        "server_stderr_log_group_name",
        "module.compute.log_group_stderr_name",
    )
    require_assignment(monitoring, "name_prefix", "local.name_prefix")
    require_assignment(
        monitoring, "chatbot_owned_externally", "var.chatbot_owned_externally"
    )

    ac = find_block(root_main, "module", "ac")
    require_assignment(ac, "count", "var.deploy_ac ? 1 : 0")
    require_assignment(ac, "enable_cloudwatch_alarms", "true")
    require_assignment(ac, "alarm_sns_topic_arn", "module.monitoring.sns_topic_arn")
    require_assignment(ac, "alerts_sns_topic_arn", "module.monitoring.sns_topic_arn")


def check_shared_resources(repo: Path) -> None:
    monitoring_main = repo / "terraform" / "modules" / "monitoring" / "main.tf"
    ac_monitoring = repo / "terraform" / "modules" / "ac" / "monitoring.tf"
    ac_variables = repo / "terraform" / "modules" / "ac" / "variables.tf"
    compute_main = repo / "terraform" / "modules" / "compute" / "main.tf"
    compute_outputs = repo / "terraform" / "modules" / "compute" / "outputs.tf"

    alerts_topic = find_block(monitoring_main, 'resource "aws_sns_topic"', "alerts")
    for key in ("count", "for_each"):
        require_absent_assignment(
            alerts_topic,
            key,
            "the shared alert SNS topic must be unconditional for alarm routing",
        )

    require_resource(compute_main, "aws_cloudwatch_log_group", "server_stderr")
    require_assignment(
        find_block(compute_outputs, "output", "log_group_stderr_name"),
        "value",
        "aws_cloudwatch_log_group.server_stderr.name",
    )

    require_resource(monitoring_main, "aws_cloudwatch_log_metric_filter", "server_panic")
    require_alarm_actions(
        find_block(
            monitoring_main, 'resource "aws_cloudwatch_metric_alarm"', "server_panic"
        ),
        "[aws_sns_topic.alerts.arn]",
        insufficient_data=True,
    )
    require_alarm_actions(
        find_block(
            monitoring_main,
            'resource "aws_cloudwatch_metric_alarm"',
            "server_instance_restart",
        ),
        "[aws_sns_topic.alerts.arn]",
    )
    require_alarm_actions(
        find_block(
            monitoring_main,
            'resource "aws_cloudwatch_metric_alarm"',
            "ac_registration_latency",
        ),
        "[aws_sns_topic.alerts.arn]",
    )
    ac_alarm_blocks = {
        block.name: block
        for block in find_blocks(ac_monitoring, 'resource "aws_cloudwatch_metric_alarm"')
    }
    missing_ac_alarms = sorted(set(AC_CORE_ALARM_NAMES) - set(ac_alarm_blocks))
    if missing_ac_alarms:
        raise LintError(
            f"{ac_monitoring}: missing AC CloudWatch alarm resource(s): "
            + ", ".join(missing_ac_alarms)
        )
    untracked_ac_alarms = sorted(
        set(ac_alarm_blocks) - set(AC_CORE_ALARM_NAMES) - set(AC_ALARM_EXEMPTIONS)
    )
    if untracked_ac_alarms:
        raise LintError(
            f"{ac_monitoring}: AC CloudWatch alarm(s) must be added to "
            "AC_CORE_ALARM_NAMES or AC_ALARM_EXEMPTIONS: "
            + ", ".join(untracked_ac_alarms)
        )
    # AC alarms intentionally pin only alarm/ok actions; insufficient-data
    # handling differs by alarm and is not the #1141 SNS-routing contract.
    for name in AC_CORE_ALARM_NAMES:
        alarm = ac_alarm_blocks[name]
        require_alarm_actions(alarm, AC_ALARM_ACTION_EXPR)
        if name == "registration_stale":
            require_assignment(
                alarm,
                "count",
                "var.enable_cloudwatch_alarms ? 1 : 0",
            )

    require_assignment(
        find_block(ac_variables, "variable", "enable_cloudwatch_alarms"),
        "default",
        "true",
    )


def run(repo: Path) -> None:
    # Discover env roots so a future deployable env cannot escape the #1141
    # guard by omission.
    for env in deployable_env_names(repo):
        check_env_root(repo, env)
    check_root_module(repo)
    check_shared_resources(repo)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_repo_root(),
        help="Repository root to scan (defaults to this script's checkout)",
    )
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    try:
        run(repo)
    except LintError as exc:
        print(f"ERROR: observability parity check failed: {exc}", file=sys.stderr)
        return 1

    print("OK: prod/sandbox observability parity surfaces are wired (#1141)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
