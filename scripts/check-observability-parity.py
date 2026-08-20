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


def _block_location(block: HclBlock) -> str:
    return f'{block.path}: {block.kind} "{block.name}"'


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
    "ac_tg_no_healthy_targets",
    "ac_tg_no_healthy_targets_any_color",
    "ebpf_map_full",
    "ebpf_perf_lost_samples",
    "ebpf_deny_telemetry_suppressed",
    "ebpf_conntrack_v4_usage_high",
    "ebpf_conntrack_v6_usage_high",
    "ebpf_frag_state_v6_usage_high",
    "ebpf_conntrack_sample_errors",
    "ebpf_conntrack_partial_samples",
)
# Keep exemptions explicit and rare. An exemption means the alarm intentionally
# does not use the shared AC SNS action contract; otherwise a new AC alarm
# should join AC_CORE_ALARM_NAMES so it cannot lose SNS routing by omission.
AC_ALARM_EXEMPTIONS: tuple[str, ...] = ()

RELAY_ALARM_ACTION_EXPR = "local.relay_alarm_actions"
RELAY_CORE_ALARM_NAMES = (
    "relay_tg_unhealthy_hosts",
    "relay_tg_zero_healthy_targets",
    "relay_bootstrap_failure",
    "relay_capacity_below_baseline",
    "relay_shedding",
    "relay_shedding_unknown_environment",
)
# Mirror AC_ALARM_EXEMPTIONS: a relay alarm here intentionally opts out of the
# shared relay SNS action contract; otherwise a new relay alarm should join
# RELAY_CORE_ALARM_NAMES so it cannot escape the parity fences by omission.
RELAY_ALARM_EXEMPTIONS: tuple[str, ...] = ()
# Single-event detectors set ok_actions=[]: returning to OK means no new event
# arrived in the lookback window, not that the underlying fault cleared. The
# remaining relay alarms keep symmetric action routing. The paired fixture
# imports this set so the checker and test cannot drift on which alarms are
# single-event.
RELAY_SINGLE_EVENT_ALARM_NAMES = (
    "relay_bootstrap_failure",
    "relay_shedding",
    "relay_shedding_unknown_environment",
)
QURL_SERVICE_ALARM_ACTION_EXPR = "local.qurl_service_alarm_actions"
QURL_RESOURCE_KEY_FAILURE_FILTER_PATTERN = (
    r'"{ $.msg = \"resource-key provisioning failed\" }"'
)
QURL_CI_LOCK_FAILURE_ALARM_NAME = "qurl_ci_sandbox_live_env_lock_failure"
QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY = (
    "SELECT SUM(SandboxLiveEnvLockFailure) "
    'FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)'
)
QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY_PATTERN = (
    r'SELECT\s+SUM\(SandboxLiveEnvLockFailure\)\s+'
    r'FROM\s+SCHEMA\("LayerV/QURLServiceCI",\s*Reason,\s*Action\)'
)
QURL_CI_LOCK_FAILURE_RUNBOOK_DIAGNOSTIC_QUERY_PATTERN = (
    r'```sql\r?\nSELECT SUM\(SandboxLiveEnvLockFailure\)\r?\n'
    r'FROM SCHEMA\("LayerV/QURLServiceCI", Reason, Action\)\r?\n```'
)
QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY = (
    "SELECT SUM(SandboxLiveEnvLockFailure) "
    'FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action) '
    "GROUP BY Reason, Action ORDER BY SUM() DESC"
)
QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY_PATTERN = (
    r'```sql\r?\nSELECT SUM\(SandboxLiveEnvLockFailure\)\r?\n'
    r'FROM SCHEMA\("LayerV/QURLServiceCI", Reason, Action\)\r?\n'
    r'GROUP BY Reason, Action\r?\nORDER BY SUM\(\) DESC\r?\n```'
)
QURL_CI_LOCK_FAILURE_RUNBOOK = "docs/runbooks/qurl-sandbox-live-env-lock-alarm.md"
QURL_CI_LOCK_FAILURE_RUNBOOK_URL = (
    "https://github.com/layervai/nhp/blob/main/"
    f"{QURL_CI_LOCK_FAILURE_RUNBOOK}"
)
QURL_CI_LOCK_FAILURE_CANARY_DIMENSIONS = "Reason=AlarmCanary,Action=acquire"
QURL_CI_LOCK_FAILURE_CONTENTION_CONTRACT = (
    "7,200-second wait budget is exhausted and the waiting job fails"
)
QURL_CI_LOCK_FAILURE_CANARY_PATTERN = (
    r"aws cloudwatch put-metric-data \\\r?\n"
    r"\s*--region us-east-2 \\\r?\n"
    r"\s*--namespace 'LayerV/QURLServiceCI' \\\r?\n"
    r"\s*--metric-name 'SandboxLiveEnvLockFailure' \\\r?\n"
    r"\s*--value 1 \\\r?\n"
    r"\s*--unit Count\r?\n\r?\n"
    r"aws cloudwatch put-metric-data \\\r?\n"
    r"\s*--region us-east-2 \\\r?\n"
    r"\s*--namespace 'LayerV/QURLServiceCI' \\\r?\n"
    r"\s*--metric-name 'SandboxLiveEnvLockFailure' \\\r?\n"
    r"\s*--dimensions 'Reason=AlarmCanary,Action=acquire' \\\r?\n"
    r"\s*--value 1 \\\r?\n"
    r"\s*--unit Count"
)
ASYNC_RUNTIME_PANIC_MESSAGE = "runtime panic encountered"
ASYNC_RUNTIME_PANIC_FILTER_PATTERN = (
    r'"\"msgToPacketRoutine\" \"runtime panic encountered\""'
)
# The dispatchHandler recover (PR #3643) is the second structured recover site
# that converts a panic into dropped work. Recovering removed this class from
# the stderr "panic:" detector, so its structured log line is the ONLY alarm
# signal — the Go line and this filter must stay in lockstep or a
# remote-triggerable handler panic drops requests silently.
HANDLER_PANIC_FILTER_PATTERN = r'"\"dispatchHandler\" \"runtime panic encountered\""'
HANDLER_PANIC_LOG_CALL_SITE = "dispatchHandler"
HANDLER_PANIC_LOG_WRAPPER = "core.ErrRuntimePanic.WithExtra("


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise LintError(f"missing required file: {path}") from exc


def _scan_block_end(text: str, open_brace: int, *, language: str = "hcl") -> int:
    # This parser is intentionally narrow for the Terraform blocks and small Go
    # functions it scans today. If a targeted Terraform block grows an HCL
    # heredoc, add heredoc support and fixtures in the same PR so braces inside
    # heredocs stay inert.
    if language not in {"hcl", "go"}:
        raise LintError(f"unsupported block scan language: {language}")
    depth = 0
    in_string = False
    in_raw_string = False
    in_rune = False
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

        if in_raw_string:
            if ch == "`":
                in_raw_string = False
            i += 1
            continue

        if in_rune:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_rune = False
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

        if language == "hcl" and ch == "#":
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
        if language == "go" and ch == "`":
            in_raw_string = True
            i += 1
            continue
        if language == "go" and ch == "'":
            in_rune = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1

    raise LintError(f"unterminated {language} block")


def find_block(path: Path, kind: str, name: str) -> HclBlock:
    text = _read(path)
    pattern = re.compile(
        rf'(?m)^[ \t]*{re.escape(kind)}[ \t]+"{re.escape(name)}"[ \t]*\{{'
    )
    match = pattern.search(text)
    if not match:
        raise LintError(f'{path}: missing {kind} "{name}" block')

    open_brace = text.find("{", match.start())
    end = _scan_block_end(text, open_brace)
    return HclBlock(
        path=path, kind=kind, name=name, body=text[open_brace + 1 : end - 1]
    )


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


def _strip_line_comment(
    expr: str,
    comment_prefixes: tuple[str, ...] = ("#", "//"),
    string_quotes: tuple[str, ...] = ('"',),
) -> str:
    in_string: str | None = None
    escaped = False
    for i, ch in enumerate(expr):
        prev = expr[i - 1] if i > 0 else ""

        if in_string:
            # Shell callers only pin simple single-quoted literals today; if a
            # pinned single-quoted shell string needs POSIX backslash semantics,
            # add a fixture and split the quote handling here.
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            continue

        if ch in string_quotes:
            in_string = ch
            continue
        for prefix in comment_prefixes:
            if expr.startswith(prefix, i) and (i == 0 or prev.isspace()):
                return expr[:i]
    return expr


def _normalise_expr(expr: str) -> str:
    # This is not a general HCL expression normalizer; it is only safe for the
    # simple pinned expressions in this file. Inline comments are stripped only
    # outside quoted strings so literal values such as "https://example.com" stay
    # intact.
    expr = _strip_line_comment(expr)
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
        where = _block_location(block)
        if actual is None:
            raise LintError(f"{where} must set `{key} = {expected_norm}`")
        raise LintError(
            f"{where} has `{key} = {actual}`, want `{key} = {expected_norm}`"
        )


def require_block_text(block: HclBlock, needle: str, reason: str) -> None:
    if needle not in block.body:
        raise LintError(f"{_block_location(block)} missing `{needle}` ({reason})")


def require_block_regex(block: HclBlock, pattern: str, reason: str) -> None:
    if re.search(pattern, block.body) is None:
        raise LintError(
            f"{_block_location(block)} missing pattern `{pattern}` ({reason})"
        )


def require_file_tokens(
    path: Path, text: str, tokens: tuple[str, ...], reason: str
) -> None:
    for token in tokens:
        if token not in text:
            raise LintError(f"{path}: missing `{token}` ({reason})")


def require_file_regex(
    path: Path, text: str, pattern: str, expected: str, reason: str
) -> None:
    if re.search(pattern, text) is None:
        raise LintError(f"{path}: missing `{expected}` ({reason})")


def has_metric_name(text: str, metric_name: str) -> bool:
    return (
        re.search(rf'\bmetric_name\s*=\s*"{re.escape(metric_name)}"', text) is not None
    )


def require_hcl_map_entry(block: HclBlock, key: str, value: str, reason: str) -> None:
    if not re.search(
        rf'(?m)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*"{re.escape(value)}"[ \t]*$',
        block.body,
    ):
        raise LintError(
            f'{_block_location(block)} missing `{key} = "{value}"` ({reason})'
        )


def map_assignment(block: HclBlock, key: str) -> dict[str, str] | None:
    # Deliberately narrow like assignment(): relay/monitoring dimensions are
    # simple string expressions today. If a pinned map grows multi-line values,
    # update this extractor and its fixtures in the same PR. Terraform fmt
    # canonicalizes the maps this lint pins to the multi-line form below.
    match = re.search(
        rf"(?ms)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*\{{(?P<body>.*?)^[ \t]*\}}",
        block.body,
    )
    if not match:
        return None

    result: dict[str, str] = {}
    for line in match.group("body").splitlines():
        line = _strip_line_comment(line).strip()
        if not line:
            continue
        item = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", line)
        if not item:
            where = _block_location(block)
            raise LintError(f"{where} has unsupported `{key}` entry: {line}")
        result[item.group(1)] = _normalise_expr(item.group(2))
    return result


def require_map_assignment(block: HclBlock, key: str, expected: dict[str, str]) -> None:
    actual = map_assignment(block, key)
    expected_norm = {name: _normalise_expr(value) for name, value in expected.items()}
    where = _block_location(block)
    if actual is None:
        raise LintError(f"{where} must set `{key} = {expected_norm}`")
    if actual != expected_norm:
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
        raise LintError(f"{_block_location(block)} must not set `{key}`; {reason}")


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


def require_shell_arg(path: Path, arg: str, reason: str) -> None:
    pattern = re.compile(r"(?<!\S)" + re.escape(arg) + r"(?=\s|\\|$)")
    for line in _read(path).splitlines():
        line = _strip_line_comment(line, ("#",), ('"', "'"))
        if pattern.search(line):
            return
    raise LintError(f"{path}: missing `{arg}` ({reason})")


def go_function_body(path: Path, name: str) -> str:
    text = _read(path)
    match = re.search(rf"(?m)^func {re.escape(name)}\([^)]*\)[^{{]*\{{", text)
    if not match:
        raise LintError(f"{path}: missing Go function `{name}`")
    # The regex ends at the opening brace ([^{]* admits no earlier one), so the
    # match's last char is that brace.
    open_brace = match.end() - 1
    end = _scan_block_end(text, open_brace, language="go")
    return text[open_brace + 1 : end - 1]


def require_go_function_text(
    path: Path, function: str, needle: str, reason: str
) -> None:
    for line in go_function_body(path, function).splitlines():
        # The pinned dim builders have no raw strings; add a fixture before
        # matching a future Go needle that can contain `//` inside backticks.
        line = _strip_line_comment(line, ("//",))
        if needle in line:
            return
    raise LintError(f"{path}: {function}: missing `{needle}` ({reason})")


def go_new_error_message(path: Path, name: str) -> str:
    text = _read(path)
    pattern = (
        rf"(?ms)^[ \t]*{re.escape(name)}[ \t]*=[ \t]*"
        r'newError\([^,]+,[ \t]*"(?P<message>[^"]+)"\)'
    )
    match = re.search(pattern, text)
    if not match:
        raise LintError(f"{path}: missing Go error message for `{name}`")
    return match.group("message")


def list_assignment(block: HclBlock, key: str) -> tuple[str, ...] | None:
    # Terraform fmt canonicalizes the lists this lint pins to the multi-line
    # form below.
    match = re.search(
        rf"(?ms)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*\[(?P<body>.*?)^[ \t]*\]",
        block.body,
    )
    if not match:
        return None

    items: list[str] = []
    for line in match.group("body").splitlines():
        line = _strip_line_comment(line).strip().rstrip(",").strip()
        if line:
            items.append(_normalise_expr(line))
    return tuple(items)


def require_list_contains(block: HclBlock, key: str, expected: str) -> None:
    items = list_assignment(block, key)
    expected_norm = _normalise_expr(expected)
    where = _block_location(block)
    if items is None:
        raise LintError(f"{where} must set `{key}` including {expected_norm}")
    if expected_norm not in items:
        raise LintError(
            f"{where} has `{key} = {list(items)}`, want it to include {expected_norm}"
        )


def require_name_subset(
    values: tuple[str, ...],
    allowed: tuple[str, ...],
    values_name: str,
    allowed_name: str,
) -> None:
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise LintError(
            f"{values_name} must be a subset of {allowed_name}: " + ", ".join(unknown)
        )


def require_cloudwatch_dimension_arg(
    path: Path,
    expected: dict[str, str],
    reason: str,
) -> None:
    # Narrow by file convention, not by a full shell parser: relay_user_data has
    # one put-metric-data --dimensions emitter today (BootstrapFailure). If a
    # second one appears, scope this helper to a command block in the same PR.
    for line in _read(path).splitlines():
        line = _strip_line_comment(line, ("#",), ('"', "'"))
        match = re.search(r"--dimensions[ \t]+([\"'])(?P<body>.*?)\1", line)
        if not match:
            continue
        actual: dict[str, str] = {}
        for item in match.group("body").split(","):
            if "=" not in item:
                raise LintError(
                    f"{path}: malformed --dimensions token `{item.strip()}` ({reason})"
                )
            key, value = item.split("=", 1)
            actual[key.strip()] = value.strip()
        if actual == expected:
            return
        raise LintError(
            f"{path}: --dimensions has {actual}, want {expected} ({reason})"
        )
    raise LintError(f"{path}: missing `{expected}` ({reason})")


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


def require_alarm_registry(
    monitoring: Path,
    label: str,
    core_names: tuple[str, ...],
    exemptions: tuple[str, ...],
    names_hint: str,
) -> dict[str, HclBlock]:
    # Every alarm in the monitoring file must be tracked: missing core alarms
    # fail loudly, and a newly added alarm must join core_names or an explicit
    # exemption so it cannot escape the parity fences by omission.
    blocks = {
        block.name: block
        for block in find_blocks(monitoring, 'resource "aws_cloudwatch_metric_alarm"')
    }
    missing = sorted(set(core_names) - set(blocks))
    if missing:
        raise LintError(
            f"{monitoring}: missing {label} CloudWatch alarm resource(s): "
            + ", ".join(missing)
        )
    untracked = sorted(set(blocks) - set(core_names) - set(exemptions))
    if untracked:
        raise LintError(
            f"{monitoring}: {label} CloudWatch alarm(s) must be added to "
            f"{names_hint}: " + ", ".join(untracked)
        )
    return blocks


# Env roots intentionally exempt from the per-env `module "nhp"` parity wiring
# (#1141). Keep this set tiny and each entry justified: an exemption means the
# root does NOT instantiate the giant cell-parameterized `module "nhp"`, so it
# carries none of the prod/sandbox alarm/metric parity surfaces directly — its
# observability must ride an env root this same lint already checks.
#
#   sandbox-cell1: a separately deployed second cell (cell1) for the two-cell
#   qURL Connector proof (PR #3413). Its root wires cell-scoped networking,
#   NHP, and private qurl-service resources but, unlike every other env root,
#   does NOT instantiate `module "nhp"`. That module's
#   always-on `module.security` creates ACCOUNT-SINGLETON GuardDuty/Config/
#   SecurityHub that would collide with cell0 in the same account, so a second
#   full instantiation is unsafe here. Account-wide observability remains
#   cell0-owned while cell1's local qurl-service gets its own health alarm.
#   Removing cell1's tree should drop this entry too.
#
#   sandbox-hub-dns: a DNS-only root that emits public A-alias records whose
#   target NLBs live in roots that cannot emit their own Route 53 record —
#   hub.nhp.layerv.xyz -> the Connector Hub UDP:443 NLB (Step 5 slice 5c; the
#   Control tree forbids aws_route53_record) and cell0.nhp.layerv.xyz -> the
#   cell0 server UDP:443 NLB (Step 7; kept out of the giant main root). It
#   instantiates no compute/AC/relay/security and no `module "nhp"` — those
#   servers + their alarms live in other roots this lint already checks, so there
#   is no server observability surface to enforce parity on here. Removing the
#   record root should drop this entry too.
#
#   prod-hub-dns: a source-locked DNS-only root for the explicit production
#   Hub A-alias. It owns no data-plane compute or alarms; Control owns the Hub
#   worker/NLB and their observability. Its lock prevents even the NLB lookup
#   until a later reviewed activation.
#   sandbox-runtime-attestation: a sandbox-only root composing
#   modules/runtime-attestation-store — the immutable per-node runtime evidence
#   channel (one KMS-encrypted, versioned, public-blocked S3 bucket, its
#   self-binding policy, the canonical collector + pinned State Manager repair
#   document, and the two public SSM parameters the UDP-proof manifest producer
#   reads). It instantiates no compute/AC/relay/security and no `module "nhp"`;
#   the fleets it attests (cell0/cell1/qRTS) + their alarms live in roots this
#   lint already checks, and a failure here surfaces as the producer failing
#   closed, not as an unalarmed data plane. Removing the store root should drop
#   this entry too.
OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS: frozenset[str] = frozenset(
    {
        "prod-hub-dns",
        "sandbox-cell1",
        "sandbox-hub-dns",
        "sandbox-runtime-attestation",
    }
)


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
        "deploy_relay",
        "enable_slack_notifications",
        "slack_workspace_id",
        "slack_channel_id",
        "chatbot_owned_externally",
        "qurl_browser_rejected_alarm_actions_enabled",
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
        "server_log_group_name",
        "module.compute.log_group_name",
    )
    require_assignment(
        monitoring,
        "server_stderr_log_group_name",
        "module.compute.log_group_stderr_name",
    )
    require_assignment(monitoring, "name_prefix", "local.name_prefix")
    require_assignment(
        monitoring, "chatbot_owned_externally", "var.chatbot_owned_externally"
    )
    require_assignment(
        monitoring,
        "qurl_browser_rejected_alarm_actions_enabled",
        "var.qurl_browser_rejected_alarm_actions_enabled",
    )
    require_assignment(monitoring, "deploy_relay", "var.deploy_relay")

    ac = find_block(root_main, "module", "ac")
    require_assignment(ac, "count", "var.deploy_ac ? 1 : 0")
    require_assignment(ac, "enable_cloudwatch_alarms", "true")
    require_assignment(ac, "alarm_sns_topic_arn", "module.monitoring.sns_topic_arn")
    require_assignment(ac, "alerts_sns_topic_arn", "module.monitoring.sns_topic_arn")

    qurl_service = find_block(root_main, "module", "qurl_service")
    require_assignment(qurl_service, "count", "var.deploy_qurl_service ? 1 : 0")
    require_assignment(
        qurl_service,
        "qurl_service_alarm_sns_topic_arn",
        "module.monitoring.sns_topic_arn",
    )


def check_shared_resources(repo: Path) -> None:
    monitoring_main = repo / "terraform" / "modules" / "monitoring" / "main.tf"
    ac_monitoring = repo / "terraform" / "modules" / "ac" / "monitoring.tf"
    ac_variables = repo / "terraform" / "modules" / "ac" / "variables.tf"
    compute_main = repo / "terraform" / "modules" / "compute" / "main.tf"
    compute_outputs = repo / "terraform" / "modules" / "compute" / "outputs.tf"
    relay_monitoring = repo / "terraform" / "modules" / "relay" / "monitoring.tf"
    relay_compute = repo / "terraform" / "modules" / "relay" / "compute.tf"
    relay_user_data = repo / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
    qurl_service_monitoring = (
        repo / "terraform" / "modules" / "qurl-service" / "monitoring.tf"
    )
    qurl_service_ci = repo / "terraform" / "qurl_service_ci.tf"
    qurl_service_ci_runbook = repo / QURL_CI_LOCK_FAILURE_RUNBOOK
    observability_docs = repo / "docs" / "OBSERVABILITY.md"
    server_udp = repo / "endpoints" / "server" / "udpserver.go"
    relay_go = repo / "endpoints" / "relay" / "relay.go"
    core_errors = repo / "nhp" / "core" / "errors.go"

    alerts_topic = find_block(monitoring_main, 'resource "aws_sns_topic"', "alerts")
    for key in ("count", "for_each"):
        require_absent_assignment(
            alerts_topic,
            key,
            "the shared alert SNS topic must be unconditional for alarm routing",
        )

    require_resource(compute_main, "aws_cloudwatch_log_group", "server_stderr")
    require_assignment(
        find_block(compute_outputs, "output", "log_group_name"),
        "value",
        "aws_cloudwatch_log_group.server.name",
    )
    require_assignment(
        find_block(compute_outputs, "output", "log_group_stderr_name"),
        "value",
        "aws_cloudwatch_log_group.server_stderr.name",
    )

    require_resource(
        monitoring_main, "aws_cloudwatch_log_metric_filter", "server_panic"
    )
    async_panic_filter = find_block(
        monitoring_main,
        'resource "aws_cloudwatch_log_metric_filter"',
        "server_async_runtime_panic",
    )
    async_runtime_panic_message = go_new_error_message(core_errors, "ErrRuntimePanic")
    if async_runtime_panic_message != ASYNC_RUNTIME_PANIC_MESSAGE:
        raise LintError(
            f"{core_errors}: ErrRuntimePanic message is "
            f"`{async_runtime_panic_message}`, want `{ASYNC_RUNTIME_PANIC_MESSAGE}` "
            "(CloudWatch server_async_runtime_panic filter depends on this string)"
        )
    require_assignment(
        async_panic_filter,
        "pattern",
        ASYNC_RUNTIME_PANIC_FILTER_PATTERN,
    )

    # dispatchHandler recover site (PR #3643). Same two-term AND match as the
    # async filter, keyed on the call-site name plus ErrRuntimePanic's message
    # (already pinned above -- both filters share that string).
    handler_panic_filter = find_block(
        monitoring_main,
        'resource "aws_cloudwatch_log_metric_filter"',
        "server_handler_panic",
    )
    require_assignment(
        handler_panic_filter,
        "pattern",
        HANDLER_PANIC_FILTER_PATTERN,
    )
    # Both filter terms must be emitted by the recover block itself. The Go
    # side is a method with a nested-paren signature, so this pins the log
    # statement directly rather than parsing the enclosing function body.
    server_udp = repo / "endpoints" / "server" / "udpserver.go"
    server_udp_text = _read(server_udp)
    require_file_regex(
        server_udp,
        server_udp_text,
        r'log\.Critical\(\s*"'
        + re.escape(HANDLER_PANIC_LOG_CALL_SITE)
        + r'[^"]*recovered from panic',
        f'log.Critical("{HANDLER_PANIC_LOG_CALL_SITE} ... recovered from panic"',
        "CloudWatch server_handler_panic filter matches this call-site term",
    )
    require_file_tokens(
        server_udp,
        server_udp_text,
        (HANDLER_PANIC_LOG_WRAPPER,),
        "the recover line must render ErrRuntimePanic's message for the "
        "server_handler_panic filter's second term",
    )

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
            "server_async_runtime_panic",
        ),
        "[aws_sns_topic.alerts.arn]",
    )
    require_alarm_actions(
        find_block(
            monitoring_main,
            'resource "aws_cloudwatch_metric_alarm"',
            "server_handler_panic",
        ),
        "[aws_sns_topic.alerts.arn]",
    )
    require_alarm_actions(
        find_block(
            monitoring_main,
            'resource "aws_cloudwatch_metric_alarm"',
            "server_forward_target_drop",
        ),
        "[aws_sns_topic.alerts.arn]",
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
    relay_forward_reject = find_block(
        monitoring_main,
        'resource "aws_cloudwatch_metric_alarm"',
        "relay_forward_reject",
    )
    require_assignment(relay_forward_reject, "count", "var.deploy_relay ? 1 : 0")
    require_assignment(
        relay_forward_reject, "alarm_actions", "[aws_sns_topic.alerts.arn]"
    )
    require_assignment(relay_forward_reject, "ok_actions", "[aws_sns_topic.alerts.arn]")
    require_assignment(relay_forward_reject, "metric_name", '"RelayForwardReject"')
    require_assignment(relay_forward_reject, "namespace", '"LayerV/NHP"')
    require_assignment(relay_forward_reject, "statistic", '"Sum"')
    require_map_assignment(
        relay_forward_reject,
        "dimensions",
        {"Environment": "var.environment", "Cell": "var.cell_id"},
    )
    qurl_browser_rejected_ratio = find_block(
        monitoring_main,
        'resource "aws_cloudwatch_metric_alarm"',
        "qurl_browser_rejected_ratio",
    )
    require_assignment(
        qurl_browser_rejected_ratio,
        "for_each",
        "local.qurl_browser_rejected_alarms",
    )
    require_assignment(qurl_browser_rejected_ratio, "threshold", "each.value.threshold")
    require_assignment(qurl_browser_rejected_ratio, "evaluation_periods", "3")
    require_assignment(qurl_browser_rejected_ratio, "datapoints_to_alarm", "3")
    require_assignment(
        qurl_browser_rejected_ratio,
        "actions_enabled",
        "var.qurl_browser_rejected_alarm_actions_enabled",
    )
    require_assignment(
        qurl_browser_rejected_ratio,
        "comparison_operator",
        '"GreaterThanThreshold"',
    )
    require_assignment(
        qurl_browser_rejected_ratio, "alarm_actions", "[aws_sns_topic.alerts.arn]"
    )
    require_assignment(
        qurl_browser_rejected_ratio, "ok_actions", "[aws_sns_topic.alerts.arn]"
    )
    require_assignment(
        qurl_browser_rejected_ratio, "treat_missing_data", '"notBreaching"'
    )
    require_map_assignment(
        qurl_browser_rejected_ratio,
        "dimensions",
        {"Environment": "var.environment", "Cell": "var.cell_id"},
    )
    require_block_text(
        qurl_browser_rejected_ratio,
        "IF(resolve_attempts >= ${local.qurl_browser_rejected_min_resolve_attempts}, FILL(rejected, 0) / resolve_attempts, 0)",
        "qURL browser rejected alarms must remain normalized by resolve attempts and gated by the low-volume floor",
    )
    require_block_text(
        qurl_browser_rejected_ratio,
        "metric_name = each.value.metric_name",
        "qURL browser rejected numerator must use the selected alarm metric",
    )
    require_block_text(
        qurl_browser_rejected_ratio,
        "iterator = outcome",
        "qURL browser rejected denominator metric query iterator must stay explicit",
    )
    require_block_text(
        qurl_browser_rejected_ratio,
        "metric_name = outcome.value",
        "qURL browser rejected denominator metric queries must use the selected outcome metric",
    )
    monitoring_text = _read(monitoring_main)
    for metric_name in (
        "QurlResolveBrowserRejectedMalformed",
        "QurlResolveBrowserRejectedOutOfRange",
    ):
        if not has_metric_name(monitoring_text, metric_name):
            raise LintError(
                f"{monitoring_main}: missing qURL browser rejected metric `{metric_name}`"
            )
    for metric_id, metric_name in (
        ("success", "QurlResolveSuccess"),
        ("fail_validate", "QurlResolveFailValidate"),
        ("fail_resolve_catalog", "QurlResolveFailResolveCatalog"),
        ("fail_knock", "QurlResolveFailKnock"),
        ("fail_post_knock", "QurlResolveFailPostKnock"),
        ("fail_canceled", "QurlResolveFailCanceled"),
        ("fail_unknown", "QurlResolveFailUnknown"),
    ):
        require_hcl_map_entry(
            qurl_browser_rejected_ratio,
            metric_id,
            metric_name,
            "qURL browser rejected ratio denominator/numerator set must not drift",
        )

    qurl_resource_key_failure_filter = find_block(
        qurl_service_monitoring,
        'resource "aws_cloudwatch_log_metric_filter"',
        "qurl_api_resource_key_provisioning_failed",
    )
    require_assignment(
        qurl_resource_key_failure_filter,
        "log_group_name",
        "aws_cloudwatch_log_group.qurl.name",
    )
    require_assignment(
        qurl_resource_key_failure_filter,
        "pattern",
        QURL_RESOURCE_KEY_FAILURE_FILTER_PATTERN,
    )
    require_block_regex(
        qurl_resource_key_failure_filter,
        r'\bname\s*=\s*"ResourceKeyProvisioningFailedCount"',
        "qurl-api resource-key failure alarm depends on this metric filter output",
    )
    require_block_regex(
        qurl_resource_key_failure_filter,
        r'\bnamespace\s*=\s*"LayerV/QurlService"',
        "qurl-api resource-key failure alarm depends on this metric namespace",
    )
    qurl_resource_key_failure_alarm = find_block(
        qurl_service_monitoring,
        'resource "aws_cloudwatch_metric_alarm"',
        "qurl_api_resource_key_provisioning_failures",
    )
    require_assignment(
        qurl_resource_key_failure_alarm,
        "alarm_actions",
        QURL_SERVICE_ALARM_ACTION_EXPR,
    )
    require_assignment(qurl_resource_key_failure_alarm, "ok_actions", "[]")
    require_assignment(
        qurl_resource_key_failure_alarm,
        "comparison_operator",
        '"GreaterThanThreshold"',
    )
    require_assignment(qurl_resource_key_failure_alarm, "evaluation_periods", "1")
    require_assignment(qurl_resource_key_failure_alarm, "datapoints_to_alarm", "1")
    require_assignment(
        qurl_resource_key_failure_alarm,
        "metric_name",
        '"ResourceKeyProvisioningFailedCount"',
    )
    require_assignment(
        qurl_resource_key_failure_alarm,
        "namespace",
        '"LayerV/QurlService"',
    )
    require_assignment(qurl_resource_key_failure_alarm, "period", "60")
    require_assignment(qurl_resource_key_failure_alarm, "statistic", '"Sum"')
    require_assignment(qurl_resource_key_failure_alarm, "threshold", "0")
    require_assignment(
        qurl_resource_key_failure_alarm,
        "treat_missing_data",
        '"notBreaching"',
    )

    # #3247: publishers emit a dimensionless alarm sample followed by a
    # Reason/Action diagnostic sample for every failure. Pin the standard alarm
    # to the exact dimensionless stream so a new diagnostic dimension pair does
    # not depend on Metrics Insights discovery before the first event can page.
    qurl_ci_lock_failure_alarm = find_block(
        qurl_service_ci,
        'resource "aws_cloudwatch_metric_alarm"',
        QURL_CI_LOCK_FAILURE_ALARM_NAME,
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "count",
        'var.environment == "sandbox" ? 1 : 0',
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "alarm_name",
        '"${local.name_prefix}-qurl-service-ci-live-env-lock-failure"',
    )
    require_assignment(qurl_ci_lock_failure_alarm, "actions_enabled", "true")
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "comparison_operator",
        '"GreaterThanThreshold"',
    )
    require_assignment(qurl_ci_lock_failure_alarm, "evaluation_periods", "1")
    require_assignment(qurl_ci_lock_failure_alarm, "datapoints_to_alarm", "1")
    require_assignment(qurl_ci_lock_failure_alarm, "threshold", "0")
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "treat_missing_data",
        '"notBreaching"',
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "alarm_actions",
        "[module.monitoring.sns_topic_arn]",
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "ok_actions",
        "[module.monitoring.sns_topic_arn]",
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "insufficient_data_actions",
        "[]",
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "metric_name",
        '"SandboxLiveEnvLockFailure"',
    )
    require_assignment(
        qurl_ci_lock_failure_alarm,
        "namespace",
        '"LayerV/QURLServiceCI"',
    )
    require_assignment(qurl_ci_lock_failure_alarm, "Component", '"qurl-service"')
    require_assignment(qurl_ci_lock_failure_alarm, "period", "60")
    require_assignment(qurl_ci_lock_failure_alarm, "statistic", '"Sum"')
    for key in ("dimensions", "unit"):
        require_absent_assignment(
            qurl_ci_lock_failure_alarm,
            key,
            "the qURL CI lock alarm must select the exact dimensionless producer stream",
        )
    if "metric_query {" in qurl_ci_lock_failure_alarm.body:
        raise LintError(
            f"{_block_location(qurl_ci_lock_failure_alarm)} must use the standard "
            "dimensionless metric fields, not a `metric_query` block"
        )
    require_block_text(
        qurl_ci_lock_failure_alarm,
        QURL_CI_LOCK_FAILURE_RUNBOOK_URL,
        "the actionable alarm description must point responders to its runbook",
    )

    qurl_ci_runbook_text = _read(qurl_service_ci_runbook)
    require_file_tokens(
        qurl_service_ci_runbook,
        qurl_ci_runbook_text,
        (
            "layerv-nhp-sandbox-qurl-service-ci-live-env-lock-failure",
            "layerv-nhp-sandbox-cell0-alerts",
            "sandbox-alerts-sandbox",
            "/layerv-nhp-sandbox/qurl-live-env-lock",
            QURL_CI_LOCK_FAILURE_CANARY_DIMENSIONS,
            "An ordinary lock collision emits no failure metric.",
            "`Reason=Contention`",
            QURL_CI_LOCK_FAILURE_CONTENTION_CONTRACT,
            "#3244",
            "#3246",
            "#3247",
        ),
        "qURL CI lock alarm owner/query/runbook contract drift",
    )
    require_file_regex(
        qurl_service_ci_runbook,
        qurl_ci_runbook_text,
        QURL_CI_LOCK_FAILURE_RUNBOOK_DIAGNOSTIC_QUERY_PATTERN,
        QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY,
        "qURL CI lock alarm owner/query/runbook contract drift",
    )
    require_file_regex(
        qurl_service_ci_runbook,
        qurl_ci_runbook_text,
        QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY_PATTERN,
        QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY,
        "qURL CI lock alarm diagnostic breakdown contract drift",
    )
    require_file_regex(
        qurl_service_ci_runbook,
        qurl_ci_runbook_text,
        QURL_CI_LOCK_FAILURE_CANARY_PATTERN,
        f"dimensionless canary followed by {QURL_CI_LOCK_FAILURE_CANARY_DIMENSIONS}",
        "qURL CI lock alarm producer/canary contract drift",
    )

    observability_text = _read(observability_docs)
    require_file_tokens(
        observability_docs,
        observability_text,
        (
            "LayerV/QURLServiceCI",
            "SandboxLiveEnvLockFailure",
            "runbooks/qurl-sandbox-live-env-lock-alarm.md",
        ),
        "qURL CI lock alarm observability documentation drift",
    )
    require_file_regex(
        observability_docs,
        observability_text,
        QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY_PATTERN,
        QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY,
        "qURL CI lock alarm observability documentation drift",
    )
    # Go-side checks scope to the metric-dimension builders the Terraform
    # selectors depend on. They catch simple emitter renames without pulling a Go
    # parser into this small static lint.
    require_go_function_text(
        server_udp,
        "buildServerMetricDimensions",
        'Name: aws.String("Environment")',
        "server-side relay_forward_reject alarm depends on the Go emitter Environment dimension name",
    )
    require_go_function_text(
        server_udp,
        "buildServerMetricDimensions",
        'Name: aws.String("Cell")',
        "server-side relay_forward_reject alarm depends on the Go emitter Cell dimension name",
    )
    ac_alarm_blocks = require_alarm_registry(
        ac_monitoring,
        "AC",
        AC_CORE_ALARM_NAMES,
        AC_ALARM_EXEMPTIONS,
        "AC_CORE_ALARM_NAMES or AC_ALARM_EXEMPTIONS",
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

    relay_alarm_blocks = require_alarm_registry(
        relay_monitoring,
        "relay",
        RELAY_CORE_ALARM_NAMES,
        RELAY_ALARM_EXEMPTIONS,
        "RELAY_CORE_ALARM_NAMES or RELAY_ALARM_EXEMPTIONS",
    )

    # #2644: relay alarms are only useful if their dimensions exactly match the
    # emitters. Terraform validates syntax, not metric-stream selectors.
    require_map_assignment(
        relay_alarm_blocks["relay_bootstrap_failure"],
        "dimensions",
        {"Component": '"relay"', "Environment": "var.environment"},
    )
    require_cloudwatch_dimension_arg(
        relay_user_data,
        {"Component": "relay", "Environment": "${environment}"},
        "BootstrapFailure alarm dimensions must match the CLI publisher tokens",
    )

    for name in ("relay_tg_unhealthy_hosts", "relay_tg_zero_healthy_targets"):
        require_map_assignment(
            relay_alarm_blocks[name],
            "dimensions",
            {
                "LoadBalancer": "aws_lb.relay.arn_suffix",
                "TargetGroup": "aws_lb_target_group.relay.arn_suffix",
            },
        )
    require_assignment(
        relay_alarm_blocks["relay_tg_zero_healthy_targets"],
        "treat_missing_data",
        '"breaching"',
    )

    require_map_assignment(
        relay_alarm_blocks["relay_capacity_below_baseline"],
        "dimensions",
        {"AutoScalingGroupName": "aws_autoscaling_group.relay.name"},
    )
    require_assignment(
        relay_alarm_blocks["relay_capacity_below_baseline"],
        "metric_name",
        '"GroupInServiceInstances"',
    )
    relay_asg = find_block(relay_compute, 'resource "aws_autoscaling_group"', "relay")
    require_list_contains(
        relay_asg,
        "enabled_metrics",
        '"GroupInServiceInstances"',
    )

    require_map_assignment(
        relay_alarm_blocks["relay_shedding"],
        "dimensions",
        {"Environment": "var.environment"},
    )
    require_map_assignment(
        relay_alarm_blocks["relay_shedding_unknown_environment"],
        "dimensions",
        {"Environment": '"unknown"'},
    )
    for name in ("relay_shedding", "relay_shedding_unknown_environment"):
        require_assignment(relay_alarm_blocks[name], "metric_name", '"RelayShed"')
        require_assignment(relay_alarm_blocks[name], "namespace", '"LayerV/NHP"')
        require_assignment(relay_alarm_blocks[name], "statistic", '"Sum"')
        require_assignment(
            relay_alarm_blocks[name], "comparison_operator", '"GreaterThanThreshold"'
        )
        require_assignment(relay_alarm_blocks[name], "threshold", "0")
        require_assignment(
            relay_alarm_blocks[name],
            "treat_missing_data",
            '"notBreaching"',
        )
    require_shell_arg(
        relay_user_data,
        "-e NHP_ENVIRONMENT=${environment}",
        "primary RelayShed alarm depends on the relay process receiving NHP_ENVIRONMENT",
    )
    # Deliberately source-shaped, not AST-shaped: a benign Go refactor that
    # renames these builders or moves dim names to constants should update this
    # fence with the metric-emitter contract in the same PR.
    require_go_function_text(
        relay_go,
        "buildRelayMetricDimensions",
        'Name: aws.String("Environment")',
        "relay_shedding alarms depend on the Go emitter Environment dimension name",
    )
    require_go_function_text(
        relay_go,
        "buildRelayMetricDimensions",
        'environment = "unknown"',
        "relay_shedding_unknown_environment alarm matches the Go fallback Environment value",
    )
    require_name_subset(
        RELAY_SINGLE_EVENT_ALARM_NAMES,
        RELAY_CORE_ALARM_NAMES,
        "RELAY_SINGLE_EVENT_ALARM_NAMES",
        "RELAY_CORE_ALARM_NAMES",
    )
    for name in RELAY_CORE_ALARM_NAMES:
        require_assignment(
            relay_alarm_blocks[name], "alarm_actions", RELAY_ALARM_ACTION_EXPR
        )
        if name in RELAY_SINGLE_EVENT_ALARM_NAMES:
            require_assignment(relay_alarm_blocks[name], "ok_actions", "[]")
        else:
            require_assignment(
                relay_alarm_blocks[name], "ok_actions", RELAY_ALARM_ACTION_EXPR
            )


def run(repo: Path) -> None:
    # Discover env roots so a future deployable env cannot escape the #1141
    # guard by omission. A root may opt out only via the explicit, per-env
    # justified exemption set (a lean cell whose observability rides cell0).
    for env in deployable_env_names(repo):
        if env in OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS:
            continue
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
