#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_DATA="${1:-${ROOT_DIR}/terraform/modules/ac/user_data.sh.tpl}"

python3 - "$USER_DATA" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()

# These heredocs write boot-critical AC config, units, or scripts during
# user-data. If the delimiter is unquoted, bash performs command substitution
# before `cat` receives the body. A markdown-style `foo` in a generated-file
# comment can therefore execute `foo` during cloud-init and block AC bootstrap.
#
# This source-level guard catches literal raw command substitutions in the
# template. It assumes Terraform-rendered scalar values are operator-controlled
# and backtick-free; changing a heredoc to interpolate arbitrary rendered text
# needs a separate rendered-template test.
open_unquoted = None
failures: list[str] = []

heredoc_open_re = re.compile(
    r"""
    \bcat\b
    (?:
      (?P<prefix>.*?)
      (?P<redir1>>>?)\s*(?P<target1>\S+)
      (?P<middle1>.*?)
      <<(?P<strip1>-?)\s*(?P<delim1>'[^']+'|"[^"]+"|\\?[A-Za-z_][A-Za-z0-9_]*)
    |
      (?P<middle2>.*?)
      <<(?P<strip2>-?)\s*(?P<delim2>'[^']+'|"[^"]+"|\\?[A-Za-z_][A-Za-z0-9_]*)
      (?P<middle3>.*?)
      (?P<redir2>>>?)\s*(?P<target2>\S+)
    )
    """,
    re.VERBOSE,
)


def is_shell_quoted(raw: str) -> bool:
    return raw.startswith(("'", '"', "\\"))


def heredoc_delim(raw: str) -> str:
    if raw.startswith(("'", '"')) and raw.endswith(raw[0]):
        return raw[1:-1]
    if raw.startswith("\\"):
        return raw[1:]
    return raw


def unquote_target(raw: str) -> str:
    return raw.strip("'\"")


def is_guarded_target(target: str) -> bool:
    target = unquote_target(target)
    guarded_prefixes = (
        "/home/ubuntu/traefik/",
        "/opt/layerv/nhp-ac/",
        "/etc/systemd/system/",
        "/etc/rsyslog.d/",
        "/opt/aws/amazon-cloudwatch-agent/",
    )
    return any(target.startswith(prefix) for prefix in guarded_prefixes)


def is_escaped(line: str, idx: int) -> bool:
    slash_count = 0
    pos = idx - 1
    while pos >= 0 and line[pos] == "\\":
        slash_count += 1
        pos -= 1
    return slash_count % 2 == 1


def has_unescaped_backtick(line: str) -> bool:
    return any(ch == "`" and not is_escaped(line, idx) for idx, ch in enumerate(line))


def has_unescaped_dollar_paren(line: str) -> bool:
    for idx, ch in enumerate(line[:-1]):
        if ch == "$" and line[idx + 1] == "(" and not is_escaped(line, idx):
            return True
    return False


def is_terminator(line: str, delim: str, strip_tabs: bool) -> bool:
    candidate = line.lstrip("\t") if strip_tabs else line
    return candidate == delim


for lineno, line in enumerate(lines, 1):
    if open_unquoted is not None:
        delim, start, target, strip_tabs = open_unquoted
        if is_terminator(line, delim, strip_tabs):
            open_unquoted = None
            continue
        if has_unescaped_backtick(line):
            failures.append(
                f"{path}:{lineno}: unescaped backtick inside unquoted AC boot heredoc "
                f"{delim} (target {target}) opened at line {start}: {line}"
            )
        if has_unescaped_dollar_paren(line):
            failures.append(
                f"{path}:{lineno}: unescaped '$(' inside unquoted AC boot heredoc "
                f"{delim} (target {target}) opened at line {start}: {line}"
            )
        continue

    match = heredoc_open_re.search(line)
    if not match:
        continue

    target = match.group("target1") or match.group("target2")
    raw_delim = match.group("delim1") or match.group("delim2")
    strip_tabs = bool(match.group("strip1") or match.group("strip2"))
    if not target or not raw_delim or not is_guarded_target(target):
        continue
    if is_shell_quoted(raw_delim):
        continue

    open_unquoted = (heredoc_delim(raw_delim), lineno, unquote_target(target), strip_tabs)

if open_unquoted is not None:
    delim, start, target, _ = open_unquoted
    failures.append(f"{path}:{start}: unterminated AC boot heredoc {delim} targeting {target}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
PY

echo "AC boot heredoc command-substitution guard passed"
