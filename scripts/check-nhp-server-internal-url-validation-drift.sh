#!/usr/bin/env bash
# check-nhp-server-internal-url-validation-drift.sh
# ----------------------------------------------------------------------------
# Fail if the nhp_server_internal_url validation regexes drift between the
# root precondition and the two module variable validations. Terraform cannot
# share variable validation logic across these module boundaries, so the
# duplication is intentional and this lint is the structural fence.

set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$REPO_ROOT" <<'PY'
import difflib
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])

targets = [
    (
        "root precondition",
        repo_root / "terraform/main.tf",
        r'resource\s+"terraform_data"\s+"nhp_server_internal_url_preconditions"\s*\{',
    ),
    (
        "qurl-reverse-tunnel-server module",
        repo_root / "terraform/modules/qurl-reverse-tunnel-server/variables.tf",
        r'variable\s+"nhp_server_internal_url"\s*\{',
    ),
    (
        "qurl-service module",
        repo_root / "terraform/modules/qurl-service/variables.tf",
        r'variable\s+"nhp_server_internal_url"\s*\{',
    ),
]


def mask_heredocs(text: str) -> str:
    lines = text.splitlines(keepends=True)
    masked: list[str] = []
    terminator: str | None = None

    for line in lines:
        if terminator is not None:
            # Mask the terminator line too. HCL heredoc terminators are plain
            # identifiers, so they cannot carry braces needed by block balance.
            masked.append(re.sub(r"[^\n]", " ", line))
            if line.strip() == terminator:
                terminator = None
            continue

        masked.append(line)
        match = re.search(r"<<-?([A-Za-z_][A-Za-z0-9_]*)", line)
        if match:
            terminator = match.group(1)

    return "".join(masked)


def extract_block(text: str, start_pattern: str, path: Path) -> str:
    match = re.search(start_pattern, text)
    if not match:
        raise SystemExit(f"ERROR: could not find nhp_server_internal_url validation block in {path}")

    masked_text = mask_heredocs(text)
    brace_pos = masked_text.find("{", match.start(), match.end())
    if brace_pos == -1:
        raise SystemExit(f"ERROR: malformed validation block in {path}: missing opening brace")

    # This is a narrow HCL block scanner, not a general parser. It masks heredoc
    # bodies before brace balancing and handles quoted string literals because
    # the validation regexes and error strings must stay single-line quoted
    # values.
    depth = 0
    in_string = False
    escape = False
    for pos in range(brace_pos, len(masked_text)):
        ch = masked_text[pos]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[match.start() : pos + 1]

    raise SystemExit(f"ERROR: unterminated validation block in {path}")


def extract_contract(name: str, path: Path, start_pattern: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    block = extract_block(text, start_pattern, path)
    regexes = re.findall(r'regex\("((?:\\.|[^"\\])*)"', block)
    # Deliberately require single-line quoted error_message values; if a
    # validation moves to a heredoc message, teach this extractor that shape
    # before landing it.
    error_match = re.search(r'error_message\s*=\s*"((?:\\.|[^"\\])*)"', block)

    if len(regexes) != 2:
        raise SystemExit(f"ERROR: expected exactly 2 regex() calls in {name} ({path}), found {len(regexes)}")
    if not error_match:
        raise SystemExit(f"ERROR: missing error_message in {name} ({path})")

    error_message = error_match.group(1)
    if name == "root precondition":
        error_message = error_message.replace("local.nhp_server_internal_url", "nhp_server_internal_url")
    elif "local.nhp_server_internal_url" in error_message:
        raise SystemExit(f"ERROR: module validation error message in {name} ({path}) must not refer to local.nhp_server_internal_url")

    return [f"https_regex={regexes[0]}", f"internal_http_regex={regexes[1]}", f"error_message={error_message}"]


contracts = [(name, path, extract_contract(name, path, pattern)) for name, path, pattern in targets]
source_name, source_path, source_contract = contracts[0]
drift_detected = False

for name, path, contract in contracts[1:]:
    if contract == source_contract:
        continue

    drift_detected = True
    print(
        f"ERROR: nhp_server_internal_url validation drifted between {source_name} ({source_path}) "
        f"and {name} ({path}).",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    for line in difflib.unified_diff(
        source_contract,
        contract,
        fromfile=str(source_path),
        tofile=str(path),
        lineterm="",
    ):
        print(line, file=sys.stderr)
    print("", file=sys.stderr)

if drift_detected:
    print(
        "Update all three regex/error-message copies in lockstep, or update this lint "
        "and the inline mirror comments to document intentional divergence.",
        file=sys.stderr,
    )
    sys.exit(1)

print("nhp_server_internal_url validation: root and module declarations are in sync.")
PY
