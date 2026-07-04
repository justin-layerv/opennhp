#!/usr/bin/env bash
# Asserts the AC L3 netlink conntrack pool-size operator knob stays in lockstep
# between the Go source-of-truth constants and the Terraform validation/docs.
#
# Sites compared:
#   - endpoints/ac/expiry_scheduler.go::defaultWorkerCount
#   - endpoints/ac/expiry_conntrack_flusher.go
#       conntrackNetlinkWorkersPerSocket
#       defaultConntrackNetlinkPoolSize = defaultWorkerCount / conntrackNetlinkWorkersPerSocket
#       maxConntrackNetlinkPoolSize = defaultWorkerCount * 2
#   - Terraform l3_flush_conntrack_pool_size variable blocks in:
#       terraform/modules/ac/variables.tf
#       terraform/variables.tf
#       terraform/environments/sandbox/variables.tf
#       terraform/environments/prod/variables.tf
#
# The AC still clamps at boot, so stale Terraform bounds fail safe at runtime.
# This lint keeps the operator-facing plan-time validation and docs truthful
# when the Go-side worker/socket ratio changes.
#
# Testability: REPO_ROOT may be overridden via
# $L3_CONNTRACK_POOL_LOCKSTEP_ROOT so the paired fixture test can point the
# extractors at mutated copies in a tempdir. Defaults to the git toplevel.

set -euo pipefail

REPO_ROOT="${L3_CONNTRACK_POOL_LOCKSTEP_ROOT:-$(git rev-parse --show-toplevel)}"

python3 - "$REPO_ROOT" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
VAR_NAME = "l3_flush_conntrack_pool_size"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def read(rel_path: str) -> str:
    path = ROOT / rel_path
    if not path.is_file():
        fail(f"{rel_path} not found under {ROOT}")
    return path.read_text(encoding="utf-8")


def require_match(pattern: str, text: str, label: str) -> re.Match:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        fail(f"could not extract {label}")
    return match


def extract_variable_block(text: str, rel_path: str) -> str:
    header = re.search(rf'variable\s+"{re.escape(VAR_NAME)}"\s*{{', text)
    if not header:
        fail(f"{rel_path} is missing variable \"{VAR_NAME}\"")

    brace_start = text.find("{", header.start())
    depth = 0
    for idx in range(brace_start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[header.start() : idx + 1]

    fail(f"{rel_path} has an unterminated variable \"{VAR_NAME}\" block")
    raise AssertionError("unreachable")


scheduler = read("endpoints/ac/expiry_scheduler.go")
flusher = read("endpoints/ac/expiry_conntrack_flusher.go")

worker_count = int(
    require_match(
        r"^\s*defaultWorkerCount\s*=\s*(\d+)\s*(?://.*)?$",
        scheduler,
        "defaultWorkerCount from endpoints/ac/expiry_scheduler.go",
    ).group(1)
)
workers_per_socket = int(
    require_match(
        r"^\s*conntrackNetlinkWorkersPerSocket\s*=\s*(\d+)\s*(?://.*)?$",
        flusher,
        "conntrackNetlinkWorkersPerSocket from endpoints/ac/expiry_conntrack_flusher.go",
    ).group(1)
)

if workers_per_socket <= 0:
    fail("conntrackNetlinkWorkersPerSocket must be positive")
if worker_count % workers_per_socket != 0:
    fail(
        "defaultWorkerCount is not divisible by conntrackNetlinkWorkersPerSocket; "
        "update the pool-size constant and this lint together"
    )

require_match(
    r"^\s*defaultConntrackNetlinkPoolSize\s*=\s*defaultWorkerCount\s*/\s*conntrackNetlinkWorkersPerSocket\s*(?://.*)?$",
    flusher,
    "defaultConntrackNetlinkPoolSize expression from endpoints/ac/expiry_conntrack_flusher.go",
)
require_match(
    r"^\s*const\s+maxConntrackNetlinkPoolSize\s*=\s*defaultWorkerCount\s*\*\s*2\s*(?://.*)?$",
    flusher,
    "maxConntrackNetlinkPoolSize expression from endpoints/ac/expiry_conntrack_flusher.go",
)

expected_default = worker_count // workers_per_socket
expected_max = worker_count * 2

tf_paths = [
    "terraform/modules/ac/variables.tf",
    "terraform/variables.tf",
    "terraform/environments/sandbox/variables.tf",
    "terraform/environments/prod/variables.tf",
]
paths_with_default_doc = {
    "terraform/modules/ac/variables.tf",
    "terraform/variables.tf",
    "terraform/environments/sandbox/variables.tf",
    "terraform/environments/prod/variables.tf",
}

for rel_path in tf_paths:
    block = extract_variable_block(read(rel_path), rel_path)

    # The Terraform comparison ordering is intentional; a rewrite like
    # "128 >= var.foo" should trip this guard so reviewers re-check the bound.
    bounds = re.findall(rf"var\.{VAR_NAME}\s*<=\s*(\d+)\b", block)
    if not bounds:
        fail(f"{rel_path} variable \"{VAR_NAME}\" is missing a <= max bound")
    if str(expected_max) not in bounds:
        fail(
            f"Terraform max bound drift in {rel_path}: expected <= {expected_max} "
            f"from maxConntrackNetlinkPoolSize, found <= {', <= '.join(bounds)}"
        )

    if not re.search(rf"var\.{VAR_NAME}\s*>=\s*0\b", block):
        fail(f"{rel_path} variable \"{VAR_NAME}\" must reject negative values")
    if not re.search(rf"floor\(var\.{VAR_NAME}\)\s*==\s*var\.{VAR_NAME}\b", block):
        fail(f"{rel_path} variable \"{VAR_NAME}\" must require integer values")

    error_message = re.search(r'error_message\s*=\s*"([^"]+)"', block)
    if not error_message:
        fail(f"{rel_path} variable \"{VAR_NAME}\" is missing an error_message")
    expected_error_fragment = f"between 0 and {expected_max}"
    if expected_error_fragment not in error_message.group(1):
        fail(
            f"Terraform error-message drift in {rel_path}: expected "
            f"'{expected_error_fragment}' from maxConntrackNetlinkPoolSize"
        )

    if rel_path in paths_with_default_doc:
        description = re.search(r'description\s*=\s*"([^"]+)"', block)
        if not description:
            fail(f"{rel_path} variable \"{VAR_NAME}\" is missing a description")
        expected_doc_fragment = f"currently {expected_default}"
        if expected_doc_fragment not in description.group(1):
            fail(
                f"Terraform default-doc drift in {rel_path}: expected "
                f"'{expected_doc_fragment}' from defaultConntrackNetlinkPoolSize"
            )

print(
    "OK: L3 conntrack pool Terraform bounds match Go constants "
    f"(default={expected_default} max={expected_max})"
)
PY
