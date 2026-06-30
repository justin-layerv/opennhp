#!/usr/bin/env bash
# Fails if the eBPF committed-object toolchain pins drift between CI, helper
# scripts, and maintainer-facing docs. CI's workflow env is the source of truth;
# script defaults exist for local runs and must stay in lockstep.
#
# Wired into `make lint-workflows` and validate-workflows.yml. Tests can point
# the checker at a fixture tree with EBPF_TOOLCHAIN_PIN_LOCKSTEP_ROOT.

set -euo pipefail

REPO_ROOT="${EBPF_TOOLCHAIN_PIN_LOCKSTEP_ROOT:-$(git rev-parse --show-toplevel)}"
WF="${REPO_ROOT}/.github/workflows/ebpf-datapath-test.yml"
INSTALLER="${REPO_ROOT}/scripts/install-ebpf-toolchain.sh"
DRIFT="${REPO_ROOT}/scripts/check-ebpf-committed-object-drift.sh"
CLAUDE_MD="${REPO_ROOT}/CLAUDE.md"

for f in "$WF" "$INSTALLER" "$DRIFT" "$CLAUDE_MD"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

python3 - "$WF" "$INSTALLER" "$DRIFT" "$CLAUDE_MD" <<'PY'
import re
import sys

workflow_path, installer_path, drift_path, claude_path = sys.argv[1:]

KEYS = (
    "EBPF_APT_SNAPSHOT",
    "EBPF_CLANG_PACKAGE",
    "EBPF_LLVM_PACKAGE",
    "EBPF_LIBBPF_DEV_PACKAGE",
)


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def require_match(label, text, key, pattern):
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        fail(f"{label}: could not extract {key}; update scripts/check-ebpf-toolchain-pin-lockstep.sh with the new shape")
    return match.group(1)


def workflow_pins(path):
    # Avoid a PyYAML dependency for local `make lint-workflows`; the workflow
    # shape is intentionally small here, so an indentation-aware extraction is
    # enough and fails loud if the job/env layout changes.
    pins = {}
    in_job = False
    in_env = False
    for line in read(path).splitlines():
        if not in_job:
            if re.match(r"^  ebpf-datapath:\s*(?:#.*)?$", line):
                in_job = True
            continue

        if re.match(r"^  [A-Za-z0-9_-]+:\s*(?:#.*)?$", line):
            break

        if not in_env:
            if re.match(r"^    env:\s*(?:#.*)?$", line):
                in_env = True
            continue

        if re.match(r"^    [A-Za-z0-9_-]+:\s*", line):
            break

        match = re.match(r"^      (EBPF_[A-Z0-9_]+):\s*(.*?)\s*(?:#.*)?$", line)
        if match:
            value = match.group(2).strip()
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]
            pins[match.group(1)] = value

    if not in_job:
        fail(f"{path}: jobs.ebpf-datapath is missing")
    if not in_env:
        fail(f"{path}: jobs.ebpf-datapath.env is missing")
    for key in KEYS:
        if key not in pins:
            fail(f"{path}: missing jobs.ebpf-datapath.env.{key}")
    return pins


def require_case_body(label, text, opener_pattern):
    match = re.search(
        opener_pattern + r"\n(?P<body>.*?)^\s*esac\s*$",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        fail(f"{label}: could not extract LLVM_STRIP derivation case block")
    return match.group("body")


def require_llvm_strip_rules(label, rules):
    expected = {"llvm-*", "*"}
    missing = sorted(expected - set(rules))
    extra = sorted(set(rules) - expected)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing rules {', '.join(missing)}")
        if extra:
            parts.append(f"unexpected rules {', '.join(extra)}")
        fail(f"{label}: unsupported LLVM_STRIP derivation shape ({'; '.join(parts)})")
    return rules


def workflow_llvm_strip_derivation(path):
    text = read(path)
    body = require_case_body(
        path,
        text,
        r'^\s*case "\$EBPF_LLVM_PACKAGE_NAME" in$',
    )
    rules = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r'^(llvm-\*|\*)\)\s+LLVM_STRIP="([^"]+)"\s*;;$', line)
        if not match:
            fail(f"{path}: unsupported workflow LLVM_STRIP derivation line: {line}")
        pattern, value = match.groups()
        if pattern in rules:
            fail(f"{path}: duplicate workflow LLVM_STRIP derivation rule for {pattern}")
        if value == "llvm-strip${EBPF_LLVM_PACKAGE_NAME#llvm}":
            value = "llvm-strip${package#llvm}"
        rules[pattern] = value
    return require_llvm_strip_rules(path, rules)


def drift_llvm_strip_derivation(path):
    text = read(path)
    body = require_case_body(
        path,
        text,
        r'^\s*case "\$expected_llvm_package_name" in$',
    )
    rules = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        suffix_match = re.match(
            r'^(llvm-\*)\)\s+printf \'llvm-strip%s\'\s+"\$\{expected_llvm_package_name#llvm\}"\s*;;$',
            line,
        )
        simple_match = re.match(r"^(\*)\)\s+printf '([^']+)'\s*;;$", line)
        if suffix_match:
            pattern = suffix_match.group(1)
            value = "llvm-strip${package#llvm}"
        elif simple_match:
            pattern, value = simple_match.groups()
        else:
            fail(f"{path}: unsupported drift-script LLVM_STRIP derivation line: {line}")
        if pattern in rules:
            fail(f"{path}: duplicate drift-script LLVM_STRIP derivation rule for {pattern}")
        rules[pattern] = value
    return require_llvm_strip_rules(path, rules)


def format_llvm_strip_rules(rules):
    return ", ".join(f"{pattern}->{rules[pattern]}" for pattern in ("llvm-*", "*"))


def installer_defaults(path):
    text = read(path)
    return {
        key: require_match(
            path,
            text,
            key,
            rf'^{key}="\$\{{{key}:-([^}}]+)\}}"$',
        )
        for key in KEYS
    }


def drift_defaults(path):
    text = read(path)
    apt_snapshot = require_match(
        path,
        text,
        "EBPF_APT_SNAPSHOT",
        r'^canonical_apt_snapshot="([^"]+)"$',
    )
    require_match(
        path,
        text,
        "actual EBPF_APT_SNAPSHOT fallback",
        r'^(actual_apt_snapshot="\$\{EBPF_APT_SNAPSHOT:-\$canonical_apt_snapshot\}")$',
    )
    require_match(
        path,
        text,
        "expected EBPF_APT_SNAPSHOT fallback",
        r'^(expected_apt_snapshot="\$\{EBPF_EXPECTED_APT_SNAPSHOT:-\$canonical_apt_snapshot\}")$',
    )
    return {
        "EBPF_APT_SNAPSHOT": apt_snapshot,
        "EBPF_CLANG_PACKAGE": require_match(
            path,
            text,
            "EBPF_CLANG_PACKAGE",
            r'^expected_clang_package="\$\{EBPF_EXPECTED_CLANG_PACKAGE:-\$\{EBPF_CLANG_PACKAGE:-([^}]+)\}\}"$',
        ),
        "EBPF_LLVM_PACKAGE": require_match(
            path,
            text,
            "EBPF_LLVM_PACKAGE",
            r'^expected_llvm_package="\$\{EBPF_EXPECTED_LLVM_PACKAGE:-\$\{EBPF_LLVM_PACKAGE:-([^}]+)\}\}"$',
        ),
        "EBPF_LIBBPF_DEV_PACKAGE": require_match(
            path,
            text,
            "EBPF_LIBBPF_DEV_PACKAGE",
            r'^expected_libbpf_dev_package_spec="\$\{EBPF_EXPECTED_LIBBPF_DEV_PACKAGE:-\$\{EBPF_LIBBPF_DEV_PACKAGE:-([^}]+)\}\}"$',
        ),
    }


def drift_comment_pins(path):
    text = read(path)
    return {
        "EBPF_APT_SNAPSHOT": require_match(path, text, "EBPF_APT_SNAPSHOT", r"^#   apt snapshot (\S+)$"),
        "EBPF_CLANG_PACKAGE": require_match(path, text, "EBPF_CLANG_PACKAGE", r"^#   (clang-\d+=\S+)$"),
        "EBPF_LLVM_PACKAGE": require_match(path, text, "EBPF_LLVM_PACKAGE", r"^#   (llvm-\d+=\S+)$"),
        "EBPF_LIBBPF_DEV_PACKAGE": require_match(path, text, "EBPF_LIBBPF_DEV_PACKAGE", r"^#   (libbpf-dev=\S+)$"),
    }


def claude_pins(path):
    text = read(path)
    match = re.search(
        r"^Current canonical eBPF toolchain pins \(guarded by `scripts/check-ebpf-toolchain-pin-lockstep.sh`\): "
        r"EBPF_APT_SNAPSHOT=(\S+), "
        r"EBPF_CLANG_PACKAGE=(\S+), "
        r"EBPF_LLVM_PACKAGE=(\S+), "
        r"EBPF_LIBBPF_DEV_PACKAGE=(\S+)\.$",
        text,
        re.MULTILINE,
    )
    if not match:
        fail(f"{path}: missing canonical eBPF toolchain pin line guarded by scripts/check-ebpf-toolchain-pin-lockstep.sh")
    return dict(zip(KEYS, match.groups()))


sources = [
    ("workflow env", workflow_pins(workflow_path)),
    ("installer defaults", installer_defaults(installer_path)),
    ("drift-script defaults", drift_defaults(drift_path)),
    ("drift-script canonical comment", drift_comment_pins(drift_path)),
    ("CLAUDE.md prose", claude_pins(claude_path)),
]

baseline_label, baseline = sources[0]
errors = []
for label, pins in sources[1:]:
    for key in KEYS:
        if pins[key] != baseline[key]:
            errors.append(
                f"{label}: {key}={pins[key]} (want {baseline_label} {key}={baseline[key]})"
            )

workflow_llvm_rules = workflow_llvm_strip_derivation(workflow_path)
drift_llvm_rules = drift_llvm_strip_derivation(drift_path)
if drift_llvm_rules != workflow_llvm_rules:
    errors.append(
        "drift-script LLVM_STRIP derivation="
        f"{format_llvm_strip_rules(drift_llvm_rules)} "
        "(want workflow Resolve eBPF tool names "
        f"{format_llvm_strip_rules(workflow_llvm_rules)})"
    )

if errors:
    print("ERROR: eBPF toolchain pin or LLVM_STRIP derivation drift detected:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    print(
        "\nUpdate the workflow env, script defaults, drift-script canonical comment, "
        "CLAUDE.md pin line, and mirrored LLVM_STRIP derivation in the same "
        "change, then regenerate the committed XDP object when package/snapshot "
        "pins change.",
        file=sys.stderr,
    )
    sys.exit(1)

pin_summary = ", ".join(f"{key}={baseline[key]}" for key in KEYS)
print(
    "OK: eBPF toolchain pins lockstep across workflow, installer, drift guard, "
    f"and CLAUDE.md; LLVM_STRIP derivation lockstep ({pin_summary})"
)
PY
