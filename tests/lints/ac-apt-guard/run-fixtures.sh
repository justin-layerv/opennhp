#!/usr/bin/env bash
# Regression fixtures for terraform_data.ac_user_data_runtime_apt_guard_fence.
#
# The production fence lives in terraform/modules/ac/main.tf and scans the AC
# user_data template source for boot-time apt update/install/upgrade calls.
# This runner also applies the same regex to the tiny launch-template bootstrap
# heredoc in main.tf because that path runs before the S3-hosted init script.
# The fixtures exercise the same regex so future edits do not narrow the guard
# back to only the incident's exact `apt-get update` shape.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
AC_MAIN="$REPO_ROOT/terraform/modules/ac/main.tf"

if [[ ! -f "$AC_MAIN" ]]; then
  echo "::error::missing $AC_MAIN" >&2
  exit 1
fi

python3 - "$AC_MAIN" <<'PY'
import re
import sys
from pathlib import Path

main_tf_path = Path(sys.argv[1])
main_tf = main_tf_path.read_text()
match = re.search(
    r'ac_runtime_apt_regex\s*=\s*"((?:\\.|[^"])*)"',
    main_tf,
    re.S,
)
if not match:
    print("::error::could not find local.ac_runtime_apt_regex", file=sys.stderr)
    sys.exit(1)

pattern = match.group(1).replace(r"\\", "\\").replace(r"\"", '"')
# Terraform uses RE2 with POSIX character classes; Python's stdlib re does not.
pattern = pattern.replace("[[:space:]]", r"\s").replace("[^[:space:]]", r"[^\s]")
# Multi-line mode is inline `(?m)` in the production pattern itself — do not
# pass re.MULTILINE here, so a future strip of `(?m)` from main.tf surfaces as
# a fixture divergence instead of being silently re-applied by the compiler.
regex = re.compile(pattern)

bootstrap = re.search(
    r'user_data = var\.plugin_bucket_name != null \? base64encode\(<<-BOOTSTRAP\n(.*?)\nBOOTSTRAP',
    main_tf,
    re.S,
)
if not bootstrap:
    print("::error::could not find AC launch-template bootstrap heredoc", file=sys.stderr)
    sys.exit(1)

production_sources = [
    ("terraform/modules/ac/user_data.sh.tpl", main_tf_path.with_name("user_data.sh.tpl").read_text()),
    ("terraform/modules/ac/main.tf bootstrap heredoc", bootstrap.group(1)),
    ("terraform/modules/ac/main.tf", main_tf),
]
for source_name, source in production_sources:
    match = regex.search(source)
    if match:
        print(
            f"::error::{source_name} contains a boot-time apt invocation matched by "
            f"ac_user_data_runtime_apt_guard_fence: {match.group(0)!r}",
            file=sys.stderr,
        )
        sys.exit(1)

fixtures = [
    ("clean", "echo all good\ncommand -v jq >/dev/null\n", False),
    ("comment", "# apt-get install jq\n  # sudo apt update\n", False),
    ("string-literal", 'echo "do not run apt-get install here"\n', False),
    # Known boundary: this fence is a source-scan regression guard, not a shell
    # parser. Chained/command-substitution forms are documented misses.
    ("known-gap-chained-command", "cd /tmp && apt-get install -y jq\n", False),
    ("apt-get-install", "apt-get install -y jq\n", True),
    ("apt-get-update", "  apt-get update -y\n", True),
    ("sudo-apt-get", "sudo apt-get install -y jq\n", True),
    ("env-prefixed", "DEBIAN_FRONTEND=noninteractive apt-get install -y jq\n", True),
    ("env-command", "env DEBIAN_FRONTEND=noninteractive apt-get install -y jq\n", True),
    ("sudo-env-prefixed", "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y jq\n", True),
    ("command-wrapper", "command apt-get install -y jq\n", True),
    ("path-qualified", "/usr/bin/apt-get install -y jq\n", True),
    ("subshell-wrapper", "( apt-get install -y jq )\n", True),
    ("apt-install", "apt install -y jq\n", True),
    ("aptitude-install", "aptitude install -y jq\n", True),
    ("apt-get-upgrade", "apt-get upgrade -y\n", True),
    ("apt-get-dist-upgrade", "apt-get dist-upgrade -y\n", True),
    ("apt-full-upgrade", "apt full-upgrade -y\n", True),
    ("helper-install", "apt_get_with_retry install -y jq\n", True),
]

failures = 0
for name, body, should_match in fixtures:
    matched = regex.search(body) is not None
    if matched != should_match:
        failures += 1
        print(
            f"  FAIL: {name}: matched={matched}, expected={should_match}",
            file=sys.stderr,
        )
    else:
        print(f"  PASS: {name}")

if failures:
    print(f"::error::{failures} ac apt guard fixture(s) failed", file=sys.stderr)
    sys.exit(1)

print(f"All {len(fixtures)} ac apt guard fixtures passed.")
PY
