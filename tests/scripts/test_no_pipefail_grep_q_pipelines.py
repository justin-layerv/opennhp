#!/usr/bin/env python3
"""`cmd | grep -q` under `set -o pipefail` is a false negative on large input.

`grep -q` exits at its FIRST match. The writer still has bytes to push, gets
EPIPE, and `pipefail` promotes the writer's failure to the pipeline's status --
so a pattern that IS present reports absent.

It is invisible below the pipe buffer (64 KiB on Linux): the writer finishes
before grep exits, so every small-input test passes. Between there and grep's
initial read buffer (96 KiB) it is a coin flip -- one read can drain the whole
pipe and let the writer finish -- which is why the field symptom comes and goes.
Only past that buffer does grep reliably exit still owing the writer bytes. That
progression, invisible then intermittent then certain, is what makes it worth a
fence rather than a code review note.

Observed 2026-08-02: `deploy-sandbox-cell1-infra` read the 69 KB cell1
server-init.sh and reported

    printf: write error: Broken pipe
    ::error::cell1 server-init.sh is missing AGENT_OTP_REGISTRATION_ENABLED
    ::error::cell1 server-init.sh is missing QURL_V2_ADMISSION_ENABLED

while the live object had carried both flags, unchanged, for eight hours. It
blocked Build and Deploy NHP on a perfectly healthy cell.

A herestring has no pipeline and no writer to kill, so the fix is `grep -q PAT
<<<"$var"`.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

class NoPipefailGrepQTest(unittest.TestCase):
    def test_the_bug_is_real_and_the_herestring_is_the_fix(self) -> None:
        """Demonstrate it, so the rule below is not folklore.

        Without this, a future reader has only an assertion that some shell
        idiom is banned, and no way to check whether it still matters.

        The demonstration uses 1 MiB rather than the incident's 69 KB. 69 KB
        fits inside grep's 96 KiB initial read, so a single read can empty the
        pipe and let the writer finish -- the false negative reproduces only
        some of the time (found in 42 of 60 runs on GNU grep 3.11 / Ubuntu
        24.04), and this test went red on main on 2026-08-10 for exactly that
        reason. Past that buffer grep always exits with bytes still unwritten,
        which is the property being fenced; the size at which it starts is not.
        """
        script = r"""
        set -euo pipefail
        big="$(python3 -c "print('FLAG=true'); print('x'*(1024*1024))")"
        piped=found;      printf '%s' "$big" | grep -q '^FLAG=' 2>/dev/null || piped=MISSING
        herestring=found; grep -q '^FLAG=' <<<"$big" || herestring=MISSING
        echo "$piped $herestring"
        """
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=60
        )
        # Without this the split below raises a bare ValueError -- the one
        # failure that says nothing about which of the two probes went wrong.
        self.assertEqual(result.returncode, 0, result.stderr)
        piped, herestring = result.stdout.split()
        self.assertEqual(
            piped,
            "MISSING",
            "the pipe no longer false-negatives on 1 MiB; if the platform "
            "changed, this fence can be reconsidered",
        )
        self.assertEqual(herestring, "found", "the herestring must find it")

    def test_the_large_object_guards_do_not_pipe(self) -> None:
        """Scoped to the guards that read genuinely large objects.

        A repo-wide ban would be wrong: `echo "$AMI_ID" | grep -Eq …` is a dozen
        bytes and can never fill a pipe buffer, and failing someone's PR for that
        teaches people to ignore the rule. What matters is the handful of places
        that read something whose size is not bounded by construction -- an S3
        object, an AWS CLI listing, a captured stderr.
        """
        guards = {
            ".github/workflows/build-and-push.yml": [
                # the 69 KB cell1 server-init.sh object
                'grep -q "^${key}=" <<<"${script}"',
            ],
            ".github/actions/verify-image-attestation/action.yml": [
                # AWS CLI describe output and captured gh stderr
                'grep -qiE "$ABSENT_RE" <<<"$DESCRIBE_OUT"',
                'grep -qiE "$INFRA_RE" <<<"$SCRUBBED_OUT"',
                'grep -qiE "$INFRA_RE" <<<"$GH_ERR"',
            ],
        }
        for relative, fragments in guards.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            for fragment in fragments:
                with self.subTest(file=relative, fragment=fragment):
                    self.assertIn(
                        fragment,
                        text,
                        f"{relative} no longer reads this value with a "
                        "herestring; piping it into grep -q silently reports a "
                        "present pattern as absent once it exceeds 64 KiB",
                    )

    def test_the_cell1_guard_reads_the_s3_object_not_the_launch_template(
        self,
    ) -> None:
        """The guard is only worth having if it reads the real config.

        The launch template holds a bootstrap shim; the server configuration is
        the S3 object instances fetch at boot. Reading the template instead is
        what made the original cell1 gap invisible for days.
        """
        text = (ROOT / ".github/workflows/build-and-push.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            's3://layerv-nhp-sandbox-cell1-plugins/scripts/server-init.sh',
            text,
        )
        for key in ("AGENT_OTP_REGISTRATION_ENABLED", "QURL_V2_ADMISSION_ENABLED"):
            with self.subTest(key=key):
                self.assertIn(key, text)


if __name__ == "__main__":
    unittest.main()
