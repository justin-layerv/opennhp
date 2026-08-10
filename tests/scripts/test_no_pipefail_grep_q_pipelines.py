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

        Both ends of that progression are demonstrated, because the small end
        carries an argument of its own: 100 bytes must NOT false-negative. That
        is the "invisible" leg above, and it is why the guard below is scoped to
        the handful of large-object reads rather than banning the idiom repo-
        wide. Asserting it here keeps that scoping honest -- if small input ever
        did false-negative, the guard would be under-reaching and silent about
        it. Both payloads put the pattern on their FIRST line, so `grep -q`
        exits after its first read either way and the only difference is what
        the writer still owes behind it.

        The writer's own exit status is asserted alongside the pipeline result.
        Without it a regression reports only that the pattern went missing, and
        cannot separate a platform that stopped false-negating from unrelated
        breakage that happens to look identical from the outside.
        """
        script = r"""
        set -euo pipefail

        probe() {
            big="$(python3 -c "import sys; sys.stdout.write('FLAG=true\n' + 'x' * $1)")"

            piped=found
            if printf '%s' "$big" | grep -q '^FLAG='; then
                writer=${PIPESTATUS[0]}
            else
                writer=${PIPESTATUS[0]}
                piped=MISSING
            fi

            herestring=found
            grep -q '^FLAG=' <<<"$big" || herestring=MISSING

            echo "bytes=${#big} piped=$piped writer=$writer herestring=$herestring"
        }

        probe 100                 # below the 64 KiB pipe buffer
        probe $((1024 * 1024))    # past grep's 96 KiB initial read
        """
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=60
        )
        # Without this the unpacking below raises a bare ValueError -- the one
        # failure that says nothing about which of the two probes went wrong.
        self.assertEqual(result.returncode, 0, result.stderr)
        small, large = (
            dict(field.split("=", 1) for field in line.split())
            for line in result.stdout.strip().splitlines()
        )

        self.assertGreater(
            int(large["bytes"]),
            512 * 1024,
            "the demonstration payload has been shrunk. It has to clear the "
            "64 KiB pipe buffer plus grep's 96 KiB initial read with room to "
            "spare, or whether the writer drains before grep exits goes back to "
            "being a scheduling race and this test flakes on unrelated PRs",
        )
        self.assertEqual(
            small["piped"],
            "found",
            "a payload below the pipe buffer must NOT false-negative -- the "
            "writer lands its whole write in the buffer and never sees EPIPE. "
            "If this fails the idiom is worse than documented and the guard "
            "below is scoped too narrowly",
        )
        self.assertEqual(
            large["piped"],
            "MISSING",
            f"the pipe no longer false-negatives on {large['bytes']} bytes "
            f"(the writer exited {large['writer']}, stderr {result.stderr!r}); "
            "if the platform changed, this fence can be reconsidered",
        )
        self.assertNotEqual(
            large["writer"],
            "0",
            "the writer was supposed to die on EPIPE -- 141 for SIGPIPE, or 1 "
            "where an ancestor left SIGPIPE ignored and printf reports the "
            "write error itself, as the 2026-08-02 incident above shows. A "
            "writer that succeeded leaves pipefail nothing to promote, so a "
            "MISSING alongside it has some other cause",
        )
        for size, row in (("small", small), ("large", large)):
            with self.subTest(size=size):
                self.assertEqual(
                    row["herestring"], "found", "the herestring must find it"
                )

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
