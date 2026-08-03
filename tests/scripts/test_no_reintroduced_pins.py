#!/usr/bin/env python3
"""Main is the bible: the proof must never re-acquire a pin.

The UDP proof used to bind two frozen candidate SHAs, restated in the controller,
the producer's dispatch inputs, and both client repositories. Any change to a
client branch -- even absorbing main -- moved a head and broke the binding, so the
candidate branches could never converge. With many developers merging
concurrently that loop tightens instead of settling, and it cost a full day.

De-pinning is only durable if re-pinning fails the build. A 40-hex literal or a
`*_pr_number` selector is easy to add back under deadline, reads as harmless in
review, and breaks nothing until the proof runs hours later.

Scope is deliberately the UDP proof surface, not the whole repo: pinning an
ACTION at a SHA is correct supply-chain practice, and Terraform legitimately pins
image digests. What must never come back is pinning WHICH COMMIT OF OUR OWN
CLIENTS the proof tests. That answer is always main.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

COLLECTOR = ROOT / ".github/scripts/collect_udp_proof_deployment_evidence.py"
CONTROLLER = ROOT / ".github/workflows/udp-proof-controller.yml"
PRODUCER = ROOT / ".github/workflows/udp-proof-deployment-manifest.yml"
PROOF_SURFACE = (CONTROLLER, PRODUCER, COLLECTOR)

CLIENTS = ("layervai/qurl-connector", "layervai/qurl-go")

# `uses: owner/action@<sha>` is correct and must stay allowed.
ACTION_PIN = re.compile(r"uses:\s*\S+@[0-9a-f]{40}")
BARE_SHA = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
# Selectors that name WHICH client commit or PR to prove.
CLIENT_SELECTOR = re.compile(
    r"\b(?:PINNED_[A-Z_]*SHA"
    r"|qurl_(?:go|connector)_candidate_sha"
    r"|qurl_(?:go|connector)_pr_number"
    r"|connector-pr-number|qurl-go-pr-number)\b"
)


def significant_lines(path: Path):
    """Code lines only. A comment explaining why a pin was removed is not a pin."""
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        yield number, raw


class NoReintroducedPinsTest(unittest.TestCase):
    def test_no_bare_commit_sha_literals(self) -> None:
        for path in PROOF_SURFACE:
            for number, line in significant_lines(path):
                if ACTION_PIN.search(line):
                    continue  # pinning a third-party action is correct
                with self.subTest(file=path.name, line=number):
                    self.assertIsNone(
                        BARE_SHA.search(line),
                        f"{path.relative_to(ROOT)}:{number} hard-codes a 40-hex commit. "
                        "The proof tests main; resolve the commit at run time instead.\n"
                        f"  {line.strip()[:120]}",
                    )

    def test_no_client_commit_selectors(self) -> None:
        for path in PROOF_SURFACE:
            for number, line in significant_lines(path):
                found = CLIENT_SELECTOR.search(line)
                with self.subTest(file=path.name, line=number):
                    self.assertIsNone(
                        found,
                        f"{path.relative_to(ROOT)}:{number} reintroduces a client "
                        f"selector ({found.group(0) if found else ''}). Which commit the "
                        "proof tests is not a choice: it is main.\n"
                        f"  {line.strip()[:120]}",
                    )

    def test_the_proof_actually_resolves_client_main(self) -> None:
        """Absence of pins is only half the guarantee; CLIENT main must be read.

        Asserting that "git/ref/heads/main" appears somewhere is too weak: the
        producer also resolves nhp's OWN main, so that string survives even if
        client resolution is deleted. An earlier version of this test passed
        against exactly that mutation, which is why it now names the resolver and
        requires each client to go through it.
        """
        collector = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn(
            "_resolve_client_main",
            collector,
            "the producer must resolve client main through a named resolver",
        )
        self.assertIn(
            'f"repos/{repository}/git/ref/heads/main"',
            collector,
            "_resolve_client_main must read the client repository's main ref",
        )
        for client in CLIENTS:
            with self.subTest(client=client):
                pattern = r"_resolve_client_main\(\s*" + re.escape('"' + client + '"')
                self.assertRegex(
                    collector,
                    pattern,
                    f"{client} must be resolved through _resolve_client_main",
                )

        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn(
            "git/ref/heads/main",
            controller,
            "the controller must re-read client main",
        )
        self.assertIn(
            "but main is now",
            controller,
            "the controller must fail when the producer bound a commit that is no "
            "longer main",
        )

    def test_client_identity_is_reachability_never_equality(self) -> None:
        """Resolving main is not enough if the comparison is then `==`.

        Equality against a freshly-resolved main head IS a pin, just one that
        re-acquires itself every run: any client commit landing between the
        canary build and validation invalidates an image that was correct when
        built. With many developers merging, the only way to satisfy it is to
        re-select and race -- the same loop this file exists to prevent, which is
        why absence of literal SHAs did not catch it.

        The honest question is reachability, and the collector already answers it
        for the Connector. Both clients must go through the same helper.
        """
        collector = COLLECTOR.read_text(encoding="utf-8")
        self.assertIn(
            "def _canary_commit_is_in_main",
            collector,
            "the collector must ask reachability through a named helper",
        )
        for client in CLIENTS:
            with self.subTest(client=client):
                self.assertRegex(
                    collector,
                    r"_canary_commit_is_in_main\(\s*" + re.escape('"' + client + '"'),
                    f"{client} identity must be checked by reachability, not equality",
                )
        self.assertNotRegex(
            collector,
            r'!=\s*metadata\["candidates"\]\["qurl_go"\]\["head_sha"\]',
            "qurl-go identity must not be an equality check against resolved main",
        )
        # The same pin wearing the Connector's clothes: comparing the published
        # canary's head_sha to the resolved candidate is equality against a
        # moving head, and reachability already answers the real question.
        self.assertNotRegex(
            collector,
            r'published\["head_sha"\]\s*!=\s*candidate\["head_sha"\]',
            "the published canary must not be pinned to the resolved candidate head",
        )
        self.assertNotRegex(
            collector,
            r'!=\s*candidate\["head_sha"\]',
            "no client identity may be an equality check against a resolved head",
        )

    def test_the_guard_is_not_vacuous(self) -> None:
        for path in PROOF_SURFACE:
            with self.subTest(file=path.name):
                self.assertTrue(path.exists(), f"{path} is missing")
                self.assertTrue(
                    any(True for _ in significant_lines(path)),
                    f"{path} has no code lines; the scan would prove nothing",
                )


if __name__ == "__main__":
    unittest.main()
