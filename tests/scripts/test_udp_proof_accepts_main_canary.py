#!/usr/bin/env python3
"""The proof must be able to consume a Connector canary built from main.

The canary publisher was pull-request-only. Every one of its identifiers encoded
a PR number, and so did every check on the nhp side that consumed them. That made
the proof structurally incapable of testing main: the only image it would accept
was one built from a branch, and when that branch squash-merged its commit was no
longer reachable from main at all.

De-pinning the proof fixed which COMMIT is proved. This fences the other half --
the shape of the evidence for a commit that has no pull request:

  * the evidence artifact is named connector-canary-main-<sha>, not
    connector-canary-pr--<sha>;
  * pr_number is null, and null is accepted;
  * a resolved candidate carries no pull request number at all.

Each of these failed a live main canary in a different place, one per attempt, so
they are asserted together rather than trusting one to imply the others.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import collect_udp_proof_deployment_evidence as collector  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402

SHA = "c" * 40


class CanaryEvidenceArtifactNameTest(unittest.TestCase):
    def test_accepts_a_canary_built_from_main(self) -> None:
        self.assertRegex(f"connector-canary-main-{SHA}", contract.CANARY_EVIDENCE_ARTIFACT_RE)

    def test_still_accepts_a_pre_merge_pull_request_canary(self) -> None:
        for number in (1, 9, 517, 999999):
            with self.subTest(number=number):
                self.assertRegex(
                    f"connector-canary-pr-{number}-{SHA}",
                    contract.CANARY_EVIDENCE_ARTIFACT_RE,
                )

    def test_rejects_the_empty_pull_request_number_the_publisher_used_to_emit(
        self,
    ) -> None:
        """`pr-${PR_NUMBER}` with an empty PR_NUMBER rendered `pr--<sha>`.

        That string is what a main build produced while the publisher still
        rebuilt its label from a pull request number. It must never be treated as
        a valid canary: it names no pull request and no branch.
        """
        self.assertNotRegex(
            f"connector-canary-pr--{SHA}", contract.CANARY_EVIDENCE_ARTIFACT_RE
        )

    def test_rejects_shapes_that_are_not_a_canary_for_an_exact_commit(self) -> None:
        for name in (
            f"connector-canary-{SHA}",  # no label
            "connector-canary-main-",  # no commit
            f"connector-canary-main-{SHA[:39]}",  # truncated commit
            f"connector-canary-main-{SHA}Z",  # trailing junk
            f"connector-canary-MAIN-{SHA}",  # not the branch name
            f"connector-canary-pr-0-{SHA}",  # not a real PR number
            f"connector-canary-pr-01-{SHA}",  # leading zero
            f"connector-canary-branch-{SHA}",  # any other branch
            f"connector-canary-main-{SHA.upper()}",  # non-canonical sha case
            f"x-connector-canary-main-{SHA}",  # prefixed
        ):
            with self.subTest(name=name):
                self.assertNotRegex(name, contract.CANARY_EVIDENCE_ARTIFACT_RE)

    def test_the_lookup_and_the_revalidation_share_one_definition(self) -> None:
        """Two halves of one contract, so one shape change cannot pass only one.

        The artifact lookup lives in the collector and the manifest
        re-validation in the contract module. They each held their own copy of
        this regex, so widening one silently left the other rejecting the very
        evidence the first had just accepted.
        """
        source = (SCRIPT_DIR / "collect_udp_proof_deployment_evidence.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            "CANARY_EVIDENCE_ARTIFACT_RE = re.compile",
            source,
            "the collector must use the contract's definition, not redeclare it",
        )
        self.assertIn("contract.CANARY_EVIDENCE_ARTIFACT_RE", source)


class OptionalPullRequestNumberTest(unittest.TestCase):
    def test_null_is_accepted_because_main_has_no_pull_request(self) -> None:
        self.assertTrue(collector._is_optional_pull_request_number(None))

    def test_a_real_pull_request_number_is_still_accepted(self) -> None:
        for number in (1, 452, 517, 999999):
            with self.subTest(number=number):
                self.assertTrue(collector._is_optional_pull_request_number(number))

    def test_junk_is_rejected(self) -> None:
        for value in (0, -1, "517", "", [], {}, 1.0, True, False):
            with self.subTest(value=value):
                self.assertFalse(collector._is_optional_pull_request_number(value))

    def test_both_canary_checks_route_through_it(self) -> None:
        """Accepting null in one check and not the other just moves the failure.

        The canary provenance check and the published-canary handoff check each
        carry their own pr_number assertion; a live main canary failed the first,
        was fixed, and then failed the second.
        """
        source = (SCRIPT_DIR / "collect_udp_proof_deployment_evidence.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            source.count("_is_optional_pull_request_number(root.get(\"pr_number\"))"),
            1,
            "canary provenance must accept a null pr_number",
        )
        self.assertEqual(
            source.count(
                "_is_optional_pull_request_number(published.get(\"pr_number\"))"
            ),
            1,
            "the published-canary handoff must accept a null pr_number",
        )
        self.assertNotIn(
            'isinstance(root.get("pr_number"), int)',
            source,
            "a bare int check rejects every canary built from main",
        )
        self.assertNotIn(
            'isinstance(published.get("pr_number"), int)',
            source,
            "a bare int check rejects every canary built from main",
        )


class ResolvedCandidateCarriesNoPullRequestTest(unittest.TestCase):
    def test_no_pull_request_number_survives_anywhere_in_the_proof(self) -> None:
        """The producer stopped emitting it; the validator still demanded it.

        One side of a two-sided contract was left behind, so every producer run
        failed shape validation. Neither side may name the field again.
        """
        # Match the JSON FIELD -- '"pull_request_number"' -- not the bare
        # substring, which also appears in _is_optional_pull_request_number, the
        # helper that exists precisely because the field went away.
        for script in (
            "collect_udp_proof_deployment_evidence.py",
            "udp_proof_deployment_contract.py",
        ):
            with self.subTest(script=script):
                self.assertNotIn(
                    '"pull_request_number"',
                    (SCRIPT_DIR / script).read_text(encoding="utf-8"),
                    f"{script} still binds a client pull request number; the proof "
                    "binds main, so there is nothing to select",
                )


if __name__ == "__main__":
    unittest.main()
