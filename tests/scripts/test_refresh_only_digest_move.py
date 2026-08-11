#!/usr/bin/env python3
"""Fence _check_refresh_only_outputs' published-digest allowance.

#3761 made the Authority image digest track an SSM parameter the publisher
updates out of band, so `authority_image_uri` legitimately moves on every image
publish. The refresh-only normalizer was written when the digest was pinned and
every root output was stable across a refresh, so it rejected that movement --
which wedged the Control root: apply refuses any drift, and the only thing that
absorbs drift could not run.

The allowance is deliberately the narrowest thing that unblocks it. These tests
exist to keep it that way: widening it to another output, another repository, or
a non-digest URI must fail here.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / ".github" / "scripts" / "check-control-sandbox-first-apply.py"

spec = importlib.util.spec_from_file_location("control_first_apply", CHECKER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules["control_first_apply"] = module
spec.loader.exec_module(module)

REPO = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv-nhp-sandbox-connector-authority"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def entry(value: str) -> dict:
    return {"sensitive": False, "type": "string", "value": value}


class PublishedDigestMoveTest(unittest.TestCase):
    def test_same_repository_digest_move_is_allowed(self):
        """The exact shape #3761 makes routine: same repo, new digest."""
        self.assertTrue(
            module._is_published_digest_move(
                entry(f"{REPO}@sha256:{DIGEST_A}"), entry(f"{REPO}@sha256:{DIGEST_B}")
            )
        )

    def test_different_repository_is_rejected(self):
        """A repository swap is not a publish; it is a different image entirely."""
        self.assertFalse(
            module._is_published_digest_move(
                entry(f"{REPO}@sha256:{DIGEST_A}"),
                entry(f"{REPO}-other@sha256:{DIGEST_B}"),
            )
        )

    def test_tag_form_uri_is_rejected(self):
        """Only immutable digest URIs qualify; a tag can be repointed."""
        self.assertFalse(
            module._is_published_digest_move(
                entry(f"{REPO}:latest"), entry(f"{REPO}@sha256:{DIGEST_B}")
            )
        )

    def test_malformed_digest_is_rejected(self):
        self.assertFalse(
            module._is_published_digest_move(
                entry(f"{REPO}@sha256:nothex"), entry(f"{REPO}@sha256:{DIGEST_B}")
            )
        )

    def test_non_string_values_are_rejected(self):
        self.assertFalse(
            module._is_published_digest_move(
                {"sensitive": False, "type": "string", "value": None},
                entry(f"{REPO}@sha256:{DIGEST_B}"),
            )
        )

    def test_allowance_is_scoped_to_one_output_name(self):
        """The allowance must be keyed on authority_image_uri and nothing else.

        _is_published_digest_move is value-shape only; the caller is what binds
        it to a single output. If that binding is ever loosened, any output
        holding an ECR digest URI could drift unnoticed.
        """
        self.assertEqual(module._DIGEST_TRACKING_OUTPUT, "authority_image_uri")


if __name__ == "__main__":
    unittest.main(verbosity=2)
