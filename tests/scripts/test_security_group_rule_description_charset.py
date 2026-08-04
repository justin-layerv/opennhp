#!/usr/bin/env python3
"""Fence every security-group rule description to the charset AWS accepts.

AuthorizeSecurityGroupIngress rejects the WHOLE call when a description carries
a character outside

    a-zA-Z0-9 . _ - : / ( ) # , @ [ ] + = & ; { } ! $ *   (and space)

There is no plan-time validation for this, so an offending description is
invisible until the resource is first created. That is how it shipped: the
connector-authority Lambda-endpoint rule sat behind a dark `count` with the
description "HTTPS from this cell's NHP server", and the apostrophe only failed
the day the slice was activated -- taking the whole sandbox infrastructure apply
down with it.

Static, offline, and repository-wide, so a new rule anywhere gets the same fence
rather than the next dark slice discovering it in production.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._-:/()#,@[]+=&;{}!$* "
)
MAX_DESCRIPTION_LENGTH = 255

RULE_RESOURCE = re.compile(
    r'resource\s+"(aws_vpc_security_group_(?:in|e)gress_rule)"\s+"([^"]+)"\s*\{(.*?)\n\}',
    re.S,
)
DESCRIPTION = re.compile(r'description\s*=\s*"([^"]*)"')


def iter_rule_descriptions():
    for path in sorted(REPO_ROOT.glob("terraform/**/*.tf")):
        text = path.read_text(encoding="utf-8")
        for match in RULE_RESOURCE.finditer(text):
            description = DESCRIPTION.search(match.group(3))
            if description is None:
                continue
            yield path, match.group(2), description.group(1)


class SecurityGroupRuleDescriptionCharsetTests(unittest.TestCase):
    def test_the_repository_actually_declares_rules_to_check(self) -> None:
        """Guard the guard: a regex that matches nothing would pass silently."""
        self.assertGreater(len(list(iter_rule_descriptions())), 0)

    def test_every_description_uses_only_characters_aws_accepts(self) -> None:
        for path, name, description in iter_rule_descriptions():
            with self.subTest(rule=f"{path.relative_to(REPO_ROOT)}:{name}"):
                invalid = sorted({c for c in description if c not in ALLOWED})
                self.assertEqual(
                    invalid,
                    [],
                    f"{description!r} carries {invalid}; AWS rejects the whole "
                    "AuthorizeSecurityGroupIngress call. Apostrophes are the "
                    "common one -- rephrase rather than quote.",
                )

    def test_every_description_is_within_the_length_limit(self) -> None:
        for path, name, description in iter_rule_descriptions():
            with self.subTest(rule=f"{path.relative_to(REPO_ROOT)}:{name}"):
                self.assertLessEqual(len(description), MAX_DESCRIPTION_LENGTH)


if __name__ == "__main__":
    unittest.main()
