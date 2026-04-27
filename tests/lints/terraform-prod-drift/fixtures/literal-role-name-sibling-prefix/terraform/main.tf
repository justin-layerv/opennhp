# literal-role-name-sibling-prefix fixture (cr round 15 false-positive
# fence):
#
# Pre-fix, `LITERAL_ROLE_NAME_SUFFIX` was matched with `in` (substring),
# so a sibling module's role like `traefik-plugins-prod-github-actions`
# would silently get credited to the canonical NHP role's coverage
# union — a silent false-positive in the dangerous direction (lint
# passes when a real grant is missing). Post-fix, the literal-name
# match is anchored on BOTH prefix `nhp-` AND suffix `-github-actions`,
# so the sibling role doesn't match.
#
# The fixture has:
# - canonical NHP role declared in `modules/ecr/`, no grant for
#   `cloudformation:DescribeStacks/GetTemplate`
# - sibling traefik-plugins role with a literal-name attachment
#   that grants those actions to itself (NOT the canonical role)
# - a data source needing the actions
#
# Pre-fix: lint exits 0 (false-positive, silent miss). Post-fix:
# lint exits 1 (correctly reports the gap).

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
