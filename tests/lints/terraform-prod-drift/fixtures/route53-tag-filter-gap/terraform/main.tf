# route53-tag-filter-gap fixture (cr round 14 issue 3):
#
# Regression fence for the `aws_route53_zone` tag-filter drift
# detection. Pre-fix, `DATA_SOURCE_ACTIONS` listed only
# `route53:ListHostedZones` regardless of the data-source body, so
# adding `tags = {...}` to the data block silently demanded the
# extra `route53:ListTagsForResource` action without the lint
# noticing — the failure mode the comment warned about.
#
# Post-fix, the lint inspects the data-source body for `tags` and
# adds the extra action conditionally. The fixture has the tags
# filter set but the role grants only `route53:ListHostedZones`,
# so iam-coverage exits 1 (missing action). Pre-fix, this would
# have exited 0 silently.

data "aws_route53_zone" "tagged" {
  name = "fixture.example.com."
  tags = {
    Environment = "fixture"
  }
}
