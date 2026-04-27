# cr round 6 fence: a data source that requires IAM grants is present,
# but no canonical role lives under modules/ecr/. The lint should detect
# the empty-attribution case specifically and exit 3 with the
# "CANONICAL_ROLE_MODULE_PATH may have moved" diagnostic — load-bearing
# fail-loud for a future refactor that relocates the role.

data "aws_cloudformation_stack" "lint_test" {
  name = "fixture-stack"
}
