# legacy-multi-target-attachment fixture (cr round 11 suggestion 1):
#
# Regression fence for the `aws_iam_policy_attachment` (legacy
# multi-target) attachment shape. Pre-fix, only
# `aws_iam_role_policy_attachment` was walked, so a refactor to the
# legacy multi-target form would silently drop the role's coverage
# union. The fixture asserts the lint walks the `roles = [...]`
# array and credits the policy's actions when the canonical role
# appears.

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
