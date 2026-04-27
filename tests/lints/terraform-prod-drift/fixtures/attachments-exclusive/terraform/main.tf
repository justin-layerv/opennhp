# attachments-exclusive fixture (cr round 12 substantive 1):
#
# Regression fence for the `aws_iam_role_policy_attachments_exclusive`
# attachment shape (the documented terraform-aws-provider migration
# path away from `aws_iam_role_policy_attachment`). Pre-fix, the lint
# walked only the singular shape; a future migration would silently
# drop the role's coverage union. The fixture asserts the lint walks
# `policy_arns = [...]` and credits each ARN's actions to the role.

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
