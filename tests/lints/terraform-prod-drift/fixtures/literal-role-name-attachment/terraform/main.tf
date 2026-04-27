# literal-role-name-attachment fixture (cr round 14 issue 2):
#
# Regression fence for the literal-string role-name match in
# `_attached_to_github_actions`. Pre-fix, the resolver only matched
# the HCL refs `aws_iam_role.github_actions.{id,name}` and
# `module.ecr.github_actions_role_name`; a hardcoded
# `role = "nhp-prod-github-actions"` would silently miss the
# coverage union. The lint now matches on the literal-name suffix
# `-github-actions`. The fixture exercises this on
# `aws_iam_role_policy_attachments_exclusive` since cr called it out
# specifically, but the match works for every attachment shape.

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
