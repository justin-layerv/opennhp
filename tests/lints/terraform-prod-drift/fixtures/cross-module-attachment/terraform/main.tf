# cross-module-attachment fixture (cr round 12 test-coverage gap):
#
# Positive case for the cross-module role-attribution path. The
# canonical `modules/ecr/` declares the github_actions role; the
# parent `terraform/main.tf` (this file, outside the canonical
# module path) declares a grant with `role =
# module.ecr.github_actions_role_name`. The lint must resolve
# `CROSS_MODULE_ROLE_REF` from a non-canonical-module file and
# credit the grant. Mirrors the real-tree shape at
# `terraform/main.tf:1284` (the cost-analytics cross-account
# attachment).

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}

module "ecr" {
  source = "./modules/ecr"
}

# Parent-module attachment via the canonical role's module output.
# This file is OUTSIDE `modules/ecr/`, so `_in_canonical_module`
# returns false and the cross-module branch in
# `_attached_to_github_actions` is the path under test.
resource "aws_iam_role_policy" "cloudformation_website_api_parent" {
  name = "cloudformation-website-api-parent"
  role = module.ecr.github_actions_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WebsiteAPIStackRead"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate"
        ]
        Resource = "*"
      }
    ]
  })
}
