# Canonical role with an `aws_iam_role_policy_attachments_exclusive`
# resource carrying the cloudformation grants. Replaces
# `aws_iam_role_policy_attachment` blocks per terraform-aws-provider
# migration guidance. The lint must walk the `policy_arns = [...]`
# array and credit each ARN's actions.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_policy" "cloudformation_grants" {
  name = "cloudformation-grants"

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

resource "aws_iam_role_policy_attachments_exclusive" "github_actions" {
  role_name = aws_iam_role.github_actions.name
  policy_arns = [
    aws_iam_policy.cloudformation_grants.arn,
  ]
}
