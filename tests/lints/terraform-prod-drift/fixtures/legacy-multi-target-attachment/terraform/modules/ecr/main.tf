# Canonical role + a managed policy attached via the legacy
# `aws_iam_policy_attachment` (multi-target) shape rather than
# `aws_iam_role_policy_attachment`. The lint must walk the `roles =
# [...]` array and credit the policy's actions to the role.

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

resource "aws_iam_policy_attachment" "cloudformation_grants" {
  name       = "cloudformation-grants"
  roles      = [aws_iam_role.github_actions.name]
  policy_arn = aws_iam_policy.cloudformation_grants.arn
}
