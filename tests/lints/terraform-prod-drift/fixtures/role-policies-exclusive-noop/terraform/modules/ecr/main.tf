# Canonical role with an inline `aws_iam_role_policy` providing the
# data source's required actions, plus an
# `aws_iam_role_policies_exclusive` block declaring the inline-
# policy NAMES exhaustively. The lint walks the inline policy as
# usual; the exclusive block is silently skipped (correct behavior
# — it carries no policy body, just names). The fixture exits 0.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudformation_website_api" {
  name = "cloudformation-website-api"
  role = aws_iam_role.github_actions.id

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

resource "aws_iam_role_policies_exclusive" "github_actions" {
  role_name    = aws_iam_role.github_actions.name
  policy_names = ["cloudformation-website-api"]
}
