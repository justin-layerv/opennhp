# Canonical role with a wildcard grant. The data source needs
# `cloudformation:DescribeStacks` + `cloudformation:GetTemplate`; the
# role grants `cloudformation:*` which covers both.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudformation_wildcard" {
  name = "cloudformation-wildcard"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudformationWildcard"
        Effect   = "Allow"
        Action   = ["cloudformation:*"]
        Resource = "*"
      }
    ]
  })
}
