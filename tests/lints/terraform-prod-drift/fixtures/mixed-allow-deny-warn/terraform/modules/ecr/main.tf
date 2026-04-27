# Canonical role with a mixed Allow/Deny inline policy. The Allow leg
# grants the actions `aws_cloudformation_stack` requires, so the IAM
# coverage check exits 0; the lint also warns once because the Deny
# leg's narrowing is not modeled.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudformation_with_deny" {
  name = "cloudformation-with-deny"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowStackRead"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyDeleteStack"
        Effect   = "Deny"
        Action   = ["cloudformation:DeleteStack"]
        Resource = "*"
      }
    ]
  })
}
