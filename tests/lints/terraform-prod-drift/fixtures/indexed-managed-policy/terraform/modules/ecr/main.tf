# Canonical role + count-gated managed policy attached via indexed ARN.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_policy" "secrets_describe" {
  count = 1

  name = "fixture-secrets-describe"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DescribeSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "secrets_describe" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.secrets_describe[0].arn
}
