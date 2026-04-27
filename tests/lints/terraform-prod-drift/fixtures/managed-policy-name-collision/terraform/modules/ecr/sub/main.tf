# Canonical-side declaration of the colliding policy name + the
# canonical role.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_policy" "shared_name" {
  name = "fixture-shared-name"

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

resource "aws_iam_role_policy_attachment" "shared_name" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.shared_name.arn
}
