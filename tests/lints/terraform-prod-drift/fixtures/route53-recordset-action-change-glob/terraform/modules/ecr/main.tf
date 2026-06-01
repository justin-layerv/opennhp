resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_change_glob" {
  name = "route53-change-glob"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53ChangeGlob"
        Effect   = "Allow"
        Action   = "route53:Change*"
        Resource = "*"
      }
    ]
  })
}
