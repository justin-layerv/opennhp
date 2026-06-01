resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_service_glob" {
  name = "route53-service-glob"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53ServiceGlob"
        Effect   = "Allow"
        Action   = "route53:*"
        Resource = "*"
      }
    ]
  })
}
