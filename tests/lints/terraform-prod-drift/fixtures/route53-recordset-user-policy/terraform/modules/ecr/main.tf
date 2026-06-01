resource "aws_iam_user" "deploy" {
  name = "fixture-deploy"
}

resource "aws_iam_user_policy" "route53_wildcard" {
  name = "route53-wildcard"
  user = aws_iam_user.deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53WildcardUserPolicy"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "*"
      }
    ]
  })
}

