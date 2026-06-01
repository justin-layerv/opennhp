resource "aws_iam_group" "deploy" {
  name = "fixture-deploy"
}

resource "aws_iam_group_policy" "route53_wildcard" {
  name  = "route53-wildcard"
  group = aws_iam_group.deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53WildcardGroupPolicy"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "*"
      }
    ]
  })
}

