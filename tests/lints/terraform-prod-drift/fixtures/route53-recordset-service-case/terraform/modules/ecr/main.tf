# Mixed-case Route53 service ARN fixture for nhp#1146. AWS treats ARN service
# matching case-insensitively, so the static lint should not rely on lowercase
# spelling to catch hosted-zone wildcards.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_service_case" {
  name = "route53-service-case"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53ServiceCase"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:Route53:::hostedzone/Z*"
      }
    ]
  })
}
