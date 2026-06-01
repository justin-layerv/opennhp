# Service-level Route53 wildcard fixture for nhp#1146. This reaches all Route53
# resource types, including hosted zones, so ChangeResourceRecordSets needs the
# same normalized-record-name guard as Resource="*".

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_service_wildcard" {
  name = "route53-service-wildcard"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53ServiceWildcard"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::*"
      }
    ]
  })
}
