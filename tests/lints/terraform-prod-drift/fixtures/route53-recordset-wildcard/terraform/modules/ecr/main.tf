# Route53 wildcard record-change fixture for nhp#1146. A statement that can
# mutate records in every hosted zone must carry the normalized-record-name
# condition; otherwise sandbox CI can pre-stage records in orphan public zones.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_wildcard" {
  name = "route53-wildcard"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53Wildcard"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "*"
      }
    ]
  })
}
