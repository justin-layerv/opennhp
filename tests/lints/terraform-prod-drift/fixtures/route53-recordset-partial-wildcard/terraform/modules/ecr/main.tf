# Partial hosted-zone wildcard fixture for nhp#1146. `Z*` is narrower than
# Resource="*" textually, but it is still all hosted zones for practical IAM
# evaluation and must carry the normalized-record-name condition.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_partial_wildcard" {
  name = "route53-partial-wildcard"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53PartialWildcard"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/Z*"
      }
    ]
  })
}
