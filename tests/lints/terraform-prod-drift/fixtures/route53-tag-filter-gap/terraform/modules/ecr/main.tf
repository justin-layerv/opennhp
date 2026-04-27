# Canonical role with the basic route53 grant only — does NOT
# include `route53:ListTagsForResource`. The fixture's data source
# uses the `tags` filter, so the lint must demand the extra action
# and report a missing-grant.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_basic" {
  name = "route53-basic"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53Basic"
        Effect   = "Allow"
        Action   = ["route53:ListHostedZones"]
        Resource = "*"
      }
    ]
  })
}
