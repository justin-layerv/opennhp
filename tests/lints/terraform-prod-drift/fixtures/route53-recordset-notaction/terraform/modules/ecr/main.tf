# NotAction fixture for nhp#1146. An Allow statement with NotAction grants
# every action except the excluded set, so it can include
# route53:ChangeResourceRecordSets without naming it directly.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_notaction" {
  name = "route53-notaction"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Route53ViaNotAction"
        Effect    = "Allow"
        NotAction = "s3:*"
        Resource  = "*"
      }
    ]
  })
}
