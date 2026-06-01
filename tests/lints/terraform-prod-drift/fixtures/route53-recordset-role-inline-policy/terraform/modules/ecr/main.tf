resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"

  inline_policy {
    name = "route53-wildcard-inline"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "Route53WildcardInline"
          Effect   = "Allow"
          Action   = "route53:ChangeResourceRecordSets"
          Resource = "*"
        }
      ]
    })
  }
}

