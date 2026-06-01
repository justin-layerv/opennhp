# Plain normalized-name condition fixture for nhp#1146. The key is present and
# the value is narrow, but the operator is not ForAllValues-prefixed.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_plain_condition" {
  name = "route53-plain-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53PlainCondition"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          StringLike = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["internal-api.qurl.layerv.xyz"]
          }
        }
      }
    ]
  })
}
