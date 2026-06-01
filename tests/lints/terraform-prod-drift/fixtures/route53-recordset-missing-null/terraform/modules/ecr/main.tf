# Missing Null guard fixture for nhp#1146. ForAllValues is vacuously true when
# AWS omits the multi-valued key, so the wildcard-resource grant is acceptable
# only when the same statement also requires Null=false.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_missing_null" {
  name = "route53-missing-null"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53MissingNull"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["internal-api.qurl.layerv.xyz"]
          }
        }
      }
    ]
  })
}
