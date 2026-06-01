# Negated normalized-name condition fixture for nhp#1146. A ForAllValues
# operator is not enough by itself: StringNotLike inverts the intended
# constraint and must not satisfy the wildcard-resource guard.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_negated_condition" {
  name = "route53-negated-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53NegatedCondition"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          "ForAllValues:StringNotLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["internal-api.qurl.layerv.xyz"]
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
          }
        }
      }
    ]
  })
}
