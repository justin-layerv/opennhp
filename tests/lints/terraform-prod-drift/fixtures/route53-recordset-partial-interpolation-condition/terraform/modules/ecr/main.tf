variable "route53_record_suffix" {
  type    = string
  default = "qurl.layerv.xyz"
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_partial_interpolation_condition" {
  name = "route53-partial-interpolation-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53PartialInterpolationCondition"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["internal-api.${var.route53_record_suffix}"]
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
          }
        }
      }
    ]
  })
}
