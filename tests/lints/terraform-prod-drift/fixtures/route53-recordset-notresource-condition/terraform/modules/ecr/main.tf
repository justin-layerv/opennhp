resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_notresource_condition" {
  name = "route53-notresource-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid         = "Route53NotResourceCondition"
        Effect      = "Allow"
        Action      = "route53:ChangeResourceRecordSets"
        NotResource = "arn:aws:route53:::hostedzone/Z10394893FM38A1RXLL32"
        Condition = {
          "ForAllValues:StringLike" = {
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
