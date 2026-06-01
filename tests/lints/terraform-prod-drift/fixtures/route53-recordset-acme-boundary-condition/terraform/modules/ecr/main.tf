resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_acme_boundary_condition" {
  name = "route53-acme-boundary-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53ACMEBoundaryCondition"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["_acme-challenge.*"]
          }
          "ForAllValues:StringEquals" = {
            "route53:ChangeResourceRecordSetsActions"     = ["CREATE", "UPSERT", "DELETE"]
            "route53:ChangeResourceRecordSetsRecordTypes" = ["TXT"]
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
            "route53:ChangeResourceRecordSetsActions"               = "false"
            "route53:ChangeResourceRecordSetsRecordTypes"           = "false"
          }
        }
      }
    ]
  })
}
