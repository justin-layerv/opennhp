# Positive fixture for nhp#1146's real computed-zone policy shape. python-hcl2
# surfaces this condition value as an interpolation string; the lint should not
# reject the static policy, while Terraform variable validation remains the
# runtime guard for the resolved names.

variable "route53_change_record_name_patterns" {
  type    = list(string)
  default = ["internal-api.qurl.layerv.xyz"]
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "route53_variable_condition" {
  name = "route53-variable-condition"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53VariableCondition"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "arn:aws:route53:::hostedzone/*"
        Condition = {
          "ForAllValues:StringLike" = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = var.route53_change_record_name_patterns
          }
          Null = {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = "false"
          }
        }
      }
    ]
  })
}
